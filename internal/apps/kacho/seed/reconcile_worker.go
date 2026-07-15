// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package seed

// reconcile_worker.go — reconciler-worker orchestration.
//
// A thin composition-root loop that drives the reconcile use-case to
// convergence on two fast/slow paths:
//
//	FAST (event-driven, Q1=(c)) — drain resource_reconcile_outbox: every
//	  RegisterResource/UnregisterResource enqueued a "this object's mirror state
//	  changed" event; the worker re-evaluates the bindings that reference it
//	  (ReconcileObject) and marks the event sent only after the reconcile commits
//	  (at-least-once; the reconcile is idempotent). Дренаж пробуждается по
//	  LISTEN/NOTIFY (NotifyWatcher, паритет с fga_outbox drainer): событие в очереди
//	  шлет pg_notify, worker просыпается и дренажит в пределах одного прохода. Poll
//	  по DrainInterval остается fallback'ом на случай пропущенного NOTIFY.
//	SLOW (periodic sweep, D12 + D9) — every interval: (a) re-reconcile every
//	  selector binding (defense-in-depth against a lost event / restart before
//	  drain) and (b) expire TTL-elapsed bindings (eager-revoke, γ-16).
//
// Clean Architecture: the loop owns no SQL — it depends on the reconcile
// use-case (ReconcileObject/ReconcileBinding/ExpireBinding) + the narrow drain
// ports below (implemented by the pg ReconcileAdapter). Non-fatal by contract:
// a transient error is logged and retried on the next tick; the worker never
// crashes the server.

import (
	"context"
	"log/slog"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/reconcile_outbox"
)

// ReconcileEngine — the reconcile use-case surface the worker drives.
type ReconcileEngine interface {
	ReconcileObject(ctx context.Context, objectType, objectID string) error
	ReconcileBinding(ctx context.Context, bindingID domain.AccessBindingID) error
	ExpireBinding(ctx context.Context, bindingID domain.AccessBindingID) error
}

// ReconcileQueue — the drain + sweep-source ports (pg ReconcileAdapter).
type ReconcileQueue interface {
	ClaimReconcileEvents(ctx context.Context, limit int) ([]reconcile_outbox.Event, error)
	MarkReconcileEventSent(ctx context.Context, id int64) error
	ListSelectorBindingIDs(ctx context.Context) ([]domain.AccessBindingID, error)
	ListExpiredBindingIDs(ctx context.Context) ([]domain.AccessBindingID, error)
}

// NotifyWatcher — источник пробуждений по LISTEN/NOTIFY для fast-path дренажа
// (паритет с fga_outbox drainer). Реализуется pg-адаптером: LISTEN на канал
// resource_reconcile_outbox. Watch блокируется до отмены ctx и шлет в wakeup
// (неблокирующе) на каждый NOTIFY и один раз на каждый успешный (пере)коннект —
// чтобы worker не пропустил событие, пришедшее в окно реконнекта. Опционален:
// при nil worker работает poll-only (прежнее поведение).
type NotifyWatcher interface {
	Watch(ctx context.Context, wakeup chan<- struct{})
}

// ReconcileWorkerConfig — tunables.
type ReconcileWorkerConfig struct {
	// SweepInterval between periodic sweeps (selector re-reconcile + expiry).
	// Defaults to 30s when zero.
	SweepInterval time.Duration
	// DrainInterval between event-queue drain polls. With a Notify watcher set this
	// is the missed-NOTIFY poll-fallback (the NOTIFY carries the materialization
	// latency); poll-only без него. Defaults to 2s when zero.
	DrainInterval time.Duration
	// BatchSize for each drain claim. Defaults to 64 when zero.
	BatchSize int
	// Notify — опциональный LISTEN/NOTIFY-источник пробуждений. Когда задан, worker
	// дренажит очередь по NOTIFY, а DrainInterval вырождается в poll-fallback. nil →
	// poll-only.
	Notify NotifyWatcher
	Logger *slog.Logger
}

// ReconcileWorker — the γ reconciler loop.
type ReconcileWorker struct {
	engine    ReconcileEngine
	queue     ReconcileQueue
	notify    NotifyWatcher
	sweepIvl  time.Duration
	drainIvl  time.Duration
	batchSize int
	logger    *slog.Logger
}

// NewReconcileWorker constructs the worker.
func NewReconcileWorker(engine ReconcileEngine, queue ReconcileQueue, cfg ReconcileWorkerConfig) *ReconcileWorker {
	sweep := cfg.SweepInterval
	if sweep <= 0 {
		sweep = 30 * time.Second
	}
	drain := cfg.DrainInterval
	if drain <= 0 {
		drain = 2 * time.Second
	}
	batch := cfg.BatchSize
	if batch <= 0 {
		batch = 64
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &ReconcileWorker{
		engine: engine, queue: queue, notify: cfg.Notify,
		sweepIvl: sweep, drainIvl: drain, batchSize: batch, logger: logger,
	}
}

// Run drives the worker until ctx is cancelled. Returns nil on clean shutdown.
func (w *ReconcileWorker) Run(ctx context.Context) error {
	drainTick := time.NewTicker(w.drainIvl)
	sweepTick := time.NewTicker(w.sweepIvl)
	defer drainTick.Stop()
	defer sweepTick.Stop()

	// wakeup — сигнал «в очереди есть событие» от NotifyWatcher (LISTEN/NOTIFY).
	// Буфер 1: один сигнал не теряется, даже если worker сейчас занят дренажем (он
	// перепроверит очередь следующим claim). При notify=nil канал остается пустым,
	// и worker дренажит только по drainTick (poll-only). При заданном watcher'е
	// drainTick деградирует до poll-fallback на пропущенный NOTIFY.
	wakeup := make(chan struct{}, 1)
	if w.notify != nil {
		go w.notify.Watch(ctx, wakeup)
	}

	// Immediate sweep on boot (converge memberships against the current mirror
	// before the first interval elapses).
	w.sweep(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-wakeup:
			w.drain(ctx)
		case <-drainTick.C:
			w.drain(ctx)
		case <-sweepTick.C:
			w.sweep(ctx)
		}
	}
}

// drain claims a batch of reconcile events and processes each: reconcile the
// affected bindings, then mark the event sent only on success (at-least-once).
func (w *ReconcileWorker) drain(ctx context.Context) {
	events, err := w.queue.ClaimReconcileEvents(ctx, w.batchSize)
	if err != nil {
		w.logger.WarnContext(ctx, "reconcile drain claim failed", slog.Any("err", err))
		return
	}
	for _, e := range events {
		if err := w.engine.ReconcileObject(ctx, e.ObjectType, e.ObjectID); err != nil {
			w.logger.WarnContext(ctx, "reconcile object failed, will retry",
				slog.String("object_type", e.ObjectType), slog.String("object_id", e.ObjectID),
				slog.Any("err", err))
			continue // leave event unsent → re-delivered next drain (idempotent)
		}
		if err := w.queue.MarkReconcileEventSent(ctx, e.ID); err != nil {
			w.logger.WarnContext(ctx, "reconcile mark-sent failed",
				slog.Int64("event_id", e.ID), slog.Any("err", err))
		}
	}
}

// sweep re-reconciles every selector binding (D12 defense-in-depth) and expires
// TTL-elapsed bindings (D9 eager-revoke, γ-16).
func (w *ReconcileWorker) sweep(ctx context.Context) {
	selectorIDs, err := w.queue.ListSelectorBindingIDs(ctx)
	if err != nil {
		w.logger.WarnContext(ctx, "reconcile sweep: list selector bindings failed", slog.Any("err", err))
	}
	for _, id := range selectorIDs {
		if err := w.engine.ReconcileBinding(ctx, id); err != nil {
			w.logger.WarnContext(ctx, "reconcile sweep: reconcile binding failed",
				slog.String("binding_id", string(id)), slog.Any("err", err))
		}
	}

	expiredIDs, err := w.queue.ListExpiredBindingIDs(ctx)
	if err != nil {
		w.logger.WarnContext(ctx, "reconcile sweep: list expired bindings failed", slog.Any("err", err))
	}
	for _, id := range expiredIDs {
		if err := w.engine.ExpireBinding(ctx, id); err != nil {
			w.logger.WarnContext(ctx, "reconcile sweep: expire binding failed",
				slog.String("binding_id", string(id)), slog.Any("err", err))
		}
	}
}
