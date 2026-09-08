// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

// bootstrap_reconciler.go — startup reconciler that drives RunBootstrapAdmin
// to convergence.
//
// Why a loop (not a one-shot call): RunBootstrapAdmin grants
// `system_admin@cluster_root` to the bootstrap user identified by
// KANAME_BOOTSTRAP_ROOT_EMAIL and enqueues the FGA tuple into the
// transactional fga_outbox. But the bootstrap user row only appears in
// kaname.users on first login / fixture upsert (InternalUserService.
// UpsertFromIdentity), which happens AFTER kaname boots. A single startup
// call therefore races the user row and skips ("user not registered"), so the
// cluster-admin tuple is never written → cluster-scope AccessBinding cases
// 403/404 (Bug B). The reconciler re-runs on an interval until the grant
// commits (Skipped=false) or a terminal skip ("email empty") short-circuits.
//
// Idempotent: once the grant exists, a subsequent run returns the 23505
// graceful-skip path — but the reconciler stops on the first committed grant,
// so that path is only hit on HA cold-start races.
//
// This is a thin orchestration seam (composition-root concern); the actual
// DB/outbox work stays in RunBootstrapAdmin. The runner is injected so the
// loop semantics are unit-testable without a database.

import (
	"context"
	"log/slog"
	"time"
)

// BootstrapRunFn — the unit of work the reconciler drives. In production this
// is a closure over RunBootstrapAdmin(pool, ...); tests inject a fake.
type BootstrapRunFn func(ctx context.Context) (BootstrapAdminResult, error)

// Исходы ОДНОЙ попытки посева. Набор ЗАКРЫТ и выводится из закрытого набора
// причин пропуска ([AllBootstrapSkipReasons]) плюс двух исходов, причины
// пропуска не имеющих: закоммиченная выдача и отказ исполнителя.
//
// Значения уезжают меткой счётчика, поэтому свободной строкой быть не могут:
// метка из запроса растит кардинальность, а метка из закрытого словаря — нет.
const (
	// BootstrapOutcomeGranted — выдача закоммичена.
	//
	// Полоса заводится счётчиком ЗАРАНЕЕ, значением ноль. Иначе на стенде, где
	// посев не исполнился ни разу, ряда просто НЕТ — а отсутствующий ряд снаружи
	// неотличим от отсутствующего согласователя, то есть ровно от той тишины,
	// ради которой эта полоса и заведена.
	BootstrapOutcomeGranted = "granted"
	// BootstrapOutcomeDisabled — адрес администратора не задан (терминально).
	BootstrapOutcomeDisabled = "disabled"
	// BootstrapOutcomeNotRegistered — строки личности ещё нет.
	BootstrapOutcomeNotRegistered = "not_registered"
	// BootstrapOutcomeNotActive — строка есть, аутентифицироваться не может.
	BootstrapOutcomeNotActive = "not_active"
	// BootstrapOutcomeConcurrentRace — выдачу закоммитила соседняя реплика.
	BootstrapOutcomeConcurrentRace = "concurrent_race"
	// BootstrapOutcomeFailed — исполнитель вернул отказ.
	//
	// Отдельно от пропусков намеренно: «стенд сломан» и «условие не создано» —
	// разные вопросы, и слитые в одну полосу они не отвечают ни на один.
	BootstrapOutcomeFailed = "failed"
)

// BootstrapOutcomes — все полосы счётчика. Читается тем, кто заводит ряды
// заранее: полоса, появляющаяся вместе с первым событием, до него не существует.
var BootstrapOutcomes = []string{
	BootstrapOutcomeGranted,
	BootstrapOutcomeDisabled,
	BootstrapOutcomeNotRegistered,
	BootstrapOutcomeNotActive,
	BootstrapOutcomeConcurrentRace,
	BootstrapOutcomeFailed,
}

// skipReasonOutcome — отображение причины пропуска в полосу счётчика.
//
// Отображение, а не `switch` с веткой по умолчанию: корзина «прочее» приняла бы
// новую причину молча и назвала бы её чужим именем. Полноту относительно
// [AllBootstrapSkipReasons] сторожит проба пакета.
var skipReasonOutcome = map[BootstrapSkipReason]string{
	BootstrapSkipEmailEmpty:     BootstrapOutcomeDisabled,
	BootstrapSkipNotRegistered:  BootstrapOutcomeNotRegistered,
	BootstrapSkipNotActive:      BootstrapOutcomeNotActive,
	BootstrapSkipConcurrentRace: BootstrapOutcomeConcurrentRace,
}

// BootstrapAttemptObserver — куда согласователь отдаёт исход КАЖДОЙ попытки.
//
// Порт объявлен здесь, реализация — в слое наблюдаемости (композиционный
// корень). Согласователь о прометее не знает: use-case не тащит адаптер.
type BootstrapAttemptObserver interface {
	// IncBootstrapAdminAttempt — одна попытка с названным исходом.
	IncBootstrapAdminAttempt(outcome string)
}

// BootstrapReconcilerConfig — tunables.
type BootstrapReconcilerConfig struct {
	// Interval between retry attempts while the run keeps skipping. Defaults
	// to 10s when zero.
	Interval time.Duration
	// Logger — optional; slog.Default() when nil.
	Logger *slog.Logger
	// Observer — наблюдатель исходов попыток; необязателен.
	//
	// Отсутствие наблюдателя посев не роняет: реестр метрик собирается не на
	// каждом стенде, а посев обязан работать и там, где его не собрали.
	Observer BootstrapAttemptObserver
}

// BootstrapReconciler re-runs a BootstrapRunFn until it commits the grant.
type BootstrapReconciler struct {
	run      BootstrapRunFn
	interval time.Duration
	logger   *slog.Logger
	observer BootstrapAttemptObserver
}

// NewBootstrapReconciler constructs a reconciler around the supplied runner.
func NewBootstrapReconciler(run BootstrapRunFn, cfg BootstrapReconcilerConfig) *BootstrapReconciler {
	interval := cfg.Interval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &BootstrapReconciler{run: run, interval: interval, logger: logger, observer: cfg.Observer}
}

// Run drives the runner to convergence. It returns nil on:
//   - committed grant (Skipped=false),
//   - terminal skip ("email empty" — no email configured, nothing to do),
//   - context cancellation (clean shutdown; never-converged is not an error).
//
// Transient errors and non-terminal skips ("user not registered") are retried
// on the configured interval. Run is non-fatal by contract — the bootstrap
// grant is a best-effort startup convenience, never a hard startup gate.
//
// РЕПЛИКИ: на-реплику — петля сходящаяся: она прекращается, как только выдача закоммичена.
// Взаимное исключение держит ОГРАНИЧЕНИЕ УНИКАЛЬНОСТИ в базе — проигравший
// получает 23505 и отчитывается пропуском «concurrent race», а не отказом.
func (r *BootstrapReconciler) Run(ctx context.Context) error {
	// Immediate first attempt (don't wait a full interval on a fresh boot).
	for {
		res, err := r.run(ctx)
		r.observe(res, err)
		switch {
		case err != nil:
			r.logger.WarnContext(ctx, "bootstrap admin reconcile attempt failed, will retry", slog.Any("err", err))
		case !res.Skipped:
			r.logger.InfoContext(ctx, "bootstrap admin reconciled — cluster-admin grant committed",
				slog.String("user_id", res.UserID),
				slog.String("grant_id", res.GrantID),
				slog.String("fga_outbox_id", res.FGAOutboxID))
			return nil
		case res.SkipReason == BootstrapSkipEmailEmpty:
			// No bootstrap email configured — terminal, nothing to reconcile.
			r.logger.DebugContext(ctx, "bootstrap admin disabled (no email), reconciler exiting")
			return nil
		default:
			// Non-terminal skip (user not registered yet / concurrent race) — retry.
			r.logger.DebugContext(ctx, "bootstrap admin not yet reconciled, will retry",
				slog.String("reason", string(res.SkipReason)))
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(r.interval):
		}
	}
}

// observe — отдать исход одной попытки наблюдателю.
//
// Причина, которой нет в закрытом отображении, НЕ получает корзины «прочее»:
// она остаётся неназванной, и об этом громко говорит журнал. Молчаливое
// приписывание её к чужой полосе было бы ровно тем, ради снятия чего заведён
// этот счётчик, — данные есть, а означают они не то.
func (r *BootstrapReconciler) observe(res BootstrapAdminResult, err error) {
	if r.observer == nil {
		return
	}
	switch {
	case err != nil:
		r.observer.IncBootstrapAdminAttempt(BootstrapOutcomeFailed)
	case !res.Skipped:
		r.observer.IncBootstrapAdminAttempt(BootstrapOutcomeGranted)
	default:
		outcome, known := skipReasonOutcome[res.SkipReason]
		if !known {
			r.logger.Error("исход попытки посева не имеет полосы счётчика: "+
				"причина объявлена без отображения — счётчик о ней молчит",
				slog.String("reason", string(res.SkipReason)))
			return
		}
		r.observer.IncBootstrapAdminAttempt(outcome)
	}
}
