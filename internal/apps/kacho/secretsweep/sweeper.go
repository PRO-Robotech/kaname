// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package secretsweep — the periodic backstop that clears one-shot credentials
// left staged in finished operation responses.
//
// The fast path is a goroutine detached from the issuing request: it waits out the
// grace window the polling client needs to collect the credential, then clears it.
// Detached is the whole point — the client already holds the operation envelope by
// the time the worker finishes — and detached is also why it does not survive the
// process. A rollout ends it, and the default termination grace is shorter than the
// credential grace window, so the routine case is enough to strand a credential.
//
// Nothing else could pick it up: the row is done=true and the orphan reconciler
// claims done=false, so those rows are outside its claim by construction, and no
// retention ages operations out. This loop is what makes the clean-up survive a
// restart.
//
// It is also the only thing that can say the fast path is broken. Every "key
// material may remain" branch lives inside the goroutine that no longer exists, so
// a strand was silent. Here a non-zero count is reported at WARN with the operation
// ids' count — because "the backstop has never had to act" and "the backstop acts
// on every key" must not look the same in a log.
package secretsweep

import (
	"context"
	"log/slog"
	"time"
)

// Store — the durable side of the sweep. Implemented by the Postgres adapter
// (repo/kacho/pg.OpsResponseRedactor); the use-case never sees pgx.
type Store interface {
	SweepStrandedSecrets(ctx context.Context, spec Spec) (Result, error)
}

// Spec / Result mirror the adapter's contract. They are declared here because the
// port belongs to the caller, not to the adapter (clean architecture); the adapter
// converts.
type Spec struct {
	Targets []Target
	Settled time.Duration
	Window  time.Duration
	Limit   int
}

// Target — one credential-bearing response type and the fields to clear on it.
type Target struct {
	ResponseType string
	Fields       []string
}

// Result — rows read, and rows that still carried a credential.
type Result struct {
	Scanned  int
	Redacted int
}

// Sweeper runs Store.SweepStrandedSecrets on an interval.
type Sweeper struct {
	store    Store
	spec     Spec
	interval time.Duration
	logger   *slog.Logger
	// ticker — injectable for deterministic tests; nil → time.NewTicker.
	ticker func(time.Duration) (<-chan time.Time, func())
}

// New builds the sweeper. interval <= 0 → defaultInterval.
func New(store Store, spec Spec, interval time.Duration, logger *slog.Logger) *Sweeper {
	if interval <= 0 {
		interval = defaultInterval
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Sweeper{store: store, spec: spec, interval: interval, logger: logger}
}

// defaultInterval — a strand should be measured in a minute, not in a shift. The
// sweep is bounded by Spec.Window and Spec.Limit, so the cost does not grow with
// the table.
const defaultInterval = time.Minute

// WithTicker replaces the clock (tests).
func (s *Sweeper) WithTicker(f func(time.Duration) (<-chan time.Time, func())) *Sweeper {
	s.ticker = f
	return s
}

// Run sweeps once immediately — a restart is exactly when a strand is most likely —
// and then on the interval until ctx is done. Non-fatal by contract: a failing
// sweep is logged and retried, never a reason to take the process down.
//
// РЕПЛИКИ: на-реплику — петля идёт в каждой реплике, и дубль здесь безвреден не
// по совпадению, а по конструкции записи: каждая правка — идемпотентный
// однооператорный UPDATE одной строки, и два процесса, стирающие одно и то же
// поле, производят одинаковые байты. Клейма нет НАМЕРЕННО: замок добавил бы
// способ застрять самому страховочному механизму, а он существует ровно на тот
// случай, когда застрял быстрый путь.
//
// Запись появилась вместе с расширением распознавателя петель (задача #1264):
// петля движима каналом тикера В ПЕРЕМЕННОЙ (подменяемые часы), и до расширения
// гейт её НЕ ВИДЕЛ — молчание здесь означало «не смотрели», а не «исход
// объявлен».
func (s *Sweeper) Run(ctx context.Context) {
	s.SweepOnce(ctx)

	var (
		c    <-chan time.Time
		stop func()
	)
	if s.ticker != nil {
		c, stop = s.ticker(s.interval)
	} else {
		t := time.NewTicker(s.interval)
		c, stop = t.C, t.Stop
	}
	defer stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c:
			s.SweepOnce(ctx)
		}
	}
}

// SweepOnce runs a single pass and reports what it found.
func (s *Sweeper) SweepOnce(ctx context.Context) Result {
	res, err := s.store.SweepStrandedSecrets(ctx, s.spec)
	if err != nil {
		s.logger.ErrorContext(ctx, "one-shot credential backstop sweep failed — a credential may remain staged in a finished operation",
			slog.Any("err", err))
		return res
	}
	if res.Redacted > 0 {
		// Not Info. This is the in-process clean-up failing to run, and the only
		// place it becomes visible: every branch that would have said so lives in
		// the goroutine that did not survive.
		s.logger.WarnContext(ctx, "one-shot credential backstop cleared credentials the in-process clean-up did not — expect this after a restart, investigate if it repeats",
			slog.Int("redacted", res.Redacted),
			slog.Int("scanned", res.Scanned))
	}
	return res
}
