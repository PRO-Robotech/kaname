// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package secretsweep_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/secretsweep"
)

type fakeStore struct {
	mu    sync.Mutex
	calls int
	res   secretsweep.Result
	err   error
	seen  secretsweep.Spec
}

func (f *fakeStore) SweepStrandedSecrets(_ context.Context, spec secretsweep.Spec) (secretsweep.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.seen = spec
	return f.res, f.err
}

func (f *fakeStore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func logbuf() (*slog.Logger, *bytes.Buffer) {
	var b bytes.Buffer
	return slog.New(slog.NewTextHandler(&b, &slog.HandlerOptions{Level: slog.LevelDebug})), &b
}

// A restart is exactly when a credential is most likely to be stranded, so the
// first sweep must not wait for the first tick.
func TestRun_SweepsImmediatelyOnStart(t *testing.T) {
	store := &fakeStore{}
	logger, _ := logbuf()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // no ticks at all

	secretsweep.New(store, secretsweep.Spec{Limit: 10}, time.Hour, logger).Run(ctx)

	if got := store.count(); got != 1 {
		t.Fatalf("sweeps on start = %d, want 1 — a strand must not wait for the first tick", got)
	}
}

// Having to clear a credential means the in-process clean-up did not run. That is
// the only signal anyone gets, so it must not be filed at Info among the noise.
func TestSweepOnce_ReportsClearedCredentialsLoudly(t *testing.T) {
	store := &fakeStore{res: secretsweep.Result{Scanned: 3, Redacted: 2}}
	logger, buf := logbuf()

	res := secretsweep.New(store, secretsweep.Spec{Limit: 10}, time.Hour, logger).SweepOnce(context.Background())

	if res.Redacted != 2 {
		t.Fatalf("Redacted = %d, want 2", res.Redacted)
	}
	out := buf.String()
	if !strings.Contains(out, "level=WARN") {
		t.Fatalf("clearing a stranded credential must be reported above Info, got: %s", out)
	}
	if !strings.Contains(out, "redacted=2") {
		t.Fatalf("the report must carry the count, got: %s", out)
	}
}

// Nothing to clear is the normal state and must stay quiet — otherwise the signal
// above is buried by the case it is supposed to stand out from.
func TestSweepOnce_SilentWhenThereIsNothingToClear(t *testing.T) {
	store := &fakeStore{res: secretsweep.Result{Scanned: 5, Redacted: 0}}
	logger, buf := logbuf()

	secretsweep.New(store, secretsweep.Spec{Limit: 10}, time.Hour, logger).SweepOnce(context.Background())

	if out := buf.String(); strings.Contains(out, "level=WARN") || strings.Contains(out, "level=ERROR") {
		t.Fatalf("a clean sweep must not raise anything, got: %s", out)
	}
}

// A failing sweep is reported and never fatal: the backstop exists because the
// process already lost a clean-up, and taking the process down would be worse than
// the strand it guards.
func TestSweepOnce_FailureIsReportedAndNotFatal(t *testing.T) {
	store := &fakeStore{err: errors.New("database is starting up")}
	logger, buf := logbuf()

	secretsweep.New(store, secretsweep.Spec{Limit: 10}, time.Hour, logger).SweepOnce(context.Background())

	if out := buf.String(); !strings.Contains(out, "level=ERROR") {
		t.Fatalf("a failing sweep must be reported at ERROR, got: %s", out)
	}
}

// The loop keeps running on the injected clock, and stops when the context does.
func TestRun_SweepsOnEveryTickAndStopsWithTheContext(t *testing.T) {
	store := &fakeStore{}
	logger, _ := logbuf()
	tick := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		secretsweep.New(store, secretsweep.Spec{Limit: 10}, time.Hour, logger).
			WithTicker(func(time.Duration) (<-chan time.Time, func()) { return tick, func() {} }).
			Run(ctx)
		close(done)
	}()

	tick <- time.Now()
	tick <- time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
	if got := store.count(); got != 3 { // one on start + two ticks
		t.Fatalf("sweeps = %d, want 3 (start + two ticks)", got)
	}
}
