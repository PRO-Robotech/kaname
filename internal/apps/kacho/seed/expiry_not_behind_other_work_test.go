// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// expiry_not_behind_other_work_test.go — a grant whose term has ended must stop
// answering "allowed" without waiting for unrelated work.
//
// WHAT THIS IS ABOUT
//
// A binding's term is enforced in exactly one way: the sweep notices
// `expires_at < now()` and deletes the binding's tuples. Nothing else ends it — the
// tuples carry no expiry condition, so the store has no idea a term exists
// (fga_model.fga declares `condition non_expired(current_time, valid_until)` and NO
// relation references it). Until that deletion lands, an expired grant is
// indistinguishable from a live one.
//
// That deletion used to be the LAST thing in a sweep that first re-reconciled every
// selector binding in the cluster — each taking a per-binding exclusive advisory
// lock, and by the reconciler's own measurement reading tens of thousands of rows —
// on the SAME goroutine as the event drain. So the delay between "the term ended"
// and "the grant stops working" was not the sweep interval; it was the interval plus
// a full pass over the cluster plus whatever the drain was doing, and it grew with
// the size of the installation. On a loaded stand that came to 951 seconds, during
// which 1806 identical probes were all answered "allowed".
//
// These tests pin the property that fixes: term enforcement runs on its own
// schedule, so neither a slow drain nor a slow selector pass can hold it up. They
// are deterministic — a fake blocks, and the test waits for expiry to happen anyway.
//
// WHAT THEY DO NOT FIX, on purpose: the window becomes BOUNDED by the configured
// interval instead of unbounded, which is the difference between the observed defect
// and correct-by-schedule. Making it request-time means putting the term ON the
// tuple as a condition, which needs a model change (see the package note in
// reconcile_worker.go) and is the owner's call to apply.

package seed

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/reconcile_outbox"
)

// discardLogger keeps the worker's non-fatal warnings out of the test output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// exEngine records what the worker asked for, and can be made to block on the
// selector-reconcile path (the cluster-sized work expiry must not queue behind).
type exEngine struct {
	mu             sync.Mutex
	expired        []domain.AccessBindingID
	reconciled     []domain.AccessBindingID
	blockReconcile chan struct{} // when non-nil, ReconcileBinding waits on it
}

func (e *exEngine) ReconcileObject(context.Context, string, string) error { return nil }

func (e *exEngine) ReconcileBinding(_ context.Context, id domain.AccessBindingID) error {
	if e.blockReconcile != nil {
		<-e.blockReconcile
	}
	e.mu.Lock()
	e.reconciled = append(e.reconciled, id)
	e.mu.Unlock()
	return nil
}

func (e *exEngine) ExpireBinding(_ context.Context, id domain.AccessBindingID) error {
	e.mu.Lock()
	e.expired = append(e.expired, id)
	e.mu.Unlock()
	return nil
}

func (e *exEngine) expiredIDs() []domain.AccessBindingID {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]domain.AccessBindingID(nil), e.expired...)
}

// exQueue serves a fixed selector set and expired set, and can block the drain
// claim (the other thing expiry must not queue behind).
type exQueue struct {
	selectors  []domain.AccessBindingID
	expired    []domain.AccessBindingID
	blockClaim chan struct{} // when non-nil, ClaimReconcileEvents waits on it
}

func (q *exQueue) ClaimReconcileEvents(context.Context, int) ([]reconcile_outbox.Event, error) {
	if q.blockClaim != nil {
		<-q.blockClaim
	}
	return nil, nil
}
func (q *exQueue) MarkReconcileEventSent(context.Context, int64) error { return nil }

// RecordReconcileEventFailure — порт учёта отказа (#2050). Здесь он не предмет:
// сверка в этих пробах не отказывает, поэтому дублёр обязан молчать, а не
// считать. Вызов на успешном пути — находка, и её ловит
// `TestReconcileDrain_SuccessIsNotCounted`.
func (q *exQueue) RecordReconcileEventFailure(context.Context, int64, string) (int, error) {
	return 0, nil
}

func (q *exQueue) ListSelectorBindingIDs(context.Context) ([]domain.AccessBindingID, error) {
	return q.selectors, nil
}
func (q *exQueue) ListExpiredBindingIDs(context.Context) ([]domain.AccessBindingID, error) {
	return q.expired, nil
}

// waitForExpiries waits until ExpireBinding has been called at least n times, or
// reports the shortfall. Counting PASSES rather than watching for a single call is
// deliberate: the worker runs one sweep on boot before entering its loop, so a
// one-shot assertion is satisfied by that boot pass and would stay green even if the
// loop never enforced a term again.
func waitForExpiries(t *testing.T, eng *exEngine, n int, within time.Duration, why string) {
	t.Helper()
	deadline := time.After(within)
	for {
		if got := len(eng.expiredIDs()); got >= n {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("term enforcement ran %d times, wanted at least %d within %s: %s",
				len(eng.expiredIDs()), n, within, why)
		case <-time.After(2 * time.Millisecond):
		}
	}
}

// runWorker starts the worker and returns a stop func.
func runWorker(t *testing.T, w *ReconcileWorker) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = w.Run(ctx)
	}()
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("worker did not stop")
		}
	}
}

// TestExpiryIsNotHeldUpByTheSelectorSweep — the cluster-sized pass must not stand
// between the end of a term and the end of the access.
func TestExpiryIsNotHeldUpByTheSelectorSweep(t *testing.T) {
	block := make(chan struct{})
	eng := &exEngine{blockReconcile: block}
	q := &exQueue{
		selectors: []domain.AccessBindingID{"abn-sel1", "abn-sel2", "abn-sel3"},
		expired:   []domain.AccessBindingID{"abn-expired"},
	}
	w := NewReconcileWorker(eng, q, ReconcileWorkerConfig{
		SweepInterval: 20 * time.Millisecond,
		DrainInterval: time.Hour, // keep the drain out of this test
		Logger:        discardLogger(),
	})
	stop := runWorker(t, w)
	defer func() { close(block); stop() }()

	waitForExpiries(t, eng, 2, 3*time.Second,
		"term enforcement is queued behind a pass whose cost grows with the size of the "+
			"installation, so an expired grant keeps answering allowed for as long as that "+
			"pass takes")
	if got := eng.expiredIDs(); got[0] != "abn-expired" {
		t.Fatalf("expired the wrong binding: %v", got)
	}
}

// TestExpiryIsNotHeldUpByTheEventDrain — the same for the fast path. A drain that
// is slow (or wedged on a peer) must not extend anyone's access.
func TestExpiryIsNotHeldUpByTheEventDrain(t *testing.T) {
	block := make(chan struct{})
	eng := &exEngine{}
	q := &exQueue{
		expired:    []domain.AccessBindingID{"abn-expired"},
		blockClaim: block,
	}
	w := NewReconcileWorker(eng, q, ReconcileWorkerConfig{
		SweepInterval: 20 * time.Millisecond,
		DrainInterval: 5 * time.Millisecond, // drains eagerly, and blocks in the claim
		Logger:        discardLogger(),
	})
	stop := runWorker(t, w)
	defer func() { close(block); stop() }()

	waitForExpiries(t, eng, 2, 3*time.Second,
		"term enforcement shares its goroutine with the event drain, so a slow or wedged "+
			"drain extends an expired grant for as long as it lasts")
}

// TestExpiryKeepsRunningEveryInterval — the schedule must be a schedule, not a
// single pass. An expiry loop that ran once on boot would pass the two tests above
// and enforce nothing afterwards.
func TestExpiryKeepsRunningEveryInterval(t *testing.T) {
	eng := &exEngine{}
	q := &exQueue{expired: []domain.AccessBindingID{"abn-expired"}}
	w := NewReconcileWorker(eng, q, ReconcileWorkerConfig{
		SweepInterval: 10 * time.Millisecond,
		DrainInterval: time.Hour,
		Logger:        discardLogger(),
	})
	stop := runWorker(t, w)
	defer stop()

	waitForExpiries(t, eng, 3, 3*time.Second,
		"at a 10ms interval it is not on a schedule at all — a single pass on boot would "+
			"satisfy the two tests above and enforce nothing afterwards")
}
