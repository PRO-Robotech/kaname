// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package subjectchange_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/pkg/subjectchange"
)

// fakePoller returns configured batches one per call, then empty slices.
// headID is max(ids) for non-empty batches, 0 for empty ones.
//
// It carries no completion signal, and that is deliberate: a fake can only ever
// signal from INSIDE the call, i.e. before the tick that made the call has
// decided anything — so a case waiting on such a signal reads the flush counter
// in a race with the flush. The cases below drive ticks synchronously instead
// (subjectchange.Tick), which makes the fake's own bookkeeping the only state there is.
type fakePoller struct {
	mu      sync.Mutex
	batches [][]int64 // ids per call; nil / empty = empty batch
	errs    []error   // parallel to batches; errs[i] (if set) is returned on call i
	calls   int
	sinces  []int64 // records the `since` cursor observed on each call
}

func (f *fakePoller) PollSubjectChanges(
	_ context.Context, since int64, _ int32,
) (changes []subjectchange.SubjectChange, headID int64, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sinces = append(f.sinces, since)
	i := f.calls
	f.calls++
	var scriptedErr error
	if i < len(f.errs) {
		scriptedErr = f.errs[i]
	}
	if scriptedErr != nil {
		return nil, 0, scriptedErr
	}
	var b []int64
	if i < len(f.batches) {
		b = f.batches[i]
	}
	// compute headID as max(ids), or 0 for empty
	var h int64
	out := make([]subjectchange.SubjectChange, 0, len(b))
	for _, id := range b {
		if id > h {
			h = id
		}
		out = append(out, subjectchange.SubjectChange{ID: id})
	}
	return out, h, nil
}

// sinceAt returns the `since` cursor observed on the (0-indexed) n-th poll call.
func (f *fakePoller) sinceAt(n int) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n < 0 || n >= len(f.sinces) {
		return -1
	}
	return f.sinces[n]
}

// deadlinePoller records whether the ctx it was handed carries a deadline.
type deadlinePoller struct {
	seen chan bool // receives ctx.Deadline() ok on the first call
	once sync.Once
}

func (d *deadlinePoller) PollSubjectChanges(
	ctx context.Context, _ int64, _ int32,
) ([]subjectchange.SubjectChange, int64, error) {
	_, ok := ctx.Deadline()
	d.once.Do(func() { d.seen <- ok })
	return nil, 0, nil
}

// TestSubjectChangeWatcher_PollHasPerCallDeadline verifies that each
// PollSubjectChanges call is bounded by a per-call deadline, so a hung iam
// handler cannot stall the whole cross-replica invalidation loop forever.
func TestSubjectChangeWatcher_PollHasPerCallDeadline(t *testing.T) {
	seen := make(chan bool, 1)
	p := &deadlinePoller{seen: seen}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Parent ctx has NO deadline — any deadline observed by the poller must come
	// from the watcher's per-call context.WithTimeout.
	w, err := subjectchange.New(subjectchange.Config{
		Poller: p, Flush: func() {}, Interval: 5 * time.Millisecond, Logger: slog.Default(),
		Closer: noStreams{}, StaleAfter: time.Minute,
	})
	if err != nil {
		t.Fatalf("сборка наблюдателя: %v", err)
	}
	go w.Run(ctx)

	select {
	case ok := <-seen:
		if !ok {
			t.Fatal("PollSubjectChanges was called without a per-call deadline")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("poller was not called within timeout")
	}
	cancel()
}

// script builds a watcher over a scripted poller and returns the poller, a
// pointer to the flush counter, and a function that drives ONE complete poll
// cycle.
//
// The cycle is synchronous, so after the n-th drive() returns, everything the
// n-th tick was ever going to do has been done — nothing here waits, retries or
// budgets, and no assertion below can be read early or late. The interval given
// to New is never consulted: these cases do not run the loop, they run its body.
func script(t *testing.T, batches [][]int64, errs []error) (*fakePoller, *int, func()) {
	t.Helper()
	p := &fakePoller{batches: batches, errs: errs}
	var flushes int
	w, err := subjectchange.New(subjectchange.Config{
		Poller: p, Flush: func() { flushes++ }, Interval: time.Second, Logger: slog.Default(),
		Closer: noStreams{}, StaleAfter: time.Minute,
	})
	if err != nil {
		t.Fatalf("сборка наблюдателя: %v", err)
	}
	return p, &flushes, func() { w.Poll(context.Background()) }
}

// TestSubjectChangeWatcher_PrimingTickDoesNotFlush verifies:
//   - The FIRST (priming) tick — even if non-empty — does NOT flush.
//   - A LATER non-empty tick DOES flush (exactly once for a single non-empty batch).
func TestSubjectChangeWatcher_PrimingTickDoesNotFlush(t *testing.T) {
	// tick0 = {} → priming; tick1 = {1,2,3} → flush.
	p, flushes, tick := script(t, [][]int64{{}, {1, 2, 3}}, nil)

	tick()
	if *flushes != 0 {
		t.Fatalf("the priming tick flushed %d time(s); a cold cache has nothing to invalidate and the "+
			"historical backlog must not be replayed", *flushes)
	}
	tick()

	if *flushes != 1 {
		t.Errorf("expected exactly 1 flush (priming tick contributes 0), got %d", *flushes)
	}
	if p.calls != 2 {
		t.Errorf("expected 2 polls, got %d", p.calls)
	}
}

// TestSubjectChangeWatcher_PrimingNonEmptyStillDoesNotFlush verifies that even
// when the very first poll returns non-empty ids, priming suppresses the flush.
func TestSubjectChangeWatcher_PrimingNonEmptyStillDoesNotFlush(t *testing.T) {
	// tick0 = {10,20} → priming (non-empty!); tick1 = {30} → flush.
	p, flushes, tick := script(t, [][]int64{{10, 20}, {30}}, nil)

	tick()
	if *flushes != 0 {
		t.Fatalf("a non-empty priming tick flushed %d time(s); priming adopts headID as the cursor "+
			"WITHOUT flushing, whatever the first batch contains", *flushes)
	}
	tick()

	if *flushes != 1 {
		t.Errorf("expected exactly 1 flush (non-empty priming tick must not flush), got %d", *flushes)
	}
	// Priming adopted headID=20, so the flushing tick was polled from there.
	if got := p.sinceAt(1); got != 20 {
		t.Errorf("post-priming poll observed since=%d, want 20 (headID adopted by priming)", got)
	}
}

// TestSubjectChangeWatcher_NoFlushWhenAllEmpty verifies no flush when every tick is empty.
func TestSubjectChangeWatcher_NoFlushWhenAllEmpty(t *testing.T) {
	p, flushes, tick := script(t, [][]int64{{}, {}, {}}, nil)

	tick() // prime
	tick()
	tick()

	if *flushes != 0 {
		t.Errorf("expected 0 flushes for all-empty batches, got %d", *flushes)
	}
	if p.calls != 3 {
		t.Errorf("expected 3 polls, got %d", p.calls)
	}
}

// TestSubjectChangeWatcher_PollErrorPreservesCursorNoFlush verifies the
// security-relevant error branch: a poll error must NOT flush and must NOT
// advance the cursor, so the recovered connection replays the backlog missed
// during the outage (revocation propagation to sibling replicas, CWE-613).
//
// Script (cursor starts at 0):
//
//	tick0: {}    -> priming tick, cursor := headID(=0), no flush
//	tick1: {5}   -> flush #1, cursor := 5
//	tick2: ERROR -> no flush, cursor preserved at 5
//	tick3: {6}   -> flush #2, and MUST have been polled with since=5
func TestSubjectChangeWatcher_PollErrorPreservesCursorNoFlush(t *testing.T) {
	p, flushes, tick := script(t,
		[][]int64{{}, {5}, {}, {6}},
		[]error{nil, nil, errors.New("iam blip"), nil})

	tick() // prime
	tick() // flush #1, cursor := 5
	if *flushes != 1 {
		t.Fatalf("premise: the first non-priming non-empty batch must flush once, got %d", *flushes)
	}
	tick() // ERROR
	if *flushes != 1 {
		t.Fatalf("a failed poll flushed: got %d flushes, want the flush count unchanged at 1", *flushes)
	}
	tick() // recovery

	// The errored tick2 was polled at cursor 5 (set by tick1's flush), and the
	// recovery tick3 must STILL poll at 5 — the error did not advance the cursor.
	if got := p.sinceAt(2); got != 5 {
		t.Fatalf("errored poll observed since=%d, want 5 (cursor after tick1 flush)", got)
	}
	if got := p.sinceAt(3); got != 5 {
		t.Fatalf("recovery poll observed since=%d, want 5 (cursor preserved across error)", got)
	}
	if *flushes != 2 {
		t.Fatalf("expected exactly 2 flushes (error must not flush), got %d", *flushes)
	}
}

// TestSubjectChangeWatcher_ErrorOnFirstPollDoesNotPrime verifies that an error
// on the very first poll does NOT prime: priming is deferred to the first
// SUCCESSFUL poll, so the first successful (even non-empty) batch is adopted as
// the cold-start cursor without flushing, and only the NEXT batch flushes.
//
// Script:
//
//	tick0: ERROR -> not primed, cursor stays 0
//	tick1: {7}   -> FIRST successful poll => priming tick, cursor := 7, NO flush
//	tick2: {8}   -> primed now => flush #1, cursor := 8
func TestSubjectChangeWatcher_ErrorOnFirstPollDoesNotPrime(t *testing.T) {
	p, flushes, tick := script(t,
		[][]int64{{}, {7}, {8}},
		[]error{errors.New("iam cold blip"), nil, nil})

	tick() // ERROR — must not prime
	tick() // first SUCCESSFUL poll — deferred priming, no flush
	if *flushes != 0 {
		t.Fatalf("the deferred priming tick flushed %d time(s): an errored first poll must leave the "+
			"watcher unprimed, so the first SUCCESSFUL batch is the one adopted as the cold-start cursor", *flushes)
	}
	tick()

	// The errored first poll must not have primed/advanced: tick1 still polls at 0.
	if got := p.sinceAt(1); got != 0 {
		t.Fatalf("post-error poll observed since=%d, want 0 (error must not prime)", got)
	}
	// Only tick2's {8} flushes; tick1's {7} is the (deferred) priming tick.
	if *flushes != 1 {
		t.Fatalf("expected exactly 1 flush (error-first defers priming to tick1), got %d", *flushes)
	}
}

// noStreams — реестр без открытых потоков.
//
// Не «закрывателя нет»: закрыватель ОБЯЗАТЕЛЕН, и ноль отвергается сборкой. Эти
// пробы про курсор и сброс кэша, поэтому реестр пуст, а не отсутствует.
type noStreams struct{}

func (noStreams) CloseSubject(string) int { return 0 }
func (noStreams) CloseAll() int           { return 0 }
