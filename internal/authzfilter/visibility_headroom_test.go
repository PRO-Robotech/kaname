// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzfilter

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/validate"
)

// TestVisibleSet_MaxPageBoundedFanOut — the iam counterpart of the vpc/compute/nlb
// list-filter headroom lock.
//
// The siblings' regression was serialising a page into one round-trip per chunk.
// iam cannot regress that way for a reason that is not a virtue: it does not batch
// at all, so there are no chunks — it asks one question per (object, relation) and
// fans those out over a BOUNDED worker pool (DefaultParallelism). This test pins
// the two properties of that fan-out:
//
//  1. the fan-out stays bounded (never goroutine-per-id — a 1000-id page must not
//     put 1000 questions in flight at once). This used to be argued from a named
//     connection-pool size on the HTTP client for the external engine; that client
//     is gone (stage S6) and so is the constant, so the argument is restated from
//     what remains and is not weaker for it: every question is a query, the pool it
//     contends for is now the service's own database pool, and an unbounded burst
//     exhausts a bounded pool whatever is on the other side of it. Naming a number
//     that no longer exists would have been a reason nobody could check;
//  2. a max-size page still resolves in bounded-parallel waves, not sequentially.
//
// What this test does NOT establish is what a page COSTS. It measures a MIXED page
// — a third of it resolves on the first relation — so it observes 1666 questions
// where the contract permits 2000, and it asserts wall time against a stub rather
// than against a network. The ceiling is stated as a count in
// TestVisibleSet_WorstCasePageCost: "bounded" and "cheap" are different claims,
// and only the first one is tested here.
func TestVisibleSet_MaxPageBoundedFanOut(t *testing.T) {
	pageSize := int(validate.MaxPageSize)
	const perCheckLatency = 2 * time.Millisecond

	// A MIXED page needs a type whose predicate asks more than one relation, so the
	// type is DERIVED rather than named: a literal would silently stop being mixed the
	// moment its predicate is narrowed, and the "1666 of a permitted 2000" shape stated
	// above would quietly become a different measurement wearing the same words.
	objType, rels := dearestPredicate()

	granted := make([]string, 0, pageSize)
	ids := make([]string, 0, pageSize)
	want := map[string]bool{}
	for i := 0; i < pageSize; i++ {
		id := fmt.Sprintf("obj%04d", i)
		ids = append(ids, id)
		switch i % 3 {
		case 0: // resolves on the FIRST relation asked — one question
			granted = append(granted, rels[0]+"|"+objType+":"+id)
			want[id] = true
		case 1: // resolves only on the LAST — the full per-object price
			granted = append(granted, rels[len(rels)-1]+"|"+objType+":"+id)
			want[id] = true
		}
	}
	f := newFakeChecker(granted...)
	f.sleep = perCheckLatency

	t0 := time.Now()
	got, err := VisibleSet(context.Background(), f, "user:u1", objType, ids)
	elapsed := time.Since(t0)

	require.NoError(t, err)
	assert.Equal(t, want, got, "every id must get its own honest verdict under fan-out")

	maxInFlight := f.observedMaxInFlight()
	assert.LessOrEqual(t, maxInFlight, DefaultParallelism,
		"fan-out must stay inside the worker pool, never goroutine-per-id")
	assert.Greater(t, maxInFlight, 1, "a max-size page must actually fan out, not run serially")

	checks := f.nCalls.Load()
	// Sequential worst case is checks × latency; bounded-parallel must beat it by
	// roughly the pool size. Half of it is a loose, non-flaky bound.
	sequentialWall := time.Duration(checks) * perCheckLatency
	assert.Less(t, elapsed, sequentialWall/2,
		"page must resolve in bounded-parallel waves (sequential wall would be %s)", sequentialWall)

	t.Logf("page=%d ids | checks=%d | parallelism bound=%d | observed max in-flight=%d | "+
		"per-check latency=%s | sequential wall=%s | MEASURED elapsed=%s | depth=%d waves",
		pageSize, checks, DefaultParallelism, maxInFlight, perCheckLatency,
		sequentialWall, elapsed.Round(time.Millisecond),
		(int(checks)+DefaultParallelism-1)/DefaultParallelism)
}
