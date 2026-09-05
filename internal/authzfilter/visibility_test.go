// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzfilter

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeChecker — a per-object oracle over an explicit "<relation>|<object>" set.
// Thread-safe: VisibleSet fans out, and the production port (authzcascade.Client
// over the service's own relational form) is likewise called concurrently.
type fakeChecker struct {
	granted map[string]bool
	err     error
	// sleep — artificial per-Check latency (models a loaded store of any kind), so a
	// test can observe fan-out depth rather than guess at it. The latency is a
	// property of the SHAPE — one question per object — and survived the store moving
	// from another pod into this service's own database: it got smaller, not zero.
	sleep time.Duration

	mu     sync.Mutex
	asked  []string // every (relation, object) pair asked, in completion order
	nCalls atomic.Int64
	// inFlight/maxInFlight — observed concurrency, so a test can PROVE the
	// fan-out stays bounded instead of trusting the constant.
	inFlight    int
	maxInFlight int
}

func newFakeChecker(granted ...string) *fakeChecker {
	g := make(map[string]bool, len(granted))
	for _, k := range granted {
		g[k] = true
	}
	return &fakeChecker{granted: g}
}

func (f *fakeChecker) CheckWithContext(ctx context.Context, _, relation, object string,
	_ map[string]any) (bool, error) {
	f.nCalls.Add(1)

	f.mu.Lock()
	f.inFlight++
	if f.inFlight > f.maxInFlight {
		f.maxInFlight = f.inFlight
	}
	sleep := f.sleep
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inFlight--
		f.mu.Unlock()
	}()

	if sleep > 0 {
		select {
		case <-time.After(sleep):
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	if f.err != nil {
		return false, f.err
	}
	f.mu.Lock()
	f.asked = append(f.asked, relation+"|"+object)
	f.mu.Unlock()
	return f.granted[relation+"|"+object], nil
}

// observedMaxInFlight — peak concurrency seen by the stub.
func (f *fakeChecker) observedMaxInFlight() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxInFlight
}

func (f *fakeChecker) askedSet() map[string]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]bool, len(f.asked))
	for _, a := range f.asked {
		out[a] = true
	}
	return out
}

// The predicate is the UNION viewer ∪ v_list — a v_list-only grant is visible,
// and `v_list` is queried only for what `viewer` denied (cost order).
func TestVisible_ViewerVListUnion(t *testing.T) {
	t.Run("viewer alone suffices and short-circuits v_list", func(t *testing.T) {
		f := newFakeChecker("viewer|iam_role:r1")
		ok, err := Visible(context.Background(), f, "user:u1", "iam_role", "r1")
		require.NoError(t, err)
		assert.True(t, ok)
		assert.False(t, f.askedSet()["v_list|iam_role:r1"],
			"v_list must not be asked once viewer already allowed (cost order)")
	})

	t.Run("v_list-only grant is visible", func(t *testing.T) {
		f := newFakeChecker("v_list|iam_role:r1")
		ok, err := Visible(context.Background(), f, "user:u1", "iam_role", "r1")
		require.NoError(t, err)
		assert.True(t, ok, "an object-only v_list selector grant must resolve visible "+
			"(Design-B: v_* do NOT cascade into viewer)")
	})

	t.Run("neither relation → invisible", func(t *testing.T) {
		f := newFakeChecker()
		ok, err := Visible(context.Background(), f, "user:u1", "iam_role", "r1")
		require.NoError(t, err)
		assert.False(t, ok)
		asked := f.askedSet()
		assert.True(t, asked["viewer|iam_role:r1"] && asked["v_list|iam_role:r1"],
			"both relations must be evaluated before answering invisible")
	})
}

// Fail-closed: a Check error is propagated, never collapsed into a deny — a question
// that could not be answered must surface as UNAVAILABLE, not as a silent permanent
// 404. "Could not ask" and "not allowed" are different worlds.
func TestVisible_CheckError_Propagates(t *testing.T) {
	boom := errors.New("relation form did not answer: connection closed")
	f := newFakeChecker()
	f.err = boom

	ok, err := Visible(context.Background(), f, "user:u1", "iam_role", "r1")
	assert.False(t, ok)
	assert.ErrorIs(t, err, boom, "an unanswered question must propagate, not read as a deny")
}

// Degraded wiring is a deny, not a panic and not an allow.
func TestVisible_DegradedInputs_Deny(t *testing.T) {
	f := newFakeChecker("viewer|iam_role:r1")
	for name, tc := range map[string]struct {
		chk           ObjectChecker
		subj, typ, id string
	}{
		"nil checker":   {nil, "user:u1", "iam_role", "r1"},
		"empty subject": {f, "", "iam_role", "r1"},
		"empty type":    {f, "user:u1", "", "r1"},
		"empty id":      {f, "user:u1", "iam_role", ""},
	} {
		t.Run(name, func(t *testing.T) {
			ok, err := Visible(context.Background(), tc.chk, tc.subj, tc.typ, tc.id)
			require.NoError(t, err)
			assert.False(t, ok, "a degraded input must fail closed")
		})
	}
}

// VisibleSet answers only for the ids given (page-scoped, never the universe),
// deduplicates repeats, and returns a usable non-nil map.
func TestVisibleSet_PageScopedAndDeduplicated(t *testing.T) {
	// The arithmetic below counts relation questions, so the type and its predicate are
	// derived: a literal relation pair would stop describing the cost the moment the
	// predicate changes, and the count would get re-baselined instead of re-derived.
	objType, rels := dearestPredicate()

	f := newFakeChecker(rels[0]+"|"+objType+":a1", rels[len(rels)-1]+"|"+objType+":a3")

	got, err := VisibleSet(context.Background(), f, "user:u1", objType,
		[]string{"a1", "a2", "a3", "a1", "", "a2"})
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"a1": true, "a3": true}, got)

	// a1 costs 1 question (the first relation allows and short-circuits); a2 costs the
	// full predicate (all deny); a3 costs the full predicate (only the last allows).
	// Repeats and "" cost nothing.
	assert.Equal(t, int64(1+2*len(rels)), f.nCalls.Load(),
		"each distinct id is resolved once; duplicates and empties are free")
}

func TestVisibleSet_EmptyInputs(t *testing.T) {
	f := newFakeChecker("viewer|acc:a1")
	for name, ids := range map[string][]string{"nil": nil, "empty": {}, "blank only": {"", ""}} {
		t.Run(name, func(t *testing.T) {
			got, err := VisibleSet(context.Background(), f, "user:u1", "acc", ids)
			require.NoError(t, err)
			require.NotNil(t, got, "the result must be indexable without a nil check")
			assert.Empty(t, got)
		})
	}
}

// Fail-closed on a page: one Check error aborts the whole resolution. A
// partially-resolved set is never returned — it would under-report silently,
// which is the exact failure mode this package exists to remove.
func TestVisibleSet_OneErrorFailsTheWholePage(t *testing.T) {
	boom := errors.New("relation form did not answer: connection closed")
	f := newFakeChecker("viewer|acc:a1")
	f.err = boom

	ids := make([]string, 0, 64)
	for i := 0; i < 64; i++ {
		ids = append(ids, fmt.Sprintf("a%02d", i))
	}
	got, err := VisibleSet(context.Background(), f, "user:u1", "acc", ids)
	assert.ErrorIs(t, err, boom)
	assert.Nil(t, got, "no partial set may escape on a fail-closed path")
}

// Concurrency: a page far larger than DefaultParallelism resolves correctly and
// race-free (run under -race).
func TestVisibleSet_LargePageConcurrent(t *testing.T) {
	const n = 500
	granted := make([]string, 0, n/2)
	ids := make([]string, 0, n)
	want := map[string]bool{}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("obj%04d", i)
		ids = append(ids, id)
		if i%2 == 0 {
			// An unlisted type takes the default predicate, so grant exactly that.
			granted = append(granted, RelationsFor("t")[0]+"|t:"+id)
			want[id] = true
		}
	}
	f := newFakeChecker(granted...)

	got, err := VisibleSet(context.Background(), f, "user:u1", "t", ids)
	require.NoError(t, err)
	assert.Equal(t, want, got, "every id must get its own honest verdict under fan-out")
}

// A parent context that expires mid-page must surface as an error, not as a
// half-resolved "these are the visible ones" answer.
func TestVisibleSet_ParentContextCancelled(t *testing.T) {
	f := newFakeChecker(RelationsFor("t")[0] + "|t:a0")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := VisibleSet(ctx, f, "user:u1", "t", []string{"a0", "a1"})
	assert.ErrorIs(t, err, context.Canceled,
		"an expired request context must not be reported as a resolved visibility set")
	assert.Nil(t, got)
}
