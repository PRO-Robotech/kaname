// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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
// iam does NOT share the sibling services' regression: it never batched, and it
// already fans out over a BOUNDED worker pool (DefaultParallelism), so no request
// serialises a page into one round-trip per chunk. This test pins the two
// properties that keep it that way, because both are exactly what regressed
// elsewhere:
//
//  1. the fan-out stays bounded (never goroutine-per-id — a 1000-id page must not
//     put 1000 requests on the OpenFGA client at once; `http.DefaultClient`'s
//     transport keeps only a couple of idle conns per host, so an unbounded burst
//     would thrash connections rather than go faster);
//  2. a max-size page still resolves in bounded-parallel waves, not sequentially.
func TestVisibleSet_MaxPageBoundedFanOut(t *testing.T) {
	pageSize := int(validate.MaxPageSize)
	const perCheckLatency = 2 * time.Millisecond

	granted := make([]string, 0, pageSize)
	ids := make([]string, 0, pageSize)
	want := map[string]bool{}
	for i := 0; i < pageSize; i++ {
		id := fmt.Sprintf("obj%04d", i)
		ids = append(ids, id)
		switch i % 3 {
		case 0:
			granted = append(granted, "viewer|t:"+id)
			want[id] = true
		case 1:
			granted = append(granted, "v_list|t:"+id)
			want[id] = true
		}
	}
	f := newFakeChecker(granted...)
	f.sleep = perCheckLatency

	t0 := time.Now()
	got, err := VisibleSet(context.Background(), f, "user:u1", "t", ids)
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
