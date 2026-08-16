// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/fga_outbox"
)

// TestFGAOutboxDrainerConfig_PartitionsOnTheGrantNotTheObject pins the two
// settings of the fga_outbox drainer that carry the ordering contract, because
// they are only correct TOGETHER and each has a plausible-looking wrong value.
//
// ApplyConcurrency>1 without PartitionColumn reorders non-commutative rows: the
// claim's ORDER BY (attempt_count, id) puts a transiently-bumped WRITE behind a
// fresh DELETE of the same tuple, the DELETE applies first, and the tuple survives
// the revoke — the caller keeps access it was just denied.
//
// PartitionColumn wider than the row's unit is the opposite failure: it is SAFE but
// serialises rows that commute. Partitioning on payload->>'object' made every revoke
// queue behind every unrelated grant on the same object — measured on a live stand:
// 8 643 pending rows over 1 439 objects but 8 641 distinct tuples, one revoke waiting
// on up to 632 same-object predecessors while its own tuple had at most 3. Under
// packed e2e load that pushed revoke visibility to ~30 s average / 49 s worst against
// a 15 s probe budget.
//
// The key is (user, object) — the GRANT — because that is what a row now IS: one
// subject's whole relation set on one object, carried together so the set cannot be
// observed half present (migration 0098, fga_outbox.emitTx). The object key's cost
// does not come back with it: different SUBJECTS on one object stay in different
// partitions, and it is those that the measurement above was about.
//
// The value must stay a plain column (`tuple_key`, populated by a trigger — the name
// is historical, see the migration) rather than an inline jsonb expression: the
// claim's correlated NOT EXISTS needs a matching partial index, and a column key
// keeps that index a plain btree the planner cannot fail to match.
func TestFGAOutboxDrainerConfig_PartitionsOnTheGrantNotTheObject(t *testing.T) {
	cfg := fgaOutboxDrainerConfig()

	require.Equal(t, "tuple_key", cfg.PartitionColumn,
		"the fga_outbox ordering partition must be the GRANT identity (user, object), "+
			"which is what one row carries. An empty value drops ordering entirely "+
			"(delete-before-write → the revoked tuple survives); a NARROWER key splits one "+
			"row's own set across partitions so a revoke can overtake its grant; a wider "+
			"key such as payload->>'object' keeps ordering but serialises rows of "+
			"different subjects, which commute.")

	require.Equal(t, fga_outbox.PartitionColumn, cfg.PartitionColumn,
		"the column must be named by the package that owns the row's shape: the emitter "+
			"decides what a row is, and a partition that stopped matching that unit "+
			"reorders rows that must not overtake each other, silently.")

	assert.Greater(t, cfg.ApplyConcurrency, 1,
		"ApplyConcurrency must stay >1: the partition predicate serialises only WITHIN a "+
			"grant, and the whole point of it is to make concurrent drain safe. At 1 the "+
			"drain is single-file and the revoke lag returns by a different route.")

	// The claim batch is sized EXACTLY to ApplyConcurrency, so a BatchSize that
	// disagrees is a config that documents something the drainer does not do.
	assert.Equal(t, cfg.ApplyConcurrency, cfg.BatchSize,
		"BatchSize must equal ApplyConcurrency: with ApplyConcurrency>1 the claim LIMIT is "+
			"the concurrency, and BatchSize only feeds the sequential path")

	// The partition key is only usable if it names this table's column set, and the
	// wedge observer is the only per-partition visibility into the head-of-line
	// trade-off the predicate deliberately accepts.
	assert.Equal(t, "kacho_iam.fga_outbox", cfg.Table)
	assert.Equal(t, "kacho_iam_fga_outbox", cfg.Channel)
	assert.Positive(t, cfg.WedgeWarnAfter,
		"a blocked partition head is invisible without per-partition wedge attribution: "+
			"the table-wide oldest-pending gauge says the queue is stuck, not WHICH tuple "+
			"is stuck.")
}
