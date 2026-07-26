// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFGAOutboxDrainerConfig_PartitionsOnTheTupleNotTheObject pins the two
// settings of the fga_outbox drainer that carry the ordering contract, because
// they are only correct TOGETHER and each has a plausible-looking wrong value.
//
// ApplyConcurrency>1 without PartitionColumn reorders non-commutative rows: the
// claim's ORDER BY (attempt_count, id) puts a transiently-bumped WRITE behind a
// fresh DELETE of the same tuple, the DELETE applies first, and the tuple survives
// the revoke — the caller keeps access it was just denied.
//
// PartitionColumn wider than the tuple is the opposite failure and the one this
// test exists for: it is SAFE but serialises rows that commute. OpenFGA keys its
// state by the whole (user, relation, object) triple, so rows sharing only an
// `object` are independent entries. Partitioning on payload->>'object' therefore
// made every revoke queue behind every unrelated grant on the same object —
// measured on a live stand: 8 643 pending rows over 1 439 objects but 8 641
// distinct tuples, one revoke waiting on up to 632 same-object predecessors while
// its own tuple had at most 3. Under packed e2e load that pushed revoke visibility
// to ~30 s average / 49 s worst against a 15 s probe budget.
//
// The value must stay a plain column (migration 0067's `tuple_key`, populated by a
// trigger) rather than an inline jsonb expression: the claim's correlated
// NOT EXISTS needs a matching partial index, and a column key keeps that index a
// plain btree the planner cannot fail to match.
func TestFGAOutboxDrainerConfig_PartitionsOnTheTupleNotTheObject(t *testing.T) {
	cfg := fgaOutboxDrainerConfig()

	require.Equal(t, "tuple_key", cfg.PartitionColumn,
		"the fga_outbox ordering partition must be the FULL tuple identity "+
			"(user, relation, object) materialised by migration 0067 into `tuple_key`. "+
			"An empty value drops ordering entirely (delete-before-write → the revoked "+
			"tuple survives); a wider key such as payload->>'object' keeps ordering but "+
			"serialises rows that commute, so a revoke waits behind every unrelated grant "+
			"on the same object.")

	assert.Greater(t, cfg.ApplyConcurrency, 1,
		"ApplyConcurrency must stay >1: the partition predicate serialises only WITHIN a "+
			"tuple, and the whole point of it is to make concurrent drain safe. At 1 the "+
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
