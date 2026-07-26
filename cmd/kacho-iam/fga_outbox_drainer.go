// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"time"

	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"
)

// fgaOutboxTupleKeyColumn is the ORDERING PARTITION key of kacho_iam.fga_outbox:
// the full tuple identity (user, relation, object), materialised into a column by
// migration 0067's BEFORE INSERT trigger and indexed by
// fga_outbox_tuple_head_idx.
//
// It must be the NARROWEST key over which the target's events fail to commute.
// OpenFGA's state is a SET OF TUPLES keyed by the whole triple, so a WRITE and a
// DELETE only conflict when they name the SAME triple; rows that merely share an
// `object` touch different entries and may apply in any order. Partitioning on
// payload->>'object' (as this did until migration 0067) therefore serialised a
// revoke behind every unrelated grant queued earlier against the same object —
// measured on a live stand: 8 643 pending rows over 1 439 objects but 8 641
// distinct tuples, one revoke behind up to 632 same-object predecessors while its
// own tuple had at most 3.
const fgaOutboxTupleKeyColumn = "tuple_key"

// fgaOutboxApplyConcurrency is how many rows of one claim batch are applied to
// OpenFGA in parallel.
//
// It is bounded by TWO things, and as of migration 0067 only one of them binds.
//
//   - Claimable partition HEADS. The claim takes at most one row per partition, so
//     concurrency above the number of heads buys nothing. This used to bind: sampled
//     live during a packed run under the OLD object-keyed partition, the pending
//     queue offered 13 / 99 / 77 / 13 heads — REPEATEDLY FEWER THAN 16 — while the
//     same instants offered 136 / 1286 / 808 / 103 TUPLE heads. The wide key was
//     starving the apply wave, so the fan-out was nominal. Narrowing the key
//     (migration 0067) removed that limit.
//
//   - What OpenFGA will absorb. This is what binds now, and it is why the number is
//     16 rather than something larger. Measured on the stand with an identical
//     synthetic 20 000-row burst and no competing producer, drained end to end:
//
//     ApplyConcurrency = 16  →  448 rows/s  (45 s), 0 retries
//     ApplyConcurrency = 48  →  403 rows/s  (50 s), 0 retries
//
//     More fan-out is slightly WORSE, so the ceiling is downstream (OpenFGA and its
//     Postgres), not this fan-out. Raising this number does not buy drain rate; it
//     only adds contention. If the residual materialization lag under a packed burst
//     needs to come down further, the lever is OpenFGA-side capacity or producer
//     volume — NOT this constant.
//
// Ordering is independent of this value: the partition-head predicate admits at
// most one row per tuple into any batch, cross-batch and cross-replica alike (see
// drainer.Config.PartitionColumn). Changing it widens or narrows the wave, never the
// ordering window. The connection pool must stay sized above it — see
// clients.fgaMaxIdleConnsPerHost, otherwise each wave re-handshakes most of its
// connections.
const fgaOutboxApplyConcurrency = 16

// fgaOutboxDrainerConfig is the drainer configuration for kacho_iam.fga_outbox.
//
// Extracted from the wiring so the two settings that carry the ordering contract
// — ApplyConcurrency and PartitionColumn — are assertable without standing up a
// server (fga_outbox_drainer_test.go). They are a PAIR: raising concurrency
// without the partition key reorders non-commutative rows, and the partition key
// alone leaves the drain single-file.
func fgaOutboxDrainerConfig() drainer.Config {
	return drainer.Config{
		Table:   "kacho_iam.fga_outbox",
		Channel: "kacho_iam_fga_outbox",
		// Matches ApplyConcurrency: with ApplyConcurrency>1 the claim batch is sized
		// EXACTLY to the concurrency, so a differing BatchSize would only mislead.
		BatchSize:    fgaOutboxApplyConcurrency,
		PollFallback: 30 * time.Second,
		MaxAttempts:  10,
		BackoffMin:   1 * time.Second,
		BackoffMax:   30 * time.Second,
		ApplyTimeout: 5 * time.Second,
		// Order-preserving concurrent drain. iam's fga_outbox carries BOTH tuple
		// WRITES (grant / label-register) AND DELETES (revoke / label-remove /
		// delete-stale) of the SAME (user,relation,object) — NOT commutative.
		// ApplyConcurrency>1 alone does NOT preserve order (and the claim
		// ORDER BY (attempt_count,id) splits a bumped WRITE and a fresh DELETE into
		// different batches), so a naive N=16 let a DELETE apply before its
		// predecessor WRITE → delete-before-write → the tuple survives the revoke →
		// authz OVER-GRANT / cross-account leak (observed: authz-deny + iam-role
		// foreign-Get 200-not-404). PartitionColumn makes the claim
		// partition-head-only: a row is never claimed while a DELIVERABLE
		// same-TUPLE predecessor with a smaller id is unsent, so per-tuple FIFO holds
		// cross-batch AND cross-replica and at most one row per tuple is in flight —
		// safe to raise the revoke/membership drain to N=16. Requires migration
		// 0067's partial index (tuple_key,id) WHERE sent_at IS NULL for the claim's
		// NOT EXISTS, and migration 0063's (attempt_count,id) for its outer ordered
		// scan. See drainer.Config.PartitionColumn.
		ApplyConcurrency: fgaOutboxApplyConcurrency,
		PartitionColumn:  fgaOutboxTupleKeyColumn,
		// Per-partition head-of-line wedge attribution: a persistently-transient
		// tuple head blocks its successors until the peer recovers (temporary, by
		// design — leak-safety over per-partition liveness). WedgeWarnAfter surfaces
		// WHICH tuple is stuck, beyond the table-wide oldest-pending-age gauge.
		WedgeWarnAfter: 60 * time.Second,
	}
}
