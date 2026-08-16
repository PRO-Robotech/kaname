// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"time"

	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"
)

// Coordinates of the tuple outbox. Named once so the drainer that empties it and
// the scanner that reports its state cannot end up talking about different tables
// — the failure mode of two literals is a gauge that looks healthy because it is
// measuring something else.
const (
	fgaOutboxTable   = "kacho_iam.fga_outbox"
	fgaOutboxChannel = "kacho_iam_fga_outbox"
)

// fgaOutboxGrantKeyColumn is the ORDERING PARTITION key of kacho_iam.fga_outbox:
// the GRANT identity (user, object), materialised into a column by the table's
// BEFORE INSERT trigger (migration 0098) and indexed by fga_outbox_tuple_head_idx.
//
// It is a LITERAL here, deliberately, and not an alias of the emitter's constant: the
// tree gate that checks every drained queue declares an ordering key resolves it by
// PARSING THE SOURCE, and a cross-package reference is indistinguishable to it from no
// key at all — the queue would drop out of that check silently. Drift against the
// emitter is caught instead by a paired probe that reads BOTH values
// (fga_outbox_drainer_test.go), which is the same arrangement the redrive backstop
// already uses for the same reason.
//
// It must be the NARROWEST key over which the target's events fail to commute, and
// what that is depends on what a row carries. A row carries one subject's WHOLE
// relation set on one object (fga_outbox.emitTx), because the row is the unit that
// reaches OpenFGA atomically and a set split across rows is a grant observed half
// present. Two such rows fail to commute when their sets intersect — that is
// (user, object).
//
// This is NOT a retreat to the object key migration 0067 removed. 0067's measured
// cost was DIFFERENT SUBJECTS on one object serialising against each other (a revoke
// behind up to 632 same-object predecessors while its own tuple had at most 3);
// different subjects stay in different partitions here. What merges is one subject's
// own relations — the rows that must be ordered — and the emitter no longer writes
// them separately.
const fgaOutboxGrantKeyColumn = "tuple_key"

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
//     (migration 0067) removed that limit. Migration 0098 widened it again to the
//     GRANT — one head per (subject, object) rather than per tuple — which sits
//     between the two shapes measured above and was NOT re-measured on a stand;
//     what is known is that it is bounded below by the object-key head count.
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
// most one row per grant into any batch, cross-batch and cross-replica alike (see
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
		Table:   fgaOutboxTable,
		Channel: fgaOutboxChannel,
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
		// delete-stale) of the SAME (user,object) grant — NOT commutative.
		// ApplyConcurrency>1 alone does NOT preserve order (and the claim
		// ORDER BY (attempt_count,id) splits a bumped WRITE and a fresh DELETE into
		// different batches), so a naive N=16 let a DELETE apply before its
		// predecessor WRITE → delete-before-write → the tuple survives the revoke →
		// authz OVER-GRANT / cross-account leak (observed: authz-deny + iam-role
		// foreign-Get 200-not-404). PartitionColumn makes the claim
		// partition-head-only: a row is never claimed while a DELIVERABLE
		// same-GRANT predecessor with a smaller id is unsent, so per-grant FIFO holds
		// cross-batch AND cross-replica and at most one row per grant is in flight —
		// safe to raise the revoke/membership drain to N=16. Requires migration
		// 0067's partial index (tuple_key,id) WHERE sent_at IS NULL for the claim's
		// NOT EXISTS, and migration 0063's (attempt_count,id) for its outer ordered
		// scan. See drainer.Config.PartitionColumn.
		ApplyConcurrency: fgaOutboxApplyConcurrency,
		PartitionColumn:  fgaOutboxGrantKeyColumn,
		// Per-partition head-of-line wedge attribution: a persistently-transient
		// grant head blocks its successors until the peer recovers (temporary, by
		// design — leak-safety over per-partition liveness). WedgeWarnAfter surfaces
		// WHICH grant is stuck, beyond the table-wide oldest-pending-age gauge.
		WedgeWarnAfter: 60 * time.Second,
	}
}
