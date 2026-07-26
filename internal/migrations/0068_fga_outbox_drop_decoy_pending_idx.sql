-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- Drop fga_outbox_pending_idx — the (created_at) WHERE sent_at IS NULL index from
-- migration 0001. It serves no query, and its mere EXISTENCE is what lets the
-- planner build the O(backlog) claim that migrations 0061/0063/0064 were meant to
-- eliminate.
--
-- WHY (this is a plan fix, not tidying)
--
-- The drainer's claim is
--
--   SELECT t.id FROM kacho_iam.fga_outbox t
--    WHERE t.sent_at IS NULL AND t.attempt_count < $max
--      AND NOT EXISTS (SELECT 1 FROM kacho_iam.fga_outbox p
--                       WHERE p.sent_at IS NULL AND p.attempt_count < $max
--                         AND p.id < t.id AND p.tuple_key = t.tuple_key)
--    ORDER BY t.attempt_count, t.id
--    FOR UPDATE OF t SKIP LOCKED
--    LIMIT $n
--
-- Its whole efficiency rests on the LIMIT stopping an INDEX-ORDERED outer scan
-- after the first handful of partition heads (migration 0063 supplies that order).
-- A queue table, however, is empty almost all of the time, so its last ANALYZE
-- almost always ran on an empty backlog and the estimate it carries INTO a burst is
-- `rows=1`. On a one-row estimate a Sort is free — so the planner happily picks
--
--   Index Scan (created_at) -> Sort -> LockRows -> Limit
--
-- because THIS index offers a cheap-looking scan of the pending rows in the wrong
-- order. That plan cannot stop early: the Sort must materialise the WHOLE pending
-- set first, so the anti-join runs once per pending row and the claim's cost
-- becomes quadratic in the backlog. Migration 0063's ordering index is present and
-- simply not chosen.
--
-- Measured on a live stand (Postgres 16, kacho_iam.fga_outbox, 8 600 pending rows,
-- statistics gathered while the queue was empty — the SAME claim statement,
-- differing only in whether this index exists):
--
--     this index present    6 990 ms per claim   (62M rows removed by join filter)
--     this index dropped       29 ms per claim   (204x faster)
--
-- and at 32 000 pending rows with the index dropped, still 125 ms stale / 0.17 ms
-- once autovacuum re-analyzes. The consequence in production was directly
-- observable in the drainer's own output: it applied exactly one 16-row batch every
-- ~11.5 s for 46 s — 1.4 rows/s — and then jumped to ~600 rows/s the instant
-- autovacuum finally re-analyzed the table. Revokes enqueued behind that stall
-- reached OpenFGA after 30 s on average (49 s worst) against a 15 s e2e probe
-- budget, which is the `post-revoke-deny` red under packed load.
--
-- Migration 0064 attacks the same problem from the statistics side (analyze every
-- ~1000 modifications), and it is necessary — but autovacuum_naptime is 1 min
-- cluster-wide, so the launcher can only react up to a minute after the burst
-- starts. 0064 shortens the bad window; removing the decoy removes the bad PLAN, so
-- the window costs 125 ms per claim instead of 7 000 ms.
--
-- NOTHING READS IT
--
--   * the claim — never used it as intended; it was only ever the decoy above;
--   * the oldest-pending-age metric (pkg/outbox/metrics) — aggregates the WHOLE
--     table with FILTER clauses and no WHERE, so it seq-scans regardless;
--   * the per-partition wedge scan (pkg/outbox/drainer) — groups by the partition
--     key and is served by fga_outbox_tuple_head_idx.
--
-- Re-measured after the drop, at 32 000 pending: oldest-pending metric 3.9 ms,
-- wedge scan 17.5 ms — both served from the remaining partial indexes.
--
-- The general rule now lives in pkg/outbox/drainer Config.PartitionColumn: an
-- outbox table carries EXACTLY TWO partial indexes over `sent_at IS NULL` —
-- (partition_key, id) and (attempt_count, id) — and NO OTHER, because any further
-- ordering over the pending rows is a decoy the planner will take under
-- empty-queue statistics. Locked by
-- pkg/outbox/drainer Test_ClaimPlan_StaleStatistics_DoesNotCollapse and by the
-- iam-side index-set test.

DROP INDEX IF EXISTS kacho_iam.fga_outbox_pending_idx;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

CREATE INDEX IF NOT EXISTS fga_outbox_pending_idx
    ON kacho_iam.fga_outbox (created_at)
    WHERE sent_at IS NULL;

-- +goose StatementEnd
