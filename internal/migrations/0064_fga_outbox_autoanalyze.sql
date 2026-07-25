-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- Keep planner statistics fresh on the fga_outbox queue table. Second half of the
-- claim-throughput fix; migration 0063 (the ordering index) does not land without
-- it.
--
-- WHY: the drainer's partition-head-only claim filters on `sent_at IS NULL`, and
-- the planner's row estimate for that predicate comes from the LAST ANALYZE. A
-- queue table is empty most of the time, so the last analyze almost always
-- happened while the backlog was ZERO — and the estimate the planner carries into
-- a burst is therefore `rows=1`. On a one-row estimate it discards both partial
-- indexes 0061/0063 provide and picks a nested loop over
-- fga_outbox_pending_idx(created_at), re-scanning the pending set once per
-- candidate row.
--
-- Measured on a live stand, the SAME claim statement against the SAME table,
-- differing only in statistics freshness:
--
--     backlog   stale stats (last ANALYZE on empty queue)   after ANALYZE
--       2 495                                   4 488 ms
--       7 849                                                      3.6 ms
--
-- i.e. a stale-stats plan is ~1000x slower on a DEEPER backlog, and it re-creates
-- exactly the O(backlog) claim 0063 was meant to remove. The index alone is
-- necessary but NOT sufficient: the planner has to be able to see that the
-- pending set is large enough to be worth an ordered index scan.
--
-- Autovacuum's default analyze trigger is `50 + 0.1 * n_live_tup`. fga_outbox is
-- append-mostly and long-lived, so on the measured stand that threshold was
-- ~21 751 modifications — far larger than an entire e2e burst. Statistics
-- therefore stayed frozen at "queue is empty" across the whole burst, which is
-- precisely when the good plan matters.
--
-- WHAT: per-table autovacuum settings that decouple the trigger from table SIZE
-- and tie it to ABSOLUTE churn (scale_factor = 0 + fixed threshold), the standard
-- treatment for a queue table:
--
--   * analyze every ~1000 modifications — at the measured peak producer rate
--     (~150 rows/s) that bounds statistics staleness to ~7 s of burst instead of
--     an entire run. ANALYZE on this table samples a fixed 30 000 rows
--     (default_statistics_target 100) and costs tens of ms, so the trade is
--     strongly favourable.
--   * vacuum every ~1000 dead tuples — the drainer UPDATEs every row once to set
--     sent_at, so each drained row leaves a dead tuple. Reclaiming them promptly
--     keeps BOTH partial indexes (`WHERE sent_at IS NULL`) tracking the live
--     backlog rather than accumulating dead entries the claim must skip past.
--
-- Catalog-only change: takes a brief lock, rewrites nothing, and does not alter
-- query semantics — only how often the statistics behind the plan are refreshed.
ALTER TABLE kacho_iam.fga_outbox SET (
    autovacuum_analyze_scale_factor = 0.0,
    autovacuum_analyze_threshold    = 1000,
    autovacuum_vacuum_scale_factor  = 0.0,
    autovacuum_vacuum_threshold     = 1000
);

-- Seed the statistics immediately: without this the first burst after deploy still
-- runs on whatever stale snapshot the table carried, since autovacuum only
-- reacts to churn that happens AFTER this migration.
ANALYZE kacho_iam.fga_outbox;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE kacho_iam.fga_outbox RESET (
    autovacuum_analyze_scale_factor,
    autovacuum_analyze_threshold,
    autovacuum_vacuum_scale_factor,
    autovacuum_vacuum_threshold
);

-- +goose StatementEnd
