-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- Index for the OUTER ordered scan of the fga_outbox drainer's claim. Completes
-- migration 0061, which supplied only the index for the claim's correlated
-- NOT EXISTS.
--
-- WHY: the partition-head-only claim (corelib drainer, Config.PartitionColumn =
-- payload->>'object') reads
--
--   SELECT t.id FROM kacho_iam.fga_outbox t
--    WHERE t.sent_at IS NULL AND t.attempt_count < $max
--      AND NOT EXISTS (SELECT 1 FROM kacho_iam.fga_outbox p
--                       WHERE p.sent_at IS NULL AND p.attempt_count < $max
--                         AND p.id < t.id
--                         AND p.payload->>'object' = t.payload->>'object')
--    ORDER BY t.attempt_count, t.id
--    FOR UPDATE OF t SKIP LOCKED
--    LIMIT $n
--
-- 0061 indexed the inner predecessor lookup, but nothing could produce the OUTER
-- `ORDER BY (attempt_count, id)` over the pending rows. With no ordered access
-- path Postgres never reaches the nested-loop anti-join 0061 was built for: it
-- seq-scans the WHOLE pending backlog, sorts it, and hash-anti-joins it against a
-- second full seq-scan of the same backlog — leaving 0061's index unused and the
-- claim O(backlog).
--
-- That shape is a throughput INVERSION, not merely slowness: the deeper the
-- queue, the slower each claim, the slower the drain, the deeper the queue. A
-- producer only marginally faster than the consumer diverges without bound
-- instead of settling at a small standing lag. Measured on a live stand
-- (Postgres 16, real fga_outbox rows), one claim:
--
--     backlog     without this index     with this index
--       5 000              11.7 ms              0.81 ms
--      10 000              28.2 ms              0.66 ms
--      20 000              61.6 ms              0.72 ms
--      40 000             105.7 ms              0.75 ms
--      80 000             327.0 ms              0.82 ms
--
-- On the e2e run this let a ~150 rows/s producer outrun a ~147 rows/s consumer
-- into a 70+ second materialization lag — long enough for a first repository
-- create to answer 404 for 64 s while the api-gateway scope-extractor could not
-- yet resolve it to a project.
--
-- WHAT: btree on (attempt_count, id) — exactly the claim's ORDER BY, so the scan
-- is index-ordered and the LIMIT stops it after the first few partition heads
-- instead of after the whole backlog. PARTIAL on sent_at IS NULL so its size
-- tracks only the PENDING backlog (drained rows fall out of the index), never the
-- append-mostly table. attempt_count leads because the claim orders by it first
-- (transient-retry fairness: a freshly enqueued attempt_count=0 row must not be
-- shadowed by capped, repeatedly-failing rows).
--
-- Behaviour is UNCHANGED: same claim statement, same partition-head semantics,
-- same per-partition FIFO. Only the access path changes. Locked by
-- pkg/outbox/drainer Test_ClaimPlan_DoesNotScaleWithBacklogDepth (rows examined
-- must not track backlog depth) and by the iam-side index-presence test.
--
-- Plain (in-tx) CREATE INDEX IF NOT EXISTS, matching the table's sibling index
-- migrations (0001 fga_outbox_pending_idx, 0061 fga_outbox_partition_head_idx).
-- The pending backlog is small on a healthy stand; on a matured cluster where the
-- build's brief table write-lock would stall the drainer/writers, switch to
-- CREATE INDEX CONCURRENTLY (needs the goose NO-TRANSACTION directive, keep
-- IF NOT EXISTS) — same escape hatch noted on migrations 0054 and 0061.
CREATE INDEX IF NOT EXISTS fga_outbox_claim_order_idx
    ON kacho_iam.fga_outbox (attempt_count, id)
    WHERE sent_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS kacho_iam.fga_outbox_claim_order_idx;

-- +goose StatementEnd
