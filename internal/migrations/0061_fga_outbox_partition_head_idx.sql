-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- Partial index supporting the fga_outbox drainer's partition-head-only CLAIM
-- (corelib drainer Config.PartitionColumn = 'payload->>'object'').
--
-- WHY: iam's fga_outbox carries BOTH tuple WRITES (grant / label-register) AND
-- DELETES (revoke / delete-stale) of the SAME (user,relation,object). These are
-- NOT commutative, so the drainer runs order-preserving concurrent (ApplyConcurrency=16
-- + PartitionColumn): the claim refuses to take a row whose partition
-- (payload->>'object') has a DELIVERABLE (sent_at IS NULL AND attempt_count <
-- MaxAttempts) predecessor with a smaller id, via
--
--   AND NOT EXISTS (SELECT 1 FROM kacho_iam.fga_outbox p
--                    WHERE p.sent_at IS NULL AND p.attempt_count < $max
--                      AND p.id < t.id
--                      AND p.payload->>'object' = t.payload->>'object')
--
-- Without an index this correlated NOT EXISTS is a seq-scan per candidate row on
-- every claim — quadratic under a backlog. This index makes it an index-only
-- lookup: seek to the object key, then range-scan ids < t.id.
--
-- WHAT: btree on ((payload->>'object'), id), PARTIAL on sent_at IS NULL so its
-- size tracks only the PENDING backlog (drained rows fall out), never the whole
-- (append-mostly) table. The expression key matches Config.PartitionColumn
-- byte-for-byte; the trailing id column serves the `p.id < t.id` range and the
-- ORDER BY (…, id) tie-break.
--
-- Plain (in-tx) CREATE INDEX IF NOT EXISTS, matching the table's sibling index
-- migrations (0001 fga_outbox_pending_idx). The pending backlog is small on a
-- healthy stand; on a matured cluster where the build's brief table write-lock
-- stalls the drainer/writers, switch to CREATE INDEX CONCURRENTLY (needs the
-- goose NO-TRANSACTION directive, keep IF NOT EXISTS) — same escape hatch noted
-- on migration 0054.
CREATE INDEX IF NOT EXISTS fga_outbox_partition_head_idx
    ON kacho_iam.fga_outbox ((payload->>'object'), id)
    WHERE sent_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS kacho_iam.fga_outbox_partition_head_idx;

-- +goose StatementEnd
