-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- Narrow the fga_outbox drainer's ORDERING PARTITION from the object to the FULL
-- TUPLE (user, relation, object) — the narrowest key over which the target's
-- events actually fail to commute.
--
-- WHY
--
-- The drainer runs order-preserving concurrent (ApplyConcurrency=16 +
-- Config.PartitionColumn): the claim refuses to take a row whose partition has a
-- DELIVERABLE (sent_at IS NULL AND attempt_count < MaxAttempts) predecessor with a
-- smaller id. That predicate is what keeps a revoke (DELETE) from applying before
-- the grant (WRITE) it supersedes — without it the tuple survives the revoke and
-- the caller keeps access (authz over-grant, migration 0061).
--
-- The predicate is correct; its KEY was too wide. OpenFGA's state is a SET OF
-- TUPLES keyed by the whole (user, relation, object) triple, so two rows that
-- merely share an object touch DIFFERENT entries and commute freely: writing
-- (user:a, v_get, project:P) and deleting (user:b, v_get, project:P) may be applied
-- in either order with the same final state. Partitioning on payload->>'object'
-- nevertheless lumped every subject of one object into ONE ordering chain, so a
-- revoke had to wait for every unrelated grant queued earlier against the same
-- object — pure over-serialisation, no correctness bought.
--
-- Measured on a live stand during a packed e2e run (kind, Postgres 16, real rows):
--
--     pending rows           8 643
--     distinct objects       1 439   <- claimable heads under the OLD key
--     distinct tuples        8 641   <- claimable heads under the NEW key
--     same-OBJECT predecessors ahead of one revoke:  avg 157, max 632
--     same-TUPLE  predecessors ahead of one revoke:  avg 0.87, max 3
--
-- i.e. a revoke was made to wait on ~180x more predecessors than its own ordering
-- requires, and the claim discarded ~3 of every 4 rows it examined as "not a
-- partition head" (68 candidates scanned to find 16 claimable, versus exactly 16
-- under the tuple key).
--
-- WHAT
--
-- A `tuple_key` column carrying `user || ' ' || relation || ' ' || object`,
-- populated by a BEFORE INSERT trigger (single source of truth for ALL ten emit
-- sites: the Go emitters, the access_binding writer, the seed backfill and the
-- data migrations), plus the partial index the claim's correlated NOT EXISTS needs
-- over it. The space separator matches OpenFGA's canonical `user relation object`
-- rendering and keeps the per-partition wedge WARN readable; OpenFGA forbids
-- whitespace in every component, and even if one ever carried a space two triples
-- could only COLLIDE into a single partition (over-ordering — the safe direction),
-- never split one triple across partitions.
--
-- A plain column + trigger rather than GENERATED ALWAYS AS ... STORED: adding a
-- stored generated column REWRITES the table (344 MB and an ACCESS EXCLUSIVE lock
-- on the measured stand, blocking the drainer and every writer), while ADD COLUMN
-- of a nullable plain column is catalog-only and instant.
--
-- The backfill deliberately touches ONLY the pending rows. Historic rows are all
-- sent_at IS NOT NULL; the claim and both partial indexes filter on
-- `sent_at IS NULL`, so a drained row's tuple_key is never read — backfilling 1.4M
-- of them would rewrite the heap for data nothing consults. The NOT VALID check
-- expresses exactly that: enforced for every row inserted from here on (so a
-- payload missing a component fails LOUDLY at emit instead of enqueueing a row
-- that can only poison later), never validated against the historic NULLs.
--
-- ROLLING DEPLOY is safe. A still-running old pod partitions on
-- payload->>'object', which is STRICTLY WIDER than the tuple key (same tuple ⇒
-- same object), so both predicates block on a same-tuple predecessor and neither
-- pod can apply a delete ahead of its write. Only the object index it used is
-- gone, so its claim is slower for the length of the rollout — never incorrect.

ALTER TABLE kacho_iam.fga_outbox ADD COLUMN IF NOT EXISTS tuple_key text;

-- +goose StatementEnd

-- +goose StatementBegin

CREATE OR REPLACE FUNCTION kacho_iam.fga_outbox_tuple_key() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.tuple_key :=
        (NEW.payload->>'user')     || ' ' ||
        (NEW.payload->>'relation') || ' ' ||
        (NEW.payload->>'object');
    RETURN NEW;
END;
$$;

-- +goose StatementEnd

-- +goose StatementBegin

DROP TRIGGER IF EXISTS fga_outbox_tuple_key_trigger ON kacho_iam.fga_outbox;
CREATE TRIGGER fga_outbox_tuple_key_trigger
    BEFORE INSERT ON kacho_iam.fga_outbox
    FOR EACH ROW EXECUTE FUNCTION kacho_iam.fga_outbox_tuple_key();

-- +goose StatementEnd

-- +goose StatementBegin

-- Backfill the rows the claim can still see (PENDING only — see above). Anything
-- in flight when this migration lands therefore partitions correctly from the
-- first claim after it, with no NULL-key window in which ordering would silently
-- not apply (NULL = NULL is not true, so a NULL key never blocks a successor).
UPDATE kacho_iam.fga_outbox
   SET tuple_key = (payload->>'user') || ' ' || (payload->>'relation') || ' ' || (payload->>'object')
 WHERE sent_at IS NULL
   AND tuple_key IS NULL;

-- +goose StatementEnd

-- +goose StatementBegin

-- The claim's correlated NOT EXISTS over the new key: seek to the tuple, then
-- range-scan ids < t.id. PARTIAL on sent_at IS NULL so its size tracks only the
-- PENDING backlog (drained rows fall out), never the append-mostly table.
--
-- Plain (in-tx) CREATE INDEX IF NOT EXISTS, matching the table's sibling index
-- migrations (0001, 0061, 0063). On a matured cluster where the build's brief
-- table write-lock would stall the drainer/writers, switch to CREATE INDEX
-- CONCURRENTLY (needs the goose NO-TRANSACTION directive, keep IF NOT EXISTS) —
-- the same escape hatch noted on 0054/0061/0063.
CREATE INDEX IF NOT EXISTS fga_outbox_tuple_head_idx
    ON kacho_iam.fga_outbox (tuple_key, id)
    WHERE sent_at IS NULL;

-- The object-keyed partition index (migration 0061) is superseded: nothing reads
-- payload->>'object' as a partition any more, and an unused index on a queue table
-- is pure write amplification on every INSERT and every sent_at UPDATE.
DROP INDEX IF EXISTS kacho_iam.fga_outbox_partition_head_idx;

-- +goose StatementEnd

-- +goose StatementBegin

-- Going-forward guarantee that the trigger's output is complete. NOT VALID: new
-- and updated rows are checked, the historic (sent, never re-read) NULLs are left
-- alone — validating them would buy nothing and cost a full-table scan.
ALTER TABLE kacho_iam.fga_outbox
    ADD CONSTRAINT fga_outbox_tuple_key_present_check
    CHECK (tuple_key IS NOT NULL) NOT VALID;

ANALYZE kacho_iam.fga_outbox;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE kacho_iam.fga_outbox DROP CONSTRAINT IF EXISTS fga_outbox_tuple_key_present_check;

CREATE INDEX IF NOT EXISTS fga_outbox_partition_head_idx
    ON kacho_iam.fga_outbox ((payload->>'object'), id)
    WHERE sent_at IS NULL;

DROP INDEX IF EXISTS kacho_iam.fga_outbox_tuple_head_idx;

DROP TRIGGER IF EXISTS fga_outbox_tuple_key_trigger ON kacho_iam.fga_outbox;
DROP FUNCTION IF EXISTS kacho_iam.fga_outbox_tuple_key();

ALTER TABLE kacho_iam.fga_outbox DROP COLUMN IF EXISTS tuple_key;

-- +goose StatementEnd
