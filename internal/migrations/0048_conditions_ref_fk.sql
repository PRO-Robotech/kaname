-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0048_conditions_ref_fk.sql — close the Condition-delete TOCTOU at the DB level.
--
-- The reference from an attached binding-condition (access_binding_conditions)
-- to a named catalog Condition (conditions) was stored ONLY as a JSONB path
-- (params ->> 'condition_id'), with no FK/CHECK/trigger backing it. Condition
-- delete therefore relied on a software "count-then-delete" refcheck
-- (ConditionsCRUDService.doDelete → CountReferencesTx + DeleteTx), a
-- read-then-act pattern that hard-rule #10 forbids for within-service
-- invariants: a concurrent attach committing between the count and the delete
-- leaves the binding pointing at a deleted Condition (dangling reference), and
-- Postgres cannot stop it because a JSONB path cannot carry a FK.
--
-- Fix (DB-level, project rule #10):
--   1. Promote the reference to a real column `condition_id`.
--   2. Keep it derived in-DB from `params ->> 'condition_id'` via a BEFORE
--      INSERT/UPDATE trigger, so NO Go write-path changes are needed and the
--      column can never drift from the JSONB source of truth.
--   3. Back it with a real FK REFERENCES conditions(id) ON DELETE RESTRICT.
--
-- Why this closes the race (write-skew): a real FK makes the child INSERT take
-- a FOR KEY SHARE lock on the referenced conditions row, which conflicts with
-- the parent-row DELETE. The two operations therefore serialize instead of
-- interleaving — whichever commits first wins, the other sees the conflict
-- (attach → 23503 "condition not found"; delete → 23503 RESTRICT) and rolls
-- back. Exactly one outcome; no dangling reference is ever left behind. A plain
-- trigger-only existence check would NOT close it (two READ COMMITTED txns each
-- reading the other's not-yet-committed table = classic write-skew).
--
-- This is a NEW internal migration for a within-service invariant. It changes
-- no wire contract (no proto/gen/REST/public-field-semantics change): the new
-- column is internal and derived, never accepted on the request path.

-- +goose Up
-- +goose StatementBegin

-- 1. New nullable column. NULL = this attached condition is expression-only and
--    does not reference a named catalog Condition (the common case: existing
--    rows carry params '{}' and stay NULL).
ALTER TABLE kacho_iam.access_binding_conditions
    ADD COLUMN IF NOT EXISTS condition_id text;

-- +goose StatementEnd
-- +goose StatementBegin

-- 2. Backfill from existing params. Only backfill references that actually
--    resolve to a live Condition, so a pre-existing orphan (which the old
--    software refcheck could have left) does not block the FK creation below;
--    orphans keep their params intact and are simply not FK-tracked, while all
--    valid references and every future write ARE enforced.
UPDATE kacho_iam.access_binding_conditions abc
   SET condition_id = NULLIF(abc.params ->> 'condition_id', '')
 WHERE NULLIF(abc.params ->> 'condition_id', '') IS NOT NULL
   AND EXISTS (SELECT 1 FROM kacho_iam.conditions c
                WHERE c.id = abc.params ->> 'condition_id');

-- +goose StatementEnd
-- +goose StatementBegin

-- 3. Trigger function: keep condition_id derived from params on every write.
CREATE OR REPLACE FUNCTION kacho_iam.access_binding_conditions_sync_condition_id()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.condition_id := NULLIF(NEW.params ->> 'condition_id', '');
    RETURN NEW;
END;
$$;

-- +goose StatementEnd
-- +goose StatementBegin

DROP TRIGGER IF EXISTS access_binding_conditions_sync_condition_id_trg
    ON kacho_iam.access_binding_conditions;

CREATE TRIGGER access_binding_conditions_sync_condition_id_trg
    BEFORE INSERT OR UPDATE ON kacho_iam.access_binding_conditions
    FOR EACH ROW
    EXECUTE FUNCTION kacho_iam.access_binding_conditions_sync_condition_id();

-- +goose StatementEnd
-- +goose StatementBegin

-- 4. Real FK — the DB-level enforcement + locking that closes the TOCTOU.
ALTER TABLE kacho_iam.access_binding_conditions
    ADD CONSTRAINT access_binding_conditions_condition_fk
    FOREIGN KEY (condition_id)
    REFERENCES kacho_iam.conditions(id) ON DELETE RESTRICT;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE kacho_iam.access_binding_conditions
    DROP CONSTRAINT IF EXISTS access_binding_conditions_condition_fk;

-- +goose StatementEnd
-- +goose StatementBegin

DROP TRIGGER IF EXISTS access_binding_conditions_sync_condition_id_trg
    ON kacho_iam.access_binding_conditions;

-- +goose StatementEnd
-- +goose StatementBegin

DROP FUNCTION IF EXISTS kacho_iam.access_binding_conditions_sync_condition_id();

-- +goose StatementEnd
-- +goose StatementBegin

ALTER TABLE kacho_iam.access_binding_conditions
    DROP COLUMN IF EXISTS condition_id;

-- +goose StatementEnd
