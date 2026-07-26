-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- Covering index for the NARROW per-object member read the object-triggered reconcile
-- pass performs:
--
--   SELECT binding_id, role_id, rule_fp, object_type, object_id, verification_status
--     FROM kacho_iam.access_binding_target_members
--    WHERE object_type = $2 AND object_id = $3 AND binding_id = $1
--
-- WHY IT IS NEEDED. A resource_mirror upsert/delete (a create, a re-register, a label
-- UPDATE) changes exactly ONE object, so only that object's members can change. The pass
-- therefore diffs one object's members per fanned-out binding instead of recomputing the
-- binding's whole desired set — but the table's only usable access paths for that read
-- were the PK (leading column binding_id) and the by-object index (object_type,
-- object_id) WITHOUT binding_id.
--
--   - via the PK: the read degenerates to "scan every member of this binding, filter to
--     one object". On the measured stand the two hottest bindings carry 10 140 members
--     each — precisely the O(mirror) read the narrowing exists to remove.
--   - via the existing by-object index: correct and already selective (an object carries
--     3.2 member rows on average, 66 at the tail), but every candidate row must be
--     heap-fetched just to discard the other bindings' rows.
--
-- Appending binding_id makes the lookup an exact three-column probe, and INCLUDE-ing the
-- projected columns keeps it index-only — so the hot path touches no heap pages at all.
-- This matters because the read happens INSIDE the per-binding EXCLUSIVE advisory lock
-- that every sibling registration in the account queues behind: shortening that critical
-- section is the throughput property, not just a saved page read.
--
-- The pre-existing access_binding_target_members_object_idx (object_type, object_id) is
-- KEPT: BindingsForObjectTx does `SELECT DISTINCT binding_id … WHERE object_type=$1 AND
-- object_id=$2`, which this index also serves, but the narrower two-column one stays the
-- better fit for that fan-out probe and for any future object-only scan. Both are cheap.
--
-- Additive and online-safe: a new index changes no rows and no constraint, so it cannot
-- fail on existing data and needs no backfill. Created NON-concurrently to stay inside
-- the goose transaction — the table is small (50 136 rows on the busiest measured stand)
-- and the build is sub-second; a CONCURRENTLY build would have to leave the migration
-- transaction and could then abort half-built (INVALID index) with no goose-level retry.

CREATE INDEX IF NOT EXISTS access_binding_target_members_object_binding_idx
    ON kacho_iam.access_binding_target_members (object_type, object_id, binding_id)
    INCLUDE (role_id, rule_fp, verification_status);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS kacho_iam.access_binding_target_members_object_binding_idx;

-- +goose StatementEnd
