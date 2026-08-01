-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- Retire the compute block-storage authorization surface from iam.
--
-- kacho-storage owns Volume / Snapshot / Image / DiskType. compute's second copy
-- of those resources is gone — no tables, no services, no routes, no catalog
-- entries, held there by services/compute/internal/check/retired_block_storage_test.go.
-- What outlived the resources on THIS side is authorization state: nine seeded,
-- bindable system roles (`compute.{disk,image,snapshot}.{admin,edit,view}`), the
-- wildcard system-role selectors that expand onto the three dotted types, mirror
-- rows and materialized members of those types, any binding written against those
-- roles, and any queued tuple aimed at them.
--
-- A grantable role for a resource the product does not serve is a promise it
-- cannot keep: it appears in the catalog, it can be bound, and the binding then
-- materializes per-object tuples for objects that will never exist.
--
-- ORDER. The authorization TYPE declaration in the model goes LAST, after this
-- migration, once nothing can emit onto it any more. The reverse order — dropping
-- `type compute_disk` while a producer still writes onto it — turns every such
-- write into a rejection OpenFGA never stops returning, which poisons the outbox
-- partition behind it. This migration is the "retract the producers" step; the
-- model edit ships in the same change, downstream of it.
--
-- IDEMPOTENT. Every statement is keyed on the retired names, so a re-run (or a
-- re-apply against a database already retired) changes nothing. Additive to the
-- migration history — no applied migration is edited (ban #5).

-- (1) Selectors that name ONLY retired types: nothing would be left to select,
--     and role_rule_selectors_types_nonempty forbids a zero-type row, so the row
--     itself goes. `<@` is "contained by", which also covers the (impossible)
--     empty array.
DELETE FROM kacho_iam.role_rule_selectors
 WHERE object_types <@ ARRAY['compute.disk', 'compute.image', 'compute.snapshot']::text[];

-- (2) Selectors that name a retired type ALONGSIDE live ones (the wildcard `*.*`
--     rows of admin/edit/view/owner, and any custom role authored the same way):
--     strip the retired elements, keep the row. Dropping the whole row here would
--     take the live types' materialization with it — a project-editor would stop
--     getting per-object verbs on their own instances.
UPDATE kacho_iam.role_rule_selectors
   SET object_types = array_remove(array_remove(array_remove(
         object_types, 'compute.disk'), 'compute.image'), 'compute.snapshot'),
       updated_at   = now()
 WHERE object_types && ARRAY['compute.disk', 'compute.image', 'compute.snapshot']::text[];

-- (3) Members already materialized against a retired type. object_type here is the
--     dotted closed-table key (see 0020), same spelling as the selector arrays.
DELETE FROM kacho_iam.access_binding_target_members
 WHERE object_type IN ('compute.disk', 'compute.image', 'compute.snapshot');

-- (4) Mirror rows of the retired types. The mirror is what the reconciler scans to
--     decide what to materialize; a row here keeps producing work for a resource
--     nobody owns.
DELETE FROM kacho_iam.resource_mirror
 WHERE object_type IN ('compute.disk', 'compute.image', 'compute.snapshot');

-- (5) Queued tuples aimed at the retired FGA types. These must go BEFORE the type
--     declaration does: a queued write onto an undeclared type is the permanent
--     rejection described above, and a queued delete is equally undeliverable.
--     Once the type is out of the model, every tuple on it is unreachable anyway,
--     so dropping the queue entry grants nothing.
DELETE FROM kacho_iam.fga_outbox
 WHERE sent_at IS NULL
   AND split_part(payload->>'object', ':', 1) IN ('compute_disk', 'compute_image', 'compute_snapshot');

-- (6) Bindings written against a retired role. access_bindings_role_fk is
--     ON DELETE RESTRICT, so these go before the roles; access_binding_target_members
--     cascades from the binding.
DELETE FROM kacho_iam.access_bindings
 WHERE role_id IN (
   SELECT id FROM kacho_iam.roles
    WHERE name IN ('compute.disk.admin', 'compute.disk.edit', 'compute.disk.view',
                   'compute.image.admin', 'compute.image.edit', 'compute.image.view',
                   'compute.snapshot.admin', 'compute.snapshot.edit', 'compute.snapshot.view')
 );

-- (7) The nine seeded system roles themselves (0001 seed, rules re-authored by
--     0031). role_rule_selectors and access_binding_target_members cascade from
--     roles(id). Scoped to system roles so an account-scoped custom role that
--     happens to carry one of these names is left to its owner.
DELETE FROM kacho_iam.roles
 WHERE is_system
   AND name IN ('compute.disk.admin', 'compute.disk.edit', 'compute.disk.view',
                'compute.image.admin', 'compute.image.edit', 'compute.image.view',
                'compute.snapshot.admin', 'compute.snapshot.edit', 'compute.snapshot.view');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- There is no down path that restores authorization state for a resource the
-- platform no longer serves. Re-seeding the nine roles would re-advertise a
-- resource compute does not implement and storage does not answer to under these
-- names, and the bindings/members/mirror rows that were removed belonged to
-- objects that no longer exist. A rollback of the code that needs the roles back
-- must re-seed them deliberately, in a migration of its own, together with the
-- model type it also needs.
SELECT 1;

-- +goose StatementEnd
