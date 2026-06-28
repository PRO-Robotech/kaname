-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- RBAC rules-model 2026 — attribute materialized members to their (role, rule).
--
-- Rekey access_binding_target_members so a materialized member is attributed to
-- the (role, rule) that produced it. The rules-model drives membership from
-- role.rules ARM_LABELS selectors (role_rule_selectors), so the same (binding,
-- object) may be produced by MULTIPLE rules at DIFFERENT tiers — the old PK
-- (binding_id, object_type, object_id) cannot represent that, and a Role.Update
-- that removes ONE rule must eager-revoke ONLY that rule's members, which
-- requires the rule coordinate on the member row.
--
-- Real schema-migration (NOT a logical "rekey"): ADD role_id + rule_fp,
-- backfill the existing legacy rows to a stable SENTINEL rule coordinate (the
-- legacy per-binding selector arm is NOT a role.rule), then swap the PK to the
-- 5-tuple (binding_id, role_id, rule_fp, object_type, object_id).
--
-- WITHIN-SERVICE INVARIANTS — DB-level only (ban #10):
--   * role_id NOT NULL FK → roles(id) ON DELETE CASCADE — the producing role; a
--     member is dropped if its role is deleted (a role in use is FK-RESTRICT-
--     protected by access_bindings, so this only fires after all its bindings are
--     gone).
--   * rule_fp NOT NULL — the producing rule's content-hash (domain.Rule.Fingerprint)
--     for a role.rules-driven member, OR the sentinel 'legacy-selector' for a
--     legacy binding.selector member (the sentinel can never collide with a real
--     64-hex-char fingerprint).
--   * PK (binding_id, role_id, rule_fp, object_type, object_id) — exactly one row
--     per (binding, role, rule, object). The reconciler UPSERTs on this key, so a
--     re-materialization of the same (rule, object) is idempotent and serializes
--     concurrent passes on the PK row-lock.
--   * binding_id FK ON DELETE CASCADE retained (deleting a binding drops members).

-- The legacy per-binding selector member coordinate. Distinct from any real rule_fp
-- (a sha256 hex digest is 64 chars; this sentinel is short and non-hex-shaped), so
-- the legacy selector path and the role.rules path never collide on the PK.
ALTER TABLE kacho_iam.access_binding_target_members
  ADD COLUMN role_id text,
  ADD COLUMN rule_fp text;

-- Backfill: existing rows are legacy per-binding selector members. role_id is the
-- binding's role; rule_fp is the legacy sentinel. The reconciler's role.rules path
-- writes a real fingerprint; the legacy reconciler keeps writing the sentinel.
UPDATE kacho_iam.access_binding_target_members m
   SET role_id = b.role_id,
       rule_fp = 'legacy-selector'
  FROM kacho_iam.access_bindings b
 WHERE b.id = m.binding_id
   AND m.role_id IS NULL;

ALTER TABLE kacho_iam.access_binding_target_members
  ALTER COLUMN role_id SET NOT NULL,
  ALTER COLUMN rule_fp SET NOT NULL;

ALTER TABLE kacho_iam.access_binding_target_members
  ADD CONSTRAINT access_binding_target_members_role_fk
    FOREIGN KEY (role_id) REFERENCES kacho_iam.roles (id) ON DELETE CASCADE,
  ADD CONSTRAINT access_binding_target_members_rulefp_nonempty CHECK (rule_fp <> '');

-- Swap the PK from the 3-tuple to the 5-tuple. The old object-probe index
-- (object_type, object_id) is retained (by-object reconcile fan-out).
ALTER TABLE kacho_iam.access_binding_target_members
  DROP CONSTRAINT access_binding_target_members_pkey;
ALTER TABLE kacho_iam.access_binding_target_members
  ADD CONSTRAINT access_binding_target_members_pkey
    PRIMARY KEY (binding_id, role_id, rule_fp, object_type, object_id);

-- +goose Down

ALTER TABLE kacho_iam.access_binding_target_members
  DROP CONSTRAINT access_binding_target_members_pkey;
-- Collapse any role.rules-produced duplicates of a (binding, object) before
-- restoring the 3-tuple PK (the Down path is dev-only; a real downgrade with
-- multi-rule members present would need manual dedup first).
DELETE FROM kacho_iam.access_binding_target_members a
 USING kacho_iam.access_binding_target_members b
 WHERE a.ctid < b.ctid
   AND a.binding_id = b.binding_id
   AND a.object_type = b.object_type
   AND a.object_id = b.object_id;
ALTER TABLE kacho_iam.access_binding_target_members
  ADD CONSTRAINT access_binding_target_members_pkey
    PRIMARY KEY (binding_id, object_type, object_id);
ALTER TABLE kacho_iam.access_binding_target_members
  DROP CONSTRAINT IF EXISTS access_binding_target_members_role_fk,
  DROP CONSTRAINT IF EXISTS access_binding_target_members_rulefp_nonempty;
ALTER TABLE kacho_iam.access_binding_target_members
  DROP COLUMN IF EXISTS role_id,
  DROP COLUMN IF EXISTS rule_fp;
