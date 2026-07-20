-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0056_role_definition_tier.sql — redesign-2026 F4 (IAM-1-10/11).
--
-- The Role carries a `definitionTier{tierType,tierId}` wire projection over the
-- typed scope columns (cluster_id / account_id / project_id). Two DB changes back
-- that contract:
--
--   1. RENAME the exactly-one-anchor XOR CHECK `roles_scope_xor` →
--      `roles_definition_tier_xor`, expressed purely over the tier columns
--      (num_nonnulls(cluster_id, account_id, project_id) = 1). The word "scope" is
--      freed for the AccessBinding anchor.
--
--   2. Make `is_system` a GENERATED derivation of the definition tier
--      (cluster_id present ⇔ cluster tier ⇔ system role), NOT an independently
--      stored bool. A GENERATED ALWAYS ... STORED column cannot drift from the
--      tier — it replaces the old denorm-column-plus-CHECK arrangement (the
--      redesign wants derived, not denorm+CHECK). All existing rows keep the same
--      is_system value (the old roles_scope_xor already tied is_system to
--      cluster_id), so the recompute is value-preserving.
--
-- ban #5: applied migrations are never edited — this is a new forward migration.
-- ban #10: the invariant stays on the DB (CHECK + generated column), not software.

-- +goose Up
-- +goose StatementBegin

-- 1. Drop the objects that depend on the stored is_system column (they are
--    recreated below against the generated column).
DROP INDEX IF EXISTS kacho_iam.roles_acc_custom_unique;
DROP INDEX IF EXISTS kacho_iam.roles_prj_custom_unique;
DROP INDEX IF EXISTS kacho_iam.roles_system_unique;

ALTER TABLE kacho_iam.roles
  DROP CONSTRAINT IF EXISTS roles_scope_xor,
  DROP CONSTRAINT IF EXISTS roles_custom_name_check,
  DROP CONSTRAINT IF EXISTS roles_system_name_check;

-- 2. Replace the stored is_system column with a GENERATED derivation of the
--    definition tier. DROP COLUMN + ADD COLUMN is required — Postgres has no
--    ALTER COLUMN ... ADD GENERATED for computed-stored columns.
ALTER TABLE kacho_iam.roles DROP COLUMN is_system;
ALTER TABLE kacho_iam.roles
  ADD COLUMN is_system boolean
    GENERATED ALWAYS AS (cluster_id IS NOT NULL) STORED;

-- 3. Recreate the exactly-one-anchor XOR under its redesign name, over the tier
--    columns only (system ⇒ cluster; custom ⇒ exactly one of {account, project}).
ALTER TABLE kacho_iam.roles
  ADD CONSTRAINT roles_definition_tier_xor
    CHECK (num_nonnulls(cluster_id, account_id, project_id) = 1);

-- 4. Recreate the name-format CHECKs (now referencing the generated is_system).
ALTER TABLE kacho_iam.roles
  ADD CONSTRAINT roles_custom_name_check
    CHECK (is_system OR (name ~ '^[a-z][a-z0-9_]{0,40}$')),
  ADD CONSTRAINT roles_system_name_check
    CHECK ((NOT is_system) OR (name ~ '^[a-z][-a-z0-9]*(\.[a-z][a-z0-9_]*){0,2}$'));

-- 5. Recreate the per-tier partial UNIQUE indexes.
CREATE UNIQUE INDEX roles_acc_custom_unique
  ON kacho_iam.roles (account_id, name) WHERE (is_system = false AND account_id IS NOT NULL);
CREATE UNIQUE INDEX roles_prj_custom_unique
  ON kacho_iam.roles (project_id, name) WHERE (is_system = false AND project_id IS NOT NULL);
CREATE UNIQUE INDEX roles_system_unique
  ON kacho_iam.roles (cluster_id, name) WHERE (is_system = true);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS kacho_iam.roles_acc_custom_unique;
DROP INDEX IF EXISTS kacho_iam.roles_prj_custom_unique;
DROP INDEX IF EXISTS kacho_iam.roles_system_unique;

ALTER TABLE kacho_iam.roles
  DROP CONSTRAINT IF EXISTS roles_definition_tier_xor,
  DROP CONSTRAINT IF EXISTS roles_custom_name_check,
  DROP CONSTRAINT IF EXISTS roles_system_name_check;

-- Restore is_system as a plain stored column, backfilled from the tier.
ALTER TABLE kacho_iam.roles DROP COLUMN is_system;
ALTER TABLE kacho_iam.roles ADD COLUMN is_system boolean;
UPDATE kacho_iam.roles SET is_system = (cluster_id IS NOT NULL);
ALTER TABLE kacho_iam.roles ALTER COLUMN is_system SET DEFAULT false;
ALTER TABLE kacho_iam.roles ALTER COLUMN is_system SET NOT NULL;

ALTER TABLE kacho_iam.roles
  ADD CONSTRAINT roles_scope_xor CHECK (
    (
      (is_system = true)
      AND (cluster_id IS NOT NULL)
      AND (account_id IS NULL)
      AND (project_id IS NULL)
    )
    OR
    (
      (is_system = false)
      AND (cluster_id IS NULL)
      AND (
        ((account_id IS NOT NULL) AND (project_id IS NULL))
        OR ((account_id IS NULL) AND (project_id IS NOT NULL))
      )
    )
  ),
  ADD CONSTRAINT roles_custom_name_check
    CHECK (is_system OR (name ~ '^[a-z][a-z0-9_]{0,40}$')),
  ADD CONSTRAINT roles_system_name_check
    CHECK ((NOT is_system) OR (name ~ '^[a-z][-a-z0-9]*(\.[a-z][a-z0-9_]*){0,2}$'));

CREATE UNIQUE INDEX roles_acc_custom_unique
  ON kacho_iam.roles (account_id, name) WHERE (is_system = false AND account_id IS NOT NULL);
CREATE UNIQUE INDEX roles_prj_custom_unique
  ON kacho_iam.roles (project_id, name) WHERE (is_system = false AND project_id IS NOT NULL);
CREATE UNIQUE INDEX roles_system_unique
  ON kacho_iam.roles (cluster_id, name) WHERE (is_system = true);

-- +goose StatementEnd
