-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0008_drop_organizations.sql — production-strict cleanup.
--
-- Organization / SCIM / SAML are dead: the domain types, repos and handlers
-- were removed (after the SCIM/SAML/break-glass *tables* were already dropped
-- in 0006). This migration retires the remaining dead schema:
--
--   - the `organizations` table (zero production callers, always empty);
--   - the forward-referencing `organization_id` columns on `accounts` and
--     `roles` (always NULL; never read/written by live code);
--   - the `audit_outbox.tenant_organization_id` column (always NULL — the
--     write-path that set it was removed with the Organization domain).
--
-- The `roles_scope_xor` CHECK is rewritten to drop the organization branch:
-- a custom role is now scoped to exactly one of {account, project}.
--
-- Forward-only (no Down), matching 0006/0007 — these drops are an
-- irreversible cleanup of dead schema (ban #5: new migration, never edit
-- an applied one). All DDL is IF EXISTS / CASCADE-safe for retry/HA re-apply.

-- +goose Up
-- +goose StatementBegin

-- 1. Drop the organizations table. CASCADE removes the FKs that reference it
--    (accounts_organization_fk, roles_organization_fk) and the FKs it owns
--    (organizations_default_account_fk, organizations_initial_role_fk) plus
--    its own indexes/constraints.
DROP TABLE IF EXISTS kacho_iam.organizations CASCADE;

-- 2. Drop the multi-scope CHECK that references organization_id (single-column
--    indexes on the columns are auto-dropped by DROP COLUMN below; the
--    org+name partial UNIQUE is dropped explicitly first).
ALTER TABLE IF EXISTS kacho_iam.roles
  DROP CONSTRAINT IF EXISTS roles_scope_xor;

DROP INDEX IF EXISTS kacho_iam.roles_org_custom_unique;
DROP INDEX IF EXISTS kacho_iam.roles_organization_idx;
DROP INDEX IF EXISTS kacho_iam.accounts_organization_idx;

-- 3. Drop the now-orphaned organization_id columns.
ALTER TABLE IF EXISTS kacho_iam.roles
  DROP COLUMN IF EXISTS organization_id;
ALTER TABLE IF EXISTS kacho_iam.accounts
  DROP COLUMN IF EXISTS organization_id;

-- 4. Recreate roles_scope_xor without the organization branch:
--    system role → cluster_id only; custom role → exactly one of {account, project}.
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
  );

-- 5. Drop the always-NULL audit_outbox.tenant_organization_id column + its index.
DROP INDEX IF EXISTS kacho_iam.audit_outbox_tenant_org_idx;
ALTER TABLE IF EXISTS kacho_iam.audit_outbox
  DROP COLUMN IF EXISTS tenant_organization_id;

-- +goose StatementEnd
