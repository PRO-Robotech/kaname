-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- Backfill kacho_iam.operations.account_id for rows
-- created BEFORE migration 0016 (which added the column) + before the create
-- use-cases started stamping account_id from metadata.
--
-- Those older rows carry account_id IS NULL, so the account-scoped
-- /iam/operations feed (AccountService.ListAllOperations, WHERE account_id=$x —
-- partial index operations_account_id_idx) shows EMPTY for all historical data
-- (observed on the live stand: 50 ops, 0 with account_id).
--
-- The fix derives account_id from the already-populated resource_id column,
-- joining it to the resource's owning account. resource_id carries the
-- first/primary resource id of the op (clear type prefixes: acc/prj/grp/sva/usr)
-- and is populated for category-I rows. account_id columns EXIST in
-- projects/groups/service_accounts/users; accounts has none (the account IS the
-- account → account_id = resource_id). access_bindings + roles have no owning
-- account_id column → category-II, intentionally left NULL: they stay out
-- of the account-scoped feed, exactly as a fresh write would leave them.
--
-- ADDITIVE + IDEMPOTENT: every statement guards `WHERE o.account_id IS NULL`,
-- so it only fills gaps (never overwrites an already-stamped value) and
-- re-running on already-backfilled rows is a no-op. Data-only (no DDL), so it
-- does not redefine the column added by 0016 (ban #5: applied migrations are
-- not edited — this is a NEW file).

-- account ops: the account itself is the scope (resource_id = account id).
UPDATE kacho_iam.operations o
   SET account_id = o.resource_id
  FROM kacho_iam.accounts a
 WHERE o.resource_id = a.id
   AND o.account_id IS NULL;

-- project ops: derive from the project's owning account.
UPDATE kacho_iam.operations o
   SET account_id = p.account_id
  FROM kacho_iam.projects p
 WHERE o.resource_id = p.id
   AND o.account_id IS NULL;

-- group ops: derive from the group's owning account.
UPDATE kacho_iam.operations o
   SET account_id = g.account_id
  FROM kacho_iam.groups g
 WHERE o.resource_id = g.id
   AND o.account_id IS NULL;

-- service_account ops: derive from the service account's owning account.
UPDATE kacho_iam.operations o
   SET account_id = s.account_id
  FROM kacho_iam.service_accounts s
 WHERE o.resource_id = s.id
   AND o.account_id IS NULL;

-- user ops: derive from the user's owning account.
UPDATE kacho_iam.operations o
   SET account_id = u.account_id
  FROM kacho_iam.users u
 WHERE o.resource_id = u.id
   AND o.account_id IS NULL;

-- +goose Down
-- No-op: the account_id column itself is dropped by 0016 Down; this migration is
-- a data-only backfill with no schema to reverse. A backfilled value is
-- indistinguishable from a freshly-stamped one, so there is nothing to undo.
SELECT 1;
