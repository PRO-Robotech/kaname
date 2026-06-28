-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- Add the additive,
-- nullable account_id denormalization to kacho_iam.operations so the
-- account-scoped IAM operation-listing (AccountService.ListAllOperations) and
-- the cluster-wide Internal feed (InternalOperationsService.ListIamOperations)
-- filter on it at the DB level (partial cursor index, not software aggregation).
--
-- This mirrors the corelib common migration
-- (kacho-corelib/migrations/common/0003_operations_account_id.sql): the
-- kacho_iam.operations table is the IAM-extended copy of the shared operations
-- schema (it carries the IAM-only principal_* columns), so the column must be
-- added here too. corelib operations.Repo.CreateWithPrincipal now INSERTs
-- account_id unconditionally; without this column the INSERT fails (42703).
--
-- ADDITIVE / BACK-COMPAT: nullable, no DEFAULT, no NOT NULL. account_id is set
-- only when the writing use-case passed metadata with the exact-name account_id
-- field (corelib extractAccountID). Category-(II) IAM ops (cluster-global Role,
-- project/cluster-scoped AccessBinding, SAKey, Condition) and Internal-only
-- op-producers leave account_id NULL and stay out of the account-scoped list.
--
-- partial index (account_id, created_at, id) WHERE account_id IS NOT NULL —
-- covers the account-scoped cursor pagination (WHERE account_id = $x ORDER BY
-- created_at, id) and does NOT index the NULL rows (no bloat from non-IAM /
-- category-II operations).

ALTER TABLE kacho_iam.operations
  ADD COLUMN account_id text NULL;

CREATE INDEX operations_account_id_idx
  ON kacho_iam.operations (account_id, created_at, id)
  WHERE account_id IS NOT NULL;

-- +goose Down

DROP INDEX IF EXISTS kacho_iam.operations_account_id_idx;

ALTER TABLE kacho_iam.operations
  DROP COLUMN account_id;
