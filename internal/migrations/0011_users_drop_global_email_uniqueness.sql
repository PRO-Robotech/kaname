-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0011_users_drop_global_email_uniqueness.sql — restore the user-per-account
-- uniqueness model that migration 0002 over-broadened.
--
-- ban #5: new migration, never edits an applied one (0002 stays untouched).
--
-- ─── Problem ───────────────────────────────────────────────────────────────
-- kacho-iam is user-per-account: one identity (Kratos `sub`) has N user-rows,
-- one per Account it belongs to, ALL sharing the same email. This is the
-- documented model, which the squashed baseline 0001_initial.sql already
-- enforces correctly:
--     users_account_email_unique        UNIQUE (account_id, lower(email))
--     users_account_external_id_unique  UNIQUE (account_id, external_id) WHERE external_id <> ''
--
-- Migration 0002_users_unique_email_dedup.sql (2026-05-25) was authored against
-- the earlier schema (no account_id column) to fix a concurrent-relogin
-- duplicate-row bug. It added GLOBAL constraints:
--     users_email_uniq        UNIQUE (email)
--     users_external_id_uniq  UNIQUE (external_id) WHERE external_id <> ''
-- After the 0001 baseline squash incorporated the per-account
-- constraints, these globals became contradictory: a single identity can no
-- longer hold a user-row in a second Account.
--
-- Live failure (kind, 2026-06-14): UserService.Invite of an existing-email user
-- into a SECOND Account fails in the async LRO worker with
--     duplicate key value violates unique constraint "users_email_uniq"
-- (op error_code=6 FAILED_PRECONDITION). The whole invite TX (PENDING user
-- INSERT + project-scoped AccessBinding INSERT) rolls back → the invitee never
-- receives the grant → authz Check `no path` → 403. This breaks the shared
-- newman authz gate (invitee→project-A1 ALLOW; invitee-sees-users-in-accountB
-- membership).
--
-- ─── Fix ───────────────────────────────────────────────────────────────────
--   1. DROP global UNIQUE(email)            — email is unique per-Account (0001).
--   2. DROP global partial UNIQUE(external_id) — external_id is unique per-Account
--      for ACTIVE/BLOCKED rows (0001 users_account_external_id_unique).
--   3. ADD BACK a NARROWER global guard: a partial UNIQUE on (external_id) for
--      ACTIVE rows ONLY. This preserves the "one ACTIVE identity-row per Kratos
--      sub, globally" invariant that GetByExternalID (ORDER BY created_at ASC
--      LIMIT 1), resolveCanonicalSubjectID and the gateway LookupSubject all
--      rely on, AND closes the concurrent-bootstrap race that step 2 would
--      otherwise reopen (two racing first-logins each pick a DIFFERENT new
--      account_id, so the per-account index does NOT serialize them — only a
--      global guard does). PENDING invites carry external_id='' (CHECK
--      users_invite_status_consistency) so they are excluded and may freely
--      multiply per-Account.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE kacho_iam.users DROP CONSTRAINT IF EXISTS users_email_uniq;
DROP INDEX IF EXISTS kacho_iam.users_external_id_uniq;

CREATE UNIQUE INDEX IF NOT EXISTS users_active_external_id_uniq
    ON kacho_iam.users (external_id)
    WHERE invite_status = 'ACTIVE' AND external_id <> '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Symmetric DDL rollback. NOTE: re-creating the global UNIQUE(email) /
-- UNIQUE(external_id) may fail on data accumulated under the user-per-account
-- model (legitimate same-email / same-external_id rows in different Accounts).
-- This Down is best-effort DDL reversibility, NOT a data-safe rollback — the
-- fix is logically incompatible with the earlier global constraints.
DROP INDEX IF EXISTS kacho_iam.users_active_external_id_uniq;

CREATE UNIQUE INDEX users_external_id_uniq
    ON kacho_iam.users (external_id)
    WHERE external_id <> '';
ALTER TABLE kacho_iam.users
    ADD CONSTRAINT users_email_uniq UNIQUE (email);
-- +goose StatementEnd
