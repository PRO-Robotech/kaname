-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- RBAC explicit-model 2026 — owner-binding DATA backfill for accounts that
-- EXISTED before the Account.Create auto owner-binding was wired.
--
-- WHAT this does:
--   For every account that does NOT already have an ACTIVE owner-role binding,
--   INSERT an AccessBinding(subject = accounts.owner_user_id, role = owner system-
--   role, scope = ACCOUNT:<A>, deletion_protection = true) + its projected
--   access_binding_subjects row. The per-object access tuples (scope-self verbs on
--   account:<A> + the account's content) are NOT emitted here — they are
--   materialized FORWARD by the reconcile-sweep (the SINGLE materialization
--   path). The migration only creates the binding ROW; on an empty/existing
--   account the reconciler fills the ledger.
--
-- WITHIN-SERVICE INVARIANTS — DB-level only (ban #10):
--   * Idempotency rests on the active-grant partial-UNIQUE
--     access_bindings_active_grant_uniq (subject_id, subject_type, role_id,
--     resource_type, resource_id) WHERE revoked_at IS NULL. The `WHERE NOT EXISTS`
--     guard skips an account that already has an active owner-binding (an account
--     created later, or a re-apply of this migration) — re-running is a no-op.
--     The partial-UNIQUE is the backstop: even a racing insert raises 23505
--     instead of a duplicate active grant.
--   * Deterministic id `'acb' || substr(md5('owner-binding:' || a.id), 1, 17)` —
--     20-char acb-prefixed id stable per account (mirrors the 0035 owner-role
--     deterministic-id pattern), so a re-apply targets the SAME id and the
--     subjects INSERT ON CONFLICT DO NOTHING is a clean no-op.
--   * role_id references the `owner` system-role seeded by migration 0035 (FK
--     access_bindings_role_fk); a missing role would 23503 — but 0035 runs first.
--
-- CHUNKED tx-size: this is a set-based INSERT … SELECT. On a deployment with
-- a very large number of accounts a single statement is still ONE row per account
-- (lightweight — no per-object tuples are written here; those are the reconcile-
-- sweep's chunked concern). The heavy per-object materialization is deferred to the
-- singleton reconcile-backfill runner (seed.BackfillRunner) which is chunked.
--
-- FORWARD-ONLY: additive data migration; no schema change, no edit to an applied
-- migration (ban #5). The next migration is 0037.

-- 1) owner-binding rows for accounts lacking an active owner-binding.
INSERT INTO kacho_iam.access_bindings
  (id, subject_type, subject_id, role_id, resource_type, resource_id,
   status, granted_by_user_id, deletion_protection)
SELECT
  'acb' || substr(md5('owner-binding:' || a.id), 1, 17),
  'user',
  a.owner_user_id,
  'rol' || substr(md5('owner'), 1, 17),          -- owner system-role (mig 0035)
  'account',
  a.id,
  'ACTIVE',
  'system',                                        -- granted_by = migrate-backfill
  true                                             -- deletion_protection
FROM kacho_iam.accounts a
WHERE NOT EXISTS (
  SELECT 1
    FROM kacho_iam.access_bindings b
   WHERE b.subject_type  = 'user'
     AND b.subject_id    = a.owner_user_id
     AND b.role_id       = 'rol' || substr(md5('owner'), 1, 17)
     AND b.resource_type = 'account'
     AND b.resource_id   = a.id
     AND b.revoked_at IS NULL
)
ON CONFLICT (id) DO NOTHING;

-- 2) projected single-subject row for each backfilled owner-binding (parity with
--    the multi-subject set, migration 0028). Idempotent ON CONFLICT.
INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
SELECT b.id, b.subject_type, b.subject_id, 0
  FROM kacho_iam.access_bindings b
 WHERE b.role_id       = 'rol' || substr(md5('owner'), 1, 17)
   AND b.resource_type = 'account'
   AND b.revoked_at IS NULL
ON CONFLICT (binding_id, subject_type, subject_id) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Remove the migrate-backfilled owner-bindings (granted_by_user_id='system' marks
-- the backfill source; an Account.Create owner-binding is granted_by the creator).
-- The access_binding_subjects rows drop via FK ON DELETE CASCADE.
DELETE FROM kacho_iam.access_bindings
 WHERE role_id           = 'rol' || substr(md5('owner'), 1, 17)
   AND resource_type     = 'account'
   AND granted_by_user_id = 'system'
   AND id LIKE 'acb%';

-- +goose StatementEnd
