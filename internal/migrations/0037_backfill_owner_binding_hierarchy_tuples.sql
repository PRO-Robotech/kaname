-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- RBAC explicit-model 2026.
--
-- INTENTIONAL NO-OP migration.
--
-- An earlier revision of THIS migration emitted the owner-binding OBJECT hierarchy
-- parent-pointer FGA tuple
--     account:<A>#account@iam_access_binding:<bindingID>
-- directly into kacho_iam.fga_outbox for every pre-existing owner-role account-scoped
-- binding (Account.Create + migrate-backfill 0036). That was WRONG for two reasons:
--
--   1. A goose DATA migration MUST NOT have an fga_outbox side-effect. The outbox is a
--      transactional write-ahead queue owned by request-path / boot-path use-cases; a
--      migration that enqueues a tuple silently pollutes the outbox for EVERY test and
--      tool that counts/asserts on it (the RegisterResource SEC-C
--      integration tests assert "exactly one outbox row" and saw 2 — the migration's
--      seeded kacho-system owner-binding pointer was the phantom extra row).
--
--   2. The emit is DUPLICATED with the boot-time idempotent backfill
--      seed.BackfillOwnerBindings (backfillOwnerHierarchyTuplesSQL, run from
--      cmd/kacho-iam/serve.go). That boot-path is the CORRECT home for the
--      hierarchy-pointer INTENT for existing owner-bindings: it is idempotent
--      (NOT EXISTS payload de-dupe), at-least-once, and runs under the singleton
--      backfill lock — exactly the discipline an outbox emit requires. It ALSO covers
--      accounts created AFTER goose.Up (which a migration can never see).
--
-- The hierarchy-pointer emit therefore lives in ONE place only:
--   * NEW owner-bindings  → account/create.go ownerBindingHierarchyTuples (co-commit
--     in the writer-tx, NOT a migration).
--   * EXISTING owner-bindings → seed.BackfillOwnerBindings at boot (idempotent,
--     at-least-once, singleton-locked).
--
-- This migration is kept as a no-op (rather than deleted) to preserve the goose
-- version sequence (0037) on any environment that already recorded it applied. It
-- performs NO data change and NO outbox emit. The next migration is 0038.
SELECT 1;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- No-op up ⇒ no-op down.
SELECT 1;

-- +goose StatementEnd
