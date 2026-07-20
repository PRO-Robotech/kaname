-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin
--
-- redesign-2026 F8 (IAM-1-21..29): reintroduce AccessBinding.target — the
-- least-privilege object-selection UNDER a binding's scope-anchor.
--
--   target        JSONB  — the selection: {"allInScope":true} OR
--                          {"resources":[{"type":"compute.instance","id":"ins-…"}]}.
--   target_digest TEXT   — a deterministic, SET-BASED canonicalization used solely
--                          as a key column of the active-grant partial UNIQUE:
--                          "all" for allInScope / whole-anchor, "obj:<sha256>" of the
--                          SORTED "type:id" members for a per-object set (so the same
--                          set in any order collides — IAM-1-29).
--
-- The active-grant UNIQUE is EXTENDED (not weakened): the WHERE predicate stays
-- `revoked_at IS NULL` (migration 0003 discipline — catches PENDING dups too;
-- NEVER relaxed to status='ACTIVE'); only the key gains `target_digest`, so an
-- identical (subject, role, scope, target) collides while distinct per-object
-- targets coexist. Re-grant after revoke keeps working (revoke stamps revoked_at →
-- the row leaves the partial index → a fresh identical Create is a NEW ACTIVE row).
--
-- Backfill: every pre-F8 row is a whole-anchor grant → the column DEFAULTs
-- ('{"allInScope":true}' / 'all') backfill existing rows. The DEFAULTs are KEPT as
-- the legacy target-less = whole-anchor semantic: the app repo Insert always
-- supplies target + digest explicitly, and the PUBLIC Create RPC enforces
-- target-required (least-priv at the boundary), so the DEFAULT only serves
-- low-level raw-SQL / fixture inserts, for which whole-anchor is correct.

ALTER TABLE kacho_iam.access_bindings
  ADD COLUMN target        JSONB NOT NULL DEFAULT '{"allInScope":true}'::jsonb,
  ADD COLUMN target_digest TEXT  NOT NULL DEFAULT 'all';

DROP INDEX IF EXISTS kacho_iam.access_bindings_active_grant_uniq;

CREATE UNIQUE INDEX access_bindings_active_grant_uniq
  ON kacho_iam.access_bindings
  (subject_id, subject_type, role_id, resource_type, resource_id, target_digest)
  WHERE revoked_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS kacho_iam.access_bindings_active_grant_uniq;

CREATE UNIQUE INDEX access_bindings_active_grant_uniq
  ON kacho_iam.access_bindings
  (subject_id, subject_type, role_id, resource_type, resource_id)
  WHERE revoked_at IS NULL;

ALTER TABLE kacho_iam.access_bindings DROP COLUMN IF EXISTS target_digest;
ALTER TABLE kacho_iam.access_bindings DROP COLUMN IF EXISTS target;
-- +goose StatementEnd
