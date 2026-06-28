-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- RBAC rules-model 2026 — CRITICAL fix: split the emitted-tuple ledger by SOURCE
-- so a Role.Update reconcile cannot wipe ARM_LABELS per-member tuples.
--
-- THE BUG:
--   kacho_iam.access_binding_emitted_tuples (0024) is a SINGLE ledger keyed by
--   (binding_id, fga_user, relation, object) that holds BOTH:
--     * BINDING-LEVEL tuples — scope_grant / anchor / hierarchy parent-pointer,
--       written by Create.InsertEmittedTuples and the Role.Update
--       RoleTupleReconciler (object-space: scope_grant:* / iam_access_binding:* /
--       <scope>:<id>);
--     * MEMBER-LEVEL tuples — ARM_LABELS per-object v_*/tier tuples written by the
--       reconciler RecordEmittedTuples (object-space: <fga_type>:<object_id>,
--       e.g. vpc_subnet:sub-x).
--   RoleTupleReconciler.ReconcileRoleTuples derives the NEW set from
--   buildBindingTuples (binding-level ONLY — ARM_LABELS rules are skipped there)
--   but read the OLD set via SelectEmittedTuples (the WHOLE ledger). The set-diff
--   therefore classified every per-member tuple as `removed` → EmitRelationDelete
--   revoked the live member FGA tuples, and ReplaceEmittedTuples DELETE-d the whole
--   ledger and re-inserted only binding-level rows. Result: every rules-changing
--   Role.Update of a custom role that mixes a binding-level arm with an ARM_LABELS
--   arm transiently (or, on a post-commit fan-out failure, durably-until-sweep)
--   revoked all label-selected access. RoleTupleReconciler owns binding-level
--   tuples; RoleMembershipFanout owns member tuples — the ledger must tell them
--   apart.
--
-- THE FIX:
--   A `source` column ('binding' | 'member') tags every row by its owner.
--   InsertEmittedTuples (binding writer) stamps 'binding'; RecordEmittedTuples
--   (the member writer) stamps 'member'. ReplaceEmittedTuples (RoleTupleReconciler)
--   deletes ONLY source='binding' rows, and the reconcile diff reads the
--   source='binding' subset — so member rows are never seen, revoked, or wiped by
--   a binding-level reconcile. The symmetric full-binding revoke (delete.go) keeps
--   reading the WHOLE ledger (it must revoke member tuples too) and the FK ON
--   DELETE CASCADE still drops every row of a deleted binding.
--
-- BACKFILL — none, by design:
--   This whole ledger ships with the unreleased RBAC rules-model 2026 work
--   (migrations 0024-0032 not in production), so a fresh deploy has ZERO rows when
--   this runs (the DEFAULT is irrelevant). Existing rows on a dev stand default to
--   'binding'; any mis-tagged member row self-heals on the next reconcile, because
--   RecordEmittedTuples upserts ON CONFLICT DO UPDATE SET source='member'. A
--   content-based backfill is intentionally avoided: the member object string is
--   the FGA type (`vpc_subnet:id`) while access_binding_target_members.object_type
--   is the dotted key (`vpc.subnet`), and the FGA-type mapping (authzmap.objectTypes)
--   is not a pure '.'→'_' transform, so a SQL join cannot reconstruct it reliably.

ALTER TABLE kacho_iam.access_binding_emitted_tuples
  ADD COLUMN source text NOT NULL DEFAULT 'binding';

ALTER TABLE kacho_iam.access_binding_emitted_tuples
  ADD CONSTRAINT access_binding_emitted_tuples_source_ck
  CHECK (source IN ('binding', 'member'));

-- +goose Down

ALTER TABLE kacho_iam.access_binding_emitted_tuples
  DROP CONSTRAINT IF EXISTS access_binding_emitted_tuples_source_ck;
ALTER TABLE kacho_iam.access_binding_emitted_tuples
  DROP COLUMN IF EXISTS source;
