-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- RBAC explicit-model 2026 — unified materializer.
--
-- The reconciler becomes the SINGLE materialization path for ALL selector arms —
-- ARM_ANCHOR(all) + ARM_NAMES + ARM_LABELS (binding-time scope_grant emission is
-- removed). Previously, role_rule_selectors only stored ARM_LABELS rules (the only
-- arm the reconciler materialized). Now it must carry EVERY materializing rule so
-- the forward-materialization fast-path (ReconcileObject on a freshly-registered
-- object) can find anchor/names bindings on the change event (≤2s), not only on the
-- periodic sweep.
--
-- Changes:
--   * arm text NOT NULL — the selector arm ('anchor'|'names'|'labels'), so the
--     fast-path query picks the right match predicate (anchor → type only; names →
--     type + id ∈ resource_names; labels → type + labels @> match_labels).
--   * resource_names text[] NOT NULL DEFAULT '{}' — the ARM_NAMES id list.
--   * match_labels relaxed: ARM_ANCHOR/ARM_NAMES have NO labels, so the
--     non-empty/object CHECK from 0026 must allow '{}' for those arms. The CHECK is
--     rewritten arm-aware: labels-arm requires a non-empty object; anchor/names-arm
--     require the empty object.
--
-- WITHIN-SERVICE INVARIANTS — DB-level only (ban #10):
--   * PRIMARY KEY (role_id, rule_fp) unchanged — one selector row per rule.
--   * arm ∈ {'anchor','names','labels'} (CHECK).
--   * arm-aware shape CHECK (labels XOR names XOR anchor) so a malformed projection
--     cannot be persisted.
-- ReplaceRuleSelectors (role write path) REPLACES the role's whole selector set in
-- the same writer-tx as the role write (DELETE-then-INSERT keyed by role_id).

ALTER TABLE kacho_iam.role_rule_selectors
  ADD COLUMN arm           text   NOT NULL DEFAULT 'labels',
  ADD COLUMN resource_names text[] NOT NULL DEFAULT '{}';

-- Existing rows are all ARM_LABELS (the only arm stored until now) — the default
-- 'labels' is correct for them; drop the default afterwards so new inserts MUST
-- state the arm explicitly.
ALTER TABLE kacho_iam.role_rule_selectors
  ALTER COLUMN arm DROP DEFAULT;

ALTER TABLE kacho_iam.role_rule_selectors
  ADD CONSTRAINT role_rule_selectors_arm_valid
    CHECK (arm IN ('anchor', 'names', 'labels'));

-- Replace the 0026 labels-non-empty CHECKs with an arm-aware shape constraint:
--   labels arm → match_labels is a non-empty object, resource_names is empty.
--   names  arm → resource_names is non-empty,         match_labels is '{}'.
--   anchor arm → both empty (match-all-of-type within scope).
ALTER TABLE kacho_iam.role_rule_selectors
  DROP CONSTRAINT IF EXISTS role_rule_selectors_labels_obj,
  DROP CONSTRAINT IF EXISTS role_rule_selectors_labels_nonempty;

ALTER TABLE kacho_iam.role_rule_selectors
  ADD CONSTRAINT role_rule_selectors_labels_obj
    CHECK (jsonb_typeof(match_labels) = 'object'),
  ADD CONSTRAINT role_rule_selectors_arm_shape CHECK (
        (arm = 'labels' AND match_labels <> '{}'::jsonb AND cardinality(resource_names) = 0)
     OR (arm = 'names'  AND match_labels =  '{}'::jsonb AND cardinality(resource_names) >= 1)
     OR (arm = 'anchor' AND match_labels =  '{}'::jsonb AND cardinality(resource_names) = 0)
  );

-- +goose Down

ALTER TABLE kacho_iam.role_rule_selectors
  DROP CONSTRAINT IF EXISTS role_rule_selectors_arm_shape,
  DROP CONSTRAINT IF EXISTS role_rule_selectors_arm_valid,
  DROP CONSTRAINT IF EXISTS role_rule_selectors_labels_obj;

ALTER TABLE kacho_iam.role_rule_selectors
  ADD CONSTRAINT role_rule_selectors_labels_obj      CHECK (jsonb_typeof(match_labels) = 'object'),
  ADD CONSTRAINT role_rule_selectors_labels_nonempty CHECK (match_labels <> '{}'::jsonb);

ALTER TABLE kacho_iam.role_rule_selectors
  DROP COLUMN IF EXISTS resource_names,
  DROP COLUMN IF EXISTS arm;
