-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- RBAC rules-model 2026 — per-rule label selectors materialized by the reconciler.
--
-- role_rule_selectors — the per-rule ARM_LABELS selector spec the reconciler
-- materializes membership from. This migration moves label-selection from the legacy
-- per-binding access_binding_selector (one selector / binding) to role.rules: a
-- role's ARM_LABELS rules each contribute one (role_id, rule_fp) selector covering
-- object_types (cartesian modules×resources) narrowed by match_labels. EVERY
-- ACTIVE binding carrying that role then materializes membership against these
-- selectors (one role → N bindings fan-out), so the spec lives on the ROLE,
-- keyed by the rule's CONTENT-HASH (rule_fp = domain.Rule.Fingerprint) — NOT a
-- positional index, because rules[] is mutable (reorder/remove must not desync
-- membership).
--
-- WITHIN-SERVICE INVARIANTS — DB-level only (ban #10):
--   * PRIMARY KEY (role_id, rule_fp) — exactly one selector row per rule of a role.
--     Role.Create/Update REPLACES the role's selector set in the same writer-tx as
--     the role write (DELETE-then-INSERT keyed by role_id), so a removed/edited
--     ARM_LABELS rule drops/replaces its selector atomically with the rules change.
--   * role_id FK → roles(id) ON DELETE CASCADE — same-DB cascade (ban #4 allows
--     same-schema FK cascade). Deleting a role drops its selectors; the role's
--     bindings are FK-RESTRICT-protected (a role in use cannot be deleted), so a
--     selector is never orphaned from a live binding.
--   * object_types text[] NOT NULL, len ≥1 (CHECK) — the dotted closed-table types
--     (authzmap.ObjectType key, e.g. "compute.instance") the rule selects.
--   * match_labels jsonb NOT NULL, non-empty object (CHECK kacho_labels_valid +
--     length ≥1) — the label-equality selector (labels @> match_labels), the same
--     shape access_binding_selector enforces.
--
-- This table COEXISTS with access_binding_selector (the legacy per-binding arm).
-- The legacy selector path stays authoritative for legacy bindings until
-- re-author; the role.rules path drives bindings whose ROLE carries
-- ARM_LABELS rules. The reconciler reads role_rule_selectors for the latter.

CREATE TABLE kacho_iam.role_rule_selectors (
  role_id      text        NOT NULL
    REFERENCES kacho_iam.roles (id) ON DELETE CASCADE,
  rule_fp      text        NOT NULL,
  object_types text[]      NOT NULL,
  match_labels jsonb       NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT role_rule_selectors_pkey PRIMARY KEY (role_id, rule_fp),
  CONSTRAINT role_rule_selectors_fp_nonempty    CHECK (rule_fp <> ''),
  CONSTRAINT role_rule_selectors_types_nonempty CHECK (cardinality(object_types) >= 1),
  CONSTRAINT role_rule_selectors_labels_obj      CHECK (jsonb_typeof(match_labels) = 'object'),
  -- non-empty without a subquery (CHECK forbids subqueries): an empty jsonb object
  -- is the canonical '{}' literal, so inequality to it is the non-empty predicate.
  CONSTRAINT role_rule_selectors_labels_nonempty CHECK (match_labels <> '{}'::jsonb),
  CONSTRAINT role_rule_selectors_labels_valid    CHECK (kacho_iam.kacho_labels_valid(match_labels))
);

-- Fast-path reconcile-by-object (when an object gets a matching label):
-- when a resource_mirror row changes, the reconciler probes which role selectors
-- now match the object (object_type ∈ object_types AND mirror.labels @> match_labels).
-- A GIN index on object_types serves the "type is one of mine" membership test.
CREATE INDEX role_rule_selectors_object_types_idx
  ON kacho_iam.role_rule_selectors USING gin (object_types);

-- +goose Down

DROP TABLE IF EXISTS kacho_iam.role_rule_selectors;
