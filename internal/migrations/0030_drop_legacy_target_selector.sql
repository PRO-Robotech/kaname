-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- RBAC rules-model 2026 clean-cut. The legacy per-binding
-- resource-scoped target arms are removed: the role.rules[] model
-- fully supersedes them. The "what object" decision now lives on the ROLE (rules
-- ARM_NAMES / ARM_LABELS materialized by the reconciler), not on the binding via
-- access_binding_targets (byName) / access_binding_selector (byLabel).
--
-- DROP the two legacy child tables:
--   * kacho_iam.access_binding_targets  (mig 0018, byName resources[] arm)
--   * kacho_iam.access_binding_selector (mig 0022, byLabel selector arm)
--
-- KEEP kacho_iam.access_binding_target_members (mig 0020/0027) — the rules
-- reconciler materializes role.rules ARM_LABELS membership into it; it is NOT a
-- legacy table.
--
-- access_bindings has NO target/selector/target_ref COLUMNS (the legacy arms lived
-- ONLY in these child tables); the canonical `scope` SMALLINT column (mig 0005)
-- backing scope_ref is KEPT untouched.
--
-- Same-DB DROP, no cross-service cascade (ban #4 only forbids
-- CASCADE across a service boundary). Both tables carry FK binding_id →
-- access_bindings(id) ON DELETE CASCADE; dropping the tables removes those child
-- FKs cleanly. Forward-only (ban #5 — not an edit of an applied migration). The
-- Down recreates the empty DDL for rollback completeness (data is NOT restored —
-- a clean-cut is one-way; the rules model is the source of truth).

DROP TABLE IF EXISTS kacho_iam.access_binding_targets;
DROP TABLE IF EXISTS kacho_iam.access_binding_selector;

-- +goose Down

-- Rollback completeness: recreate the legacy child tables (empty). The original
-- DDL is copied verbatim from mig 0018 / 0022. Data is NOT restored — the
-- clean-cut migrated authority to role.rules[] (no reverse projection).

CREATE TABLE kacho_iam.access_binding_targets (
  binding_id text NOT NULL
    REFERENCES kacho_iam.access_bindings (id) ON DELETE CASCADE,
  type       text NOT NULL,
  id         text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT access_binding_targets_uniq UNIQUE (binding_id, type, id),
  CONSTRAINT access_binding_targets_type_nonempty CHECK (type <> ''),
  CONSTRAINT access_binding_targets_id_nonempty   CHECK (id <> '' AND id <> '*')
);

CREATE TABLE kacho_iam.access_binding_selector (
  binding_id   text        NOT NULL
    REFERENCES kacho_iam.access_bindings (id) ON DELETE CASCADE,
  types        text[]      NOT NULL,
  match_labels jsonb       NOT NULL DEFAULT '{}'::jsonb,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT access_binding_selector_pkey PRIMARY KEY (binding_id),
  CONSTRAINT access_binding_selector_types_nonempty
    CHECK (array_length(types, 1) >= 1),
  CONSTRAINT access_binding_selector_match_labels_object
    CHECK (jsonb_typeof(match_labels) = 'object' AND match_labels <> '{}'::jsonb)
);
