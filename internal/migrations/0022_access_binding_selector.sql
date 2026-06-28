-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- The SELECTOR spec of a
-- binding's `selector` target arm (byLabel). An earlier migration persisted only
-- the `resources[]` arm (one row per ref in access_binding_targets) and
-- `all_in_scope` (the ABSENCE of any target rows). This migration activates the
-- third arm — a label selector —
-- and it needs its OWN storage: a selector is a single (types, match_labels)
-- spec per binding, not a list of object refs.
--
-- WHY A SEPARATE TABLE (not reusing access_binding_targets): the selector is a
-- POLICY (types + label-equality set), not a concrete object list; the concrete
-- objects it currently resolves to live in access_binding_target_members
-- (materialized by the reconciler from resource_mirror). One selector row per
-- binding (PK binding_id); the materialized membership is the dynamic projection.
--
-- WITHIN-SERVICE INVARIANTS — DB-level only (ban #10):
--   * binding_id PK + FK → access_bindings(id) ON DELETE CASCADE — exactly one
--     selector row per binding, dropped atomically with the binding (same-DB
--     cascade, ban #4 allows it; mirrors access_binding_targets / _members). The
--     PK also makes ReplaceTargetSelector's UPSERT idempotent and serializes
--     concurrent replaces on the row-lock (the CAS on access_bindings.xmin in the
--     use-case is the lost-update guard).
--   * types text[] NOT NULL + CHECK array_length >= 1 — a selector MUST constrain
--     the object type; an empty types array can never land (the use-case
--     rejects it sync, this is the DB belt).
--   * match_labels jsonb NOT NULL + CHECK jsonb_typeof = 'object' AND != '{}'
--     — AND-equality match set, non-empty (empty matchLabels ⇒ "use all_in_scope").
--     A non-object or empty map can never land.
--
-- The binding's target arm is discriminated by storage:
--   * row in access_binding_selector            ⇒ TargetKindSelector
--   * rows in access_binding_targets            ⇒ TargetKindResources
--   * neither                                   ⇒ TargetKindAllInScope (default)
-- A binding can never have BOTH (the use-case persists exactly one arm; switching
-- arms is Delete+Create).

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

-- +goose Down

DROP TABLE IF EXISTS kacho_iam.access_binding_selector;
