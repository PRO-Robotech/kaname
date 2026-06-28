-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- The child table
-- kacho_iam.access_binding_targets carries the per-object target refs of a
-- binding. The "what object" decision moves out of role.permissions (concrete
-- resourceName) into the binding itself, so the role becomes a reusable
-- verb-bundle.
--
-- WITHIN-SERVICE INVARIANTS — DB-level only (ban #10):
--   * binding_id FK → access_bindings(id) ON DELETE CASCADE — same-DB cascade
--     (ban #4 explicitly allows same-schema FK cascade). Deleting a binding
--     drops all its target rows atomically; no software cascade.
--   * UNIQUE(binding_id, type, id) — idempotent add/dedup: a repeated
--     AddTargetResources of the same ref is a no-op via INSERT … ON CONFLICT
--     DO NOTHING; a concurrent double-add serializes on the unique
--     index, leaving exactly one row.
--
-- ALL_IN_SCOPE SEMANTICS: a binding with `all_in_scope` target has ZERO
-- rows here. The read-side projects 0 rows ⇒ all_in_scope, which also yields the
-- forward-only backfill of legacy bindings — no nullable
-- flag column needed.
--
-- type — closed-table object type (authzmap.ObjectType key, e.g.
-- "compute.instance"); validated in the use-case (closed enumeration). id —
-- opaque cross-DB soft-ref (no FK, no peer-existence; ban #8) like the parent
-- access_bindings.resource_id. created_at orders the read projection
-- deterministically.

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

-- No dedicated read index is needed: the UNIQUE(binding_id, type, id) index
-- above leads with binding_id and already covers both the membership/dedup
-- probe AND the ListByResource/Get target-projection read filtered by
-- binding_id and ordered by (type, id) — the leading-column prefix
-- serves the filter and the index order serves the stable read order.

-- +goose Down

DROP TABLE IF EXISTS kacho_iam.access_binding_targets;
