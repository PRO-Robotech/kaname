-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- The materialized
-- desired-state MEMBERSHIP of a binding's target — the set of concrete objects a
-- selector (byLabel) OR a resources[] (byName) target currently resolves to,
-- each carrying an observable verification_status.
--
-- WHY MATERIALIZED: selector membership is dynamic — labels
-- change in the owning service (compute) and arrive over the `compute→iam`
-- RegisterResource edge into kacho_iam.resource_mirror. The reconciler
-- recomputes the desired set on each trigger and DIFFS it against the rows here:
-- a newly-matched-under-scope object → ACTIVE + per-object FGA tuple emit; an
-- object that fell out (label removed / no longer matches) → eager-revoke + row
-- removal. Materializing gives a cheap diff AND an observable per-member
-- verification_status for read/UI WITHOUT a mirror-scan on the authz/read
-- path (Check stays an O(1) FGA tuple lookup, no on-Check selector evaluation).
--
-- verification_status — the observable per-member containment verdict:
--   * ACTIVE               — object is in resource_mirror AND under the binding's
--                            scope-anchor → per-object FGA tuple IS emitted.
--   * PENDING_VERIFICATION — object NOT yet in resource_mirror (the grant raced
--                            ahead of the owner's RegisterResource) → NO tuple;
--                            the reconciler verifies it when the mirror row lands.
--   * REJECTED             — object IS in resource_mirror but NOT under scope
--                            (mirror.parent_* ⋢ scope) → NO tuple + audit event
--                            (not silent — enforces containment).
--
-- WITHIN-SERVICE INVARIANTS — DB-level only (ban #10):
--   * binding_id FK → access_bindings(id) ON DELETE CASCADE — same-DB cascade
--     (ban #4 explicitly allows same-schema FK cascade). Deleting a binding
--     atomically drops all its materialized members; the reconciler never
--     re-materializes a deleted binding. No software cascade.
--   * PRIMARY KEY (binding_id, object_type, object_id) — exactly one membership
--     row per (binding, object). The reconciler UPSERTs (ON CONFLICT … DO UPDATE
--     verification_status) so a re-materialization of the same object is
--     idempotent and serializes concurrent reconcile passes on the PK row-lock
--     (deterministic last-write, no duplicate members/tuples).
--   * CHECK verification_status IN ('PENDING_VERIFICATION','ACTIVE','REJECTED')
--     — closed enumeration; an arbitrary status can never land (the use-case
--     maps the containment verdict to exactly one of these, defense-in-depth).
--
-- object_type — closed-table object type (authzmap.ObjectType key, e.g.
-- "compute.instance"); object_id — opaque cross-DB soft-ref (no FK, ban #8) like
-- access_binding_targets.id and resource_mirror.object_id. created_at orders the
-- read projection; updated_at marks the last status transition.

CREATE TABLE kacho_iam.access_binding_target_members (
  binding_id          text        NOT NULL
    REFERENCES kacho_iam.access_bindings (id) ON DELETE CASCADE,
  object_type         text        NOT NULL,
  object_id           text        NOT NULL,
  verification_status text        NOT NULL DEFAULT 'PENDING_VERIFICATION',
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT access_binding_target_members_pkey
    PRIMARY KEY (binding_id, object_type, object_id),
  CONSTRAINT access_binding_target_members_type_nonempty CHECK (object_type <> ''),
  CONSTRAINT access_binding_target_members_id_nonempty   CHECK (object_id <> ''),
  CONSTRAINT access_binding_target_members_status_valid
    CHECK (verification_status IN ('PENDING_VERIFICATION', 'ACTIVE', 'REJECTED'))
);

-- Reconcile-scan by object: when a resource_mirror row changes (RegisterResource
-- brought/updated/removed an object), the reconciler must find every membership
-- row referencing that (object_type, object_id) to re-evaluate it across all
-- bindings (PENDING→ACTIVE verify). The PK leads with
-- binding_id, so a separate index on (object_type, object_id) serves the
-- by-object reconcile probe.
CREATE INDEX access_binding_target_members_object_idx
  ON kacho_iam.access_binding_target_members (object_type, object_id);

-- Reconcile-scan by status: the periodic sweep and the PENDING-verify pass
-- scan members in a non-terminal status (PENDING_VERIFICATION) to re-evaluate
-- them; a partial index keeps that scan tight.
CREATE INDEX access_binding_target_members_pending_idx
  ON kacho_iam.access_binding_target_members (binding_id)
  WHERE verification_status = 'PENDING_VERIFICATION';

-- +goose Down

DROP TABLE IF EXISTS kacho_iam.access_binding_target_members;
