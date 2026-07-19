-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- RBAC explicit-model 2026 — generalize the owner-only role_rule_selectors seed to the
-- WILDCARD catalog system roles (`admin`/`edit`/`view`).
--
-- WHAT this does:
--   Seeds each wildcard catalog role's UNIFIED materializing selector into
--   kacho_iam.role_rule_selectors (the forward fast-path JOIN index used by
--   SelectorBindingsMatchingObject + ListSelectorBindingIDs). These roles are seeded by
--   raw SQL (migrations 0001/0031) and therefore — unlike a custom role written via
--   Role.Create + ReplaceRuleSelectors — never get a role_rule_selectors row. Without it
--   a BOUNDED-scope binding of these roles (project-admin `admin`@PROJECT, project-editor
--   `edit`@PROJECT, project-viewer `view`@PROJECT) never fast-path-matches a
--   freshly-registered object, so its per-object v_* is never materialized → the grantee
--   403s on its OWN resource forever (and the owner-tuple op-gate fails-closed 30s).
--   This is the keystone authz-fix: project-editor CRUD over project content is
--   first-class (explicit-rbac-model.md).
--
-- Seeding it as a MIGRATION makes the invariant hold at DB-level right after `goose up`,
-- before any traffic — independent of the best-effort Go boot-backfill
-- (seed.SyncAllSystemRoleSelectors), which remains the COMPREHENSIVE self-healing seeder
-- (it also projects the per-domain roles `vpc.network.admin`… + the kacho-system
-- built-ins, and prunes stale fingerprints). The migration seeds ONLY the three
-- bounded-scope-relevant WILDCARD roles here because SQL cannot compute the Go sha256
-- rule fingerprint — hard-coding all 58 system roles' fingerprints would be an
-- unmaintainable lockstep surface; the Go projection is the maintainable path for the
-- rest, and this migration covers the load-bearing project-admin/editor/viewer trio.
--
-- The values are the DETERMINISTIC projection of each role's rule through
-- domain.Rules.MaterializingSelectors() (role-level, wildcard-expanding):
--   admin (`*.*.*`)              → rule_fp 3a9a54c3…  (identical rule shape to owner)
--   edit  (`*.*` get/list/update)→ rule_fp e4919459…  (verbs differ → distinct fp)
--   view  (`*.*` read/list/get)  → rule_fp fe68d56d…
--   arm='anchor', object_types = domain.AllMaterializableTypes() (sorted 23-type set,
--     mirror of the owner selector list, migration 0043), resource_names/match_labels
--     empty (anchor arm-shape, migration 0034).
-- A domain lockstep guard (rule_wildcard_scope_test.go
-- TestSystemWildcardRoleSelectors_MigrationLockstep) asserts these fps + types match the
-- Go projection byte-for-byte, so the SQL constants can never silently drift.
--
-- SECURITY (not over-grant): a wildcard role bound at a BOUNDED scope materializes
-- per-object v_* ONLY on objects contained in that scope — the reconciler re-verifies
-- MirrorObject.IsContainedIn per object (a project-A editor is never materialized on
-- project-B), and MaterializingSelectorsInScope yields NO content selectors for a
-- GLOBAL/CLUSTER binding (cluster super-admin stays the D-9 flat short-circuit). The
-- role-level index over-includes; the per-binding scope gate narrows.
--
-- Idempotent: ON CONFLICT (role_id, rule_fp) DO UPDATE re-applies the same row (the Go
-- self-heal converges on the same rows). Additive — no column drop, no edit to an applied
-- migration (ban #5). Next migration: 0054.

INSERT INTO kacho_iam.role_rule_selectors
  (role_id, rule_fp, arm, object_types, resource_names, match_labels, created_at, updated_at)
VALUES
  -- admin (`*.*.*`) — full CRUD; identical rule shape (and fp) to owner.
  ('rol' || substr(md5('admin'), 1, 17),
   '3a9a54c3276716602674c9995c9321bea53a5ae693684842a389a80ecb1c80c4',
   'anchor',
   ARRAY[
     'compute.disk', 'compute.image', 'compute.instance', 'compute.snapshot',
     'iam.accessBinding', 'iam.account', 'iam.group', 'iam.project',
     'iam.role', 'iam.serviceAccount', 'iam.user',
     'loadbalancer.listeners', 'loadbalancer.networkLoadBalancers', 'loadbalancer.targetGroups',
     'registry.registries', 'registry.repositories',
     'vpc.address', 'vpc.gateway', 'vpc.network', 'vpc.networkInterface',
     'vpc.routeTable', 'vpc.securityGroup', 'vpc.subnet'
   ]::text[],
   '{}'::text[], '{}'::jsonb, now(), now()),
  -- edit (`*.*` get/list/update) — CRUD-editor (must read what it edits, migration 0040).
  ('rol' || substr(md5('edit'), 1, 17),
   'e4919459188e4b7b3786370b6c0899a79b4df159bd1988aef0b3ad23bb5aacfe',
   'anchor',
   ARRAY[
     'compute.disk', 'compute.image', 'compute.instance', 'compute.snapshot',
     'iam.accessBinding', 'iam.account', 'iam.group', 'iam.project',
     'iam.role', 'iam.serviceAccount', 'iam.user',
     'loadbalancer.listeners', 'loadbalancer.networkLoadBalancers', 'loadbalancer.targetGroups',
     'registry.registries', 'registry.repositories',
     'vpc.address', 'vpc.gateway', 'vpc.network', 'vpc.networkInterface',
     'vpc.routeTable', 'vpc.securityGroup', 'vpc.subnet'
   ]::text[],
   '{}'::text[], '{}'::jsonb, now(), now()),
  -- view (`*.*` read/list/get) — read-only.
  ('rol' || substr(md5('view'), 1, 17),
   'fe68d56d542e8b599256b1a7eee6e31eed6db358e7254af4b5e25c7195dcf68e',
   'anchor',
   ARRAY[
     'compute.disk', 'compute.image', 'compute.instance', 'compute.snapshot',
     'iam.accessBinding', 'iam.account', 'iam.group', 'iam.project',
     'iam.role', 'iam.serviceAccount', 'iam.user',
     'loadbalancer.listeners', 'loadbalancer.networkLoadBalancers', 'loadbalancer.targetGroups',
     'registry.registries', 'registry.repositories',
     'vpc.address', 'vpc.gateway', 'vpc.network', 'vpc.networkInterface',
     'vpc.routeTable', 'vpc.securityGroup', 'vpc.subnet'
   ]::text[],
   '{}'::text[], '{}'::jsonb, now(), now())
ON CONFLICT (role_id, rule_fp) DO UPDATE
   SET arm            = EXCLUDED.arm,
       object_types   = EXCLUDED.object_types,
       resource_names = EXCLUDED.resource_names,
       match_labels   = EXCLUDED.match_labels,
       updated_at     = now();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM kacho_iam.role_rule_selectors
 WHERE (role_id = 'rol' || substr(md5('admin'), 1, 17)
        AND rule_fp = '3a9a54c3276716602674c9995c9321bea53a5ae693684842a389a80ecb1c80c4')
    OR (role_id = 'rol' || substr(md5('edit'), 1, 17)
        AND rule_fp = 'e4919459188e4b7b3786370b6c0899a79b4df159bd1988aef0b3ad23bb5aacfe')
    OR (role_id = 'rol' || substr(md5('view'), 1, 17)
        AND rule_fp = 'fe68d56d542e8b599256b1a7eee6e31eed6db358e7254af4b5e25c7195dcf68e');

-- +goose StatementEnd
