-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- #71: EXTEND the wildcard-catalog system-role `*.*` materializing selectors
-- (admin / edit / view / owner) to the storage namespace resources.
--
-- WHY: storage Volume/Snapshot/Image carry own-table labels (mirror-fed via
-- storage->iam RegisterResource `Labels` payload), exactly like vpc/compute, so
-- they joined domain.labelSelectableTypes and thus domain.AllMaterializableTypes()
-- (now 26 types, the prior 23 + storage.images/snapshots/volumes). The system
-- roles' UNIFIED materializing selector (role_rule_selectors row) MUST carry them,
-- otherwise a freshly-created Volume/Snapshot/Image does NOT fast-path-match the
-- account/project-editor|owner binding -> the reconciler materializes NO per-object
-- v_* for the creator -> the OWNER gets 403 on their OWN just-created volume (the
-- storage_volume tuple then carries only the `#project` structural link, no v_get
-- for the creator SA). This is the materialization-side completion of the #71
-- FGA-type + authzmap wiring (commit c01c2b9): the types being valid FGA writes is
-- necessary but not sufficient — the binding-discovery selector must include them.
--
-- WHAT: re-seed admin/edit/view (migration 0053) + owner (migration 0043) with the
-- EXPANDED object_types list. Keyed by (role_id, rule_fp) — the rule_fp is UNCHANGED
-- (it hashes Rule{module:"*",resources:["*"],verbs:[...]}, NOT object_types), so this
-- is an UPSERT of the SAME rows' object_types (same shape as 0043). The values are the
-- deterministic sorted projection of domain.AllMaterializableTypes() (storage sorts
-- between registry.repositories and vpc.address). The remaining materializing system
-- roles (kacho-system.*, per-domain `<mod>.<res>.<verb>`) are re-projected from Go by
-- the boot-backfill SyncAllSystemRoleSelectors, which now returns the 26-type set.
--
-- Idempotent: ON CONFLICT (role_id, rule_fp) DO UPDATE re-applies the same row, so a
-- re-run (or the Go self-heal at boot) is a no-op. Additive — no column drop, no edit
-- to an applied migration (ban #5). Next migration: 0061.

INSERT INTO kacho_iam.role_rule_selectors
  (role_id, rule_fp, arm, object_types, resource_names, match_labels, created_at, updated_at)
VALUES
  -- admin (`*.*.*`) — full CRUD; same rule (and fp) as owner.
  ('rol' || substr(md5('admin'), 1, 17),
   '3a9a54c3276716602674c9995c9321bea53a5ae693684842a389a80ecb1c80c4',
   'anchor',
   ARRAY[
     'compute.disk', 'compute.image', 'compute.instance', 'compute.snapshot',
     'iam.accessBinding', 'iam.account', 'iam.group', 'iam.project',
     'iam.role', 'iam.serviceAccount', 'iam.user',
     'loadbalancer.listeners', 'loadbalancer.networkLoadBalancers', 'loadbalancer.targetGroups',
     'registry.registries', 'registry.repositories',
     'storage.images', 'storage.snapshots', 'storage.volumes',
     'vpc.address', 'vpc.gateway', 'vpc.network', 'vpc.networkInterface',
     'vpc.routeTable', 'vpc.securityGroup', 'vpc.subnet'
   ]::text[],
   '{}'::text[], '{}'::jsonb, now(), now()),
  -- edit (`*.*` get/list/update) — CRUD-editor (reads what it edits, migration 0040).
  ('rol' || substr(md5('edit'), 1, 17),
   'e4919459188e4b7b3786370b6c0899a79b4df159bd1988aef0b3ad23bb5aacfe',
   'anchor',
   ARRAY[
     'compute.disk', 'compute.image', 'compute.instance', 'compute.snapshot',
     'iam.accessBinding', 'iam.account', 'iam.group', 'iam.project',
     'iam.role', 'iam.serviceAccount', 'iam.user',
     'loadbalancer.listeners', 'loadbalancer.networkLoadBalancers', 'loadbalancer.targetGroups',
     'registry.registries', 'registry.repositories',
     'storage.images', 'storage.snapshots', 'storage.volumes',
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
     'storage.images', 'storage.snapshots', 'storage.volumes',
     'vpc.address', 'vpc.gateway', 'vpc.network', 'vpc.networkInterface',
     'vpc.routeTable', 'vpc.securityGroup', 'vpc.subnet'
   ]::text[],
   '{}'::text[], '{}'::jsonb, now(), now()),
  -- owner (`*.*.*`) — account/project owner, admin on every object kind in scope.
  ('rol' || substr(md5('owner'), 1, 17),
   '3a9a54c3276716602674c9995c9321bea53a5ae693684842a389a80ecb1c80c4',
   'anchor',
   ARRAY[
     'compute.disk', 'compute.image', 'compute.instance', 'compute.snapshot',
     'iam.accessBinding', 'iam.account', 'iam.group', 'iam.project',
     'iam.role', 'iam.serviceAccount', 'iam.user',
     'loadbalancer.listeners', 'loadbalancer.networkLoadBalancers', 'loadbalancer.targetGroups',
     'registry.registries', 'registry.repositories',
     'storage.images', 'storage.snapshots', 'storage.volumes',
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

-- Revert to the pre-storage object_types list (0053/0043 set, without storage.*),
-- keyed by the same (role_id, rule_fp). Idempotent.
UPDATE kacho_iam.role_rule_selectors
   SET object_types = ARRAY[
         'compute.disk', 'compute.image', 'compute.instance', 'compute.snapshot',
         'iam.accessBinding', 'iam.account', 'iam.group', 'iam.project',
         'iam.role', 'iam.serviceAccount', 'iam.user',
         'loadbalancer.listeners', 'loadbalancer.networkLoadBalancers', 'loadbalancer.targetGroups',
         'registry.registries', 'registry.repositories',
         'vpc.address', 'vpc.gateway', 'vpc.network', 'vpc.networkInterface',
         'vpc.routeTable', 'vpc.securityGroup', 'vpc.subnet'
       ]::text[],
       updated_at = now()
 WHERE (role_id = 'rol' || substr(md5('admin'), 1, 17) AND rule_fp = '3a9a54c3276716602674c9995c9321bea53a5ae693684842a389a80ecb1c80c4')
    OR (role_id = 'rol' || substr(md5('edit'), 1, 17)  AND rule_fp = 'e4919459188e4b7b3786370b6c0899a79b4df159bd1988aef0b3ad23bb5aacfe')
    OR (role_id = 'rol' || substr(md5('view'), 1, 17)  AND rule_fp = 'fe68d56d542e8b599256b1a7eee6e31eed6db358e7254af4b5e25c7195dcf68e')
    OR (role_id = 'rol' || substr(md5('owner'), 1, 17) AND rule_fp = '3a9a54c3276716602674c9995c9321bea53a5ae693684842a389a80ecb1c80c4');

-- +goose StatementEnd
