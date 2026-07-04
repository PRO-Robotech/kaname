-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- Owner `*.*` per-object forward path EXTENDED to the registry namespace resources.
--
-- WHY: registry.registries carries own-table labels (label-selectable authz scope),
-- and registry.repositories is the per-repo authz object materialized on docker push
-- (materializable, NOT label-selectable). Both are in domain.AllMaterializableTypes().
-- The owner role's UNIFIED materializing selector (role_rule_selectors row) must carry
-- BOTH, otherwise a freshly-created Registry / freshly-pushed repository would not
-- fast-path-match the account/project-owner binding (owner would not see their own
-- registries, and the pushed images would be unreachable even for the owner).
--
-- WHAT: re-seed the owner role's role_rule_selectors row with the EXPANDED
-- object_types list. Keyed by (role_id, rule_fp) — the rule_fp is UNCHANGED (it is
-- Rule{module:"*",resources:["*"],verbs:["*"]}.Fingerprint(), a hash of the RULE, not
-- of object_types), so this is an UPSERT of the SAME row's object_types (migration
-- 0039's ON CONFLICT … DO UPDATE shape). The values are the deterministic projection
-- of domain.OwnerRoleRules() through MaterializingSelectors():
--   rule_fp      = unchanged sha256 (lockstep-guarded in rule_wildcard_scope_test.go)
--   arm          = 'anchor'  (the `*.*` "selector all" shape)
--   object_types = domain.AllMaterializableTypes() (sorted closed set — now 23 types,
--                  the 21 prior + registry.registries + registry.repositories)
--
-- Idempotent: ON CONFLICT (role_id, rule_fp) DO UPDATE re-applies the same row, so a
-- re-run (or the Go self-heal) is a no-op. Additive — no column drop, no edit to an
-- applied migration.

INSERT INTO kacho_iam.role_rule_selectors
  (role_id, rule_fp, arm, object_types, resource_names, match_labels, created_at, updated_at)
VALUES (
  'rol' || substr(md5('owner'), 1, 17),
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
  '{}'::text[],
  '{}'::jsonb,
  now(),
  now()
)
ON CONFLICT (role_id, rule_fp) DO UPDATE
   SET arm            = EXCLUDED.arm,
       object_types   = EXCLUDED.object_types,
       resource_names = EXCLUDED.resource_names,
       match_labels   = EXCLUDED.match_labels,
       updated_at     = now();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Revert to the pre-registry object_types list (migration 0039's set, without
-- registry.registries). Keyed by the same (role_id, rule_fp); idempotent.
UPDATE kacho_iam.role_rule_selectors
   SET object_types = ARRAY[
         'compute.disk', 'compute.image', 'compute.instance', 'compute.snapshot',
         'iam.accessBinding', 'iam.account', 'iam.group', 'iam.project',
         'iam.role', 'iam.serviceAccount', 'iam.user',
         'loadbalancer.listeners', 'loadbalancer.networkLoadBalancers', 'loadbalancer.targetGroups',
         'vpc.address', 'vpc.gateway', 'vpc.network', 'vpc.networkInterface',
         'vpc.routeTable', 'vpc.securityGroup', 'vpc.subnet'
       ]::text[],
       updated_at = now()
 WHERE role_id = 'rol' || substr(md5('owner'), 1, 17)
   AND rule_fp = '3a9a54c3276716602674c9995c9321bea53a5ae693684842a389a80ecb1c80c4';

-- +goose StatementEnd
