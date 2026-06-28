-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- RBAC explicit-model 2026 — owner `*.*` per-object content forward path EXTENDED to
-- iam-NATIVE content (role/group/serviceAccount/user/accessBinding).
--
-- WHY: the flat OpenFGA model (Contract-A) removed the `<rel> from account` ACCESS
-- cascade on the iam leaf types, so the owner's access on a Role/Group/SA/User/
-- AccessBinding must be MATERIALIZED per-object (forward-mat) instead of
-- derived. domain.AllMaterializableTypes() now includes these five iam content types
-- (the `*.*` wildcard-expansion set), so the owner role's UNIFIED materializing
-- selector (role_rule_selectors row seeded by migration 0038) must carry them too —
-- otherwise SelectorBindingsMatchingObject / IAMDirectSelectorBindingsMatchingObject
-- would not fast-path-match a freshly-created iam content object to the owner binding.
--
-- WHAT: re-seed the owner role's role_rule_selectors row with the EXPANDED
-- object_types list. Keyed by (role_id, rule_fp) — the rule_fp is UNCHANGED (it is
-- Rule{module:"*",resources:["*"],verbs:["*"]}.Fingerprint(), a hash of the RULE, not
-- of object_types), so this is an UPSERT of the SAME row's object_types (migration
-- 0038's ON CONFLICT … DO UPDATE shape). The values are the deterministic projection
-- of domain.OwnerRoleRules() through MaterializingSelectors():
--   rule_fp      = unchanged sha256 (lockstep-guarded in rule_wildcard_scope_test.go)
--   arm          = 'anchor'  (the `*.*` "selector all" shape, migration 0034)
--   object_types = domain.AllMaterializableTypes() (sorted closed set, now 21 types)
-- The domain lockstep guard test asserts these match the Go projection byte-for-byte.
--
-- Idempotent: ON CONFLICT (role_id, rule_fp) DO UPDATE re-applies the same row, so a
-- re-run (or the Go self-heal) is a no-op. Additive — no column drop, no edit to an
-- applied migration (ban #5). The next migration is 0040.

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

-- Revert the owner selector row to migration 0038's 16-type list (pre-iam-content).
INSERT INTO kacho_iam.role_rule_selectors
  (role_id, rule_fp, arm, object_types, resource_names, match_labels, created_at, updated_at)
VALUES (
  'rol' || substr(md5('owner'), 1, 17),
  '3a9a54c3276716602674c9995c9321bea53a5ae693684842a389a80ecb1c80c4',
  'anchor',
  ARRAY[
    'compute.disk', 'compute.image', 'compute.instance', 'compute.snapshot',
    'iam.account', 'iam.project',
    'loadbalancer.listeners', 'loadbalancer.networkLoadBalancers', 'loadbalancer.targetGroups',
    'vpc.address', 'vpc.gateway', 'vpc.network', 'vpc.networkInterface',
    'vpc.routeTable', 'vpc.securityGroup', 'vpc.subnet'
  ]::text[],
  '{}'::text[],
  '{}'::jsonb,
  now(),
  now()
)
ON CONFLICT (role_id, rule_fp) DO UPDATE
   SET object_types = EXCLUDED.object_types,
       updated_at   = now();

-- +goose StatementEnd
