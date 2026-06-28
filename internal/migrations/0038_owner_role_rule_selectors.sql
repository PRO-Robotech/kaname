-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- RBAC explicit-model 2026 — owner `*.*` per-object content forward path.
--
-- WHAT this does:
--   Seeds the OWNER system-role's UNIFIED materializing selector into
--   kacho_iam.role_rule_selectors (the forward fast-path JOIN index used by
--   SelectorBindingsMatchingObject + ListSelectorBindingIDs). The owner role is
--   seeded by raw SQL (migration 0035) and therefore — unlike a custom role written
--   via Role.Create + ReplaceRuleSelectors — never gets its role_rule_selectors row.
--   Without this row a freshly-registered object never fast-path-matches an owner
--   binding, so owner-content-forward would only converge on the periodic
--   sweep (and ONLY once the Go boot-backfill seeded the row). Seeding it as a
--   MIGRATION makes the invariant hold at DB-level right after `goose up`, before any
--   traffic — so a fresh account's new objects forward-materialize owner content on
--   their RegisterResource change event (≤2s), independent of the best-effort boot
--   backfill (which remains as idempotent self-heal).
--
-- The values are the DETERMINISTIC projection of domain.OwnerRoleRules() through
-- MaterializingSelectors() (role-level, wildcard-expanding):
--   rule_fp      = Rule{module:"*",resources:["*"],verbs:["*"]}.Fingerprint() (sha256)
--   arm          = 'anchor'  (the `*.*` "selector all" shape)
--   object_types = domain.AllMaterializableTypes() (sorted closed set, 16 types)
--   resource_names = '{}', match_labels = '{}'  (anchor arm-shape, migration 0034)
-- A domain lockstep guard test (rule_wildcard_scope_test.go) asserts these match the
-- Go projection byte-for-byte, so the SQL constant can never silently drift.
--
-- Idempotent: ON CONFLICT (role_id, rule_fp) DO UPDATE re-applies the same row, so
-- re-running the migration (or the Go self-heal) is a no-op. Additive — no column
-- drop, no edit to an applied migration (ban #5). The next migration is 0039.

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
   SET arm            = EXCLUDED.arm,
       object_types   = EXCLUDED.object_types,
       resource_names = EXCLUDED.resource_names,
       match_labels   = EXCLUDED.match_labels,
       updated_at     = now();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM kacho_iam.role_rule_selectors
 WHERE role_id = 'rol' || substr(md5('owner'), 1, 17)
   AND rule_fp = '3a9a54c3276716602674c9995c9321bea53a5ae693684842a389a80ecb1c80c4';

-- +goose StatementEnd
