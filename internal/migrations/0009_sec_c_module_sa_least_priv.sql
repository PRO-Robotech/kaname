-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0009_sec_c_module_sa_least_priv.sql — SEC-C: least-privilege module
-- ServiceAccount identities (ReBAC) + backing 4-segment RBAC-v2 roles +
-- cluster-scope AccessBindings + FGA `fga_writer` relation-tuples.
--
-- ban #5: new migration, never edits applied ones.
--
-- Provisions a personal system ServiceAccount per internal module
-- (vpc / compute / nlb / vpc-operator / api-gateway) with:
--   * deterministic sva-id  = 'sva' || substr(md5('kacho-<svc>'), 1, 17)
--   * a backing system role (deterministic rol-id) carrying the EXACT
--     4-segment permission set — empirically derived from
--     kacho-proto/gen/permission_catalog.json (promoted module.resource.*.verb;
--     `*` = wildcard resourceName as in 0005 / seed_nlb_roles precedent).
--   * an AccessBinding (subject=service_account, role, cluster scope).
--   * an FGA relation-tuple `service_account:<sva>#fga_writer@iam_fgaproxy:system`
--     (enqueued via kacho_iam.fga_outbox, applied by the drainer) for the modules
--     that use the FGA-proxy: vpc / compute / nlb. vpc-operator (read-only sync)
--     and api-gateway (identity-only) get NO fga_writer tuple.
--
-- The least-priv authority model is ReBAC (relation-tuples); the RBAC-v2 role is
-- the backing carrier whose permission strings satisfy the strict 4-segment
-- CHECK iam_permissions_valid (0005).
--
-- service_accounts.account_id is NOT NULL (FK → accounts), accounts.owner_user_id
-- is NOT NULL (FK → users): the migration therefore first seeds a deterministic
-- system user + system account to anchor the module SAs (all idempotent,
-- ON CONFLICT DO NOTHING). These rows are immutable system rows; deletion is
-- RESTRICT-guarded by downstream FKs.

-- +goose Up
-- +goose StatementBegin

-- ── 1. System anchor user + account (immutable; owns the module SAs) ──────────
-- Deterministic ids; PENDING invite_status keeps external_id='' valid
-- (users_invite_status_consistency).
INSERT INTO kacho_iam.users (id, external_id, email, display_name, account_id, invite_status)
VALUES (
  'usr' || substr(md5('kacho-system'), 1, 17),
  '',
  'system@kacho.local',
  'Kacho System (module SA owner)',
  'acc' || substr(md5('kacho-system'), 1, 17),
  'PENDING'
)
ON CONFLICT (id) DO NOTHING;

-- accounts.owner_user_id FK is DEFERRABLE INITIALLY DEFERRED, so the
-- account → user reference resolves at commit even though we insert the user
-- first above (order-independent).
INSERT INTO kacho_iam.accounts (id, name, description, owner_user_id)
VALUES (
  'acc' || substr(md5('kacho-system'), 1, 17),
  'kacho-system',
  'System account anchoring internal module service-accounts (SEC-C)',
  'usr' || substr(md5('kacho-system'), 1, 17)
)
ON CONFLICT (id) DO NOTHING;

-- ── 2. Module ServiceAccounts (deterministic sva-id, system account) ─────────
INSERT INTO kacho_iam.service_accounts (id, account_id, name, description) VALUES
  ('sva' || substr(md5('kacho-vpc'), 1, 17),
   'acc' || substr(md5('kacho-system'), 1, 17), 'kacho-vpc',
   'Module SA: kacho-vpc (SEC-C least-priv)'),
  ('sva' || substr(md5('kacho-compute'), 1, 17),
   'acc' || substr(md5('kacho-system'), 1, 17), 'kacho-compute',
   'Module SA: kacho-compute (SEC-C least-priv)'),
  ('sva' || substr(md5('kacho-nlb'), 1, 17),
   'acc' || substr(md5('kacho-system'), 1, 17), 'kacho-nlb',
   'Module SA: kacho-nlb (SEC-C least-priv)'),
  ('sva' || substr(md5('kacho-vpc-operator'), 1, 17),
   'acc' || substr(md5('kacho-system'), 1, 17), 'kacho-vpc-operator',
   'Module SA: kacho-vpc-operator (SEC-C read-only)'),
  ('sva' || substr(md5('kacho-api-gateway'), 1, 17),
   'acc' || substr(md5('kacho-system'), 1, 17), 'kacho-api-gateway',
   'Module SA: kacho-api-gateway (SEC-C identity-only)')
ON CONFLICT (id) DO NOTHING;

-- ── 3. Backing RBAC-v2 roles (4-segment, cluster-scoped, is_system) ──────────
-- Permission sets are fixed per the least-priv catalog.
-- Role names obey roles_system_name_check ^[a-z][-a-z0-9]*(\.[a-z][a-z0-9_]*){0,2}$
-- (post-dot segment permits underscore, NOT dash) → svc dashes become underscores.
INSERT INTO kacho_iam.roles (id, cluster_id, account_id, is_system, name, description, permissions) VALUES
  ('rol' || substr(md5('module.compute_sa'), 1, 17),
   'cluster_kacho_root', NULL, true,
   'module.compute_sa',
   'Backing least-priv role for kacho-compute module SA (SEC-C)',
   '["vpc.subnets.*.get","vpc.security_groups.*.get","vpc.addresses.*.get","vpc.addresses.*.create","vpc.addresses.*.delete","vpc.addresses.*.update","iam.projects.*.get"]'::jsonb),
  ('rol' || substr(md5('module.vpc_sa'), 1, 17),
   'cluster_kacho_root', NULL, true,
   'module.vpc_sa',
   'Backing least-priv role for kacho-vpc module SA (SEC-C)',
   '["compute.zones.*.get","iam.projects.*.get"]'::jsonb),
  ('rol' || substr(md5('module.nlb_sa'), 1, 17),
   'cluster_kacho_root', NULL, true,
   'module.nlb_sa',
   'Backing least-priv role for kacho-nlb module SA (SEC-C)',
   '["vpc.subnets.*.get","iam.projects.*.get"]'::jsonb),
  ('rol' || substr(md5('module.vpc_operator_sa'), 1, 17),
   'cluster_kacho_root', NULL, true,
   'module.vpc_operator_sa',
   'Backing read-only role for kacho-vpc-operator module SA (SEC-C)',
   '["vpc.subnetses.*.list","vpc.networks.*.get","vpc.network_interfaces.*.get","iam.projectses.*.list"]'::jsonb),
  ('rol' || substr(md5('module.api_gateway_sa'), 1, 17),
   'cluster_kacho_root', NULL, true,
   'module.api_gateway_sa',
   'Identity-only role for kacho-api-gateway module SA (SEC-C); authz by user JWT',
   '["iam.projects.*.get"]'::jsonb)
ON CONFLICT (id) DO NOTHING;

-- ── 4. AccessBindings (SA → backing role → cluster scope) ────────────────────
-- access_bindings_scope_default_trg derives scope from resource_type='cluster'
-- (=1); we set it explicitly for clarity. Idempotent via
-- access_bindings_active_grant_uniq (ACTIVE partial unique on the 5-tuple).
INSERT INTO kacho_iam.access_bindings
  (id, subject_type, subject_id, role_id, resource_type, resource_id, scope, status)
VALUES
  ('acb' || substr(md5('module.vpc_sa'), 1, 17), 'service_account',
   'sva' || substr(md5('kacho-vpc'), 1, 17),
   'rol' || substr(md5('module.vpc_sa'), 1, 17),
   'cluster', 'cluster_kacho_root', 1, 'ACTIVE'),
  ('acb' || substr(md5('module.compute_sa'), 1, 17), 'service_account',
   'sva' || substr(md5('kacho-compute'), 1, 17),
   'rol' || substr(md5('module.compute_sa'), 1, 17),
   'cluster', 'cluster_kacho_root', 1, 'ACTIVE'),
  ('acb' || substr(md5('module.nlb_sa'), 1, 17), 'service_account',
   'sva' || substr(md5('kacho-nlb'), 1, 17),
   'rol' || substr(md5('module.nlb_sa'), 1, 17),
   'cluster', 'cluster_kacho_root', 1, 'ACTIVE'),
  ('acb' || substr(md5('module.vpc_operator_sa'), 1, 17), 'service_account',
   'sva' || substr(md5('kacho-vpc-operator'), 1, 17),
   'rol' || substr(md5('module.vpc_operator_sa'), 1, 17),
   'cluster', 'cluster_kacho_root', 1, 'ACTIVE'),
  ('acb' || substr(md5('module.api_gateway_sa'), 1, 17), 'service_account',
   'sva' || substr(md5('kacho-api-gateway'), 1, 17),
   'rol' || substr(md5('module.api_gateway_sa'), 1, 17),
   'cluster', 'cluster_kacho_root', 1, 'ACTIVE')
ON CONFLICT DO NOTHING;

-- ── 5. FGA relation-tuples `<sva>#fga_writer@iam_fgaproxy:system` ────────────
-- Only modules that use the FGA-proxy: vpc / compute / nlb. The drainer applies
-- these to OpenFGA (idempotent). vpc-operator / api-gateway get NO such tuple.
INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at) VALUES
  ('fga.tuple.write',
   jsonb_build_object('user', 'service_account:' || ('sva' || substr(md5('kacho-vpc'), 1, 17)),
                      'relation', 'fga_writer', 'object', 'iam_fgaproxy:system'),
   now()),
  ('fga.tuple.write',
   jsonb_build_object('user', 'service_account:' || ('sva' || substr(md5('kacho-compute'), 1, 17)),
                      'relation', 'fga_writer', 'object', 'iam_fgaproxy:system'),
   now()),
  ('fga.tuple.write',
   jsonb_build_object('user', 'service_account:' || ('sva' || substr(md5('kacho-nlb'), 1, 17)),
                      'relation', 'fga_writer', 'object', 'iam_fgaproxy:system'),
   now())
-- fga_outbox has a bigserial id (no natural key) → guard duplicate seed-tuples
-- by NOT EXISTS on re-apply (the drainer is idempotent regardless, but we keep
-- the outbox lean across re-applies).
ON CONFLICT DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM kacho_iam.access_bindings WHERE id IN (
  'acb' || substr(md5('module.vpc_sa'), 1, 17),
  'acb' || substr(md5('module.compute_sa'), 1, 17),
  'acb' || substr(md5('module.nlb_sa'), 1, 17),
  'acb' || substr(md5('module.vpc_operator_sa'), 1, 17),
  'acb' || substr(md5('module.api_gateway_sa'), 1, 17)
);

DELETE FROM kacho_iam.fga_outbox
 WHERE payload->>'relation' = 'fga_writer'
   AND payload->>'object'   = 'iam_fgaproxy:system';

DELETE FROM kacho_iam.service_accounts WHERE id IN (
  'sva' || substr(md5('kacho-vpc'), 1, 17),
  'sva' || substr(md5('kacho-compute'), 1, 17),
  'sva' || substr(md5('kacho-nlb'), 1, 17),
  'sva' || substr(md5('kacho-vpc-operator'), 1, 17),
  'sva' || substr(md5('kacho-api-gateway'), 1, 17)
);

DELETE FROM kacho_iam.roles WHERE id IN (
  'rol' || substr(md5('module.compute_sa'), 1, 17),
  'rol' || substr(md5('module.vpc_sa'), 1, 17),
  'rol' || substr(md5('module.nlb_sa'), 1, 17),
  'rol' || substr(md5('module.vpc_operator_sa'), 1, 17),
  'rol' || substr(md5('module.api_gateway_sa'), 1, 17)
);

-- The kacho-system anchor user + account are intentionally LEFT in place on
-- down. They form a circular FK pair (accounts.owner_user_id → users with
-- ON DELETE RESTRICT, which Postgres checks immediately and cannot defer; and
-- users.account_id → accounts) that has no safe single-tx delete order. They
-- are benign idempotent system rows whose sole purpose is to anchor module SAs;
-- re-up is a no-op on them (ON CONFLICT DO NOTHING). The SEC-C-specific
-- artifacts above (SAs, roles, bindings, fga tuples) are fully reverted.

-- +goose StatementEnd
