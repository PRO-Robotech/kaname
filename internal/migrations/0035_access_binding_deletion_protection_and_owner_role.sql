-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- RBAC explicit-model 2026. Two additive, forward-only,
-- idempotent changes:
--
--   1. access_bindings.deletion_protection — persists the proto field
--      AccessBinding.deletion_protection. DB-level guard: the binding Delete
--      path uses an atomic CAS `DELETE … WHERE deletion_protection=false` backstop
--      (data-integrity.md — no software TOCTOU). Default false → existing rows are
--      unprotected (no behaviour change for prior bindings).
--
--   2. owner system-role (net-new). Cluster-scoped, is_system=true, account_id NULL,
--      rules `[{module:*, resources:[*], verbs:[*]}]` (scalar-module form post-0033)
--      — the `*.*.*` "selector all" shape. Deterministic id
--      `rol||substr(md5('owner'),1,17)` like the other catalog roles, so re-apply is
--      a no-op (ON CONFLICT (id) DO NOTHING). Account.Create auto-creates an
--      AccessBinding(subject=creator, role=owner, scope=ACCOUNT:<A>,
--      deletion_protection=true); per-object access is materialized forward by the
--      reconciler (the wildcard rule yields scope-self verbs on account:<A> + an
--      ARM_ANCHOR materializing selector for the account's content).
--
-- Both are additive: no column drop, no row delete, no edit to an applied migration
-- (ban #5). The next migration is 0036.

-- 1) deletion_protection column.
ALTER TABLE kacho_iam.access_bindings
  ADD COLUMN IF NOT EXISTS deletion_protection boolean NOT NULL DEFAULT false;

-- 2) owner system-role seed (permissions[] backs FGA emission, rules[] is the
--    public source of truth — both populated, mirroring the catalog seed pattern).
INSERT INTO kacho_iam.roles (id, cluster_id, account_id, name, description, permissions, rules, is_system)
VALUES (
  'rol' || substr(md5('owner'), 1, 17),
  'cluster_kacho_root',
  NULL,
  'owner',
  'Account owner (all modules, all resources, all verbs within the account)',
  -- 4-segment RBAC v2 grammar module.resource.resourceName.verb (mig 0005);
  -- the 3-segment '*.*.*' would violate roles_permissions_valid.
  '["*.*.*.*"]'::jsonb,
  '[{"module":"*","resources":["*"],"verbs":["*"]}]'::jsonb,
  true
)
ON CONFLICT (id) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM kacho_iam.roles WHERE id = 'rol' || substr(md5('owner'), 1, 17);
ALTER TABLE kacho_iam.access_bindings DROP COLUMN IF EXISTS deletion_protection;

-- +goose StatementEnd
