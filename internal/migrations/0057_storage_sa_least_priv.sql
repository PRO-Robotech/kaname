-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0057_storage_sa_least_priv.sql — least-privilege module ServiceAccount for
-- kacho-storage (ReBAC) + backing RBAC-v2 role + cluster-scope AccessBinding +
-- FGA `fga_writer` relation-tuple.
--
-- Mirrors the SEC-C module-SA pattern (migrations 0009 compute / 0044 registry):
-- kacho-storage is a new FGA-proxy consumer (compute/storage split, SEC-D / CS-1
-- GAP-D) — it emits owner/project/parent-tuple RegisterResource intents for
-- storage_volume / storage_snapshot (and other storage_* objects), gated by a ReBAC
-- Check `service_account:<sva>#fga_writer@iam_fgaproxy:system`. Without the fga_writer
-- tuple every owner-tuple write is rejected PermissionDenied, so the gateway
-- scope_extractors {storage_volume,volume_id}/{storage_snapshot,snapshot_id} cannot
-- resolve target->project (anti-BOLA) and creators cannot see their own volumes in
-- authz-filtered List.
--
-- Identity binding: kacho-storage dials iam with client-cert URI-SAN
-- spiffe://kacho.cloud/ns/<ns>/sa/kacho-storage → IAM fgaproxy SANToServiceDomain
-- extracts svc="storage" → objectDomainForCaller="storage" (ValidateProxyTuple only
-- admits storage_* objects) and SANToServiceAccountID derives the deterministic
-- sva-id below. The storage deploy chart's client leaf saName MUST be `kacho-storage`
-- (services/storage/deploy/values.yaml mtls.spiffe.saName).
--
-- Deterministic ids: sva-id = 'sva' || substr(md5('kacho-storage'), 1, 17);
-- role-id = 'rol' || substr(md5('module.storage_sa'), 1, 17). The SA is anchored to
-- the kacho-system account/user already seeded by migration 0009 (idempotent, so the
-- anchor is re-asserted here defensively via ON CONFLICT DO NOTHING).
--
-- Least-priv catalog: kacho-storage validates projectId cross-domain on Create via
-- iam.ProjectService.Get → the sole standing permission is `iam.projects.*.get`. FGA
-- owner-tuple writes are authorized by the fga_writer ReBAC tuple, not by a role
-- permission (privilege-guard: RegisterResource may only write hierarchy relations).

-- +goose Up
-- +goose StatementBegin

-- ── 0. System anchor user + account (idempotent re-assert; seeded by 0009) ────
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

INSERT INTO kacho_iam.accounts (id, name, description, owner_user_id)
VALUES (
  'acc' || substr(md5('kacho-system'), 1, 17),
  'kacho-system',
  'System account anchoring internal module service-accounts (SEC-C)',
  'usr' || substr(md5('kacho-system'), 1, 17)
)
ON CONFLICT (id) DO NOTHING;

-- ── 1. Module ServiceAccount (deterministic sva-id, system account) ──────────
INSERT INTO kacho_iam.service_accounts (id, account_id, name, description) VALUES
  ('sva' || substr(md5('kacho-storage'), 1, 17),
   'acc' || substr(md5('kacho-system'), 1, 17), 'kacho-storage',
   'Module SA: kacho-storage (SEC-C least-priv)')
ON CONFLICT (id) DO NOTHING;

-- ── 2. Backing RBAC-v2 role (4-segment, cluster-scoped, is_system) ───────────
-- Role name obeys roles_system_name_check (post-dot segment permits underscore) →
-- 'module.storage_sa'. Permission set: only iam.projects.*.get (project existence
-- check on Volume/Snapshot.Create); FGA owner-tuple writes are fga_writer-gated, not
-- role-permission-gated.
-- is_system опущен: с 0056 это GENERATED ALWAYS колонка (derived из cluster_id
-- IS NOT NULL). cluster_id='cluster_kacho_root' → is_system деривит в true.
-- Вставка значения в generated-колонку = ERROR 428C9 (0057 идёт ПОСЛЕ 0056,
-- в отличие от 0044/0045 registry-seed, применявшихся до 0056).
-- rules (RBAC-v2 4-сегментная грамматика) ОБЯЗАТЕЛЬНЫ для system-роли (F53
-- tier-parity/SystemRolesReseededWithRules): зеркалит 0045_registry_sa_rules.
-- permissions оставлен для legacy-совместимости; rules — авторитетный источник.
INSERT INTO kacho_iam.roles (id, cluster_id, account_id, name, description, permissions, rules) VALUES
  ('rol' || substr(md5('module.storage_sa'), 1, 17),
   'cluster_kacho_root', NULL,
   'module.storage_sa',
   'Backing least-priv role for kacho-storage module SA (SEC-C)',
   '["iam.projects.*.get"]'::jsonb,
   '[{"module":"iam","resources":["projects"],"verbs":["get"]}]'::jsonb)
ON CONFLICT (id) DO NOTHING;

-- ── 3. AccessBinding (SA → backing role → cluster scope) ─────────────────────
INSERT INTO kacho_iam.access_bindings
  (id, subject_type, subject_id, role_id, resource_type, resource_id, scope, status)
VALUES
  ('acb' || substr(md5('module.storage_sa'), 1, 17), 'service_account',
   'sva' || substr(md5('kacho-storage'), 1, 17),
   'rol' || substr(md5('module.storage_sa'), 1, 17),
   'cluster', 'cluster_kacho_root', 1, 'ACTIVE')
ON CONFLICT DO NOTHING;

-- ── 4. FGA relation-tuple `<sva>#fga_writer@iam_fgaproxy:system` ─────────────
-- Enqueued via fga_outbox; the drainer applies it to OpenFGA (idempotent). Without
-- it every storage owner/project/parent-tuple RegisterResource is denied.
INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at) VALUES
  ('fga.tuple.write',
   jsonb_build_object('user', 'service_account:' || ('sva' || substr(md5('kacho-storage'), 1, 17)),
                      'relation', 'fga_writer', 'object', 'iam_fgaproxy:system'),
   now())
ON CONFLICT DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM kacho_iam.access_bindings
 WHERE id = 'acb' || substr(md5('module.storage_sa'), 1, 17);

DELETE FROM kacho_iam.fga_outbox
 WHERE payload->>'relation' = 'fga_writer'
   AND payload->>'object'   = 'iam_fgaproxy:system'
   AND payload->>'user'     = 'service_account:' || ('sva' || substr(md5('kacho-storage'), 1, 17));

DELETE FROM kacho_iam.service_accounts
 WHERE id = 'sva' || substr(md5('kacho-storage'), 1, 17);

DELETE FROM kacho_iam.roles
 WHERE id = 'rol' || substr(md5('module.storage_sa'), 1, 17);

-- The kacho-system anchor user + account are intentionally LEFT in place (shared
-- with migration 0009; benign idempotent system rows).

-- +goose StatementEnd
