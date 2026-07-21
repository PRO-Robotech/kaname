-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0058_bootstrap_service_account.sql — seed the SINGLETON bootstrap-admin
-- ServiceAccount (#58), the principal that InternalBootstrapTokenService mints
-- tokens for (non-interactive production-mode seed entry point).
--
-- DB-invariant "exactly one bootstrap-SA" (data-integrity.md ban #10 — DB-level,
-- not software check-then-act): the row carries a DETERMINISTIC id
-- (`sva||substr(md5('kacho-bootstrap-admin'),1,17)`, the same module-SA seed
-- convention as 0009/0044/0057), so `ON CONFLICT (id) DO NOTHING` makes the seed
-- idempotent AND a second bootstrap-SA is impossible by construction (same id →
-- PK collision → no-op). The runtime Hydra OAuth-client + its 1:1
-- `service_account_oauth_clients` mapping (UNIQUE(sva_id)) are provisioned by the
-- mint use-case (they need the env-provided signing key + Hydra Admin, so they
-- cannot live in a migration) — the UNIQUE(sva_id) mapping index is the singleton
-- backstop for the runtime provisioning CAS (IBT-03).
--
-- The bootstrap SA holds cluster `system_admin` (subject_type='service_account',
-- which the cluster_admin_grants CHECK already permits) so its minted token can
-- drive the acr-gated seed RPCs (UserTokenService.Issue / SAKeyService.Issue) —
-- service principals are acr-EXEMPT by design (security.md §4.1.2). The grant's
-- FGA owner-tuple (cluster:cluster_kacho_root#system_admin@service_account:<sva>)
-- is emitted into fga_outbox for the drainer to materialise in OpenFGA.
--
-- Anchored to the already-seeded system account (`acc||substr(md5('kacho-system'),
-- 1,17)`, seeded 0009/0044/0057), project_id NULL (cluster-scoped, no project).

-- +goose Up
-- +goose StatementBegin

INSERT INTO kacho_iam.service_accounts (id, account_id, name, description, labels)
VALUES (
  'sva' || substr(md5('kacho-bootstrap-admin'), 1, 17),
  'acc' || substr(md5('kacho-system'), 1, 17),
  'kacho-bootstrap-admin',
  'Bootstrap admin ServiceAccount for non-interactive production-mode token mint (#58)',
  '{}'::jsonb
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO kacho_iam.cluster_admin_grants (id, cluster_id, subject_type, subject_id, granted_by)
VALUES (
  'cag_' || substr(md5('kacho-bootstrap-grant'), 1, 17),
  'cluster_kacho_root',
  'service_account',
  'sva' || substr(md5('kacho-bootstrap-admin'), 1, 17),
  'bootstrap'
)
ON CONFLICT ON CONSTRAINT cluster_admin_grants_cluster_subject_uniq DO NOTHING;

-- FGA owner-tuple intent (idempotent at the drainer; guarded against a duplicate
-- outbox row on re-seed since fga_outbox has no natural unique key).
INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
SELECT
  'fga.tuple.write',
  jsonb_build_object(
    'user',     'service_account:' || ('sva' || substr(md5('kacho-bootstrap-admin'), 1, 17)),
    'relation', 'system_admin',
    'object',   'cluster:cluster_kacho_root'
  ),
  now()
WHERE NOT EXISTS (
  SELECT 1 FROM kacho_iam.fga_outbox
   WHERE event_type = 'fga.tuple.write'
     AND payload->>'user'     = 'service_account:' || ('sva' || substr(md5('kacho-bootstrap-admin'), 1, 17))
     AND payload->>'relation' = 'system_admin'
     AND payload->>'object'   = 'cluster:cluster_kacho_root'
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM kacho_iam.cluster_admin_grants
 WHERE id = 'cag_' || substr(md5('kacho-bootstrap-grant'), 1, 17);

DELETE FROM kacho_iam.service_account_oauth_clients
 WHERE sva_id = 'sva' || substr(md5('kacho-bootstrap-admin'), 1, 17);

DELETE FROM kacho_iam.service_accounts
 WHERE id = 'sva' || substr(md5('kacho-bootstrap-admin'), 1, 17);

-- +goose StatementEnd
