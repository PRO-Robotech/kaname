// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// seed_module_sa_identity_helper_test.go — TEST-ONLY helper that re-applies the
// SEC-C module ServiceAccount least-priv seed.
//
// The authoritative seed lives in migration 0009 (runs once via goose). This
// helper re-executes the SAME idempotent INSERTs so the B-06 integration test
// can assert re-apply idempotency without hand-copying SQL into the test. Every
// statement is ON CONFLICT DO NOTHING (or NOT EXISTS-guarded for fga_outbox,
// which has no natural key), so a second call inserts nothing.
//
// It lives in a _test.go file (compiled only for tests, never shipped in the
// prod binary): there is no production cold-start re-seed path — migration 0009
// is the single live seed. If HA cold-start re-apply is ever genuinely needed,
// it must be wired into a real boot path (serve / cmd/migrator) under an
// APPROVED acceptance doc, not resurrected as an unreferenced prod export.
package pg

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// seedModuleSAIdentitySQL — idempotent seed body, equivalent (post-0056 is_system is a GENERATED column, so it is omitted here — unlike migration 0009 which predates 0056) to
// migration 0009's INSERTs (single source of truth for the re-apply path).
// fga_outbox rows are NOT EXISTS-guarded (no unique key) so re-apply is a no-op.
const seedModuleSAIdentitySQL = `
INSERT INTO kacho_iam.users (id, external_id, email, display_name, account_id, invite_status)
VALUES (
  'usr' || substr(md5('kacho-system'), 1, 17), '', 'system@kacho.local',
  'Kacho System (module SA owner)', 'acc' || substr(md5('kacho-system'), 1, 17), 'PENDING')
ON CONFLICT (id) DO NOTHING;

INSERT INTO kacho_iam.accounts (id, name, description, owner_user_id)
VALUES (
  'acc' || substr(md5('kacho-system'), 1, 17), 'kacho-system',
  'System account anchoring internal module service-accounts (SEC-C)',
  'usr' || substr(md5('kacho-system'), 1, 17))
ON CONFLICT (id) DO NOTHING;

INSERT INTO kacho_iam.service_accounts (id, account_id, name, description) VALUES
  ('sva' || substr(md5('kacho-vpc'), 1, 17), 'acc' || substr(md5('kacho-system'), 1, 17), 'kacho-vpc', 'Module SA: kacho-vpc (SEC-C least-priv)'),
  ('sva' || substr(md5('kacho-compute'), 1, 17), 'acc' || substr(md5('kacho-system'), 1, 17), 'kacho-compute', 'Module SA: kacho-compute (SEC-C least-priv)'),
  ('sva' || substr(md5('kacho-nlb'), 1, 17), 'acc' || substr(md5('kacho-system'), 1, 17), 'kacho-nlb', 'Module SA: kacho-nlb (SEC-C least-priv)'),
  ('sva' || substr(md5('kacho-vpc-operator'), 1, 17), 'acc' || substr(md5('kacho-system'), 1, 17), 'kacho-vpc-operator', 'Module SA: kacho-vpc-operator (SEC-C read-only)'),
  ('sva' || substr(md5('kacho-api-gateway'), 1, 17), 'acc' || substr(md5('kacho-system'), 1, 17), 'kacho-api-gateway', 'Module SA: kacho-api-gateway (SEC-C identity-only)')
ON CONFLICT (id) DO NOTHING;

INSERT INTO kacho_iam.roles (id, cluster_id, account_id, name, description, permissions) VALUES
  ('rol' || substr(md5('module.compute_sa'), 1, 17), 'cluster_kacho_root', NULL, 'module.compute_sa', 'Backing least-priv role for kacho-compute module SA (SEC-C)', '["vpc.subnets.*.get","vpc.security_groups.*.get","vpc.addresses.*.get","vpc.addresses.*.create","vpc.addresses.*.delete","vpc.addresses.*.update","iam.projects.*.get"]'::jsonb),
  ('rol' || substr(md5('module.vpc_sa'), 1, 17), 'cluster_kacho_root', NULL, 'module.vpc_sa', 'Backing least-priv role for kacho-vpc module SA (SEC-C)', '["compute.zones.*.get","iam.projects.*.get"]'::jsonb),
  ('rol' || substr(md5('module.nlb_sa'), 1, 17), 'cluster_kacho_root', NULL, 'module.nlb_sa', 'Backing least-priv role for kacho-nlb module SA (SEC-C)', '["vpc.subnets.*.get","iam.projects.*.get"]'::jsonb),
  ('rol' || substr(md5('module.vpc_operator_sa'), 1, 17), 'cluster_kacho_root', NULL, 'module.vpc_operator_sa', 'Backing read-only role for kacho-vpc-operator module SA (SEC-C)', '["vpc.subnetses.*.list","vpc.networks.*.get","vpc.network_interfaces.*.get","iam.projectses.*.list"]'::jsonb),
  ('rol' || substr(md5('module.api_gateway_sa'), 1, 17), 'cluster_kacho_root', NULL, 'module.api_gateway_sa', 'Identity-only role for kacho-api-gateway module SA (SEC-C); authz by user JWT', '["iam.projects.*.get"]'::jsonb)
ON CONFLICT (id) DO NOTHING;

INSERT INTO kacho_iam.access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id, scope, status) VALUES
  ('acb' || substr(md5('module.vpc_sa'), 1, 17), 'service_account', 'sva' || substr(md5('kacho-vpc'), 1, 17), 'rol' || substr(md5('module.vpc_sa'), 1, 17), 'cluster', 'cluster_kacho_root', 1, 'ACTIVE'),
  ('acb' || substr(md5('module.compute_sa'), 1, 17), 'service_account', 'sva' || substr(md5('kacho-compute'), 1, 17), 'rol' || substr(md5('module.compute_sa'), 1, 17), 'cluster', 'cluster_kacho_root', 1, 'ACTIVE'),
  ('acb' || substr(md5('module.nlb_sa'), 1, 17), 'service_account', 'sva' || substr(md5('kacho-nlb'), 1, 17), 'rol' || substr(md5('module.nlb_sa'), 1, 17), 'cluster', 'cluster_kacho_root', 1, 'ACTIVE'),
  ('acb' || substr(md5('module.vpc_operator_sa'), 1, 17), 'service_account', 'sva' || substr(md5('kacho-vpc-operator'), 1, 17), 'rol' || substr(md5('module.vpc_operator_sa'), 1, 17), 'cluster', 'cluster_kacho_root', 1, 'ACTIVE'),
  ('acb' || substr(md5('module.api_gateway_sa'), 1, 17), 'service_account', 'sva' || substr(md5('kacho-api-gateway'), 1, 17), 'rol' || substr(md5('module.api_gateway_sa'), 1, 17), 'cluster', 'cluster_kacho_root', 1, 'ACTIVE')
ON CONFLICT DO NOTHING;

INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
SELECT 'fga.tuple.write',
       jsonb_build_object('user', 'service_account:' || t.sva, 'relation', 'fga_writer', 'object', 'iam_fgaproxy:system'),
       now()
  FROM (VALUES
    ('sva' || substr(md5('kacho-vpc'), 1, 17)),
    ('sva' || substr(md5('kacho-compute'), 1, 17)),
    ('sva' || substr(md5('kacho-nlb'), 1, 17))
  ) AS t(sva)
 WHERE NOT EXISTS (
   SELECT 1 FROM kacho_iam.fga_outbox o
    WHERE o.event_type = 'fga.tuple.write'
      AND o.payload->>'user'     = 'service_account:' || t.sva
      AND o.payload->>'relation' = 'fga_writer'
      AND o.payload->>'object'   = 'iam_fgaproxy:system'
 );
`

// SeedModuleSAIdentity re-applies the SEC-C module-SA least-priv seed
// idempotently. Safe to call any number of times — every statement is
// ON CONFLICT DO NOTHING or NOT EXISTS-guarded, so re-application inserts
// nothing. Test-only — used solely by the B-06 idempotency integration test.
func SeedModuleSAIdentity(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, seedModuleSAIdentitySQL); err != nil {
		return fmt.Errorf("seed module sa identity: %w", err)
	}
	return nil
}
