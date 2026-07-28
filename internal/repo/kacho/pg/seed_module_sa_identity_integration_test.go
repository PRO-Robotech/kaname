// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// seed_module_sa_identity_integration_test.go — module ServiceAccount identity seed.
//
// Verifies the seed migration (0009) that provisions least-privilege
// module ServiceAccount identities in the ReBAC model:
//   - 5 module SAs (deterministic sva-id, system account, cluster scope);
//   - per-module backing RBAC-v2 role with exact 4-segment permission set
//     (byte-for-byte from permission_catalog.json);
//   - per-module AccessBinding (subject=service_account, role, cluster-scope);
//   - FGA relation-tuples `<sva>#fga_writer@iam_fgaproxy:system` in fga_outbox
//     for vpc/compute/nlb only (vpc-operator / api-gateway have none);
//   - immutable system role; idempotent ON CONFLICT re-apply.
//
// Source-of-truth permission strings (permission_catalog.json):
//
//	compute     vpc.subnets.*.get, vpc.security_groups.*.get,
//	            vpc.addresses.*.get/create/delete/update, iam.projects.*.get
//	vpc         compute.zones.*.get, iam.projects.*.get
//	nlb         vpc.subnets.*.get, iam.projects.*.get
//	vpc-operator vpc.subnetses.*.list, vpc.networks.*.get,
//	            vpc.network_interfaces.*.get, iam.projectses.*.list
//	api-gateway (none — identity-only)
//
// Skipped under `go test -short`.
package pg_test

import (
	"context"
	"crypto/md5" //nolint:gosec // deterministic seed-id derivation, not security
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// svaID derives the deterministic ServiceAccount id for a module svc-name
// (`'sva' || substr(md5('kacho-<svc>'), 1, 17)`), matching the seed migration.
func svaID(svc string) string {
	sum := md5.Sum([]byte("kacho-" + svc)) //nolint:gosec // deterministic id, not crypto
	return "sva" + hex.EncodeToString(sum[:])[:17]
}

// roleName maps a module svc-name to its backing-role name. Role names obey the
// system-role CHECK `^[a-z][-a-z0-9]*(\.[a-z][a-z0-9_]*){0,2}$` (post-dot
// segment allows underscore, NOT dash), so dashes in svc become underscores.
func roleName(svc string) string {
	switch svc {
	case "vpc":
		return "module.vpc_sa"
	case "compute":
		return "module.compute_sa"
	case "nlb":
		return "module.nlb_sa"
	case "vpc-operator":
		return "module.vpc_operator_sa"
	case "api-gateway":
		return "module.api_gateway_sa"
	default:
		return "module." + svc
	}
}

// rolID derives the deterministic backing-role id for a module
// (`'rol' || substr(md5(<role-name>), 1, 17)`), matching the seed migration.
func rolID(svc string) string {
	sum := md5.Sum([]byte(roleName(svc))) //nolint:gosec // deterministic id, not crypto
	return "rol" + hex.EncodeToString(sum[:])[:17]
}

func TestSeedModuleSA_B01_AllFiveModuleSAsCreated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	wantSvcs := []string{"vpc", "compute", "nlb", "vpc-operator", "api-gateway"}
	for _, svc := range wantSvcs {
		var id, name, accountID string
		err := pool.QueryRow(ctx,
			`SELECT id, name, account_id FROM kacho_iam.service_accounts WHERE id = $1`,
			svaID(svc)).Scan(&id, &name, &accountID)
		require.NoError(t, err, "module SA %q must exist with deterministic id %s", svc, svaID(svc))
		require.Equal(t, "kacho-"+svc, name, "SA name segment is canonical kacho-<svc>")
		require.NotEmpty(t, accountID, "SA must be attached to the seeded system account (account_id NOT NULL)")
	}
}

func TestSeedModuleSA_B02_ComputeExactPermissionSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	got := readRolePermissions(t, ctx, pool, rolID("compute"))
	want := []string{
		"iam.projects.*.get",
		"vpc.addresses.*.create",
		"vpc.addresses.*.delete",
		"vpc.addresses.*.get",
		"vpc.addresses.*.update",
		"vpc.security_groups.*.get",
		"vpc.subnets.*.get",
	}
	require.Equal(t, want, got, "compute SA backing-role permission set must match the source catalog byte-for-byte")

	// Over-grant negative: no vpc-network mutations.
	for _, forbidden := range []string{"vpc.networks.*.delete", "vpc.networks.*.create", "vpc.networks.*.update"} {
		require.NotContains(t, got, forbidden, "least-priv: compute SA must NOT carry %q", forbidden)
	}
	// 3-segment form must be absent (4-segment grammar only).
	require.NotContains(t, got, "vpc.subnets.get", "3-segment form must not appear (4-segment grammar)")

	// FGA relation-tuple fga_writer present.
	requireFGAWriterTuple(t, ctx, pool, svaID("compute"), true)
}

func TestSeedModuleSA_B03_VpcExactPermissionSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	got := readRolePermissions(t, ctx, pool, rolID("vpc"))
	want := []string{"compute.zones.*.get", "iam.projects.*.get"}
	require.Equal(t, want, got, "vpc SA backing-role permission set must match the source catalog")

	for _, forbidden := range []string{"compute.instances.*.create", "compute.instances.*.delete", "iam.accounts.*.get"} {
		require.NotContains(t, got, forbidden, "least-priv: vpc SA must NOT carry %q", forbidden)
	}
	requireFGAWriterTuple(t, ctx, pool, svaID("vpc"), true)
}

func TestSeedModuleSA_B04_NlbExactPermissionSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	got := readRolePermissions(t, ctx, pool, rolID("nlb"))
	want := []string{"iam.projects.*.get", "vpc.subnets.*.get"}
	require.Equal(t, want, got, "nlb SA backing-role permission set must match the source catalog")
	requireFGAWriterTuple(t, ctx, pool, svaID("nlb"), true)

	// SA name segment canonical kacho-nlb (not legacy kacho-loadbalancer).
	var name string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT name FROM kacho_iam.service_accounts WHERE id = $1`, svaID("nlb")).Scan(&name))
	require.Equal(t, "kacho-nlb", name)
}

func TestSeedModuleSA_B05_OperatorReadOnlyNoFGAWriter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	got := readRolePermissions(t, ctx, pool, rolID("vpc-operator"))
	want := []string{
		"iam.projectses.*.list",
		"vpc.network_interfaces.*.get",
		"vpc.networks.*.get",
		"vpc.subnetses.*.list",
	}
	require.Equal(t, want, got, "vpc-operator SA backing-role permission set must match the source catalog")

	// Read-only: no mutating verbs.
	for _, p := range got {
		require.NotContains(t, p, ".create", "operator SA must be read-only")
		require.NotContains(t, p, ".update", "operator SA must be read-only")
		require.NotContains(t, p, ".delete", "operator SA must be read-only")
	}
	// No fga_writer tuple for operator (read-only sync, registers nothing).
	requireFGAWriterTuple(t, ctx, pool, svaID("vpc-operator"), false)
	// api-gateway also has no fga_writer tuple.
	requireFGAWriterTuple(t, ctx, pool, svaID("api-gateway"), false)
}

func TestSeedModuleSA_B06_AccessBindingScopeAndIdempotency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	for _, svc := range []string{"vpc", "compute", "nlb", "vpc-operator", "api-gateway"} {
		var count int
		var resourceType, resourceID string
		var scope int16
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.access_bindings
			  WHERE subject_type='service_account' AND subject_id=$1 AND role_id=$2`,
			svaID(svc), rolID(svc)).Scan(&count))
		require.Equal(t, 1, count, "exactly one AccessBinding per module SA %q", svc)

		require.NoError(t, pool.QueryRow(ctx,
			`SELECT resource_type, resource_id, scope FROM kacho_iam.access_bindings
			  WHERE subject_type='service_account' AND subject_id=$1 AND role_id=$2`,
			svaID(svc), rolID(svc)).Scan(&resourceType, &resourceID, &scope))
		require.Equal(t, "cluster", resourceType)
		require.Equal(t, "cluster_kacho_root", resourceID)
		require.Equal(t, int16(1), scope, "cluster scope = 1")
	}

	// Re-apply seed body (idempotent ON CONFLICT DO NOTHING) — count unchanged.
	reapplySeed(t, ctx, pool)
	for _, svc := range []string{"vpc", "compute", "nlb", "vpc-operator", "api-gateway"} {
		var count int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.access_bindings
			  WHERE subject_type='service_account' AND subject_id=$1`, svaID(svc)).Scan(&count))
		require.Equal(t, 1, count, "re-apply must not duplicate AccessBinding for %q", svc)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func readRolePermissions(t *testing.T, ctx context.Context, pool *pgxpool.Pool, roleID string) []string {
	t.Helper()
	var raw string
	err := pool.QueryRow(ctx,
		`SELECT permissions::text FROM kacho_iam.roles WHERE id = $1`, roleID).Scan(&raw)
	require.NoError(t, err, "backing role %s must exist", roleID)
	var perms []string
	require.NoError(t, json.Unmarshal([]byte(raw), &perms))
	sort.Strings(perms)
	return perms
}

func requireFGAWriterTuple(t *testing.T, ctx context.Context, pool *pgxpool.Pool, sva string, want bool) {
	t.Helper()
	var count int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE event_type='fga.tuple.write'
		    AND payload->>'user'     = $1
		    AND payload->>'relation' = 'fga_writer'
		    AND payload->>'object'   = 'iam_fgaproxy:system'`,
		"service_account:"+sva).Scan(&count))
	if want {
		require.GreaterOrEqual(t, count, 1, "fga_writer tuple must be seeded for %s", sva)
	} else {
		require.Equal(t, 0, count, "no fga_writer tuple must be seeded for %s", sva)
	}
}

// reapplySeed re-executes the seed body (idempotency assertion). It calls
// the exported SeedModuleSAIdentity helper so the test never hand-copies SQL.
func reapplySeed(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	require.NoError(t, pg.SeedModuleSAIdentity(ctx, pool))
}
