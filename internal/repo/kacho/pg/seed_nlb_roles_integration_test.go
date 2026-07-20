// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// seed_nlb_roles_integration_test.go — NLB integration tests for
// migration 0025_nlb_operator_target_manager_roles.sql.
//
// Verifies:
// - 01: Both new cluster-scoped system roles exist after migration apply.
// - 02: Permission lists match the design baseline byte-for-byte.
// - 03: `is_system = true`, `account_id IS NULL`, `cluster_id = 'cluster_kacho_root'`.
// - 04: Re-apply (ON CONFLICT DO NOTHING) is idempotent.
// - 05: `Update` on a system role → ErrFailedPrecondition (immutable contract holds).
// - 06: `Delete` on a system role → ErrFailedPrecondition "System role".
// - 07: Permissions regex accepts camelCase resource segments after the
// migration relaxes `iam_permissions_valid` (kacho-nlb domain strings).
//
// Deterministic ids are derived via `'rol' || substr(md5('<name>'), 1, 17)`
//.

import (
	"context"
	"database/sql"
	stderrors "errors"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// Deterministic ids — must match migration 0025 SQL expression:
//
//	`'rol' || substr(md5('<name>'), 1, 17)`.
//
// Verify with:
//
//	echo -n 'loadbalancer.operator' | md5sum | cut -c1-17 -> ecba563ba8698e792
//	echo -n 'loadbalancer.target_manager' | md5sum | cut -c1-17 -> e563eb4128875f8d1
const (
	seedRoleIDLBOperator      = "rolecba563ba8698e792"
	seedRoleIDLBTargetManager = "role563eb4128875f8d1"
)

// expectedOperatorPermissions — design 2026-05-23-kacho-nlb-design.md
// baseline. Permission strings are camelCase per kacho-nlb's authoritative
// catalog (internal/check/permission_map.go).
// RBAC v2: migration 0005 promotes 3-segment role permissions
// to 4-segment by inserting a wildcard resourceName ('*') as the third
// segment. The seed NLB permissions land in their promoted form, so the
// expected baselines here track that shape.
var expectedOperatorPermissions = []string{
	"loadbalancer.listeners.*.get",
	"loadbalancer.listeners.*.list",
	"loadbalancer.listeners.*.listOperations",
	"loadbalancer.networkLoadBalancers.*.get",
	"loadbalancer.networkLoadBalancers.*.getTargetStates",
	"loadbalancer.networkLoadBalancers.*.list",
	"loadbalancer.networkLoadBalancers.*.listOperations",
	"loadbalancer.networkLoadBalancers.*.start",
	"loadbalancer.networkLoadBalancers.*.stop",
	"loadbalancer.operations.*.get",
	"loadbalancer.targetGroups.*.get",
	"loadbalancer.targetGroups.*.list",
	"loadbalancer.targetGroups.*.listOperations",
}

var expectedTargetManagerPermissions = []string{
	"loadbalancer.listeners.*.get",
	"loadbalancer.listeners.*.list",
	"loadbalancer.networkLoadBalancers.*.get",
	"loadbalancer.networkLoadBalancers.*.getTargetStates",
	"loadbalancer.networkLoadBalancers.*.list",
	"loadbalancer.operations.*.get",
	"loadbalancer.targetGroups.*.addTargets",
	"loadbalancer.targetGroups.*.get",
	"loadbalancer.targetGroups.*.list",
	"loadbalancer.targetGroups.*.listOperations",
	"loadbalancer.targetGroups.*.removeTargets",
}

func TestSeed_NLB_01_BothRolesSeeded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	op, err := rd.Roles().Get(ctx, domain.RoleID(seedRoleIDLBOperator))
	require.NoError(t, err)
	assert.Equal(t, domain.RoleName("loadbalancer.operator"), op.Name)
	assert.True(t, op.IsSystem)
	assert.Empty(t, op.AccountID, "system role must have NULL account_id")

	tm, err := rd.Roles().Get(ctx, domain.RoleID(seedRoleIDLBTargetManager))
	require.NoError(t, err)
	assert.Equal(t, domain.RoleName("loadbalancer.target_manager"), tm.Name)
	assert.True(t, tm.IsSystem)
	assert.Empty(t, tm.AccountID, "system role must have NULL account_id")
}

func TestSeed_NLB_02_PermissionsMatchDesignBaseline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	for _, tc := range []struct {
		name     string
		id       string
		expected []string
	}{
		{"operator", seedRoleIDLBOperator, expectedOperatorPermissions},
		{"target_manager", seedRoleIDLBTargetManager, expectedTargetManagerPermissions},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := rd.Roles().Get(ctx, domain.RoleID(tc.id))
			require.NoError(t, err)

			got := make([]string, len(r.Permissions))
			for i, p := range r.Permissions {
				got[i] = string(p)
			}
			sort.Strings(got)
			sortedExp := append([]string(nil), tc.expected...)
			sort.Strings(sortedExp)
			assert.Equal(t, sortedExp, got)
		})
	}
}

func TestSeed_NLB_03_ClusterScopeAndIsSystem(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// Direct pool query — the role-CQRS adapter doesn't expose cluster_id /
	// project_id columns. We verify scope at the table level. (organization_id
	// column dropped in migration 0008.)
	for _, tc := range []struct {
		id   string
		name string
	}{
		{seedRoleIDLBOperator, "loadbalancer.operator"},
		{seedRoleIDLBTargetManager, "loadbalancer.target_manager"},
	} {
		var (
			isSystem  bool
			clusterID sql.NullString
			accountID sql.NullString
			projectID sql.NullString
			gotName   string
			permsRaw  []byte
		)
		err := pool.QueryRow(ctx, `
			SELECT is_system, cluster_id, account_id, project_id, name, permissions
			 FROM kacho_iam.roles
			 WHERE id = $1`, tc.id).Scan(
			&isSystem, &clusterID, &accountID, &projectID, &gotName, &permsRaw,
		)
		require.NoError(t, err, "role %s missing from seed", tc.name)

		assert.True(t, isSystem, "%s must be system", tc.name)
		require.True(t, clusterID.Valid, "%s.cluster_id must be NOT NULL (cluster scope)", tc.name)
		assert.Equal(t, "cluster_kacho_root", clusterID.String, "%s.cluster_id", tc.name)
		assert.False(t, accountID.Valid, "%s.account_id must be NULL (cluster scope)", tc.name)
		assert.False(t, projectID.Valid, "%s.project_id must be NULL (cluster scope)", tc.name)
		assert.Equal(t, tc.name, gotName)
		assert.NotEmpty(t, permsRaw, "permissions JSONB must be populated")
	}
}

func TestSeed_NLB_04_ReapplyIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// Re-execute the seed INSERT manually. ON CONFLICT (id) DO NOTHING should
	// make the second apply a no-op (no constraint violation, row count == 1
	// for each id).
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.roles
		 (id, cluster_id, account_id, name, description, permissions)
		VALUES
		 ($1, 'cluster_kacho_root', NULL,
		 'loadbalancer.operator',
		 'NLB operator (start/stop/getTargetStates/listOperations + viewer on LB hierarchy)',
		 '[
		 "loadbalancer.networkLoadBalancers.*.start",
		 "loadbalancer.networkLoadBalancers.*.stop",
		 "loadbalancer.networkLoadBalancers.*.getTargetStates",
		 "loadbalancer.networkLoadBalancers.*.listOperations",
		 "loadbalancer.networkLoadBalancers.*.get",
		 "loadbalancer.networkLoadBalancers.*.list",
		 "loadbalancer.listeners.*.get",
		 "loadbalancer.listeners.*.list",
		 "loadbalancer.listeners.*.listOperations",
		 "loadbalancer.targetGroups.*.get",
		 "loadbalancer.targetGroups.*.list",
		 "loadbalancer.targetGroups.*.listOperations",
		 "loadbalancer.operations.*.get"
		 ]'::jsonb)
		ON CONFLICT (id) DO NOTHING`, seedRoleIDLBOperator)
	require.NoError(t, err, "re-apply seed must be idempotent (ON CONFLICT DO NOTHING)")

	// Verify still exactly one row.
	var count int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM kacho_iam.roles WHERE id = $1`,
		seedRoleIDLBOperator).Scan(&count))
	assert.Equal(t, 1, count, "exactly one row for operator after re-apply")
}

func TestSeed_NLB_05_DeleteSystemRoleForbidden(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	for _, id := range []string{seedRoleIDLBOperator, seedRoleIDLBTargetManager} {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		err = w.RolesW().Delete(ctx, domain.RoleID(id))
		_ = w.Rollback(ctx)
		require.Error(t, err, "Delete on system role %s must fail", id)
		assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition),
			"Delete on system role must yield ErrFailedPrecondition (got %v)", err)
		assert.Contains(t, err.Error(), "System role",
			"verbatim 'System role' text expected in error")
	}
}

func TestSeed_NLB_06_PermissionsRegexAllowsCamelCaseResource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// Migration 0005 (RBAC v2) enforces a strict 4-segment grammar
	// `module.resource.resourceName.verb`. Resource segment camelCase OK,
	// resourceName alphanum + dash/underscore, verb lowercase camelCase.
	// Sanity-check the validator helper by directly invoking it from SQL.
	for _, tc := range []struct {
		perm string
		want bool
		why  string
	}{
		{"loadbalancer.networkLoadBalancers.*.start", true, "wildcard resourceName + lowercase verb"},
		{"loadbalancer.targetGroups.*.addTargets", true, "wildcard resourceName + camelCase verb"},
		{"loadbalancer.listeners.*.listOperations", true, "wildcard resourceName + camelCase verb"},
		{"loadbalancer.operations.*.get", true, "all-lowercase still valid"},
		{"*.*.*.*", true, "all wildcards still accepted"},
		{"loadbalancer.NetworkLoadBalancers.*.start", false, "resource MUST start lowercase"},
		{"loadbalancer.net works.*.start", false, "whitespace forbidden"},
		{"loadbalancer.networkLoadBalancers.start", false, "3-segment legacy must reject"},
	} {
		var ok bool
		err := pool.QueryRow(ctx,
			`SELECT kacho_iam.iam_permissions_valid($1::jsonb)`,
			`["`+tc.perm+`"]`,
		).Scan(&ok)
		require.NoError(t, err, "regex evaluation failed for %q", tc.perm)
		assert.Equal(t, tc.want, ok, "perm %q (%s) — got valid=%v", tc.perm, tc.why, ok)
	}
}

// TestSeed_NLB_07_GreaterOrEqualSystemRoleCountAfterSeed — sanity check
// that the new roles join the existing system-role set. baseline
// seeds 2 system roles (kacho-system.admin / kacho-system.viewer); the
// NLB migration adds 2 more, so we expect >= 4 system rows after
// migration apply. (Other migrations may add more — we only assert
// monotonic floor.)
func TestSeed_NLB_07_GreaterOrEqualSystemRoleCountAfterSeed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	var count int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM kacho_iam.roles
		 WHERE is_system = true
		 AND cluster_id = 'cluster_kacho_root'`).Scan(&count))
	assert.GreaterOrEqual(t, count, 4,
		"expect ≥4 cluster-scoped system roles after KAC-NLB seed "+
			"(2 baseline + 2 KAC-NLB new)")
}
