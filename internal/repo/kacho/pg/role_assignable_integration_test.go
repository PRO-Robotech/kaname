// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// role_assignable_integration_test.go — integration tests (testcontainers PG16)
// for the assignable-roles read side:
//
//   - roleCols regression: Get/List now also project cluster_id + project_id
//     so the domain.Role carries the scope fields the predicate needs
//     (was: only account_id) — existing reads still work.
//   - Reader.ListAssignable filters roles by the scope-matrix predicate
//     (system everywhere; account-role only own account; project-role only own
//     project; cluster ⇒ system only) with keyset (created_at,id) ASC pagination.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	reporole "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
)

// seedProjectRole — INSERT a project-scoped custom role directly (no public
// Create path mints project-scoped roles yet). The role is
// is_system=false, cluster_id NULL, account_id NULL, project_id set.
func seedProjectRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, prj domain.ProjectID, name string) domain.RoleID {
	t.Helper()
	rid := domain.RoleID(ids.NewID(domain.PrefixRole))
	_, err := pool.Exec(ctx, `
		INSERT INTO roles (id, project_id, name, description, permissions)
		VALUES ($1, $2, $3, $4, '["iam.users.*.read"]'::jsonb)`,
		string(rid), string(prj), name, "project role "+name)
	require.NoError(t, err, "seed project-scoped role")
	return rid
}

// roleIDs collects ids from a role slice for set assertions.
func roleIDs(rs []domain.Role) map[domain.RoleID]domain.Role {
	m := map[domain.RoleID]domain.Role{}
	for _, r := range rs {
		m[r.ID] = r
	}
	return m
}

// TestRole_RoleColsRegression_ScopeFieldsPopulated — Get/List must now populate
// ClusterID (system) and ProjectID (project-scoped), in addition to AccountID.
// Pre-1.5 roleCols omitted cluster_id/project_id → both stayed empty.
func TestRole_RoleColsRegression_ScopeFieldsPopulated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "rcr")
	acc := seedAccount(t, ctx, repo, "acc-rcr", owner)
	proj := seedProject(t, ctx, repo, acc.ID, "proj-rcr")

	accRole := seedCustomRole(t, ctx, repo, acc.ID, "rcr_acc")
	prjRoleID := seedProjectRole(t, ctx, pool, proj.ID, "rcr_prj")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// account-scoped role still reads its account_id (regression) + project_id empty.
	gotAcc, err := rd.Roles().Get(ctx, accRole.ID)
	require.NoError(t, err)
	assert.Equal(t, acc.ID, gotAcc.AccountID, "account_id still populated (regression)")
	assert.Empty(t, gotAcc.ProjectID)
	assert.Empty(t, gotAcc.ClusterID)

	// project-scoped role: project_id now populated (the NEW projection).
	gotPrj, err := rd.Roles().Get(ctx, prjRoleID)
	require.NoError(t, err)
	assert.Equal(t, proj.ID, gotPrj.ProjectID, "project_id populated by expanded roleCols")
	assert.Empty(t, gotPrj.AccountID)

	// a system role (seed migration) carries cluster_id.
	gotSys, err := rd.Roles().Get(ctx, domain.RoleID("rol000000000sysviewer"))
	require.NoError(t, err)
	assert.True(t, gotSys.IsSystem)
	assert.Equal(t, domain.ClusterID(domain.ClusterSingletonID), gotSys.ClusterID,
		"system role cluster_id populated by expanded roleCols")
}

// TestRole_ListAssignable_AccountResource — 1.5-01: account resource returns
// SYSTEM + own ACCOUNT-roles, NOT a foreign account's custom role.
func TestRole_ListAssignable_AccountResource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	ownerA := mustSeedUser(t, ctx, pool, "laa")
	accA := seedAccount(t, ctx, repo, "acc-laa-a", ownerA)
	ownerB := mustSeedUser(t, ctx, pool, "lab")
	accB := seedAccount(t, ctx, repo, "acc-laa-b", ownerB)

	accustom := seedCustomRole(t, ctx, repo, accA.ID, "laa_custom")
	bcustom := seedCustomRole(t, ctx, repo, accB.ID, "lab_custom")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// page_size big enough for a single page (all system roles + accustom).
	out, _, err := rd.Roles().ListAssignable(ctx, "account", string(accA.ID),
		reporole.ListFilter{PageSize: 1000})
	require.NoError(t, err)

	byID := roleIDs(out)
	assert.Contains(t, byID, accustom.ID, "own account-role assignable")
	assert.NotContains(t, byID, bcustom.ID, "foreign account-role NOT assignable (1.5-01 isolation)")

	// at least one system role present and is_system=true with cluster scope.
	sawSystem := false
	for _, r := range out {
		if r.IsSystem {
			sawSystem = true
			assert.NotEmpty(t, r.ClusterID)
		}
	}
	assert.True(t, sawSystem, "system roles assignable on account")
}

// TestRole_ListAssignable_ProjectResource_StrictAccountExcluded — 1.5-02 / 1.5-02b:
// project resource returns SYSTEM + own PROJECT-role; STRICTLY excludes the
// account-scoped role of the owning account.
func TestRole_ListAssignable_ProjectResource_StrictAccountExcluded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "lap")
	acc := seedAccount(t, ctx, repo, "acc-lap", owner)
	proj := seedProject(t, ctx, repo, acc.ID, "proj-lap")

	accustom := seedCustomRole(t, ctx, repo, acc.ID, "lap_acc")
	pcustomID := seedProjectRole(t, ctx, pool, proj.ID, "lap_prj")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	out, _, err := rd.Roles().ListAssignable(ctx, "project", string(proj.ID),
		reporole.ListFilter{PageSize: 1000})
	require.NoError(t, err)

	byID := roleIDs(out)
	assert.Contains(t, byID, pcustomID, "own project-role assignable (1.5-02)")
	assert.NotContains(t, byID, accustom.ID, "account-role NOT assignable on project (1.5-02b STRICT)")
}

// TestRole_ListAssignable_ClusterResource_SystemOnly — 1.5-03: cluster resource
// returns ONLY system roles.
func TestRole_ListAssignable_ClusterResource_SystemOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "lac")
	acc := seedAccount(t, ctx, repo, "acc-lac", owner)
	accustom := seedCustomRole(t, ctx, repo, acc.ID, "lac_acc")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	out, _, err := rd.Roles().ListAssignable(ctx, "cluster", domain.ClusterSingletonID,
		reporole.ListFilter{PageSize: 1000})
	require.NoError(t, err)

	byID := roleIDs(out)
	assert.NotContains(t, byID, accustom.ID, "custom role NOT assignable on cluster")
	for _, r := range out {
		assert.True(t, r.IsSystem, "cluster ⇒ only system roles (1.5-03), got non-system %s", r.ID)
	}
	assert.NotEmpty(t, out, "system roles seeded → cluster returns them")
}

// TestRole_ListAssignable_Pagination — 1.5-04: keyset pagination over the
// filtered set (page_size=1 yields a page + cursor, second page the remainder).
func TestRole_ListAssignable_Pagination(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "lpg")
	acc := seedAccount(t, ctx, repo, "acc-lpg", owner)
	seedCustomRole(t, ctx, repo, acc.ID, "lpg_acc")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// First gather the full set to know the count.
	full, _, err := rd.Roles().ListAssignable(ctx, "account", string(acc.ID),
		reporole.ListFilter{PageSize: 1000})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(full), 2, "system roles + accustom ≥ 2")

	// Walk the set one element per page; collect ids; assert no dup, full coverage.
	seen := map[domain.RoleID]bool{}
	token := ""
	pages := 0
	for {
		page, next, perr := rd.Roles().ListAssignable(ctx, "account", string(acc.ID),
			reporole.ListFilter{PageSize: 1, PageToken: token})
		require.NoError(t, perr)
		require.LessOrEqual(t, len(page), 1, "page_size=1 yields ≤1 element")
		for _, r := range page {
			require.False(t, seen[r.ID], "no duplicate across pages: %s", r.ID)
			seen[r.ID] = true
		}
		pages++
		if next == "" {
			break
		}
		token = next
		require.LessOrEqual(t, pages, len(full)+2, "must terminate")
	}
	assert.Equal(t, len(full), len(seen), "paged walk covers the full filtered set")
}
