// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// role_project_scope_integration_test.go — project-scoped custom role persistence.
//
// The repo Insert must persist a PROJECT-scoped custom role (project_id set,
// account_id NULL) so the project-anchor path becomes reachable via the
// public Role.Create. Previously the Insert wrote only account_id, so a
// project-scoped role could be created only by raw SQL (seedProjectRole) —
// never through the production RolesW().Insert path.
//
// Asserts:
//   - Insert(project-scoped role) round-trips through Get with ProjectID set,
//     AccountID empty, IsSystem=false (the XOR CHECK roles_definition_tier_xor accepts it
//     because account_id is stored NULL, not '').
//   - domain.IsRoleAssignable(role, "project", <P>) == true (so AccessBinding
//     on project:<P> passes the scope gate).
//   - domain.IsRoleAssignable(role, "account", <A>) == false (STRICT: a
//     project-scoped role is NOT assignable on the parent account).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func TestRole_212_InsertProjectScoped_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "r212")
	acc := seedAccount(t, ctx, repo, "acc-r212", owner)
	proj := seedProject(t, ctx, repo, acc.ID, "proj-r212")

	// Insert a project-scoped role through the PRODUCTION writer path.
	r := domain.Role{
		ID:          domain.RoleID(ids.NewID(domain.PrefixRole)),
		ProjectID:   proj.ID,
		Name:        domain.RoleName("prj_scoped_212"),
		Description: domain.Description("project-scoped custom role"),
		Permissions: domain.Permissions{"iam.project.*.get"},
		IsSystem:    false,
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	inserted, err := w.RolesW().Insert(ctx, r)
	require.NoError(t, err, "Insert must accept a project-scoped role (account_id NULL)")
	require.NoError(t, w.Commit(ctx))

	assert.Equal(t, proj.ID, inserted.ProjectID, "ProjectID persisted")
	assert.Empty(t, string(inserted.AccountID), "AccountID empty for a project-scoped role")
	assert.False(t, inserted.IsSystem)

	// Get round-trip: project_id is read back (roleCols includes it).
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	got, err := rd.Roles().Get(ctx, inserted.ID)
	require.NoError(t, err)
	assert.Equal(t, proj.ID, got.ProjectID)
	assert.Empty(t, string(got.AccountID))

	// The shared assignability predicate: assignable on its OWN project only.
	assert.True(t, domain.IsRoleAssignable(got, "project", string(proj.ID)),
		"project-scoped role must be assignable on project:%s", proj.ID)
	assert.False(t, domain.IsRoleAssignable(got, "account", string(acc.ID)),
		"STRICT: project-scoped role is NOT assignable on the parent account")
	assert.Equal(t, domain.RoleScopeGroupProject, domain.ScopeGroupOf(got))
}

// 212 negative at the DB layer: inserting a role with BOTH account_id and
// project_id set must be rejected by the roles_definition_tier_xor CHECK (the use-case
// also rejects it earlier, but the DB is the backstop, ban #10).
func TestRole_212_InsertBothScopes_CheckViolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "r212b")
	acc := seedAccount(t, ctx, repo, "acc-r212b", owner)
	proj := seedProject(t, ctx, repo, acc.ID, "proj-r212b")

	r := domain.Role{
		ID:          domain.RoleID(ids.NewID(domain.PrefixRole)),
		AccountID:   acc.ID,
		ProjectID:   proj.ID,
		Name:        domain.RoleName("both_scopes_212"),
		Description: domain.Description("invalid: two scopes"),
		Permissions: domain.Permissions{"iam.project.*.get"},
		IsSystem:    false,
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.RolesW().Insert(ctx, r)
	require.Error(t, err, "DB CHECK roles_definition_tier_xor must reject account_id AND project_id both set")
	_ = w.Rollback(ctx)
}
