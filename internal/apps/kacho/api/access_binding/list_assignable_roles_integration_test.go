// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding_test

// list_assignable_roles_integration_test.go — use-case-level integration tests
// (testcontainers PG16) for AccessBindingService.ListAssignableRoles. Wires the
// real CQRS repo so the role-scope read + isRoleAssignable filter + scope_group
// derivation + authz (requireGrantAuthority) are all exercised end-to-end.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/jackc/pgx/v5/pgxpool"

	accessbindingapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	reporole "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
)

func asUser(ctx context.Context, uid domain.UserID) context.Context {
	return operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: string(uid)})
}

// seedAccountCustomRole — account-scoped custom role via direct SQL.
func seedAccountCustomRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, acc domain.AccountID, name string) domain.RoleID {
	t.Helper()
	rid := domain.RoleID(ids.NewID(domain.PrefixRole))
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, is_system)
		VALUES ($1, $2, $3, $4, '["iam.users.*.read"]'::jsonb, false)`,
		string(rid), string(acc), name, "acc role "+name)
	require.NoError(t, err)
	return rid
}

func TestListAssignableRoles_Account_HappyAndIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	uc := accessbindingapp.NewListAssignableRolesUseCase(repo)

	ownerA := mustSeedUser(t, ctx, pool, "lar01a")
	accA := seedAccountByOwner(t, ctx, pool, "acc-lar01a", ownerA)
	ownerB := mustSeedUser(t, ctx, pool, "lar01b")
	accB := seedAccountByOwner(t, ctx, pool, "acc-lar01b", ownerB)

	accustom := seedAccountCustomRole(t, ctx, pool, accA, "lar01_own")
	bcustom := seedAccountCustomRole(t, ctx, pool, accB, "lar01_foreign")

	out, next, err := uc.Execute(asUser(ctx, ownerA), "account", string(accA),
		reporole.ListFilter{PageSize: 1000})
	require.NoError(t, err)
	assert.Empty(t, next)

	byID := map[domain.RoleID]domain.AssignableRole{}
	for _, r := range out {
		byID[r.RoleID] = r
	}
	own, ok := byID[accustom]
	require.True(t, ok, "own account-role assignable (1.5-01)")
	assert.Equal(t, domain.RoleScopeGroupAccount, own.ScopeGroup, "scope_group computed server-side (1.5-11)")
	assert.False(t, own.IsSystem)
	assert.Equal(t, "lar01_own", string(own.Name), "resolved name (1.5-11)")
	assert.NotContains(t, byID, bcustom, "foreign account-role NOT returned (1.5-01 isolation)")

	sawSystem := false
	for _, r := range out {
		if r.IsSystem {
			sawSystem = true
			assert.Equal(t, domain.RoleScopeGroupSystem, r.ScopeGroup)
		}
	}
	assert.True(t, sawSystem, "system roles present with scope_group=SYSTEM")
}

func TestListAssignableRoles_Cluster_SystemOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	// cluster scope has no DB owner — authority is FGA admin only; wire the
	// allow-all fake RelationStore so the cluster grant-authority path passes.
	uc := accessbindingapp.NewListAssignableRolesUseCase(repo).WithRelationStore(allowRelationStore{}, nil)

	admin := mustSeedUser(t, ctx, pool, "lar03")
	seedClusterAdmin(t, ctx, pool, admin)
	acc := seedAccountByOwner(t, ctx, pool, "acc-lar03", admin)
	accustom := seedAccountCustomRole(t, ctx, pool, acc, "lar03_acc")

	out, _, err := uc.Execute(asUser(ctx, admin), "cluster", domain.ClusterSingletonID,
		reporole.ListFilter{PageSize: 1000})
	require.NoError(t, err, "cluster-admin allowed (1.5-03)")

	for _, r := range out {
		assert.True(t, r.IsSystem, "cluster ⇒ only SYSTEM (1.5-03), got %s", r.RoleID)
		assert.NotEqual(t, accustom, r.RoleID)
	}
	assert.NotEmpty(t, out, "system roles seeded")
}

func TestListAssignableRoles_UnknownResourceType_InvalidArgument(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	uc := accessbindingapp.NewListAssignableRolesUseCase(repo)

	caller := mustSeedUser(t, ctx, pool, "lar05")

	_, _, err := uc.Execute(asUser(ctx, caller), "instance", "epd-XXXX", reporole.ListFilter{})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "1.5-05 unknown resource_type")
	assert.Contains(t, status.Convert(err).Message(), "resource_type")
}

func TestListAssignableRoles_MalformedResourceID_InvalidArgument(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	uc := accessbindingapp.NewListAssignableRolesUseCase(repo)

	caller := mustSeedUser(t, ctx, pool, "lar06")

	// account with garbage id.
	_, _, err := uc.Execute(asUser(ctx, caller), "account", "not-a-valid-id", reporole.ListFilter{})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "invalid account id")

	// cluster with wrong id.
	_, _, err = uc.Execute(asUser(ctx, caller), "cluster", "cluster-wrong", reporole.ListFilter{})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "1.5-06 cluster singleton guard")

	// prefix↔type mismatch: project id under resource_type=account.
	_, _, err = uc.Execute(asUser(ctx, caller), "account", "prj00000000000000000P", reporole.ListFilter{})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "1.5-06 prefix↔type mismatch")
}

func TestListAssignableRoles_MissingResource_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	uc := accessbindingapp.NewListAssignableRolesUseCase(repo)

	caller := mustSeedUser(t, ctx, pool, "lar07")

	// well-formed acc id (exactly 20 chars: "acc" + 17) that does not exist.
	const ghostAcc = "acc00000000000ghost"
	require.Len(t, ghostAcc+"a", 20)
	_, _, err := uc.Execute(asUser(ctx, caller), "account", ghostAcc+"a", reporole.ListFilter{})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err), "1.5-07 well-formed-but-missing → NotFound")
}

func TestListAssignableRoles_NoGrantAuthority_PermissionDenied(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	uc := accessbindingapp.NewListAssignableRolesUseCase(repo)

	ownerA := mustSeedUser(t, ctx, pool, "lar08a")
	accA := seedAccountByOwner(t, ctx, pool, "acc-lar08a", ownerA)
	userB := mustSeedUser(t, ctx, pool, "lar08b") // not owner of accA, no FGA admin

	_, _, err := uc.Execute(asUser(ctx, userB), "account", string(accA), reporole.ListFilter{PageSize: 1000})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "1.5-08 no grant-authority")
}

func TestListAssignableRoles_Anonymous_FailClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	uc := accessbindingapp.NewListAssignableRolesUseCase(repo)

	ownerA := mustSeedUser(t, ctx, pool, "lar09")
	accA := seedAccountByOwner(t, ctx, pool, "acc-lar09", ownerA)

	// no principal in ctx → anonymous.
	_, _, err := uc.Execute(ctx, "account", string(accA), reporole.ListFilter{PageSize: 1000})
	require.Error(t, err)
	code := status.Code(err)
	assert.True(t, code == codes.Unauthenticated || code == codes.PermissionDenied,
		"1.5-09 anonymous fail-closed, got %v", code)
}
