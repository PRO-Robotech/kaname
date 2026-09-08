// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// f9_hierarchy_down_integration_test.go — redesign-2026 F9 (IAM-1-25) hierarchy-down:
// an iam.account-tier custom role is assignable on a project NESTED in the role's
// account (acceptance IAM-1-25 "And обратное валидно: iam.account-роль assignable на
// вложенном iam.project того же аккаунта"). The stateless IsRoleAssignable predicate
// cannot know the project's owning account (no repo), so the Create gate resolves
// project→account and admits the account-tier role when the project belongs to the
// role's account. A role of a DIFFERENT account stays a sync FAILED_PRECONDITION.
//
// END-TO-END through the real Handler + use-case + testcontainers PG16. Run with
// `-p 1` under Docker contention.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// IAM-1-25 (positive hierarchy-down): an account-tier role R∈acc-A bound on a project
// prj-X∈acc-A passes the IsRoleAssignable gate (account→nested-project) and the binding
// is created. IAM-1-25 (negative isolation): the SAME role R∈acc-A on a project
// prj-Y∈acc-B stays a sync FAILED_PRECONDITION "not assignable".
func TestAB_IAM_1_25_AccountRoleOnNestedProject_Assignable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kanamepg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kaname")
	h := deltaHandler(t, repo, opsRepo)

	ownerA := mustSeedUser(t, ctx, pool, "hd25a")
	accA := seedAccountByOwner(t, ctx, pool, "acc-hd25a", ownerA)
	prjX := seedProjectInAccount(t, ctx, pool, accA, "prj-hd25x")
	member := mustSeedUser(t, ctx, pool, "hd25m")
	// account-tier custom role in acc-A (definitionTier iam.account).
	roleA := seedAccountCustomRole(t, ctx, pool, accA, "hd25_acc_role")

	// POSITIVE: account-role R∈acc-A on project prj-X∈acc-A → assignable (hierarchy-down).
	op, err := h.Create(asUser(ctx, ownerA), &iamv1.CreateAccessBindingRequest{
		SubjectType: "user", SubjectId: string(member), RoleId: string(roleA),
		ScopeType: "iam.project", ScopeId: string(prjX),
		Target: allInScopeTarget(),
	})
	require.NoError(t, err, "account-role on nested project of same account must pass IsRoleAssignable gate (IAM-1-25)")
	done := awaitOp(t, ctx, opsRepo, op.GetId())
	require.Nil(t, done.Error, "create must succeed (no async error)")
	assert.Equal(t, 1, bindingCount(t, ctx, repo, roleA, "project", string(prjX)),
		"binding materialized on the nested project")

	// NEGATIVE (isolation): the same account-role R∈acc-A on a project prj-Y∈acc-B
	// (a DIFFERENT account) stays a sync FAILED_PRECONDITION — hierarchy-down never
	// crosses the account boundary. LEAST-INFO: the reject is the byte-identical
	// not-found text of an ABSENT role, never the actionable definitionTier one — a
	// role outside the scope's account tree must not be distinguishable from a
	// non-existent one (parity with RoleService.Get's hide-existence contract).
	ownerB := mustSeedUser(t, ctx, pool, "hd25b")
	accB := seedAccountByOwner(t, ctx, pool, "acc-hd25b", ownerB)
	prjY := seedProjectInAccount(t, ctx, pool, accB, "prj-hd25y")

	_, err = h.Create(asUser(ctx, ownerA), &iamv1.CreateAccessBindingRequest{
		SubjectType: "user", SubjectId: string(member), RoleId: string(roleA),
		ScopeType: "iam.project", ScopeId: string(prjY),
		Target: allInScopeTarget(),
	})
	require.Error(t, err, "account-role on a project of a DIFFERENT account → sync error")
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code(), "cross-account role → FAILED_PRECONDITION (sync)")
	assert.Equal(t, "Role "+string(roleA)+" not found", st.Message(),
		"a foreign-account role is indistinguishable from an absent one")
	assert.NotContains(t, st.Message(), "definitionTier",
		"the role's tier must not leak across the account boundary")
	assert.Equal(t, 0, bindingCount(t, ctx, repo, roleA, "project", string(prjY)),
		"no binding written for cross-account role")

	// An ABSENT role id on the SAME scope yields the same shape — the two branches
	// are indistinguishable to the caller.
	absent := domain.RoleID(ids.NewID(domain.PrefixRole))
	_, err = h.Create(asUser(ctx, ownerA), &iamv1.CreateAccessBindingRequest{
		SubjectType: "user", SubjectId: string(member), RoleId: string(absent),
		ScopeType: "iam.project", ScopeId: string(prjY),
		Target: allInScopeTarget(),
	})
	require.Error(t, err)
	stAbsent, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, stAbsent.Code())
	assert.Equal(t, "Role "+string(absent)+" not found", stAbsent.Message())

	// IN-TREE non-assignable keeps the ACTIONABLE text: a PROJECT-tier role of prj-X
	// bound on a SIBLING project prj-Z of the SAME account is visible to this scope's
	// administrator, so the message must tell them what to do (no over-tightening).
	prjZ := seedProjectInAccount(t, ctx, pool, accA, "prj-hd25z")
	roleProjX := seedProjectCustomRole(t, ctx, pool, prjX, "hd25_prj_role")
	_, err = h.Create(asUser(ctx, ownerA), &iamv1.CreateAccessBindingRequest{
		SubjectType: "user", SubjectId: string(member), RoleId: string(roleProjX),
		ScopeType: "iam.project", ScopeId: string(prjZ),
		Target: allInScopeTarget(),
	})
	require.Error(t, err, "a project-tier role is not assignable on a sibling project")
	stSibling, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, stSibling.Code())
	assert.Contains(t, stSibling.Message(), "is not assignable on iam.project:"+string(prjZ),
		"an in-tree role keeps the actionable IsRoleAssignable text")
	assert.Contains(t, stSibling.Message(), "definitionTier iam.project")
}

// seedProjectCustomRole — project-scoped custom role via direct SQL (roles_scope_xor
// admits exactly one of cluster/organization/account/project).
func seedProjectCustomRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, prj domain.ProjectID, name string) domain.RoleID {
	t.Helper()
	rid := domain.RoleID(ids.NewID(domain.PrefixRole))
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.roles (id, project_id, name, description, permissions)
		VALUES ($1, $2, $3, $4, '["iam.users.*.read"]'::jsonb)`,
		string(rid), string(prj), name, "prj role "+name)
	require.NoError(t, err)
	return rid
}
