// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
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
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
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
	// crosses the account boundary.
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
	assert.Contains(t, st.Message(), "not assignable")
	assert.Equal(t, 0, bindingCount(t, ctx, repo, roleA, "project", string(prjY)),
		"no binding written for cross-account role")
}
