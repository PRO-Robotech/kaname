// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding_test

// f9_gates_integration_test.go — redesign-2026 F9 (IAM-1-24/26) END-TO-END through
// the real Handler + use-case + testcontainers PG16: the SYNC structural gates
// RoleCoversType (a per-object target type not covered by the role's rules) and
// scope well-formedness (a malformed scope id) reject FIRST-statement, before any
// Operation is minted.

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

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// seedAccountRulesRole seeds an account-scoped rules-role whose authored rules cover
// only the given module (e.g. "vpc"). Used to exercise the RoleCoversType gate.
func seedAccountRulesRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, acc domain.AccountID, name, module string) domain.RoleID {
	t.Helper()
	rid := domain.RoleID(ids.NewID(domain.PrefixRole))
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, rules)
		VALUES ($1, $2, $3, $4, '[]'::jsonb,
		        ('[{"module":"'||$5||'","resources":["network"],"verbs":["get","list"]}]')::jsonb)`,
		string(rid), string(acc), name, "rules role "+name, module)
	require.NoError(t, err)
	return rid
}

// IAM-1-24: a role covering only vpc.* + a per-object target compute.instance →
// sync FAILED_PRECONDITION (RoleCoversType), before any Operation is minted.
func TestAB_IAM_1_24_RoleCoversType_Uncovered(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	h := deltaHandler(t, repo, opsRepo)

	owner := mustSeedUser(t, ctx, pool, "f9a")
	acc := seedAccountByOwner(t, ctx, pool, "acc-f9a", owner)
	member := mustSeedUser(t, ctx, pool, "f9am")
	role := seedAccountRulesRole(t, ctx, pool, acc, "f9a_vpc", "vpc")

	_, err := h.Create(asUser(ctx, owner), &iamv1.CreateAccessBindingRequest{
		SubjectType: "user", SubjectId: string(member), RoleId: string(role),
		ScopeType: "iam.account", ScopeId: string(acc),
		Target: resourcesTarget(&iamv1.ResourceRef{Type: "compute.instance", Id: "ins-abc"}),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Contains(t, st.Message(), "does not grant verbs on compute.instance")
	assert.Contains(t, st.Message(), "must be covered by role.rules")
	assert.Equal(t, 0, bindingCount(t, ctx, repo, role, "account", string(acc)), "no binding created")

	// but a COVERED per-object target (vpc.network) passes the gate.
	op, err := h.Create(asUser(ctx, owner), &iamv1.CreateAccessBindingRequest{
		SubjectType: "user", SubjectId: string(member), RoleId: string(role),
		ScopeType: "iam.account", ScopeId: string(acc),
		Target: resourcesTarget(&iamv1.ResourceRef{Type: "vpc.network", Id: "enp-xyz"}),
	})
	require.NoError(t, err, "covered target type passes RoleCoversType")
	done := awaitOp(t, ctx, opsRepo, op.GetId())
	require.Nil(t, done.Error)
}

// IAM-1-26: a malformed scope id → sync INVALID_ARGUMENT first statement.
func TestAB_IAM_1_26_MalformedScopeId_InvalidArgument(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	h := deltaHandler(t, repo, opsRepo)

	owner := mustSeedUser(t, ctx, pool, "f9b")
	acc := seedAccountByOwner(t, ctx, pool, "acc-f9b", owner)
	member := mustSeedUser(t, ctx, pool, "f9bm")
	role := seedAccountCustomRole(t, ctx, pool, acc, "f9b_role")

	_, err := h.Create(asUser(ctx, owner), &iamv1.CreateAccessBindingRequest{
		SubjectType: "user", SubjectId: string(member), RoleId: string(role),
		ScopeType: "iam.account", ScopeId: "!!!",
		Target: allInScopeTarget(),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "invalid access binding scope id '!!!'")
}
