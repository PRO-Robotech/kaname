// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding_test

// f9_perms_only_target_integration_test.go — least-privilege spine, second path
// (companion to Finding 1). A per-object target (target.resources[]) materializes
// per-object v_* tuples from role.rules via the reconciler. A LEGACY permissions-only
// role (no rules — not creatable in IAM-1, RoleService.Create requires rules[], but a
// pre-rules-model row may survive back-compat read) has NO per-object materialization
// path: its access is scope-level tier (tuplesForBinding). Pairing it with a per-object
// target would SILENTLY grant the WHOLE scope (over-grant, same class as Finding 1).
//
// The F9 structural gates therefore REJECT a per-object target on a rules-less role
// (fail-closed) — an allInScope target on the same role stays accepted (scope-level
// grant is the legacy role's intended semantics; only per-object is incoherent for it).
//
// END-TO-END through the real Handler + use-case + testcontainers PG16.

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

func TestAB_PermsOnlyRole_PerObjectTarget_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	h := deltaHandler(t, repo, opsRepo)

	owner := mustSeedUser(t, ctx, pool, "po1")
	acc := seedAccountByOwner(t, ctx, pool, "acc-po1", owner)
	member := mustSeedUser(t, ctx, pool, "po1m")
	// A legacy permissions-only role (rules-less): seeded via direct SQL (the public
	// RoleService.Create requires rules[], so this shape is a back-compat legacy row).
	role := seedAccountCustomRole(t, ctx, pool, acc, "po1_perms")

	// per-object target on a rules-less role → sync FAILED_PRECONDITION (least-priv:
	// a permissions-only role has no per-object materialization path, so honouring the
	// target is impossible — it would over-grant the whole scope).
	_, err := h.Create(asUser(ctx, owner), &iamv1.CreateAccessBindingRequest{
		SubjectType: "user", SubjectId: string(member), RoleId: string(role),
		ScopeType: "iam.account", ScopeId: string(acc),
		Target: resourcesTarget(&iamv1.ResourceRef{Type: "vpc.network", Id: "enp-x"}),
	})
	require.Error(t, err, "per-object target on a rules-less role must be rejected sync")
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Contains(t, st.Message(), "has no rules")
	assert.Equal(t, 0, bindingCount(t, ctx, repo, role, "account", string(acc)),
		"no binding created for the rejected per-object grant")

	// allInScope target on the SAME permissions-only role → accepted (scope-level grant
	// is the legacy role's intended semantics; only per-object is incoherent for it).
	op, err := h.Create(asUser(ctx, owner), &iamv1.CreateAccessBindingRequest{
		SubjectType: "user", SubjectId: string(member), RoleId: string(role),
		ScopeType: "iam.account", ScopeId: string(acc),
		Target: allInScopeTarget(),
	})
	require.NoError(t, err, "permissions-only role + allInScope is accepted (scope-level grant)")
	done := awaitOp(t, ctx, opsRepo, op.GetId())
	require.Nil(t, done.Error, "allInScope grant on a permissions-only role succeeds")
}
