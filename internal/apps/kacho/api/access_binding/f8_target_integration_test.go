// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding_test

// f8_target_integration_test.go — redesign-2026 F8 (IAM-1-21/22/23) END-TO-END
// through the real Handler + use-cases + testcontainers PG16. Drives the proto
// request/response surface: target is REQUIRED (least-priv), allInScope round-trips
// through the DB, and a missing / unknown-type target is rejected sync.

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

// allInScopeTarget is the explicit whole-anchor opt-in target (F8).
func allInScopeTarget() *iamv1.AccessTarget {
	return &iamv1.AccessTarget{
		Target: &iamv1.AccessTarget_AllInScope{AllInScope: &iamv1.AccessTargetAllInScope{}},
	}
}

// resourcesTarget builds a per-object target from (type,id) pairs.
func resourcesTarget(refs ...*iamv1.ResourceRef) *iamv1.AccessTarget {
	return &iamv1.AccessTarget{
		Target: &iamv1.AccessTarget_Resources{Resources: &iamv1.AccessTargetResources{Resources: refs}},
	}
}

// IAM-1-21: Create with target.allInScope{} → after done, Get.target.allInScope set.
func TestAB_IAM_1_21_TargetAllInScope_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	h := deltaHandler(t, repo, opsRepo)

	owner := mustSeedUser(t, ctx, pool, "f8a")
	acc := seedAccountByOwner(t, ctx, pool, "acc-f8a", owner)
	member := mustSeedUser(t, ctx, pool, "f8am")
	role := seedAccountCustomRole(t, ctx, pool, acc, "f8a_role")

	op, err := h.Create(asUser(ctx, owner), &iamv1.CreateAccessBindingRequest{
		SubjectType: "user", SubjectId: string(member), RoleId: string(role),
		ScopeType: "iam.account", ScopeId: string(acc),
		Target: allInScopeTarget(),
	})
	require.NoError(t, err)
	done := awaitOp(t, ctx, opsRepo, op.GetId())
	require.Nil(t, done.Error)

	var md iamv1.CreateAccessBindingMetadata
	require.NoError(t, done.Metadata.UnmarshalTo(&md))
	pb, gerr := h.Get(asUser(ctx, owner), &iamv1.GetAccessBindingRequest{AccessBindingId: md.GetAccessBindingId()})
	require.NoError(t, gerr)
	assert.NotNil(t, pb.GetTarget().GetAllInScope(), "whole-anchor grant projects as allInScope")
	assert.Empty(t, pb.GetTarget().GetResources().GetResources())
}

// IAM-1-22: Create WITHOUT target (valid scope) → sync INVALID_ARGUMENT actionable.
func TestAB_IAM_1_22_MissingTarget_InvalidArgument(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	h := deltaHandler(t, repo, opsRepo)

	owner := mustSeedUser(t, ctx, pool, "f8b")
	acc := seedAccountByOwner(t, ctx, pool, "acc-f8b", owner)
	member := mustSeedUser(t, ctx, pool, "f8bm")
	role := seedAccountCustomRole(t, ctx, pool, acc, "f8b_role")

	_, err := h.Create(asUser(ctx, owner), &iamv1.CreateAccessBindingRequest{
		SubjectType: "user", SubjectId: string(member), RoleId: string(role),
		ScopeType: "iam.account", ScopeId: string(acc),
		// target omitted
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "target is required")
	assert.Contains(t, st.Message(), "allInScope")
	assert.Equal(t, 0, bindingCount(t, ctx, repo, role, "account", string(acc)), "no binding created")
}

// IAM-1-23: Create with an unknown per-object target type → sync INVALID_ARGUMENT.
func TestAB_IAM_1_23_UnknownTargetType_InvalidArgument(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	h := deltaHandler(t, repo, opsRepo)

	owner := mustSeedUser(t, ctx, pool, "f8c")
	acc := seedAccountByOwner(t, ctx, pool, "acc-f8c", owner)
	member := mustSeedUser(t, ctx, pool, "f8cm")
	role := seedAccountCustomRole(t, ctx, pool, acc, "f8c_role")

	_, err := h.Create(asUser(ctx, owner), &iamv1.CreateAccessBindingRequest{
		SubjectType: "user", SubjectId: string(member), RoleId: string(role),
		ScopeType: "iam.account", ScopeId: string(acc),
		Target: resourcesTarget(&iamv1.ResourceRef{Type: "unknown.thing", Id: "x"}),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "target.resources[].type")
}
