// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding_test

// f7_scope_anchor_integration_test.go — redesign-2026 F7 (IAM-1-18/19/20)
// END-TO-END through the real Handler + use-cases + testcontainers PG16. Drives the
// proto request/response surface (where the scope-anchor rename lives): the input
// dotted scopeType (iam.cluster|iam.account|iam.project) is mapped to the bare
// within-service anchor kind, and Get projects the bare DB row back to the dotted
// scopeType/scopeId as the SOLE scope projection (no legacy resource-named fields).
//
// Run with `-p 1` under Docker contention.

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	accessbindingapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// deltaHandler wires the minimal Handler needed for Create + Get round-trips
// (other use-cases are nil — not exercised here).
func deltaHandler(t *testing.T, repo *kachopg.Repository, opsRepo operations.Repo) *accessbindingapp.Handler {
	t.Helper()
	create := accessbindingapp.NewCreateAccessBindingUseCase(repo, opsRepo).
		WithRelationStore(allowRelationStore{}, nil)
	get := accessbindingapp.NewGetAccessBindingUseCase(repo).
		WithRelationStore(allowRelationStore{}, nil)
	return accessbindingapp.NewHandler(create, nil, get, nil, nil, nil, nil)
}

// IAM-1-18 (round-trip): Create with the dotted scopeType/scopeId; after done, Get
// projects the bare DB row back to the dotted scopeType/scopeId.
func TestAB_IAM_1_18_DottedScope_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	h := deltaHandler(t, repo, opsRepo)

	owner := mustSeedUser(t, ctx, pool, "f7a")
	acc := seedAccountByOwner(t, ctx, pool, "acc-f7a", owner)
	member := mustSeedUser(t, ctx, pool, "f7am")
	role := seedAccountCustomRole(t, ctx, pool, acc, "f7a_role")

	op, err := h.Create(asUser(ctx, owner), &iamv1.CreateAccessBindingRequest{
		SubjectType: "user",
		SubjectId:   string(member),
		RoleId:      string(role),
		ScopeType:   "iam.account",
		ScopeId:     string(acc),
	})
	require.NoError(t, err)
	done := awaitOp(t, ctx, opsRepo, op.GetId())
	require.Nil(t, done.Error, "create must succeed")

	// Extract the created id from the operation metadata and Get it.
	var md iamv1.CreateAccessBindingMetadata
	require.NoError(t, done.Metadata.UnmarshalTo(&md))
	pb, gerr := h.Get(asUser(ctx, owner), &iamv1.GetAccessBindingRequest{AccessBindingId: md.GetAccessBindingId()})
	require.NoError(t, gerr)

	assert.Equal(t, "iam.account", pb.GetScopeType(), "sole scope projection is dotted")
	assert.Equal(t, string(acc), pb.GetScopeId())
}

// IAM-1-18 (negative): Create WITHOUT scopeType → sync INVALID_ARGUMENT first
// statement (pre-Phase-0 scopeType is REQUIRED); no binding row created.
func TestAB_IAM_1_18_MissingScopeType_InvalidArgument(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	h := deltaHandler(t, repo, opsRepo)

	owner := mustSeedUser(t, ctx, pool, "f7b")
	acc := seedAccountByOwner(t, ctx, pool, "acc-f7b", owner)
	member := mustSeedUser(t, ctx, pool, "f7bm")
	role := seedAccountCustomRole(t, ctx, pool, acc, "f7b_role")

	_, err := h.Create(asUser(ctx, owner), &iamv1.CreateAccessBindingRequest{
		SubjectType: "user",
		SubjectId:   string(member),
		RoleId:      string(role),
		ScopeId:     string(acc), // scopeType omitted
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "scopeType is required")
	assert.Equal(t, 0, bindingCount(t, ctx, repo, role, "account", string(acc)), "no binding created")
}

// IAM-1-18 (negative): unknown dotted scopeType → sync INVALID_ARGUMENT.
func TestAB_IAM_1_18_UnknownScopeType_InvalidArgument(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	h := deltaHandler(t, repo, opsRepo)

	owner := mustSeedUser(t, ctx, pool, "f7c")
	acc := seedAccountByOwner(t, ctx, pool, "acc-f7c", owner)
	member := mustSeedUser(t, ctx, pool, "f7cm")
	role := seedAccountCustomRole(t, ctx, pool, acc, "f7c_role")

	_, err := h.Create(asUser(ctx, owner), &iamv1.CreateAccessBindingRequest{
		SubjectType: "user",
		SubjectId:   string(member),
		RoleId:      string(role),
		ScopeType:   "iam.folder", // not in the closed three-tier set
		ScopeId:     string(acc),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "Illegal argument scopeType")
}

// IAM-1-18: a bare account row inserted directly (legacy-shaped) projects to the
// dotted scopeType on read — the dto boundary mapping, no backfill.
func TestAB_IAM_1_18_DbRowProjectsDotted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	h := deltaHandler(t, repo, operations.NewRepo(pool, "kacho_iam"))

	owner := mustSeedUser(t, ctx, pool, "f7d")
	acc := seedAccountByOwner(t, ctx, pool, "acc-f7d", owner)
	member := mustSeedUser(t, ctx, pool, "f7dm")
	role := seedAccountCustomRole(t, ctx, pool, acc, "f7d_role")

	bid := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	// `scope` (SMALLINT) omitted — the migration-0005 BEFORE INSERT trigger derives
	// it from resource_type (account ⇒ ACCOUNT).
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.access_bindings
		    (id, subject_type, subject_id, role_id, resource_type, resource_id, status, granted_by_user_id)
		VALUES ($1,'user',$2,$3,'account',$4,'ACTIVE',$5)`,
		string(bid), string(member), string(role), string(acc), string(owner))
	require.NoError(t, err)

	pb, gerr := h.Get(asUser(ctx, owner), &iamv1.GetAccessBindingRequest{AccessBindingId: string(bid)})
	require.NoError(t, gerr)
	assert.Equal(t, "iam.account", pb.GetScopeType())
	assert.Equal(t, string(acc), pb.GetScopeId())
}

// IAM-1-18/29: two concurrent IDENTICAL Create (dotted form) for the same active
// grant → exactly one wins, the other surfaces AlreadyExists (the partial
// active-grant UNIQUE, WHERE revoked_at IS NULL, is unchanged by the F7 rename).
func TestAB_IAM_1_18_ConcurrentIdenticalCreate_StrictCreateUnchanged(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	h := deltaHandler(t, repo, opsRepo)

	owner := mustSeedUser(t, ctx, pool, "f7e")
	acc := seedAccountByOwner(t, ctx, pool, "acc-f7e", owner)
	member := mustSeedUser(t, ctx, pool, "f7em")
	role := seedAccountCustomRole(t, ctx, pool, acc, "f7e_role")
	callerCtx := asUser(ctx, owner)

	newReq := func() *iamv1.CreateAccessBindingRequest {
		return &iamv1.CreateAccessBindingRequest{
			SubjectType: "user", SubjectId: string(member), RoleId: string(role),
			ScopeType: "iam.account", ScopeId: string(acc),
		}
	}

	var wg sync.WaitGroup
	opIDs := make([]string, 2)
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			op, e := h.Create(callerCtx, newReq())
			errs[i] = e
			if e == nil {
				opIDs[i] = op.GetId()
			}
		}(i)
	}
	wg.Wait()

	okCount, alreadyExists := 0, 0
	for i := 0; i < 2; i++ {
		require.NoError(t, errs[i], "Execute enqueues the Operation (async contract)")
		done := awaitOp(t, ctx, opsRepo, opIDs[i])
		if done.Error == nil {
			okCount++
		} else if done.Error.Code == int32(codes.AlreadyExists) {
			alreadyExists++
		}
	}
	assert.Equal(t, 1, okCount, "exactly one concurrent Create wins (strict-create unchanged)")
	assert.Equal(t, 1, alreadyExists, "the other surfaces AlreadyExists")
	assert.Equal(t, 1, bindingCount(t, ctx, repo, role, "account", string(acc)))
}
