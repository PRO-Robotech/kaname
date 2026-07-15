// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding_test

// delta_two_way_integration_test.go — END-TO-END two-way projection through the
// real Handler + use-cases + testcontainers PG16. Drives the proto
// request/response surface (the layer the projection lives in) so the
// form-normalization on INPUT and the both-forms fill on OUTPUT are exercised
// against a real binding row.
//
// Scenarios:
//   - Create with the OLD form (resource_type/resource_id/scope-enum +
//     target.resources) → Operation done; Get returns BOTH forms.
//   - Create with the NEW form (scope_ref + target_ref.by_name) → Operation
//     done; binding equivalent on read (same DB row, both forms).
//   - Get returns both scope + target representations consistently.
//   - conflicting old≠new scope in one request → sync INVALID_ARGUMENT
//     (before any Operation); binding not created.
//   - a pre-existing binding inserted directly (no canonical columns) → Get
//     returns both forms derived read-time (no backfill).
//   - byName per-object target persists + reads back identically regardless of
//     input form.
//   - two concurrent Create (one old form, one new form) for the SAME active
//     5-tuple → exactly one succeeds, the other AlreadyExists (strict-create is
//     unchanged; the input form does not affect the DB outcome).
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

// deltaHandler wires the minimal Handler needed for Create + Get round-trips in
// the two-way projection integration tests (other use-cases are nil — not exercised here).
func deltaHandler(t *testing.T, repo *kachopg.Repository, opsRepo operations.Repo) *accessbindingapp.Handler {
	t.Helper()
	create := accessbindingapp.NewCreateAccessBindingUseCase(repo, opsRepo).
		WithRelationStore(allowRelationStore{}, nil)
	get := accessbindingapp.NewGetAccessBindingUseCase(repo).
		WithRelationStore(allowRelationStore{}, nil)
	return accessbindingapp.NewHandler(create, nil, get, nil, nil, nil, nil)
}

func TestDelta_ConflictOldNewScope_InvalidArgument(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	h := deltaHandler(t, repo, opsRepo)

	owner := mustSeedUser(t, ctx, pool, "d04")
	acc := seedAccountByOwner(t, ctx, pool, "acc-d04", owner)
	prj := seedProjectInAccount(t, ctx, pool, acc, "prj-d04")
	member := mustSeedUser(t, ctx, pool, "d04m")
	role := seedAccountCustomRole(t, ctx, pool, acc, "d04_role")

	// old project scope vs new account scope (conflict) → sync INVALID_ARGUMENT.
	_, err := h.Create(asUser(ctx, owner), &iamv1.CreateAccessBindingRequest{
		SubjectType:  "user",
		SubjectId:    string(member),
		RoleId:       string(role),
		ResourceType: "project",
		ResourceId:   string(prj),
		ScopeRef:     &iamv1.ScopeRef{Tier: iamv1.AccessBinding_ACCOUNT, Id: string(acc)},
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "scope conflicts with resource_type/resource_id")

	// No binding created (the error is before any Operation).
	assert.Equal(t, 0, bindingCount(t, ctx, repo, role, "project", string(prj)))
}

func TestDelta_PreDeltaBinding_ReadsBothForms(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	h := deltaHandler(t, repo, opsRepo)

	owner := mustSeedUser(t, ctx, pool, "d06")
	acc := seedAccountByOwner(t, ctx, pool, "acc-d06", owner)
	member := mustSeedUser(t, ctx, pool, "d06m")
	role := seedAccountCustomRole(t, ctx, pool, acc, "d06_role")

	// insert a pre-existing all_in_scope account binding directly (no canonical
	// columns exist; the row is legacy-shaped). The canonical form must derive on read.
	bid := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	// `scope` (SMALLINT 1/2/3) is omitted — the migration-0005 BEFORE INSERT
	// trigger derives it from resource_type (account ⇒ 2/ACCOUNT), exactly as a
	// legacy row was written.
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.access_bindings
		    (id, subject_type, subject_id, role_id, resource_type, resource_id, status, granted_by_user_id)
		VALUES ($1,'user',$2,$3,'account',$4,'ACTIVE',$5)`,
		string(bid), string(member), string(role), string(acc), string(owner))
	require.NoError(t, err)

	pb, gerr := h.Get(asUser(ctx, owner), &iamv1.GetAccessBindingRequest{AccessBindingId: string(bid)})
	require.NoError(t, gerr)

	// legacy form.
	assert.Equal(t, "account", pb.GetResourceType())
	assert.Equal(t, string(acc), pb.GetResourceId())
	assert.Equal(t, iamv1.AccessBinding_ACCOUNT, pb.GetScope())

	// canonical form derived read-time (no backfill).
	require.NotNil(t, pb.GetScopeRef())
	assert.Equal(t, iamv1.AccessBinding_ACCOUNT, pb.GetScopeRef().GetTier())
	assert.Equal(t, string(acc), pb.GetScopeRef().GetId())
}

// concurrent old-form + new-form Create for the SAME active 5-tuple:
// strict-create (migration 0003) is unchanged — exactly one wins, the other
// surfaces AlreadyExists via Operation.error. The input form does not affect the
// DB outcome (both project to one mutation).
func TestDelta_ConcurrentOldNewForm_StrictCreateUnchanged(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	h := deltaHandler(t, repo, opsRepo)

	owner := mustSeedUser(t, ctx, pool, "d10")
	acc := seedAccountByOwner(t, ctx, pool, "acc-d10", owner)
	member := mustSeedUser(t, ctx, pool, "d10m")
	role := seedAccountCustomRole(t, ctx, pool, acc, "d10_role")
	callerCtx := asUser(ctx, owner)

	oldReq := &iamv1.CreateAccessBindingRequest{
		SubjectType: "user", SubjectId: string(member), RoleId: string(role),
		ResourceType: "account", ResourceId: string(acc),
	}
	newReq := &iamv1.CreateAccessBindingRequest{
		SubjectType: "user", SubjectId: string(member), RoleId: string(role),
		ScopeRef: &iamv1.ScopeRef{Tier: iamv1.AccessBinding_ACCOUNT, Id: string(acc)},
	}

	var wg sync.WaitGroup
	opIDs := make([]string, 2)
	reqs := []*iamv1.CreateAccessBindingRequest{oldReq, newReq}
	errs := make([]error, 2)
	for i := range reqs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			op, e := h.Create(callerCtx, reqs[i])
			errs[i] = e
			if e == nil {
				opIDs[i] = op.GetId()
			}
		}(i)
	}
	wg.Wait()

	okCount, alreadyExists := 0, 0
	for i := range reqs {
		require.NoError(t, errs[i], "Execute enqueues the Operation (async contract)")
		done := awaitOp(t, ctx, opsRepo, opIDs[i])
		if done.Error == nil {
			okCount++
		} else if done.Error.Code == int32(codes.AlreadyExists) {
			alreadyExists++
		}
	}
	assert.Equal(t, 1, okCount, "exactly one concurrent Create wins (strict-create unchanged)")
	assert.Equal(t, 1, alreadyExists, "the other surfaces AlreadyExists — form does not affect CAS outcome")
	assert.Equal(t, 1, bindingCount(t, ctx, repo, role, "account", string(acc)))
}
