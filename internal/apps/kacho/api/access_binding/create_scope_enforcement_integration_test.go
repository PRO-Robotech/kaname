// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding_test

// create_scope_enforcement_integration_test.go — use-case integration tests
// (testcontainers PG16) for scope-enforcement on AccessBinding.Create plus the
// forward-only guarantee.
//
// Create is async: the contractual error surface for a mis-scoped role is
// Operation.error (code FAILED_PRECONDITION), NOT a sync error (mutations are
// async, ban #9). A sync pre-check optimisation is allowed but the contract is
// asserted on Operation.error here.
//
// Scenarios:
//   - list⇔create parity (assignable accepted; foreign account-role rejected
//     via Operation.error FAILED_PRECONDITION; binding not created).
//   - concurrent mis-scoped Create → BOTH FAILED_PRECONDITION, none written.
//   - account-role on cluster → FAILED_PRECONDITION (cluster ⇒ system only).
//   - a pre-existing mis-scoped binding (inserted directly) → ListByScope /
//     ListSubjectPrivileges still show it; Delete revokes it OK
//     (enforcement gates ONLY new Create).

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	accessbindingapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func bindingCount(t *testing.T, ctx context.Context, repo *kachopg.Repository, roleID domain.RoleID, resourceType, resourceID string) int {
	t.Helper()
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	rows, _, err := rd.AccessBindings().ListByScope(ctx, domain.ResourceType(resourceType), resourceID, repoab.PageFilter{PageSize: 1000})
	require.NoError(t, err)
	n := 0
	for _, b := range rows {
		if b.RoleID == roleID {
			n++
		}
	}
	return n
}

func TestCreate_ScopeEnforcement_ListCreateParity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	create := accessbindingapp.NewCreateAccessBindingUseCase(repo, opsRepo).
		WithRelationStore(allowRelationStore{}, nil)

	ownerA := mustSeedUser(t, ctx, pool, "ce12a")
	accA := seedAccountByOwner(t, ctx, pool, "acc-ce12a", ownerA)
	ownerB := mustSeedUser(t, ctx, pool, "ce12b")
	accB := seedAccountByOwner(t, ctx, pool, "acc-ce12b", ownerB)
	member := mustSeedUser(t, ctx, pool, "ce12m")

	accustom := seedAccountCustomRole(t, ctx, pool, accA, "ce12_own")
	bcustom := seedAccountCustomRole(t, ctx, pool, accB, "ce12_foreign")

	callerCtx := asUser(ctx, ownerA)

	// assignable role → Create succeeds (Operation done, no error) (1.5-12).
	opOK, err := create.Execute(callerCtx, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: accustom, ResourceType: "account", ResourceID: string(accA),
		Scope: domain.ScopeAccount,
	})
	require.NoError(t, err)
	doneOK := awaitOp(t, ctx, opsRepo, opOK.ID)
	require.Nil(t, doneOK.Error, "assignable role → Operation has no error (1.5-13 happy)")
	assert.Equal(t, 1, bindingCount(t, ctx, repo, accustom, "account", string(accA)))

	// foreign account-role (NOT assignable) → Operation.error FAILED_PRECONDITION.
	opBad, err := create.Execute(callerCtx, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: bcustom, ResourceType: "account", ResourceID: string(accA),
		Scope: domain.ScopeAccount,
	})
	require.NoError(t, err, "Execute still enqueues the Operation (async contract)")
	doneBad := awaitOp(t, ctx, opsRepo, opBad.ID)
	require.NotNil(t, doneBad.Error, "mis-scoped role → Operation.error (1.5-12)")
	assert.Equal(t, int32(codes.FailedPrecondition), doneBad.Error.Code,
		"mis-scoped → FAILED_PRECONDITION via Operation.error (Q#3, ban#9)")
	assert.Contains(t, doneBad.Error.Message, string(bcustom))
	assert.Contains(t, doneBad.Error.Message, "not assignable")
	assert.Equal(t, 0, bindingCount(t, ctx, repo, bcustom, "account", string(accA)),
		"no binding written for mis-scoped role")
}

func TestCreate_ScopeEnforcement_ConcurrentMisScoped_BothRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	create := accessbindingapp.NewCreateAccessBindingUseCase(repo, opsRepo).
		WithRelationStore(allowRelationStore{}, nil)

	ownerA := mustSeedUser(t, ctx, pool, "ce12ba")
	accA := seedAccountByOwner(t, ctx, pool, "acc-ce12ba", ownerA)
	ownerB := mustSeedUser(t, ctx, pool, "ce12bb")
	accB := seedAccountByOwner(t, ctx, pool, "acc-ce12bb", ownerB)
	m1 := mustSeedUser(t, ctx, pool, "ce12bm1")
	m2 := mustSeedUser(t, ctx, pool, "ce12bm2")

	bcustom := seedAccountCustomRole(t, ctx, pool, accB, "ce12b_foreign")
	callerCtx := asUser(ctx, ownerA)

	subjects := []domain.UserID{m1, m2}
	ops := make([]*operations.Operation, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	for i := range subjects {
		go func() {
			defer wg.Done()
			op, err := create.Execute(callerCtx, domain.AccessBinding{
				SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(subjects[i]),
				RoleID: bcustom, ResourceType: "account", ResourceID: string(accA),
				Scope: domain.ScopeAccount,
			})
			require.NoError(t, err)
			ops[i] = op
		}()
	}
	wg.Wait()

	for i := range ops {
		done := awaitOp(t, ctx, opsRepo, ops[i].ID)
		require.NotNil(t, done.Error, "concurrent mis-scoped Create #%d must fail (1.5-12b)", i)
		assert.Equal(t, int32(codes.FailedPrecondition), done.Error.Code,
			"both concurrent mis-scoped → FAILED_PRECONDITION (no TOCTOU window)")
	}
	assert.Equal(t, 0, bindingCount(t, ctx, repo, bcustom, "account", string(accA)),
		"NO binding written for mis-scoped role under concurrency (1.5-12b)")
}

func TestCreate_ScopeEnforcement_AccountRoleOnCluster_FailedPrecondition(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	create := accessbindingapp.NewCreateAccessBindingUseCase(repo, opsRepo).
		WithRelationStore(allowRelationStore{}, nil)

	admin := mustSeedUser(t, ctx, pool, "ce13")
	acc := seedAccountByOwner(t, ctx, pool, "acc-ce13", admin)
	member := mustSeedUser(t, ctx, pool, "ce13m")
	accustom := seedAccountCustomRole(t, ctx, pool, acc, "ce13_acc")

	op, err := create.Execute(asUser(ctx, admin), domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: accustom, ResourceType: "cluster", ResourceID: domain.ClusterSingletonID,
		Scope: domain.ScopeCluster,
	})
	require.NoError(t, err)
	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.NotNil(t, done.Error, "account-role on cluster → Operation.error (1.5-13)")
	assert.Equal(t, int32(codes.FailedPrecondition), done.Error.Code)
	assert.Contains(t, done.Error.Message, "not assignable")
	assert.Equal(t, 0, bindingCount(t, ctx, repo, accustom, "cluster", domain.ClusterSingletonID))
}

// TestCreate_RoleMissing_FailedPrecondition — a non-existent roleId on Create
// must surface Operation.error FAILED_PRECONDITION (the FK access_bindings_role_fk
// RESTRICT contract: 23503 → FailedPrecondition), NOT NotFound. Guards against a
// regression: the early role-read added for scope-enforcement
// (doCreate reads the role BEFORE the INSERT) can surface the role's raw ErrNotFound
// (code 5) and thereby change the missing-role error code from 9
// to 5. The contract (and the black-box newman case
// IAM-ACB-CR-NEG-ROLE-MISSING) require FAILED_PRECONDITION.
func TestCreate_RoleMissing_FailedPrecondition(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	create := accessbindingapp.NewCreateAccessBindingUseCase(repo, opsRepo).
		WithRelationStore(allowRelationStore{}, nil)

	admin := mustSeedUser(t, ctx, pool, "cerm")
	acc := seedAccountByOwner(t, ctx, pool, "acc-cerm", admin)
	member := mustSeedUser(t, ctx, pool, "cermm")

	op, err := create.Execute(asUser(ctx, admin), domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: domain.RoleID("rol00000000000notfnd"), ResourceType: "account", ResourceID: string(acc),
		Scope: domain.ScopeAccount,
	})
	require.NoError(t, err, "Execute still enqueues the Operation (async contract)")
	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.NotNil(t, done.Error, "non-existent role → Operation.error")
	assert.Equal(t, int32(codes.FailedPrecondition), done.Error.Code,
		"missing role → FAILED_PRECONDITION (FK RESTRICT contract), not NotFound")
	assert.Contains(t, done.Error.Message, "not found")
	assert.Equal(t, 0, bindingCount(t, ctx, repo, domain.RoleID("rol00000000000notfnd"), "account", string(acc)))
}

// TestCreate_ForwardOnly_LegacyMisScopedSurvives — 1.5-21: a pre-1.5 mis-scoped
// binding (inserted directly, bypassing the new enforcement) is still readable
// via ListByResource AND revocable via Delete. Enforcement gates ONLY new Create.
func TestCreate_ForwardOnly_LegacyMisScopedSurvives(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	del := accessbindingapp.NewDeleteAccessBindingUseCase(repo, opsRepo).
		WithRelationStore(allowRelationStore{}, nil)

	ownerA := mustSeedUser(t, ctx, pool, "ce21a")
	accA := seedAccountByOwner(t, ctx, pool, "acc-ce21a", ownerA)
	ownerB := mustSeedUser(t, ctx, pool, "ce21b")
	accB := seedAccountByOwner(t, ctx, pool, "acc-ce21b", ownerB)
	member := mustSeedUser(t, ctx, pool, "ce21m")

	bcustom := seedAccountCustomRole(t, ctx, pool, accB, "ce21_foreign") // mis-scoped on accA

	// Insert the LEGACY mis-scoped binding directly (the pre-1.5 permissive path).
	legacyID := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.access_bindings
		    (id, subject_type, subject_id, role_id, resource_type, resource_id, status, granted_by_user_id)
		VALUES ($1, 'user', $2, $3, 'account', $4, 'ACTIVE', $5)`,
		string(legacyID), string(member), string(bcustom), string(accA), string(ownerA))
	require.NoError(t, err, "seed pre-1.5 mis-scoped binding directly")

	// (a) read-time: ListByScope still shows the legacy binding.
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	rows, _, err := rd.AccessBindings().ListByScope(ctx, "account", string(accA), repoab.PageFilter{PageSize: 1000})
	require.NoError(t, err)
	_ = rd.Rollback(ctx)
	found := false
	for _, b := range rows {
		if b.ID == legacyID {
			found = true
		}
	}
	assert.True(t, found, "legacy mis-scoped binding still listed (1.5-21 a — no read-time hiding)")

	// (d) Delete revokes it OK (not gated by enforcement).
	op, err := del.Execute(asUser(ctx, ownerA), legacyID)
	require.NoError(t, err)
	done := awaitOp(t, ctx, opsRepo, op.ID)
	assert.Nil(t, done.Error, "legacy mis-scoped binding revocable via Delete (1.5-21 d, forward-only)")
}
