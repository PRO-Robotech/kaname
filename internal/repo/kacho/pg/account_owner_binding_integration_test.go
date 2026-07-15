// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// account_owner_binding_integration_test.go — integration-тест для RBAC
// explicit-model 2026: Account.Create co-commit owner AccessBinding.
//
// Dual-write co-commit: Account INSERT + owner-binding
// row + emitted-tuple ledger + fga_outbox tuple — в ОДНОЙ writer-tx. owner-binding:
//   subject = creator user, role = owner, scope = ACCOUNT:<newId>,
//   deletion_protection = true, status = ACTIVE.
//
// Здесь проверяется репо-уровневая атомарность через прямой writer-tx helper,
// который имитирует то, что делает account.CreateAccountUseCase.doCreate:
// Insert account + Insert owner-binding (dp=true) + InsertEmittedTuples в ОДНОЙ tx,
// затем commit. Падение любого шага → ни account, ни binding (rollback).
//
// Use-case-уровневый co-commit (через CreateAccountUseCase.Execute) —
// в internal/apps/kacho/api/account/create_test.go
// (TestCreate_SECL_EmitsOwnerAndClusterTupleInTx).

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

// TestAccountOwnerBinding_P6_CoCommit_Atomic — the owner-binding row co-commits
// with the account INSERT in one writer-tx (ВЗ-3). After commit both exist; the
// owner-binding carries deletion_protection=true, role=owner, ACCOUNT scope.
func TestAccountOwnerBinding_P6_CoCommit_Atomic(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "p6-owner-cc")
	acc := newAccount("acc-p6-owner-cc", uid)

	bindingID := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	insertedAcc, err := w.AccountsW().Insert(ctx, acc)
	require.NoError(t, err)
	ownerBinding := domain.AccessBinding{
		ID:                 bindingID,
		SubjectType:        domain.SubjectTypeUser,
		SubjectID:          domain.SubjectID(uid),
		RoleID:             domain.OwnerRoleID,
		ResourceType:       "account",
		ResourceID:         string(insertedAcc.ID),
		Scope:              domain.ScopeAccount,
		DeletionProtection: true,
	}
	createdBinding, err := w.AccessBindingsW().Insert(ctx, ownerBinding)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	assert.True(t, createdBinding.DeletionProtection)
	assert.Equal(t, domain.OwnerRoleID, string(createdBinding.RoleID))

	// Both visible after commit.
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	gotAcc, err := rd.Accounts().Get(ctx, insertedAcc.ID)
	require.NoError(t, err)
	assert.Equal(t, uid, gotAcc.OwnerUserID)
	gotBinding, err := rd.AccessBindings().Get(ctx, bindingID)
	require.NoError(t, err)
	assert.True(t, gotBinding.DeletionProtection, "owner-binding deletion_protection=true (D-8/D-10)")
	assert.Equal(t, domain.SubjectID(uid), gotBinding.SubjectID)
}

// TestAccountOwnerBinding_P6_RollbackOnBindingFailure — co-commit atomicity: if
// the owner-binding INSERT fails (FK role missing), the account INSERT in the same
// tx is rolled back too (neither persists). Uses a non-existent role id to trip FK.
func TestAccountOwnerBinding_P6_RollbackOnBindingFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "p6-owner-rb")
	acc := newAccount("acc-p6-owner-rb", uid)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	insertedAcc, err := w.AccountsW().Insert(ctx, acc)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID:          domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol_does_not_exist01", ResourceType: "account", ResourceID: string(insertedAcc.ID),
		Scope: domain.ScopeAccount, DeletionProtection: true,
	})
	require.Error(t, err, "owner-binding INSERT with missing role FK must fail")
	_ = w.Rollback(ctx)

	// Account must NOT persist (rolled back with the binding failure).
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	_, gerr := rd.Accounts().Get(ctx, insertedAcc.ID)
	require.Error(t, gerr, "account must be rolled back when owner-binding co-commit fails (ВЗ-3)")
}
