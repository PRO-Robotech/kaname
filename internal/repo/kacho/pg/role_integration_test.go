// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// role_integration_test.go — integration tests RoleRepo.
//
// Покрытие:
// - 26: Insert custom role → Get round-trip.
// - 27: Duplicate name per account → ErrAlreadyExists.
// - 28: List system-roles (seeded по миграции) — должно быть >= 12.
// - 29: List custom-роли per account.
// - 30a: Delete custom без bindings → OK.
// - 30b: Delete custom с bindings → FailedPrecondition.
// - 30c: Delete system-role → FailedPrecondition "System role".
// - 30d: Delete несущ. → NotFound.
// - Update rename custom (sticky permissions/is_system).

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	reporole "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
)

func seedCustomRole(t *testing.T, ctx context.Context, repo *kachopg.Repository, accID domain.AccountID, name string) domain.Role {
	t.Helper()
	r := domain.Role{
		ID:          domain.RoleID(ids.NewID(domain.PrefixRole)),
		AccountID:   accID,
		Name:        domain.RoleName(name),
		Description: domain.Description("test role " + name),
		Permissions: domain.Permissions{"iam.users.*.read"},
		IsSystem:    false,
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	out, err := w.RolesW().Insert(ctx, r)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return out
}

func TestRole_26_CreateGet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "r26")
	acc := seedAccount(t, ctx, repo, "acc-r26", uid)
	r := seedCustomRole(t, ctx, repo, acc.ID, "custom_read")

	assert.False(t, r.IsSystem)
	assert.Equal(t, acc.ID, r.AccountID)
	assert.WithinDuration(t, time.Now(), r.CreatedAt, 30*time.Second)
	assert.Equal(t, domain.Permissions{"iam.users.*.read"}, r.Permissions)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	got, err := rd.Roles().Get(ctx, r.ID)
	require.NoError(t, err)
	assert.Equal(t, r.ID, got.ID)
}

func TestRole_27_DuplicateName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "r27")
	acc := seedAccount(t, ctx, repo, "acc-r27", uid)
	_ = seedCustomRole(t, ctx, repo, acc.ID, "dup_role")

	r2 := domain.Role{
		ID:          domain.RoleID(ids.NewID(domain.PrefixRole)),
		AccountID:   acc.ID,
		Name:        "dup_role",
		Permissions: domain.Permissions{"iam.users.*.read"},
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.RolesW().Insert(ctx, r2)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrAlreadyExists))
}

func TestRole_28_ListSystemRoles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	isSystem := true
	rows, _, err := rd.Roles().List(ctx, reporole.ListFilter{
		IsSystem: &isSystem,
		PageSize: 100,
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(rows), 12, "12 default system roles seeded by migration")
	for _, r := range rows {
		assert.True(t, r.IsSystem)
		assert.Empty(t, r.AccountID, "system roles have NULL account_id")
	}
}

func TestRole_30a_DeleteCustom_Happy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "r30a")
	acc := seedAccount(t, ctx, repo, "acc-r30a", uid)
	r := seedCustomRole(t, ctx, repo, acc.ID, "to_delete")

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.RolesW().Delete(ctx, r.ID))
	require.NoError(t, w.Commit(ctx))
}

func TestRole_30b_DeleteCustom_WithBindings(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "r30b")
	acc := seedAccount(t, ctx, repo, "acc-r30b", uid)
	r := seedCustomRole(t, ctx, repo, acc.ID, "bound_role")

	abID := ids.NewID(domain.PrefixAccessBinding)
	_, err = pool.Exec(ctx, `
		INSERT INTO access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id)
		VALUES ($1, 'user', $2, $3, 'account', $4)`,
		abID, string(uid), string(r.ID), string(acc.ID),
	)
	require.NoError(t, err)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.RolesW().Delete(ctx, r.ID)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition))
	assert.Contains(t, err.Error(), "access bindings")
}

func TestRole_30c_DeleteSystem(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.RolesW().Delete(ctx, seedSystemRoleIDIAMView) // iam.viewer seed
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition))
	assert.Contains(t, err.Error(), "System role")
}

func TestRole_30d_DeleteNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.RolesW().Delete(ctx, "rol0000000000000ghst")
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound))
}

func TestRole_UpdateRename(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "rupd")
	acc := seedAccount(t, ctx, repo, "acc-rupd", uid)
	r := seedCustomRole(t, ctx, repo, acc.ID, "to_rename")

	patched := r
	patched.Name = "renamed_role"
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	updated, err := w.RolesW().Update(ctx, patched, []string{"name"})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	assert.Equal(t, domain.RoleName("renamed_role"), updated.Name)
	assert.Equal(t, r.AccountID, updated.AccountID, "sticky account_id")
	assert.Equal(t, r.Permissions, updated.Permissions, "sticky permissions")
	assert.False(t, updated.IsSystem)
}
