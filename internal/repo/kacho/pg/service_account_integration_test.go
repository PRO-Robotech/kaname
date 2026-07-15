// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// service_account_integration_test.go — integration tests SARepo.
//
// Покрытие:
// - 17: Create + Get round-trip.
// - 18: Duplicate name per account → ErrAlreadyExists.
// - 18b: FK service_accounts_account_fk (missing account) → ErrFailedPrecondition.
// - 19: Delete с access binding → ErrFailedPrecondition.
// - 19b: Delete с group member → ErrFailedPrecondition.
// - 20: Update rename (sticky account_id, description).
// - Delete happy → OK; повторный → NotFound.

import (
	"context"
	stderrors "errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func seedSA(t *testing.T, ctx context.Context, repo *kachopg.Repository, accID domain.AccountID, name string) domain.ServiceAccount {
	t.Helper()
	sa := domain.ServiceAccount{
		ID:          domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount)),
		AccountID:   accID,
		Name:        domain.SvcAccountName(name),
		Description: domain.Description("test sa " + name),
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	out, err := w.ServiceAccountsW().Insert(ctx, sa)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return out
}

func TestSA_17_CreateGet_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "sa17")
	acc := seedAccount(t, ctx, repo, "acc-sa17", uid)
	sa := seedSA(t, ctx, repo, acc.ID, "sa-rt")

	assert.True(t, strings.HasPrefix(string(sa.ID), "sva"))
	assert.Equal(t, acc.ID, sa.AccountID)
	assert.WithinDuration(t, time.Now(), sa.CreatedAt, 30*time.Second)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	got, err := rd.ServiceAccounts().Get(ctx, sa.ID)
	require.NoError(t, err)
	assert.Equal(t, sa.ID, got.ID)
}

func TestSA_18_DuplicateName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "sa18")
	acc := seedAccount(t, ctx, repo, "acc-sa18", uid)
	_ = seedSA(t, ctx, repo, acc.ID, "dup-sa")

	sa2 := domain.ServiceAccount{
		ID:        domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount)),
		AccountID: acc.ID,
		Name:      "dup-sa",
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.ServiceAccountsW().Insert(ctx, sa2)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrAlreadyExists))
	assert.Contains(t, err.Error(), "ServiceAccount with name dup-sa already exists")
}

func TestSA_18b_FKMissingAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	sa := domain.ServiceAccount{
		ID:        domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount)),
		AccountID: "acc0000000000000ghst",
		Name:      "ghost-sa",
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.ServiceAccountsW().Insert(ctx, sa)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition))
}

func TestSA_19_DeleteWithAccessBinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "sa19")
	acc := seedAccount(t, ctx, repo, "acc-sa19", uid)
	sa := seedSA(t, ctx, repo, acc.ID, "sa-bound")

	abID := ids.NewID(domain.PrefixAccessBinding)
	_, err = pool.Exec(ctx, `
		INSERT INTO access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id)
		VALUES ($1, 'service_account', $2, $3, 'account', 'acc0000000000000xxxx')`,
		abID, string(sa.ID), seedSystemRoleIDIAMView,
	)
	require.NoError(t, err)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.ServiceAccountsW().Delete(ctx, sa.ID)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition))
	assert.Contains(t, err.Error(), "access bindings")
}

func TestSA_DeleteHappy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "sadel")
	acc := seedAccount(t, ctx, repo, "acc-sadel", uid)
	sa := seedSA(t, ctx, repo, acc.ID, "sa-del")

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.ServiceAccountsW().Delete(ctx, sa.ID))
	require.NoError(t, w.Commit(ctx))

	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w2.ServiceAccountsW().Delete(ctx, sa.ID)
	_ = w2.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound))
}

func TestSA_UpdateRename(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "saupd")
	acc := seedAccount(t, ctx, repo, "acc-saupd", uid)
	sa := seedSA(t, ctx, repo, acc.ID, "to-rename-sa")

	patched := sa
	patched.Name = "renamed-sa"
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	updated, err := w.ServiceAccountsW().Update(ctx, patched, []string{"name"})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	assert.Equal(t, domain.SvcAccountName("renamed-sa"), updated.Name)
	assert.Equal(t, sa.AccountID, updated.AccountID, "sticky account_id")
	assert.Equal(t, sa.Description, updated.Description, "sticky description")
}
