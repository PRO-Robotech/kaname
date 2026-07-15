// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// project_integration_test.go — TDD integration-тесты для ProjectRepo.
//
// Покрытие:
// - 09: Create + Get round-trip.
// - 10: Duplicate name per account → ErrAlreadyExists.
// - 11: FK accounts_account_fk (account_id отсутствует) → ErrFailedPrecondition.
// - 05: Get NotFound (well-formed-несущ.).
// - Update: rename (sticky account_id, description).
// - Delete: happy + повторный → NotFound.

import (
	"context"
	stderrors "errors"
	"fmt"
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
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
)

func seedProject(t *testing.T, ctx context.Context, repo *kachopg.Repository, accID domain.AccountID, name string) domain.Project {
	t.Helper()
	p := domain.Project{
		ID:          domain.ProjectID(ids.NewID(domain.PrefixProject)),
		AccountID:   accID,
		Name:        domain.ProjectName(name),
		Description: domain.Description("integration test " + name),
		Labels:      domain.Labels{},
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	out, err := w.ProjectsW().Insert(ctx, p)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return out
}

// ── 09: Create + Get round-trip ─────────────────────────────────────────────
func TestProject_09_CreateGet_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "p09")
	acc := seedAccount(t, ctx, repo, "acc-p09", uid)

	created := seedProject(t, ctx, repo, acc.ID, "prj-create-get")
	assert.True(t, strings.HasPrefix(string(created.ID), "prj"), "id prefix")
	assert.Equal(t, acc.ID, created.AccountID)
	assert.Equal(t, domain.ProjectName("prj-create-get"), created.Name)
	assert.WithinDuration(t, time.Now(), created.CreatedAt, 30*time.Second, "created_at")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	got, err := rd.Projects().Get(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)
	assert.Equal(t, created.Name, got.Name)
	assert.Equal(t, created.AccountID, got.AccountID)
}

// ── 10: Duplicate name per account → ErrAlreadyExists ──────────────────────
func TestProject_10_Create_DuplicateName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "p10")
	acc := seedAccount(t, ctx, repo, "acc-p10", uid)
	_ = seedProject(t, ctx, repo, acc.ID, "dup-name")

	p2 := domain.Project{
		ID:        domain.ProjectID(ids.NewID(domain.PrefixProject)),
		AccountID: acc.ID,
		Name:      "dup-name",
		Labels:    domain.Labels{},
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.ProjectsW().Insert(ctx, p2)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrAlreadyExists), "expected ErrAlreadyExists, got %v", err)
	assert.Contains(t, err.Error(), "Project with name dup-name already exists")
}

// ── 11: FK projects_account_fk → ErrFailedPrecondition ─────────────────────
func TestProject_11_Create_FKMissingAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	p := domain.Project{
		ID:        domain.ProjectID(ids.NewID(domain.PrefixProject)),
		AccountID: "acc00000000000000ghst", // не существует
		Name:      "ghost-acc-prj",
		Labels:    domain.Labels{},
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.ProjectsW().Insert(ctx, p)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition), "expected ErrFailedPrecondition, got %v", err)
}

// ── 05: Get NotFound ────────────────────────────────────────────────────────
func TestProject_GetNotFound(t *testing.T) {
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
	_, err = rd.Projects().Get(ctx, "prj00000000000000ghst")
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound))
	assert.Contains(t, err.Error(), "Project prj00000000000000ghst not found")
}

// ── Update: rename + sticky account_id/description ─────────────────────────
func TestProject_UpdateRename(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "pupd")
	acc := seedAccount(t, ctx, repo, "acc-pupd", uid)
	p := seedProject(t, ctx, repo, acc.ID, "to-rename")

	patched := p
	patched.Name = "renamed"
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	updated, err := w.ProjectsW().Update(ctx, patched, []string{"name"})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	assert.Equal(t, domain.ProjectName("renamed"), updated.Name)
	assert.Equal(t, p.AccountID, updated.AccountID, "sticky account_id")
	assert.Equal(t, p.Description, updated.Description, "sticky description")
}

// ── Delete: happy + повторный → NotFound ───────────────────────────────────
func TestProject_DeleteHappy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "pdel")
	acc := seedAccount(t, ctx, repo, "acc-pdel", uid)
	p := seedProject(t, ctx, repo, acc.ID, "to-delete")

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.ProjectsW().Delete(ctx, p.ID))
	require.NoError(t, w.Commit(ctx))

	// Повторный Delete → NotFound.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w2.ProjectsW().Delete(ctx, p.ID)
	_ = w2.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound))
}

// ── List by AccountID scope ────────────────────────────────────────────────
func TestProject_List_ByAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "plst")
	accA := seedAccount(t, ctx, repo, "acc-list-a", uid)
	accB := seedAccount(t, ctx, repo, "acc-list-b", uid)
	for i := 0; i < 3; i++ {
		_ = seedProject(t, ctx, repo, accA.ID, fmt.Sprintf("a-prj-%d", i))
	}
	_ = seedProject(t, ctx, repo, accB.ID, "b-prj")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	rows, _, err := rd.Projects().List(ctx, project.ListFilter{
		AccountID: accA.ID,
		PageSize:  100,
	})
	require.NoError(t, err)
	assert.Equal(t, 3, len(rows), "should be 3 projects in accA scope")
	for _, p := range rows {
		assert.Equal(t, accA.ID, p.AccountID)
	}
}
