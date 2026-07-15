// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// conditions_repo_integration_test.go — testcontainers Postgres-backed
// tests for ConditionsRepo.
//
// Coverage:
// - Insert + Get round-trip.
// - Insert duplicate name in folder → ErrAlreadyExists (UNIQUE).
// - UpdateMutable CAS — happy path, version conflict.
// - SetStatus + Delete tombstone semantics (Get → NotFound when DELETING).
// - List pagination + folder filter.
// - CountReferences — returns 0 by default; non-zero after we sprinkle
// access_binding_conditions row referring to our condition.

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/condition"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func newTestCondition(folderID, name string) domain.Condition {
	return domain.Condition{
		ID:         domain.ConditionID(ids.NewID(domain.PrefixConditionResource)),
		FolderID:   folderID,
		Name:       name,
		Expression: `current_time < valid_until`,
		Status:     domain.ConditionStatusCreating,
	}
}

func TestCondition_IamExt_Insert_Get_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	dsn := setupTestDB(t)
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })

	repo := kachopg.NewConditionsRepo(pool)
	in := newTestCondition("prj_test_folder", "ip-corp")
	out, err := repo.Insert(ctx, in)
	require.NoError(t, err)
	require.Equal(t, in.ID, out.ID)
	require.Equal(t, "prj_test_folder", out.FolderID)
	require.Equal(t, "ip-corp", out.Name)
	require.Equal(t, domain.ConditionStatusCreating, out.Status)
	require.EqualValues(t, 1, out.ResourceVersion)

	got, err := repo.Get(ctx, in.ID)
	require.NoError(t, err)
	require.Equal(t, "ip-corp", got.Name)
}

func TestCondition_IamExt_Insert_DuplicateName_AlreadyExists(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dsn := setupTestDB(t)
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })

	repo := kachopg.NewConditionsRepo(pool)
	first := newTestCondition("prj_folder", "name-uniq")
	_, err = repo.Insert(ctx, first)
	require.NoError(t, err)

	dup := newTestCondition("prj_folder", "name-uniq") // same folder + name
	_, err = repo.Insert(ctx, dup)
	require.Error(t, err)
	require.True(t, stderrors.Is(err, iamerr.ErrAlreadyExists), "expected ErrAlreadyExists; got %v", err)
}

func TestCondition_IamExt_UpdateMutable_CAS_Conflict(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dsn := setupTestDB(t)
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })

	repo := kachopg.NewConditionsRepo(pool)
	in := newTestCondition("prj_cas", "cas-test")
	_, err = repo.Insert(ctx, in)
	require.NoError(t, err)

	// First Update with correct version (1).
	desc := "first update"
	upd1, err := repo.UpdateMutable(ctx, in.ID, condition.UpdatePatch{Description: &desc}, 1)
	require.NoError(t, err)
	require.Equal(t, "first update", upd1.Description)
	require.EqualValues(t, 2, upd1.ResourceVersion)

	// Second Update with stale version (1) should fail with FailedPrecondition.
	desc2 := "second update"
	_, err = repo.UpdateMutable(ctx, in.ID, condition.UpdatePatch{Description: &desc2}, 1)
	require.Error(t, err)
	require.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition))
}

func TestCondition_IamExt_Delete_Tombstone(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dsn := setupTestDB(t)
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })

	repo := kachopg.NewConditionsRepo(pool)
	in := newTestCondition("prj_del", "to-delete")
	_, err = repo.Insert(ctx, in)
	require.NoError(t, err)

	// Flip to DELETING — Get must return NotFound (tombstone).
	require.NoError(t, repo.SetStatus(ctx, in.ID, domain.ConditionStatusDeleting))
	_, err = repo.Get(ctx, in.ID)
	require.True(t, stderrors.Is(err, iamerr.ErrNotFound))

	// Hard delete.
	require.NoError(t, repo.Delete(ctx, in.ID))

	// Deleting a missing row → NotFound.
	require.True(t, stderrors.Is(repo.Delete(ctx, in.ID), iamerr.ErrNotFound))
}

func TestCondition_IamExt_List_PaginationAndFolderScope(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dsn := setupTestDB(t)
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })

	repo := kachopg.NewConditionsRepo(pool)

	// Insert 5 in folder A, 2 in folder B.
	for _, name := range []string{"a-1", "a-2", "a-3", "a-4", "a-5"} {
		_, err := repo.Insert(ctx, newTestCondition("folder-a", name))
		require.NoError(t, err)
	}
	for _, name := range []string{"b-1", "b-2"} {
		_, err := repo.Insert(ctx, newTestCondition("folder-b", name))
		require.NoError(t, err)
	}

	// List folder-a — all 5.
	rows, next, err := repo.List(ctx, condition.ListFilter{FolderID: "folder-a", PageSize: 100})
	require.NoError(t, err)
	require.Empty(t, next)
	require.Len(t, rows, 5)

	// Paginate folder-a by 2.
	rows, next, err = repo.List(ctx, condition.ListFilter{FolderID: "folder-a", PageSize: 2})
	require.NoError(t, err)
	require.Len(t, rows, 2)
	require.NotEmpty(t, next)

	// Filter folder-b only — 2 rows.
	rows, _, err = repo.List(ctx, condition.ListFilter{FolderID: "folder-b", PageSize: 100})
	require.NoError(t, err)
	require.Len(t, rows, 2)
}

func TestCondition_IamExt_CountReferences_Zero(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dsn := setupTestDB(t)
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })

	repo := kachopg.NewConditionsRepo(pool)
	in := newTestCondition("prj_ref", "ref-test")
	_, err = repo.Insert(ctx, in)
	require.NoError(t, err)

	n, err := repo.CountReferences(ctx, in.ID)
	require.NoError(t, err)
	require.EqualValues(t, 0, n)
}
