// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// access_binding_subjects_integration_test.go — RBAC rules-model multi-subject
// support. testcontainers Postgres 16 integration tests for
// the multi-subject child table (kacho_iam.access_binding_subjects, migration
// 0028) + the ListByRole audit read.
//
//   - -ROUNDTRIP: InsertSubjects co-committed with the binding INSERT +
//     ListSubjects reads back the exact ordered set.
//   - -CASCADE: deleting the binding row CASCADE-drops its subject rows
//     (FK ON DELETE CASCADE) — no orphan subject rows after revoke.
//   - -UNIQUE: a duplicate (binding,subject) is an idempotent no-op (ON CONFLICT
//     DO NOTHING); the set never inflates.
//   - -PERSUBJECT: DeleteSubject removes ONE subject's row and leaves the
//     others untouched (independent revoke).
//   - -BATCH: ListSubjectsForBindings loads many bindings' subjects in one query.
//   - -LISTBYROLE: ListByRole returns the bindings of a role, keyset-paged,
//     hiding REVOKED unless IncludeRevoked.
//   - -RACE (ban #10): concurrent InsertSubjects of the SAME (binding,subject)
//     converge to exactly one row (PK row-lock idempotency, not software guard).

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho-corelib/db"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

func countABSubjects(t *testing.T, ctx context.Context, repo *kachopg.Repository, bindingID domain.AccessBindingID) int {
	t.Helper()
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	subs, err := rd.AccessBindings().ListSubjects(ctx, bindingID)
	require.NoError(t, err)
	return len(subs)
}

func insertSubjects(t *testing.T, ctx context.Context, repo *kachopg.Repository, id domain.AccessBindingID, subs []domain.Subject) {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	if err := w.AccessBindingsW().InsertSubjects(ctx, id, subs); err != nil {
		_ = w.Rollback(ctx)
		require.NoError(t, err)
	}
	require.NoError(t, w.Commit(ctx))
}

func TestABSubjects_E34_RoundTripOrdered(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "absubrt")
	acc := seedAccount(t, ctx, repo, "acc-absubrt", uid)
	ab := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol000000000sysviewer", ResourceType: "account", ResourceID: string(acc.ID),
	})

	subs := []domain.Subject{
		{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)},
		{Type: domain.SubjectTypeGroup, ID: "grp_absubrt"},
		{Type: domain.SubjectTypeServiceAccount, ID: "sva_absubrt"},
	}
	insertSubjects(t, ctx, repo, ab.ID, subs)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	got, err := rd.AccessBindings().ListSubjects(ctx, ab.ID)
	require.NoError(t, err)
	require.Len(t, got, 3)
	// Ordinal preserves insert order → subjects[0] is the user.
	assert.Equal(t, domain.SubjectTypeUser, got[0].Type)
	assert.Equal(t, domain.SubjectID(uid), got[0].ID)
	assert.Equal(t, domain.SubjectTypeGroup, got[1].Type)
	assert.Equal(t, domain.SubjectTypeServiceAccount, got[2].Type)
}

func TestABSubjects_E30_CascadeOnBindingDelete(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "absubcas")
	acc := seedAccount(t, ctx, repo, "acc-absubcas", uid)
	ab := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol000000000sysviewer", ResourceType: "account", ResourceID: string(acc.ID),
	})
	insertSubjects(t, ctx, repo, ab.ID, []domain.Subject{
		{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)},
		{Type: domain.SubjectTypeGroup, ID: "grp_absubcas"},
	})
	require.Equal(t, 2, countABSubjects(t, ctx, repo, ab.ID))

	// HARD delete the binding row → CASCADE drops subject rows.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().Delete(ctx, ab.ID))
	require.NoError(t, w.Commit(ctx))

	assert.Equal(t, 0, countABSubjects(t, ctx, repo, ab.ID), "subject rows must CASCADE-drop with the binding")
}

func TestABSubjects_PerSubjectDelete_Independent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "absubdel")
	acc := seedAccount(t, ctx, repo, "acc-absubdel", uid)
	ab := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol000000000sysviewer", ResourceType: "account", ResourceID: string(acc.ID),
	})
	insertSubjects(t, ctx, repo, ab.ID, []domain.Subject{
		{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)},
		{Type: domain.SubjectTypeGroup, ID: "grp_absubdel"},
	})

	// Remove ONLY the group subject; the user subject survives.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	deleted, err := w.AccessBindingsW().DeleteSubject(ctx, ab.ID, domain.Subject{Type: domain.SubjectTypeGroup, ID: "grp_absubdel"})
	require.NoError(t, err)
	require.True(t, deleted)
	require.NoError(t, w.Commit(ctx))

	got := func() []domain.Subject {
		rd, err := repo.Reader(ctx)
		require.NoError(t, err)
		defer func() { _ = rd.Rollback(ctx) }()
		s, err := rd.AccessBindings().ListSubjects(ctx, ab.ID)
		require.NoError(t, err)
		return s
	}()
	require.Len(t, got, 1)
	assert.Equal(t, domain.SubjectTypeUser, got[0].Type)

	// Idempotent: deleting an absent subject returns false.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	d2, err := w2.AccessBindingsW().DeleteSubject(ctx, ab.ID, domain.Subject{Type: domain.SubjectTypeGroup, ID: "grp_absubdel"})
	require.NoError(t, err)
	assert.False(t, d2)
	require.NoError(t, w2.Commit(ctx))
}

func TestABSubjects_Batch_ListForBindings(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "absubbat")
	acc := seedAccount(t, ctx, repo, "acc-absubbat", uid)
	ab1 := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol000000000sysviewer", ResourceType: "account", ResourceID: string(acc.ID),
	})
	ab2 := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol000000000sysadmin", ResourceType: "account", ResourceID: string(acc.ID),
	})
	insertSubjects(t, ctx, repo, ab1.ID, []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}, {Type: domain.SubjectTypeGroup, ID: "grp_a"}})
	insertSubjects(t, ctx, repo, ab2.ID, []domain.Subject{{Type: domain.SubjectTypeServiceAccount, ID: "sva_b"}})

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	m, err := rd.AccessBindings().ListSubjectsForBindings(ctx, []domain.AccessBindingID{ab1.ID, ab2.ID})
	require.NoError(t, err)
	require.Len(t, m[ab1.ID], 2)
	require.Len(t, m[ab2.ID], 1)
	assert.Equal(t, domain.SubjectID("sva_b"), m[ab2.ID][0].ID)
}

func TestABSubjects_E33_ListByRole(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ablbr")
	acc := seedAccount(t, ctx, repo, "acc-ablbr", uid)
	// Two ACTIVE bindings carrying the same role; one of a different role.
	insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol000000000sysviewer", ResourceType: "account", ResourceID: string(acc.ID),
	})
	insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeGroup, SubjectID: "grp_ablbr",
		RoleID: "rol000000000sysviewer", ResourceType: "account", ResourceID: string(acc.ID),
	})
	insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol000000000sysadmin", ResourceType: "account", ResourceID: string(acc.ID),
	})

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	got, _, err := rd.AccessBindings().ListByRole(ctx, "rol000000000sysviewer", repoab.ListByRoleFilter{PageSize: 50})
	require.NoError(t, err)
	require.Len(t, got, 2, "ListByRole returns exactly the bindings carrying the role")
	for _, b := range got {
		assert.Equal(t, domain.RoleID("rol000000000sysviewer"), b.RoleID)
	}
}

func TestABSubjects_RACE_ConcurrentInsertSameSubject_OneRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "absubrace")
	acc := seedAccount(t, ctx, repo, "acc-absubrace", uid)
	ab := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol000000000sysviewer", ResourceType: "account", ResourceID: string(acc.ID),
	})
	sub := domain.Subject{Type: domain.SubjectTypeGroup, ID: "grp_race"}

	const n = 8
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			w, werr := repo.Writer(ctx)
			if werr != nil {
				return
			}
			if ierr := w.AccessBindingsW().InsertSubjects(ctx, ab.ID, []domain.Subject{sub}); ierr != nil {
				_ = w.Rollback(ctx)
				return
			}
			_ = w.Commit(ctx)
		}()
	}
	wg.Wait()

	// Exactly one row for (binding, group) — PK + ON CONFLICT DO NOTHING (ban #10).
	got := func() []domain.Subject {
		rd, err := repo.Reader(ctx)
		require.NoError(t, err)
		defer func() { _ = rd.Rollback(ctx) }()
		s, err := rd.AccessBindings().ListSubjects(ctx, ab.ID)
		require.NoError(t, err)
		return s
	}()
	count := 0
	for _, s := range got {
		if s == sub {
			count++
		}
	}
	assert.Equal(t, 1, count, "concurrent identical InsertSubjects must converge to exactly one row")
}
