// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// access_binding_deletion_protection_integration_test.go — TDD integration-тесты
// для RBAC explicit-model 2026 (deletion_protection на AccessBinding).
//
// Покрытие:
//   - TestAB_P6_DeletionProtection_PersistRoundTrip — миграция 0035 добавила
//     колонку deletion_protection; Insert(true) → Get читает true (поле проброшено
//     через abCols/scanAB/Insert).
//   - TestAB_P6_DeleteGuarded_RefusesProtected — DeleteGuarded на protected binding
//     → FailedPrecondition (атомарный CAS `DELETE … WHERE deletion_protection=false`).
//   - TestAB_P6_DeleteGuarded_DeletesUnprotected — DeleteGuarded на unprotected →
//     удаляет (1 row).
//   - TestAB_P6_DeleteGuarded_NotFound — DeleteGuarded несуществующего → NotFound.
//   - TestAB_P6_DeleteGuarded_ConcurrentCAS — ≥2 goroutine конкурентно
//     DeleteGuarded на ОДНОМ unprotected binding → ровно один success, остальные
//     NotFound; ни паники, ни double-delete (concurrent-CAS чек-лист).
//   - TestAB_P6_ClearProtection_ThenDelete — SetDeletionProtection(false) →
//     DeleteGuarded проходит.
//
// Запуск: `make test` или
//   TESTCONTAINERS_RYUK_DISABLED=true go test ./internal/repo/kacho/pg/... -race

import (
	"context"
	stderrors "errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func TestAB_P6_DeletionProtection_PersistRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "p6-persist")
	acc := seedAccount(t, ctx, repo, "acc-p6-persist", uid)

	b := domain.AccessBinding{
		ID:                 domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
		SubjectType:        domain.SubjectTypeUser,
		SubjectID:          domain.SubjectID(uid),
		RoleID:             "rol000000000sysviewer",
		ResourceType:       "account",
		ResourceID:         string(acc.ID),
		DeletionProtection: true,
	}

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	out, err := w.AccessBindingsW().Insert(ctx, b)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	assert.True(t, out.DeletionProtection, "Insert must persist deletion_protection=true")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	got, err := rd.AccessBindings().Get(ctx, out.ID)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)
	assert.True(t, got.DeletionProtection, "Get must read deletion_protection=true (scanAB)")
}

func TestAB_P6_DeleteGuarded_RefusesProtected(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "p6-refuse")
	acc := seedAccount(t, ctx, repo, "acc-p6-refuse", uid)
	id := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID: id, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol000000000sysviewer", ResourceType: "account", ResourceID: string(acc.ID),
		DeletionProtection: true,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w2.AccessBindingsW().DeleteGuarded(ctx, id)
	_ = w2.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition),
		"DeleteGuarded on protected binding → FailedPrecondition, got %v", err)
}

func TestAB_P6_DeleteGuarded_DeletesUnprotected(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "p6-del")
	acc := seedAccount(t, ctx, repo, "acc-p6-del", uid)
	id := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID: id, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol000000000sysviewer", ResourceType: "account", ResourceID: string(acc.ID),
		DeletionProtection: false,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w2.AccessBindingsW().DeleteGuarded(ctx, id))
	require.NoError(t, w2.Commit(ctx))

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	_, gerr := rd.AccessBindings().Get(ctx, id)
	_ = rd.Rollback(ctx)
	assert.True(t, stderrors.Is(gerr, iamerr.ErrNotFound), "binding must be gone after DeleteGuarded")
}

func TestAB_P6_DeleteGuarded_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.AccessBindingsW().DeleteGuarded(ctx, domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)))
	_ = w.Rollback(ctx)
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound), "DeleteGuarded missing → NotFound, got %v", err)
}

// TestAB_P6_DeleteGuarded_ConcurrentCAS — concurrent-CAS инвариант:
// N goroutine конкурентно DeleteGuarded ОДИН unprotected binding → ровно один
// success, остальные NotFound (single-statement DELETE RETURNING берет row-lock;
// проигравшие видят строку уже удаленной). Ни паники, ни «успех у двоих».
func TestAB_P6_DeleteGuarded_ConcurrentCAS(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "p6-race")
	acc := seedAccount(t, ctx, repo, "acc-p6-race", uid)
	id := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID: id, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol000000000sysviewer", ResourceType: "account", ResourceID: string(acc.ID),
		DeletionProtection: false,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	const goroutines = 8
	results := make(chan error, goroutines)
	var ready sync.WaitGroup
	ready.Add(goroutines)
	startGate := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			ready.Done()
			<-startGate
			gw, werr := repo.Writer(ctx)
			if werr != nil {
				results <- werr
				return
			}
			derr := gw.AccessBindingsW().DeleteGuarded(ctx, id)
			if derr != nil {
				_ = gw.Rollback(ctx)
				results <- derr
				return
			}
			results <- gw.Commit(ctx)
		}()
	}
	ready.Wait()
	close(startGate)

	successes, notFound, other := 0, 0, 0
	for i := 0; i < goroutines; i++ {
		switch err := <-results; {
		case err == nil:
			successes++
		case stderrors.Is(err, iamerr.ErrNotFound):
			notFound++
		default:
			other++
			t.Logf("unexpected race error: %v", err)
		}
	}
	assert.Equal(t, 1, successes, "exactly one DeleteGuarded wins")
	assert.Equal(t, goroutines-1, notFound, "losers see the row already deleted → NotFound")
	assert.Equal(t, 0, other, "no unexpected errors / panics")
}

// TestAB_P6_DeleteVsRearm_ConcurrentCAS — concurrent interleave: one goroutine
// re-arms protection via SetDeletionProtection(true) while another concurrently runs
// DeleteGuarded on the same (currently unprotected) binding. The single-statement
// `DELETE … WHERE deletion_protection=false` row-lock serializes them: either Delete
// wins (binding gone, the rearm UPDATE then hits 0 rows → NotFound) OR the rearm wins
// (binding survives protected, Delete sees deletion_protection=true → FailedPrecondition).
// Never: binding deleted AND still protected; never a panic.
func TestAB_P6_DeleteVsRearm_ConcurrentCAS(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "p6-rearm")
	acc := seedAccount(t, ctx, repo, "acc-p6-rearm", uid)
	id := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID: id, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol000000000sysviewer", ResourceType: "account", ResourceID: string(acc.ID),
		DeletionProtection: false,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	var wg sync.WaitGroup
	wg.Add(2)
	startGate := make(chan struct{})
	delErrCh := make(chan error, 1)
	rearmErrCh := make(chan error, 1)

	go func() { // re-arm protection
		defer wg.Done()
		<-startGate
		gw, werr := repo.Writer(ctx)
		if werr != nil {
			rearmErrCh <- werr
			return
		}
		_, serr := gw.AccessBindingsW().SetDeletionProtection(ctx, id, true)
		if serr != nil {
			_ = gw.Rollback(ctx)
			rearmErrCh <- serr
			return
		}
		rearmErrCh <- gw.Commit(ctx)
	}()
	go func() { // guarded delete
		defer wg.Done()
		<-startGate
		gw, werr := repo.Writer(ctx)
		if werr != nil {
			delErrCh <- werr
			return
		}
		derr := gw.AccessBindingsW().DeleteGuarded(ctx, id)
		if derr != nil {
			_ = gw.Rollback(ctx)
			delErrCh <- derr
			return
		}
		delErrCh <- gw.Commit(ctx)
	}()
	close(startGate)
	wg.Wait()

	delErr := <-delErrCh
	rearmErr := <-rearmErrCh

	// Disambiguate the final state by reading the row.
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	final, gerr := rd.AccessBindings().Get(ctx, id)
	_ = rd.Rollback(ctx)

	if stderrors.Is(gerr, iamerr.ErrNotFound) {
		// Delete won: it succeeded; the rearm UPDATE hit 0 rows → NotFound.
		assert.NoError(t, delErr, "delete winner must succeed")
		assert.True(t, stderrors.Is(rearmErr, iamerr.ErrNotFound),
			"rearm on a deleted row → NotFound, got %v", rearmErr)
	} else {
		// Rearm won: the binding survives protected; Delete saw protection → FP.
		require.NoError(t, gerr)
		assert.True(t, final.DeletionProtection, "surviving binding must be protected")
		assert.NoError(t, rearmErr, "rearm winner must succeed")
		assert.True(t, stderrors.Is(delErr, iamerr.ErrFailedPrecondition),
			"delete on re-armed binding → FailedPrecondition, got %v", delErr)
	}
}

// TestAB_P6_ClearProtection_ThenDelete — clear deletion_protection via the
// repo SetDeletionProtection CAS, then DeleteGuarded succeeds.
func TestAB_P6_ClearProtection_ThenDelete(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "p6-clear")
	acc := seedAccount(t, ctx, repo, "acc-p6-clear", uid)
	id := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID: id, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol000000000sysviewer", ResourceType: "account", ResourceID: string(acc.ID),
		DeletionProtection: true,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	// Clear protection (C-03 Update path at the repo level).
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	updated, err := w2.AccessBindingsW().SetDeletionProtection(ctx, id, false)
	require.NoError(t, err)
	require.NoError(t, w2.Commit(ctx))
	assert.False(t, updated.DeletionProtection)

	// Now Delete passes.
	w3, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w3.AccessBindingsW().DeleteGuarded(ctx, id))
	require.NoError(t, w3.Commit(ctx))
}
