// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// access_binding_revoke_integration_test.go — TDD integration-тесты для
// redesign-2026 F10 (AccessBinding.:revoke = soft, Delete = hard; IAM-1-28/29).
//
// Покрытие (testcontainers Postgres 16, реальные миграции + partial UNIQUE):
//   - TestAB_IAM_1_28_RevokeGuarded_SoftRevoke — ACTIVE→REVOKED CAS; row RETAINED
//     (Get всё ещё возвращает строку, НЕ NotFound), revoked_at/revoked_by set
//     (audit-retention) — контраст с Delete=hard (Get→NotFound).
//   - TestAB_IAM_1_28_RevokeGuarded_RefusesProtected — deletion_protection=true →
//     FAILED_PRECONDITION (atomic CAS `WHERE …AND deletion_protection=false`,
//     owner-binding не отзывается случайно, паритет с Delete).
//   - TestAB_IAM_1_28_RevokeGuarded_NotFound — отсутствующий binding → NotFound.
//   - TestAB_IAM_1_28_RevokeGuarded_TerminalRevoked — повторный revoke уже-REVOKED
//     → FAILED_PRECONDITION (REVOKED терминален; идемпотентность grant-lifecycle).
//   - TestAB_IAM_1_29_ReGrantAfterRevoke_Race — concurrent-race на partial-UNIQUE
//     re-grant (data-integrity §5): N goroutine Insert идентичного (subject,role,
//     scope) при ACTIVE → ровно 1 winner, остальные ALREADY_EXISTS; после :revoke
//     winner'а → новый идентичный Create проходит как НОВАЯ ACTIVE-строка (revoked
//     строка освобождает slot partial UNIQUE `WHERE revoked_at IS NULL`).
//   - TestAB_IAM_1_28_RevokeGuarded_ConcurrentCAS — N goroutine RevokeGuarded
//     ОДНОГО ACTIVE binding → ровно один success, остальные FAILED_PRECONDITION
//     (row-lock сериализует; проигравшие видят строку уже REVOKED). Под -race.
//
// Запуск: TESTCONTAINERS_RYUK_DISABLED=true go test ./internal/repo/kacho/pg/... -race

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

// insertActiveBinding is a small helper that Inserts+Commits one ACTIVE binding
// with the given id and 5-tuple, mirroring the deletion_protection harness.
func insertActiveBinding(t *testing.T, ctx context.Context, repo *kachopg.Repository,
	id domain.AccessBindingID, uid domain.UserID, accID string, protected bool) {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID: id, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol000000000sysviewer", ResourceType: "account", ResourceID: accID,
		DeletionProtection: protected,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
}

func TestAB_IAM_1_28_RevokeGuarded_SoftRevoke(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "iam1-28-soft")
	acc := seedAccount(t, ctx, repo, "acc-iam1-28-soft", uid)
	id := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	insertActiveBinding(t, ctx, repo, id, uid, string(acc.ID), false)

	// Soft-revoke.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	revoked, err := w.AccessBindingsW().RevokeGuarded(ctx, id, uid)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	assert.Equal(t, domain.AccessBindingStatusRevoked, revoked.Status,
		"RevokeGuarded returns the row transitioned to REVOKED")
	require.NotNil(t, revoked.RevokedAt, "revoked_at must be stamped")
	require.NotNil(t, revoked.RevokedByUserID, "revoked_by_user_id must be retained (audit)")
	assert.Equal(t, uid, *revoked.RevokedByUserID)

	// Row is RETAINED — Get still returns it (contrast with Delete=hard → NotFound).
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	got, gerr := rd.AccessBindings().Get(ctx, id)
	_ = rd.Rollback(ctx)
	require.NoError(t, gerr, "soft-revoke retains the row — Get must still succeed")
	assert.Equal(t, domain.AccessBindingStatusRevoked, got.Status)
	require.NotNil(t, got.RevokedAt)
}

func TestAB_IAM_1_28_RevokeGuarded_RefusesProtected(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "iam1-28-prot")
	acc := seedAccount(t, ctx, repo, "acc-iam1-28-prot", uid)
	id := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	insertActiveBinding(t, ctx, repo, id, uid, string(acc.ID), true) // protected

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().RevokeGuarded(ctx, id, uid)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition),
		"RevokeGuarded on protected binding → FailedPrecondition, got %v", err)

	// The row must survive the refused revoke (still ACTIVE).
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	got, gerr := rd.AccessBindings().Get(ctx, id)
	_ = rd.Rollback(ctx)
	require.NoError(t, gerr)
	assert.Equal(t, domain.AccessBindingStatusActive, got.Status, "protected binding stays ACTIVE")
}

func TestAB_IAM_1_28_RevokeGuarded_NotFound(t *testing.T) {
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
	_, err = w.AccessBindingsW().RevokeGuarded(ctx,
		domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)), "usr-nobody")
	_ = w.Rollback(ctx)
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound),
		"RevokeGuarded missing → NotFound, got %v", err)
}

func TestAB_IAM_1_28_RevokeGuarded_TerminalRevoked(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "iam1-28-term")
	acc := seedAccount(t, ctx, repo, "acc-iam1-28-term", uid)
	id := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	insertActiveBinding(t, ctx, repo, id, uid, string(acc.ID), false)

	// First revoke wins.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().RevokeGuarded(ctx, id, uid)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	// Second revoke of the now-REVOKED (terminal) row → FailedPrecondition.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w2.AccessBindingsW().RevokeGuarded(ctx, id, uid)
	_ = w2.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition),
		"re-revoke of REVOKED (terminal) → FailedPrecondition, got %v", err)
}

// TestAB_IAM_1_29_ReGrantAfterRevoke_Race — the emphasized concurrent-race on the
// partial active-grant UNIQUE (data-integrity §5). N goroutines concurrently Insert
// the SAME 5-tuple (distinct ids) → exactly ONE wins ACTIVE, the rest get
// ALREADY_EXISTS. After :revoke of the winner, an identical re-grant Create is a NEW
// ACTIVE row (the REVOKED row carries revoked_at, freeing the partial-UNIQUE slot).
func TestAB_IAM_1_29_ReGrantAfterRevoke_Race(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "iam1-29-race")
	acc := seedAccount(t, ctx, repo, "acc-iam1-29-race", uid)
	accID := string(acc.ID)

	// ── Phase 1: concurrent identical Create → exactly one winner ──────────
	const goroutines = 8
	type res struct {
		id  domain.AccessBindingID
		err error
	}
	out := make(chan res, goroutines)
	var ready sync.WaitGroup
	ready.Add(goroutines)
	startGate := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			id := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
			ready.Done()
			<-startGate
			gw, werr := repo.Writer(ctx)
			if werr != nil {
				out <- res{id, werr}
				return
			}
			_, ierr := gw.AccessBindingsW().Insert(ctx, domain.AccessBinding{
				ID: id, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
				RoleID: "rol000000000sysviewer", ResourceType: "account", ResourceID: accID,
			})
			if ierr != nil {
				_ = gw.Rollback(ctx)
				out <- res{id, ierr}
				return
			}
			out <- res{id, gw.Commit(ctx)}
		}()
	}
	ready.Wait()
	close(startGate)

	var winner domain.AccessBindingID
	successes, already, other := 0, 0, 0
	for i := 0; i < goroutines; i++ {
		r := <-out
		switch {
		case r.err == nil:
			successes++
			winner = r.id
		case stderrors.Is(r.err, iamerr.ErrAlreadyExists):
			already++
		default:
			other++
			t.Logf("unexpected race error: %v", r.err)
		}
	}
	require.Equal(t, 1, successes, "exactly one identical Create wins the active-grant UNIQUE")
	assert.Equal(t, goroutines-1, already, "losers get ALREADY_EXISTS (partial UNIQUE)")
	assert.Equal(t, 0, other, "no unexpected errors / panics")

	// ── Phase 2: revoke the winner ────────────────────────────────────────
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().RevokeGuarded(ctx, winner, uid)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	// ── Phase 3: identical re-grant is now a NEW ACTIVE row ───────────────
	regrantID := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	regranted, err := w2.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID: regrantID, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol000000000sysviewer", ResourceType: "account", ResourceID: accID,
	})
	require.NoError(t, err, "re-grant after revoke must succeed — revoked row frees the slot")
	require.NoError(t, w2.Commit(ctx))
	assert.NotEqual(t, winner, regranted.ID, "re-grant is a distinct new ACTIVE binding id")
	assert.Equal(t, domain.AccessBindingStatusActive, regranted.Status)
}

// TestAB_IAM_1_28_RevokeGuarded_ConcurrentCAS — N goroutines RevokeGuarded ONE
// ACTIVE binding → exactly one success, the rest FailedPrecondition (the single
// UPDATE … WHERE status='ACTIVE' row-lock serializes; losers see it already
// REVOKED). Never two winners, never a panic. Runs under -race.
func TestAB_IAM_1_28_RevokeGuarded_ConcurrentCAS(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "iam1-28-cas")
	acc := seedAccount(t, ctx, repo, "acc-iam1-28-cas", uid)
	id := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	insertActiveBinding(t, ctx, repo, id, uid, string(acc.ID), false)

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
			_, rerr := gw.AccessBindingsW().RevokeGuarded(ctx, id, uid)
			if rerr != nil {
				_ = gw.Rollback(ctx)
				results <- rerr
				return
			}
			results <- gw.Commit(ctx)
		}()
	}
	ready.Wait()
	close(startGate)

	successes, failedPre, other := 0, 0, 0
	for i := 0; i < goroutines; i++ {
		switch err := <-results; {
		case err == nil:
			successes++
		case stderrors.Is(err, iamerr.ErrFailedPrecondition):
			failedPre++
		default:
			other++
			t.Logf("unexpected race error: %v", err)
		}
	}
	assert.Equal(t, 1, successes, "exactly one RevokeGuarded wins")
	assert.Equal(t, goroutines-1, failedPre, "losers see the row already REVOKED → FailedPrecondition")
	assert.Equal(t, 0, other, "no unexpected errors / panics")
}
