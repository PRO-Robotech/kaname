// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// access_binding_integration_test.go — integration tests AccessBindingRepo
// (migration 0003 strict-create).
//
// Покрытие:
// - 31a: Insert NEW → новая row + new id.
// - 31b (migration 0003): Insert duplicate active 5-tuple → ErrAlreadyExists
//   с verbatim text «these permissions are already granted to <subject_id>
//   on <res_type>:<res_id>».
// - 31c (migration 0003): Insert после revoke того же 5-tuple → новая ACTIVE row
//   (partial UNIQUE WHERE revoked_at IS NULL не блокирует revoked rows).
// - 32: Insert с несущ. role_id → FailedPrecondition (FK access_bindings_role_fk).
// - 33: Insert с invalid subject_type → CHECK violation → InvalidArgument.
// - 34a: Delete happy.
// - 34b: Delete несущ. → NotFound.
// - 35a: ListByScope — несколько binding'ов одного resource.
// - 35b: ListBySubject — несколько binding'ов одного subject.

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
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// insertAB — helper для seed-вставки AccessBinding.
//
// Использует `assert.NoError + explicit Rollback + t.FailNow` (не голый
// `require.NoError`), чтобы освободить открытый Writer на любом code-path. Иначе
// при FK-violation (например, role_id ссылается на несуществующую роль)
// `require.FailNow` → `runtime.Goexit` ДО `w.Commit/Rollback` → connection
// остается acquired → `pool.Close` блокируется на pgxpool puddle WaitGroup →
// тест висит до timeout. Параллель `mustBeginTx` из
// kac127_repos_integration_test.go.
func insertAB(t *testing.T, ctx context.Context, repo *kachopg.Repository, b domain.AccessBinding) domain.AccessBinding {
	t.Helper()
	if b.ID == "" {
		b.ID = domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	}
	w, err := repo.Writer(ctx)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	out, err := w.AccessBindingsW().Insert(ctx, b)
	if err != nil {
		_ = w.Rollback(ctx) // освобождаем connection до FailNow
		assert.NoError(t, err)
		t.FailNow()
	}
	if err := w.Commit(ctx); err != nil {
		_ = w.Rollback(ctx)
		assert.NoError(t, err)
		t.FailNow()
	}
	return out
}

func TestAB_31a_Insert_New(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ab31a")
	acc := seedAccount(t, ctx, repo, "acc-ab31a", uid)

	b := domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       "rol000000000sysviewer", // seed system role (migration 0011)
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	}
	out := insertAB(t, ctx, repo, b)
	assert.NotEmpty(t, out.ID)
	assert.Equal(t, b.SubjectID, out.SubjectID)
}

// TestAB_31b_Insert_DuplicateActiveIsAlreadyExists — migration 0003.
//
// Inserting the SAME 5-tuple twice (both rows would be ACTIVE) must surface
// SQLSTATE 23505 from access_bindings_active_grant_uniq, which mapErr
// translates to ErrAlreadyExists with the canonical Kachō error text
// «these permissions are already granted to <subject_id> on
// <res_type>:<res_id>». Replaces the historical idempotent-upsert behaviour.
func TestAB_31b_Insert_DuplicateActiveIsAlreadyExists(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ab31b")
	acc := seedAccount(t, ctx, repo, "acc-ab31b", uid)

	b := domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       "rol000000000sysviewer", // seed system role (migration 0011)
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	}
	_ = insertAB(t, ctx, repo, b)

	// Second insert with a fresh candidate id but identical 5-tuple — must fail.
	b2 := b
	b2.ID = domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, insErr := w.AccessBindingsW().Insert(ctx, b2)
	_ = w.Rollback(ctx) // release connection even on error path

	require.Error(t, insErr, "duplicate active grant must surface")
	assert.True(t, stderrors.Is(insErr, iamerr.ErrAlreadyExists),
		"expected ErrAlreadyExists sentinel, got %v", insErr)
	// The canonical Kachō error text.
	wantMsg := "these permissions are already granted to " + string(uid) + " on account:" + string(acc.ID)
	assert.Contains(t, insErr.Error(), wantMsg,
		"error message must include the canonical Kachō error text")
}

// TestAB_31c_Insert_AfterRevokeIsAllowed — migration 0003.
//
// The partial UNIQUE access_bindings_active_grant_uniq scopes uniqueness to
// WHERE revoked_at IS NULL. A re-grant of the SAME 5-tuple AFTER the prior
// row is revoked must succeed (operators legitimately re-grant).
func TestAB_31c_Insert_AfterRevokeIsAllowed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ab31c")
	acc := seedAccount(t, ctx, repo, "acc-ab31c", uid)

	b := domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       "rol000000000sysviewer",
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	}
	first := insertAB(t, ctx, repo, b)

	// Revoke the first binding.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	revoker := domain.UserID(uid)
	_, err = w.AccessBindingsW().TransitionStatus(ctx, first.ID,
		[]domain.AccessBindingStatus{domain.AccessBindingStatusActive},
		domain.AccessBindingStatusRevoked, &revoker)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	// Re-grant the same 5-tuple — must succeed (new ACTIVE row).
	b2 := b
	b2.ID = domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	second := insertAB(t, ctx, repo, b2)
	assert.NotEqual(t, first.ID, second.ID, "re-grant after revoke must produce a fresh row")
	assert.Equal(t, domain.AccessBindingStatusActive, second.Status)
}

func TestAB_32_Insert_MissingRole(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ab32")

	b := domain.AccessBinding{
		ID:           domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       "rol0000000000000ghst", // не существует
		ResourceType: "account",
		ResourceID:   "acc0000000000000xxxx",
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().Insert(ctx, b)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition))
}

func TestAB_33_Insert_InvalidSubjectType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ab33")

	b := domain.AccessBinding{
		ID:           domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
		SubjectType:  domain.SubjectType("badtype"), // нарушает DB CHECK access_bindings_subject_ck
		SubjectID:    domain.SubjectID(uid),
		RoleID:       seedSystemRoleIDIAMView,
		ResourceType: "account",
		ResourceID:   "acc0000000000000xxxx",
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().Insert(ctx, b)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrInvalidArg))
}

func TestAB_34a_Delete_Happy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ab34a")
	acc := seedAccount(t, ctx, repo, "acc-ab34a", uid)
	ab := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       seedSystemRoleIDIAMView,
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	})

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().Delete(ctx, ab.ID))
	require.NoError(t, w.Commit(ctx))
}

func TestAB_34b_Delete_NotFound(t *testing.T) {
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
	err = w.AccessBindingsW().Delete(ctx, "acb0000000000000ghst")
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound))
}

func TestAB_35_ListByScopeAndBySubject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ab35a")
	uid2 := mustSeedUser(t, ctx, pool, "ab35b")
	acc := seedAccount(t, ctx, repo, "acc-ab35", uid)

	// uid → admin + viewer на acc
	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       seedSystemRoleIDIAMAdmin,
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	})
	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       seedSystemRoleIDIAMView,
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	})
	// uid2 → viewer на acc
	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid2),
		RoleID:       seedSystemRoleIDIAMView,
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	})

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// ListByScope (account = acc.ID) → 3 bindings.
	byRes, _, err := rd.AccessBindings().ListByScope(ctx, "account", string(acc.ID), repoab.PageFilter{PageSize: 100})
	require.NoError(t, err)
	assert.Equal(t, 3, len(byRes))

	// ListBySubject (uid) → 2 bindings (admin + viewer).
	bySub, _, err := rd.AccessBindings().ListBySubject(ctx, domain.SubjectTypeUser, domain.SubjectID(uid), repoab.PageFilter{PageSize: 100})
	require.NoError(t, err)
	assert.Equal(t, 2, len(bySub))
}

// TestAccessBinding_ConcurrentActiveGrant_ExactlyOneWinner — migration 0003,
// the "concurrent goroutines" race mandate for contended DB invariants.
//
// AccessBinding.Create is the highest-traffic contended write in IAM. The
// strict-create contract (partial UNIQUE access_bindings_active_grant_uniq
// WHERE revoked_at IS NULL) must be RACE-safe at the DB level — N goroutines
// inserting the IDENTICAL active 5-tuple must produce EXACTLY ONE row, with the
// rest fail-closed via ErrAlreadyExists. No second-writer-wins, no panic, no
// leaked pgx error (ban #10 — invariant enforced by Postgres, not software
// check-then-act). The sequential dup test (TestAB_31b) cannot catch a TOCTOU
// race; this test does.
//
// Each goroutine drives its own Writer-tx (pool.Begin → Insert → Commit) — the
// shared insertAB helper is NOT goroutine-safe (it uses t.FailNow), so the
// transaction lifecycle is inlined here, mirroring the
// cluster_admin_grant_integration_test.go race pattern.
func TestAccessBinding_ConcurrentActiveGrant_ExactlyOneWinner(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "abconc")
	acc := seedAccount(t, ctx, repo, "acc-abconc", uid)

	// The contended 5-tuple — identical across all goroutines (only the
	// candidate id differs, which is the realistic concurrent-Create shape).
	tuple := domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       seedSystemRoleIDIAMView,
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	}

	const N = 8
	var wg sync.WaitGroup
	winners := make(chan domain.AccessBindingID, N)
	dupErrs := make(chan error, N)
	otherErrs := make(chan error, N)

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := tuple
			b.ID = domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))

			w, ierr := repo.Writer(ctx)
			if ierr != nil {
				otherErrs <- ierr
				return
			}
			out, ierr := w.AccessBindingsW().Insert(ctx, b)
			if ierr != nil {
				_ = w.Rollback(ctx) // release connection on the loser path
				if stderrors.Is(ierr, iamerr.ErrAlreadyExists) {
					dupErrs <- ierr
				} else {
					otherErrs <- ierr
				}
				return
			}
			if ierr := w.Commit(ctx); ierr != nil {
				// A serialization/commit race that surfaces the active-grant
				// conflict at COMMIT time is still a duplicate-grant outcome.
				if stderrors.Is(ierr, iamerr.ErrAlreadyExists) {
					dupErrs <- ierr
				} else {
					otherErrs <- ierr
				}
				return
			}
			winners <- out.ID
		}()
	}
	wg.Wait()
	close(winners)
	close(dupErrs)
	close(otherErrs)

	// No unexpected (non-sentinel) errors.
	for e := range otherErrs {
		require.NoError(t, e, "only ErrAlreadyExists is an acceptable loser outcome")
	}

	winnerIDs := make([]domain.AccessBindingID, 0, N)
	for id := range winners {
		winnerIDs = append(winnerIDs, id)
	}
	dupCount := 0
	for range dupErrs {
		dupCount++
	}

	require.Len(t, winnerIDs, 1, "exactly one concurrent Insert of the same active 5-tuple must win")
	require.Equal(t, N-1, dupCount, "the remaining goroutines must fail with ErrAlreadyExists")

	// Exactly one ACTIVE row persisted in the DB (no second-writer-wins).
	var active int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_bindings
		   WHERE subject_type = $1 AND subject_id = $2 AND role_id = $3
		     AND resource_type = $4 AND resource_id = $5
		     AND revoked_at IS NULL`,
		string(tuple.SubjectType), string(tuple.SubjectID), tuple.RoleID,
		string(tuple.ResourceType), tuple.ResourceID).Scan(&active))
	require.Equal(t, 1, active, "exactly one active grant row must persist after the race")
}

// TestAccessBinding_RegrantAfterRevoke_Succeeds — migration 0003.
//
// The partial UNIQUE access_bindings_active_grant_uniq is scoped to
// WHERE revoked_at IS NULL, so a REVOKED grant must NOT block a fresh active
// grant of the same 5-tuple. Operators legitimately re-grant after revoke.
// Distinct from the existing TestAB_31c by asserting the surviving-active-row
// count via the revoke path (TransitionStatus → REVOKED sets revoked_at).
func TestAccessBinding_RegrantAfterRevoke_Succeeds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "abregr")
	acc := seedAccount(t, ctx, repo, "acc-abregr", uid)

	tuple := domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       seedSystemRoleIDIAMView,
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	}
	first := insertAB(t, ctx, repo, tuple)
	require.Equal(t, domain.AccessBindingStatusActive, first.Status)

	// Revoke the first grant via the real repo path (CAS UPDATE sets
	// revoked_at + status='REVOKED').
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	revoker := domain.UserID(uid)
	revoked, err := w.AccessBindingsW().TransitionStatus(ctx, first.ID,
		[]domain.AccessBindingStatus{domain.AccessBindingStatusActive},
		domain.AccessBindingStatusRevoked, &revoker)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	require.Equal(t, domain.AccessBindingStatusRevoked, revoked.Status)

	// Re-grant the SAME 5-tuple — must SUCCEED (revoked row is out of the
	// partial-UNIQUE scope), yielding a fresh ACTIVE row.
	regrant := tuple
	regrant.ID = domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	second := insertAB(t, ctx, repo, regrant)
	assert.NotEqual(t, first.ID, second.ID, "re-grant after revoke must produce a fresh row id")
	assert.Equal(t, domain.AccessBindingStatusActive, second.Status)

	// Exactly one ACTIVE row + one REVOKED history row for the 5-tuple.
	var active, revokedCnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT
		   count(*) FILTER (WHERE revoked_at IS NULL),
		   count(*) FILTER (WHERE revoked_at IS NOT NULL)
		 FROM kacho_iam.access_bindings
		 WHERE subject_type = $1 AND subject_id = $2 AND role_id = $3
		   AND resource_type = $4 AND resource_id = $5`,
		string(tuple.SubjectType), string(tuple.SubjectID), tuple.RoleID,
		string(tuple.ResourceType), tuple.ResourceID).Scan(&active, &revokedCnt))
	require.Equal(t, 1, active, "exactly one active grant after re-grant")
	require.Equal(t, 1, revokedCnt, "the revoked grant remains as history")
}
