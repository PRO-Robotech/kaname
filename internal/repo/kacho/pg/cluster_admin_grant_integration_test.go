// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// cluster_admin_grant_integration_test.go — integration tests for the
// cluster-admin Writer/Reader repos (kacho_iam.cluster_admin_grants).
//
// Required tests:
//   - TestGrant_Idempotent                  — повторный grant → no-op.
//   - TestGrant_ConcurrentSameSubject       — 10 goroutines → ровно одна row.
//   - TestRevoke_LastAdmin_Sequential       — единственный admin → ErrLastAdmin.
//   - TestRevoke_ConcurrentLastAdmin        — race; CAS WHERE count>1.
//   - TestRevoke_Self                       — self-revoke → ErrSelfRevoke.
//   - TestRevoke_NotAdmin                   — never-admin → ErrNotFound.
//   - TestRevoke_AlreadyRevoked             — уже-revoked → ErrNotFound.
//   - TestGrantRevoke_ConcurrentSameSubject — invariants на 2 goroutines.
//   - TestList_JoinsUsers                   — denormalised email/display_name.
//   - TestGrant_OpenFGAOutage               — DB-row + fga_outbox row commit'ятся
//                                              в одной TX независимо от OpenFGA.
//
// TestGet_Singleton — отдельный файл cluster_reader_integration_test.go.
//
// Все тесты используют testcontainers Postgres + goose-миграции через
// существующий setupTestDB (см. account_integration_test.go).
//
// Сetup-helpers переиспользуют mustSeedUser. Для каждого теста создается
// fresh DB-контейнер — параллельные тесты НЕ делят state.

import (
	"context"
	stderrors "errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// seedClusterAdmin — helper для тестов last-admin: вставляет permanent
// active grant напрямую через pool (минуя Writer.Grant, чтобы изолировать
// SUT). granted_by = self.
func seedClusterAdmin(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subject domain.UserID) {
	t.Helper()
	id := domain.NewKac127ID(domain.PrefixClusterAdminGrant)
	_, err := pool.Exec(ctx,
		`INSERT INTO kacho_iam.cluster_admin_grants
		     (id, cluster_id, subject_type, subject_id, granted_by, granted_at, granted_until)
		 VALUES ($1, $2, 'user', $3, $3, now(), NULL)`,
		id, domain.ClusterSingletonID, string(subject))
	require.NoError(t, err, "seed cluster_admin_grants row")
}

// seedRevokedClusterAdmin — для TestRevoke_AlreadyRevoked: insert history
// row с granted_until установленным в прошлом.
func seedRevokedClusterAdmin(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subject domain.UserID) {
	t.Helper()
	id := domain.NewKac127ID(domain.PrefixClusterAdminGrant)
	revokedAt := time.Now().UTC().Add(-1 * time.Hour)
	grantedAt := revokedAt.Add(-1 * time.Hour)
	_, err := pool.Exec(ctx,
		`INSERT INTO kacho_iam.cluster_admin_grants
		     (id, cluster_id, subject_type, subject_id, granted_by, granted_at, granted_until)
		 VALUES ($1, $2, 'user', $3, $3, $4, $5)`,
		id, domain.ClusterSingletonID, string(subject), grantedAt, revokedAt)
	require.NoError(t, err, "seed revoked cluster_admin_grants row")
}

// countActiveAdmins — single-row SELECT, для assertions.
func countActiveAdmins(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.cluster_admin_grants WHERE granted_until IS NULL`).
		Scan(&n))
	return n
}

func countOutboxByEvent(t *testing.T, ctx context.Context, pool *pgxpool.Pool, eventType string) int {
	t.Helper()
	var n int
	// Count ONLY the cluster-admin grant/revoke tuples these tests emit — they
	// all carry relation `system_admin` (object `cluster:cluster_kacho_root` via
	// fgaTuplesGrantSystemAdmin). An allowlist on the relation is robust against
	// every migration-seeded tuple in a fresh DB, which use DIFFERENT relations:
	// 0009 `fga_writer`@iam_fgaproxy:system, and 0010 (operator) +
	// 0014 (reader SAs) `system_viewer`@cluster:cluster_kacho_root. A prior
	// object-blocklist (`object NOT IN (…, 'cluster:cluster_kacho_root')`) wrongly
	// excluded the test's OWN system_admin grants too (they share that object),
	// so the assertions counted 0 — fixed by discriminating on relation, not object.
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE event_type = $1
		    AND payload->>'relation' = 'system_admin'`,
		eventType).Scan(&n))
	return n
}

// ── TestGrant_Idempotent ─────────────────────────────────────────────────────

func TestGrant_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	caller := mustSeedUser(t, ctx, pool, "caller")
	target := mustSeedUser(t, ctx, pool, "target")

	w := kachopg.NewClusterAdminGrantWriter(pool)

	// 1st Grant — fresh INSERT, created=true.
	tx1, err := pool.Begin(ctx)
	require.NoError(t, err)
	g1, created1, err := w.Grant(ctx, tx1, domain.SubjectID(target), string(caller))
	require.NoError(t, err)
	require.NoError(t, tx1.Commit(ctx))
	require.True(t, created1, "first Grant must return created=true")
	require.Equal(t, domain.GrantSubjectTypeUser, g1.SubjectType)
	require.Equal(t, domain.SubjectID(target), g1.SubjectID)
	require.True(t, g1.IsActive())

	// 2nd Grant on same subject — no-op, created=false, same id returned.
	tx2, err := pool.Begin(ctx)
	require.NoError(t, err)
	g2, created2, err := w.Grant(ctx, tx2, domain.SubjectID(target), string(caller))
	require.NoError(t, err)
	require.NoError(t, tx2.Commit(ctx))
	require.False(t, created2, "second Grant must return created=false (idempotent)")
	require.Equal(t, g1.ID, g2.ID, "idempotent grant must return existing id")

	// Exactly one active row.
	require.Equal(t, 1, countActiveAdmins(t, ctx, pool))
}

// ── TestGrant_ConcurrentSameSubject ─────────────────────────────────────────
//
// 10 goroutines concurrently call Grant for the same subject. Exactly one wins
// the INSERT (created=true), the rest see the partial UNIQUE conflict and
// return created=false with the existing row. No panic / no leaked pgx-error.

func TestGrant_ConcurrentSameSubject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	caller := mustSeedUser(t, ctx, pool, "caller")
	target := mustSeedUser(t, ctx, pool, "target")

	w := kachopg.NewClusterAdminGrantWriter(pool)

	const N = 10
	var wg sync.WaitGroup
	winners := make(chan domain.ClusterAdminGrantID, N)
	losers := make(chan domain.ClusterAdminGrantID, N)
	errs := make(chan error, N)

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx, ierr := pool.Begin(ctx)
			if ierr != nil {
				errs <- ierr
				return
			}
			g, created, ierr := w.Grant(ctx, tx, domain.SubjectID(target), string(caller))
			if ierr != nil {
				_ = tx.Rollback(ctx)
				errs <- ierr
				return
			}
			if ierr := tx.Commit(ctx); ierr != nil {
				errs <- ierr
				return
			}
			if created {
				winners <- g.ID
			} else {
				losers <- g.ID
			}
		}()
	}
	wg.Wait()
	close(winners)
	close(losers)
	close(errs)

	// No errors.
	for e := range errs {
		require.NoError(t, e)
	}

	// Exactly one winner.
	winnerIDs := drainChan(winners)
	loserIDs := drainChan(losers)
	require.Len(t, winnerIDs, 1, "exactly one goroutine must observe created=true")
	require.Len(t, loserIDs, N-1, "the rest must observe created=false")

	// All goroutines see the same id (winner's id).
	for _, id := range loserIDs {
		require.Equal(t, winnerIDs[0], id, "loser must return winner's id (idempotent)")
	}

	// Exactly one row in DB.
	require.Equal(t, 1, countActiveAdmins(t, ctx, pool))
}

func drainChan(ch <-chan domain.ClusterAdminGrantID) []domain.ClusterAdminGrantID {
	out := []domain.ClusterAdminGrantID{}
	for v := range ch {
		out = append(out, v)
	}
	return out
}

// ── TestRevoke_LastAdmin_Sequential ──────────────────────────────────────────

func TestRevoke_LastAdmin_Sequential(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// Setup: ONE admin only.
	s1 := mustSeedUser(t, ctx, pool, "s1")
	caller := mustSeedUser(t, ctx, pool, "caller") // separate principal to avoid self-revoke
	seedClusterAdmin(t, ctx, pool, s1)
	require.Equal(t, 1, countActiveAdmins(t, ctx, pool))

	w := kachopg.NewClusterAdminGrantWriter(pool)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, rerr := w.Revoke(ctx, tx, domain.SubjectID(s1), string(caller))
	_ = tx.Rollback(ctx)
	require.Error(t, rerr)
	require.True(t, stderrors.Is(rerr, iamerr.ErrLastAdmin),
		"last-admin revoke must return ErrLastAdmin, got %v", rerr)

	// State unchanged: row still active.
	require.Equal(t, 1, countActiveAdmins(t, ctx, pool))
}

// ── TestRevoke_ConcurrentLastAdmin ───────────────────────────────────────────
//
// Setup count=2 (S1, S2). 2 goroutines simultaneously revoke each other.
// CAS-WHERE `count(*) > 1` is single-statement atomic — exactly one wins
// (count: 2→1), the other sees count==1 and gets ErrLastAdmin. Either S1
// or S2 survives (non-deterministic, depends on goroutine scheduling).

func TestRevoke_ConcurrentLastAdmin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	s1 := mustSeedUser(t, ctx, pool, "s1")
	s2 := mustSeedUser(t, ctx, pool, "s2")
	seedClusterAdmin(t, ctx, pool, s1)
	seedClusterAdmin(t, ctx, pool, s2)
	require.Equal(t, 2, countActiveAdmins(t, ctx, pool))

	w := kachopg.NewClusterAdminGrantWriter(pool)

	type res struct {
		grant domain.ClusterAdminGrant
		err   error
	}
	out := make(chan res, 2)

	done := make(chan struct{})

	go func() {
		// Goroutine A: S1 revokes S2.
		<-done // wait for both to be ready
		tx, ierr := pool.Begin(ctx)
		if ierr != nil {
			out <- res{err: ierr}
			return
		}
		g, ierr := w.Revoke(ctx, tx, domain.SubjectID(s2), string(s1))
		if ierr != nil {
			_ = tx.Rollback(ctx)
		} else {
			_ = tx.Commit(ctx)
		}
		out <- res{grant: g, err: ierr}
	}()

	go func() {
		// Goroutine B: S2 revokes S1.
		<-done
		tx, ierr := pool.Begin(ctx)
		if ierr != nil {
			out <- res{err: ierr}
			return
		}
		g, ierr := w.Revoke(ctx, tx, domain.SubjectID(s1), string(s2))
		if ierr != nil {
			_ = tx.Rollback(ctx)
		} else {
			_ = tx.Commit(ctx)
		}
		out <- res{grant: g, err: ierr}
	}()

	// Release both goroutines together.
	close(done)

	deadline := time.After(5 * time.Second)
	results := []res{}
	for i := 0; i < 2; i++ {
		select {
		case r := <-out:
			results = append(results, r)
		case <-deadline:
			t.Fatal("concurrent revoke deadlocked / timed out > 5s")
		}
	}

	// Invariant: exactly one success + exactly one ErrLastAdmin.
	successes, lastAdminErrs := 0, 0
	for _, r := range results {
		switch {
		case r.err == nil:
			successes++
			require.False(t, r.grant.IsActive(), "successful revoke must mark grant inactive")
		case stderrors.Is(r.err, iamerr.ErrLastAdmin):
			lastAdminErrs++
		default:
			t.Fatalf("unexpected error: %v", r.err)
		}
	}
	require.Equal(t, 1, successes, "exactly one revoke must succeed")
	require.Equal(t, 1, lastAdminErrs, "exactly one revoke must hit ErrLastAdmin")

	// Final state: exactly one active admin survives.
	require.Equal(t, 1, countActiveAdmins(t, ctx, pool))
}

// ── TestRevoke_ConcurrentLastAdmin_WriteSkew ─────────────────────────────────
//
// Write-skew regression (sec-hardening-r7). Setup count=2 (S1, S2). Two
// goroutines concurrently revoke DISTINCT admins (A revokes S2, B revokes S1)
// and each holds its tx OPEN for `window` after the guarded UPDATE before
// COMMIT.
//
// This deterministically forces the write-skew window that the flaky
// TestRevoke_ConcurrentLastAdmin only hits by luck: without serialization,
// each UPDATE's `count(*) WHERE granted_until IS NULL > 1` guard reads the
// OTHER revoke as still-active (READ COMMITTED, sibling row not locked), so
// BOTH read count=2, BOTH pass the guard, BOTH commit → ZERO admins.
//
// With the tx-scoped advisory lock inside Revoke, the second revoke BLOCKS on
// the lock until the first COMMITs, then re-reads count=1 and is denied with
// ErrLastAdmin. Invariant (verified): exactly one success + exactly one
// ErrLastAdmin, and exactly one active admin survives — never zero.
func TestRevoke_ConcurrentLastAdmin_WriteSkew(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	s1 := mustSeedUser(t, ctx, pool, "s1")
	s2 := mustSeedUser(t, ctx, pool, "s2")
	seedClusterAdmin(t, ctx, pool, s1)
	seedClusterAdmin(t, ctx, pool, s2)
	require.Equal(t, 2, countActiveAdmins(t, ctx, pool))

	w := kachopg.NewClusterAdminGrantWriter(pool)

	// window — how long each goroutine holds its tx open AFTER the guarded
	// UPDATE, before COMMIT. Deliberately widens the read-then-write window so
	// the unserialized (buggy) path is a DETERMINISTIC failure rather than a
	// flaky one. Under the fix, one goroutine simply blocks on the advisory
	// lock for ~window (well within the deadline below), so the value only
	// affects the RED path's reliability, never correctness.
	const window = 300 * time.Millisecond

	type res struct {
		grant domain.ClusterAdminGrant
		err   error
	}
	out := make(chan res, 2)
	start := make(chan struct{})

	revoke := func(subject, principal domain.UserID) {
		<-start // release both goroutines together
		tx, ierr := pool.Begin(ctx)
		if ierr != nil {
			out <- res{err: ierr}
			return
		}
		g, ierr := w.Revoke(ctx, tx, domain.SubjectID(subject), string(principal))
		// Hold the tx open to widen the write-skew window (see `window`).
		time.Sleep(window)
		if ierr != nil {
			_ = tx.Rollback(ctx)
		} else {
			_ = tx.Commit(ctx)
		}
		out <- res{grant: g, err: ierr}
	}

	go revoke(s2, s1) // A: S1 revokes S2
	go revoke(s1, s2) // B: S2 revokes S1
	close(start)

	deadline := time.After(15 * time.Second)
	results := []res{}
	for i := 0; i < 2; i++ {
		select {
		case r := <-out:
			results = append(results, r)
		case <-deadline:
			t.Fatal("concurrent revoke deadlocked / timed out > 15s")
		}
	}

	successes, lastAdminErrs := 0, 0
	for _, r := range results {
		switch {
		case r.err == nil:
			successes++
			require.False(t, r.grant.IsActive(), "successful revoke must mark grant inactive")
		case stderrors.Is(r.err, iamerr.ErrLastAdmin):
			lastAdminErrs++
		default:
			t.Fatalf("unexpected error: %v", r.err)
		}
	}
	require.Equal(t, 1, successes,
		"exactly one revoke may succeed — two successes is the write-skew (zero admins)")
	require.Equal(t, 1, lastAdminErrs,
		"the losing revoke must be denied with ErrLastAdmin")
	require.Equal(t, 1, countActiveAdmins(t, ctx, pool),
		"exactly one cluster admin must survive — never zero (write-skew)")
}

// ── TestRevoke_Self ──────────────────────────────────────────────────────────

func TestRevoke_Self(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// Setup: TWO admins (so last-admin guard does NOT fire — we want only
	// self-guard to fire).
	s := mustSeedUser(t, ctx, pool, "self")
	other := mustSeedUser(t, ctx, pool, "other")
	seedClusterAdmin(t, ctx, pool, s)
	seedClusterAdmin(t, ctx, pool, other)
	require.Equal(t, 2, countActiveAdmins(t, ctx, pool))

	w := kachopg.NewClusterAdminGrantWriter(pool)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, rerr := w.Revoke(ctx, tx, domain.SubjectID(s), string(s))
	_ = tx.Rollback(ctx)

	require.Error(t, rerr)
	require.True(t, stderrors.Is(rerr, iamerr.ErrSelfRevoke),
		"self-revoke must return ErrSelfRevoke, got %v", rerr)

	// State unchanged.
	require.Equal(t, 2, countActiveAdmins(t, ctx, pool))
}

// ── TestRevoke_NotAdmin ──────────────────────────────────────────────────────

func TestRevoke_NotAdmin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// Setup: one admin (so count>1 is FALSE, but Revoke target is never-admin
	// — diagnostic must report not-found before last-admin).
	admin := mustSeedUser(t, ctx, pool, "admin")
	seedClusterAdmin(t, ctx, pool, admin)
	// Add second admin so last-admin guard would NOT fire if target had a row.
	admin2 := mustSeedUser(t, ctx, pool, "admin2")
	seedClusterAdmin(t, ctx, pool, admin2)
	never := mustSeedUser(t, ctx, pool, "never")

	w := kachopg.NewClusterAdminGrantWriter(pool)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, rerr := w.Revoke(ctx, tx, domain.SubjectID(never), string(admin))
	_ = tx.Rollback(ctx)

	require.Error(t, rerr)
	require.True(t, stderrors.Is(rerr, iamerr.ErrNotFound),
		"revoke never-admin must return ErrNotFound, got %v", rerr)
}

// ── TestRevoke_AlreadyRevoked ────────────────────────────────────────────────

func TestRevoke_AlreadyRevoked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// Setup: target has history row (granted_until IS NOT NULL); active count=2
	// for two other admins (so last-admin guard does NOT fire).
	admin := mustSeedUser(t, ctx, pool, "admin")
	admin2 := mustSeedUser(t, ctx, pool, "admin2")
	seedClusterAdmin(t, ctx, pool, admin)
	seedClusterAdmin(t, ctx, pool, admin2)
	target := mustSeedUser(t, ctx, pool, "target")
	seedRevokedClusterAdmin(t, ctx, pool, target)

	w := kachopg.NewClusterAdminGrantWriter(pool)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, rerr := w.Revoke(ctx, tx, domain.SubjectID(target), string(admin))
	_ = tx.Rollback(ctx)

	require.Error(t, rerr)
	require.True(t, stderrors.Is(rerr, iamerr.ErrNotFound),
		"revoke already-revoked must return ErrNotFound, got %v", rerr)

	// History row should remain untouched (existence-only check).
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.cluster_admin_grants
		   WHERE subject_id = $1 AND granted_until IS NOT NULL`,
		string(target)).Scan(&n))
	require.Equal(t, 1, n, "history row must remain")
}

// ── TestGrantRevoke_ConcurrentSameSubject ────────────────────────────────────
//
// 1 goroutine Grants(U2), 1 goroutine Revokes(U2), simultaneously.
//
// Acceptable outcomes (non-determinism — schedule-dependent):
//   (a) Grant first → row created → Revoke succeeds (count>1 guarded by
//       baseline admin S in setup).
//   (b) Revoke first → ErrNotFound (no active row) → Grant creates row.
//
// Invariants (verified):
//   (i)   no >1 active rows for U2;
//   (ii)  no deadlock (<5s for both goroutines);
//   (iii) typed errors only (no panic / no leak pgx-error).

func TestGrantRevoke_ConcurrentSameSubject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	caller := mustSeedUser(t, ctx, pool, "caller")
	baseline := mustSeedUser(t, ctx, pool, "baseline")
	seedClusterAdmin(t, ctx, pool, baseline) // ensures count>1 guard tolerates revoke
	u2 := mustSeedUser(t, ctx, pool, "u2")
	seedClusterAdmin(t, ctx, pool, u2) // U2 starts as admin so Revoke is well-defined

	w := kachopg.NewClusterAdminGrantWriter(pool)
	type res struct {
		op  string
		err error
	}
	out := make(chan res, 2)
	gate := make(chan struct{})

	go func() {
		<-gate
		tx, ierr := pool.Begin(ctx)
		if ierr != nil {
			out <- res{"grant", ierr}
			return
		}
		_, _, ierr = w.Grant(ctx, tx, domain.SubjectID(u2), string(caller))
		if ierr != nil {
			_ = tx.Rollback(ctx)
		} else {
			_ = tx.Commit(ctx)
		}
		out <- res{"grant", ierr}
	}()
	go func() {
		<-gate
		tx, ierr := pool.Begin(ctx)
		if ierr != nil {
			out <- res{"revoke", ierr}
			return
		}
		_, ierr = w.Revoke(ctx, tx, domain.SubjectID(u2), string(caller))
		if ierr != nil {
			_ = tx.Rollback(ctx)
		} else {
			_ = tx.Commit(ctx)
		}
		out <- res{"revoke", ierr}
	}()
	close(gate)

	deadline := time.After(5 * time.Second)
	results := []res{}
	for i := 0; i < 2; i++ {
		select {
		case r := <-out:
			results = append(results, r)
		case <-deadline:
			t.Fatal("grant+revoke deadlocked / timed out > 5s")
		}
	}

	// Invariant: at most one active row for U2.
	var u2Active int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.cluster_admin_grants
		   WHERE subject_id = $1 AND granted_until IS NULL`,
		string(u2)).Scan(&u2Active))
	require.LessOrEqual(t, u2Active, 1, "no >1 active rows for U2")

	// Each goroutine returned either nil (success) or a typed sentinel.
	for _, r := range results {
		if r.err != nil {
			isSentinel := stderrors.Is(r.err, iamerr.ErrNotFound) ||
				stderrors.Is(r.err, iamerr.ErrLastAdmin) ||
				stderrors.Is(r.err, iamerr.ErrSelfRevoke) ||
				stderrors.Is(r.err, iamerr.ErrAlreadyExists) ||
				stderrors.Is(r.err, iamerr.ErrFailedPrecondition)
			require.True(t, isSentinel, "unexpected non-sentinel error from %s: %v", r.op, r.err)
		}
	}
}

// ── TestList_JoinsUsers ──────────────────────────────────────────────────────

func TestList_JoinsUsers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// Setup: 2 admins (active) + 1 history-row (revoked, must NOT appear in List).
	a1 := mustSeedUser(t, ctx, pool, "a1")
	a2 := mustSeedUser(t, ctx, pool, "a2")
	revoked := mustSeedUser(t, ctx, pool, "rv")
	seedClusterAdmin(t, ctx, pool, a1)
	seedClusterAdmin(t, ctx, pool, a2)
	seedRevokedClusterAdmin(t, ctx, pool, revoked)

	r := kachopg.NewClusterAdminGrantReader(pool)

	entries, err := r.ListActive(ctx)
	require.NoError(t, err)
	require.Len(t, entries, 2, "List must return only active admins")

	// Build by-subject map for stable assertion.
	bySubject := map[string]domain.ClusterAdminEntry{}
	for _, e := range entries {
		bySubject[e.SubjectID] = e
	}
	require.Contains(t, bySubject, string(a1))
	require.Contains(t, bySubject, string(a2))
	require.NotContains(t, bySubject, string(revoked))

	// Denormalised user fields populated (mustSeedUser sets email/display_name).
	for _, e := range entries {
		require.NotEmpty(t, e.SubjectEmail, "subject_email must be JOINed from users")
		require.NotEmpty(t, e.SubjectDisplayName, "subject_display_name must be JOINed")
	}

	// Ordering: by granted_at ASC.
	for i := 1; i < len(entries); i++ {
		require.False(t, entries[i].GrantedAt.Before(entries[i-1].GrantedAt),
			"entries must be ordered by granted_at ASC")
	}
}

// ── TestGrant_OpenFGAOutage ──────────────────────────────────────────────────
//
// Repo-layer scope of the OpenFGA-outage scenario:
//
//   The Writer.Grant operation MUST commit the cluster_admin_grants row and
//   the fga_outbox row in a single TX, with NO live dependency on the
//   OpenFGA service. The drainer + OperationsWorker (Task 3+) handle the
//   live-FGA write asynchronously; their behaviour on outage is verified
//   at the handler / e2e level.
//
//   This test confirms the atomicity contract: even with no OpenFGA running,
//   the writer's TX succeeds and both rows are visible. The integration-test
//   environment has no OpenFGA container, so this is the natural state.

func TestGrant_OpenFGAOutage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	caller := mustSeedUser(t, ctx, pool, "caller")
	target := mustSeedUser(t, ctx, pool, "target")

	w := kachopg.NewClusterAdminGrantWriter(pool)
	emit := kachopg.NewFGAOutboxEmitter() // existing adapter (pg/fga_outbox_emitter.go)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)

	// 1. Insert cluster_admin_grants row via Writer.Grant.
	_, created, err := w.Grant(ctx, tx, domain.SubjectID(target), string(caller))
	require.NoError(t, err)
	require.True(t, created)

	// 2. Emit fga_outbox row in the SAME tx (atomic emit).
	require.NoError(t, emit.EmitWriteTx(ctx, tx, nil)) // 0-tuple no-op for adapter sanity
	require.NoError(t, emit.EmitWriteTx(ctx, tx, fgaTuplesGrantSystemAdmin(string(target))))

	require.NoError(t, tx.Commit(ctx))

	// Verify both rows visible (TX committed independent of any OpenFGA RPC).
	require.Equal(t, 1, countActiveAdmins(t, ctx, pool))
	require.Equal(t, 1, countOutboxByEvent(t, ctx, pool, "fga.tuple.write"))
}

// ── TestReactivate_GrantRevokeGrant ──────────────────────────────────────────
//
// Reactivate semantics: after a Grant→Revoke cycle the subject can be
// re-granted. Because the schema has a TOTAL UNIQUE (cluster_id, subject_id)
// a new INSERT would conflict — Reactivate updates the existing row in place.
//
// Invariants:
//   (a) After reactivation: exactly ONE active row for the subject.
//   (b) After Grant→Revoke→Grant cycle: ListActive shows the subject.
//   (c) After the whole cycle: 3 fga_outbox rows (1 grant + 1 revoke + 1 re-grant).

func TestReactivate_GrantRevokeGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	caller := mustSeedUser(t, ctx, pool, "caller")
	target := mustSeedUser(t, ctx, pool, "target")
	// second admin so last-admin guard doesn't fire during Revoke
	other := mustSeedUser(t, ctx, pool, "other")
	seedClusterAdmin(t, ctx, pool, other)

	w := kachopg.NewClusterAdminGrantWriter(pool)
	emit := kachopg.NewFGAOutboxEmitter()

	// — Step 1: Grant ————————————————————————————————
	tx1, err := pool.Begin(ctx)
	require.NoError(t, err)
	g1, created1, err := w.Grant(ctx, tx1, domain.SubjectID(target), string(caller))
	require.NoError(t, err)
	require.True(t, created1)
	require.NoError(t, emit.EmitWriteTx(ctx, tx1, fgaTuplesGrantSystemAdmin(string(target))))
	require.NoError(t, tx1.Commit(ctx))
	require.True(t, g1.IsActive())
	require.Equal(t, 1, countOutboxByEvent(t, ctx, pool, "fga.tuple.write"))

	// — Step 2: Revoke ———————————————————————————————
	tx2, err := pool.Begin(ctx)
	require.NoError(t, err)
	g2, err := w.Revoke(ctx, tx2, domain.SubjectID(target), string(caller))
	require.NoError(t, err)
	require.NoError(t, emit.EmitDeleteTx(ctx, tx2, fgaTuplesGrantSystemAdmin(string(target))))
	require.NoError(t, tx2.Commit(ctx))
	require.False(t, g2.IsActive())
	require.Equal(t, 0, countActiveAdmins(t, ctx, pool)-1) // other is still active, target revoked

	// — Step 3: Re-Grant (triggers Reactivate path) ——
	tx3, err := pool.Begin(ctx)
	require.NoError(t, err)
	// Grant returns created=false because the row already exists (UNIQUE conflict).
	g3, created3, err := w.Grant(ctx, tx3, domain.SubjectID(target), string(caller))
	require.NoError(t, err)
	// The Grant path returns the existing (revoked) row: !IsActive → caller invokes Reactivate.
	require.False(t, created3, "re-grant of previously-revoked subject must return created=false")
	require.False(t, g3.IsActive(), "Grant on revoked row returns the revoked state pre-Reactivate")

	// Caller calls Reactivate inside the same tx.
	g3r, rerr := w.Reactivate(ctx, tx3, domain.SubjectID(target), string(caller))
	require.NoError(t, rerr)
	require.True(t, g3r.IsActive(), "Reactivate must return active row")
	require.Equal(t, g1.ID, g3r.ID, "Reactivate must update the existing row (same id)")

	require.NoError(t, emit.EmitWriteTx(ctx, tx3, fgaTuplesGrantSystemAdmin(string(target))))
	require.NoError(t, tx3.Commit(ctx))

	// — Invariants ————————————————————————————————————
	// (a) Exactly one active row for target.
	var targetActive int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.cluster_admin_grants
		   WHERE subject_id = $1 AND granted_until IS NULL`,
		string(target)).Scan(&targetActive))
	require.Equal(t, 1, targetActive, "exactly one active row for target after reactivation")

	// (b) ListActive shows target.
	r := kachopg.NewClusterAdminGrantReader(pool)
	entries, err := r.ListActive(ctx)
	require.NoError(t, err)
	found := false
	for _, e := range entries {
		if e.SubjectID == string(target) {
			found = true
		}
	}
	require.True(t, found, "reactivated target must appear in ListActive")

	// (c) 2 fga.tuple.write + 1 fga.tuple.delete outbox rows.
	require.Equal(t, 2, countOutboxByEvent(t, ctx, pool, "fga.tuple.write"))
	require.Equal(t, 1, countOutboxByEvent(t, ctx, pool, "fga.tuple.delete"))
}

// fgaTuplesGrantSystemAdmin — minimal tuple shape for the OpenFGA outage test.
// The real use-case-level emitter call (Task 3) goes through the cluster
// grant use-case which assembles the same single-tuple shape.
func fgaTuplesGrantSystemAdmin(subjectID string) []service.RelationTuple {
	return []service.RelationTuple{
		{User: "user:" + subjectID, Relation: "system_admin", Object: "cluster:" + domain.ClusterSingletonID},
	}
}
