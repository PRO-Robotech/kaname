// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// cluster_admin_grant_integration_test.go — integration tests for the
// cluster-admin Writer/Reader repos (kaname.cluster_admin_grants).
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
//   - TestGrant_RowAndJournalCommitInOneTx  — строка выдачи + строка журнала
//                                              коммитятся одной TX (ban #10).
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

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// seedClusterAdmin — helper для тестов last-admin: вставляет permanent
// active grant напрямую через pool (минуя Writer.Grant, чтобы изолировать
// SUT). granted_by = self.
func seedClusterAdmin(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subject domain.UserID) {
	t.Helper()
	id := domain.NewKac127ID(domain.PrefixClusterAdminGrant)
	_, err := pool.Exec(ctx,
		`INSERT INTO kaname.cluster_admin_grants
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
		`INSERT INTO kaname.cluster_admin_grants
		     (id, cluster_id, subject_type, subject_id, granted_by, granted_at, granted_until)
		 VALUES ($1, $2, 'user', $3, $3, $4, $5)`,
		id, domain.ClusterSingletonID, string(subject), grantedAt, revokedAt)
	require.NoError(t, err, "seed revoked cluster_admin_grants row")
}

// countActiveAdmins — TOTAL active grants, every subject_type included.
//
// This is the exact population the last-admin guard counts, so tests that
// exercise D-6 assert on THIS number — including the bootstrap-SA grant that
// migration 0058 seeds into every database (see bootstrapSeedSubject).
func countActiveAdmins(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.cluster_admin_grants WHERE granted_until IS NULL`).
		Scan(&n))
	return n
}

// countActiveUserAdmins — active grants of subject_type='user', i.e. exactly
// the rows a test seeds itself / the Writer creates (Writer.Grant hard-codes
// 'user'). Use this when the assertion is about the SUT's own rows ("the
// idempotent second Grant created no extra row") rather than about the
// cluster-wide admin population — it stays exact (never `>= n`) while being
// blind to the migration-seeded service_account grant.
func countActiveUserAdmins(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.cluster_admin_grants
		  WHERE granted_until IS NULL AND subject_type = 'user'`).
		Scan(&n))
	return n
}

// countActiveAdminsForSubject — active grants held by ONE subject. The
// per-subject invariant ("at most one active grant per subject", partial
// UNIQUE) is what most repo tests actually mean by "exactly one row".
func countActiveAdminsForSubject(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subjectID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.cluster_admin_grants
		  WHERE subject_id = $1 AND granted_until IS NULL`, subjectID).
		Scan(&n))
	return n
}

// bootstrapSeedSubject — id of the bootstrap-admin ServiceAccount that
// migration 0058 seeds a permanent cluster system_admin grant for. Asserts the
// singleton (exactly one service_account grant) so a future migration adding a
// second system principal fails here loudly instead of silently skewing the
// counts below.
func bootstrapSeedSubject(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT subject_id FROM kaname.cluster_admin_grants
		  WHERE subject_type = 'service_account' AND granted_until IS NULL`)
	require.NoError(t, err)
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		ids = append(ids, id)
	}
	require.NoError(t, rows.Err())
	require.Len(t, ids, 1, "migration 0058 seeds exactly one bootstrap-SA cluster admin grant")
	return ids[0]
}

// decommissionBootstrapSeedGrant — revokes the migration-seeded bootstrap-SA
// grant so that the user grants a test seeds are the ONLY active ones.
//
// Required by every D-6 (last-admin) test: the guard counts ALL active grants,
// and RevokeAdmin can only ever revoke subject_type='user' rows, so while the
// 0058 seed is active the "one active grant left" state is unreachable through
// the RPC (see TestRevoke_LastUserAdmin_BootstrapSAKeepsClusterAdministrable,
// which pins that production behaviour). Revoking — not deleting — the row
// models the real decommission path (same granted_until lifecycle column) and
// keeps the history row intact.
func decommissionBootstrapSeedGrant(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	tag, err := pool.Exec(ctx,
		`UPDATE kaname.cluster_admin_grants
		    SET granted_until = now()
		  WHERE subject_type = 'service_account' AND granted_until IS NULL`)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(),
		"exactly one seeded service_account grant must be decommissioned")
}

func countOutboxByEvent(t *testing.T, ctx context.Context, pool *pgxpool.Pool, eventType string) int {
	t.Helper()
	var n int
	// Count ONLY the cluster-admin grant/revoke tuples these tests emit — they
	// all carry relation `system_admin` AND a `user:<id>` subject (object
	// `cluster:cluster_root` via fgaTuplesGrantSystemAdmin). Discriminating
	// on relation alone is no longer enough: migration 0058 seeds a
	// `system_admin` tuple of its own for the bootstrap ServiceAccount
	// (`service_account:<sva>` on the same object), so the subject-prefix
	// predicate is what keeps these counts exact. The other migration-seeded
	// tuples use DIFFERENT relations and are excluded by the relation predicate:
	// 0009 `fga_writer`@iam_fgaproxy:system, 0010 (operator) + 0014 (reader SAs)
	// `system_viewer`@cluster:cluster_root. A prior object-blocklist
	// (`object NOT IN (…, 'cluster:cluster_root')`) wrongly excluded the
	// test's OWN system_admin grants too (they share that object), so the
	// assertions counted 0 — hence discriminating on relation+user, not object.
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.fga_outbox
		  WHERE event_type = $1
		    AND `+fga_outbox.RelationPredicate("payload", "'system_admin'")+`
		    AND payload->>'user' LIKE 'user:%'`,
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

	w := kanamepg.NewClusterAdminGrantWriter(pool)

	// 1st Grant — fresh INSERT, created=true.
	tx1, err := pool.Begin(ctx)
	require.NoError(t, err)
	g1, created1, err := w.Grant(ctx, tx1, domain.GrantSubjectTypeUser, domain.SubjectID(target), string(caller))
	require.NoError(t, err)
	require.NoError(t, tx1.Commit(ctx))
	require.True(t, created1, "first Grant must return created=true")
	require.Equal(t, domain.GrantSubjectTypeUser, g1.SubjectType)
	require.Equal(t, domain.SubjectID(target), g1.SubjectID)
	require.True(t, g1.IsActive())

	// 2nd Grant on same subject — no-op, created=false, same id returned.
	tx2, err := pool.Begin(ctx)
	require.NoError(t, err)
	g2, created2, err := w.Grant(ctx, tx2, domain.GrantSubjectTypeUser, domain.SubjectID(target), string(caller))
	require.NoError(t, err)
	require.NoError(t, tx2.Commit(ctx))
	require.False(t, created2, "second Grant must return created=false (idempotent)")
	require.Equal(t, g1.ID, g2.ID, "idempotent grant must return existing id")

	// Exactly one active user row — the second Grant added none.
	require.Equal(t, 1, countActiveUserAdmins(t, ctx, pool))
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

	w := kanamepg.NewClusterAdminGrantWriter(pool)

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
			g, created, ierr := w.Grant(ctx, tx, domain.GrantSubjectTypeUser, domain.SubjectID(target), string(caller))
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

	// Exactly one user row in DB — 9 losers wrote nothing.
	require.Equal(t, 1, countActiveUserAdmins(t, ctx, pool))
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

	// Setup: ONE active grant in the whole table. The migration-seeded
	// bootstrap-SA grant is decommissioned first — the guard counts EVERY
	// active grant, so "S1 is the last admin" is only true once no system
	// principal holds one either.
	s1 := mustSeedUser(t, ctx, pool, "s1")
	caller := mustSeedUser(t, ctx, pool, "caller") // separate principal to avoid self-revoke
	decommissionBootstrapSeedGrant(t, ctx, pool)
	seedClusterAdmin(t, ctx, pool, s1)
	require.Equal(t, 1, countActiveAdmins(t, ctx, pool))

	w := kanamepg.NewClusterAdminGrantWriter(pool)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, rerr := w.Revoke(ctx, tx, domain.GrantSubjectTypeUser, domain.SubjectID(s1), string(caller))
	_ = tx.Rollback(ctx)
	require.Error(t, rerr)
	require.True(t, stderrors.Is(rerr, iamerr.ErrLastAdmin),
		"last-admin revoke must return ErrLastAdmin, got %v", rerr)

	// State unchanged: row still active.
	require.Equal(t, 1, countActiveAdmins(t, ctx, pool))
}

// ── TestRevoke_LastUserAdmin_BootstrapSAKeepsClusterAdministrable ────────────
//
// Post-0058 semantics of the D-6 last-admin guard, pinned deliberately.
//
// The guard counts EVERY active grant, and since migration 0058 every database
// permanently carries one: the bootstrap-admin ServiceAccount's cluster
// system_admin grant. Revoke only ever targets `subject_type='user'` rows (SQL
// WHERE + the use-case's "only 'user' supported" validation), so that seeded
// row can never be revoked through this path.
//
// Consequences, both asserted here:
//   - revoking the LAST USER admin now SUCCEEDS (count 2 > 1) — a human-free
//     admin population is reachable, whereas before 0058 it was refused;
//   - the invariant D-6 actually defends — "the cluster never reaches zero
//     active admins", i.e. never locks itself out — still holds, because the
//     bootstrap SA (the non-interactive recovery principal that mints tokens
//     for any subject) remains an active admin.
//
// ErrLastAdmin therefore stays reachable only once the seeded grant is
// decommissioned (TestRevoke_LastAdmin_Sequential covers that state); the guard
// remains a correct fail-safe backstop, not dead code.
func TestRevoke_LastUserAdmin_BootstrapSAKeepsClusterAdministrable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// The ONLY user admin, on top of the untouched 0058 seed.
	only := mustSeedUser(t, ctx, pool, "only")
	caller := mustSeedUser(t, ctx, pool, "caller") // separate principal — not a self-revoke
	seedClusterAdmin(t, ctx, pool, only)
	seedSubject := bootstrapSeedSubject(t, ctx, pool)
	require.Equal(t, 1, countActiveUserAdmins(t, ctx, pool))
	require.Equal(t, 2, countActiveAdmins(t, ctx, pool), "user admin + bootstrap-SA grant")

	w := kanamepg.NewClusterAdminGrantWriter(pool)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	g, rerr := w.Revoke(ctx, tx, domain.GrantSubjectTypeUser, domain.SubjectID(only), string(caller))
	require.NoError(t, rerr,
		"the last USER admin is revocable — the bootstrap-SA grant satisfies count>1")
	require.NoError(t, tx.Commit(ctx))
	require.False(t, g.IsActive())

	// Zero human admins left — but the cluster still has an admin (never zero).
	require.Equal(t, 0, countActiveUserAdmins(t, ctx, pool))
	require.Equal(t, 1, countActiveAdmins(t, ctx, pool))
	require.Equal(t, 1, countActiveAdminsForSubject(t, ctx, pool, seedSubject),
		"the bootstrap-SA grant is untouched and keeps the cluster administrable")
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
	// Decommission the 0058 seed so the guard's count reflects S1+S2 only —
	// otherwise BOTH revokes see count=3 and succeed (no ErrLastAdmin).
	decommissionBootstrapSeedGrant(t, ctx, pool)
	seedClusterAdmin(t, ctx, pool, s1)
	seedClusterAdmin(t, ctx, pool, s2)
	require.Equal(t, 2, countActiveAdmins(t, ctx, pool))

	w := kanamepg.NewClusterAdminGrantWriter(pool)

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
		g, ierr := w.Revoke(ctx, tx, domain.GrantSubjectTypeUser, domain.SubjectID(s2), string(s1))
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
		g, ierr := w.Revoke(ctx, tx, domain.GrantSubjectTypeUser, domain.SubjectID(s1), string(s2))
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
	// Decommission the 0058 seed — the write-skew this test forces is only
	// observable when S1+S2 are the entire active-admin population.
	decommissionBootstrapSeedGrant(t, ctx, pool)
	seedClusterAdmin(t, ctx, pool, s1)
	seedClusterAdmin(t, ctx, pool, s2)
	require.Equal(t, 2, countActiveAdmins(t, ctx, pool))

	w := kanamepg.NewClusterAdminGrantWriter(pool)

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
		g, ierr := w.Revoke(ctx, tx, domain.GrantSubjectTypeUser, domain.SubjectID(subject), string(principal))
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
	require.Equal(t, 2, countActiveUserAdmins(t, ctx, pool))

	w := kanamepg.NewClusterAdminGrantWriter(pool)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, rerr := w.Revoke(ctx, tx, domain.GrantSubjectTypeUser, domain.SubjectID(s), string(s))
	_ = tx.Rollback(ctx)

	require.Error(t, rerr)
	require.True(t, stderrors.Is(rerr, iamerr.ErrSelfRevoke),
		"self-revoke must return ErrSelfRevoke, got %v", rerr)

	// State unchanged.
	require.Equal(t, 2, countActiveUserAdmins(t, ctx, pool))
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

	w := kanamepg.NewClusterAdminGrantWriter(pool)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, rerr := w.Revoke(ctx, tx, domain.GrantSubjectTypeUser, domain.SubjectID(never), string(admin))
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

	w := kanamepg.NewClusterAdminGrantWriter(pool)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, rerr := w.Revoke(ctx, tx, domain.GrantSubjectTypeUser, domain.SubjectID(target), string(admin))
	_ = tx.Rollback(ctx)

	require.Error(t, rerr)
	require.True(t, stderrors.Is(rerr, iamerr.ErrNotFound),
		"revoke already-revoked must return ErrNotFound, got %v", rerr)

	// History row should remain untouched (existence-only check).
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.cluster_admin_grants
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

	w := kanamepg.NewClusterAdminGrantWriter(pool)
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
		_, _, ierr = w.Grant(ctx, tx, domain.GrantSubjectTypeUser, domain.SubjectID(u2), string(caller))
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
		_, ierr = w.Revoke(ctx, tx, domain.GrantSubjectTypeUser, domain.SubjectID(u2), string(caller))
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
		`SELECT count(*) FROM kaname.cluster_admin_grants
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

	seedSubject := bootstrapSeedSubject(t, ctx, pool)

	r := kanamepg.NewClusterAdminGrantReader(pool)

	entries, err := r.ListActive(ctx)
	require.NoError(t, err)

	// Build by-subject map for stable assertion.
	bySubject := map[string]domain.ClusterAdminEntry{}
	for _, e := range entries {
		bySubject[e.SubjectID] = e
	}
	require.Contains(t, bySubject, string(a1))
	require.Contains(t, bySubject, string(a2))
	require.NotContains(t, bySubject, string(revoked),
		"revoked grants must never appear in ListActive")

	// The reader returns the WHOLE active-admin population — the two user
	// admins seeded here plus the bootstrap ServiceAccount that migration 0058
	// grants cluster system_admin to. Assert both halves exactly, so a third
	// unexpected row still fails the test.
	require.Len(t, entries, 3, "two seeded user admins + the bootstrap-SA grant")
	require.Contains(t, bySubject, seedSubject, "bootstrap-SA grant must be listed")
	require.Equal(t, string(domain.GrantSubjectTypeServiceAccount),
		bySubject[seedSubject].SubjectType,
		"the bootstrap-SA row must keep its service_account subject_type")

	// Denormalised user fields populated (mustSeedUser sets email/display_name)
	// for the USER-typed rows. The service_account row has no users-row to JOIN,
	// so its email/display_name are legitimately empty (LEFT JOIN).
	for _, id := range []string{string(a1), string(a2)} {
		e := bySubject[id]
		require.Equal(t, string(domain.GrantSubjectTypeUser), e.SubjectType)
		require.NotEmpty(t, e.SubjectEmail, "subject_email must be JOINed from users")
		require.NotEmpty(t, e.SubjectDisplayName, "subject_display_name must be JOINed")
	}

	// Ordering: by granted_at ASC.
	for i := 1; i < len(entries); i++ {
		require.False(t, entries[i].GrantedAt.Before(entries[i-1].GrantedAt),
			"entries must be ordered by granted_at ASC")
	}
}

// ── TestGrant_RowAndJournalCommitInOneTx ─────────────────────────────────────
//
// Строка выдачи и строка ЖУРНАЛА намерений коммитятся ОДНОЙ транзакцией — ban #10:
// инвариант держит оператор базы, а не последовательность «вставил, потом позвал».
//
// Прежде это утверждение называлось «переживает недоступность движка» и доказывало
// отсутствие живой зависимости от чужой службы. Со снятием движка предмет не пропал,
// а стал НЕСУЩИМ: строка журнала и есть доставка — из неё триггер
// (`kaname.relation_fact_from_journal`) складывает прямой факт в тот же коммит.
// Значит откат этой транзакции не может оставить выданное право, а её коммит не может
// оставить право невыданным. Разъехаться этим двум строкам больше негде.

func TestGrant_RowAndJournalCommitInOneTx(t *testing.T) {
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

	w := kanamepg.NewClusterAdminGrantWriter(pool)
	emit := kanamepg.NewFGAOutboxEmitter() // existing adapter (pg/fga_outbox_emitter.go)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)

	// 1. Insert cluster_admin_grants row via Writer.Grant.
	_, created, err := w.Grant(ctx, tx, domain.GrantSubjectTypeUser, domain.SubjectID(target), string(caller))
	require.NoError(t, err)
	require.True(t, created)

	// 2. Emit fga_outbox row in the SAME tx (atomic emit).
	require.NoError(t, emit.EmitWriteTx(ctx, tx, nil)) // 0-tuple no-op for adapter sanity
	require.NoError(t, emit.EmitWriteTx(ctx, tx, fgaTuplesGrantSystemAdmin(string(target))))

	require.NoError(t, tx.Commit(ctx))

	// Обе строки видны: транзакция закоммичена целиком, без обращения наружу.
	require.Equal(t, 1, countActiveUserAdmins(t, ctx, pool))
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

	w := kanamepg.NewClusterAdminGrantWriter(pool)
	emit := kanamepg.NewFGAOutboxEmitter()

	// — Step 1: Grant ————————————————————————————————
	tx1, err := pool.Begin(ctx)
	require.NoError(t, err)
	g1, created1, err := w.Grant(ctx, tx1, domain.GrantSubjectTypeUser, domain.SubjectID(target), string(caller))
	require.NoError(t, err)
	require.True(t, created1)
	require.NoError(t, emit.EmitWriteTx(ctx, tx1, fgaTuplesGrantSystemAdmin(string(target))))
	require.NoError(t, tx1.Commit(ctx))
	require.True(t, g1.IsActive())
	require.Equal(t, 1, countOutboxByEvent(t, ctx, pool, "fga.tuple.write"))

	// — Step 2: Revoke ———————————————————————————————
	tx2, err := pool.Begin(ctx)
	require.NoError(t, err)
	g2, err := w.Revoke(ctx, tx2, domain.GrantSubjectTypeUser, domain.SubjectID(target), string(caller))
	require.NoError(t, err)
	require.NoError(t, emit.EmitDeleteTx(ctx, tx2, fgaTuplesGrantSystemAdmin(string(target))))
	require.NoError(t, tx2.Commit(ctx))
	require.False(t, g2.IsActive())
	// Target is revoked; `other` (the second admin seeded above) stays active.
	require.Equal(t, 0, countActiveAdminsForSubject(t, ctx, pool, string(target)),
		"revoked target must have no active row")
	require.Equal(t, 1, countActiveAdminsForSubject(t, ctx, pool, string(other)),
		"the other admin must be untouched by the revoke")

	// — Step 3: Re-Grant (triggers Reactivate path) ——
	tx3, err := pool.Begin(ctx)
	require.NoError(t, err)
	// Grant returns created=false because the row already exists (UNIQUE conflict).
	g3, created3, err := w.Grant(ctx, tx3, domain.GrantSubjectTypeUser, domain.SubjectID(target), string(caller))
	require.NoError(t, err)
	// The Grant path returns the existing (revoked) row: !IsActive → caller invokes Reactivate.
	require.False(t, created3, "re-grant of previously-revoked subject must return created=false")
	require.False(t, g3.IsActive(), "Grant on revoked row returns the revoked state pre-Reactivate")

	// Caller calls Reactivate inside the same tx.
	g3r, rerr := w.Reactivate(ctx, tx3, domain.GrantSubjectTypeUser, domain.SubjectID(target), string(caller))
	require.NoError(t, rerr)
	require.True(t, g3r.IsActive(), "Reactivate must return active row")
	require.Equal(t, g1.ID, g3r.ID, "Reactivate must update the existing row (same id)")

	require.NoError(t, emit.EmitWriteTx(ctx, tx3, fgaTuplesGrantSystemAdmin(string(target))))
	require.NoError(t, tx3.Commit(ctx))

	// — Invariants ————————————————————————————————————
	// (a) Exactly one active row for target.
	require.Equal(t, 1, countActiveAdminsForSubject(t, ctx, pool, string(target)),
		"exactly one active row for target after reactivation")

	// (b) ListActive shows target.
	r := kanamepg.NewClusterAdminGrantReader(pool)
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

// fgaTuplesGrantSystemAdmin — минимальная форма кортежа для пробы атомарности выше.
// Настоящий вызов эмиттера идёт через use-case выдачи кластерного администратора и
// собирает ту же одиночную форму. Имя `fga` историческое и совпадает с именем таблицы
// журнала (`kaname.fga_outbox`), которая жива.
func fgaTuplesGrantSystemAdmin(subjectID string) []service.RelationTuple {
	return []service.RelationTuple{
		{User: "user:" + subjectID, Relation: "system_admin", Object: "cluster:" + domain.ClusterSingletonID},
	}
}
