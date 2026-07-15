// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// user_reenable_concurrent_integration_test.go — concurrent-goroutine CAS test
// for userWriter.ReEnable.
//
// The recovery use-case serializes everything on the recovery_completions PK
// (the dedup gate), so the losing goroutines of a duplicate delivery never reach
// ReEnable. This test drives ReEnable DIRECTLY — N goroutines, each in its own
// writer-tx, calling ReEnable on ONE seeded BLOCKED user row — to prove the
// `UPDATE … FROM (SELECT … FOR UPDATE)` row-lock serializes correctly:
// exactly ONE goroutine observes wasBlocked=true (it won
// the BLOCKED→ACTIVE transition), the rest observe wasBlocked=false (they see the
// already-committed ACTIVE row → re-enable no-op, no lost update), and the final
// status is ACTIVE.

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func TestUserReEnable_ConcurrentCAS_ExactlyOneWasBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	// ONE BLOCKED user row.
	uid, _ := seedAccountAndUser(t, ctx, pool, "krt_grace", "grace@example.com", "BLOCKED")

	const N = 20
	var (
		wg         sync.WaitGroup
		mu         sync.Mutex
		blockedHit int // number of goroutines that observed wasBlocked=true
		errs       []error
	)
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			// Each goroutine drives ReEnable in its OWN writer-tx (bypasses the
			// dedup gate entirely), commits, and records whether it won the
			// BLOCKED→ACTIVE transition.
			w, werr := repo.Writer(ctx)
			if werr != nil {
				mu.Lock()
				errs = append(errs, werr)
				mu.Unlock()
				return
			}
			_, wasBlocked, rerr := w.UsersW().ReEnable(ctx, uid)
			if rerr != nil {
				_ = w.Rollback(ctx)
				mu.Lock()
				errs = append(errs, rerr)
				mu.Unlock()
				return
			}
			if cerr := w.Commit(ctx); cerr != nil {
				mu.Lock()
				errs = append(errs, cerr)
				mu.Unlock()
				return
			}
			mu.Lock()
			if wasBlocked {
				blockedHit++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	require.Empty(t, errs, "no ReEnable should error (already-ACTIVE is a no-op, not an error)")
	assert.Equal(t, 1, blockedHit,
		"exactly ONE goroutine wins BLOCKED→ACTIVE (wasBlocked=true); the rest see the committed ACTIVE row (no lost update)")

	// Final status is ACTIVE.
	var statusDB string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM users WHERE id = $1`, string(uid)).Scan(&statusDB))
	assert.Equal(t, "ACTIVE", statusDB, "final status ACTIVE")

	// Exactly one row (no spurious inserts).
	var rowN int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE external_id = $1`, "krt_grace").Scan(&rowN))
	assert.Equal(t, 1, rowN)

	_ = domain.InviteStatusActive
}
