// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// role_occ_integration_test.go — optimistic-concurrency guard on roles UPDATE.
//
// roles has NO version column (like access_bindings), so the OCC token is the
// row's xmin::text snapshot (read-modify-write OCC without a version column).
// Without it two concurrent Role.Update each derive the FGA fan-out from
// THEIR OWN role projection and both commit → the loser already enqueued a stale
// fan-out into fga_outbox → ledger↔FGA drift. The xmin-CAS makes the loser fail
// with FAILED_PRECONDITION and its whole writer-tx (UPDATE + reconcile fan-out)
// roll back (one writer-tx, ban #10).
//
// Coverage:
//   - two concurrent UpdateCAS with the SAME expected xmin → exactly
//     one commits, the other → ErrFailedPrecondition (no lost-update).
//   - GetWithVersion round-trips; a stale expected version → FailedPrecondition.

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// TestRoleOCC_178_V2_ConcurrentUpdateCAS_ExactlyOneWins — read the role xmin once,
// then fire TWO concurrent UpdateCAS with the SAME expected version. The row-lock
// serializes them: the first bumps xmin and wins; the second reads the SAME
// expected version, finds xmin changed, matches 0 rows → ErrFailedPrecondition.
func TestRoleOCC_178_V2_ConcurrentUpdateCAS_ExactlyOneWins(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "roccown")
	acc := seedAccount(t, ctx, repo, "acc-rocc", owner)
	role := seedCustomRole(t, ctx, repo, acc.ID, "occ_role")

	// Snapshot the OCC token once — both writers will race on it.
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	_, version, err := rd.Roles().GetWithVersion(ctx, role.ID)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, version, "GetWithVersion must return a non-empty xmin token")

	var wins, losers int32
	var wg sync.WaitGroup
	for i, perms := range []domain.Permissions{
		{"iam.access_bindings.*.admin"},
		{"iam.access_bindings.*.get"},
	} {
		wg.Add(1)
		go func(i int, perms domain.Permissions) {
			defer wg.Done()
			w, e := repo.Writer(ctx)
			if e != nil {
				return
			}
			patched := role
			patched.Permissions = perms
			_, ue := w.RolesW().UpdateCAS(ctx, patched, []string{"permissions"}, version)
			if ue != nil {
				_ = w.Rollback(ctx)
				if errors.Is(ue, iamerr.ErrFailedPrecondition) {
					atomic.AddInt32(&losers, 1)
				}
				return
			}
			if ce := w.Commit(ctx); ce == nil {
				atomic.AddInt32(&wins, 1)
			}
		}(i, perms)
	}
	wg.Wait()

	assert.Equal(t, int32(1), atomic.LoadInt32(&wins), "exactly one concurrent UpdateCAS commits")
	assert.Equal(t, int32(1), atomic.LoadInt32(&losers),
		"the loser must get ErrFailedPrecondition (role was modified concurrently), not silently overwrite")
}

// TestRoleOCC_178_V2b_StaleVersion_FailsPrecondition — a stale expected version
// (after the row already moved) is rejected; the current version succeeds.
func TestRoleOCC_178_V2b_StaleVersion_FailsPrecondition(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "rocc2own")
	acc := seedAccount(t, ctx, repo, "acc-rocc2", owner)
	role := seedCustomRole(t, ctx, repo, acc.ID, "occ_role2")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	_, v0, err := rd.Roles().GetWithVersion(ctx, role.ID)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)

	// First update with v0 → succeeds and bumps xmin.
	w1, err := repo.Writer(ctx)
	require.NoError(t, err)
	p1 := role
	p1.Permissions = domain.Permissions{"iam.access_bindings.*.admin"}
	_, err = w1.RolesW().UpdateCAS(ctx, p1, []string{"permissions"}, v0)
	require.NoError(t, err)
	require.NoError(t, w1.Commit(ctx))

	// Second update REUSING the now-stale v0 → FailedPrecondition.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	p2 := role
	p2.Permissions = domain.Permissions{"iam.access_bindings.*.get"}
	_, err = w2.RolesW().UpdateCAS(ctx, p2, []string{"permissions"}, v0)
	_ = w2.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, errors.Is(err, iamerr.ErrFailedPrecondition),
		"stale xmin must be rejected with FailedPrecondition (OCC guard)")
}
