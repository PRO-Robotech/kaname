// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// session_revocation_loop_integration_test.go — closes the revoke→deny loop.
//
// P0 regression guard: the api-gateway logout handler writes a revocation via
// InternalSessionRevocationsService.Revoke, which lands in session_revocations;
// the Hydra refresh-hook then reads the SAME table via IsRevoked and denies the
// refresh. Before the fix the Revoke RPC was unimplemented, so nothing was ever
// written and IsRevoked always returned false (revocation was inert).
//
// This integration test exercises the production write path
// (SessionRevocationsAdapter.Revoke — the same adapter the new use-case calls)
// and the production read path (SessionRevocationsAdapter.IsRevoked — the same
// method the refresh-hook calls) against a real Postgres, proving the loop is
// now wired end to end.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func TestSessionRevocation_RevokeThenIsRevoked_ClosesLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	uid := mustSeedUser(t, ctx, pool, "srloop")
	adapter := kachopg.NewSessionRevocationsAdapter(pool)

	const jti = "jti-srloop-001"

	// Pre-condition: a fresh jti is NOT revoked.
	revoked, err := adapter.IsRevoked(ctx, jti)
	require.NoError(t, err)
	require.False(t, revoked, "fresh jti must not be revoked")

	// Write the revocation via the production writer (what Revoke uses).
	now := time.Now().UTC()
	err = adapter.Revoke(ctx, domain.SessionRevocation{
		TokenJTI:     jti,
		RevokedAt:    now,
		Reason:       "user-logout",
		UserID:       uid,
		TTLExpiresAt: now.Add(24 * time.Hour),
	}, "" /* revokedBy = system/self */)
	require.NoError(t, err, "Revoke must persist the row")

	// Post-condition: the refresh-hook read path now sees it as revoked.
	revoked, err = adapter.IsRevoked(ctx, jti)
	require.NoError(t, err)
	assert.True(t, revoked, "after Revoke, IsRevoked must return true (refresh denied)")
}

func TestSessionRevocation_Revoke_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	uid := mustSeedUser(t, ctx, pool, "sridem")
	adapter := kachopg.NewSessionRevocationsAdapter(pool)

	now := time.Now().UTC()
	rev := domain.SessionRevocation{
		TokenJTI:     "jti-sridem-001",
		RevokedAt:    now,
		Reason:       "user-logout",
		UserID:       uid,
		TTLExpiresAt: now.Add(24 * time.Hour),
	}
	require.NoError(t, adapter.Revoke(ctx, rev, ""))
	// Repeat — ON CONFLICT (token_jti) DO UPDATE makes this idempotent.
	require.NoError(t, adapter.Revoke(ctx, rev, ""), "repeat Revoke must be idempotent")

	revoked, err := adapter.IsRevoked(ctx, rev.TokenJTI)
	require.NoError(t, err)
	assert.True(t, revoked)
}
