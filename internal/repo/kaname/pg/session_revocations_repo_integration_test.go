// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// session_revocations_repo_integration_test.go — integration tests.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func TestSessionRevocations_Hook_RevokeWithAdmin_PersistsRevokedBy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	uid := mustSeedUser(t, ctx, pool, "rev-1")
	adminUID := mustSeedUser(t, ctx, pool, "admin-1")

	repo := kanamepg.NewSessionRevocationRepo(pool)
	rev := domain.SessionRevocation{
		TokenJTI:     "A1-test-" + ids.NewID(domain.PrefixUser),
		Reason:       "force_logout",
		UserID:       uid,
		TTLExpiresAt: time.Now().Add(1 * time.Hour),
	}
	out, err := repo.RevokeWithAdmin(ctx, rev, adminUID)
	require.NoError(t, err)
	assert.Equal(t, rev.TokenJTI, out.TokenJTI)

	// IsRevoked возвращает true.
	revoked, err := repo.IsRevoked(ctx, rev.TokenJTI)
	require.NoError(t, err)
	assert.True(t, revoked)

	// Storage row contains revoked_by_user_id.
	var dbRevokedBy *string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT revoked_by_user_id FROM session_revocations WHERE token_jti = $1`,
		rev.TokenJTI).Scan(&dbRevokedBy))
	require.NotNil(t, dbRevokedBy)
	assert.Equal(t, string(adminUID), *dbRevokedBy)
}

func TestSessionRevocations_Hook_ListRecent_PickupsWithinWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	uid := mustSeedUser(t, ctx, pool, "recent-1")
	repo := kanamepg.NewSessionRevocationRepo(pool)

	// Insert 3 rows, one of which is older than 1 min window.
	for i := 0; i < 3; i++ {
		ttl := time.Now().Add(1 * time.Hour)
		jti := fmt.Sprintf("R-test-%d-%s", i, ids.NewID(domain.PrefixUser))
		_, err := repo.RevokeWithAdmin(ctx, domain.SessionRevocation{
			TokenJTI: jti, Reason: "test", UserID: uid, TTLExpiresAt: ttl,
		}, "")
		require.NoError(t, err)
	}

	got, err := repo.ListRecent(ctx, 10*time.Second)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(got), 3)
}

func TestSessionRevocations_Hook_Idempotent_DoubleRevoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	uid := mustSeedUser(t, ctx, pool, "idem-1")
	repo := kanamepg.NewSessionRevocationRepo(pool)

	jti := "IDEM-" + ids.NewID(domain.PrefixUser)
	rev := domain.SessionRevocation{
		TokenJTI: jti, Reason: "v1", UserID: uid, TTLExpiresAt: time.Now().Add(1 * time.Hour),
	}
	first, err := repo.RevokeWithAdmin(ctx, rev, "")
	require.NoError(t, err)
	require.WithinDuration(t, rev.TTLExpiresAt, first.TTLExpiresAt, time.Microsecond)

	rev.Reason = "v2"
	rev.TTLExpiresAt = first.TTLExpiresAt.Add(-20 * time.Minute)
	repeated, err := repo.RevokeWithAdmin(ctx, rev, "")
	require.NoError(t, err, "ON CONFLICT DO UPDATE — idempotent")
	require.Equal(t, first.TTLExpiresAt, repeated.TTLExpiresAt)
	require.Equal(t, rev.Reason, repeated.Reason)

	rev.TTLExpiresAt = first.TTLExpiresAt.Add(time.Hour)
	extended, err := repo.RevokeWithAdmin(ctx, rev, "")
	require.NoError(t, err)
	require.Equal(t, rev.TTLExpiresAt, extended.TTLExpiresAt)

	other := rev
	other.UserID = mustSeedUser(t, ctx, pool, "idem-other")
	other.TTLExpiresAt = rev.TTLExpiresAt.Add(time.Hour)
	_, err = repo.RevokeWithAdmin(ctx, other, "")
	require.Error(t, err)

	var owner string
	var ttl time.Time
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT user_id, ttl_expires_at FROM session_revocations WHERE token_jti = $1`, jti).Scan(&owner, &ttl))
	require.Equal(t, string(uid), owner)
	require.Equal(t, extended.TTLExpiresAt, ttl)
}

func TestSessionRevocations_Hook_ConcurrentRevoke_NoRace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	uid := mustSeedUser(t, ctx, pool, "race-1")
	repo := kanamepg.NewSessionRevocationRepo(pool)

	const N = 50
	jti := "RACE-" + ids.NewID(domain.PrefixUser)
	firstTTL := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	errs := make([]error, N)
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			_, errs[i] = repo.RevokeWithAdmin(ctx, domain.SessionRevocation{
				TokenJTI: jti, Reason: "concurrent", UserID: uid,
				TTLExpiresAt: firstTTL.Add(time.Duration(i) * time.Minute),
			}, "")
		}()
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}

	// Одна строка с самым поздним сроком при любом порядке записи.
	var count int
	var ttl time.Time
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*), max(ttl_expires_at) FROM session_revocations WHERE token_jti = $1`, jti).Scan(&count, &ttl))
	require.Equal(t, 1, count)
	require.WithinDuration(t, firstTTL.Add((N-1)*time.Minute), ttl, 0)
}
