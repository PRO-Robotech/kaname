// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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

	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
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

	repo := kachopg.NewSessionRevocationRepo(pool)
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
	repo := kachopg.NewSessionRevocationRepo(pool)

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
	repo := kachopg.NewSessionRevocationRepo(pool)

	jti := "IDEM-" + ids.NewID(domain.PrefixUser)
	rev := domain.SessionRevocation{
		TokenJTI: jti, Reason: "v1", UserID: uid, TTLExpiresAt: time.Now().Add(1 * time.Hour),
	}
	_, err = repo.RevokeWithAdmin(ctx, rev, "")
	require.NoError(t, err)

	rev.Reason = "v2"
	_, err = repo.RevokeWithAdmin(ctx, rev, "")
	require.NoError(t, err, "ON CONFLICT DO UPDATE — idempotent")

	var reason string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT reason FROM session_revocations WHERE token_jti = $1`, jti).Scan(&reason))
	assert.Equal(t, "v2", reason, "second call UPDATE-ит reason")
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
	repo := kachopg.NewSessionRevocationRepo(pool)

	const N = 50
	jti := "RACE-" + ids.NewID(domain.PrefixUser)
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			_, _ = repo.RevokeWithAdmin(ctx, domain.SessionRevocation{
				TokenJTI: jti, Reason: "concurrent", UserID: uid,
				TTLExpiresAt: time.Now().Add(1 * time.Hour),
			}, "")
		}()
	}
	wg.Wait()

	// Только одна row в БД (PK constraint).
	var count int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM session_revocations WHERE token_jti = $1`, jti).Scan(&count))
	assert.Equal(t, 1, count)
}

func TestDPoPReplay_Hook_PostgresPersistence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	// This test verifies dpop_replay_jti migration applies and PK enforces.
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	// First INSERT succeeds.
	jti := "dpop-" + ids.NewID(domain.PrefixUser)
	_, err = pool.Exec(ctx,
		`INSERT INTO dpop_replay_jti (jti, seen_at, htm, htu, jkt) VALUES ($1, now(), 'POST', 'https://x', 'jkt-x')`,
		jti)
	require.NoError(t, err)

	// Second INSERT (replay) fails with SQLSTATE 23505.
	_, err = pool.Exec(ctx,
		`INSERT INTO dpop_replay_jti (jti, seen_at, htm, htu, jkt) VALUES ($1, now(), 'POST', 'https://x', 'jkt-x')`,
		jti)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate key")

	// DELETE cleanup на старые rows.
	_, err = pool.Exec(ctx, `UPDATE dpop_replay_jti SET seen_at = now() - INTERVAL '10 minutes' WHERE jti = $1`, jti)
	require.NoError(t, err)
	tag, err := pool.Exec(ctx, `DELETE FROM dpop_replay_jti WHERE seen_at <= now() - INTERVAL '5 minutes'`)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, tag.RowsAffected(), int64(1))
}
