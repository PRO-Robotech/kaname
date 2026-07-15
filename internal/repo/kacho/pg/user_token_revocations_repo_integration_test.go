// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// user_token_revocations_repo_integration_test.go — integration tests for the
// user-level ("revoke-all-before") token revocation marker (migration 0012).
//
// Proves the gate the refresh-hook enforces: ForceLogout / Revoke(revoke_all)
// write a per-user cutoff; a token whose session auth_time is at-or-before the
// cutoff is denied; a newer token is allowed; another user is unaffected.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func TestUserTokenRevocations_Upsert_RevokedBefore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	uid := mustSeedUser(t, ctx, pool, "utr-victim")
	adminUID := mustSeedUser(t, ctx, pool, "utr-admin")
	repo := kachopg.NewUserTokenRevocationRepo(pool)

	// No marker yet.
	_, ok, err := repo.RevokedBefore(ctx, string(uid))
	require.NoError(t, err)
	assert.False(t, ok, "no marker before any revoke-all")

	cutoff := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, repo.UpsertRevokeAll(ctx, domain.UserTokenRevocation{
		UserID:       uid,
		RevokeBefore: cutoff,
		Reason:       "admin-force-logout",
	}, adminUID))

	got, ok, err := repo.RevokedBefore(ctx, string(uid))
	require.NoError(t, err)
	require.True(t, ok)
	assert.WithinDuration(t, cutoff, got, time.Second)

	// revoked_by_user_id persisted.
	var dbBy *string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT revoked_by_user_id FROM user_token_revocations WHERE user_id = $1`,
		string(uid)).Scan(&dbBy))
	require.NotNil(t, dbBy)
	assert.Equal(t, string(adminUID), *dbBy)
}

func TestUserTokenRevocations_Upsert_MonotonicGreatest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	uid := mustSeedUser(t, ctx, pool, "utr-mono")
	repo := kachopg.NewUserTokenRevocationRepo(pool)

	newer := time.Now().UTC().Truncate(time.Second)
	older := newer.Add(-time.Hour)

	require.NoError(t, repo.UpsertRevokeAll(ctx, domain.UserTokenRevocation{
		UserID: uid, RevokeBefore: newer, Reason: "first",
	}, ""))
	// A second revoke with an OLDER cutoff must NOT roll the cutoff backwards.
	require.NoError(t, repo.UpsertRevokeAll(ctx, domain.UserTokenRevocation{
		UserID: uid, RevokeBefore: older, Reason: "second-older",
	}, ""))

	got, ok, err := repo.RevokedBefore(ctx, string(uid))
	require.NoError(t, err)
	require.True(t, ok)
	assert.WithinDuration(t, newer, got, time.Second, "cutoff is monotonic (GREATEST), never moves backwards")
}

func TestUserTokenRevocations_GateSemantics(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	victim := mustSeedUser(t, ctx, pool, "gate-victim")
	other := mustSeedUser(t, ctx, pool, "gate-other")
	repo := kachopg.NewUserTokenRevocationRepo(pool)

	cutoff := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, repo.UpsertRevokeAll(ctx, domain.UserTokenRevocation{
		UserID: victim, RevokeBefore: cutoff, Reason: "admin-revoke",
	}, ""))

	before, ok, err := repo.RevokedBefore(ctx, string(victim))
	require.NoError(t, err)
	require.True(t, ok)

	// Token A authenticated 1h ago → before cutoff → DENY.
	older := cutoff.Add(-time.Hour)
	assert.True(t, !older.After(before), "older token (auth_time <= revoke_before) is denied")
	// Token B authenticated 1h from now → after cutoff → ALLOW.
	newer := cutoff.Add(time.Hour)
	assert.True(t, newer.After(before), "newer token (auth_time > revoke_before) is allowed")

	// Other user has no marker → unaffected.
	_, ok, err = repo.RevokedBefore(ctx, string(other))
	require.NoError(t, err)
	assert.False(t, ok, "another user is unaffected by the victim's revoke-all")
}

func TestUserTokenRevocations_ConcurrentUpsert_NoRace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	uid := mustSeedUser(t, ctx, pool, "utr-race")
	repo := kachopg.NewUserTokenRevocationRepo(pool)

	base := time.Now().UTC().Truncate(time.Second)
	const N = 50
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			_ = repo.UpsertRevokeAll(ctx, domain.UserTokenRevocation{
				UserID:       uid,
				RevokeBefore: base.Add(time.Duration(i) * time.Second),
				Reason:       "concurrent",
			}, "")
		}(i)
	}
	wg.Wait()

	// Exactly one row (PK user_id) and the cutoff equals the maximum submitted.
	var count int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM user_token_revocations WHERE user_id = $1`, string(uid)).Scan(&count))
	assert.Equal(t, 1, count)

	got, ok, err := repo.RevokedBefore(ctx, string(uid))
	require.NoError(t, err)
	require.True(t, ok)
	assert.WithinDuration(t, base.Add((N-1)*time.Second), got, time.Second,
		"concurrent upserts converge to the maximum cutoff (GREATEST)")
}
