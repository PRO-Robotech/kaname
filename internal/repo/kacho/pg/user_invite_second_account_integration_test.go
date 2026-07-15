// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// user_invite_second_account_integration_test.go — regression tests for the
// user-per-account invite/bootstrap uniqueness model (migration 0011).
//
// Root-cause (live, kind 2026-06-14): migration 0002 added GLOBAL
// UNIQUE(email) + partial UNIQUE(external_id) which contradict the user-per-
// account model (one identity → N rows, one per Account, same email). Inviting
// an existing-email user into a SECOND Account died on `users_email_uniq`
// (23505), rolling back the whole invite TX → invitee never got the grant.
//
// Migration 0011 drops the over-broad globals and replaces the external_id one
// with a partial UNIQUE on ACTIVE rows only (closing the concurrent-bootstrap
// race the global previously guarded).
//
// These tests assert the post-0011 invariant directly at the repo layer with
// testcontainers (goose.Up applies ALL migrations including 0011).

import (
	"context"
	stderrors "errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// ── 0011-A — invite existing-email user into a SECOND account ───────────────
//
// An identity is ACTIVE in account A (its bootstrap home). A second admin
// invites the SAME email into account B → a fresh PENDING row in account B must
// INSERT cleanly. Pre-0011 this failed with `users_email_uniq` (global email
// UNIQUE), rolling back the invite TX.
func TestUserInvite_0011A_InviteExistingEmail_SecondAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	const email = domain.Email("multi-account@example.com")

	// Identity is ACTIVE in account A (bootstrap home).
	adminA, accA := bootstrapAdmin(t, ctx, repo, "i11aA")
	w0, err := repo.Writer(ctx)
	require.NoError(t, err)
	activeID := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err = w0.UsersW().InsertActive(ctx, domain.User{
		ID:           activeID,
		AccountID:    accA,
		ExternalID:   domain.ExternalSubject("ext-i11a-sub"),
		Email:        email,
		DisplayName:  domain.DisplayName("Multi Account"),
		InviteStatus: domain.InviteStatusActive,
	})
	require.NoError(t, err, "seed ACTIVE row in account A")
	require.NoError(t, w0.Commit(ctx))

	// A separate account B with its own admin.
	_, accB := bootstrapAdmin(t, ctx, repo, "i11aB")

	// Invite the SAME email into account B — fresh PENDING row.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	pendingID := domain.UserID(ids.NewID(domain.PrefixUser))
	out, inserted, err := w.UsersW().InsertPending(ctx, domain.User{
		ID:           pendingID,
		AccountID:    accB,
		Email:        email, // same email, different account
		DisplayName:  domain.DisplayName("Multi Account (invited)"),
		InviteStatus: domain.InviteStatusPending,
		InvitedBy:    adminA,
	})
	require.NoError(t, err,
		"invite of existing-email user into a second account must NOT violate a global email UNIQUE")
	require.NoError(t, w.Commit(ctx))

	assert.True(t, inserted, "second-account invite inserts a fresh PENDING row")
	assert.Equal(t, pendingID, out.ID)
	assert.Equal(t, accB, out.AccountID)
	assert.Equal(t, domain.InviteStatusPending, out.InviteStatus)

	// Both rows coexist: one ACTIVE in A, one PENDING in B, same email.
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	pendings, err := rd.Users().FindPendingByEmail(ctx, email)
	require.NoError(t, err)
	assert.Len(t, pendings, 1, "exactly the account-B PENDING row")
	gotA, err := rd.Users().GetByAccountEmail(ctx, accA, email)
	require.NoError(t, err)
	assert.Equal(t, activeID, gotA.ID, "account-A ACTIVE row still present")
	gotB, err := rd.Users().GetByAccountEmail(ctx, accB, email)
	require.NoError(t, err)
	assert.Equal(t, pendingID, gotB.ID, "account-B PENDING row present")
}

// ── 0011-B — concurrent first-login bootstrap is race-safe ──────────────────
//
// N concurrent first-logins for the SAME external_id each try to bootstrap a
// fresh personal account (InsertActive into a DIFFERENT new account_id). The
// per-account index does NOT serialize them (distinct account_ids). The 0011
// partial UNIQUE on ACTIVE external_id is the DB guard that lets exactly one
// win; the rest get ErrAlreadyExists (23505). Without 0011's replacement guard
// (i.e. if step-2 drop left no global ACTIVE-external_id constraint) ALL would
// commit → duplicate ACTIVE identity rows (the bug 0002 originally fixed).
func TestUserInvite_0011B_ConcurrentBootstrap_RaceSafe(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	const ext = domain.ExternalSubject("ext-i11b-racing-sub")
	const email = domain.Email("racing-bootstrap@example.com")
	const N = 5

	var (
		wg        sync.WaitGroup
		successes int64
		failures  int64
		mu        sync.Mutex
		loserErrs []error
	)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, err := repo.Writer(ctx)
			if err != nil {
				atomic.AddInt64(&failures, 1)
				return
			}
			defer func() { _ = w.Rollback(ctx) }()
			// Each racing first-login bootstraps a DISTINCT new account_id.
			uid := domain.UserID(ids.NewID(domain.PrefixUser))
			accID := domain.AccountID(ids.NewID(domain.PrefixAccount))
			if _, err := w.UsersW().InsertActive(ctx, domain.User{
				ID:           uid,
				AccountID:    accID,
				ExternalID:   ext, // SAME identity across all goroutines
				Email:        email,
				DisplayName:  domain.DisplayName("Racing"),
				InviteStatus: domain.InviteStatusActive,
			}); err != nil {
				atomic.AddInt64(&failures, 1)
				mu.Lock()
				loserErrs = append(loserErrs, err)
				mu.Unlock()
				return
			}
			if _, err := w.AccountsW().Insert(ctx, domain.Account{
				ID:          accID,
				Name:        domain.AccountName("racing-" + string(accID[len(accID)-6:])),
				OwnerUserID: uid,
				Labels:      domain.Labels{},
			}); err != nil {
				atomic.AddInt64(&failures, 1)
				return
			}
			if err := w.Commit(ctx); err != nil {
				atomic.AddInt64(&failures, 1)
				return
			}
			atomic.AddInt64(&successes, 1)
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(1), atomic.LoadInt64(&successes),
		"exactly one concurrent first-login bootstraps the ACTIVE identity row")
	assert.Equal(t, int64(N-1), atomic.LoadInt64(&failures),
		"the rest lose the race on the ACTIVE-external_id UNIQUE guard")

	// Losers map to the ErrAlreadyExists sentinel with the canonical Kachō
	// message — the raw pgx constraint name must NEVER leak (data-integrity.md;
	// migration 0011 added users_active_external_id_uniq to errors.uniqueText).
	for _, e := range loserErrs {
		assert.True(t, stderrors.Is(e, iamerr.ErrAlreadyExists),
			"loser error maps to ErrAlreadyExists, got %v", e)
		assert.NotContains(t, e.Error(), "users_active_external_id_uniq",
			"canonical message must not leak the pgx constraint name")
		assert.NotContains(t, e.Error(), "duplicate key value",
			"canonical message must not leak raw pgx text")
	}

	// Exactly one ACTIVE row for the identity globally.
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	actives, err := rd.Users().FindActiveByExternalID(ctx, ext)
	require.NoError(t, err)
	assert.Len(t, actives, 1, "one ACTIVE identity row globally (no duplicates)")
}
