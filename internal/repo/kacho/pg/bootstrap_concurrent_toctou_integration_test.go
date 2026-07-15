// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// bootstrap_concurrent_toctou_integration_test.go — RC-5 bootstrap concurrency
// guard (ban #10: a within-service invariant must be DB-level/atomic, not a
// software check-then-act).
//
// BUG (5th audit, DATA-medium): UpsertFromIdentityUseCase gated the personal-
// resource bootstrap with a cross-transaction TOCTOU — countOwnedAccounts()
// opened its OWN reader-tx (SELECT count(*) FROM accounts WHERE owner_user_id=$1),
// rolled it back, and THEN inserted a personal Account/Project/owner-binding in a
// SEPARATE writer-tx when the count was 0. For the newIdentity=false path (an
// existing ACTIVE user who currently owns zero accounts — e.g. an activated
// invitee) NOTHING in the writer-tx serialized concurrent callers: the account
// name is a random 'personal-cloud-<rand>' tail (accounts_name_unique never
// fires) and accounts.owner_user_id has only a non-unique btree index + an
// ON-DELETE-RESTRICT FK (no cardinality bound). Two concurrent bootstraps for the
// SAME resolved user-id both read count==0 and both INSERT a distinct personal
// account → the user ends up owning multiple personal accounts + default projects
// + duplicate owner bindings, permanently violating one-personal-account-per-user.
//
// FIX: inside the bootstrap writer-tx take a tx-scoped
// pg_advisory_xact_lock(hashtext('iam:bootstrap:'||userID)) FIRST and RE-CHECK the
// owned-account count in the SAME tx before inserting; the loser blocks until the
// winner commits, sees count>0, and returns the already-bootstrapped user without
// creating a duplicate.
//
// RED before the fix (N concurrent bootstraps → N owned accounts), GREEN after
// (exactly ONE owned account; every Operation still succeeds).
//
// Run: `make test` (testcontainers + Docker). Skipped under -short.

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	userapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// TestBootstrapConcurrent_TOCTOU_SingleOwnedAccount — N concurrent
// UpsertFromIdentity calls for one already-ACTIVE, zero-account user must
// bootstrap EXACTLY ONE personal account (not N).
func TestBootstrapConcurrent_TOCTOU_SingleOwnedAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	const ext = "ext_BOOT_conc"
	const email = "boot-conc@example.com"

	// Seed a PENDING invitee under an inviter-account, then ACTIVATE it directly
	// (no bootstrap) so we have an ACTIVE user owning ZERO accounts — the exact
	// newIdentity=false path the TOCTOU exposes.
	_, _, inviteeID := seedInviterAndPendingInvite(t, ctx, repo, "conc", email)
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.UsersW().ActivateInvite(ctx, inviteeID,
		domain.ExternalSubject(ext), domain.DisplayName("Bootstrap Concurrent"))
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	require.Equal(t, 0, ownedAccountCount(t, ctx, pool, string(inviteeID)),
		"pre-state: activated invitee owns zero accounts")

	// Fire N concurrent bootstraps, released together by a start barrier.
	const n = 6
	uc := userapp.NewUpsertFromIdentityUseCase(repo, opsRepo)
	start := make(chan struct{})
	var wg sync.WaitGroup
	opIDs := make([]string, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start
			op, execErr := uc.Execute(ctx, userapp.UpsertFromIdentityInput{
				ExternalID:  domain.ExternalSubject(ext),
				Email:       domain.Email(email),
				DisplayName: domain.DisplayName("Bootstrap Concurrent"),
			})
			require.NoError(t, execErr)
			opIDs[idx] = op.ID
		}(i)
	}
	close(start)
	wg.Wait()

	// Every Operation must terminate successfully (the loser returns the already-
	// bootstrapped user, it does not error).
	for _, id := range opIDs {
		done := awaitOp(t, ctx, opsRepo, id)
		require.Nil(t, done.Error, "concurrent UpsertFromIdentity must succeed: %v", done.Error)
	}

	assert.Equal(t, 1, ownedAccountCount(t, ctx, pool, string(inviteeID)),
		"exactly ONE personal account after N concurrent bootstraps (TOCTOU closed)")

	// And exactly one "default" project across the (single) owned account.
	var prjCount int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.projects p
		  JOIN kacho_iam.accounts a ON a.id = p.account_id
		 WHERE a.owner_user_id = $1 AND p.name = 'default'`,
		string(inviteeID)).Scan(&prjCount))
	assert.Equal(t, 1, prjCount, "exactly one default project (no duplicate bootstrap)")
}
