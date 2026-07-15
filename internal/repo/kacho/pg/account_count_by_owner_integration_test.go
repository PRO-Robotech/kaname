// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// account_count_by_owner_integration_test.go — CountAccountsByOwner reader method.
//
// CountAccountsByOwner(ctx, ownerUserID) reports how many accounts a given user
// owns (accounts.owner_user_id == userID). It backs the "owns-zero-accounts"
// bootstrap gate (an invited+activated user with 0 owned accounts gets a personal
// default Account + "default" Project bootstrapped). Reads an EXISTING column
// (accounts.owner_user_id) — no migration.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func TestAccountCountByOwner_RC5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	// owner with one account.
	ownerID, _ := bootstrapAdmin(t, ctx, repo, "cbo1")
	// a user that owns NO account (invitee-like: row exists, owns nothing).
	inviteeOwner, _ := bootstrapAdmin(t, ctx, repo, "cbo2") // helper for an active row
	// give inviteeOwner a fresh user that owns zero accounts by inserting only the user.
	zeroOwner := domain.UserID(ids.NewID(domain.PrefixUser))
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		// bootstrap a row + account so the FK on users is satisfiable; then this
		// user (zeroOwner) is NOT the owner of any account — owns-zero.
		_ = inviteeOwner
		accID := domain.AccountID(ids.NewID(domain.PrefixAccount))
		_, err = w.UsersW().InsertActive(ctx, domain.User{
			ID:           zeroOwner,
			AccountID:    accID, // member of accID, but NOT its owner
			ExternalID:   domain.ExternalSubject("ext-cbo-zero-" + string(zeroOwner)),
			Email:        "zero-cbo@example.com",
			DisplayName:  "Zero Owner",
			InviteStatus: domain.InviteStatusActive,
		})
		require.NoError(t, err)
		_, err = w.AccountsW().Insert(ctx, domain.Account{
			ID:          accID,
			Name:        domain.AccountName("acc-cbo-zero-" + shortTail(string(accID))),
			OwnerUserID: ownerID, // owned by ownerID, NOT zeroOwner
			Labels:      domain.Labels{},
		})
		require.NoError(t, err)
		require.NoError(t, w.Commit(ctx))
	}

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// ownerID owns 2 accounts (its own bootstrapAdmin account + the acc-cbo-zero one).
	nOwner, err := rd.Accounts().CountAccountsByOwner(ctx, ownerID)
	require.NoError(t, err)
	require.Equal(t, 2, nOwner, "ownerID owns its bootstrap account + the explicitly-owned one")

	// zeroOwner owns none.
	nZero, err := rd.Accounts().CountAccountsByOwner(ctx, zeroOwner)
	require.NoError(t, err)
	require.Equal(t, 0, nZero, "zeroOwner owns no account")

	// a totally unknown user owns none (no error).
	nUnknown, err := rd.Accounts().CountAccountsByOwner(ctx, domain.UserID("usr00000000000unknown"))
	require.NoError(t, err)
	require.Equal(t, 0, nUnknown, "unknown user owns no account")
}

func shortTail(id string) string {
	if len(id) <= 6 {
		return id
	}
	return id[len(id)-6:]
}
