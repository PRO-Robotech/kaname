// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// service_account_setenabled_integration_test.go — the state a caller sets is
// the state every reader afterwards reports.
//
// `service_accounts.enabled` decides whether a service account may
// authenticate, and the sibling file in this package pins that both reads carry
// it out of the row. Neither of those facts is worth anything while the column
// has no writer: a value that only ever holds its default is not a control, it
// is a constant, and the only way to move it is a hand-written statement
// against the database.
//
// So what is asserted here is the round trip, and against BOTH readers
// separately — the tx-scoped aggregate (what an operator sees) and the
// pool-scoped read consulted while a credential is minted. A writer that
// satisfied one and not the other would leave the operator looking at a state
// the minting path does not act on, which is the same defect wearing a
// different sleeve.
//
// Idempotence is asserted, not assumed. Disabling an account that is already
// disabled is a request for a STATE, not a transition; refusing the repeat
// would make the safe direction of this control the one that fails under
// retry.
//
// Run: `go test ./internal/repo/kaname/pg/... -run ServiceAccountSetEnabled`. Skipped with -short.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func TestServiceAccountSetEnabled_RoundTripsThroughBothReaders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "sasete")
	acc := seedAccount(t, ctx, repo, "acc-sasete", uid)
	id := seedSAWithEnabled(t, ctx, pool, acc.ID, "sa-round-trip", true)

	// Disable.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	out, err := w.ServiceAccountsW().SetEnabled(ctx, id, false)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	assert.False(t, out.Enabled, "the row returned by the write must already carry the new state")
	assert.Equal(t, id, out.ID)
	assert.Equal(t, acc.ID, out.AccountID,
		"the write returns the whole row so an audit record can name the account without a second read")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	got, err := rd.ServiceAccounts().Get(ctx, id)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)
	assert.False(t, got.Enabled, "the operator-facing read must report the state that was set")

	saRepo := kanamepg.NewSAOAuthClientRepo(pool)
	hookView, err := saRepo.GetServiceAccount(ctx, id)
	require.NoError(t, err)
	assert.False(t, hookView.MayAuthenticate(),
		"the read consulted while a token is minted must report the state that was set — this is "+
			"the whole point of the column, and the half a writer could miss while looking correct")

	_, mayAuth, err := saRepo.AccountForServiceAccount(ctx, id)
	require.NoError(t, err)
	assert.False(t, mayAuth,
		"the read behind key issuance must report it too; it answers a different query and can "+
			"drift from the one above")

	// Enable again — the control has to work in both directions or it is a
	// one-way door, and an operator who disables by mistake has no way back.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	back, err := w2.ServiceAccountsW().SetEnabled(ctx, id, true)
	require.NoError(t, err)
	require.NoError(t, w2.Commit(ctx))
	assert.True(t, back.Enabled)

	_, mayAuthAgain, err := saRepo.AccountForServiceAccount(ctx, id)
	require.NoError(t, err)
	assert.True(t, mayAuthAgain, "re-enabling must restore the state every reader reports")
}

func TestServiceAccountSetEnabled_IsIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "sasetidem")
	acc := seedAccount(t, ctx, repo, "acc-sasetidem", uid)
	id := seedSAWithEnabled(t, ctx, pool, acc.ID, "sa-idempotent", false)

	// Already false. Asking for false again is asking for a state that already
	// holds, and the answer is that it holds.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	out, err := w.ServiceAccountsW().SetEnabled(ctx, id, false)
	require.NoError(t, err, "setting the state an account is already in must succeed, not fail")
	require.NoError(t, w.Commit(ctx))
	assert.False(t, out.Enabled)
}

func TestServiceAccountSetEnabled_MissingRow_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()

	_, err = w.ServiceAccountsW().SetEnabled(ctx, domain.ServiceAccountID("sva00000000000000000"), false)
	require.Error(t, err)
	assert.True(t, errors.Is(err, iamerr.ErrNotFound),
		"a well-formed id with no row behind it is this service's own miss — NOT_FOUND, contract tone")
	assert.Contains(t, err.Error(), "ServiceAccount sva00000000000000000 not found")
}
