// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// service_account_enabled_integration_test.go — the row that comes back carries
// the state the row actually holds.
//
// `service_accounts.enabled` decides whether a service account may authenticate.
// A verdict built on it is only worth as much as the read underneath: a SELECT
// that omits the column hands every caller a zero value, so the field reads
// false for an enabled account and false for a disabled one alike. Nothing in
// the verdict can tell those apart, and no test of the verdict can either —
// which is why this property is pinned on its own, BEFORE any deny branch
// exists to lean on it.
//
// Two reads answer for a service account and both are covered here, because
// both feed a decision:
//
//   - the tx-scoped aggregate reader (Get / List) — the public projection, and
//     the only way an operator can see the state they set;
//   - the pool-scoped reader behind the token hook — the one consulted while a
//     token is being minted.
//
// The rows are written with plain SQL rather than the writer, so what is
// asserted is what the DATABASE holds, not what some other Go path chose to
// pass along.
//
// Run: `go test ./internal/repo/kacho/pg/... -run ServiceAccountEnabled`. Skipped with -short.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/service_account"
)

// seedSAWithEnabled writes a service account row directly, stating `enabled`
// explicitly. Direct SQL on purpose: the assertion is about what the read
// carries out of the table, so the value must get in without passing through
// the code under test.
func seedSAWithEnabled(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	accID domain.AccountID, name string, enabled bool) domain.ServiceAccountID {
	t.Helper()
	id := domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount))
	_, err := pool.Exec(ctx,
		`INSERT INTO service_accounts (id, account_id, name, enabled) VALUES ($1, $2, $3, $4)`,
		string(id), string(accID), name, enabled)
	require.NoError(t, err)
	return id
}

func TestServiceAccountEnabled_AggregateRead_CarriesTheRowsState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "saenb")
	acc := seedAccount(t, ctx, repo, "acc-saenb", uid)

	disabledID := seedSAWithEnabled(t, ctx, pool, acc.ID, "sa-disabled", false)
	enabledID := seedSAWithEnabled(t, ctx, pool, acc.ID, "sa-enabled", true)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	disabled, err := rd.ServiceAccounts().Get(ctx, disabledID)
	require.NoError(t, err)
	assert.False(t, disabled.Enabled,
		"the row says enabled=false; a read that does not select the column reports false "+
			"for every account and cannot be told apart from this one")

	enabled, err := rd.ServiceAccounts().Get(ctx, enabledID)
	require.NoError(t, err)
	assert.True(t, enabled.Enabled,
		"the row says enabled=true and the read must say so too — this is the assertion a "+
			"SELECT missing the column fails, and the one a verdict built on the field needs")

	// List answers for the same field, so the state is visible without fetching
	// each account one at a time.
	page, _, err := rd.ServiceAccounts().List(ctx, service_account.ListFilter{AccountID: acc.ID})
	require.NoError(t, err)
	seen := map[domain.ServiceAccountID]bool{}
	for _, sa := range page {
		seen[sa.ID] = sa.Enabled
	}
	require.Contains(t, seen, disabledID)
	require.Contains(t, seen, enabledID)
	assert.False(t, seen[disabledID], "List must carry the same state as Get")
	assert.True(t, seen[enabledID], "List must carry the same state as Get")
}

// The token hook resolves the service account through its own pool-scoped read.
// That read is the one a minting decision hangs on, so it gets its own proof
// rather than inheriting confidence from the aggregate reader above.
func TestServiceAccountEnabled_TokenHookRead_CarriesTheRowsState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "sahook")
	acc := seedAccount(t, ctx, repo, "acc-sahook", uid)

	disabledID := seedSAWithEnabled(t, ctx, pool, acc.ID, "hook-disabled", false)
	enabledID := seedSAWithEnabled(t, ctx, pool, acc.ID, "hook-enabled", true)

	saRepo := kachopg.NewSAOAuthClientRepo(pool)

	disabled, err := saRepo.GetServiceAccount(ctx, disabledID)
	require.NoError(t, err)
	assert.Equal(t, disabledID, disabled.ID)
	assert.False(t, disabled.Enabled,
		"the read behind the token hook must carry enabled=false out of the row; while it "+
			"did not, the field was false for everyone and no minting decision could use it")

	enabled, err := saRepo.GetServiceAccount(ctx, enabledID)
	require.NoError(t, err)
	assert.True(t, enabled.Enabled,
		"and enabled=true for an account that is enabled — without this half, a deny branch "+
			"reading the field would refuse every service account there is")
	assert.Equal(t, acc.ID, enabled.AccountID,
		"the fields the claims are built from keep coming back unchanged")
}
