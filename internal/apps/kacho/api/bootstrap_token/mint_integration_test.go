// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package bootstrap_token

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// countingHydra is a concurrency-safe OAuthClientAdmin recording how many times
// the external Hydra create was invoked (IBT-03: at most once).
type countingHydra struct {
	mu    sync.Mutex
	calls int
}

func (h *countingHydra) CreateOAuthClient(_ context.Context, req clients.CreateOAuthClientRequest) (clients.HydraOAuthClient, error) {
	h.mu.Lock()
	h.calls++
	h.mu.Unlock()
	return clients.HydraOAuthClient{ClientID: req.ClientID}, nil
}

func (h *countingHydra) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

func buildIntegrationUseCase(t *testing.T, dsn string, hydra OAuthClientAdmin, ex TokenExchanger) *MintUseCase {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	store := kachopg.NewBootstrapStore(pool)
	txb := kachopg.NewPoolTxBeginner(pool)
	uc := NewMintUseCase(store, txb, hydra, ex, Config{
		SigningKeyPEM:     genES256PEM(t),
		AssertionAudience: "https://hydra.kacho.cloud/oauth2/token",
		GatewayAudience:   "https://api.kacho.cloud",
	})
	return uc
}

// countRows helper.
func countRows(t *testing.T, dsn, query string, args ...any) int {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	var n int
	require.NoError(t, pool.QueryRow(ctx, query, args...).Scan(&n))
	return n
}

// ── IBT-01: happy path — first call provisions + mints ──────────────────────────

func TestMintBootstrapToken_FirstCall_ProvisionsAndMints(t *testing.T) {
	dsn := setupTestDB(t)
	id := DeriveIdentity()

	// Migration 0058 pre-seeds the SA + cluster system_admin grant + fga tuple.
	require.Equal(t, 1, countRows(t, dsn, `SELECT count(*) FROM service_accounts WHERE id=$1`, id.SvaID),
		"bootstrap SA seeded by migration 0058")
	require.Equal(t, 1, countRows(t, dsn,
		`SELECT count(*) FROM cluster_admin_grants WHERE subject_type='service_account' AND subject_id=$1 AND granted_until IS NULL`, id.SvaID),
		"cluster system_admin grant on the bootstrap SA seeded")
	require.Equal(t, 1, countRows(t, dsn,
		`SELECT count(*) FROM fga_outbox WHERE payload->>'user'=$1 AND payload->>'relation'='system_admin' AND payload->>'object'='cluster:cluster_kacho_root'`,
		"service_account:"+id.SvaID), "fga owner-tuple intent emitted")
	// Not yet provisioned at runtime.
	require.Equal(t, 0, countRows(t, dsn, `SELECT count(*) FROM service_account_oauth_clients WHERE sva_id=$1`, id.SvaID))

	hydra := &countingHydra{}
	ex := &fakeExchanger{out: ExchangeOutput{AccessToken: "rs256.jwt.token", ExpiresIn: 900}}
	uc := buildIntegrationUseCase(t, dsn, hydra, ex)

	res, err := uc.Execute(context.Background(), 0)
	require.NoError(t, err)
	require.Equal(t, "rs256.jwt.token", res.AccessToken)
	require.Equal(t, "Bearer", res.TokenType)
	require.Positive(t, res.ExpiresIn)
	require.Equal(t, id.SvaID, res.PrincipalID)
	require.False(t, res.ExpiresAt.IsZero())
	require.False(t, res.IssuedAt.IsZero())

	require.Equal(t, 1, hydra.count(), "Hydra OAuth client created once")
	// Runtime mapping now exists (enrichment resolves client_id → bootstrap SA).
	require.Equal(t, 1, countRows(t, dsn, `SELECT count(*) FROM service_account_oauth_clients WHERE sva_id=$1`, id.SvaID))
	require.Equal(t, 1, countRows(t, dsn,
		`SELECT count(*) FROM service_account_oauth_clients WHERE hydra_client_id=$1 AND key_algorithm='ES256'`, id.ClientID))
	// The exchange requested the gateway audience (not registry.*).
	require.Equal(t, "https://api.kacho.cloud", ex.lastAudience)
}

// ── IBT-02: idempotent reuse ────────────────────────────────────────────────────

func TestMintBootstrapToken_Idempotent_ReusesSA(t *testing.T) {
	dsn := setupTestDB(t)
	id := DeriveIdentity()
	hydra := &countingHydra{}
	uc := buildIntegrationUseCase(t, dsn, hydra,
		&fakeExchanger{out: ExchangeOutput{AccessToken: "tok1", ExpiresIn: 900}})

	first, err := uc.Execute(context.Background(), 0)
	require.NoError(t, err)

	uc2 := buildIntegrationUseCase(t, dsn, hydra,
		&fakeExchanger{out: ExchangeOutput{AccessToken: "tok2-fresh", ExpiresIn: 900}})
	second, err := uc2.Execute(context.Background(), 0)
	require.NoError(t, err)

	require.Equal(t, first.PrincipalID, second.PrincipalID, "same bootstrap SA")
	require.Equal(t, "tok2-fresh", second.AccessToken, "a fresh token is minted for the same principal")
	require.Equal(t, 1, hydra.count(), "no new Hydra client on reuse")
	require.Equal(t, 1, countRows(t, dsn, `SELECT count(*) FROM service_account_oauth_clients WHERE sva_id=$1`, id.SvaID),
		"exactly one mapping row (singleton invariant)")
}

// ── IBT-03: concurrency — exactly one bootstrap SA / one Hydra client ────────────

func TestMintBootstrapToken_Concurrent_SingleBootstrapSA(t *testing.T) {
	dsn := setupTestDB(t)
	id := DeriveIdentity()
	hydra := &countingHydra{}

	const n = 8
	results := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Each goroutine gets its own use-case (its own pool) — realistic
			// concurrent first-callers racing the singleton provisioning.
			uc := buildIntegrationUseCase(t, dsn, hydra,
				&fakeExchanger{out: ExchangeOutput{AccessToken: "tok", ExpiresIn: 900}})
			<-start
			res, err := uc.Execute(context.Background(), 0)
			errs[i] = err
			if err == nil {
				results[i] = res.PrincipalID
			}
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 0; i < n; i++ {
		require.NoError(t, errs[i], "goroutine %d", i)
		require.Equal(t, id.SvaID, results[i], "all callers see the same bootstrap principal")
	}
	// DB-singleton: exactly one mapping row; external Hydra client created at most once.
	require.Equal(t, 1, countRows(t, dsn, `SELECT count(*) FROM service_account_oauth_clients WHERE sva_id=$1`, id.SvaID),
		"exactly one bootstrap mapping row under concurrency (no dup / no constraint-INTERNAL-leak)")
	require.Equal(t, 1, hydra.count(), "external Hydra client provisioned at most once under concurrency (IBT-03)")
}
