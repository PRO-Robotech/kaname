// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap_token

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
)

// countingMinter — НАШ подписант, считающий выпуски, потокобезопасно.
//
// Он же и есть доказательство «поставщика нет вовсе»: у use-case не осталось ни
// одного порта, которым внешнюю сторону можно было бы подать, поэтому подставить
// её в этот прогон НЕЛЬЗЯ — не «мы не стали», а «нечем».
type countingMinter struct {
	mu    sync.Mutex
	calls int
	token string
}

func (m *countingMinter) MintToken(_ context.Context, in MintInput) (MintOutput, error) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	tok := m.token
	if tok == "" {
		tok = "signed.by.us"
	}
	issued := fixedNow
	return MintOutput{AccessToken: tok, IssuedAt: issued, ExpiresAt: issued.Add(in.TTL)}, nil
}

func (m *countingMinter) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func buildIntegrationUseCase(t *testing.T, dsn string, minter LocalMinter) *MintUseCase {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	store := kachopg.NewBootstrapStore(pool)
	txb := kachopg.NewPoolTxBeginner(pool)
	return NewMintUseCase(store, txb, minter, Config{
		SigningKeyPEM:   genES256PEM(t),
		GatewayAudience: "https://api.kacho.cloud",
	})
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

	minter := &countingMinter{token: "our.jwt.token"}
	uc := buildIntegrationUseCase(t, dsn, minter)

	res, err := uc.Execute(context.Background())
	require.NoError(t, err)
	require.Equal(t, "our.jwt.token", res.AccessToken)
	require.Equal(t, "Bearer", res.TokenType)
	require.Positive(t, res.ExpiresIn)
	require.Equal(t, id.SvaID, res.PrincipalID)
	require.False(t, res.ExpiresAt.IsZero())
	require.False(t, res.IssuedAt.IsZero())

	require.Equal(t, 1, minter.count(), "удостоверение выпущено ровно один раз")
	// Runtime mapping now exists (enrichment resolves our client id → bootstrap SA).
	require.Equal(t, 1, countRows(t, dsn, `SELECT count(*) FROM service_account_oauth_clients WHERE sva_id=$1`, id.SvaID))
	require.Equal(t, 1, countRows(t, dsn,
		`SELECT count(*) FROM service_account_oauth_clients WHERE hydra_client_id=$1 AND key_algorithm='ES256'`, id.ClientID))
}

// ── IBT-02: idempotent reuse ────────────────────────────────────────────────────

func TestMintBootstrapToken_Idempotent_ReusesSA(t *testing.T) {
	dsn := setupTestDB(t)
	id := DeriveIdentity()
	uc := buildIntegrationUseCase(t, dsn, &countingMinter{token: "tok1"})

	first, err := uc.Execute(context.Background())
	require.NoError(t, err)

	uc2 := buildIntegrationUseCase(t, dsn, &countingMinter{token: "tok2-fresh"})
	second, err := uc2.Execute(context.Background())
	require.NoError(t, err)

	require.Equal(t, first.PrincipalID, second.PrincipalID, "same bootstrap SA")
	require.Equal(t, "tok2-fresh", second.AccessToken, "a fresh token is minted for the same principal")
	require.Equal(t, 1, countRows(t, dsn, `SELECT count(*) FROM service_account_oauth_clients WHERE sva_id=$1`, id.SvaID),
		"exactly one mapping row (singleton invariant)")
}

// ── IBT-03: concurrency — exactly one bootstrap SA / one Hydra client ────────────

func TestMintBootstrapToken_Concurrent_SingleBootstrapSA(t *testing.T) {
	dsn := setupTestDB(t)
	id := DeriveIdentity()
	minter := &countingMinter{}

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
			uc := buildIntegrationUseCase(t, dsn, minter)
			<-start
			res, err := uc.Execute(context.Background())
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
	// DB-singleton: exactly one mapping row under concurrency.
	//
	// Замок консультации остаётся и после снятия внешней стороны, но обоснование
	// у него теперь СВОЁ: он сериализует запись строки соответствия, и проигравшие
	// читают строку победителя вместо того, чтобы столкнуться на UNIQUE(sva_id).
	// Прежде здесь стояло «внешний клиент заводится не более раза» — предмет того
	// утверждения снят вместе с дорогой к поставщику (задача #1119).
	require.Equal(t, 1, countRows(t, dsn, `SELECT count(*) FROM service_account_oauth_clients WHERE sva_id=$1`, id.SvaID),
		"exactly one bootstrap mapping row under concurrency (no dup / no constraint-INTERNAL-leak)")
	require.Equal(t, n, minter.count(), "каждый вызывающий получил СВОЁ свежее удостоверение")
}
