// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// sa_key_n_to_one_integration_test.go — проверяет релакс SA-key 1:1 → N:1
// (миграция 0047 DROP UNIQUE service_account_oauth_clients_sva_unique). До релакса
// вторая Issue на один ServiceAccount падала 23505; теперь создаётся вторая
// независимая строка soc_. Трассируется в acceptance account-tokens-tab-SA-12.
//
// Запуск: `go test ./internal/repo/kacho/pg/... -run SAKeyNToOne`. Skip с -short.

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func TestSAKeyNToOne_ConcurrentIssue_NoSvaUnique(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	uid := mustSeedUser(t, ctx, pool, "sakn1")
	var accID string
	require.NoError(t, pool.QueryRow(ctx, `SELECT account_id FROM users WHERE id = $1`, string(uid)).Scan(&accID))

	svaID := domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount))
	_, err = pool.Exec(ctx, `INSERT INTO service_accounts (id, account_id, name) VALUES ($1, $2, $3)`,
		string(svaID), accID, "ci-builder")
	require.NoError(t, err)

	repo := kachopg.NewSAOAuthClientRepo(pool)
	txb := kachopg.NewPoolTxBeginner(pool)

	newRow := func(suffix string) domain.ServiceAccountOAuthClient {
		return domain.ServiceAccountOAuthClient{
			ID:              domain.SAOAuthClientID(domain.NewKac127ID(domain.PrefixSAOAuthClient)),
			SvaID:           svaID,
			OAuthClientID:   domain.OAuthClientID("hydra-soc-" + suffix),
			Description:     domain.Description("ci key " + suffix),
			CreatedByUserID: uid,
			PublicKeyPEM:    "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
			KeyAlgorithm:    "ES256",
		}
	}
	insert := func(c domain.ServiceAccountOAuthClient) error {
		tx, err := txb.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := repo.Insert(ctx, tx, c); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		return tx.Commit(ctx)
	}

	// Две ПАРАЛЛЕЛЬНЫЕ Issue на один sva → обе должны создать независимые строки.
	const n = 6
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = insert(newRow(fmt.Sprintf("%d", i)))
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		require.NoError(t, e, "concurrent SA Issue %d must succeed (sva_unique dropped, N:1)", i)
	}

	list, _, err := repo.List(ctx, svaID, "", 1000)
	require.NoError(t, err)
	assert.Len(t, list, n, "N:1 — %d независимых ключей на один ServiceAccount", n)
}
