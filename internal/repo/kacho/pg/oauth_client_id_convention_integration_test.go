// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// oauth_client_id_convention_integration_test.go — testcontainers Postgres 16.
// Миграция 0052 ослабляет CHECK на id обеих token-таблиц: теперь принимаются ОБА
// формата — legacy `<prefix>_<17-crockford>` (id существующих строк immutable) и
// новый corelib `<prefix><17-crockford>` (`ids.NewID`). Malformed id всё ещё
// отвергается CHECK.
//
// Покрыто (SA + user):
//   - новый corelib-формат `soc<17>`/`uoc<17>` (без `_`) → INSERT успешен.
//   - legacy `soc_<...>`/`uoc_<...>` (с `_`) → INSERT успешен (back-compat).
//   - malformed id → 23514 CHECK violation.
//
// Запуск: `go test ./internal/repo/kacho/pg/... -run OAuthClientIDConvention`. Skip с -short.

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func TestOAuthClientIDConvention_SA_BothFormatsInsert(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	uid := mustSeedUser(t, ctx, pool, "socidconv")
	var accID string
	require.NoError(t, pool.QueryRow(ctx, `SELECT account_id FROM users WHERE id = $1`, string(uid)).Scan(&accID))

	svaID := domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount))
	_, err = pool.Exec(ctx, `INSERT INTO service_accounts (id, account_id, name) VALUES ($1, $2, $3)`,
		string(svaID), accID, "ci-builder")
	require.NoError(t, err)

	insertSA := func(id string) error {
		_, e := pool.Exec(ctx, `
			INSERT INTO service_account_oauth_clients
			  (id, sva_id, hydra_client_id, description, created_by_user_id, public_key_pem, key_algorithm)
			VALUES ($1, $2, $3, '', $4, '', 'ES256')`,
			id, string(svaID), "hydra-"+id, string(uid))
		return e
	}

	// New corelib format (no underscore) — must be accepted post-0052.
	newID := ids.NewID(domain.PrefixSAOAuthClient)
	require.NotContains(t, newID, "_", "corelib id must not contain underscore")
	assert.NoError(t, insertSA(newID), "new-format id must INSERT under relaxed CHECK")

	// Legacy underscore format — must still be accepted (back-compat, immutable ids).
	legacyID := domain.NewKac127ID(domain.PrefixSAOAuthClient)
	require.True(t, strings.Contains(legacyID, "_"), "legacy id carries underscore")
	assert.NoError(t, insertSA(legacyID), "legacy-format id must still INSERT (back-compat)")

	// Malformed id — CHECK must reject.
	err = insertSA("not-a-valid-token-id")
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "check", "malformed id must trip the CHECK constraint")
}

func TestOAuthClientIDConvention_User_BothFormatsInsert(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	uid := mustSeedUser(t, ctx, pool, "uocidconv")

	insertUser := func(id string) error {
		_, e := pool.Exec(ctx, `
			INSERT INTO user_oauth_clients
			  (id, user_id, hydra_client_id, description, created_by_user_id, public_key_pem, key_algorithm)
			VALUES ($1, $2, $3, '', $4, '', 'ES256')`,
			id, string(uid), "hydra-"+id, string(uid))
		return e
	}

	newID := ids.NewID(domain.PrefixUserOAuthClient)
	require.NotContains(t, newID, "_", "corelib id must not contain underscore")
	assert.NoError(t, insertUser(newID), "new-format id must INSERT under relaxed CHECK")

	legacyID := domain.NewKac127ID(domain.PrefixUserOAuthClient)
	require.True(t, strings.Contains(legacyID, "_"), "legacy id carries underscore")
	assert.NoError(t, insertUser(legacyID), "legacy-format id must still INSERT (back-compat)")

	err = insertUser("garbage")
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "check", "malformed id must trip the CHECK constraint")
}
