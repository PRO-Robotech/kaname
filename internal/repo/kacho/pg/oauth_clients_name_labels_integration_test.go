// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// oauth_clients_name_labels_integration_test.go — testcontainers Postgres 16
// integration-тесты create-only полей name + labels на обеих token-таблицах
// (service_account_oauth_clients + user_oauth_clients). Поля выставляются на
// Insert, immutable, и возвращаются на Get/List round-trip.
//
// Покрыто:
//   - SA name+labels persist на Insert → возвращаются Get + List.
//   - User name+labels persist на Insert → возвращаются Get + List.
//   - CHECK kacho_labels_valid: невалидные labels (>64 пар) → 23514 → ErrInvalidArg.
//
// Запуск: `go test ./internal/repo/kacho/pg/... -run OAuthClientNameLabels`. Skip с -short.

import (
	"context"
	stderrors "errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func TestOAuthClientNameLabels_SA_PersistOnInsert_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	uid := mustSeedUser(t, ctx, pool, "socnl")
	var accID string
	require.NoError(t, pool.QueryRow(ctx, `SELECT account_id FROM users WHERE id = $1`, string(uid)).Scan(&accID))

	svaID := domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount))
	_, err = pool.Exec(ctx, `INSERT INTO service_accounts (id, account_id, name) VALUES ($1, $2, $3)`,
		string(svaID), accID, "ci-builder")
	require.NoError(t, err)

	repo := kachopg.NewSAOAuthClientRepo(pool)
	txb := kachopg.NewPoolTxBeginner(pool)

	row := domain.ServiceAccountOAuthClient{
		ID:              domain.SAOAuthClientID(domain.NewKac127ID(domain.PrefixSAOAuthClient)),
		SvaID:           svaID,
		OAuthClientID:   domain.OAuthClientID("hydra-soc-nl"),
		Description:     domain.Description("ci key"),
		CreatedByUserID: uid,
		PublicKeyPEM:    "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
		KeyAlgorithm:    "ES256",
		Name:            "prod-ci-key",
		Labels:          domain.Labels{"env": "prod", "team": "platform"},
	}

	tx, err := txb.Begin(ctx)
	require.NoError(t, err)
	persisted, err := repo.Insert(ctx, tx, row)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	assert.Equal(t, "prod-ci-key", string(persisted.Name))
	assert.Equal(t, domain.Labels{"env": "prod", "team": "platform"}, persisted.Labels)

	got, err := repo.Get(ctx, row.ID)
	require.NoError(t, err)
	assert.Equal(t, "prod-ci-key", string(got.Name), "name persisted + returned on Get")
	assert.Equal(t, domain.Labels{"env": "prod", "team": "platform"}, got.Labels, "labels persisted + returned on Get")

	list, _, err := repo.List(ctx, svaID, "", 100)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "prod-ci-key", string(list[0].Name), "name returned on List")
	assert.Equal(t, domain.Labels{"env": "prod", "team": "platform"}, list[0].Labels, "labels returned on List")
}

func TestOAuthClientNameLabels_SA_EmptyDefaults(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	uid := mustSeedUser(t, ctx, pool, "socnldef")
	var accID string
	require.NoError(t, pool.QueryRow(ctx, `SELECT account_id FROM users WHERE id = $1`, string(uid)).Scan(&accID))

	svaID := domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount))
	_, err = pool.Exec(ctx, `INSERT INTO service_accounts (id, account_id, name) VALUES ($1, $2, $3)`,
		string(svaID), accID, "ci-builder")
	require.NoError(t, err)

	repo := kachopg.NewSAOAuthClientRepo(pool)
	txb := kachopg.NewPoolTxBeginner(pool)

	// name/labels omitted → DEFAULT '' / '{}' — round-trips as empty (not NULL).
	row := domain.ServiceAccountOAuthClient{
		ID:              domain.SAOAuthClientID(domain.NewKac127ID(domain.PrefixSAOAuthClient)),
		SvaID:           svaID,
		OAuthClientID:   domain.OAuthClientID("hydra-soc-def"),
		Description:     domain.Description("ci key no meta"),
		CreatedByUserID: uid,
		PublicKeyPEM:    "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
		KeyAlgorithm:    "ES256",
	}
	tx, err := txb.Begin(ctx)
	require.NoError(t, err)
	_, err = repo.Insert(ctx, tx, row)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	got, err := repo.Get(ctx, row.ID)
	require.NoError(t, err)
	assert.Equal(t, "", string(got.Name))
	assert.Equal(t, domain.Labels{}, got.Labels)
}

func TestOAuthClientNameLabels_User_PersistOnInsert_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	uid := mustSeedUser(t, ctx, pool, "uocnl")
	repo := kachopg.NewUserOAuthClientRepo(pool)
	txb := kachopg.NewPoolTxBeginner(pool)

	row := domain.UserOAuthClient{
		ID:              domain.UserOAuthClientID(domain.NewKac127ID(domain.PrefixUserOAuthClient)),
		UserID:          uid,
		OAuthClientID:   domain.OAuthClientID("hydra-uoc-nl"),
		Description:     domain.Description("laptop CLI"),
		CreatedByUserID: uid,
		PublicKeyPEM:    "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
		KeyAlgorithm:    "ES256",
		Name:            "laptop-token",
		Labels:          domain.Labels{"device": "macbook", "purpose": "cli"},
	}

	tx, err := txb.Begin(ctx)
	require.NoError(t, err)
	persisted, err := repo.Insert(ctx, tx, row)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	assert.Equal(t, "laptop-token", string(persisted.Name))
	assert.Equal(t, domain.Labels{"device": "macbook", "purpose": "cli"}, persisted.Labels)

	got, err := repo.Get(ctx, row.ID)
	require.NoError(t, err)
	assert.Equal(t, "laptop-token", string(got.Name), "name persisted + returned on Get")
	assert.Equal(t, domain.Labels{"device": "macbook", "purpose": "cli"}, got.Labels, "labels persisted + returned on Get")

	list, _, err := repo.List(ctx, uid, "", 100)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "laptop-token", string(list[0].Name), "name returned on List")
	assert.Equal(t, domain.Labels{"device": "macbook", "purpose": "cli"}, list[0].Labels, "labels returned on List")
}

func TestOAuthClientNameLabels_User_InvalidLabels_CheckViolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	uid := mustSeedUser(t, ctx, pool, "uocnlbad")
	repo := kachopg.NewUserOAuthClientRepo(pool)
	txb := kachopg.NewPoolTxBeginner(pool)

	// >64 label pairs → kacho_labels_valid CHECK violation (23514 → ErrInvalidArg).
	tooMany := domain.Labels{}
	for i := 0; i < 65; i++ {
		tooMany[domain.LabelKey(fmt.Sprintf("k%d", i))] = domain.LabelVal("v")
	}
	row := domain.UserOAuthClient{
		ID:              domain.UserOAuthClientID(domain.NewKac127ID(domain.PrefixUserOAuthClient)),
		UserID:          uid,
		OAuthClientID:   domain.OAuthClientID("hydra-uoc-bad"),
		Description:     domain.Description("bad labels"),
		CreatedByUserID: uid,
		PublicKeyPEM:    "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
		KeyAlgorithm:    "ES256",
		Labels:          tooMany,
	}
	tx, err := txb.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = repo.Insert(ctx, tx, row)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrInvalidArg),
		"CHECK kacho_labels_valid SQLSTATE 23514 → ErrInvalidArg, got %v", err)
}
