// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// user_oauth_clients_repos_integration_test.go — testcontainers Postgres 16
// integration-тесты репозитория персональных access-токенов пользователя
// (UserTokenService). Трассируются в acceptance-сценарии account-tokens-tab-USR-*.
//
// Покрыто:
//   - USR-01: Insert + Get + List round-trip (метаданные, без секрета в строке).
//   - USR-09(a): CHECK (expires_at > created_at) → 23514 → ErrInvalidArg.
//   - USR-09(b): две ПАРАЛЛЕЛЬНЫЕ Issue на одного user → две независимые строки
//     uoc_ (N:1), без коллизии, ни одна не «теряется».
//   - UNIQUE hydra_client_id: коллизия → 23505 → ErrAlreadyExists.
//   - USR-09(c): FK user_id → users ON DELETE CASCADE (удаление user снимает токены).
//   - USR-13: DeleteByID идемпотентен — повторный delete → ErrNotFound.
//
// Запуск: `go test ./internal/repo/kacho/pg/... -run UserOAuthClient`. Skip с -short.

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// newUOC — доменная строка токена под данного user, с уникальными id и
// hydra_client_id (по suffix).
func newUOC(userID domain.UserID, suffix string) domain.UserOAuthClient {
	return domain.UserOAuthClient{
		ID:              domain.UserOAuthClientID(domain.NewKac127ID(domain.PrefixUserOAuthClient)),
		UserID:          userID,
		OAuthClientID:   domain.OAuthClientID("hydra-uoc-" + suffix),
		Description:     domain.Description("laptop CLI " + suffix),
		CreatedByUserID: userID,
		PublicKeyPEM:    "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
		KeyAlgorithm:    "ES256",
	}
}

// insertUOC — Insert через writer-tx + Commit.
func insertUOC(t *testing.T, ctx context.Context, txb service.TxBeginner, repo *kachopg.UserOAuthClientRepo, c domain.UserOAuthClient) domain.UserOAuthClient {
	t.Helper()
	tx, err := txb.Begin(ctx)
	require.NoError(t, err)
	out, err := repo.Insert(ctx, tx, c)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return out
}

func TestUserOAuthClient_01_InsertGetList_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	uid := mustSeedUser(t, ctx, pool, "uoc01")
	repo := kachopg.NewUserOAuthClientRepo(pool)
	txb := kachopg.NewPoolTxBeginner(pool)

	row := newUOC(uid, "a")
	ttl := time.Now().Add(24 * time.Hour)
	row.ExpiresAt = &ttl
	persisted := insertUOC(t, ctx, txb, repo, row)
	assert.Equal(t, row.ID, persisted.ID)
	assert.Equal(t, uid, persisted.UserID)
	require.NotNil(t, persisted.ExpiresAt)
	assert.Nil(t, persisted.LastUsedAt, "last_used_at unset until first use")

	got, err := repo.Get(ctx, row.ID)
	require.NoError(t, err)
	assert.Equal(t, row.OAuthClientID, got.OAuthClientID)
	assert.Equal(t, "ES256", got.KeyAlgorithm)

	// Reverse lookup для token-hook principal-mapping.
	byClient, err := repo.GetByOAuthClientID(ctx, row.OAuthClientID)
	require.NoError(t, err)
	assert.Equal(t, row.ID, byClient.ID)

	list, next, err := repo.List(ctx, uid, "", 100)
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Empty(t, next)
}

func TestUserOAuthClient_09a_ExpiresBeforeCreated_CheckViolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	uid := mustSeedUser(t, ctx, pool, "uoc09a")
	repo := kachopg.NewUserOAuthClientRepo(pool)
	txb := kachopg.NewPoolTxBeginner(pool)

	row := newUOC(uid, "expired")
	created := time.Now()
	past := created.Add(-1 * time.Hour)
	row.CreatedAt = created
	row.ExpiresAt = &past // expires_at <= created_at → CHECK violation

	tx, err := txb.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = repo.Insert(ctx, tx, row)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrInvalidArg),
		"CHECK (expires_at > created_at) SQLSTATE 23514 → ErrInvalidArg, got %v", err)
}

func TestUserOAuthClient_09b_ConcurrentIssue_NToOne(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	uid := mustSeedUser(t, ctx, pool, "uoc09b")
	repo := kachopg.NewUserOAuthClientRepo(pool)
	txb := kachopg.NewPoolTxBeginner(pool)

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	ids := make([]domain.UserOAuthClientID, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			row := newUOC(uid, fmt.Sprintf("c%d", i))
			ids[i] = row.ID
			tx, err := txb.Begin(ctx)
			if err != nil {
				errs[i] = err
				return
			}
			if _, err := repo.Insert(ctx, tx, row); err != nil {
				_ = tx.Rollback(ctx)
				errs[i] = err
				return
			}
			errs[i] = tx.Commit(ctx)
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		require.NoError(t, e, "concurrent Issue %d must succeed (N:1 — no UNIQUE(user_id))", i)
	}
	// Все n строк независимы и присутствуют в List.
	list, _, err := repo.List(ctx, uid, "", 1000)
	require.NoError(t, err)
	assert.Len(t, list, n, "N:1 — все %d токенов одного user независимы", n)
	seen := map[domain.UserOAuthClientID]struct{}{}
	for _, c := range list {
		seen[c.ID] = struct{}{}
	}
	assert.Len(t, seen, n, "уникальные id, ни одна строка не потеряна")
}

func TestUserOAuthClient_UniqueHydraClientID_Collision(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	uid := mustSeedUser(t, ctx, pool, "uocuniq")
	repo := kachopg.NewUserOAuthClientRepo(pool)
	txb := kachopg.NewPoolTxBeginner(pool)

	first := newUOC(uid, "dup")
	insertUOC(t, ctx, txb, repo, first)

	second := newUOC(uid, "dup2")
	second.OAuthClientID = first.OAuthClientID // тот же hydra_client_id

	tx, err := txb.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = repo.Insert(ctx, tx, second)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrAlreadyExists),
		"UNIQUE hydra_client_id SQLSTATE 23505 → ErrAlreadyExists, got %v", err)
}

func TestUserOAuthClient_09c_UserDelete_CascadesTokens(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	ownerID := mustSeedUser(t, ctx, pool, "uoc09c")
	repo := kachopg.NewUserOAuthClientRepo(pool)
	txb := kachopg.NewPoolTxBeginner(pool)

	// Второй, НЕ-owner user в том же account: его удаление не задевает взаимный FK
	// accounts.owner_user_id (тот указывает на ownerID) — изолируем именно CASCADE
	// user_oauth_clients.user_id → users.
	var accID string
	require.NoError(t, pool.QueryRow(ctx, `SELECT account_id FROM users WHERE id = $1`, string(ownerID)).Scan(&accID))
	memberID := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err = pool.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, 'Member', 'ACTIVE')`,
		string(memberID), accID,
		"ext-member-"+string(memberID), "member-"+string(memberID)+"@example.com")
	require.NoError(t, err)

	row := insertUOC(t, ctx, txb, repo, newUOC(memberID, "cascade"))

	// Удаление user снимает его токены (ON DELETE CASCADE).
	_, err = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, string(memberID))
	require.NoError(t, err)

	_, err = repo.Get(ctx, row.ID)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound),
		"FK ON DELETE CASCADE снял токен вместе с user, got %v", err)
}

func TestUserOAuthClient_13_DeleteByID_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	uid := mustSeedUser(t, ctx, pool, "uoc13")
	repo := kachopg.NewUserOAuthClientRepo(pool)
	txb := kachopg.NewPoolTxBeginner(pool)

	row := insertUOC(t, ctx, txb, repo, newUOC(uid, "del"))

	// Первый delete — успех.
	tx, err := txb.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, repo.DeleteByID(ctx, tx, row.ID))
	require.NoError(t, tx.Commit(ctx))

	// Повторный delete — детерминированный ErrNotFound (не 500).
	tx2, err := txb.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx2.Rollback(ctx) }()
	err = repo.DeleteByID(ctx, tx2, row.ID)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound),
		"повторный revoke уже удалённого токена → ErrNotFound, got %v", err)
}
