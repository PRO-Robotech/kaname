// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// serve_registry_token_anonymous_integration_test.go — ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ
// анонимной выдачи (kaname#495): включённая ручка анонимного принципала не
// трогает вход владельца.
//
// Полоса собрана из той же настройки службы, что у пары в
// serve_registry_token_anonymous_test.go, — с заданной ручкой, — и на живой
// базе. Вход базовым секретом служебной учётки получает 200 и токен ЗА ЭТУ
// учётку, а не за анонимного принципала: ручка, открывшая анонимную ветку,
// не имеет права подменить субъект предъявленного входа.

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/credsecret"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/handler/registrytokenhttp"
	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

const (
	anonTwinAccount = "acc000000000000an495"
	anonTwinUser    = "usr000000000000an495"
	anonTwinSA      = "sva000000000000an495"
	anonTwinCred    = "soc_000000000000an495"
)

// seedOwnerCredential заводит владельца с живым базовым секретом служебной
// учётки и возвращает предъявляемую строку.
func seedOwnerCredential(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL DEFERRED`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
INSERT INTO accounts (id, name, owner_user_id) VALUES ($1, 'an-495', $2)`, anonTwinAccount, anonTwinUser)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
INSERT INTO users (id, external_id, email, account_id, invite_status, email_verified_at)
VALUES ($1, 'ext-an-495', 'an495@example.invalid', $2, 'ACTIVE', now())`, anonTwinUser, anonTwinAccount)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
INSERT INTO service_accounts (id, account_id, name, enabled) VALUES ($1, $2, 'an-495-sa', true)`,
		anonTwinSA, anonTwinAccount)
	require.NoError(t, err)
	activewayin.Seed(t, ctx, tx)
	require.NoError(t, tx.Commit(ctx))

	secret, hash, err := credsecret.Mint(anonTwinCred)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
INSERT INTO service_account_oauth_clients
    (id, sva_id, created_by_user_id, credential_kind, secret_hash, expires_at)
VALUES ($1, $2, $3, 'SECRET', $4, now() + interval '30 days')`, anonTwinCred, anonTwinSA, anonTwinUser, hash)
	require.NoError(t, err)
	return secret
}

func TestAnonymousRegistryToken_OwnerCredentialStillGetsItsOwnToken(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	pool, err := pgxpool.New(context.Background(), iampgtest.AppendIAMSearchPath(pgtest.NewDB(t)))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	secret := seedOwnerCredential(t, pool)

	h := anonymousLaneFromSettings(t, anonLanePrincipal, pool)

	req := httptest.NewRequest(http.MethodGet, registrytokenhttp.TokenPath+
		"?service="+anonLaneService+"&scope=repository:pub/app:pull", nil)
	req.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte(anonTwinCred+":"+secret)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code,
		"вход владельца при заданной ручке анонимного принципала: тело %q", rec.Body.String())
	claims, _ := mintedClaims(t, rec)
	require.Equal(t, anonTwinSA, claims["sub"],
		"токен входа владельца обязан быть за его учётку, а не за анонимного принципала")

	// Тот же собранный обработчик без удостоверения — анонимный токен: обе
	// ветки живы в одной полосе одновременно.
	anon := anonymousPull(t, h)
	require.Equal(t, http.StatusOK, anon.Code, "анонимная ветка той же полосы: тело %q", anon.Body.String())
	anonClaims, _ := mintedClaims(t, anon)
	require.Equal(t, anonLanePrincipal, anonClaims["sub"])
}
