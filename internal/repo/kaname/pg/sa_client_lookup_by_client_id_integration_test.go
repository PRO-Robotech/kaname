// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// sa_client_lookup_by_client_id_integration_test.go — поиск ключа служебной
// учётки по имени клиента НЕ РАСШИРЯЕТ множество ответа (kaname#362).
//
// # Предмет
//
// Хук выпуска токена и докерная полоса получают имя клиента и спрашивают, какой
// ключ за ним стоит. Прежде поиск шёл по столбцу имени клиента у внешнего
// поставщика: у ключевой пары и федеративного ключа там лежал `id` строки, у
// секрета — пусто, и секрет этим поиском не находился НИКОГДА. Столбец снят, и
// поиск идёт по `id` — но множество ответа обязано остаться прежним: только
// виды, обмениваемые как клиент. Поиск «по id вообще» молча дал бы секрету
// дорогу, которой у него не было.
//
// # Что здесь утверждается
//
//   - ключевая пара и федеративный ключ находятся по своему `id` (положительный
//     контроль: без него отрицание ниже зеленело бы на поиске, не находящем
//     никого);
//   - секрет по своему `id` НЕ находится, и его отказ побайтно тот же, что у
//     несуществующего `id` (после вычёркивания эха самого `id`) — на уровне
//     хранилища и на уровне докерной полосы. Различимый отказ был бы оракулом
//     существования.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/registrytokenwire"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func TestSAClientLookupByClientID_AnswersOnlyTheExchangedKinds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	uid := mustSeedUser(t, ctx, pool, "sclookup")
	var accID string
	require.NoError(t, pool.QueryRow(ctx, `SELECT account_id FROM users WHERE id = $1`, string(uid)).Scan(&accID))
	svaID := ids.NewID(domain.PrefixServiceAccount)
	_, err = pool.Exec(ctx, `INSERT INTO service_accounts (id, account_id, name) VALUES ($1, $2, $3)`,
		svaID, accID, "client-lookup")
	require.NoError(t, err)

	keypair := ids.NewID(domain.PrefixSAOAuthClient)
	federated := ids.NewID(domain.PrefixSAOAuthClient)
	secret := ids.NewID(domain.PrefixSAOAuthClient)
	unknown := ids.NewID(domain.PrefixSAOAuthClient)
	_, err = pool.Exec(ctx, `
		INSERT INTO service_account_oauth_clients
		    (id, sva_id, created_by_user_id, credential_kind, secret_hash, public_key_pem, key_algorithm, trusted_subjects)
		VALUES ($1, $2, $3, 'KEYPAIR', ''::bytea, $4, 'ES256', '[]'::jsonb)`,
		keypair, svaID, string(uid), credPublicKey)
	require.NoError(t, err, "посев ключевой пары")
	_, err = pool.Exec(ctx, `
		INSERT INTO service_account_oauth_clients
		    (id, sva_id, created_by_user_id, credential_kind, secret_hash, public_key_pem, key_algorithm, trusted_subjects)
		VALUES ($1, $2, $3, 'FEDERATED', ''::bytea, '', '',
		        '[{"issuer":"https://idp.example.invalid","subject_pattern":"^x$"}]'::jsonb)`,
		federated, svaID, string(uid))
	require.NoError(t, err, "посев федеративного ключа")
	_, err = pool.Exec(ctx, `
		INSERT INTO service_account_oauth_clients
		    (id, sva_id, created_by_user_id, credential_kind, secret_hash, public_key_pem, key_algorithm,
		     trusted_subjects, expires_at)
		VALUES ($1, $2, $3, 'SECRET', $4, '', '', '[]'::jsonb, now() + interval '30 days')`,
		secret, svaID, string(uid), credSecretHash())
	require.NoError(t, err, "посев секрета")

	repo := kanamepg.NewSAOAuthClientRepo(pool)

	// Положительный контроль: оба обмениваемых вида находятся по своему id.
	for kind, id := range map[domain.CredentialKind]string{
		domain.CredentialKindKeypair:   keypair,
		domain.CredentialKindFederated: federated,
	} {
		row, gerr := repo.GetByClientID(ctx, domain.SAOAuthClientID(id))
		require.NoError(t, gerr, "вид %s обязан находиться по имени клиента", kind)
		require.Equal(t, id, string(row.ID))
		require.Equal(t, kind, row.CredentialKind)
	}

	// Секрет — не клиент обмена: не находится, и отказ неотличим от
	// несуществующего id.
	redact := func(err error, id string) string {
		return strings.ReplaceAll(err.Error(), id, "<id>")
	}
	_, secretErr := repo.GetByClientID(ctx, domain.SAOAuthClientID(secret))
	_, unknownErr := repo.GetByClientID(ctx, domain.SAOAuthClientID(unknown))
	require.Error(t, secretErr, "секрет по имени клиента находиться не вправе")
	require.True(t, errors.Is(secretErr, iamerr.ErrNotFound), "секрет: %v", secretErr)
	require.True(t, errors.Is(unknownErr, iamerr.ErrNotFound), "несуществующий: %v", unknownErr)
	require.Equal(t, redact(unknownErr, unknown), redact(secretErr, secret),
		"отказ на секрете обязан совпадать с отказом на несуществующем id — иначе это оракул существования")

	// Та же граница на докерной полосе: её поиск идёт через этот же метод.
	lane := registrytokenwire.NewSAClientLookup(repo)
	_, laneSecretErr := lane.KeyByClientID(ctx, secret)
	_, laneUnknownErr := lane.KeyByClientID(ctx, unknown)
	require.Error(t, laneSecretErr, "докерная полоса не вправе находить секрет по имени клиента")
	require.Equal(t, redact(laneUnknownErr, unknown), redact(laneSecretErr, secret),
		"докерная полоса: отказ на секрете обязан совпадать с отказом на несуществующем id")
	key, lerr := lane.KeyByClientID(ctx, keypair)
	require.NoError(t, lerr, "положительный контроль полосы: ключевая пара находится")
	require.Equal(t, keypair, key.ClientID, "имя клиента на полосе — id строки")
	require.Equal(t, keypair, key.KeyID)
}
