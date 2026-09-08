// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// assertion_client_integration_test.go — реестр, способный к утверждению
// (приёмка F2, сценарии F2-14, F2-17, F2-29, F2-30, F2-44).
//
// # На какой НЕВЕРНОЙ реализации эти пробы зелены — и чем это закрыто
//
//   - «клиент не резолвится» зелено на разрешении, не находящем НИКОГО ⇒ у
//     каждого отрицания здесь стоит положительный контроль на том же прогоне;
//   - «зеркальное значение не резолвится» зелено на реализации, которая ищет
//     только по нашему идентификатору И НЕ ИМЕЕТ зеркального значения в строке
//     вовсе ⇒ проба ЗАПОЛНЯЕТ зеркальную колонку и требует, чтобы наш
//     идентификатор той же строки резолвился;
//   - «владелец не активен» зелено на реализации, проверяющей ОДНО из двух
//     не-`ACTIVE` состояний ⇒ проба подаёт оба отдельными входами.
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// assertionFixture — минимальный стенд реестра.
type assertionFixture struct {
	pool *pgxpool.Pool
	// dsn — строка подключения к ТОЙ ЖЕ базе. Нужна пробе, которой требуется
	// ВТОРОЙ пул к ней: недоступность хранилища проверяется закрытым пулом, а
	// не дублёром, договорившимся с пробой вернуть ошибку.
	dsn     string
	repo    *kanamepg.AssertionClientRepo
	account string
	user    string
	sva     string
}

func newAssertionFixture(t *testing.T) assertionFixture {
	t.Helper()
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	f := assertionFixture{
		pool:    pool,
		dsn:     dsn,
		repo:    kanamepg.NewAssertionClientRepo(pool),
		account: "acc_aaaaaaaaaaaaaaaaa",
		user:    "usr_aaaaaaaaaaaaaaaaa",
		sva:     "sva_aaaaaaaaaaaaaaaaa",
	}
	// Аккаунт и его владелец ссылаются друг на друга, поэтому обе строки
	// кладутся ОДНОЙ транзакцией: внешние ключи здесь отложенные, и 23503
	// пришёл бы на COMMIT, а не на INSERT.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1,'assertion-fixture',$2)`,
		f.account, f.user)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1,$2,'ext-assertion','assert@example.com','Assert','ACTIVE')`, f.user, f.account)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	_, err = pool.Exec(ctx, `INSERT INTO kaname.service_accounts (id, account_id, name) VALUES ($1,$2,'assertion-sva')`,
		f.sva, f.account)
	require.NoError(t, err)
	return f
}

// seedUserClient кладёт строку клиента пользовательского токена.
func (f assertionFixture) seedUserClient(t *testing.T, id, mirror, keyPEM, alg string, expires *time.Time) {
	t.Helper()
	_, err := f.pool.Exec(context.Background(),
		`INSERT INTO kaname.user_oauth_clients
		   (id, user_id, hydra_client_id, created_by_user_id, public_key_pem, key_algorithm, expires_at,
		    credential_kind)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,'KEYPAIR')`,
		id, f.user, mirror, f.user, keyPEM, alg, expires)
	require.NoError(t, err)
}

// seedSAClient кладёт строку клиента ключа служебной учётки.
func (f assertionFixture) seedSAClient(t *testing.T, id, mirror, keyPEM, alg string) {
	t.Helper()
	_, err := f.pool.Exec(context.Background(),
		`INSERT INTO kaname.service_account_oauth_clients
		   (id, sva_id, hydra_client_id, created_by_user_id, public_key_pem, key_algorithm,
		    credential_kind)
		 VALUES ($1,$2,$3,$4,$5,$6,'KEYPAIR')`,
		id, f.sva, mirror, f.user, keyPEM, alg)
	require.NoError(t, err)
}

const testPublicKeyPEM = "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n"

// TestF2_14_MirrorIdentifierDoesNotResolveTheClient — §2.1.
//
// Зеркальное значение (идентификатор клиента во внешнем сервере) на пути
// разрешения НЕ УЧАСТВУЕТ. Два значения, разрешающих одного клиента у одного
// эндпоинта, — это два правила об одном поле: одно неизбежно окажется
// необязательным, и настройка, задавшая «не то», будет выглядеть исправной.
func TestF2_14_MirrorIdentifierDoesNotResolveTheClient(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	f := newAssertionFixture(t)

	const ourID = "uoc_bbbbbbbbbbbbbbbbb"
	const mirrorID = "kacho-usr-mirror-0001"
	f.seedUserClient(t, ourID, mirrorID, testPublicKeyPEM, "ES256", nil)

	// Зеркальное значение НЕ резолвится. Проба заполняет колонку — иначе она
	// зелена на реализации, у которой зеркального значения в строке нет вовсе.
	_, err := f.repo.ResolveAssertionClient(ctx, mirrorID)
	require.True(t, domain.IsAssertionClientUnknown(err),
		"зеркальное значение обязано не резолвиться, получено: %v", err)

	// НАШ идентификатор ТОЙ ЖЕ строки резолвится — положительный контроль.
	row, err := f.repo.ResolveAssertionClient(ctx, ourID)
	require.NoError(t, err)
	require.Equal(t, ourID, row.ID)
	require.Equal(t, domain.AssertionClientUser, row.Kind)
	require.Equal(t, f.user, row.OwnerID)
	require.True(t, row.CanPresentAssertion())
}

// TestF2_44_InteractiveClientDoesNotResolveAtAll — §2.9.
//
// Идентификатор интерактивного клиента не резолвится ни во что, и отказ
// наступает на том же шаге и тем же признаком, что для несуществующего.
func TestF2_44_InteractiveClientDoesNotResolveAtAll(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	f := newAssertionFixture(t)

	const interactiveID = "ic-ccccccccccccccccc"
	_, err := f.pool.Exec(ctx, `INSERT INTO kaname.interactive_clients
		  (id, name, redirect_uris, client_id)
		 VALUES ($1,'assertion-interactive',ARRAY['https://console.example/cb'],$2)`,
		interactiveID, "provider-"+interactiveID)
	require.NoError(t, err)

	// Существует в СВОЕЙ таблице — и всё же не резолвится.
	_, err = f.repo.ResolveAssertionClient(ctx, interactiveID)
	require.True(t, domain.IsAssertionClientUnknown(err))

	// Несуществующий идентификатор — ТОТ ЖЕ признак: различимость исходов была
	// бы оракулом существования.
	_, err = f.repo.ResolveAssertionClient(ctx, "uoc_zzzzzzzzzzzzzzzzz")
	require.True(t, domain.IsAssertionClientUnknown(err))

	// Положительный контроль: идентификатор ИЗ реестра, способного к
	// утверждению, резолвится. Без него проба зелена на разрешении, не
	// находящем никого.
	const ourID = "soc_ddddddddddddddddd"
	f.seedSAClient(t, ourID, "kacho-sak-mirror-0001", testPublicKeyPEM, "ES256")
	row, err := f.repo.ResolveAssertionClient(ctx, ourID)
	require.NoError(t, err)
	require.Equal(t, domain.AssertionClientServiceAccount, row.Kind)
	require.Equal(t, f.sva, row.OwnerID)
}

// TestF2_10_EmptyRegisteredAlgorithmIsALegalSchemaStateAndMeansNoKey — пустое
// значение закрытого словаря схемы доезжает до вызывающего КАК ПУСТОЕ.
func TestF2_10_EmptyRegisteredAlgorithmIsALegalSchemaStateAndMeansNoKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	f := newAssertionFixture(t)

	// Схема допускает пустой алгоритм и пустой ключ — это её умолчание.
	const bare = "uoc_eeeeeeeeeeeeeeeee"
	f.seedUserClient(t, bare, "kacho-usr-bare", "", "", nil)
	row, err := f.repo.ResolveAssertionClient(ctx, bare)
	require.NoError(t, err, "строка существует; отказывать обязан вызывающий, а не чтение")
	require.False(t, row.CanPresentAssertion(), "пустое означает «ключа нет», а не «любой алгоритм»")

	// Положительный контроль на том же прогоне.
	const armed = "uoc_fffffffffffffffff"
	f.seedUserClient(t, armed, "kacho-usr-armed", testPublicKeyPEM, "ES256", nil)
	row, err = f.repo.ResolveAssertionClient(ctx, armed)
	require.NoError(t, err)
	require.True(t, row.CanPresentAssertion())
}

// TestF2_30_OwnerStateReachesTheCallerForBothNonActiveValues — словарь состояний
// владельца из ТРЁХ значений, и не-`ACTIVE` — это ДВА из них.
//
// Реализация, проверяющая одно, зелена на половине класса.
func TestF2_30_OwnerStateReachesTheCallerForBothNonActiveValues(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	f := newAssertionFixture(t)

	const clientID = "uoc_ggggggggggggggggg"
	f.seedUserClient(t, clientID, "kacho-usr-owner-state", testPublicKeyPEM, "ES256", nil)

	// ACTIVE — положительный контроль.
	row, err := f.repo.ResolveAssertionClient(ctx, clientID)
	require.NoError(t, err)
	require.True(t, row.OwnerActive)

	// Оба не-`ACTIVE` значения подаются ОТДЕЛЬНЫМИ входами.
	for _, state := range []string{"BLOCKED", "PENDING"} {
		// Ограничение схемы связывает состояние с внешним идентификатором:
		// PENDING обязан нести пустой, прочие — непустой.
		ext := "ext-assertion"
		if state == "PENDING" {
			ext = ""
		}
		_, err = f.pool.Exec(ctx, `UPDATE kaname.users SET invite_status=$2, external_id=$3 WHERE id=$1`,
			f.user, state, ext)
		require.NoError(t, err, "состояние %s", state)

		row, err = f.repo.ResolveAssertionClient(ctx, clientID)
		require.NoError(t, err, "строка клиента обязана остаться видимой")
		require.False(t, row.OwnerActive, "состояние %s обязано доехать как «не активен»", state)
	}
}

// TestF2_29_ClientExpiryReachesTheCallerAndAbsentMeansForever — незаданный срок
// означает «бессрочно», и это ЗАКОННОЕ состояние схемы.
func TestF2_29_ClientExpiryReachesTheCallerAndAbsentMeansForever(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	f := newAssertionFixture(t)

	// Срок задан.
	at := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	const dated = "uoc_hhhhhhhhhhhhhhhhh"
	f.seedUserClient(t, dated, "kacho-usr-dated", testPublicKeyPEM, "ES256", &at)
	row, err := f.repo.ResolveAssertionClient(ctx, dated)
	require.NoError(t, err)
	require.Equal(t, at.Unix(), row.ExpiresAt)

	// Срок НЕ задан — ноль, и это «бессрочно», а не «истёк в начале эпохи».
	const forever = "uoc_jjjjjjjjjjjjjjjjj"
	f.seedUserClient(t, forever, "kacho-usr-forever", testPublicKeyPEM, "ES256", nil)
	row, err = f.repo.ResolveAssertionClient(ctx, forever)
	require.NoError(t, err)
	require.Zero(t, row.ExpiresAt)
}
