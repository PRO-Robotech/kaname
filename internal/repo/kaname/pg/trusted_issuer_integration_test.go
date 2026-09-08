// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// trusted_issuer_integration_test.go — НАШ перечень доверенных издателей
// (задача #1124).
//
// # На какой НЕВЕРНОЙ реализации эти пробы зелены — и чем это закрыто
//
//   - «пара не резолвится» зелено на разрешении, не находящем НИКОГО ⇒ у
//     каждого отрицания стоит положительный контроль на том же прогоне;
//   - «доверие снимается вместе с ключом» зелено на таблице, куда запись вообще
//     не легла ⇒ проба сперва РАЗРЕШАЕТ пару, и только потом снимает ключ;
//   - «пара уникальна» зелено на проверке-перед-вставкой, которая под
//     конкуренцией пропускает обе ⇒ инвариант проверяется ВСТАВКОЙ второй
//     строки, а не чтением.
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

const (
	testExternalIssuer  = "https://token.actions.githubusercontent.com"
	testExternalSubject = "repo:acme/infra:ref:refs/heads/main"
)

// trustFixture — стенд перечня.
type trustFixture struct {
	pool    *pgxpool.Pool
	repo    *kanamepg.TrustedIssuerRepo
	account string
	user    string
	sva     string
	client  string
}

func newTrustFixture(t *testing.T) trustFixture {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	f := trustFixture{
		pool:    pool,
		repo:    kanamepg.NewTrustedIssuerRepo(pool),
		account: "acc_ttttttttttttttttt",
		user:    "usr_ttttttttttttttttt",
		sva:     "sva_ttttttttttttttttt",
		client:  "soc_ttttttttttttttttt",
	}
	// Аккаунт и его владелец ссылаются друг на друга — обе строки одной
	// транзакцией: внешние ключи отложенные, и 23503 пришёл бы на COMMIT.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1,'trust-fixture',$2)`,
		f.account, f.user)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1,$2,'ext-trust','trust@example.com','Trust','ACTIVE')`, f.user, f.account)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	_, err = pool.Exec(ctx, `INSERT INTO kaname.service_accounts (id, account_id, name) VALUES ($1,$2,'trust-sva')`,
		f.sva, f.account)
	require.NoError(t, err)
	// Федеративная строка ключевого материала НЕ несёт: подпись проверяется
	// ключом издателя из записи доверия.
	_, err = pool.Exec(ctx, `INSERT INTO kaname.service_account_oauth_clients
		   (id, sva_id, hydra_client_id, created_by_user_id, public_key_pem, key_algorithm,
		    credential_kind)
		 VALUES ($1,$2,$1,$3,'','','LEGACY')`, f.client, f.sva, f.user)
	require.NoError(t, err)
	return f
}

// seedTrust кладёт запись доверия напрямую.
func (f trustFixture) seedTrust(t *testing.T, issuer, subject, keyPEM, alg string, expires *time.Time) {
	t.Helper()
	_, err := f.pool.Exec(context.Background(),
		`INSERT INTO kaname.federated_trusted_issuers
		   (issuer, subject, sa_oauth_client_id, public_key_pem, key_algorithm, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		issuer, subject, f.client, keyPEM, alg, expires)
	require.NoError(t, err)
}

// TestTrustedIssuer_ResolvesThePairIntoOurClient — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
func TestTrustedIssuer_ResolvesThePairIntoOurClient(t *testing.T) {
	f := newTrustFixture(t)
	f.seedTrust(t, testExternalIssuer, testExternalSubject, testPublicKeyPEM, "ES256", nil)

	trust, client, err := f.repo.ResolveTrustedIssuer(context.Background(), testExternalIssuer, testExternalSubject)
	require.NoError(t, err)
	require.Equal(t, f.client, trust.ClientID)
	require.Equal(t, testPublicKeyPEM, trust.PublicKeyPEM)
	require.Equal(t, "ES256", trust.Algorithm)
	require.Zero(t, trust.ExpiresAt, "срок не назван — доверие бессрочно, и это законное состояние")
	require.Equal(t, f.client, client.ID)
	require.Equal(t, f.sva, client.OwnerID)
	require.True(t, client.OwnerActive)
	require.Equal(t, domain.AssertionClientServiceAccount, client.Kind)
}

// TestTrustedIssuer_UnknownPairIsOneAndTheSameRefusal — пары нет · доверие
// выдано другому субъекту того же издателя · другому издателю того же субъекта.
//
// Все три обязаны давать ОДИН признак: различимые исходы сообщали бы
// предъявителю состав перечня.
func TestTrustedIssuer_UnknownPairIsOneAndTheSameRefusal(t *testing.T) {
	f := newTrustFixture(t)
	f.seedTrust(t, testExternalIssuer, testExternalSubject, testPublicKeyPEM, "ES256", nil)

	for name, pair := range map[string][2]string{
		"пары нет вовсе":        {"https://other.example", "some:subject"},
		"другой субъект":        {testExternalIssuer, "repo:acme/infra:ref:refs/heads/attacker"},
		"другой издатель":       {"https://gitlab.com", testExternalSubject},
		"субъект пуст":          {testExternalIssuer, ""},
		"издатель пуст":         {"", testExternalSubject},
		"подстрока субъекта":    {testExternalIssuer, "repo:acme/infra"},
		"субъект с надставкой":  {testExternalIssuer, testExternalSubject + "x"},
		"издатель с надставкой": {testExternalIssuer + "/", testExternalSubject},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := f.repo.ResolveTrustedIssuer(context.Background(), pair[0], pair[1])
			require.ErrorIs(t, err, domain.ErrTrustedIssuerUnknown)
		})
	}

	// Положительный контроль: законная пара по-прежнему резолвится. Без него
	// проба зелена на разрешении, не находящем никого.
	_, _, err := f.repo.ResolveTrustedIssuer(context.Background(), testExternalIssuer, testExternalSubject)
	require.NoError(t, err)
}

// TestTrustedIssuer_PairIsGloballyUnique — доверие паре выдаётся ОДИН раз, и
// держит это ПЕРВИЧНЫЙ КЛЮЧ, а не проверка перед вставкой.
//
// Без инварианта две наши строки поручились бы за один внешний субъект, и
// разрешение стало бы недетерминированным: тот же предъявитель получал бы токен
// то одной служебной учётной записи, то другой.
func TestTrustedIssuer_PairIsGloballyUnique(t *testing.T) {
	f := newTrustFixture(t)
	f.seedTrust(t, testExternalIssuer, testExternalSubject, testPublicKeyPEM, "ES256", nil)

	// Вторая наша строка ключа — другая, пара та же.
	second := "soc_vvvvvvvvvvvvvvvvv"
	_, err := f.pool.Exec(context.Background(), `INSERT INTO kaname.service_account_oauth_clients
		   (id, sva_id, hydra_client_id, created_by_user_id, public_key_pem, key_algorithm,
		    credential_kind)
		 VALUES ($1,$2,$1,$3,'','','LEGACY')`, second, f.sva, f.user)
	require.NoError(t, err)

	_, err = f.pool.Exec(context.Background(),
		`INSERT INTO kaname.federated_trusted_issuers
		   (issuer, subject, sa_oauth_client_id, public_key_pem, key_algorithm)
		 VALUES ($1,$2,$3,$4,'ES256')`,
		testExternalIssuer, testExternalSubject, second, testPublicKeyPEM)
	require.Error(t, err, "вторая запись на ту же пару обязана быть отвергнута хранилищем")

	// Положительный контроль: ДРУГАЯ пара той же строкой ложится.
	_, err = f.pool.Exec(context.Background(),
		`INSERT INTO kaname.federated_trusted_issuers
		   (issuer, subject, sa_oauth_client_id, public_key_pem, key_algorithm)
		 VALUES ($1,$2,$3,$4,'ES256')`,
		testExternalIssuer, "repo:acme/other:ref:refs/heads/main", second, testPublicKeyPEM)
	require.NoError(t, err)
}

// TestTrustedIssuer_TrustIsWithdrawnWithTheKeyItBacked — снятие ключа снимает
// доверие ТЕМ ЖЕ каскадом одной базы.
//
// Доверие, пережившее строку, ради которой выдавалось, продолжало бы называть
// постороннего доверенным при отсутствии того, кем он представлялся.
func TestTrustedIssuer_TrustIsWithdrawnWithTheKeyItBacked(t *testing.T) {
	f := newTrustFixture(t)
	f.seedTrust(t, testExternalIssuer, testExternalSubject, testPublicKeyPEM, "ES256", nil)

	// Сперва пара РАЗРЕШАЕТСЯ — иначе «сняли» было бы неотличимо от «не
	// записалось».
	_, _, err := f.repo.ResolveTrustedIssuer(context.Background(), testExternalIssuer, testExternalSubject)
	require.NoError(t, err)

	_, err = f.pool.Exec(context.Background(),
		`DELETE FROM kaname.service_account_oauth_clients WHERE id = $1`, f.client)
	require.NoError(t, err)

	_, _, err = f.repo.ResolveTrustedIssuer(context.Background(), testExternalIssuer, testExternalSubject)
	require.ErrorIs(t, err, domain.ErrTrustedIssuerUnknown)
}

// TestTrustedIssuer_ExpiredTrustStillResolvesAndCarriesItsExpiry — истечение
// решает ПРОВЕРЯЮЩИЙ, а не оператор чтения.
//
// Отсеки хранилище истёкшее — «доверия не было» и «доверие кончилось» стали бы
// неразличимы, и снятие доверия сроком перестало бы быть наблюдаемым событием
// эксплуатации: у этих двух состояний свои счётчики.
func TestTrustedIssuer_ExpiredTrustStillResolvesAndCarriesItsExpiry(t *testing.T) {
	f := newTrustFixture(t)
	// Строка кладётся ТАК, КАК ОНА СТАРЕЕТ В ЖИЗНИ: записана давно, срок назван
	// позже момента записи и уже наступил. Ограничение схемы («срок позже
	// момента записи») при этом соблюдено — оно и не должно мешать истечению:
	// момент записи не меняется, а время идёт.
	//
	// Прежняя редакция пробы состаривала живую строку правкой срока и падала на
	// этом ограничении. Падение было верным, а проба — нет: она подавала
	// состояние, до которого система не доживает.
	created := time.Now().UTC().Add(-2 * time.Hour)
	past := time.Now().UTC().Add(-time.Hour)
	_, err := f.pool.Exec(context.Background(),
		`INSERT INTO kaname.federated_trusted_issuers
		   (issuer, subject, sa_oauth_client_id, public_key_pem, key_algorithm, expires_at, created_at)
		 VALUES ($1,$2,$3,$4,'ES256',$5,$6)`,
		testExternalIssuer, testExternalSubject, f.client, testPublicKeyPEM, past, created)
	require.NoError(t, err)

	trust, _, err := f.repo.ResolveTrustedIssuer(context.Background(), testExternalIssuer, testExternalSubject)
	require.NoError(t, err, "истёкшее доверие обязано резолвиться: истечение — исход проверяющего")
	require.Equal(t, past.Unix(), trust.ExpiresAt)
}

// TestTrustedIssuer_OwnerStateArrivesInsteadOfDisappearing — служебная учётная
// запись снята с обслуживания: запись доверия обязана дать «владелец не
// активен», а не исчезнуть.
//
// Исчезновение было бы неотличимо от «доверия нет», и оба состояния получили бы
// один счётчик.
func TestTrustedIssuer_OwnerStateArrivesInsteadOfDisappearing(t *testing.T) {
	f := newTrustFixture(t)
	f.seedTrust(t, testExternalIssuer, testExternalSubject, testPublicKeyPEM, "ES256", nil)
	_, err := f.pool.Exec(context.Background(),
		`UPDATE kaname.service_accounts SET enabled = FALSE WHERE id = $1`, f.sva)
	require.NoError(t, err)

	trust, client, err := f.repo.ResolveTrustedIssuer(context.Background(), testExternalIssuer, testExternalSubject)
	require.NoError(t, err)
	require.Equal(t, f.client, trust.ClientID)
	require.False(t, client.OwnerActive)
}

// TestTrustedIssuer_KeyMaterialCannotBeBlank — пустой ключ означал бы «доверяем
// паре БЕЗ ПРОВЕРКИ ПОДПИСИ». Держит это ограничение схемы, а не проверка в
// коде: величина, которая может быть пустой и не проверена на непустоту,
// означает «принимаем любого».
func TestTrustedIssuer_KeyMaterialCannotBeBlank(t *testing.T) {
	f := newTrustFixture(t)
	for name, row := range map[string][2]string{
		"ключ пуст":            {"", "ES256"},
		"ключ — одни пробелы":  {"   ", "ES256"},
		"алгоритм пуст":        {testPublicKeyPEM, ""},
		"алгоритм вне словаря": {testPublicKeyPEM, "HS256"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := f.pool.Exec(context.Background(),
				`INSERT INTO kaname.federated_trusted_issuers
				   (issuer, subject, sa_oauth_client_id, public_key_pem, key_algorithm)
				 VALUES ($1,$2,$3,$4,$5)`,
				testExternalIssuer, "subject:"+name, f.client, row[0], row[1])
			require.Error(t, err)
		})
	}

	// Положительный контроль: законная строка ложится. Без него проба зелена на
	// таблице, отвергающей всякую вставку.
	_, err := f.pool.Exec(context.Background(),
		`INSERT INTO kaname.federated_trusted_issuers
		   (issuer, subject, sa_oauth_client_id, public_key_pem, key_algorithm)
		 VALUES ($1,$2,$3,$4,'ES256')`,
		testExternalIssuer, testExternalSubject, f.client, testPublicKeyPEM)
	require.NoError(t, err)
}

// TestTrustedIssuer_EmptyListWritesAreRefused — пустой перечень НИКОГДА не
// записывается как пустой.
//
// Ключ, чей перечень пуст, не примет никого. Запись такого перечня означала бы,
// что выдача ответила успехом на удостоверение, которым нельзя воспользоваться.
func TestTrustedIssuer_EmptyListWritesAreRefused(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	err = f.repo.InsertTrustedIssuers(ctx, tx, domain.SAOAuthClientID(f.client), nil, nil)
	require.Error(t, err, "пустой перечень означает «не доверяем никому» и как перечень не пишется")

	// Положительный контроль: непустой перечень пишется и РАЗРЕШАЕТСЯ.
	err = f.repo.InsertTrustedIssuers(ctx, tx, domain.SAOAuthClientID(f.client),
		[]domain.TrustedSubject{{
			Issuer:         testExternalIssuer,
			SubjectPattern: "^" + testExternalSubject + "$",
			PublicKeyPEM:   testPublicKeyPEM,
			KeyAlgorithm:   "ES256",
		}}, nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	trust, _, err := f.repo.ResolveTrustedIssuer(ctx, testExternalIssuer, testExternalSubject)
	require.NoError(t, err)
	require.Equal(t, testExternalSubject, trust.Subject,
		"в таблицу обязан лечь ТОЧНЫЙ субъект, а не образец, которым его назвали")
}
