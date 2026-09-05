// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// credential_quota_integration_test.go — потолок числа удостоверений на
// принципала (задача #1191, приёмка
// `services/iam/docs/engineering/acceptance/credential-ceiling-per-principal.md`).
//
// # Почему это свойство базы, а не use-case'а
//
// Удостоверение — самостоятельный путь входа. Держать потолок проверкой в коде
// нельзя: «посчитал → вставил» есть check-then-act через границу оператора, и
// между чтением и вставкой помещается чужая запись (ban #10). Поэтому вход
// подаётся ВСТАВКОЙ в ту же таблицу, в которую пишет продукт, а решение
// принимает единственный атомарный оператор.
//
// # Что именно считается — и почему это видно в имени вида
//
// Считаются ВСЕ удостоверения принципала: ключевая пара, секрет, федеративное,
// прежнего потока — и действующие, и с истёкшим сроком. Слот освобождает ОТЗЫВ,
// а не истечение: строка живёт, пока её не сняли, и остаётся в перечне, которым
// владелец обязан управлять. Имя вида учёта это и произносит — `credential`, а
// не `secret`.

package pg_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

const (
	kindUserCredential = "iam.user.credential"
	kindSACredential   = "iam.serviceAccount.credential"
)

// newCredQuotaDB — своя база и пул на пробу.
func newCredQuotaDB(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return pool, ctx
}

// credQuotaFixture заводит аккаунт, его владельца и служебную учётку — три
// принципала, между которыми проходят все границы этой пробы.
func credQuotaFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) (userID, svaID, accountID string) {
	userID, svaID, accountID, _ = credQuotaFixtureWithVictim(t, ctx, pool, suffix)
	return userID, svaID, accountID
}

// credQuotaFixtureWithVictim — та же фикстура плюс ВТОРОЙ человек того же
// аккаунта, которого можно удалить.
//
// Владельца аккаунта удалить нельзя: ссылка аккаунта на владельца объявлена
// запрещающей, и это ограничение продукта, а не предмет учёта. Проба, снимающая
// владельца, судила бы чужую полосу и краснела бы независимо от потолка.
func credQuotaFixtureWithVictim(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) (userID, svaID, accountID, victimID string) {
	t.Helper()
	userID = ids.NewID(domain.PrefixUser)
	accountID = ids.NewID(domain.PrefixAccount)
	svaID = ids.NewID(domain.PrefixServiceAccount)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL DEFERRED`)
	require.NoError(t, err)

	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		userID, accountID, "ext-cred-"+suffix+"-"+userID,
		"cred-"+suffix+"-"+userID+"@example.invalid", "Cred Fixture "+suffix)
	require.NoError(t, err, "посев человека")

	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		accountID, "cred-acc-"+suffix, userID)
	require.NoError(t, err, "посев аккаунта")

	_, err = tx.Exec(ctx, `
		INSERT INTO service_accounts (id, account_id, name)
		VALUES ($1, $2, $3)`,
		svaID, accountID, "cred-sva-"+suffix)
	require.NoError(t, err, "посев служебной учётки")

	victimID = ids.NewID(domain.PrefixUser)
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		victimID, accountID, "ext-victim-"+suffix+"-"+victimID,
		"victim-"+suffix+"-"+victimID+"@example.invalid", "Cred Victim "+suffix)
	require.NoError(t, err, "посев второго человека")

	require.NoError(t, tx.Commit(ctx), "фиксация фикстуры")
	return userID, svaID, accountID, victimID
}

// credSecretHash — свёртка секрета, РАЗНАЯ на каждый вызов: колонка несёт
// уникальный индекс по всей таблице (два принципала не могут предъявлять один и
// тот же секрет), и фикстура, дающая одинаковые байты, упёрлась бы в него раньше
// потолка — то есть проба судила бы не свою полосу.
func credSecretHash() []byte {
	h := make([]byte, 32)
	if _, err := rand.Read(h); err != nil {
		panic("credSecretHash: " + err.Error())
	}
	return h
}

const credPublicKey = "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----"

// insertUserCredential — вставка удостоверения человека ТЕМ ЖЕ оператором,
// каким пишет продукт. `kind` — вид предъявления, а не вид учёта.
func insertUserCredential(ctx context.Context, pool *pgxpool.Pool, userID, kind string, expired bool) error {
	return insertUserCredentialOn(ctx, pool, userID, kind, expired, ids.NewID(domain.PrefixUserOAuthClient))
}

// insertUserCredentialBy — то же, но автор выпуска назван отдельно.
func insertUserCredentialBy(ctx context.Context, pool *pgxpool.Pool, userID, createdBy, kind string, expired bool) error {
	return insertUserCredentialFull(ctx, pool, userID, createdBy, kind, expired,
		ids.NewID(domain.PrefixUserOAuthClient))
}

func insertUserCredentialOn(ctx context.Context, pool *pgxpool.Pool, userID, kind string, expired bool, id string) error {
	return insertUserCredentialFull(ctx, pool, userID, userID, kind, expired, id)
}

func insertUserCredentialFull(ctx context.Context, pool *pgxpool.Pool, userID, createdBy, kind string, expired bool, id string) error {
	var (
		hash   []byte
		pubKey string
		alg    string
		expiry any
	)
	switch kind {
	case "SECRET":
		hash, expiry = credSecretHash(), "now() + interval '30 days'"
	default:
		pubKey, alg = credPublicKey, "ES256"
	}
	if expired {
		// Истёкшая строка вида KEYPAIR: срок в прошлом законен — ограничение
		// требует лишь, чтобы он был позже создания.
		_, err := pool.Exec(ctx, `
			INSERT INTO user_oauth_clients
			    (id, user_id, hydra_client_id, created_by_user_id, credential_kind,
			     secret_hash, public_key_pem, key_algorithm, created_at, expires_at)
			VALUES ($1, $2, NULL, $5, $3, ''::bytea, $4, 'ES256',
			        now() - interval '60 days', now() - interval '1 day')`,
			id, userID, kind, credPublicKey, createdBy)
		return err
	}
	if expiry == nil {
		_, err := pool.Exec(ctx, `
			INSERT INTO user_oauth_clients
			    (id, user_id, hydra_client_id, created_by_user_id, credential_kind,
			     secret_hash, public_key_pem, key_algorithm)
			VALUES ($1, $2, NULL, $6, $3, ''::bytea, $4, $5)`,
			id, userID, kind, pubKey, alg, createdBy)
		return err
	}
	_, err := pool.Exec(ctx, `
		INSERT INTO user_oauth_clients
		    (id, user_id, hydra_client_id, created_by_user_id, credential_kind,
		     secret_hash, public_key_pem, key_algorithm, expires_at)
		VALUES ($1, $2, NULL, $5, $3, $4, '', '', now() + interval '30 days')`,
		id, userID, kind, hash, createdBy)
	return err
}

// insertSACredential — то же для служебной учётки. У неё зеркало поставщика
// непусто у всякого вида, кроме секрета, — это ограничение её таблицы.
func insertSACredential(ctx context.Context, pool *pgxpool.Pool, svaID, createdBy, kind string) error {
	id := ids.NewID(domain.PrefixSAOAuthClient)
	if kind == "SECRET" {
		_, err := pool.Exec(ctx, `
			INSERT INTO service_account_oauth_clients
			    (id, sva_id, hydra_client_id, created_by_user_id, credential_kind,
			     secret_hash, public_key_pem, key_algorithm, trusted_subjects, expires_at)
			VALUES ($1, $2, $3, $4, 'SECRET', $5, '', '', '[]'::jsonb, now() + interval '30 days')`,
			id, svaID, id, createdBy, credSecretHash())
		return err
	}
	_, err := pool.Exec(ctx, `
		INSERT INTO service_account_oauth_clients
		    (id, sva_id, hydra_client_id, created_by_user_id, credential_kind,
		     secret_hash, public_key_pem, key_algorithm, trusted_subjects)
		VALUES ($1, $2, $3, $4, $5, ''::bytea, $6, 'ES256', '[]'::jsonb)`,
		id, svaID, id, createdBy, kind, credPublicKey)
	return err
}

// setCredLimit правит величину В АВТОРИТЕТЕ — там же, где её меняет
// администратор облака. Проба, правящая строку УЧЁТА, утверждала бы про
// снимок, а не про предел.
func setCredLimit(t *testing.T, ctx context.Context, pool *pgxpool.Pool, kind string, value int64) {
	t.Helper()
	tag, err := pool.Exec(ctx, `
		UPDATE limits SET limit_value = $2
		 WHERE kind = $1 AND scope = 'DEFAULT' AND withdrawn_at IS NULL`, kind, value)
	require.NoError(t, err)
	require.EqualValuesf(t, 1, tag.RowsAffected(),
		"действующей величины вида %q в авторитете нет: менять администратору нечего, "+
			"и потолок держится не величиной, а кодом", kind)
}

func credUsed(t *testing.T, ctx context.Context, pool *pgxpool.Pool, carrierType, carrierID, kind string) (used, limit int64, found bool) {
	t.Helper()
	err := pool.QueryRow(ctx, `
		SELECT used, limit_value FROM project_resource_quotas
		 WHERE carrier_type = $1 AND carrier_id = $2 AND kind = $3`,
		carrierType, carrierID, kind).Scan(&used, &limit)
	if err != nil {
		return 0, 0, false
	}
	return used, limit, true
}

func requireQuotaRefusal(t *testing.T, err error, wantCode, wantText string) {
	t.Helper()
	require.Error(t, err)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, wantCode, pgErr.Code,
		"отказ обязан приходить ЕДИНСТВЕННЫМ производителем платформы: свой текст "+
			"здесь означал бы седьмую копию контракта отказа")
	if wantText != "" {
		require.Contains(t, pgErr.Message, wantText,
			"текст отказа — часть контракта: он называет носителя, предел и вид")
	}
}

// defaultUserCredentialCeiling / defaultSACredentialCeiling — действующие
// величины умолчания.
//
// Были 10 и 20; стали 12 и 24 задачей #1264 вместе с автоснятием истёкших.
// Прежние числа закладывали запас под неотозванные истёкшие удостоверения —
// разбор показал, что запаса в них не было ВОВСЕ: `5 назначений × 2` есть сам
// модельный пик правильной ротации, а не модель с запасом. Разложение и цена —
// в миграции 20260825170000 и в приёмке `expired-credential-reclaim.md` §4.
//
// Числа стоят ЗДЕСЬ ОДНАЖДЫ, а не в каждом кейсе: пять вхождений одного числа
// разошлись бы при следующем пересмотре молча.
const (
	defaultUserCredentialCeiling = 12
	defaultSACredentialCeiling   = 24
)

// CRED-CAP-01 — потолок, который ОГРАНИЧИВАЕТ.
func TestCredQuota_01_EleventhCredentialOfAPersonIsRefused(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	userID, _, _ := credQuotaFixture(t, ctx, pool, "eleventh")

	for i := 1; i <= defaultUserCredentialCeiling; i++ {
		require.NoErrorf(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false),
			"удостоверение %d из %d обязано пройти — потолок, отвергающий разрешённое, "+
				"это не потолок, а поломка", i, defaultUserCredentialCeiling)
	}
	requireQuotaRefusal(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false),
		"KQ001", fmt.Sprintf("has reached its limit of %d iam.user.credential", defaultUserCredentialCeiling))
}

// CRED-CAP-02 — то же у машины.
func TestCredQuota_02_TwentyFirstCredentialOfAServiceAccountIsRefused(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	userID, svaID, _ := credQuotaFixture(t, ctx, pool, "twentyfirst")

	for i := 1; i <= defaultSACredentialCeiling; i++ {
		require.NoErrorf(t, insertSACredential(ctx, pool, svaID, userID, "KEYPAIR"),
			"ключ %d из %d", i, defaultSACredentialCeiling)
	}
	requireQuotaRefusal(t, insertSACredential(ctx, pool, svaID, userID, "KEYPAIR"),
		"KQ001", fmt.Sprintf("has reached its limit of %d iam.serviceAccount.credential", defaultSACredentialCeiling))
}

// CRED-CAP-03 — счёт НЕ дробится по виду предъявления: секрет занимает
// следующее место ТОГО ЖЕ счёта, а не первое место отдельного.
func TestCredQuota_03_SecretTakesTheNextSlotOfTheSameCount(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	userID, _, _ := credQuotaFixture(t, ctx, pool, "samecount")

	for i := 0; i < 3; i++ {
		require.NoError(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false))
	}
	require.NoError(t, insertUserCredential(ctx, pool, userID, "SECRET", false))

	used, _, found := credUsed(t, ctx, pool, "iam.user", userID, kindUserCredential)
	require.True(t, found, "строки учёта нет: списывать нечего, и потолок не наступит")
	require.EqualValues(t, 4, used,
		"секрет завёл СВОЙ счёт: потолок обходится сменой вида предъявления, а обходимый "+
			"потолок хуже отсутствующего")
}

// CRED-CAP-04 — ломающее следствие, утверждённое поведением: исчерпав предел
// ключевыми парами, принципал не получит и секрета.
func TestCredQuota_04_SecretIsRefusedWhenKeypairsExhaustedTheCeiling(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	userID, _, _ := credQuotaFixture(t, ctx, pool, "breaking")
	setCredLimit(t, ctx, pool, kindUserCredential, 2)

	require.NoError(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false))
	require.NoError(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false))
	requireQuotaRefusal(t, insertUserCredential(ctx, pool, userID, "SECRET", false), "KQ001", "")
}

// CRED-CAP-05 — зеркало предыдущего: исчерпав секретами, не получит и пары.
func TestCredQuota_05_KeypairIsRefusedWhenSecretsExhaustedTheCeiling(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	userID, _, _ := credQuotaFixture(t, ctx, pool, "mirror")
	setCredLimit(t, ctx, pool, kindUserCredential, 2)

	require.NoError(t, insertUserCredential(ctx, pool, userID, "SECRET", false))
	require.NoError(t, insertUserCredential(ctx, pool, userID, "SECRET", false))
	requireQuotaRefusal(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false), "KQ001", "")
}

// CRED-CAP-06 — истёкшая строка МЕСТО ЗАНИМАЕТ: слот освобождает отзыв.
func TestCredQuota_06_AnExpiredCredentialStillHoldsItsSlot(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	userID, _, _ := credQuotaFixture(t, ctx, pool, "expired")
	setCredLimit(t, ctx, pool, kindUserCredential, 2)

	require.NoError(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", true), "истёкшее")
	require.NoError(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false), "действующее")
	requireQuotaRefusal(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false), "KQ001", "")
}

// CRED-CAP-07 — исчерпание у одного человека не отказывает другому.
func TestCredQuota_07_AnotherPersonHasTheirOwnCeiling(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	mine, _, _ := credQuotaFixture(t, ctx, pool, "mine")
	theirs, _, _ := credQuotaFixture(t, ctx, pool, "theirs")
	setCredLimit(t, ctx, pool, kindUserCredential, 1)

	require.NoError(t, insertUserCredential(ctx, pool, mine, "KEYPAIR", false))
	requireQuotaRefusal(t, insertUserCredential(ctx, pool, mine, "KEYPAIR", false), "KQ001", "")

	require.NoError(t, insertUserCredential(ctx, pool, theirs, "KEYPAIR", false),
		"исчерпание одного человека отказало другому: счёт ведётся не по принципалу, "+
			"и отказ достаётся невиновному")
}

// CRED-CAP-08 — два вида учёта независимы: исчерпание у человека не расходует
// счёт служебной учётки.
func TestCredQuota_08_TheMachineCountIsIndependentOfThePersonCount(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	userID, svaID, _ := credQuotaFixture(t, ctx, pool, "independent")
	setCredLimit(t, ctx, pool, kindUserCredential, 1)

	require.NoError(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false))
	requireQuotaRefusal(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false), "KQ001", "")

	require.NoError(t, insertSACredential(ctx, pool, svaID, userID, "KEYPAIR"),
		"исчерпание счёта человека отказало машине: два вида учёта считают один счётчик")
}

// CRED-CAP-09 — и наоборот, между двумя служебными учётками.
func TestCredQuota_09_AnotherServiceAccountHasItsOwnCeiling(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	userID, mine, accountID := credQuotaFixture(t, ctx, pool, "svamine")
	setCredLimit(t, ctx, pool, kindSACredential, 1)

	theirs := ids.NewID(domain.PrefixServiceAccount)
	_, err := pool.Exec(ctx, `INSERT INTO service_accounts (id, account_id, name) VALUES ($1, $2, $3)`,
		theirs, accountID, "cred-sva-theirs")
	require.NoError(t, err)

	require.NoError(t, insertSACredential(ctx, pool, mine, userID, "KEYPAIR"))
	requireQuotaRefusal(t, insertSACredential(ctx, pool, mine, userID, "KEYPAIR"), "KQ001", "")
	require.NoError(t, insertSACredential(ctx, pool, theirs, userID, "KEYPAIR"),
		"исчерпание одной учётки отказало другой в том же аккаунте")
}

// CRED-CAP-10 — существующие СВЕРХ предела не удаляются.
func TestCredQuota_10_CredentialsAboveALoweredCeilingSurvive(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	userID, _, _ := credQuotaFixture(t, ctx, pool, "lowered")

	setCredLimit(t, ctx, pool, kindUserCredential, 12)
	for i := 0; i < 12; i++ {
		require.NoError(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false))
	}
	setCredLimit(t, ctx, pool, kindUserCredential, 10)

	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM user_oauth_clients WHERE user_id = $1`, userID).Scan(&rows))
	require.Equal(t, 12, rows, "понижение величины удалило удостоверения — потолок не вправе снимать выданное")

	used, _, _ := credUsed(t, ctx, pool, "iam.user", userID, kindUserCredential)
	require.EqualValues(t, 12, used, "потребление разошлось с тем, что оно считает")

	requireQuotaRefusal(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false),
		"KQ001", "limit of 10 iam.user.credential")

	// Отзыв трёх освобождает место — потолок остаётся достижимым.
	_, err := pool.Exec(ctx, `
		DELETE FROM user_oauth_clients WHERE id IN (
			SELECT id FROM user_oauth_clients WHERE user_id = $1 LIMIT 3)`, userID)
	require.NoError(t, err)
	require.NoError(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false),
		"после отзыва трёх место не вернулось: потребление и строки разошлись")
}

// CRED-CAP-11 — отзыв возвращает место. Положительный контроль к отрицаниям:
// без него «отвергнуто» зеленело бы и на счётчике, который только растёт.
func TestCredQuota_11_RevokingReturnsTheSlot(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	userID, _, _ := credQuotaFixture(t, ctx, pool, "revoke")
	setCredLimit(t, ctx, pool, kindUserCredential, 1)

	last := ids.NewID(domain.PrefixUserOAuthClient)
	require.NoError(t, insertUserCredentialOn(ctx, pool, userID, "KEYPAIR", false, last))
	requireQuotaRefusal(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false), "KQ001", "")

	_, err := pool.Exec(ctx, `DELETE FROM user_oauth_clients WHERE id = $1`, last)
	require.NoError(t, err)

	require.NoError(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false),
		"место, освобождённое отзывом, не вернулось: потолок превратился в счётчик "+
			"выданных за всё время, а это другое ограничение")
}

// CRED-CAP-12 — гонка разрешается оператором БД, а не проверкой в коде.
func TestCredQuota_12_ConcurrentIssueAtTheLastSlotAdmitsExactlyOne(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	userID, _, _ := credQuotaFixture(t, ctx, pool, "race")
	setCredLimit(t, ctx, pool, kindUserCredential, 4)

	for i := 0; i < 3; i++ {
		require.NoError(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false))
	}

	const racers = 8
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		okCount int
		errs    []error
	)
	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func() {
			defer wg.Done()
			err := insertUserCredential(ctx, pool, userID, "KEYPAIR", false)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				okCount++
				return
			}
			errs = append(errs, err)
		}()
	}
	wg.Wait()

	require.Equal(t, 1, okCount,
		"место было одно, а прошло %d: решение принимает не атомарный оператор, и потолок "+
			"протекает ровно под той нагрузкой, ради которой он заведён", okCount)
	require.Len(t, errs, racers-1)
	for _, err := range errs {
		requireQuotaRefusal(t, err, "KQ001", "")
	}

	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM user_oauth_clients WHERE user_id = $1`, userID).Scan(&rows))
	require.Equal(t, 4, rows, "строк больше предела: списание разошлось с тем, что оно считает")
}

// CRED-CAP-13 — величина области аккаунта наступает у МАШИНЫ.
func TestCredQuota_13_AccountScopeOverridesDefaultForTheMachine(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	userID, svaID, accountID := credQuotaFixture(t, ctx, pool, "acctscope")

	_, err := pool.Exec(ctx, `
		INSERT INTO limits (id, scope, scope_id, kind, limit_value)
		VALUES ($1, 'ACCOUNT', $2, $3, 2)`,
		ids.NewHyphenID(ids.PrefixLimitHyphen), accountID, kindSACredential)
	require.NoError(t, err)

	require.NoError(t, insertSACredential(ctx, pool, svaID, userID, "KEYPAIR"))
	require.NoError(t, insertSACredential(ctx, pool, svaID, userID, "KEYPAIR"))
	requireQuotaRefusal(t, insertSACredential(ctx, pool, svaID, userID, "KEYPAIR"),
		"KQ001", "limit of 2 iam.serviceAccount.credential")
}

// CRED-CAP-14 — отзыв величины аккаунта возвращает УМОЛЧАНИЕ, а не «нет предела».
func TestCredQuota_14_WithdrawingTheAccountValueFallsBackToDefault(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	userID, svaID, accountID := credQuotaFixture(t, ctx, pool, "fallback")

	limID := ids.NewHyphenID(ids.PrefixLimitHyphen)
	_, err := pool.Exec(ctx, `
		INSERT INTO limits (id, scope, scope_id, kind, limit_value)
		VALUES ($1, 'ACCOUNT', $2, $3, 1)`, limID, accountID, kindSACredential)
	require.NoError(t, err)

	require.NoError(t, insertSACredential(ctx, pool, svaID, userID, "KEYPAIR"))
	requireQuotaRefusal(t, insertSACredential(ctx, pool, svaID, userID, "KEYPAIR"), "KQ001", "")

	_, err = pool.Exec(ctx, `UPDATE limits SET withdrawn_at = now() WHERE id = $1`, limID)
	require.NoError(t, err)

	require.NoError(t, insertSACredential(ctx, pool, svaID, userID, "KEYPAIR"),
		"после отзыва величины аккаунта не заработало умолчание: отзыв прочитан как "+
			"«предела нет» либо как «предел остался»")
}

// CRED-CAP-15 — область аккаунта к удостоверениям ЧЕЛОВЕКА не применяется.
func TestCredQuota_15_AccountScopeDoesNotBindThePerson(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	userID, _, accountID := credQuotaFixture(t, ctx, pool, "personscope")
	setCredLimit(t, ctx, pool, kindUserCredential, 10)

	_, err := pool.Exec(ctx, `
		INSERT INTO limits (id, scope, scope_id, kind, limit_value)
		VALUES ($1, 'ACCOUNT', $2, $3, 2)`,
		ids.NewHyphenID(ids.PrefixLimitHyphen), accountID, kindUserCredential)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		require.NoErrorf(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false),
			"удостоверение %d отвергнуто величиной ОДНОГО аккаунта: человек состоит во многих, "+
				"и его удостоверение действует во всех — величина одного администратора "+
				"управляла бы доступом в чужих границах", i+1)
	}
	_, limit, _ := credUsed(t, ctx, pool, "iam.user", userID, kindUserCredential)
	require.EqualValues(t, 10, limit, "снимок величины взят из области аккаунта")
}

// CRED-CAP-16 — положительный контроль к предыдущему НА ТОМ ЖЕ стенде: та же
// величина аккаунта, назначенная виду машины, срабатывает. Без него «человек не
// смотрит на область аккаунта» неотличимо от «область аккаунта не работает ни у кого».
func TestCredQuota_16_TheSameAccountValueBindsTheMachineOnTheSameStand(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	userID, svaID, accountID := credQuotaFixture(t, ctx, pool, "bothscopes")
	setCredLimit(t, ctx, pool, kindUserCredential, 10)

	for _, kind := range []string{kindUserCredential, kindSACredential} {
		_, err := pool.Exec(ctx, `
			INSERT INTO limits (id, scope, scope_id, kind, limit_value)
			VALUES ($1, 'ACCOUNT', $2, $3, 2)`, ids.NewHyphenID(ids.PrefixLimitHyphen), accountID, kind)
		require.NoError(t, err)
	}

	for i := 0; i < 3; i++ {
		require.NoError(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false),
			"человек по-прежнему не связан величиной аккаунта")
	}
	require.NoError(t, insertSACredential(ctx, pool, svaID, userID, "KEYPAIR"))
	require.NoError(t, insertSACredential(ctx, pool, svaID, userID, "KEYPAIR"))
	requireQuotaRefusal(t, insertSACredential(ctx, pool, svaID, userID, "KEYPAIR"),
		"KQ001", "limit of 2 iam.serviceAccount.credential")
}

// CRED-CAP-17 — ноль означает «выпускать нельзя», а не «не задано».
func TestCredQuota_17_ZeroIsALegalCeilingAndRefusesEverything(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	userID, _, _ := credQuotaFixture(t, ctx, pool, "zero")
	setCredLimit(t, ctx, pool, kindUserCredential, 0)

	requireQuotaRefusal(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false),
		"KQ001", "limit of 0 iam.user.credential")
}

// CRED-CAP-18 — величина ОТОЗВАНА: другой исход и другой код.
func TestCredQuota_18_AWithdrawnCeilingRefusesWithADifferentCode(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	userID, _, _ := credQuotaFixture(t, ctx, pool, "withdrawn")

	_, err := pool.Exec(ctx, `
		UPDATE limits SET withdrawn_at = now()
		 WHERE kind = $1 AND scope = 'DEFAULT' AND withdrawn_at IS NULL`, kindUserCredential)
	require.NoError(t, err)

	requireQuotaRefusal(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false),
		"KQ002", "has no ceiling stated for iam.user.credential")
}

// CRED-CAP-20 и CRED-CAP-21 — строка учёта заводится ВМЕСТЕ с принципалом, у
// обоих видов, и несёт зеркало аккаунта ровно там, где принадлежность
// однозначна.
//
// Два сценария приёмки в одной пробе НАМЕРЕННО: они утверждают не два поведения,
// а его РАЗЛИЧИЕ между человеком и машиной, а различие наблюдаемо только когда
// обе стороны сняты с одного стенда.
func TestCredQuota_20_TheAccountingRowIsBornWithItsPrincipal(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	userID, svaID, accountID := credQuotaFixture(t, ctx, pool, "lifecycle")

	used, limit, found := credUsed(t, ctx, pool, "iam.user", userID, kindUserCredential)
	require.True(t, found, "у человека нет строки учёта: списывать нечего, и первая же выдача "+
		"отвергается «потолок не назван»")
	require.EqualValues(t, 0, used)
	require.EqualValues(t, defaultUserCredentialCeiling, limit, "снимок величины не взят из авторитета")

	used, limit, found = credUsed(t, ctx, pool, "iam.serviceAccount", svaID, kindSACredential)
	require.True(t, found, "у служебной учётки нет строки учёта")
	require.EqualValues(t, 0, used)
	require.EqualValues(t, defaultSACredentialCeiling, limit)

	var mirror string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT account_id FROM project_resource_quotas
		 WHERE carrier_type = 'iam.serviceAccount' AND carrier_id = $1`, svaID).Scan(&mirror))
	require.Equal(t, accountID, mirror,
		"строка учёта машины не несёт зеркала аккаунта, хотя её принадлежность однозначна")

	require.NoError(t, pool.QueryRow(ctx, `
		SELECT account_id FROM project_resource_quotas
		 WHERE carrier_type = 'iam.user' AND carrier_id = $1`, userID).Scan(&mirror))
	require.Equal(t, "", mirror,
		"строка учёта человека назвала ОДИН аккаунт, хотя членств у него много: записанный "+
			"аккаунт утверждал бы принадлежность, которой нет")
}

// CRED-CAP-22 — строка учёта не переживает своего носителя.
func TestCredQuota_22_TheAccountingRowDiesWithItsPrincipal(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	_, _, _, victimID := credQuotaFixtureWithVictim(t, ctx, pool, "gone")
	_, _, found := credUsed(t, ctx, pool, "iam.user", victimID, kindUserCredential)
	require.True(t, found)
	userID := victimID

	_, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, victimID)
	require.NoError(t, err)

	_, _, found = credUsed(t, ctx, pool, "iam.user", userID, kindUserCredential)
	require.False(t, found,
		"строка учёта пережила своего носителя: перечень растёт монотонно и хранит счёт "+
			"того, кого нет")
}

// CRED-CAP-36 — удаление принципала С УДОСТОВЕРЕНИЯМИ проходит.
//
// Порядок двух срабатываний здесь не назначается и не должен: возврат места —
// условный UPDATE, для которого ноль затронутых строк не отказ; снятие строки
// учёта — DELETE, для которого ноль строк тоже не отказ. Ни один из путей не
// способен отвергнуть удаление, и проба утверждает именно это.
func TestCredQuota_36_DeletingAPrincipalWithCredentialsSucceeds(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	owner, _, _, victimID := credQuotaFixtureWithVictim(t, ctx, pool, "cascade")

	// Удостоверения ЖЕРТВЫ, но выпущенные владельцем аккаунта: ссылка на автора
	// запрещающая, и автор не удаляется, пока его выпуски живы. Предмет здесь —
	// удаление ДЕРЖАТЕЛЯ, а не автора.
	for i := 0; i < 3; i++ {
		require.NoError(t, insertUserCredentialBy(ctx, pool, victimID, owner, "KEYPAIR", false))
	}
	userID := victimID
	_, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, victimID)
	require.NoError(t, err,
		"человека с удостоверениями удалить нельзя: учёт стал запретом на удаление")

	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM user_oauth_clients WHERE user_id = $1`, userID).Scan(&rows))
	require.Zero(t, rows, "удостоверения не ушли каскадом")
}

// CRED-CAP-23 — строка учёта, УТРАЧЕННАЯ отзывом величины, заводится заново с
// ФАКТИЧЕСКИМ числом, а не с нуля.
func TestCredQuota_23_ARestoredAccountingRowCountsWhatIsAlreadyThere(t *testing.T) {
	pool, ctx := newCredQuotaDB(t)
	userID, _, _ := credQuotaFixture(t, ctx, pool, "restored")
	setCredLimit(t, ctx, pool, kindUserCredential, 5)

	for i := 0; i < 4; i++ {
		require.NoError(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false))
	}

	// Строка учёта УТРАЧЕНА. Причина здесь не важна и намеренно подаётся прямо:
	// её снимает откат величины и восстановление базы, а у принципала, заведённого
	// до появления этой оси, её не было вовсе. Важно, что происходит ПОТОМ.
	_, err := pool.Exec(ctx, `
		DELETE FROM project_resource_quotas
		 WHERE carrier_type = 'iam.user' AND carrier_id = $1 AND kind = $2`,
		userID, kindUserCredential)
	require.NoError(t, err)
	_, _, found := credUsed(t, ctx, pool, "iam.user", userID, kindUserCredential)
	require.False(t, found, "предпосылка сценария не создана: строка учёта на месте")

	require.NoError(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false),
		"пятое удостоверение обязано пройти: мест было пять, занято четыре")
	used, _, _ := credUsed(t, ctx, pool, "iam.user", userID, kindUserCredential)
	require.EqualValues(t, 5, used,
		"строка учёта заведена заново с НУЛЯ при четырёх лежащих удостоверениях: возврат "+
			"отозванной величины подарил бы принципалу полный потолок сверх имеющегося")
	requireQuotaRefusal(t, insertUserCredential(ctx, pool, userID, "KEYPAIR", false), "KQ001", "")
}

var _ = fmt.Sprintf
