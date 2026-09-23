// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_token_family_schema_integration_test.go — ВЫПУСК ТОКЕНА ДОСТУПА
// ПРИНАДЛЕЖИТ СВОЕМУ СЕМЕЙСТВУ, и эту связь держит схема (kaname#319, решение
// К10 вариант А; приёмка LINE-A-1, сценарии 21 и 28).
//
// # Что утверждается
//
//   - выпуск заводится только в ЖИВОЕ семейство: неизвестное и отозванное
//     семейство отвергает внешний ключ, а не проверка перед вставкой;
//   - идентификатор выпуска единственен — первичным ключом;
//   - отзыв семейства доезжает до каждой записи выпуска КАСКАДОМ ключа, а не
//     вторым оператором писателя;
//   - снятие семейства (удаление его строки по каскаду клиента, человека,
//     сессии) запись выпуска НЕ уносит: она остаётся с пустой живостью.
//     Унести её значило бы превратить «семейство снято» в «выпуск семейству не
//     принадлежит», то есть снятие — в допуск;
//   - гонка «заведение выпуска × отзыв семейства» не оставляет ЖИВОЙ записи в
//     отозванном семействе ни при каком чередовании.
//
// # Почему сырыми операторами
//
// Предмет проб — СХЕМА. Путь через слой доступа отсёк бы негодный вход до базы,
// и проба судила бы писателя, а не ограничение.
package migrations_test

import (
	"database/sql"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// accessTokenMigration — файл, заводящий предмет этих проб.
const accessTokenMigration = "20260923231545_access_token_belongs_to_its_family.sql"

// atJTI — идентификатор выпуска объявленной формы: `tok` и 17 знаков
// crockford-base32 — та же форма, что чеканит подписант (`ids.NewID("tok")`).
func atJTI(tag string) string { return "tok" + acPad(tag) }

// requireAccessTokensTable — предмет существует. Отдельное утверждение, а не
// ошибка фикстуры: отсутствие таблицы — это отсутствие предмета, и сказано оно
// должно быть так, а не текстом драйвера про неизвестное отношение.
func requireAccessTokensTable(t *testing.T, db *sql.DB) {
	t.Helper()
	var present bool
	require.NoError(t, db.QueryRow(
		`SELECT to_regclass('kaname.access_tokens') IS NOT NULL`).Scan(&present))
	require.True(t, present,
		"записи выпуска токена доступа в схеме нет: семейство выпуска узнать не из чего, "+
			"и отзыв семейства до предъявления не доезжает")
}

// atInsert — заведение выпуска сырым оператором. Живость семейства писатель НЕ
// пишет: её берёт умолчание, и ключ сверяет её с семейством.
func atInsert(db *sql.DB, jti, family string) error {
	_, err := db.Exec(`
		INSERT INTO kaname.access_tokens (jti, family_id, issued_at, expires_at)
		VALUES ($1, $2, now(), now() + interval '15 minutes')`, jti, family)
	return err
}

// atFamilyLive — живость семейства на записи выпуска: true, false либо NULL
// (семейство снято).
func atFamilyLive(t *testing.T, db *sql.DB, jti string) sql.NullBool {
	t.Helper()
	var live sql.NullBool
	require.NoError(t, db.QueryRow(
		`SELECT family_live FROM kaname.access_tokens WHERE jti = $1`, jti).Scan(&live),
		"запись выпуска %s обязана существовать", jti)
	return live
}

// atFamily заводит ЕЩЁ ОДНО семейство в сессии сцены. Сцена на раунд не
// годится: свёртка носителя сессии в ней выводится из длины метки, и две сцены
// с метками одной длины столкнулись бы на уникальности носителя.
func atFamily(t *testing.T, db *sql.DB, client, user, session, tag string) string {
	t.Helper()
	family := "tfm-" + acPad("f"+tag)
	_, err := db.Exec(`
		INSERT INTO kaname.token_families (id, client_id, user_id, session_id, scope)
		VALUES ($1, $2, $3, $4, ARRAY['openid','profile'])`,
		family, client, user, session)
	require.NoError(t, err, "посев семейства %s", tag)
	return family
}

// atRevokeFamily — отзыв семейства тем оператором, которым его пишет слой
// доступа: отметка и живость одним оператором.
func atRevokeFamily(db *sql.DB, family string) error {
	_, err := db.Exec(`
		UPDATE kaname.token_families
		   SET revoked_at = now(), revoked_reason = 'refresh-replay', live = false
		 WHERE id = $1 AND revoked_at IS NULL`, family)
	return err
}

// TestIntegration_LINE_A_1_28_AccessTokenIsIssuedIntoALiveFamilyOnly — выпуск
// заводится только в живое семейство, и отзыв доезжает до него каскадом.
func TestIntegration_LINE_A_1_28_AccessTokenIsIssuedIntoALiveFamilyOnly(t *testing.T) {
	db := acDB(t)
	requireAccessTokensTable(t, db)
	_, _, _, family := acScene(t, db, "atkeyd")

	// Положительный близнец: живое семейство принимает выпуск, и запись
	// называет его живым.
	require.NoError(t, atInsert(db, atJTI("a1"), family), "выпуск в живое семейство")
	live := atFamilyLive(t, db, atJTI("a1"))
	require.True(t, live.Valid && live.Bool, "выпуск живого семейства обязан быть живым: %+v", live)

	// Неизвестное семейство — отказ ключа.
	requirePgRefusal(t, atInsert(db, atJTI("a2"), "tfm-"+acPad("absent")),
		"23503", "access_tokens_family_fk", "выпуск в семейство, которого нет")

	// Идентификатор единственен.
	requirePgRefusal(t, atInsert(db, atJTI("a1"), family),
		"23505", "access_tokens_pkey", "второй выпуск с тем же идентификатором")

	// Отзыв семейства доезжает до выпуска КАСКАДОМ.
	require.NoError(t, atRevokeFamily(db, family))
	live = atFamilyLive(t, db, atJTI("a1"))
	require.True(t, live.Valid, "живость выпуска отозванного семейства обязана быть названа")
	require.False(t, live.Bool, "отзыв семейства не доехал до его выпуска")

	// Отозванное семейство выпуска не принимает.
	requirePgRefusal(t, atInsert(db, atJTI("a3"), family),
		"23503", "access_tokens_family_fk", "выпуск в отозванное семейство")
}

// TestIntegration_AccessTokenOutlivesItsRemovedFamily — снятие семейства
// удалением строки оставляет запись выпуска с пустой живостью.
func TestIntegration_AccessTokenOutlivesItsRemovedFamily(t *testing.T) {
	db := acDB(t)
	requireAccessTokensTable(t, db)
	client, _, _, family := acScene(t, db, "atdrp")

	require.NoError(t, atInsert(db, atJTI("g1"), family))

	// Снятие клиента удаляет его семейства каскадом — продукт делает ровно это.
	res, err := db.Exec(`DELETE FROM kaname.interactive_clients WHERE client_id = $1`, client)
	require.NoError(t, err)
	n, err := res.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "снят обязан быть ровно один клиент")

	var families int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.token_families WHERE id = $1`, family).Scan(&families))
	require.Zero(t, families, "семейство снятого клиента обязано уйти каскадом — сцена не построена")

	live := atFamilyLive(t, db, atJTI("g1"))
	require.False(t, live.Valid,
		"запись выпуска снятого семейства обязана остаться с ПУСТОЙ живостью: %+v", live)

	var recorded string
	require.NoError(t, db.QueryRow(
		`SELECT family_id FROM kaname.access_tokens WHERE jti = $1`, atJTI("g1")).Scan(&recorded))
	require.Equal(t, family, recorded, "запись выпуска обязана помнить своё семейство")
}

// TestIntegration_AccessTokenFormsAreClosed — формы значений закрыты схемой.
func TestIntegration_AccessTokenFormsAreClosed(t *testing.T) {
	db := acDB(t)
	requireAccessTokensTable(t, db)
	_, _, _, family := acScene(t, db, "atfrm")

	// Положительный близнец.
	require.NoError(t, atInsert(db, atJTI("f1"), family))

	requirePgRefusal(t, atInsert(db, "jti-not-our-form", family),
		"23514", "access_tokens_jti_form_ck", "идентификатор не нашей формы")

	_, err := db.Exec(`
		INSERT INTO kaname.access_tokens (jti, family_id, issued_at, expires_at)
		VALUES ($1, $2, now(), now())`, atJTI("f2"), family)
	requirePgRefusal(t, err, "23514", "access_tokens_expiry_after_issue_ck",
		"срок не позже выпуска")
}

// TestIntegration_LINE_A_1_28_IssuanceRacingRevocationLeavesNoLiveToken — гонка
// «заведение выпуска × отзыв семейства».
//
// Чередований два, и оба законны: успел отзыв — заведение получает отказ
// ключа; успело заведение — каскад проставляет записи отозванность. Незаконно
// одно: живая запись выпуска в отозванном семействе.
func TestIntegration_LINE_A_1_28_IssuanceRacingRevocationLeavesNoLiveToken(t *testing.T) {
	db := acDB(t)
	requireAccessTokensTable(t, db)
	db.SetMaxOpenConns(8)

	client, user, session, _ := acScene(t, db, "atrace")

	const rounds = 24
	var inserted, refused int
	for i := 0; i < rounds; i++ {
		family := atFamily(t, db, client, user, session, fmt.Sprintf("r%02d", i))
		jti := atJTI(fmt.Sprintf("r%02d", i))

		var wg sync.WaitGroup
		start := make(chan struct{})
		var insErr, revErr error
		wg.Add(2)
		go func() { defer wg.Done(); <-start; insErr = atInsert(db, jti, family) }()
		go func() { defer wg.Done(); <-start; revErr = atRevokeFamily(db, family) }()
		close(start)
		wg.Wait()

		require.NoError(t, revErr, "отзыв семейства обязан состояться в раунде %d", i)
		if insErr != nil {
			var pgErr *pgconn.PgError
			require.ErrorAs(t, insErr, &pgErr, "раунд %d: отказ обязан прийти от базы", i)
			require.Equal(t, "23503", pgErr.Code, "раунд %d: отказ заведения — только ключом", i)
			require.Equal(t, "access_tokens_family_fk", pgErr.ConstraintName)
			refused++
			continue
		}
		inserted++
		live := atFamilyLive(t, db, jti)
		require.True(t, live.Valid && !live.Bool,
			"раунд %d: запись выпуска ЖИВА в отозванном семействе: %+v", i, live)
	}
	t.Logf("перепись гонки: раундов %d, заведение успело %d, отзыв успел %d", rounds, inserted, refused)
	require.Equal(t, rounds, inserted+refused)
}

// TestIntegration_AccessTokenMigrationRollsBackAndForward — обратный ход.
func TestIntegration_AccessTokenMigrationRollsBackAndForward(t *testing.T) {
	db := acDB(t)
	requireAccessTokensTable(t, db)
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))

	own, previous := versionsOf(t, accessTokenMigration)
	require.NoError(t, goose.DownTo(db, ".", previous), "обратный ход обязан снять предмет")

	var present bool
	require.NoError(t, db.QueryRow(
		`SELECT to_regclass('kaname.access_tokens') IS NOT NULL`).Scan(&present))
	require.False(t, present, "после отката таблица выпусков остаться не должна")
	require.NoError(t, db.QueryRow(
		`SELECT to_regclass('kaname.token_families') IS NOT NULL`).Scan(&present))
	require.True(t, present, "откат обязан снять ТОЛЬКО свой предмет, семейства остаются")

	require.NoError(t, goose.Up(db, "."), "цепочка обязана накатываться снова")
	requireAccessTokensTable(t, db)

	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.GreaterOrEqual(t, version, own, "цепочка обязана стоять не ниже предмета")
}
