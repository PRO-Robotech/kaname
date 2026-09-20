// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// consent_schema_integration_test.go — СХЕМА согласия субъекта (kaname#313,
// миграция `20260920175119_consent_is_our_record.sql`).
//
// Проба идёт ПОСЛЕ миграции: предмет — сама схема.
//
// # Что утверждают пробы
//
//   - УНИКАЛЬНОСТЬ ТРОЙКИ держит БАЗА. N одновременных вставок одной тройки
//     дают РОВНО одну строку; остальные получают 23505 по имени ограничения.
//     Проверка-затем-запись здесь дала бы N строк, и положительный путь при
//     этом был бы зелёным;
//   - ОТЗЫВ — ОТМЕТКА, а повторное согласие — снятие отметки на ТОЙ ЖЕ строке:
//     «согласия не было» и «согласие отозвано» различаются;
//   - ПУСТАЯ ОБЛАСТЬ отвергается, и рядом стоит положительный контроль;
//   - УХОД клиента уносит его согласия каскадом;
//   - ОБРАТНЫЙ ХОД снимается и накатывается снова.
package migrations_test

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

const consentMigration = "20260920175119_consent_is_our_record.sql"

func cgDB(t *testing.T) *sql.DB {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	return upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
}

// TestIntegration_ConsentTripleIsUniqueByTheDatabase — уникальность тройки под
// конкуренцией.
func TestIntegration_ConsentTripleIsUniqueByTheDatabase(t *testing.T) {
	db := cgDB(t)
	client, user, _, _ := acScene(t, db, "cgthree")

	const racers = 8
	won := make([]bool, racers)
	conflicts := make([]string, racers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := db.Exec(`
				INSERT INTO kaname.consent_grants (id, user_id, client_id, scope)
				VALUES ($1, $2, $3, 'openid')`,
				"cg-"+acPad(fmt.Sprintf("cgthree%d", i)), user, client)
			if err == nil {
				won[i] = true
				return
			}
			var pgErr *pgconn.PgError
			if ok := asPgError(err, &pgErr); ok {
				conflicts[i] = pgErr.Code + ":" + pgErr.ConstraintName
			}
		}(i)
	}
	close(start)
	wg.Wait()

	var winners int
	for _, w := range won {
		if w {
			winners++
		}
	}
	var rows int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.consent_grants WHERE user_id = $1 AND client_id = $2 AND scope = 'openid'`,
		user, client).Scan(&rows))
	t.Logf("перепись: гонщиков %d, вставок %d, строк тройки %d, отказы %v", racers, winners, rows, conflicts)
	require.Equal(t, 1, winners, "вставок обязана пройти РОВНО одна, прошло %d", winners)
	require.Equal(t, 1, rows, "строк на тройку обязана быть РОВНО одна, стоит %d", rows)
	for i, c := range conflicts {
		if won[i] {
			continue
		}
		require.Equal(t, "23505:consent_grants_subject_client_scope_uk", c,
			"проигравший обязан получить отказ ИМЕННО от ограничения тройки")
	}
}

// TestIntegration_ConsentWithdrawalIsAMarkAndRegrantReusesTheRow — отзыв и
// повторное согласие на той же строке.
func TestIntegration_ConsentWithdrawalIsAMarkAndRegrantReusesTheRow(t *testing.T) {
	db := cgDB(t)
	client, user, _, _ := acScene(t, db, "cgmark")
	id := "cg-" + acPad("cgmark")

	_, err := db.Exec(`
		INSERT INTO kaname.consent_grants (id, user_id, client_id, scope)
		VALUES ($1, $2, $3, 'profile')`, id, user, client)
	require.NoError(t, err, "положительный контроль")

	_, err = db.Exec(`UPDATE kaname.consent_grants SET revoked_at = now() WHERE id = $1`, id)
	require.NoError(t, err)

	// «Согласия не было» и «согласие отозвано» РАЗЛИЧАЮТСЯ: строка на месте.
	var revoked *string
	require.NoError(t, db.QueryRow(
		`SELECT revoked_at::text FROM kaname.consent_grants WHERE id = $1`, id).Scan(&revoked))
	require.NotNil(t, revoked, "отозванное согласие обязано остаться строкой с отметкой")

	// Повторное согласие — ТА ЖЕ строка, а не вторая.
	_, err = db.Exec(`
		INSERT INTO kaname.consent_grants (id, user_id, client_id, scope)
		VALUES ($1, $2, $3, 'profile')
		ON CONFLICT (user_id, client_id, scope)
		DO UPDATE SET revoked_at = NULL, granted_at = now()`,
		"cg-"+acPad("cgmark2"), user, client)
	require.NoError(t, err)

	var rows int
	var stillRevoked *string
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.consent_grants WHERE user_id = $1 AND client_id = $2 AND scope = 'profile'`,
		user, client).Scan(&rows))
	require.Equal(t, 1, rows, "повторное согласие обязано лечь на ТУ ЖЕ строку, строк %d", rows)
	require.NoError(t, db.QueryRow(
		`SELECT revoked_at::text FROM kaname.consent_grants WHERE id = $1`, id).Scan(&stillRevoked))
	require.Nil(t, stillRevoked, "повторное согласие обязано снять отметку отзыва")
}

// TestIntegration_ConsentRefusesAnEmptyScopeAndFollowsItsClient — пустая область
// и каскад по клиенту.
//
// Каскад проверяется по КЛИЕНТУ, а не по человеку: посеянный человек — владелец
// своего аккаунта, и снять его раньше аккаунта не даёт `accounts_owner_fk`, а
// снять аккаунт раньше человека — `users_account_fk`. Проба, поставленная на эту
// пару, упиралась бы в ЧУЖОЙ ключ, а не в свой, и о своём каскаде не говорила бы
// ничего. Ключ на человека объявлен тем же `ON DELETE CASCADE` и снимается тем же
// механизмом.
func TestIntegration_ConsentRefusesAnEmptyScopeAndFollowsItsClient(t *testing.T) {
	db := cgDB(t)
	client, user, _, _ := acScene(t, db, "cgcasc")

	_, err := db.Exec(`
		INSERT INTO kaname.consent_grants (id, user_id, client_id, scope)
		VALUES ($1, $2, $3, '')`, "cg-"+acPad("cgempty"), user, client)
	requirePgRefusal(t, err, "23514", "consent_grants_scope_ck",
		"пустая область обязана быть отвергнута: это не «все права», а отсутствие решения")

	_, err = db.Exec(`
		INSERT INTO kaname.consent_grants (id, user_id, client_id, scope)
		VALUES ($1, $2, $3, 'openid')`, "cg-"+acPad("cgcasc"), user, client)
	require.NoError(t, err, "положительный контроль")

	// Уход клиента уносит согласия каскадом; семейство уходит тем же ключом.
	_, err = db.Exec(`DELETE FROM kaname.interactive_clients WHERE client_id = $1`, client)
	require.NoError(t, err, "снятие клиента")

	var rows int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.consent_grants WHERE client_id = $1`, client).Scan(&rows))
	require.Zero(t, rows, "согласия обязаны уйти вместе с человеком, осталось %d", rows)
}

// TestIntegration_ConsentMigrationRollsBackAndForward — обратный ход.
func TestIntegration_ConsentMigrationRollsBackAndForward(t *testing.T) {
	db := cgDB(t)
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))

	own, previous := versionsOf(t, consentMigration)
	require.NoError(t, goose.DownTo(db, ".", previous))

	const countTable = `
		SELECT count(*) FROM information_schema.tables
		 WHERE table_schema = 'kaname' AND table_name = 'consent_grants'`
	var present int
	require.NoError(t, db.QueryRow(countTable).Scan(&present))
	require.Zero(t, present, "после отката таблицы остаться не должно")

	require.NoError(t, goose.Up(db, "."))
	require.NoError(t, db.QueryRow(countTable).Scan(&present))
	require.Equal(t, 1, present, "после повторного наката таблица обязана стоять")

	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.GreaterOrEqual(t, version, own, "цепочка обязана стоять не ниже предмета")
}

// asPgError — отказ от СЕРВЕРА, а не от драйвера: отказ иного происхождения
// проба обязана отличать, иначе «проигравший получил 23505» было бы истинно и
// на оборванной связи.
func asPgError(err error, target **pgconn.PgError) bool {
	return errors.As(err, target)
}
