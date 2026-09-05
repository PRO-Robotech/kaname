// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// baseline_down_guard_integration_test.go — обратный ход свода ОТКАЗЫВАЕТСЯ
// уничтожать удостоверения вида SECRET.
//
// # Почему проба заведена вместе со сведением
//
// Страж стоял в откатной половине ОДНОЙ из 171 миграции. Сведение унесло бы его
// молча — и это худший вид утраты: обратный ход свода (`DROP SCHEMA … CASCADE`)
// разрушительнее того шага, который страж стерёг, а его отсутствие ничем не
// наблюдаемо. Страж перенесён в откатную половину свода; здесь — доказательство,
// что он ЖИВ, а не просто написан.
//
// # Предмет стража, а не его форма
//
// Секрет вида SECRET предъявляется арендатору ОДИН раз, в хранилище лежит только
// его свёртка. Удалённая строка не восстанавливается ничем: резервной копии
// секрета не существует by construction, а повторная выдача даёт ДРУГОЕ
// удостоверение, под которое надо перенастроить каждого предъявителя. Обычная
// потеря данных обратима восстановлением; эта — нет.
//
// # Обе стороны, иначе утверждения нет
//
// Отрицание («откат отказан») на схеме, где откат сломан всегда, выполняется
// тождественно. Поэтому рядом стоит положительный контроль: без строк вида
// SECRET тот же откат ПРОХОДИТ.

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/migrations"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// baselineUp применяет свод к чистой базе и отдаёт соединение.
func baselineUp(t *testing.T) *sql.DB {
	t.Helper()
	dsn := pgtest.NewEmptyDB(t)
	require.NoError(t, pgtest.Goose(migrations.FS)(context.Background(), dsn),
		"свод обязан примениться к чистой базе — иначе предмет пробы не создан")
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// baselineDown зовёт обратный ход свода ТЕМ ЖЕ инструментом, каким его зовёт
// оператор, а не копией его текста: копия разошлась бы с файлом молча.
//
// # Почему DownTo(0), а не Down
//
// `goose.Down` откатывает РОВНО ОДНУ, самую позднюю миграцию. Пока в каталоге
// лежал ОДИН файл, «самая поздняя» и «свод» совпадали — и совпадение это читалось
// как обращение к своду. Первая же вторая миграция разводит их: `Down` откатит
// ЕЁ, вернёт nil, и обе пробы ниже покраснеют, не сказав ни слова о страже. Хуже
// того, отрицание покраснело бы по причине, к предмету стража отношения не
// имеющей, — а положительный контроль объявил бы схему неснесённой при исправном
// своде.
//
// Это предпосылка, верная ОТНОСИТЕЛЬНО ПОПУЛЯЦИИ, на которой проба писалась
// (один файл после сведения 171 миграции). Узкая популяция предпосылку не
// подтверждала — она её СКРЫВАЛА; обнажил её первый же преемник (#2026).
//
// `DownTo(…, 0)` называет ЦЕЛЬ — «до пустой базы», — а не «на шаг назад», и
// потому не зависит от того, сколько миграций легло поверх свода: откатная
// половина каждой исполняется по очереди, и страж свода доходит до слова
// последним.
func baselineDown(t *testing.T, db *sql.DB) error {
	t.Helper()
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	return goose.DownTo(db, ".", 0)
}

// seedSecretCredentialOwners сеет аккаунт, человека и служебную учётку ОДНОЙ
// транзакцией: аккаунт и его владелец ссылаются друг на друга, ключи между ними
// отложены, и порядок вставки не определён by construction.
func seedSecretCredentialOwners(t *testing.T, db *sql.DB) {
	t.Helper()
	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec(`SET CONSTRAINTS ALL DEFERRED`)
	require.NoError(t, err)
	_, err = tx.Exec(`INSERT INTO kacho_iam.accounts (id, name, owner_user_id)
	                  VALUES ('acc00000000000000dwn', 'down-guard', 'usr00000000000000dwn')`)
	require.NoError(t, err, "посев аккаунта")
	_, err = tx.Exec(`INSERT INTO kacho_iam.users (id, external_id, email, account_id, invite_status)
	                  VALUES ('usr00000000000000dwn', 'ext-down', 'down@example.invalid',
	                          'acc00000000000000dwn', 'ACTIVE')`)
	require.NoError(t, err, "посев человека")
	_, err = tx.Exec(`INSERT INTO kacho_iam.service_accounts (id, account_id, name)
	                  VALUES ('sva00000000000000dwn', 'acc00000000000000dwn', 'down-guard-sa')`)
	require.NoError(t, err, "посев служебной учётки")
	require.NoError(t, tx.Commit(), "посев владельцев удостоверений")
}

func insertSecretCred(t *testing.T, db *sql.DB) {
	t.Helper()
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 3)
	}
	_, err := db.Exec(`INSERT INTO kacho_iam.service_account_oauth_clients
	    (id, sva_id, hydra_client_id, created_by_user_id, credential_kind, secret_hash,
	     public_key_pem, key_algorithm, trusted_subjects, expires_at)
	  VALUES ('soc_00000000000000dwn', 'sva00000000000000dwn', NULL, 'usr00000000000000dwn',
	          'SECRET', $1, '', '', '[]'::jsonb, now() + interval '30 days')`, hash)
	require.NoError(t, err,
		"Given неисполним, если законная строка вида SECRET не записывается")
}

// TestBaselineDownRefusesWhileSecretCredentialsExist — ОТРИЦАНИЕ.
func TestBaselineDownRefusesWhileSecretCredentialsExist(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := baselineUp(t)
	seedSecretCredentialOwners(t, db)
	insertSecretCred(t, db)

	err := baselineDown(t, db)
	require.Error(t, err,
		"обратный ход свода обязан ОТКАЗАТЬСЯ при живых удостоверениях вида SECRET")

	// Утверждается не «есть слово», а четыре РАЗНЫХ слагаемых: что происходит ·
	// почему необратимо · где именно лежат строки · что делать. Проверка на одно
	// слово зеленела бы на сообщении «error: SECRET».
	//
	// Всё это обязано стоять в ОСНОВНОМ сообщении: goose доносит до оператора
	// только его, DETAIL и HINT в его вывод не попадают. Выход, положенный в
	// HINT, не доехал бы ни до кого, и оператор, прочитав «откат невозможен» без
	// указания что делать, обошёл бы страж — то есть уничтожил бы ровно те
	// удостоверения, ради которых страж стоит.
	msg := strings.ToLower(err.Error())
	for want, why := range map[string]string{
		"irreversibl":                     "последствие: удаление необратимо",
		"only its digest":                 "почему необратимо: секрет не хранится",
		"way out":                         "штатный выход обязан быть НАЗВАН, иначе страж обходят",
		"revoke":                          "штатный выход: сперва отозвать продуктовым глаголом",
		"service_account_oauth_clients 1": "число ПО КАЖДОЙ таблице: общее число не говорит, где отзывать",
	} {
		require.Contains(t, msg, want,
			"основное сообщение отказа обязано нести %s: %v", why, err)
	}

	// Отказ обязан НИЧЕГО НЕ РАЗРУШИТЬ: страж стоит до первого DROP, иначе
	// оператор чинил бы две беды вместо одной.
	var n int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kacho_iam.service_account_oauth_clients`).Scan(&n),
		"схема обязана быть цела: отказ наступил ДО единого разрушающего оператора")
	require.Equal(t, 1, n, "строка вида SECRET обязана уцелеть")
}

// TestBaselineDownProceedsWithoutSecretCredentials — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
//
// Без него отрицание выше ничего не утверждает: оно зеленело бы и на своде,
// откат которого сломан при любом входе.
func TestBaselineDownProceedsWithoutSecretCredentials(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := baselineUp(t)
	seedSecretCredentialOwners(t, db)

	var before int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kacho_iam.service_account_oauth_clients
		  WHERE credential_kind = 'SECRET'`).Scan(&before))
	require.Zero(t, before, "предпосылка контроля: строк вида SECRET нет")

	require.NoError(t, baselineDown(t, db),
		"без строк вида SECRET обратный ход обязан ПРОЙТИ — иначе страж отвергает всё, "+
			"и отрицание рядом выполняется тождественно")

	var exists bool
	require.NoError(t, db.QueryRow(
		`SELECT to_regclass('kacho_iam.accounts') IS NOT NULL`).Scan(&exists))
	require.False(t, exists, "обратный ход обязан снести схему, а не только промолчать")
}
