// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_key_handle_comment_generations_integration_test.go — описание колонки
// `kaname.user_access_keys.user_handle` говорит правду о КАЖДОЙ строке, которая
// может в ней лежать (задача PRO-Robotech/kaname#344; миграция
// `20261005024608_access_key_handle_comment_names_both_generations.sql`).
//
// Решение Ф13 Р3 кладёт новое значение рукоятки ТОЛЬКО новым регистрациям:
// ключ, заведённый до миграции `20261003212856`, сохраняет то, что тогда легло
// в его строку (у ключей Ф7 — байты платформенного id человека), и сверяется со
// своим — переписать значение, уже лежащее в аутентификаторе, нечем. Описание
// колонки, утверждающее о ВСЕХ строках то, что верно лишь о новых, — тот же
// класс, что и комментарий применённой миграции, который оно заменило: схема
// сообщает читателю снятое как действующее.
//
// Предмет проверяется на лежащей строке, а не на одном тексте: строка прежнего
// поколения заводится на ревизии ДО смены значения, переживает накат всей
// цепочки неизменной — и только при этом условии требование к описанию
// осмысленно.
package migrations_test

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// keyHandleCommentMigration — файл предмета.
const keyHandleCommentMigration = "20261005024608_access_key_handle_comment_names_both_generations.sql"

// ceremonyHandleMigration — миграция, с которой церемония кладёт в строку ключа
// значение из `kaname.user_ceremony_handles`; её номер — граница поколений.
const ceremonyHandleMigration = "20261003212856_ceremony_handle_is_its_own_random_value.sql"

func keyHandleComment(t *testing.T, db *sql.DB) string {
	t.Helper()
	var c sql.NullString
	require.NoError(t, db.QueryRow(`
		SELECT col_description('kaname.user_access_keys'::regclass, a.attnum)
		  FROM pg_attribute a
		 WHERE a.attrelid = 'kaname.user_access_keys'::regclass AND a.attname = 'user_handle'`).Scan(&c))
	require.True(t, c.Valid, "у колонки user_handle нет описания вовсе")
	return c.String
}

func keyHandleDB(t *testing.T, upTo int64) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpTo(db, ".", upTo), "цепочка обязана дойти до версии %d", upTo)
	return db
}

// Ключ прежнего поколения переживает накат всей цепочки со своим значением, и
// описание колонки на голове называет оба поколения границей, по которой
// читатель отличит одно от другого, и смысл NULL.
func TestIntegration_KeyHandleCommentNamesBothGenerations(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	_, beforeCeremony := versionsOf(t, ceremonyHandleMigration)
	db := keyHandleDB(t, beforeCeremony)

	_, user, _, _ := acScene(t, db, "khg1")
	legacy := []byte(user) // так клала рукоятку церемония Ф7 до решения Ф13 Р3
	// Потолок ключей человека объявлен: без него схема отвергает вставку
	// (KQ002), и фикстура не бывает снисходительнее продукта.
	_, err := db.Exec(`INSERT INTO kaname.own_ceilings (kind, limit_value) VALUES ('iam.user.accessKey', 10)`)
	require.NoError(t, err, "потолок ключей человека")
	_, err = db.Exec(`
		INSERT INTO kaname.user_access_keys (id, user_id, credential_id, public_key, algorithm, user_handle, name)
		VALUES ('ak-'||$1, $2, $3, '\x01', -7, $4, 'legacy-key')`,
		acPad("khg1"), user, []byte("credential-khg1-0123456789"), legacy)
	require.NoError(t, err, "посев ключа прежнего поколения")

	require.NoError(t, goose.Up(db, "."), "накат всей цепочки")

	var kept []byte
	require.NoError(t, db.QueryRow(
		`SELECT user_handle FROM kaname.user_access_keys WHERE user_id = $1`, user).Scan(&kept))
	require.Equal(t, legacy, kept,
		"предпосылка: строка прежнего поколения обязана пережить цепочку со своим значением (Ф13 Р3, обратного заполнения нет)")

	comment := keyHandleComment(t, db)
	for _, want := range []struct{ fragment, why string }{
		{"kaname.user_ceremony_handles", "источник значения у ключей нового поколения"},
		{"20261003212856", "граница поколений: без неё читатель не отличит строку, лежащую выше, от новой"},
		{"платформенный id человека как байты", "значение строк прежнего поколения — оно лежит в базе, и описание не вправе его отрицать"},
		{"NULL", "смысл отсутствующего значения: колонка допускает NULL"},
	} {
		require.Truef(t, strings.Contains(comment, want.fragment),
			"описание колонки user_handle не называет %q (%s); описание: %q", want.fragment, want.why, comment)
	}
	require.NotContainsf(t, comment, "Платформенным id человека НЕ является",
		"описание утверждает о ВСЕХ строках то, что опровергает лежащая строка %q", user)
}

// Откат предмета возвращает ровно то описание, что стояло до него, а накат —
// ровно объявленное предметом: ход в обе стороны не теряет и не дописывает.
func TestIntegration_KeyHandleCommentRollsBackToThePreviousOne(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	own, previous := versionsOf(t, keyHandleCommentMigration)
	db := keyHandleDB(t, previous)
	before := keyHandleComment(t, db)

	require.NoError(t, goose.UpTo(db, ".", own), "накат предмета")
	after := keyHandleComment(t, db)
	require.NotEqual(t, before, after, "накат предмета не сменил описание колонки")

	require.NoError(t, goose.DownTo(db, ".", previous), "откат предмета")
	require.Equal(t, before, keyHandleComment(t, db), "откат вернул не то описание, что стояло до предмета")

	require.NoError(t, goose.UpTo(db, ".", own), "повторный накат предмета")
	require.Equal(t, after, keyHandleComment(t, db), "повторный накат дал другое описание")
}
