// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_family_login_level_schema_integration_test.go — СНИМОК УРОВНЯ ГРАНТА у
// семейства (задача PRO-Robotech/kaname#423; миграция
// `20260925121413_token_family_carries_its_login_level.sql`).
//
// Предмет — схема: лежащее семейство получает уровень своей сессии обратным
// заполнением; новое без уровня и с уровнем вне оси схема отвергает; откат
// снимает колонку вместе с её ограничением. Близнец каждого отказа отличается
// одним значением.
package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// familyLevelMigration — файл предмета; по нему вычисляются версии обоих ходов.
const familyLevelMigration = "20260925121413_token_family_carries_its_login_level.sql"

// familyLevelConstraint — ограничение оси уровня у семейства.
const familyLevelConstraint = "token_families_acr_ck"

func familyLevelDB(t *testing.T) (*sql.DB, int64, int64) {
	t.Helper()
	own, previous := versionsOf(t, familyLevelMigration)
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpTo(db, ".", previous), "цепочка обязана дойти до версии перед предметом")
	return db, own, previous
}

// Лежащее семейство получает уровень СВОЕЙ сессии: у двух семейств разных
// сессий уровни разные, и каждое берёт свой.
func TestIntegration_FamilyLevelIsBackfilledFromItsSession(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, own, _ := familyLevelDB(t)
	// Метки разной длины: свёртка носителя сцены выводится из длины метки
	// (`acScene`), и две сцены одной длины столкнулись бы уникальностью носителя.
	_, _, lowSession, low := acScene(t, db, "fvwa1")
	_, _, highSession, high := acScene(t, db, "fvwb2x")
	_, err := db.Exec(`UPDATE kaname.human_sessions SET assurance_level = '2', presented_methods = ARRAY['password','totp']
		WHERE id = $1`, highSession)
	require.NoError(t, err, "уровень второй сессии")
	require.NotEqual(t, lowSession, highSession)

	require.NoError(t, goose.UpTo(db, ".", own), "накат предмета")
	for family, want := range map[string]string{low: "1", high: "2"} {
		var got string
		require.NoError(t, db.QueryRow(`SELECT acr FROM kaname.token_families WHERE id = $1`, family).Scan(&got))
		require.Equal(t, want, got, "семейство %s получило уровень не своей сессии", family)
	}
}

// Новое семейство без уровня и с уровнем вне оси схема отвергает; уровень оси
// принимается. Откат снимает колонку и ограничение.
func TestIntegration_FamilyLevelIsDeclaredOnTheAxis(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, own, previous := familyLevelDB(t)
	client, user, session, _ := acScene(t, db, "fvwc3")
	require.NoError(t, goose.UpTo(db, ".", own), "накат предмета")

	insert := func(id string, acr any) error {
		_, err := db.Exec(`
			INSERT INTO kaname.token_families (id, client_id, user_id, session_id, scope, acr)
			VALUES ($1, $2, $3, $4, ARRAY['openid'], $5)`, id, client, user, session, acr)
		return err
	}
	requirePgRefusal(t, insert("tfm-"+acPad("fvwn0"), nil), "23502", "",
		"семейство без уровня принято — снимок уровня обязателен")
	requirePgRefusal(t, insert("tfm-"+acPad("fvwz0"), "0"), "23514", familyLevelConstraint,
		"уровень вне оси принят")
	require.NoError(t, insert("tfm-"+acPad("fvw22"), "2"), "близнец: уровень оси обязан приниматься")

	require.NoError(t, goose.DownTo(db, ".", previous), "откат предмета")
	var columns int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM information_schema.columns
		 WHERE table_schema = 'kaname' AND table_name = 'token_families' AND column_name = 'acr'`).Scan(&columns))
	require.Zero(t, columns, "откат не снял колонку уровня")
}
