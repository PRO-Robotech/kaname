// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_family_person_agrees_with_session_schema_integration_test.go — ЧЕЛОВЕК
// семейства есть человек ЕГО СЕССИИ (задача PRO-Robotech/kaname#423).
//
// Предмет — схема. Семейство несёт и человека, и сессию, а у сессии свой
// человек: два написания одного факта. Пока их согласие держит только оператор
// выдачи, строку семейства, в которой сессия одного человека выдаёт права
// другому, база принимает — от любого писателя, включая ручной SQL и
// восстановление из дампа.
//
// Нарушить согласие можно ТРЕМЯ путями, и каждый судится отдельно: вставкой
// семейства, сменой человека у семейства и сменой человека у сессии, на которую
// семейство ссылается. У каждого отказа есть близнец, отличающийся ОДНИМ
// значением: отказ, не имеющий принимаемого соседа, истинен и тогда, когда
// отвергается всё.
//
// Две пробы судят сам файл миграции
// (`20260926141908_token_family_person_is_the_person_of_its_session.sql`):
// лежащую строку с несогласной парой накат не чинит, а отвергает целиком; откат
// снимает ключ и набор, на который он ссылался.
package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// familyPersonMigration — файл предмета; по нему вычисляются версии обоих ходов.
const familyPersonMigration = "20260926141908_token_family_person_is_the_person_of_its_session.sql"

// familyPersonConstraint — ключ, которым база держит согласие человека
// семейства с человеком его сессии.
const familyPersonConstraint = "token_families_session_user_fk"

// familyPersonReferenced — уникальный набор сессии, на который ссылается ключ.
const familyPersonReferenced = "human_sessions_id_user_uniq"

// familyPersonScene — две сцены: у каждой свой человек со своей сессией.
// Метки разной длины: свёртка носителя сцены выводится из длины метки
// (`acScene`), и две сцены одной длины столкнулись бы уникальностью носителя.
func familyPersonScene(t *testing.T, db *sql.DB) (client, owner, session, family, stranger, strangerSession string) {
	t.Helper()
	client, owner, session, family = acScene(t, db, "fpsa1")
	_, stranger, strangerSession, _ = acScene(t, db, "fpsb2x")
	require.NotEqual(t, owner, stranger, "предпосылка: у двух сцен разные люди")
	require.NotEqual(t, session, strangerSession, "предпосылка: у двух сцен разные сессии")
	return client, owner, session, family, stranger, strangerSession
}

// Вставка: семейство, чей человек не тот, чья сессия, отвергается; близнец с
// человеком своей сессии и тем же идентификатором принимается.
func TestIntegration_FamilyOfAStrangerInASessionIsRefused(t *testing.T) {
	db := acDB(t)
	client, owner, session, _, stranger, _ := familyPersonScene(t, db)

	family := "tfm-" + acPad("fpsn0")
	insert := func(user string) error {
		_, err := db.Exec(`
			INSERT INTO kaname.token_families (id, client_id, user_id, session_id, scope, acr)
			VALUES ($1, $2, $3, $4, ARRAY['openid'], '1')`, family, client, user, session)
		return err
	}
	requirePgRefusal(t, insert(stranger), "23503", familyPersonConstraint,
		"семейство чужого человека в сессии принято — согласие человека и сессии база не держит")
	require.NoError(t, insert(owner), "близнец: семейство человека своей сессии обязано приниматься")
}

// Смена пары у семейства: на чужого человека при прежней сессии — отказ; на
// того же человека вместе с ЕГО сессией — принимается (единственное различие —
// сессия пары).
func TestIntegration_FamilyCannotBeHandedToAStranger(t *testing.T) {
	db := acDB(t)
	_, _, session, family, stranger, strangerSession := familyPersonScene(t, db)

	handTo := func(user, sess string) error {
		_, err := db.Exec(`UPDATE kaname.token_families SET user_id = $2, session_id = $3 WHERE id = $1`,
			family, user, sess)
		return err
	}
	requirePgRefusal(t, handTo(stranger, session), "23503", familyPersonConstraint,
		"семейство передано чужому человеку при прежней сессии — согласие база не держит")
	require.NoError(t, handTo(stranger, strangerSession),
		"близнец: человек вместе со своей сессией обязан приниматься")
}

// Смена человека у сессии: сессию, на которую ссылается семейство, отдать
// другому нельзя; ту же смену у той же сессии, когда семейства на ней уже нет, —
// можно (единственное различие — наличие семейства).
func TestIntegration_SessionUnderAFamilyCannotChangeItsPerson(t *testing.T) {
	db := acDB(t)
	_, _, session, family, stranger, _ := familyPersonScene(t, db)

	reassign := func() error {
		_, err := db.Exec(`UPDATE kaname.human_sessions SET user_id = $2 WHERE id = $1`, session, stranger)
		return err
	}
	requirePgRefusal(t, reassign(), "23503", familyPersonConstraint,
		"сессия с семейством отдана другому человеку — семейство осталось при прежнем")
	_, err := db.Exec(`DELETE FROM kaname.token_families WHERE id = $1`, family)
	require.NoError(t, err, "семейство снимается с сессии близнеца")
	require.NoError(t, reassign(), "близнец: та же смена у сессии без семейства обязана приниматься")
}

// familyPersonDBBefore — база, доведённая до версии ПЕРЕД предметом.
func familyPersonDBBefore(t *testing.T) (*sql.DB, int64, int64) {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	own, previous := versionsOf(t, familyPersonMigration)
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpTo(db, ".", previous), "цепочка обязана дойти до версии перед предметом")
	return db, own, previous
}

// familyPersonInsertStranger — семейство чужого человека в сессии, сырым
// оператором: предмет — схема.
func familyPersonInsertStranger(db *sql.DB, id, client, stranger, session string) error {
	_, err := db.Exec(`
		INSERT INTO kaname.token_families (id, client_id, user_id, session_id, scope, acr)
		VALUES ($1, $2, $3, $4, ARRAY['openid'], '1')`, id, client, stranger, session)
	return err
}

// familyPersonConstraints — сколько из двух ограничений предмета стоит в каталоге.
func familyPersonConstraints(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM pg_constraint
		 WHERE connamespace = 'kaname'::regnamespace AND conname = ANY ($1)`,
		pqTextArray([]string{familyPersonConstraint, familyPersonReferenced})).Scan(&n))
	return n
}

// Лежащая строка с несогласной парой: накат её НЕ чинит и НЕ удаляет — ключ
// отвергает её, накат откатывается целиком, версия остаётся прежней, строка
// цела. Близнец — та же цепочка без такой строки — накатывается.
func TestIntegration_FamilyPersonMigrationRefusesALyingRow(t *testing.T) {
	for _, lying := range []bool{true, false} {
		db, own, previous := familyPersonDBBefore(t)
		client, _, session, _, stranger, _ := familyPersonScene(t, db)
		lyingFamily := "tfm-" + acPad("fpsw0")
		if lying {
			require.NoError(t, familyPersonInsertStranger(db, lyingFamily, client, stranger, session),
				"предпосылка: до предмета несогласная строка принимается")
		}

		err := goose.UpTo(db, ".", own)
		version, verr := goose.GetDBVersion(db)
		require.NoError(t, verr)
		if !lying {
			require.NoError(t, err, "близнец: цепочка без несогласной строки обязана накатываться")
			require.Equal(t, own, version)
			require.Equal(t, 2, familyPersonConstraints(t, db), "накат завёл ключ и набор")
			continue
		}
		requirePgRefusal(t, err, "23503", familyPersonConstraint,
			"накат принял несогласную строку — либо починил её молча")
		require.Equal(t, previous, version, "отвергнутый накат обязан оставить прежнюю версию")
		require.Zero(t, familyPersonConstraints(t, db), "отвергнутый накат откатывается целиком")
		var kept int
		require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.token_families WHERE id = $1 AND user_id = $2`,
			lyingFamily, stranger).Scan(&kept))
		require.Equal(t, 1, kept, "накат не вправе удалять либо переписывать несогласную строку")
	}
}

// Откат снимает ключ и набор: несогласная строка снова принимается. Повторный
// накат ставит их обратно и снова её отвергает.
func TestIntegration_FamilyPersonMigrationRollsBack(t *testing.T) {
	db, own, previous := familyPersonDBBefore(t)
	client, _, session, _, stranger, _ := familyPersonScene(t, db)
	require.NoError(t, goose.UpTo(db, ".", own), "накат предмета")
	family := "tfm-" + acPad("fpsr0")
	requirePgRefusal(t, familyPersonInsertStranger(db, family, client, stranger, session), "23503",
		familyPersonConstraint, "после наката несогласная строка отвергается")

	require.NoError(t, goose.DownTo(db, ".", previous), "откат предмета")
	require.Zero(t, familyPersonConstraints(t, db), "откат не снял ключ либо набор")
	require.NoError(t, familyPersonInsertStranger(db, family, client, stranger, session),
		"после отката схема прежняя: несогласная строка принимается")
	_, err := db.Exec(`DELETE FROM kaname.token_families WHERE id = $1`, family)
	require.NoError(t, err)

	require.NoError(t, goose.UpTo(db, ".", own), "повторный накат")
	require.Equal(t, 2, familyPersonConstraints(t, db))
	requirePgRefusal(t, familyPersonInsertStranger(db, family, client, stranger, session), "23503",
		familyPersonConstraint, "повторный накат снова держит согласие")
}
