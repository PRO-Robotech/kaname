// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// active_identity_has_a_way_in_integration_test.go — у действующей личности
// есть способ входа паролем либо открытый путь восстановления; держит БАЗА
// (задача PRO-Robotech/kaname#608, приёмка
// `docs/engineering/acceptance/active-identity-has-a-way-in.md`, AWI-01…07,
// AWI-11).
//
// Предмет — схема. Инвариант держит ОТЛОЖЕННЫЙ составной ключ строки личности
// на строку способа входа «пароль»: ключ требует строки, пока личность
// `ACTIVE` и открытого пути у неё нет, и молчит в остальных случаях. Ключ, а не
// пользовательский триггер, потому что на таблице секрета механизмов,
// исполняющихся при записи без ведома писателя, нет и не будет (держит
// `TestIntegration_LoginVerifierStaysInside` в адаптере): отказ на удалении
// строки пароля исполняет служебная проверка ключа, строки целиком не видящая.
//
// Отказ — класс нарушения ключа (SQLSTATE 23503), и текст называет ограничение.
// Каждое отрицание стоит рядом с близнецом, отличающимся ОДНИМ фактом.
package migrations_test

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// awiMigration — файл предмета; по нему вычисляются версии обоих ходов.
const awiMigration = "20261005030000_active_identity_has_a_way_in.sql"

// awiConstraint — ключ, которым база держит инвариант.
const awiConstraint = "users_active_has_a_way_in_fk"

// awiDeferredRefusal — код отказа отложенного ключа на фиксации.
const awiDeferredRefusal = "23503"

// awiAccount заводит аккаунт с владельцем в `PENDING`: владелец нужен ключу
// аккаунта, а инвариант `PENDING` не судит — посев сцены поэтому не зависит от
// предмета, и инъекция в предмет краснеет на сценарии, а не на посеве.
func awiAccount(t *testing.T, db *sql.DB, tag string) string {
	t.Helper()
	owner := "usr" + acPad(tag+"o")
	account := "acc" + acPad(tag)
	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`
		INSERT INTO kaname.users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ($1, '', $2, 'owner', $3, 'PENDING')`, owner, tag+"-o@example.invalid", account)
	require.NoError(t, err, "посев владельца %s", tag)
	_, err = tx.Exec(`INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`, account, "acc-"+tag, owner)
	require.NoError(t, err, "посев аккаунта %s", tag)
	require.NoError(t, tx.Commit(), "посев аккаунта %s фиксируется", tag)
	return account
}

// awiPerson — строка личности указанного статуса; ACTIVE/BLOCKED несут
// внешний субъект (`users_invite_status_consistency`), PENDING — пустой.
func awiPerson(tag, status string) (id, external, email string) {
	id = "usr" + acPad(tag)
	if status != "PENDING" {
		external = "ext-" + tag
	}
	return id, external, tag + "@example.invalid"
}

func awiInsertPerson(tx *sql.Tx, account, tag, status string) (string, error) {
	id, external, email := awiPerson(tag, status)
	_, err := tx.Exec(`
		INSERT INTO kaname.users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ($1, $2, $3, 'person', $4, $5)`, id, external, email, account, status)
	return id, err
}

func awiInsertPassword(tx *sql.Tx, user string) error {
	_, err := tx.Exec(`INSERT INTO kaname.user_login_methods (user_id, kind, verifier) VALUES ($1, 'password', '$2a$12$awi.person')`, user)
	return err
}

func awiPersonExists(t *testing.T, db *sql.DB, id string) bool {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.users WHERE id = $1`, id).Scan(&n))
	return n == 1
}

// AWI-01 · AWI-02 · AWI-03 — вставка.
func TestIntegration_AWI01_ActiveWithoutAWayInIsNotCommitted(t *testing.T) {
	db := acDB(t)
	account := awiAccount(t, db, "awi01")

	// AWI-01: ACTIVE без пароля и без отметки — отказ на фиксации.
	tx, err := db.Begin()
	require.NoError(t, err)
	id, err := awiInsertPerson(tx, account, "awi01a", "ACTIVE")
	require.NoError(t, err, "вставка сама по себе проходит: проверка отложена до фиксации")
	requirePgRefusal(t, tx.Commit(), awiDeferredRefusal, awiConstraint,
		"AWI-01: ACTIVE без способа входа и без открытого пути зафиксирован — инвариант база не держит")
	require.False(t, awiPersonExists(t, db, id), "AWI-01: после отказа строки личности нет")

	// AWI-02: тот же факт плюс строка пароля той же транзакцией — фиксируется.
	tx, err = db.Begin()
	require.NoError(t, err)
	id2, err := awiInsertPerson(tx, account, "awi01b", "ACTIVE")
	require.NoError(t, err)
	require.NoError(t, awiInsertPassword(tx, id2))
	require.NoError(t, tx.Commit(), "AWI-02: ACTIVE вместе с паролем той же транзакцией обязан фиксироваться")
	require.True(t, awiPersonExists(t, db, id2))

	// AWI-03: PENDING без пароля и без отметки — инвариантом не судится.
	tx, err = db.Begin()
	require.NoError(t, err)
	id3, err := awiInsertPerson(tx, account, "awi01c", "PENDING")
	require.NoError(t, err)
	require.NoError(t, tx.Commit(), "AWI-03: PENDING без пароля инвариант не судит")
	require.True(t, awiPersonExists(t, db, id3))
}

// AWI-04 — снятие единственного пароля у ACTIVE; близнец — снятие второго фактора.
func TestIntegration_AWI04_LastPasswordOfActiveCannotBeRemoved(t *testing.T) {
	db := acDB(t)
	account := awiAccount(t, db, "awi04")
	tx, err := db.Begin()
	require.NoError(t, err)
	id, err := awiInsertPerson(tx, account, "awi04a", "ACTIVE")
	require.NoError(t, err)
	require.NoError(t, awiInsertPassword(tx, id))
	_, err = tx.Exec(`INSERT INTO kaname.user_login_methods (user_id, kind, verifier, state) VALUES ($1, 'totp', 'wrapped-secret', 'active')`, id)
	require.NoError(t, err, "посев второго фактора")
	require.NoError(t, tx.Commit())

	_, err = db.Exec(`DELETE FROM kaname.user_login_methods WHERE user_id = $1 AND kind = 'password'`, id)
	requirePgRefusal(t, err, awiDeferredRefusal, awiConstraint,
		"AWI-04: у ACTIVE снят единственный пароль — личность осталась без способа входа")
	var kinds string
	require.NoError(t, db.QueryRow(`SELECT string_agg(kind, ',' ORDER BY kind) FROM kaname.user_login_methods WHERE user_id = $1`, id).Scan(&kinds))
	require.Equal(t, "password,totp", kinds, "AWI-04: строка пароля на месте")

	_, err = db.Exec(`DELETE FROM kaname.user_login_methods WHERE user_id = $1 AND kind = 'totp'`, id)
	require.NoError(t, err, "AWI-04 близнец: снятие второго фактора обязано фиксироваться — пароль остаётся")
}

// AWI-05 — снятие отметки без первого пароля; близнец — вместе с паролем.
func TestIntegration_AWI05_OpenPathCannotBeClosedWithoutAFirstPassword(t *testing.T) {
	db := acDB(t)
	account := awiAccount(t, db, "awi05")
	tx, err := db.Begin()
	require.NoError(t, err)
	id, err := awiInsertPerson(tx, account, "awi05a", "ACTIVE")
	require.NoError(t, err)
	_, err = tx.Exec(`UPDATE kaname.users SET recovery_path_opened_at = now() WHERE id = $1`, id)
	require.NoError(t, err, "форма «после переноса»: отметка открытого пути")
	require.NoError(t, tx.Commit(), "ACTIVE без пароля С отметкой фиксируется")

	_, err = db.Exec(`UPDATE kaname.users SET recovery_path_opened_at = NULL WHERE id = $1`, id)
	requirePgRefusal(t, err, awiDeferredRefusal, awiConstraint,
		"AWI-05: отметка снята без первого пароля — личность осталась в тупике")
	var open bool
	require.NoError(t, db.QueryRow(`SELECT recovery_path_opened_at IS NOT NULL FROM kaname.users WHERE id = $1`, id).Scan(&open))
	require.True(t, open, "AWI-05: отметка на месте")

	// Близнец: снятие отметки ПЕРВЫМ, пароль — следом той же транзакцией.
	tx, err = db.Begin()
	require.NoError(t, err)
	_, err = tx.Exec(`UPDATE kaname.users SET recovery_path_opened_at = NULL WHERE id = $1`, id)
	require.NoError(t, err)
	require.NoError(t, awiInsertPassword(tx, id))
	require.NoError(t, tx.Commit(), "AWI-05 близнец: снятие отметки вместе с первым паролем обязано фиксироваться (Ф5-30)")
}

// AWI-06 — возврат из блокировки без пароля и без отметки; близнец — с отметкой.
func TestIntegration_AWI06_UnblockWithoutAWayInIsNotCommitted(t *testing.T) {
	db := acDB(t)
	account := awiAccount(t, db, "awi06")
	tx, err := db.Begin()
	require.NoError(t, err)
	bare, err := awiInsertPerson(tx, account, "awi06a", "BLOCKED")
	require.NoError(t, err)
	marked, err := awiInsertPerson(tx, account, "awi06b", "BLOCKED")
	require.NoError(t, err)
	require.NoError(t, tx.Commit(), "BLOCKED без пароля инвариант не судит — посев проходит")

	_, err = db.Exec(`UPDATE kaname.users SET invite_status = 'ACTIVE' WHERE id = $1`, bare)
	requirePgRefusal(t, err, awiDeferredRefusal, awiConstraint,
		"AWI-06: BLOCKED без способа входа возвращён в ACTIVE")
	var status string
	require.NoError(t, db.QueryRow(`SELECT invite_status FROM kaname.users WHERE id = $1`, bare).Scan(&status))
	require.Equal(t, "BLOCKED", status, "AWI-06: статус прежний")

	_, err = db.Exec(`UPDATE kaname.users SET recovery_path_opened_at = now() WHERE id = $1`, marked)
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE kaname.users SET invite_status = 'ACTIVE' WHERE id = $1`, marked)
	require.NoError(t, err, "AWI-06 близнец: перенесённая строка с отметкой возвращается из блокировки")
}

// AWI-07 — удаление личности целиком: проверять у отсутствующей нечего.
func TestIntegration_AWI07_RemovingThePersonIsCommitted(t *testing.T) {
	db := acDB(t)
	account := awiAccount(t, db, "awi07")
	tx, err := db.Begin()
	require.NoError(t, err)
	id, err := awiInsertPerson(tx, account, "awi07a", "ACTIVE")
	require.NoError(t, err)
	require.NoError(t, awiInsertPassword(tx, id))
	require.NoError(t, tx.Commit())

	_, err = db.Exec(`DELETE FROM kaname.users WHERE id = $1`, id)
	require.NoError(t, err, "AWI-07: удаление личности (строка пароля уходит каскадом) обязано фиксироваться")
	require.False(t, awiPersonExists(t, db, id))
}

// awiDBBefore — база, доведённая до версии ПЕРЕД предметом.
func awiDBBefore(t *testing.T) (*sql.DB, int64) {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	own, previous := versionsOf(t, awiMigration)
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpTo(db, ".", previous))
	return db, own
}

// awiRowImage — строка личности целиком, кроме колонок предмета, — для сверки
// «до и после» по каждому столбцу.
func awiRowImage(t *testing.T, db *sql.DB, id string) string {
	t.Helper()
	var image string
	require.NoError(t, db.QueryRow(`
		SELECT (to_jsonb(u) - 'recovery_path_opened_at' - 'expected_login_kind')::text
		  FROM kaname.users u WHERE id = $1`, id).Scan(&image))
	return image
}

// AWI-11 — перенос ставит отметку ровно тупиковым и не меняет ничего другого.
func TestIntegration_AWI11_TransferOpensThePathAndChangesNothingElse(t *testing.T) {
	db, own := awiDBBefore(t)
	account := awiAccount(t, db, "awi11")

	type seed struct {
		tag, status    string
		password, mark bool
		verified       bool
	}
	seeds := []seed{
		{tag: "awi11a", status: "ACTIVE", mark: true},
		{tag: "awi11b", status: "ACTIVE", password: true},
		{tag: "awi11c", status: "PENDING"},
		{tag: "awi11d", status: "BLOCKED", mark: true},
		{tag: "awi11e", status: "ACTIVE", verified: true, mark: true},
	}
	ids := map[string]string{}
	before := map[string]string{}
	for _, s := range seeds {
		tx, err := db.Begin()
		require.NoError(t, err)
		id, err := awiInsertPerson(tx, account, s.tag, s.status)
		require.NoError(t, err, "посев %s", s.tag)
		if s.password {
			require.NoError(t, awiInsertPassword(tx, id))
		}
		if s.verified {
			_, err = tx.Exec(`UPDATE kaname.users SET email_verified_at = now() WHERE id = $1`, id)
			require.NoError(t, err)
		}
		require.NoError(t, tx.Commit(), "посев %s на ревизии до предмета", s.tag)
		ids[s.tag] = id
		before[s.tag] = awiRowImage(t, db, id)
	}

	require.NoError(t, goose.UpTo(db, ".", own), "накат предмета")

	for _, s := range seeds {
		var open bool
		require.NoError(t, db.QueryRow(`SELECT recovery_path_opened_at IS NOT NULL FROM kaname.users WHERE id = $1`, ids[s.tag]).Scan(&open))
		require.Equal(t, s.mark, open, "AWI-11: отметка у %s (%s, пароль=%v)", s.tag, s.status, s.password)
		require.Equal(t, before[s.tag], awiRowImage(t, db, ids[s.tag]),
			"AWI-11: у %s изменилось что-то кроме отметки", s.tag)
	}

	// Проверка действует на перенесённой базе так же, как на пустой (AWI-01).
	tx, err := db.Begin()
	require.NoError(t, err)
	_, err = awiInsertPerson(tx, account, "awi11z", "ACTIVE")
	require.NoError(t, err)
	requirePgRefusal(t, tx.Commit(), awiDeferredRefusal, awiConstraint,
		"AWI-11: после переноса AWI-01 обязан краснеть, как на пустой базе")
}

// Откат снимает ключ, вычисляемую колонку и отметку — личностей и их статусов
// не трогает (AWI §4.1 п. 4).
func TestIntegration_AWIRollbackKeepsPeopleAndStatuses(t *testing.T) {
	db, own := awiDBBefore(t)
	account := awiAccount(t, db, "awirb")
	tx, err := db.Begin()
	require.NoError(t, err)
	id, err := awiInsertPerson(tx, account, "awirba", "ACTIVE")
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	require.NoError(t, goose.UpTo(db, ".", own))
	_, previous := versionsOf(t, awiMigration)
	require.NoError(t, goose.DownTo(db, ".", previous), "откат предмета")

	var status string
	require.NoError(t, db.QueryRow(`SELECT invite_status FROM kaname.users WHERE id = $1`, id).Scan(&status))
	require.Equal(t, "ACTIVE", status, "откат не трогает статусов")
	var cols []string
	rows, err := db.Query(`
		SELECT column_name FROM information_schema.columns
		 WHERE table_schema = 'kaname' AND table_name = 'users'
		   AND column_name IN ('recovery_path_opened_at', 'expected_login_kind')`)
	require.NoError(t, err)
	for rows.Next() {
		var c string
		require.NoError(t, rows.Scan(&c))
		cols = append(cols, c)
	}
	require.NoError(t, rows.Err())
	_ = rows.Close()
	require.Empty(t, cols, "откат снимает колонки предмета: %s", strings.Join(cols, ","))
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM pg_constraint WHERE conname = $1`, awiConstraint).Scan(&n))
	require.Zero(t, n, fmt.Sprintf("откат снимает ключ %s", awiConstraint))
}
