// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_account_and_identity_removal_integration_test.go — миграция, делающая
// исполнимым путь «аккаунт → личность» (задача kaname#664, приёмка
// `docs/engineering/acceptance/own-account-and-identity-are-removed-in-order.md`,
// сценарии KN664-01…04; решения Р3, Р4, Р8, Р10, Р11).
//
// # Предмет
//
// Ключ дома человека (`users_account_fk`) и ключ владельца аккаунта
// (`accounts_owner_fk`) взаимны и оба `RESTRICT`: личный аккаунт не снимается,
// пока на него указывает строка его владельца, а строка владельца — пока он
// владеет аккаунтом. Миграция переводит ключ дома в `SET NULL`, снимает
// обязательность колонки дома и три ключа `RESTRICT` на `users`, сужает охрану
// снятия субъекта до действующих выдач и заводит реестр выданных
// идентификаторов людей. Откат отказывает двумя названными текстами, когда
// вернуть прежнюю форму значило бы изобрести аккаунт или стереть записи.
//
// # Почему имя файла стоит литералом
//
// Мир «база перед миграцией» строится остановкой цепи на версии ПЕРЕД ней, и
// версию задаёт имя файла. Проба обязана сломаться, если файл переедет: вердикт
// относился бы к другому состоянию схемы. До реализации файла в цепи нет, и
// пробы красны ровно этим утверждением, ПОСЛЕ того как их мир построен.
package migrations_test

import (
	"database/sql"
	"io/fs"
	"strconv"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// ownRemovalMigration — файл миграции Р3, Р4, Р10, Р11 (приёмка §6 DoD 1).
const ownRemovalMigration = "20261011061435_own_account_and_identity_are_removed_in_order.sql"

// Тексты отказа отката — часть контракта миграции (Р8), дословно.
const (
	rollbackRefusedHomeless = "rollback refused: users without a home account exist"
	rollbackRefusedOrphans  = "rollback refused: records reference removed users"
)

// removedRestrictKeys — три ключа `RESTRICT` на `users`, которых после наката
// нет (Р4).
var removedRestrictKeys = []string{
	"session_revocations_user_fk",
	"user_oauth_clients_created_by_fk",
	"service_account_oauth_clients_created_by_fk",
}

func ownRemovalVersion(t *testing.T) int64 {
	t.Helper()
	head, _, ok := strings.Cut(ownRemovalMigration, "_")
	require.True(t, ok, "имя файла без версии: %s", ownRemovalMigration)
	v, err := strconv.ParseInt(head, 10, 64)
	require.NoError(t, err)
	return v
}

// requireOwnRemovalMigrationInChain — несущее утверждение о ПРЕДМЕТЕ: файл
// миграции стоит в цепи службы. Зовётся ПОСЛЕ построения и проверки мира.
func requireOwnRemovalMigrationInChain(t *testing.T) {
	t.Helper()
	_, err := fs.Stat(migrations.FS, ownRemovalMigration)
	require.NoError(t, err, "миграции снятия по порядку нет в цепи службы (%s): ключ дома "+
		"остаётся RESTRICT, и личный аккаунт не снимается", ownRemovalMigration)
}

// beforeOwnRemoval — база, остановленная на версии НЕПОСРЕДСТВЕННО ПЕРЕД
// миграцией. Предпосылка мира называется явно: реестра людей ещё нет, ключ
// дома — RESTRICT.
func beforeOwnRemoval(t *testing.T) *sql.DB {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	before := ownRemovalVersion(t) - 1
	require.NoError(t, goose.UpTo(db, ".", before), "цепь обязана доходить до версии %d", before)
	require.False(t, regclassPresent(t, db, "issued_user_ids"),
		"реестр людей есть уже на версии %d — остановка пришлась не туда", before)
	require.Contains(t, kn664ConstraintDef(t, db, "users_account_fk"), "ON DELETE RESTRICT",
		"предпосылка: до наката ключ дома — RESTRICT")
	return db
}

// kn664ConstraintDef — определение ограничения по имени; "" — ограничения нет.
func kn664ConstraintDef(t *testing.T, db *sql.DB, name string) string {
	t.Helper()
	var def sql.NullString
	err := db.QueryRow(`SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c
		JOIN pg_namespace n ON n.oid = c.connamespace
		WHERE n.nspname = 'kaname' AND c.conname = $1`, name).Scan(&def)
	if err == sql.ErrNoRows {
		return ""
	}
	require.NoError(t, err)
	return def.String
}

func homeColumnRequired(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var notNull bool
	require.NoError(t, db.QueryRow(`SELECT a.attnotnull FROM pg_attribute a
		WHERE a.attrelid = 'kaname.users'::regclass AND a.attname = 'account_id'`).Scan(&notNull))
	return notNull
}

// removalShape — снимок строения, которое миграция меняет: ключи на четырёх
// таблицах, обязательность колонки дома, текст функции охраны субъекта,
// присутствие реестра и триггеры на `users`. Откат обязан вернуть его ДОСЛОВНО.
func removalShape(t *testing.T, db *sql.DB) []string {
	t.Helper()
	var out []string
	rows, err := db.Query(`SELECT c.conname || ' ' || pg_get_constraintdef(c.oid)
		FROM pg_constraint c
		WHERE c.contype = 'f'
		  AND (c.conrelid IN ('kaname.users'::regclass, 'kaname.accounts'::regclass,
		                      'kaname.session_revocations'::regclass,
		                      'kaname.user_oauth_clients'::regclass,
		                      'kaname.service_account_oauth_clients'::regclass))
		ORDER BY 1`)
	require.NoError(t, err)
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		out = append(out, "fk: "+s)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	out = append(out, "users.account_id not null: "+strconv.FormatBool(homeColumnRequired(t, db)))
	var fn string
	require.NoError(t, db.QueryRow(
		`SELECT pg_get_functiondef('kaname.principal_not_referenced_as_subject'::regproc)`).Scan(&fn))
	out = append(out, "guard: "+fn)
	out = append(out, "registry: "+strconv.FormatBool(regclassPresent(t, db, "issued_user_ids")))
	trg, err := db.Query(`SELECT tgname FROM pg_trigger
		WHERE tgrelid = 'kaname.users'::regclass AND NOT tgisinternal ORDER BY 1`)
	require.NoError(t, err)
	for trg.Next() {
		var s string
		require.NoError(t, trg.Scan(&s))
		out = append(out, "trigger: "+s)
	}
	require.NoError(t, trg.Err())
	trg.Close()
	return out
}

// removalWorld — мир KN664-01: самостоятельно зарегистрированный `U` с личным
// аккаунтом `A`, приглашённый в `A` человек `M`, запись отзыва удостоверения
// `U`, личный токен `U` и ключ сервисного аккаунта в `A`, выпущенный `U`.
type removalWorld struct {
	u, m, a, sa string
}

func seedRemovalWorld(t *testing.T, db *sql.DB, tag string) removalWorld {
	t.Helper()
	w := removalWorld{
		u:  ids.NewID(domain.PrefixUser),
		m:  ids.NewID(domain.PrefixUser),
		a:  ids.NewID(domain.PrefixAccount),
		sa: ids.NewID(domain.PrefixServiceAccount),
	}
	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $3, $4, $5, 'KN664 owner', 'ACTIVE'),
		       ($2, $3, $6, $7, 'KN664 member', 'ACTIVE')`,
		w.u, w.m, w.a,
		"ext-"+tag+"-u-"+w.u, tag+"-u-"+w.u+"@example.invalid",
		"ext-"+tag+"-m-"+w.m, tag+"-m-"+w.m+"@example.invalid")
	require.NoError(t, err)
	_, err = tx.Exec(`INSERT INTO kaname.accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`, w.a, "kn664-"+tag+"-"+w.a[len(w.a)-6:], w.u)
	require.NoError(t, err)
	seedWayIn(t, tx)
	require.NoError(t, tx.Commit())

	_, err = db.Exec(`INSERT INTO kaname.service_accounts (id, account_id, name) VALUES ($1, $2, $3)`,
		w.sa, w.a, "kn664-"+tag)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO kaname.session_revocations (token_jti, user_id, ttl_expires_at, reason)
		VALUES ($1, $2, now() + interval '1 hour', 'logout')`, "jti-"+tag+"-"+w.u, w.u)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO kaname.user_oauth_clients
		(id, user_id, created_by_user_id, credential_kind, secret_hash, expires_at)
		VALUES ($1, $2, $2, 'SECRET', decode(repeat('ab', 32), 'hex'), now() + interval '1 day')`,
		ids.NewID("uoc"), w.u)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO kaname.service_account_oauth_clients
		(id, sva_id, created_by_user_id, credential_kind, secret_hash, expires_at)
		VALUES ($1, $2, $3, 'SECRET', decode(repeat('cd', 32), 'hex'), now() + interval '1 day')`,
		ids.NewID("soc"), w.sa, w.u)
	require.NoError(t, err)
	return w
}

// rowCensus — число строк каждой затронутой таблицы.
func rowCensus(t *testing.T, db *sql.DB) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, table := range []string{"users", "accounts", "memberships", "session_revocations",
		"user_oauth_clients", "service_account_oauth_clients", "service_accounts",
		"access_bindings", "access_binding_subjects"} {
		var n int
		require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.`+table).Scan(&n))
		out[table] = n
	}
	return out
}

// TestKN664_01_MigrationBreaksTheCycleAndKeepsEveryRow — KN664-01, накат.
func TestKN664_01_MigrationBreaksTheCycleAndKeepsEveryRow(t *testing.T) {
	db := beforeOwnRemoval(t)
	w := seedRemovalWorld(t, db, "kn66401")
	census := rowCensus(t, db)
	require.Positive(t, census["session_revocations"], "предпосылка: запись отзыва лежит")
	for _, k := range removedRestrictKeys {
		require.Contains(t, kn664ConstraintDef(t, db, k), "ON DELETE RESTRICT", "предпосылка: %s до наката — RESTRICT", k)
	}

	requireOwnRemovalMigrationInChain(t)
	v := ownRemovalVersion(t)
	require.NoError(t, goose.UpTo(db, ".", v), "накат обязан пройти")
	require.Equal(t, v, schemaVersion(t, db))

	require.False(t, homeColumnRequired(t, db), "колонка дома обязана допускать NULL (Р3)")
	// Квалификацию схемы печатает сервер по пути поиска соединения, поэтому
	// сверяется хвост определения, а не его префикс.
	require.Regexp(t, `^FOREIGN KEY \(account_id\) REFERENCES (kaname\.)?accounts\(id\) ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED$`,
		kn664ConstraintDef(t, db, "users_account_fk"), "ключ дома — SET NULL, отложенный (Р3)")
	require.Regexp(t, `^FOREIGN KEY \(owner_user_id\) REFERENCES (kaname\.)?users\(id\) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED$`,
		kn664ConstraintDef(t, db, "accounts_owner_fk"), "ключ владельца не меняется (Р3)")
	for _, k := range removedRestrictKeys {
		require.Empty(t, kn664ConstraintDef(t, db, k), "ключ %s обязан быть снят (Р4)", k)
	}
	require.Equal(t, census, rowCensus(t, db), "накат изменил число строк затронутых таблиц")

	for name, id := range map[string]string{"U": w.u, "M": w.m} {
		var n int
		require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.issued_user_ids WHERE id = $1`, id).Scan(&n))
		require.Equal(t, 1, n, "%s (%s) не внесён в реестр выданных идентификаторов людей (Р11)", name, id)
	}
}

// TestKN664_02_RollbackOnACleanBaseRestoresTheShapeVerbatim — KN664-02.
func TestKN664_02_RollbackOnACleanBaseRestoresTheShapeVerbatim(t *testing.T) {
	db := beforeOwnRemoval(t)
	seedRemovalWorld(t, db, "kn66402")
	before := removalShape(t, db)
	require.NotEmpty(t, before)
	prev := schemaVersion(t, db)

	requireOwnRemovalMigrationInChain(t)
	v := ownRemovalVersion(t)
	require.NoError(t, goose.UpTo(db, ".", v))
	require.NotEqual(t, before, removalShape(t, db), "предпосылка: накат меняет строение")

	require.NoError(t, goose.DownTo(db, ".", v-1), "откат на чистой базе обязан пройти")
	require.Equal(t, prev, schemaVersion(t, db), "откат вернул версию, предшествующую миграции")
	require.Equal(t, before, removalShape(t, db), "откат вернул строение не дословно")
}

// TestKN664_03_RollbackRefusesWhileAPersonHasNoHome — KN664-03.
func TestKN664_03_RollbackRefusesWhileAPersonHasNoHome(t *testing.T) {
	db := beforeOwnRemoval(t)
	w := seedRemovalWorld(t, db, "kn66403")
	requireOwnRemovalMigrationInChain(t)
	v := ownRemovalVersion(t)
	require.NoError(t, goose.UpTo(db, ".", v))

	// Дом M снят действием ключа: аккаунт A снимается вместе с владельцем
	// одним оператором, M остаётся без дома.
	_, err := db.Exec(`UPDATE kaname.users SET account_id = NULL WHERE id = $1`, w.m)
	require.NoError(t, err)
	after := removalShape(t, db)

	err = goose.DownTo(db, ".", v-1)
	require.Error(t, err, "откат при человеке без дома обязан отказать")
	require.Contains(t, err.Error(), rollbackRefusedHomeless)
	require.Equal(t, v, schemaVersion(t, db), "версия схемы ушла назад на отказе")
	require.Equal(t, after, removalShape(t, db), "отказ отката изменил строение")
	var home sql.NullString
	require.NoError(t, db.QueryRow(`SELECT account_id FROM kaname.users WHERE id = $1`, w.m).Scan(&home))
	require.False(t, home.Valid, "отказ отката изобрёл дом")
}

// TestKN664_04_RollbackRefusesWhileARecordOutlivesItsPerson — KN664-04.
func TestKN664_04_RollbackRefusesWhileARecordOutlivesItsPerson(t *testing.T) {
	db := beforeOwnRemoval(t)
	seedRemovalWorld(t, db, "kn66404")
	requireOwnRemovalMigrationInChain(t)
	v := ownRemovalVersion(t)
	require.NoError(t, goose.UpTo(db, ".", v))

	gone := ids.NewID(domain.PrefixUser) // человек, которого нет: снят после выхода
	_, err := db.Exec(`INSERT INTO kaname.session_revocations (token_jti, user_id, ttl_expires_at, reason)
		VALUES ($1, $2, now() + interval '1 hour', 'logout')`, "jti-gone-"+gone, gone)
	require.NoError(t, err, "после наката запись отзыва переживает человека (Р4)")
	after := removalShape(t, db)
	census := rowCensus(t, db)

	err = goose.DownTo(db, ".", v-1)
	require.Error(t, err, "откат при записи, пережившей человека, обязан отказать")
	require.Contains(t, err.Error(), rollbackRefusedOrphans)
	require.NotContains(t, err.Error(), gone, "текст отказа отката не называет людей (У-8)")
	require.Equal(t, v, schemaVersion(t, db))
	require.Equal(t, after, removalShape(t, db), "отказ отката изменил строение")
	require.Equal(t, census, rowCensus(t, db), "отказ отката удалил записи")
}
