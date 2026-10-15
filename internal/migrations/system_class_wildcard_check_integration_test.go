// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// system_class_wildcard_check_integration_test.go — подстановка субъектом
// после переезда на системные классы отвергается ОГРАНИЧЕНИЕМ таблицы, а не
// только разовой переписью внутри миграции (задача PRO-Robotech/kaname#829,
// инвариант 3 приёмки anonymous-and-authenticated-are-subject-classes.md).
//
// Перепись «ноль после переезда» держит состояние на миг наката; писатель
// прежней версии, работающий во время выкатки, кладёт `user:*` и после неё —
// прямо в выпущенные факты выдачи либо журналом, который проекция переносит в
// `relation_fact`. Каждая проба меняет против близнеца ровно один факт —
// субъекта: подстановку против обычного человека.
package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scWildcardRefused — вставка отвергнута проверочным ограничением с этим
// именем (23514), а не чем-либо ещё.
func scWildcardRefused(t *testing.T, err error, constraint, what string) {
	t.Helper()
	require.Errorf(t, err, "%s: подстановка субъектом принята", what)
	pgErr := pgErrorOf(err)
	require.NotNilf(t, pgErr, "%s: отказ не от базы: %v", what, err)
	assert.Equalf(t, "23514", pgErr.Code, "%s: код отказа (%s)", what, pgErr.Message)
	assert.Equalf(t, constraint, pgErr.ConstraintName, "%s: имя ограничения (%s)", what, pgErr.Message)
}

// scMoveMigration — миграция переезда подстановки на классы.
const scMoveMigration = "20261015120000_anonymous_and_authenticated_are_subject_classes.sql"

func scMovedP2(t *testing.T) (*sql.DB, string) {
	t.Helper()
	p := openP2(t)
	person := "user:" + scSeedPerson(t, p.db, "scck")
	require.NoError(t, goose.Up(p.db, "."), "накат миграций изменения")
	return p.db, person
}

// Прямой факт с подстановкой отвергнут; тот же факт обычного субъекта принят.
func TestSystemClass_RelationFactRefusesTheWildcardSubject(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, person := scMovedP2(t)
	const q = `INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
	           VALUES ('registry_repository', 'r-ck', 'v_get', $1)`

	_, err := db.Exec(q, person)
	require.NoError(t, err, "близнец: обычный субъект принят")

	for _, wildcard := range []string{"user:*", "service_account:*", "user:*#member"} {
		_, err = db.Exec(q, wildcard)
		scWildcardRefused(t, err, "relation_fact_subject_not_wildcard", "relation_fact "+wildcard)
	}
}

// Журнал прежнего писателя с подстановкой не проецируется в факт; тот же
// журнал обычного субъекта проецируется.
func TestSystemClass_JournalProjectionRefusesTheWildcardSubject(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, person := scMovedP2(t)
	const q = `INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
	           VALUES ('fga.tuple.write',
	                   jsonb_build_object('user', $1::text, 'relation', 'v_get',
	                                      'object', 'registry_repository:r-ckj',
	                                      'source_version', '-infinity'::timestamptz),
	                   now())`

	_, err := db.Exec(q, person)
	require.NoError(t, err, "близнец: журнал обычного субъекта принят")
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.relation_fact
	   WHERE object_type = 'registry_repository' AND object_id = 'r-ckj' AND subject = $1`, person).Scan(&n))
	require.Equal(t, 1, n, "близнец: журнал спроецирован в факт")

	_, err = db.Exec(q, "user:*")
	scWildcardRefused(t, err, "relation_fact_subject_not_wildcard", "журнал user:*")
}

// Выпущенный факт выдачи с подстановкой отвергнут; обычного субъекта — принят.
func TestSystemClass_EmittedTuplesRefuseTheWildcardSubject(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, person := scMovedP2(t)
	const q = `INSERT INTO kaname.access_binding_emitted_tuples (binding_id, fga_user, relation, object)
	           VALUES ($1, $2, 'viewer', 'registry_repository:r-cke')`

	_, err := db.Exec(q, scSystemGrant, person)
	require.NoError(t, err, "близнец: обычный субъект принят")

	for _, wildcard := range []string{"user:*", "group:*", "user:*#member"} {
		_, err = db.Exec(q, scSystemGrant, wildcard)
		scWildcardRefused(t, err, "access_binding_emitted_tuples_user_not_wildcard", "emitted "+wildcard)
	}
}

// Откат снимает ограничения ДО возврата подстановки: иначе шаг отката,
// кладущий `user:*` обратно в факты, отверг бы сам себя. Повторный накат
// сходится к тому же состоянию.
func TestSystemClass_DownLiftsTheWildcardChecksBeforeTheWildcardReturns(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, _ := scMovedP2(t)
	// Откат — ДО предшественницы миграции переезда, а не на один шаг: шаг
	// снимал бы ту миграцию, что стоит в дереве последней, а она не обязана
	// быть переездом.
	_, beforeMove := versionsOf(t, scMoveMigration)
	require.NoError(t, goose.DownTo(db, ".", beforeMove), "откат миграции переезда")
	back := wildcardCensus(t, db)
	assert.Equal(t, 1, back["relation_fact"], "откат: факт системной выдачи вернулся на подстановку")
	assert.Equal(t, 1, back["access_binding_emitted_tuples"], "откат: выпущенный факт вернулся на подстановку")

	require.NoError(t, goose.Up(db, "."), "повторный накат")
	assert.Equal(t, map[string]int{
		"access_bindings": 0, "access_binding_subjects": 0, "access_binding_emitted_tuples": 0, "relation_fact": 0,
	}, wildcardCensus(t, db), "повторный накат: подстановки нет")
	_, err := db.Exec(`INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
	                   VALUES ('registry_repository', 'r-ckd', 'v_get', 'user:*')`)
	scWildcardRefused(t, err, "relation_fact_subject_not_wildcard", "после повторного наката")
}
