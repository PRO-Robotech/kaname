// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// unregistration_revokes_its_grants_integration_test.go — схема изменения
// PRO-Robotech/kaname#963 (приёмка
// `docs/engineering/acceptance/unregistration-revokes-its-grants.md`, отпечаток
// 0743cd4f3f4ac1b9519870bce93475a339c7729f202ee6cc1ad5386a87bd97b4).
//
// Проба написана ДО миграции и красна на дереве, где файла предмета в цепочке
// нет: `versionsOf` не находит его.
//
//   - URG-34, строка R0: выдача, отозванная до миграции, после наката несёт пустую
//     причину (`REVOCATION_REASON_UNSPECIFIED`, Д7) и остаётся REVOKED — обратного
//     заполнения нет;
//   - Р6: пара `rules = []`, `permissions = []` до наката отвергается
//     `roles_permissions_valid`, после — принимается; близнец — та же роль с
//     правилом — принимается и до наката;
//   - Д2: закрытый словарь причины — вне словаря отказ, причина у действующей
//     выдачи — отказ;
//   - откат возвращает прежние определения дословно.
package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
)

// unregistrationMigration — файл изменения kaname#963.
const unregistrationMigration = "20261024050000_unregistration_revokes_its_grants.sql"

// urgSeed — аккаунт, человек, проект, роль с перечнем прав и выдача R0, отозванная
// глаголом (строка `REVOKED` с `revoked_by_user_id`) — одной транзакцией.
func urgSeed(t *testing.T, db *sql.DB) {
	t.Helper()
	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	for _, q := range []string{
		`INSERT INTO kaname.clusters (id, name) VALUES ('cluster_root', 'kacho') ON CONFLICT DO NOTHING`,
		`INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ('acc-urg', 'acc', 'usr-urg')`,
		`INSERT INTO kaname.users (id, external_id, email, account_id) VALUES ('usr-urg', 'ext-urg', 'usr-urg@kacho.local', 'acc-urg')`,
		`INSERT INTO kaname.projects (id, account_id, name) VALUES ('prj-urg', 'acc-urg', 'prj')`,
		`INSERT INTO kaname.roles (id, account_id, name, description, permissions)
		 VALUES ('rol-urg', 'acc-urg', 'urg_role', 'urg', '["iam.users.*.read"]'::jsonb)`,
		`INSERT INTO kaname.access_bindings
		   (id, subject_type, subject_id, role_id, resource_type, resource_id, status, revoked_at, revoked_by_user_id)
		 VALUES ('acb-urg-r0', 'user', 'usr-urg', 'rol-urg', 'project', 'prj-urg', 'REVOKED', now(), 'usr-urg')`,
		`INSERT INTO kaname.access_bindings
		   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		 VALUES ('acb-urg-live', 'user', 'usr-urg', 'rol-urg', 'account', 'acc-urg', 'ACTIVE')`,
		// Набор субъектов каждой выдачи — той же транзакцией: выдача без строки
		// набора к фиксации не допускается (миграция 20261018214804), пара выдачи
		// обязана быть в её наборе (миграция 20261019194800).
		`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
		 VALUES ('acb-urg-r0', 'user', 'usr-urg', 0), ('acb-urg-live', 'user', 'usr-urg', 0)`,
	} {
		_, err := tx.Exec(q)
		require.NoErrorf(t, err, "посев: %s", q)
	}
	activewayin.SeedGuarded(t, tx)
	require.NoError(t, tx.Commit(), "посев: фиксация")
}

// URG-34 (R0) и Р6, Д2 — накат и его границы.
func TestURG34_R0_RowRevokedBeforeMigrationKeepsUnspecifiedReason(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	own, previous := versionsOf(t, unregistrationMigration)
	db := frvOpenAt(t, previous)
	urgSeed(t, db)

	// Р6 до наката: роль без правил и без прав отвергается, близнец с правилом — нет.
	_, err := db.Exec(`INSERT INTO kaname.roles (id, account_id, name, description, permissions, rules)
	                   VALUES ('rol-urg-empty', 'acc-urg', 'urg_empty', 'urg', '[]'::jsonb, '[]'::jsonb)`)
	code, constraint := ndPgCode(err)
	require.Equal(t, "23514", code, "Р6 до наката: роль rules=[] permissions=[] обязана отвергаться")
	require.Equal(t, "roles_permissions_valid", constraint, "Р6 до наката: отказ не тем ограничением")
	_, err = db.Exec(`INSERT INTO kaname.roles (id, account_id, name, description, permissions, rules)
	                  VALUES ('rol-urg-rule', 'acc-urg', 'urg_rule', 'urg', '[]'::jsonb,
	                          '[{"module":"registry","resources":["registries"],"verbs":["get"],"resourceNames":["r1"]}]'::jsonb)`)
	require.NoError(t, err, "Р6 близнец: роль с правилом принимается и до наката")

	require.NoError(t, goose.UpTo(db, ".", own), "накат kaname#963")

	var status string
	var reason sql.NullString
	require.NoError(t, db.QueryRow(`SELECT status, revocation_reason FROM kaname.access_bindings WHERE id = 'acb-urg-r0'`).
		Scan(&status, &reason))
	require.Equal(t, "REVOKED", status, "URG-34 R0: статус строки, отозванной до миграции")
	require.False(t, reason.Valid, "URG-34 R0: у строки, отозванной до миграции, появилась причина %q", reason.String)

	// Р6 после наката.
	_, err = db.Exec(`INSERT INTO kaname.roles (id, account_id, name, description, permissions, rules)
	                  VALUES ('rol-urg-empty', 'acc-urg', 'urg_empty', 'urg', '[]'::jsonb, '[]'::jsonb)`)
	require.NoError(t, err, "Р6 после наката: роль rules=[] permissions=[] обязана приниматься")

	// Д2: закрытый словарь и согласие с отзывом.
	_, err = db.Exec(`UPDATE kaname.access_bindings SET revocation_reason = 'whatever' WHERE id = 'acb-urg-r0'`)
	code, _ = ndPgCode(err)
	require.Equal(t, "23514", code, "Д2: причина вне словаря обязана отвергаться")
	_, err = db.Exec(`UPDATE kaname.access_bindings SET revocation_reason = 'RESOURCE_UNREGISTERED' WHERE id = 'acb-urg-live'`)
	code, _ = ndPgCode(err)
	require.Equal(t, "23514", code, "Д2: причина у действующей выдачи обязана отвергаться")
	_, err = db.Exec(`UPDATE kaname.access_bindings SET revocation_reason = 'REVOKE' WHERE id = 'acb-urg-r0'`)
	require.NoError(t, err, "Д2: причина из словаря у отозванной выдачи принимается")
}

// Откат возвращает определения ограничения роли и индекса уникальности дословно.
func TestUnregistrationMigration_DownRestoresPriorDefinitions(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	own, previous := versionsOf(t, unregistrationMigration)
	reference := frvOpenAt(t, previous)
	defs := func(db *sql.DB) (roleCheck, uniq string) {
		t.Helper()
		require.NoError(t, db.QueryRow(`SELECT pg_get_constraintdef(oid) FROM pg_constraint
		                                 WHERE conname = 'roles_permissions_valid'`).Scan(&roleCheck))
		require.NoError(t, db.QueryRow(`SELECT indexdef FROM pg_indexes
		                                 WHERE schemaname = 'kaname' AND indexname = 'access_bindings_active_grant_uniq'`).Scan(&uniq))
		return roleCheck, uniq
	}
	wantCheck, wantUniq := defs(reference)

	db := frvOpenAt(t, own)
	gotCheck, gotUniq := defs(db)
	require.NotEqual(t, wantCheck, gotCheck, "Дано: накат меняет ограничение роли")
	require.NotEqual(t, wantUniq, gotUniq, "Дано: накат меняет предикат индекса уникальности")

	require.NoError(t, goose.DownTo(db, ".", previous), "откат kaname#963")
	gotCheck, gotUniq = defs(db)
	require.Equal(t, wantCheck, gotCheck, "откат: ограничение роли не прежнее")
	require.Equal(t, wantUniq, gotUniq, "откат: индекс уникальности не прежний")
	var cols int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM information_schema.columns
	                                 WHERE table_schema = 'kaname' AND table_name = 'access_bindings'
	                                   AND column_name IN ('revocation_reason', 'narrowed_at')`).Scan(&cols))
	require.Zero(t, cols, "откат: колонки изменения остались")
}
