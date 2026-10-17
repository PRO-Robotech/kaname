// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// nested_rule_guards_integration_test.go — СТРАЖИ БАЗЫ ЧИТАЮТ ВЛОЖЕННОЕ ПРАВИЛО
// (kaname#874, приёмка
// docs/engineering/acceptance/nested-rule-reaches-descendants-of-a-named-container.md,
// редакция 2, Р1, Р5; M1 круга 1).
//
// Последнее слово записи — у базы (ban #10). Три предмета:
//   - форма вложенности в `roles.rules` (`kaname.iam_rules_valid`): правило-владелец
//     — ровно один ресурс и не `*`; вложенное — без `module` и своих `children`;
//     перечень непуст;
//   - «классу — только чтение» (`kaname.role_grants_reads_only`): пишущий глагол
//     во вложенном правиле закрывает роль для класса так же, как в правиле
//     верхнего уровня;
//   - контейнер вложенного селектора (`kaname.role_rule_selectors`): форма
//     ветви контейнера, живой тип каталога, модельное имя выводит страж.
// Каждое «нет» — с близнецом «да», отличающимся одним фактом.

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func ndPgCode(err error) (string, string) {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code, pe.ConstraintName
	}
	return "", ""
}

// ndSeedTenant — арендная обвязка ОДНОЙ транзакцией: владелец аккаунта —
// отложенный внешний ключ (`accounts_owner_fk`), он судится на фиксации.
func ndSeedTenant(t *testing.T, db *sql.DB) {
	t.Helper()
	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	for _, q := range []string{
		`INSERT INTO kaname.clusters (id, name) VALUES ('cluster_root', 'kacho') ON CONFLICT DO NOTHING`,
		`INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ('acc-nd', 'acc', 'usr-nd')`,
		`INSERT INTO kaname.users (id, external_id, email, account_id) VALUES ('usr-nd', 'ext-nd', 'usr-nd@kacho.local', 'acc-nd')`,
		`INSERT INTO kaname.projects (id, account_id, name) VALUES ('prj-nd', 'acc-nd', 'prj')`,
	} {
		_, err := tx.Exec(q)
		require.NoErrorf(t, err, "посев: %s", q)
	}
	require.NoError(t, tx.Commit(), "посев: фиксация")
}

func ndInsertRole(db *sql.DB, id, rules string) error {
	_, err := db.Exec(`INSERT INTO kaname.roles (id, name, permissions, rules, cluster_id)
	                   VALUES ($1, $2, '[]'::jsonb, $3::jsonb, 'cluster_root')`, id, "registry."+id[4:], rules)
	return err
}

const ndWholeRule = `[{"module":"registry","resources":["registries"],"verbs":["get","list"],
                      "children":[{"resources":["repositories"],"verbs":["get","list"]}]}]`

// Р1: форма вложенности судится базой.
func TestIntegration_ND04_RulesGuardJudgesTheNesting(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)
	ndSeedTenant(t, db)
	require.NoError(t, ndInsertRole(db, "rol-ndok", ndWholeRule), "близнец: годная вложенность")

	for name, rules := range map[string]string{
		"владелец над двумя ресурсами": `[{"module":"registry","resources":["registries","repositories"],"verbs":["get"],
		                                   "children":[{"resources":["repositories"],"verbs":["get"]}]}]`,
		"владелец над *": `[{"module":"registry","resources":["*"],"verbs":["get"],
		                     "children":[{"resources":["repositories"],"verbs":["get"]}]}]`,
		"вложенное с module": `[{"module":"registry","resources":["registries"],"verbs":["get"],
		                         "children":[{"module":"registry","resources":["repositories"],"verbs":["get"]}]}]`,
		"вложенное со своими children": `[{"module":"registry","resources":["registries"],"verbs":["get"],
		                                   "children":[{"resources":["repositories"],"verbs":["get"],
		                                                "children":[{"resources":["repositories"],"verbs":["get"]}]}]}]`,
		"пустой перечень": `[{"module":"registry","resources":["registries"],"verbs":["get"],"children":[]}]`,
		"вложенное без глаголов": `[{"module":"registry","resources":["registries"],"verbs":["get"],
		                             "children":[{"resources":["repositories"]}]}]`,
	} {
		t.Run(name, func(t *testing.T) {
			err := ndInsertRole(db, "rol-ndbad", rules)
			code, cons := ndPgCode(err)
			require.Equalf(t, "23514", code, "ждали отказ CHECK, получено %v", err)
			require.Equal(t, "roles_rules_valid", cons)
		})
	}
}

// Р5, SC-21: классу — только чтение, и вложенное правило читается.
func TestIntegration_ND05_ClassReadsOnlyGuardReadsNestedRules(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)
	ndSeedTenant(t, db)
	require.NoError(t, ndInsertRole(db, "rol-ndrd", ndWholeRule))
	require.NoError(t, ndInsertRole(db, "rol-ndwr", `[{"module":"registry","resources":["registries"],"verbs":["get","list"],
	                       "children":[{"resources":["repositories"],"verbs":["get","update"]}]}]`))
	grant := func(id, role string) error {
		if _, err := db.Exec(`INSERT INTO kaname.access_bindings
		     (id, subject_type, subject_id, role_id, resource_type, resource_id, status, target)
		     VALUES ($1, 'system_class', 'anonymous', $2, 'project', 'prj-nd', 'ACTIVE',
		             '{"resources":[{"type":"registry.registries","id":"reg-x"}]}'::jsonb)`, id, role); err != nil {
			return err
		}
		_, err := db.Exec(`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
		                    VALUES ($1, 'system_class', 'anonymous')`, id)
		return err
	}
	require.NoError(t, grant("acb-ndrd", "rol-ndrd"), "близнец: вложенное [get, list]")
	err := grant("acb-ndwr", "rol-ndwr")
	code, cons := ndPgCode(err)
	require.Equalf(t, "23000", code, "ждали отказ стража класса, получено %v", err)
	require.Equal(t, "access_binding_subjects_system_class_reads_only", cons)
}

// Контейнер вложенного селектора: форма, живой тип каталога; модельное имя
// типа контейнера выводит страж (писатель его не пишет).
func TestIntegration_ND02_SelectorContainerIsGuarded(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)
	ndSeedTenant(t, db)
	require.NoError(t, ndInsertRole(db, "rol-ndsel", ndWholeRule))
	ins := func(fp, ctype, carm, cnames, clabels string) error {
		_, err := db.Exec(`INSERT INTO kaname.role_rule_selectors
		    (role_id, rule_fp, arm, object_types, match_labels,
		     container_type, container_arm, container_resource_names, container_match_labels)
		    VALUES ('rol-ndsel', $1, 'anchor', ARRAY['registry.repositories'], '{}'::jsonb,
		            NULLIF($2, ''), NULLIF($3, ''), $4::text[], $5::jsonb)`, fp, ctype, carm, cnames, clabels)
		return err
	}
	require.NoError(t, ins("fp-ok", "registry.registries", "anchor", "{}", "{}"), "близнец: контейнер якорем")
	var model string
	require.NoError(t, db.QueryRow(`SELECT container_object_type FROM kaname.role_rule_selectors
	                                 WHERE role_id = 'rol-ndsel' AND rule_fp = 'fp-ok'`).Scan(&model))
	require.Equal(t, "registry_registry", model, "модельное имя контейнера выведено стражем")
	require.NoError(t, ins("fp-names", "registry.registries", "names", "{reg-x}", "{}"), "близнец: контейнер именами")

	for name, c := range map[string][4]string{
		"ветвь без типа":          {"", "anchor", "{}", "{}"},
		"тип без ветви":           {"registry.registries", "", "{}", "{}"},
		"имена у якоря":           {"registry.registries", "anchor", "{reg-x}", "{}"},
		"ветвь имён без имён":     {"registry.registries", "names", "{}", "{}"},
		"контейнер — свой же тип": {"registry.repositories", "anchor", "{}", "{}"},
		"тип вне живого каталога": {"registry.nothing", "anchor", "{}", "{}"},
	} {
		t.Run(name, func(t *testing.T) {
			err := ins("fp-bad", c[0], c[1], c[2], c[3])
			code, _ := ndPgCode(err)
			require.Equalf(t, "23514", code, "ждали отказ, получено %v", err)
		})
	}
}
