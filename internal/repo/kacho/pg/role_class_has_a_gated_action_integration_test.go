// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// role_class_has_a_gated_action_integration_test.go — ИСХОД миграции
// 20260902180800_role_rules_name_only_classes_with_a_gated_action.
//
// # Предмет
//
// Правило системной роли называет КЛАСС на ресурсе. Класс что-то даёт ровно
// тогда, когда у ресурса есть действие, чей гейт спрашивает пообъектное
// отношение этого класса на типе ресурса. У ресурса `role` модуля `iam` таким
// действием не является ни одно: чтение роли (`RoleService/Get`) сужается НА
// ДАННЫХ вопросом `viewer ∪ v_list`, поэтому `v_get` на `iam_role` не
// спрашивает ни одна запись каталога прав края. Две живые роли — `iam.role.edit`
// и `iam.role.view` — этот класс называли, то есть обещали право, которого
// платформа не исполняет ни при каком входе (задача продукта kacho#1916).
//
// # Почему проба УТВЕРЖДАЕТ ОБЕ СТОРОНЫ
//
// Отрицание («класса `get` у этих двух ролей нет») зеленело бы и на миграции,
// снявшей `get` У ВСЕХ, — то есть на изменении, отнимающем живое право у
// девятнадцати соседних ролей. Поэтому рядом стоит положительный контроль:
// соседние роли, у которых тот же класс ПРИГОДЕН (у их ресурса есть действие,
// гейтящееся `v_get`), обязаны остаться дословно теми же.
//
// # Что здесь НЕ утверждается — и кем это держится
//
// Свойство «ни одна роль манифеста не называет класса без пригодного действия»
// есть свойство ДЕРЕВА, а не этой базы, и держит его разбор манифеста
// (`make -C services/iam module-manifest-check`, стадия «правила ролей»):
// он читает каталог прав края, которого в базе нет и быть не может. Здесь
// утверждается ровно то, что миграция обязана произвести и обязана НЕ тронуть.
package pg_test

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// classMigrationPrefix — префикс имени миграции-предмета: находка обязана
// называть, что смотреть.
const classMigrationPrefix = "20260902180800"

// ruleLiteral — правила роли одной строкой, ДОСЛОВНО и без сортировки.
//
// Без сортировки намеренно: `verbs` — упорядоченное поле хранимой формы, и
// объявление манифеста сверяется с ним побайтово. Проба, сортирующая стороны,
// молчала бы на перестановке, которую сверка манифеста считает расхождением.
func ruleLiteral(rs domain.Rules) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		parts = append(parts, fmt.Sprintf("%s/[%s]/[%s]",
			r.Module, strings.Join(r.Resources, " "), strings.Join(r.Verbs, " ")))
	}
	return strings.Join(parts, " + ")
}

// readClusterRules читает правила КЛАСТЕРНЫХ ролей живой базы.
//
// Вторым значением — объём осмотренного: «ноль расхождений» обязано быть
// отличимо от «ноль прочитанного».
func readClusterRules(ctx context.Context, t *testing.T, pool *pgxpool.Pool) (map[string]string, int) {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT name, rules FROM kacho_iam.roles WHERE cluster_id IS NOT NULL ORDER BY name`)
	require.NoError(t, err)
	defer rows.Close()

	out := map[string]string{}
	read := 0
	for rows.Next() {
		var name string
		var raw []byte
		require.NoError(t, rows.Scan(&name, &raw))
		read++
		rules, derr := domain.DecodeRules(raw)
		require.NoErrorf(t, derr, "роль %q: rules не декодируются кодеком домена", name)
		out[name] = ruleLiteral(rules)
	}
	require.NoError(t, rows.Err())
	return out, read
}

// TestRoleRulesNameOnlyClassesWithAGatedAction — предмет и его положительный
// контроль в одной пробе.
func TestRoleRulesNameOnlyClassesWithAGatedAction(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	live, read := readClusterRules(ctx, t, pool)
	t.Logf("перепись: кластерных ролей прочитано %d", read)
	require.GreaterOrEqual(t, read, 20,
		"кластерных ролей прочитано %d — чтение перестало видеть предмет, "+
			"и молчание пробы сказано ни о чём", read)

	// ПРЕДМЕТ: у ресурса `role` пригодны только `list`, `update`, `delete`.
	want := map[string]string{
		"iam.role.edit": "iam/[role]/[list update]",
		"iam.role.view": "iam/[role]/[list]",
	}
	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: у этих ресурсов действие чтения гейтится `v_get`,
	// класс пригоден, и правило обязано остаться ДОСЛОВНО тем же.
	untouched := map[string]string{
		"iam.account.edit":      "iam/[account]/[get list update]",
		"iam.account.view":      "iam/[account]/[list get]",
		"iam.group.view":        "iam/[group]/[list get]",
		"iam.role.admin":        "iam/[role]/[*]",
		"vpc.subnet.view":       "vpc/[subnet]/[list get]",
		"compute.instance.edit": "compute/[instance]/[get list update]",
	}

	check := func(kind string, expect map[string]string) {
		names := make([]string, 0, len(expect))
		for n := range expect {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			got, ok := live[n]
			require.Truef(t, ok, "%s: роли %q в живой базе нет — предпосылка пробы нарушена, "+
				"и «правило совпало» получено даром", kind, n)
			require.Equalf(t, expect[n], got,
				"%s: роль %q — правило расходится с ожидаемым.\n  ожидалось: %s\n  в базе:    %s\n"+
					"Предмет производит миграция %s; см. kacho#1916.",
				kind, n, expect[n], got, classMigrationPrefix)
		}
	}
	check("ПРЕДМЕТ", want)
	check("КОНТРОЛЬ", untouched)
}

// TestRoleRuleRefDropsTheClassItsRuleNoLongerNames — проекция объявленных
// сегментов не переживает свой предмет.
//
// `role_rule_ref` — проекция «правило → (модуль, ресурс, глагол)». Строка,
// чьего глагола правило больше не называет, утверждала бы, что объявление живо,
// когда его нет; и она же — референт ключа, из-за которого сегмент считается
// объявленным.
func TestRoleRuleRefDropsTheClassItsRuleNoLongerNames(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	var total int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_rule_ref`).Scan(&total))
	t.Logf("перепись: строк проекции объявленных сегментов %d", total)
	require.NotZerof(t, total,
		"проекция пуста целиком — «нужной строки нет» получено даром, а не проверено")

	// Глагол ЯКОРЯ хранится как NULL: правило-подстановка (`verbs: ["*"]`)
	// сегмент глагола не называет вовсе. Приводится к видимому имени, а не
	// отбрасывается: отброшенный якорь унёс бы из пробы `iam.role.admin` —
	// ближайший положительный контроль этой же пары (модуль, ресурс).
	rows, err := pool.Query(ctx, `
		SELECT r.name, coalesce(rr.verb, '(якорь)')
		  FROM kacho_iam.role_rule_ref rr
		  JOIN kacho_iam.roles r ON r.id = rr.role_id
		 WHERE rr.module = 'iam' AND rr.resource = 'role'
		 ORDER BY r.name, 2`)
	require.NoError(t, err)
	byRole := map[string][]string{}
	for rows.Next() {
		var name, verb string
		require.NoError(t, rows.Scan(&name, &verb))
		byRole[name] = append(byRole[name], verb)
	}
	require.NoError(t, rows.Err())

	// ПРЕДМЕТ: класса `get` на ресурсе роли не объявляет больше никто.
	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ рядом: остальные сегменты тех же двух ролей на
	// месте — иначе отрицание зеленело бы на снятой проекции целиком.
	require.Equal(t, map[string][]string{
		"iam.role.admin": {"(якорь)"},
		"iam.role.edit":  {"list", "update"},
		"iam.role.view":  {"list"},
	}, byRole,
		"проекция объявленных сегментов ресурса роли расходится с правилами.\n"+
			"Строку снимает миграция %s вместе с её предметом — глаголом правила; "+
			"остаток означает, что снят не весь предмет (kacho#1916).", classMigrationPrefix)
}
