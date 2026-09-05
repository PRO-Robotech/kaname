// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// seed_rule_resolvability_integration_test.go — гейт на класс «посеянная роль
// называет ресурс именем, которого закрытая таблица типов не несёт».
//
// # Почему это находка, а не стиль
//
// Материализация пообъектного доступа берёт у правила пару «модуль, ресурс»,
// спрашивает у закрытой таблицы тип объекта и, не получив его, не эмитит НИ
// ОДНОГО кортежа — «a typo'd type never grants», как это записано у самой
// эмиссии (reconcile/tuples.go). Отказ верный и намеренно молчаливый.
//
// Молчаливость и есть предмет. Имя, которого таблица не несёт, выглядит ровно
// как имя, которое она несёт: та же форма в посеве, тот же вид в обзоре правки,
// тот же вид при чтении роли через API. Разница обнаруживается, только если
// СПРОСИТЬ таблицу. Путь пользовательских ролей её спрашивает
// (`role.validateRuleCatalog` отвергает негрантабельную пару, называя токен), но
// системные роли из него исключены короткой веткой `systemCtx`, а посев идёт
// мимо неё сырым SQL — то есть у системной половины проверки не было вовсе.
//
// # Почему гейт интеграционный, а не текстовый по миграциям
//
// Предмет — ДЕЙСТВУЮЩЕЕ состояние `roles.rules`, а не текст, который когда-то
// был написан. Разбор миграций как текста дал бы находки на ролях, которые
// более поздняя миграция УДАЛИЛА (0074 сносит девять ролей блочного хранения
// compute) либо переписала — то есть перечень описывал бы мир, которого нет,
// ровно тем способом, который этот гейт и ловит. Поэтому чиниться он смотрит на
// строки после прогона всей цепочки.
//
// # Что гейт НЕ утверждает
//
// Он не утверждает, что разрешимая пара материализуется: это решают ещё область
// привязки и набор глаголов типа. Проверяется ровно одно звено — то, которое
// отказывает молча.
package pg_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// knownUnresolvableSeedPairs — пары ДЕЙСТВУЮЩЕГО посева, которых закрытая
// таблица типов не несёт, вместе с причиной. Ключ — точечная форма
// «модуль.ресурс».
//
// Перечень ПИНИТ цену уже принятых решений и не выдаёт разрешения на новые: он
// самоистекает (запись без предмета — находка), поэтому приведённое к словарю
// имя обязано быть отсюда снято.
var knownUnresolvableSeedPairs = map[string]string{
	// ── Дословное зеркало строк прав (решение посева 0031 §4.7) ──────────────
	// Правила системных ролей повторяют их permission-строки ДОСЛОВНО, чтобы
	// ярус, выведенный из правил, совпал с ярусом, выведенным из прав
	// (tier-parity). Строки прав написаны в snake_case и множественном числе, а
	// закрытая таблица несёт camelCase в единственном — поэтому пара не
	// разрешается, и правило пообъектно не материализует ничего.
	//
	// ЧЕМУ ЭТА ЦЕНА РАВНА НА САМОМ ДЕЛЕ. Прежняя редакция этого блока писала, что
	// «право этих ролей несёт ярусный кортеж на якоре области привязки, а не эти
	// правила». Это ЛОЖНО, и проверено пробой у самой эмиссии
	// (access_binding/tuples_module_sa_branch_test.go): `buildBindingTuples`
	// ветвится на `len(role.Rules) > 0`, и роль С правилами эмитит ТОЛЬКО
	// иерархический указатель — ярусный кортеж на якоре кладёт легаси-ветка, то
	// есть роль БЕЗ правил. У всех перечисленных здесь ролей правила ЕСТЬ.
	// Значит по этим парам не работает ни пообъектная выдача, ни ярусная: тенант,
	// которому выдали `vpc.route_table.view`, не получает НИЧЕГО.
	//
	// ЦЕНА УПЛАЧЕНА — записи сняты вместе с предметом (миграция 0101, kacho#513).
	// Из двух названных здесь путей выбран первый: имена приведены к словарю
	// каталога, и двенадцать доменных ролей заработали. Второй путь (снять
	// правила) отвергнут именно по записанной здесь причине — он не уборка, а
	// ДРУГАЯ выдача, и потребовал бы своей приёмки.
	//
	// `loadbalancer.operations` закрыт третьим способом, потому что первые два к
	// нему неприменимы: типа с таким именем в каталоге нет и быть не должно —
	// операция не объект выдачи, доступ к ней решается на её ресурсе-владельце.
	// Правило и зеркалящая его строка прав сняты с обеих ролей балансировщика.

	// ── Служебные учётки модулей: объявления СНЯТЫ (миграции 0076, 0077) ──────
	// Здесь стояли ПЯТЬ записей — `compute.zones`, `iam.projects`,
	// `vpc.addresses`, `vpc.security_groups`, `vpc.subnets`, — и ещё четыре,
	// снятые вместе с ролью оператора сети (`vpc.subnetses`, `iam.projectses`,
	// `vpc.networks`, `vpc.network_interfaces`).
	//
	// Все девять принадлежали СЕМИ ролям `module.*_sa` и никому больше: перепись
	// по дереву даёт по каждому имени только этих авторов. Первая из записей,
	// `compute.zones`, при этом лежала в блоке выше и читалась как общий случай
	// системных ролей, хотя её автором была одна `module.vpc_sa`.
	//
	// Роли сняты целиком — правила, права, привязки, роли (0076 — оператор сети,
	// 0077 — остальные шесть): ни одно из имён закрытая таблица типов не несёт,
	// разрешимое множество каждой роли пусто, материализация не эмитила ни одного
	// кортежа, а работают эти учётки тремя другими путями — кортежем fga_writer,
	// кортежем system_viewer@cluster и личностью ИНИЦИАТОРА запроса, пробрасываемой
	// на каждом межсервисном вызове. Записи сняты вместе с предметом: перечень
	// обязан самоистекать, иначе он описывает мир, которого нет.
	//
	// Кортежи при этом ОСТАЛИСЬ — см. TestModuleSACapabilitiesSurviveRetirement и
	// TestOperatorClusterTupleSurvivesRetirement.
}

// TestSeededRoleRulesResolveOrArePinned — каждая пара действующего посева либо
// разрешается закрытой таблицей, либо перечислена с причиной.
func TestSeededRoleRulesResolveOrArePinned(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	rows, err := pool.Query(ctx, `SELECT id, name, rules FROM kacho_iam.roles ORDER BY id`)
	require.NoError(t, err)

	type authored struct {
		role     string
		module   string
		resource string
	}
	var (
		roles     int
		ruleCount int
		wildcards int
		pairs     []authored
	)
	for rows.Next() {
		var id, name string
		var raw []byte
		require.NoError(t, rows.Scan(&id, &name, &raw))
		roles++
		if len(raw) == 0 {
			continue
		}
		rules, derr := domain.DecodeRules(raw)
		require.NoErrorf(t, derr, "роль %s (%s): rules не декодируются: %v", id, name, derr)
		for _, r := range rules {
			ruleCount++
			for _, res := range r.Resources {
				if r.Module == "*" || res == "*" {
					wildcards++
					continue
				}
				pairs = append(pairs, authored{role: name, module: r.Module, resource: res})
			}
		}
	}
	require.NoError(t, rows.Err())

	// Перепись — до вердикта. «Ноль находок» обязано быть отличимо от «ноль
	// прочитанного»: пустая выборка прошла бы чисто на любом посеве.
	t.Logf("осмотрено: ролей=%d, правил=%d, пар=%d, подстановок=%d, записей пина=%d",
		roles, ruleCount, len(pairs), wildcards, len(knownUnresolvableSeedPairs))

	require.NotZerof(t, roles, "предпосылка гейта нарушена: в посеве нет ни одной роли")
	require.NotZerof(t, ruleCount, "предпосылка гейта нарушена: прочитано %d ролей, но ни одного правила — "+
		"форма посева изменилась, и предикат «пара разрешается таблицей» больше ничего не проверяет", roles)
	// Предпосылка в другую сторону: таблица обязана уметь отвечать «да». Пустая
	// таблица объявила бы негрантабельным всё, и вердикт был бы получен даром.
	require.NotEmpty(t, authzmap.Catalog(),
		"предпосылка гейта нарушена: закрытая таблица типов пуста — «не разрешается» получено даром")

	seen := map[string]bool{}
	findings := map[string][]string{}
	for _, p := range pairs {
		if _, ok := authzmap.ObjectType(p.module, p.resource); ok {
			continue
		}
		key := p.module + "." + p.resource
		seen[key] = true
		if _, pinned := knownUnresolvableSeedPairs[key]; pinned {
			continue
		}
		findings[key] = append(findings[key], p.role)
	}
	var keys []string
	for k := range findings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		roleList := findings[k]
		sort.Strings(roleList)
		t.Errorf("посев называет ресурс, которого закрытая таблица типов не несёт: %s (роли: %s).\n"+
			"Материализация спросит таблицу, не получит типа и не эмитит НИ ОДНОГО кортежа — "+
			"правило выглядит выданным правом и не выдаёт ничего.\n"+
			"Приведи имя к словарю таблицы, сними правило, либо внеси пару в "+
			"knownUnresolvableSeedPairs с причиной.", k, strings.Join(dedupe(roleList), ", "))
	}

	// Самоистечение: запись пина, которой больше нечего описывать, — находка.
	// Иначе перечень переживает свой предмет и становится ложным утверждением о
	// дереве. Разбор ОБЩИЙ с гейтом-близнецом (seed_pin_self_expiry_test.go), и
	// там же лежит доказательство его способности упасть и смолчать.
	for _, f := range stalePinFindings("knownUnresolvableSeedPairs",
		"неразрешимой пары", knownUnresolvableSeedPairs, seen) {
		t.Error(f)
	}
}

// TestSeedResolvabilityPredicate_HasAControlBothWays — контроль самого
// предиката. Односторонняя проверка зеленеет сильнее всего именно тогда, когда
// таблица пуста или отвечает всем одинаково: тогда «не разрешается» получено
// даром и вердикт беспредметен.
func TestSeedResolvabilityPredicate_HasAControlBothWays(t *testing.T) {
	if _, ok := authzmap.ObjectType("vpc", "subnet"); !ok {
		t.Errorf("контроль: словарь не признал имя, которое обязан признавать (vpc.subnet) — " +
			"«не разрешается» было бы получено даром")
	}
	if _, ok := authzmap.ObjectType("vpc", "subnetses"); ok {
		t.Errorf("контроль: словарь признал имя, которого не несёт (vpc.subnetses) — предикат не различает")
	}
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
