// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
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
	// разрешается, и правило пообъектно не материализует ничего. Право этих
	// ролей несёт ярусный кортеж на якоре области привязки, а не эти правила.
	//
	// Записано как цена, а не как норма: пообъектная выдача по этим ролям
	// сегодня не работает, и когда она понадобится, имена придётся привести к
	// словарю (либо правила снять).
	"compute.zones":           "дословное зеркало строки права compute.zones.*.get; таблица несёт geo-топологию иначе",
	"iam.access_binding":      "дословное зеркало; таблица несёт iam.accessBinding",
	"iam.service_account":     "дословное зеркало; таблица несёт iam.serviceAccount",
	"loadbalancer.operations": "дословное зеркало; операции не являются грантабельным типом",
	"vpc.route_table":         "дословное зеркало; таблица несёт vpc.routeTable",
	"vpc.security_group":      "дословное зеркало; таблица несёт vpc.securityGroup",

	// ── Служебные учётки модулей (посев 0009, правила 0031 §4.7, 0045, 0057) ──
	// Те же дословные зеркала, но у машинных принципалов. Их право на чужой
	// ресурс идёт ярусным кортежем на кластерном якоре; пообъектно эти правила
	// не дают ничего.
	"iam.projects":           "служебная учётка модуля; дословное зеркало, таблица несёт iam.project",
	"vpc.addresses":          "служебная учётка модуля; дословное зеркало, таблица несёт vpc.address",
	"vpc.networks":           "служебная учётка модуля; дословное зеркало, таблица несёт vpc.network",
	"vpc.network_interfaces": "служебная учётка модуля; дословное зеркало, таблица несёт vpc.networkInterface",
	"vpc.security_groups":    "служебная учётка модуля; дословное зеркало, таблица несёт vpc.securityGroup",
	"vpc.subnets":            "служебная учётка модуля; дословное зеркало, таблица несёт vpc.subnet",

	// ── Учётка оператора сети: веер по аккаунтам и проектам МЁРТВ ────────────
	// Эти два имени вдобавок задвоены во множественном числе (subnetses /
	// projectses) и просят ТОЛЬКО перечисление, без чтения. Замерено на этой
	// ревизии: ни одно из ЧЕТЫРЁХ правил роли module.vpc_operator_sa не
	// разрешается, поэтому пообъектных кортежей нет вовсе; а каскад
	// `viewer … or system_viewer from cluster`, ради которого оператору сеяли
	// кластерный кортеж (0010), из модели УДАЛЁН — fga_model.fga говорит это
	// прямо на типах account и project. Значит перечисление аккаунтов и
	// проектов оператору сегодня не даёт ничего, и приведение имён к словарю
	// было бы не косметикой, а новой выдачей кластерного размера.
	//
	// Решение (снять правила либо переписать веер) — продуктовое и здесь не
	// принимается; запись держит цену видимой, чтобы её не приняли за
	// работающую выдачу.
	"vpc.subnetses":  "оператор сети: веер мёртв (правила не разрешаются, каскад из модели удалён)",
	"iam.projectses": "оператор сети: веер мёртв (правила не разрешаются, каскад из модели удалён)",
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
	// дереве.
	var stale []string
	for key := range knownUnresolvableSeedPairs {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		t.Errorf("запись пина без предмета: «%s» перечислена, но такой неразрешимой пары в посеве нет.\n"+
			"Имя привели к словарю, роль удалили либо правило сняли — сними и запись, иначе "+
			"перечень описывает мир, которого нет.", key)
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
