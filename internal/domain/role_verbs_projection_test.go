// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// role_verbs_projection_test.go — проекция «роль → тип × глагол» выводится из
// ТЕХ ЖЕ селекторов, которыми роль материализуется.
//
// # Предмет
//
// Форма E спрашивает пару «тип объекта × глагол»; роль объявляет разрешения
// точечными именами. Перевод обязан иметь ОДИН источник — селекторы правил.
// Второй (разбор `permissions` заново) дал бы два места об одном предмете,
// расходящиеся при первом же изменении формы правила, причём молча: обе стороны
// по отдельности непротиворечивы.
//
// # Почему подстановочный глагол отбрасывается, а не раскрывается
//
// Набор глаголов ТИПА знает каталог типов, а не домен. Раскрыть `*` здесь
// значило бы завести в домене собственную копию каталога — и она разошлась бы с
// настоящим при добавлении первого же глагола. Правило с подстановкой
// материализуется соседней стороной, получающей набор параметром от того, кто
// его знает.

import "testing"

func TestRoleVerbsFromSelectors(t *testing.T) {
	sels := []RuleSelector{
		{ObjectTypes: []string{"vpc_network", "vpc_subnet"}, Verbs: []string{"get", "LIST"}},
		// Дубль пары — проекция обязана быть множеством, а не списком доставок.
		{ObjectTypes: []string{"vpc_network"}, Verbs: []string{"get"}},
		// Подстановка: отбрасывается здесь намеренно.
		{ObjectTypes: []string{"compute_instance"}, Verbs: []string{"*"}},
		// Пустые части не порождают пар.
		{ObjectTypes: []string{""}, Verbs: []string{"get"}},
		{ObjectTypes: []string{"vpc_network"}, Verbs: []string{"  "}},
	}

	got := RoleVerbsFromSelectors(sels)

	want := map[RoleVerb]bool{
		{ObjectType: "vpc_network", Verb: "get"}:  true,
		{ObjectType: "vpc_network", Verb: "list"}: true,
		{ObjectType: "vpc_subnet", Verb: "get"}:   true,
		{ObjectType: "vpc_subnet", Verb: "list"}:  true,
	}
	if len(got) != len(want) {
		t.Fatalf("проекция = %v (пар %d), ожидалось %d — дубль или лишняя пара меняет "+
			"смысл: проекция есть МНОЖЕСТВО прав роли, а не журнал её объявлений",
			got, len(got), len(want))
	}
	for _, pv := range got {
		if !want[pv] {
			t.Errorf("лишняя пара %v — подстановочный глагол и пустые части не должны "+
				"давать прав", pv)
		}
		if pv.Verb != NormalizeVerb(pv.Verb) {
			t.Errorf("глагол %q не приведён — приведение есть свойство ПРОИЗВОДИТЕЛЯ имени; "+
				"неприведённая строка не будет найдена запросом, и отличить это от «права нет» "+
				"станет нечем", pv.Verb)
		}
	}

	// Положительный контроль: пустой вход даёт пустую проекцию, а не панику и не
	// «все права».
	if n := len(RoleVerbsFromSelectors(nil)); n != 0 {
		t.Errorf("пустые селекторы дали %d пар — роль без материализующих правил не даёт "+
			"глаголов", n)
	}

	t.Logf("осмотрено: селекторов %d, пар на выходе %d", len(sels), len(got))
}
