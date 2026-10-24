// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// class_grants_only_test.go — ворота модуля S7 (kaname#950), чистая половина:
// какая выдача классу отвергается и какой текст отказа называет тип.
//
// Сквозные исходы на базе — пробы `TestClassGrantsOnContainers_SC(78|79|81)_…`
// (`internal/apps/kaname/api/access_binding`). Здесь — формы, которых посев
// приёмки не строит: подстановка `*` в модуле и ресурсе, роль без правил,
// несколько модулей с ключом, тип вне живого каталога.

import "testing"

// s7Keyed — модуль registry с ключом: реестр — контейнер, репозиторий — нет.
func s7Keyed() ClassGrantsKeyedModules {
	return ClassGrantsKeyedModules{"registry": {
		{Resource: "repositories", Container: false},
		{Resource: "registries", Container: true},
	}}.Sorted()
}

func s7Target(types ...string) AccessTarget {
	var t AccessTarget
	for i, typ := range types {
		t.Resources = append(t.Resources, ResourceRef{Type: typ, ID: string(rune('a' + i))})
	}
	return t
}

func TestClassGrantObjectsRefusal(t *testing.T) {
	cases := []struct {
		name   string
		keyed  ClassGrantsKeyedModules
		target AccessTarget
		want   string
	}{
		{"необъявленный тип модуля с ключом", s7Keyed(), s7Target("registry.repositories"),
			"Module registry admits system class grants on its public read containers only; type registry.repositories is not one"},
		{"первый в порядке цели", s7Keyed(), s7Target("registry.registries", "vpc.network", "registry.repositories"),
			"Module registry admits system class grants on its public read containers only; type registry.repositories is not one"},
		{"тип вне живого каталога объявленным не считается", s7Keyed(), s7Target("registry.ghosts"),
			"Module registry admits system class grants on its public read containers only; type registry.ghosts is not one"},
		{"модуль с ключом без живых типов", ClassGrantsKeyedModules{"registry": nil}, s7Target("registry.registries"),
			"Module registry admits system class grants on its public read containers only; type registry.registries is not one"},
		{"объявленный контейнер проходит", s7Keyed(), s7Target("registry.registries"), ""},
		{"модуль без ключа не судится", s7Keyed(), s7Target("vpc.network"), ""},
		{"модулей с ключом нет", ClassGrantsKeyedModules{}, s7Target("registry.repositories"), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, refused := ClassGrantObjectsRefusal(c.keyed, c.target)
			if refused != (c.want != "") || got != c.want {
				t.Fatalf("исход (%q, %v), ожидался %q", got, refused, c.want)
			}
		})
	}
}

func TestClassGrantWholeScopeRefusal(t *testing.T) {
	const rid = RoleID("rol0")
	text := func(module, typ string) string { return ClassGrantWholeScopeText(module, rid, typ) }
	rules := func(rs ...Rule) Role { return Role{Rules: rs} }
	cases := []struct {
		name  string
		keyed ClassGrantsKeyedModules
		role  Role
		want  string
	}{
		{"правило с именами над необъявленным типом (роль И)", s7Keyed(),
			rules(Rule{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"get"}, ResourceNames: []string{"app"}}),
			text("registry", "registry.repositories")},
		{"правило над контейнером проходит (роль И2)", s7Keyed(),
			rules(Rule{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"}, ResourceNames: []string{"x"}}),
			""},
		{"якорь над контейнером и вложенное над необъявленным", s7Keyed(),
			rules(Rule{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get", "list"},
				Children: []Rule{{Resources: []string{"repositories"}, Verbs: []string{"get", "list"}}}}),
			text("registry", "registry.repositories")},
		{"правило по меткам — вид селектора не важен", s7Keyed(),
			rules(Rule{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"a": "b"}}),
			text("registry", "registry.repositories")},
		{"ресурс * — первый необъявленный тип в порядке имён", s7Keyed(),
			rules(Rule{Module: "registry", Resources: []string{"*"}, Verbs: []string{"get"}}),
			text("registry", "registry.repositories")},
		{"модуль * — модули с ключом в порядке имён", ClassGrantsKeyedModules{
			"zeta":     {{Resource: "a", Container: false}},
			"registry": {{Resource: "repositories", Container: false}},
		}.Sorted(),
			rules(Rule{Module: "*", Resources: []string{"*"}, Verbs: []string{"get"}}),
			text("registry", "registry.repositories")},
		{"модуль * и ресурс, которого у модуля с ключом нет", s7Keyed(),
			rules(Rule{Module: "*", Resources: []string{"network"}, Verbs: []string{"get"}}),
			""},
		{"первое по порядку правил", ClassGrantsKeyedModules{"registry": {
			{Resource: "registries", Container: true}, {Resource: "repositories", Container: false}, {Resource: "tags", Container: false},
		}}.Sorted(),
			rules(
				Rule{Module: "registry", Resources: []string{"tags"}, Verbs: []string{"get"}, ResourceNames: []string{"t"}},
				Rule{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"get"}, ResourceNames: []string{"r"}},
			),
			text("registry", "registry.tags")},
		{"роль без правил — по скомпилированным правам", s7Keyed(),
			Role{Permissions: Permissions{"registry.registries.*.get", "registry.repositories.app.get"}},
			text("registry", "registry.repositories")},
		{"роль без правил над контейнером проходит", s7Keyed(),
			Role{Permissions: Permissions{"registry.registries.*.get"}},
			""},
		{"модуль без ключа не судится", s7Keyed(),
			rules(Rule{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}, ResourceNames: []string{"n"}}),
			""},
		{"модулей с ключом нет", ClassGrantsKeyedModules{},
			rules(Rule{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"get"}, ResourceNames: []string{"app"}}),
			""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, refused := ClassGrantWholeScopeRefusal(c.keyed, rid, c.role)
			if refused != (c.want != "") || got != c.want {
				t.Fatalf("исход (%q, %v), ожидался %q", got, refused, c.want)
			}
		})
	}
}
