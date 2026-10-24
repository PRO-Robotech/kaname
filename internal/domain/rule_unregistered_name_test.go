// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// rule_unregistered_name_test.go — F2 (security-auditor, ревью kaname#963
// @5c0f8f13d): перечень `resourceNames` у правила ОДИН на все его `resources`,
// а ключ снятия — пара (тип, id). Снятие (a, N) не вправе вычеркнуть N для
// типа b: объект (b, N) — другой объект (приёмка, Д1, URG-05).
//
// Вложенное правило проверяется здесь, а не миром на Postgres: в модели прав
// нет типа-контейнера с двумя вложенными типами (registry — единственный модуль
// с вложенностью, и под реестром лежат только репозитории), поэтому вложенное
// правило над двумя типами в мире собрать нечем. Верхний уровень держит и мир:
// `TestUnregisterNameOfOneTypeKeepsItForTheOtherType`.

import (
	"reflect"
	"testing"
)

func TestWithoutResourceName_TopLevelRuleOverTwoTypesKeepsNameForTheOther(t *testing.T) {
	rules := Rules{{Module: "m", Resources: []string{"a", "b"}, Verbs: []string{"get"}, ResourceNames: []string{"N", "K"}}}

	out, removed, changed := rules.WithoutResourceName("m.a", "N")

	want := Rules{
		{Module: "m", Resources: []string{"b"}, Verbs: []string{"get"}, ResourceNames: []string{"N", "K"}},
		{Module: "m", Resources: []string{"a"}, Verbs: []string{"get"}, ResourceNames: []string{"K"}},
	}
	if !changed || removed != 0 || !reflect.DeepEqual(out, want) {
		t.Fatalf("WithoutResourceName(m.a, N) = %+v removed=%d changed=%v, want %+v removed=0 changed=true", out, removed, changed, want)
	}
}

func TestWithoutResourceName_TopLevelLastNameOfOneTypeKeepsTheOtherType(t *testing.T) {
	rules := Rules{{Module: "m", Resources: []string{"a", "b"}, Verbs: []string{"get"}, ResourceNames: []string{"N"}}}

	out, removed, changed := rules.WithoutResourceName("m.a", "N")

	want := Rules{{Module: "m", Resources: []string{"b"}, Verbs: []string{"get"}, ResourceNames: []string{"N"}}}
	if !changed || removed != 0 || !reflect.DeepEqual(out, want) {
		t.Fatalf("WithoutResourceName(m.a, N) = %+v removed=%d changed=%v, want %+v removed=0 changed=true", out, removed, changed, want)
	}
}

func TestWithoutResourceName_NestedRuleOverTwoTypesKeepsNameForTheOther(t *testing.T) {
	rules := Rules{{Module: "m", Resources: []string{"box"}, Verbs: []string{"get"}, Children: []Rule{
		{Resources: []string{"a", "b"}, Verbs: []string{"get"}, ResourceNames: []string{"N"}},
	}}}

	out, removed, changed := rules.WithoutResourceName("m.a", "N")

	want := Rules{{Module: "m", Resources: []string{"box"}, Verbs: []string{"get"}, Children: []Rule{
		{Resources: []string{"b"}, Verbs: []string{"get"}, ResourceNames: []string{"N"}},
	}}}
	if !changed || removed != 0 || !reflect.DeepEqual(out, want) {
		t.Fatalf("WithoutResourceName(m.a, N) = %+v removed=%d changed=%v, want %+v removed=0 changed=true", out, removed, changed, want)
	}
}

// Близнец: правило над одним типом теряет имя, а без имён — снимается (Р1 (д)).
func TestWithoutResourceName_SingleTypeRuleWithoutNamesIsDropped(t *testing.T) {
	rules := Rules{{Module: "m", Resources: []string{"a"}, Verbs: []string{"get"}, ResourceNames: []string{"N"}}}

	out, removed, changed := rules.WithoutResourceName("m.a", "N")

	if !changed || removed != 1 || len(out) != 0 {
		t.Fatalf("WithoutResourceName(m.a, N) = %+v removed=%d changed=%v, want [] removed=1 changed=true", out, removed, changed)
	}
}
