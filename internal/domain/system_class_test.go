// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// system_class_test.go — правила системного класса субъекта (приёмка
// anonymous-and-authenticated-are-subject-classes.md, отпечаток ae9ba373…0427f51;
// kaname#829): классификация говорящего (Р2), отказ говорящему (Р3), словарь
// имён (Р1), роль «только чтение» (Р4).

import (
	"slices"
	"testing"
)

func TestSystemClass_SpeakerClassesByKind(t *testing.T) {
	both := []string{SpeakerAuthenticated, SpeakerAnonymous}
	for _, c := range []struct {
		speaker string
		want    []string
	}{
		{"user:usr-1", both},
		{"service_account:sva-1", both},
		{SpeakerAnonymous, []string{}},
		// Подстановка классов не получает (SC-15): переходного отображения в
		// аноним больше нет, а до вопроса её не пускает [SpeakerRefusal].
		{"user:*", []string{}},
		{"service_account:*", []string{}},
		{"group:grp-1", []string{}},
		{"group:grp-1#member", []string{}},
		{"user", []string{}},
		{"", []string{}},
	} {
		got := SpeakerClasses(c.speaker)
		if !slices.Equal(got, c.want) {
			t.Errorf("SpeakerClasses(%q) = %v, ждали %v", c.speaker, got, c.want)
		}
		if got == nil {
			t.Errorf("SpeakerClasses(%q) = nil: в запрос уехал бы NULL вместо пустого массива", c.speaker)
		}
	}
}

func TestSystemClass_SpeakerRefusalTexts(t *testing.T) {
	for _, c := range []struct {
		speaker string
		want    string
	}{
		{SpeakerAuthenticated, "Illegal argument subject: system class authenticated is not a speaker"},
		{"system_class:everyone", "Illegal argument subject: system class everyone is not a speaker"},
		{"group:*", "Illegal argument subject: wildcard is not a speaker"},
		// SC-15: подстановка любого вида говорящим не бывает — в том числе
		// прежняя переходная `user:*` реестра (полоса L6, kaname#832).
		{"user:*", "Illegal argument subject: wildcard is not a speaker"},
		{"service_account:*", "Illegal argument subject: wildcard is not a speaker"},
		{SpeakerAnonymous, ""},
		{"user:usr-1", ""},
	} {
		err := SpeakerRefusal(c.speaker)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != c.want {
			t.Errorf("SpeakerRefusal(%q) = %q, ждали %q", c.speaker, got, c.want)
		}
	}
}

func TestSystemClass_SubjectValidateClosedNames(t *testing.T) {
	for _, name := range []SubjectID{ClassAnonymous, ClassAuthenticated} {
		if err := (Subject{Type: SubjectTypeSystemClass, ID: name}).Validate(); err != nil {
			t.Errorf("класс %q отвергнут: %v", name, err)
		}
	}
	err := Subject{Type: SubjectTypeSystemClass, ID: "everyone"}.Validate()
	const want = `Illegal argument subject id "everyone" for subject type system_class (allowed: anonymous|authenticated)`
	if err == nil || err.Error() != want {
		t.Errorf("имя вне словаря: %v, ждали %q", err, want)
	}
	if got := FGASubjectRef(string(SubjectTypeSystemClass), "anonymous"); got != SpeakerAnonymous {
		t.Errorf("FGASubjectRef класса = %q, ждали %q (а не выдачу человеку)", got, SpeakerAnonymous)
	}
}

func TestSystemClass_RoleGrantsReadsOnly(t *testing.T) {
	read := Role{Rules: Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get", "List"}}}}
	if !read.GrantsReadsOnly() {
		t.Error("роль [get, list] обязана читаться как только чтение")
	}
	for name, r := range map[string]Role{
		"update":   {Rules: Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get", "update"}}}},
		"wildcard": {Rules: Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"*"}}}},
		"perm":     {Permissions: []Permission{"vpc.network.*.get", "vpc.network.*.delete"}},
		"nodot":    {Permissions: []Permission{"get"}},
	} {
		if r.GrantsReadsOnly() {
			t.Errorf("роль %s пишет, а признана только читающей", name)
		}
	}
	if !(Role{Permissions: []Permission{"vpc.network.*.list", "vpc.network.*.get"}}).GrantsReadsOnly() {
		t.Error("проекция прав [list, get] обязана читаться как только чтение")
	}
}
