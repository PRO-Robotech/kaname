// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// access_binding_target_object_id_test.go — идентификатор объекта в цели выдачи
// подчиняется грамматике объекта (PRO-Robotech/kaname#1004, приёмка
// docs/engineering/acceptance/access-target-object-id-follows-the-object-grammar.md).
//
// Грамматика — та, по которой регистрация объекта судит часть после двоеточия:
// непуста, без пробела, табуляции, перевода строки, `#` и `:` (допущение Д1
// приёмки). Каждое отрицание отличается от своего близнеца ровно одним знаком:
// без близнеца «отвергнуто» не отличало бы проверку формы от проверки, которая
// отвергает всё.

import (
	"strconv"
	"testing"
)

const objectIDBase = "reg0000000000000s1a9"

// objectIDRefusal — дословный текст отказа ATI-02…04 для позиции i.
func objectIDRefusal(i int) string {
	return "Illegal argument target.resources[" + strconv.Itoa(i) +
		"].id (not a valid object id: space, tab, newline, '#' and ':' are not allowed)"
}

func repoRefs(ids ...string) AccessTarget {
	out := AccessTarget{Resources: make([]ResourceRef, 0, len(ids))}
	for _, id := range ids {
		out.Resources = append(out.Resources, ResourceRef{Type: "registry.repositories", ID: id})
	}
	return out
}

// TestAccessTarget_Validate_ObjectIDFollowsTheObjectGrammar — ATI-03: каждый
// запрещённый знак в середине идентификатора — отказ с дословным текстом, его
// близнец со знаком `-` — годен.
func TestAccessTarget_Validate_ObjectIDFollowsTheObjectGrammar(t *testing.T) {
	twin := objectIDBase + "/o-ne"
	if err := repoRefs(twin).Validate(); err != nil {
		t.Fatalf("близнец %q отвергнут: %v", twin, err)
	}
	for _, c := range []struct{ name, x string }{
		{"пробел", " "},
		{"табуляция", "\t"},
		{"перевод строки", "\n"},
		{"решётка", "#"},
		{"двоеточие", ":"},
	} {
		t.Run(c.name, func(t *testing.T) {
			id := objectIDBase + "/o" + c.x + "ne"
			err := repoRefs(id).Validate()
			if err == nil {
				t.Fatalf("идентификатор %q принят", id)
			}
			if got := err.Error(); got != objectIDRefusal(0) {
				t.Errorf("текст отказа %q = %q, ожидался %q", id, got, objectIDRefusal(0))
			}
		})
	}
}

// TestAccessTarget_Validate_GluedObjectIDIsRefused — ATI-02: идентификатор,
// дословно несущий разделитель записи состава и второй «тип:id», отвергается;
// без хвоста (ATI-02b) — годен.
func TestAccessTarget_Validate_GluedObjectIDIsRefused(t *testing.T) {
	legit := objectIDBase + "/one"
	if err := repoRefs(legit).Validate(); err != nil {
		t.Fatalf("близнец %q отвергнут: %v", legit, err)
	}
	glued := legit + "\nregistry.repositories:" + objectIDBase + "/one/two"
	err := repoRefs(glued).Validate()
	if err == nil {
		t.Fatalf("склеенный идентификатор %q принят", glued)
	}
	if got := err.Error(); got != objectIDRefusal(0) {
		t.Errorf("текст отказа = %q, ожидался %q", got, objectIDRefusal(0))
	}
}

// TestAccessTarget_Validate_ObjectIDRefusalNamesItsPosition — ATI-04: отказ
// называет позицию негодного элемента в перечне, а не первую.
func TestAccessTarget_Validate_ObjectIDRefusalNamesItsPosition(t *testing.T) {
	err := repoRefs(objectIDBase+"/one", objectIDBase+"/one two").Validate()
	if err == nil {
		t.Fatal("цель со вторым негодным элементом принята")
	}
	if got := err.Error(); got != objectIDRefusal(1) {
		t.Errorf("текст отказа = %q, ожидался %q", got, objectIDRefusal(1))
	}
}

// TestAccessTarget_Validate_SlashBoundariesAreLawful — ATI-01: `/` и каждая его
// граница законны — служба идентификатор не режет и не нормализует; отказ на
// границе — дело грамматики владельца объекта.
func TestAccessTarget_Validate_SlashBoundariesAreLawful(t *testing.T) {
	for _, id := range []string{
		objectIDBase + "/one",
		objectIDBase + "/one/two",
		objectIDBase + "/one/",
		objectIDBase + "//one",
		"/" + objectIDBase + "/one",
		objectIDBase + "%2Fone",
		objectIDBase + `\/one`,
	} {
		if err := repoRefs(id).Validate(); err != nil {
			t.Errorf("граница `/` %q отвергнута: %v", id, err)
		}
	}
}

// TestAccessTarget_Validate_EmptyObjectIDKeepsItsText — пустой идентификатор
// отвергается прежним текстом: новая проверка формы его не перекрывает.
func TestAccessTarget_Validate_EmptyObjectIDKeepsItsText(t *testing.T) {
	err := repoRefs("").Validate()
	if err == nil {
		t.Fatal("пустой идентификатор принят")
	}
	if want := "Illegal argument target.resources[0].id (empty)"; err.Error() != want {
		t.Errorf("текст отказа = %q, ожидался %q", err.Error(), want)
	}
}
