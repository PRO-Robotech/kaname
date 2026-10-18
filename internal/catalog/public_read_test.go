// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog_test

// public_read_test.go — признак контейнера публичного чтения и связь «ребёнок →
// контейнер» в каталожном факте (kaname#856, Р9 приёмки
// anonymous-and-authenticated-are-subject-classes.md).
//
// Строки — литерал посева плюс модуль `probemod` (контейнер `boxes`, ребёнок
// `items`) и чужой модуль `othermod`, чей ресурс указывает на тот же контейнер.
// Отличие каждого близнеца от предмета — один факт строки.

import (
	"reflect"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/catalog"
)

func publicReadFacts(t *testing.T, declared bool) *catalog.Facts {
	t.Helper()
	live := seed.LiteralRows()
	live.Modules = append(live.Modules, "probemod", "othermod")
	live.Resources = append(live.Resources,
		catalog.ResourceRow{Module: "probemod", Resource: "boxes", ObjectType: "probemod_box",
			ParentTypes: []string{"project"}, PublicReadToChildren: declared},
		catalog.ResourceRow{Module: "probemod", Resource: "items", ObjectType: "probemod_item",
			ParentTypes: []string{"probemod_box"}},
		catalog.ResourceRow{Module: "othermod", Resource: "notes", ObjectType: "othermod_note",
			ParentTypes: []string{"probemod_box"}},
	)
	live.Verbs = append(live.Verbs,
		catalog.VerbRow{Module: "probemod", Resource: "boxes", Verb: "get", PerObject: true},
		catalog.VerbRow{Module: "probemod", Resource: "items", Verb: "get", PerObject: true},
		catalog.VerbRow{Module: "othermod", Resource: "notes", Verb: "get", PerObject: true},
	)
	f, err := catalog.NewFacts(catalog.Halves{Live: live})
	if err != nil {
		t.Fatalf("каталожный факт: %v", err)
	}
	return f
}

// TestPublicReadChildrenAreTheSameModuleChildrenOfADeclaredContainer — у
// объявленного контейнера дети — ресурсы ТОГО ЖЕ модуля, чей указатель называет
// его тип; ребёнок чужого модуля наследования не получает. Близнец — тот же
// каталог без признака: детей публичного чтения нет.
func TestPublicReadChildrenAreTheSameModuleChildrenOfADeclaredContainer(t *testing.T) {
	if got := publicReadFacts(t, false).PublicReadChildren("probemod.boxes"); got != nil {
		t.Fatalf("близнец: необъявленный тип не передаёт чтение детям, получено %v", got)
	}
	got := publicReadFacts(t, true).PublicReadChildren("probemod.boxes")
	if want := []string{"probemod.items"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("дети публичного чтения объявленного контейнера %v, ждали %v (othermod.notes — чужой модуль)", got, want)
	}
	if got := publicReadFacts(t, true).PublicReadChildren("probemod.items"); got != nil {
		t.Fatalf("тип без признака не контейнер, получено %v", got)
	}
}

// TestResourceRowSameFormSeesEveryWrittenValue — «строка изменилась» видит каждую
// величину, которую пишет применитель: имя типа, указатели, признак контейнера.
func TestResourceRowSameFormSeesEveryWrittenValue(t *testing.T) {
	base := catalog.ResourceRow{Module: "m", Resource: "r", ObjectType: "m_r", ParentTypes: []string{"project"}}
	if !base.SameForm(catalog.ResourceRow{Module: "m", Resource: "r", ObjectType: "m_r", ParentTypes: []string{"project"}}) {
		t.Fatal("близнец: та же строка обязана быть той же формы")
	}
	for name, other := range map[string]catalog.ResourceRow{
		"тип":       {ObjectType: "m_x", ParentTypes: []string{"project"}},
		"указатель": {ObjectType: "m_r", ParentTypes: []string{"account"}},
		"указатели": {ObjectType: "m_r"},
		"признак":   {ObjectType: "m_r", ParentTypes: []string{"project"}, PublicReadToChildren: true},
	} {
		if base.SameForm(other) {
			t.Errorf("смена величины «%s» не видна SameForm", name)
		}
	}
}
