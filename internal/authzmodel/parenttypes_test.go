// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmodel_test

// parenttypes_test.go — указатели типа на предков читаются у разобранной модели
// (kaname#951). Вход — вшитый канон: ответ о нём и есть то, чем судья вложенных
// правил судит необъявленные манифестом типы.

import (
	"slices"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
)

func TestParentTypes_CanonNamesThePointerTargetsOfAType(t *testing.T) {
	p, err := authzmodel.New(authzmodel.DSL)
	if err != nil {
		t.Fatalf("канон не разобран: %v", err)
	}
	cases := []struct {
		objectType string
		want       []string
	}{
		{"registry_repository", []string{"registry_registry"}},
		{"registry_registry", []string{"project"}},
	}
	for _, c := range cases {
		got, ok := p.ParentTypes(c.objectType)
		if !ok {
			t.Fatalf("%s: тип канона назван необъявленным", c.objectType)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: предки %v, ждали %v", c.objectType, got, c.want)
		}
	}
}

// Близнец «типа нет»: ok=false, а не пустой перечень — «типа нет» и «тип есть,
// предков нет» дают судье разные отказы.
func TestParentTypes_UndeclaredTypeIsNotAnEmptyList(t *testing.T) {
	p, err := authzmodel.New(authzmodel.DSL)
	if err != nil {
		t.Fatalf("канон не разобран: %v", err)
	}
	if got, ok := p.ParentTypes("registry_image"); ok {
		t.Fatalf("необъявленный тип назван объявленным, предки %v", got)
	}
	got, ok := p.ParentTypes("system_class")
	if !ok {
		t.Fatalf("тип system_class канона назван необъявленным")
	}
	if len(got) != 0 {
		t.Fatalf("у system_class канона нет указателей, получено %v", got)
	}
}
