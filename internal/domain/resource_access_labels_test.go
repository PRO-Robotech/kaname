// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func accessLabelResourceFixtures() []any {
	return []any{
		Account{Name: "account", OwnerUserID: "usr-owner"},
		Project{Name: "project", AccountID: "acc-owner"},
		User{Email: "user@example.com"},
		ServiceAccount{Name: "service-account", AccountID: "acc-owner"},
		Group{Name: "group", AccountID: "acc-owner"},
		Role{Name: "reader", AccountID: "acc-owner"},
		AccessBinding{SubjectType: SubjectTypeUser, SubjectID: "usr-member", RoleID: "rol-reader", ResourceType: "account", ResourceID: "acc-owner"},
	}
}

func validateAccessLabelResource(value any) error {
	if role, ok := value.(Role); ok {
		return role.Validate(fixtureModules())
	}
	return value.(interface{ Validate() error }).Validate()
}

func withResourceLabels(value any, name string, labels Labels) any {
	copy := reflect.New(reflect.TypeOf(value)).Elem()
	copy.Set(reflect.ValueOf(value))
	copy.FieldByName(name).Set(reflect.ValueOf(labels))
	return copy.Interface()
}

// Обе карты судятся независимо: новая валидная карта не скрывает старую
// ошибку, а обычные метки не заменяют проверку защищённого поля.
func TestResourceAccessLabelsValidateIndependently(t *testing.T) {
	tooMany := Labels{}
	for i := 0; i < 65; i++ {
		tooMany[LabelKey("key"+strings.Repeat("a", i%60)+string(rune('a'+i/60)))] = "value"
	}
	invalid := []Labels{{"": "value"}, {"env": LabelVal(strings.Repeat("v", 64))}, tooMany}
	for _, base := range accessLabelResourceFixtures() {
		t.Run(reflect.TypeOf(base).Name(), func(t *testing.T) {
			if err := validateAccessLabelResource(base); err != nil {
				t.Fatalf("invalid base fixture: %v", err)
			}
			for _, labels := range []Labels{nil, {}, {"env": "prod", "empty": ""}} {
				candidate := withResourceLabels(base, "AccessLabels", labels)
				if err := validateAccessLabelResource(candidate); err != nil {
					t.Fatalf("valid access labels %v: %v", labels, err)
				}
			}
			for _, labels := range invalid {
				candidate := withResourceLabels(base, "Labels", Labels{"description": "ordinary"})
				candidate = withResourceLabels(candidate, "AccessLabels", labels)
				if err := validateAccessLabelResource(candidate); err == nil {
					t.Fatalf("invalid access labels accepted: %v", labels)
				}
				candidate = withResourceLabels(base, "AccessLabels", Labels{"env": "prod"})
				candidate = withResourceLabels(candidate, "Labels", labels)
				if err := validateAccessLabelResource(candidate); err == nil {
					t.Fatalf("invalid ordinary labels hidden: %v", labels)
				}
			}
		})
	}
}

// Старую JSON-форму задаёт структура без нового поля с прежними порядком и
// типами остальных полей. nil и пустая карта обязаны дать ровно эти байты.
func TestResourceAccessLabelsAbsentPreservesDirectJSON(t *testing.T) {
	fixtures := append(accessLabelResourceFixtures(), MirrorObject{ObjectType: "iam.account", ObjectID: "acc-owner", Labels: map[string]string{"ordinary": "value"}})
	for _, fixture := range fixtures {
		// Role передаётся через отдельную проекцию. Внутренний TypeVerbs
		// имеет функциональный тип и не сериализуется напрямую в JSON.
		if _, isRole := fixture.(Role); isRole {
			continue
		}
		t.Run(reflect.TypeOf(fixture).Name(), func(t *testing.T) {
			source := reflect.ValueOf(fixture)
			typ := source.Type()
			var fields []reflect.StructField
			var values []reflect.Value
			for i := 0; i < typ.NumField(); i++ {
				if typ.Field(i).Name == "AccessLabels" {
					continue
				}
				fields = append(fields, typ.Field(i))
				values = append(values, source.Field(i))
			}
			legacy := reflect.New(reflect.StructOf(fields)).Elem()
			for i, value := range values {
				legacy.Field(i).Set(value)
			}
			want, err := json.Marshal(legacy.Interface())
			if err != nil {
				t.Fatal(err)
			}
			copy := reflect.New(typ).Elem()
			copy.Set(source)
			field := copy.FieldByName("AccessLabels")
			for _, empty := range []bool{false, true} {
				if empty {
					field.Set(reflect.MakeMap(field.Type()))
				}
				got, err := json.Marshal(copy.Interface())
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("absent field changed JSON: %s != %s", got, want)
				}
			}
			field.SetMapIndex(reflect.ValueOf("env").Convert(field.Type().Key()), reflect.ValueOf("prod").Convert(field.Type().Elem()))
			got, err := json.Marshal(copy.Interface())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(got, []byte(`"AccessLabels":{"env":"prod"}`)) {
				t.Fatalf("present field lost: %s", got)
			}
		})
	}
}

func TestMirrorMatchesAccessLabelsFailsClosed(t *testing.T) {
	object := MirrorObject{ParentAccountIDs: []string{"acc-owner"}, Labels: map[string]string{"ordinary": "value", "env": "wrong"}, AccessLabels: map[string]string{"env": "prod", "team": "ops", "empty": ""}}
	cases := []struct {
		name     string
		selector map[string]string
		want     bool
	}{
		{"nil", nil, false}, {"empty", map[string]string{}, false},
		{"exact", map[string]string{"env": "prod"}, true},
		{"and", map[string]string{"env": "prod", "team": "ops"}, true},
		{"wrong", map[string]string{"env": "prod", "team": "other"}, false},
		{"missing", map[string]string{"missing": ""}, false},
		{"explicit empty", map[string]string{"empty": ""}, true},
		{"ordinary only", map[string]string{"ordinary": "value"}, false},
		{"ordinary mismatch", map[string]string{"env": "wrong"}, false},
		{"invalid key", map[string]string{"": ""}, false},
		{"invalid value", map[string]string{"env": strings.Repeat("x", 64)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := object.MatchesAccessLabels(tc.selector); got != tc.want {
				t.Fatalf("match = %v, want %v", got, tc.want)
			}
		})
	}
	for _, labels := range []map[string]string{nil, {}} {
		copy := object
		copy.AccessLabels = labels
		if copy.MatchesAccessLabels(map[string]string{"env": "prod"}) {
			t.Fatal("unknown/empty facts matched")
		}
		if copy.IsContainedIn(ScopeAnchor{Type: "account", ID: "acc-owner"}) != object.IsContainedIn(ScopeAnchor{Type: "account", ID: "acc-owner"}) {
			t.Fatal("access labels changed scope")
		}
	}
	// Даже совпадающий набор сверх лимита selector не становится действующим.
	tooMany := map[string]string{}
	for i := 0; i < 17; i++ {
		tooMany[strings.Repeat("a", i+1)] = "v"
	}
	if (MirrorObject{AccessLabels: tooMany}).MatchesAccessLabels(tooMany) {
		t.Fatal("oversized selector matched")
	}
	// Прежняя семантика обычных меток не меняется вместе с новым matcher.
	if !object.MatchesLabels(nil) || !object.MatchesLabels(map[string]string{"ordinary": "value"}) {
		t.Fatal("legacy label matcher changed")
	}
}
