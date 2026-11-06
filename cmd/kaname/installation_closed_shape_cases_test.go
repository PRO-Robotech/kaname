// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// Это входы полного нативного обязательства RID12. Предпосылка парсера
// доказывает лишь пригодность близнецов и координат; она не доказывает
// код выхода/готовность запуска, отсутствие записей поставки, успешный посев или идемпотентность.
type rid12InputCase struct {
	Name        string
	Field       string
	Changed     []any
	Invalid     []byte
	Twin        []byte
	FieldCensus bool
}

func rid12Document(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &doc))
	require.NotNil(t, doc)
	return doc
}

func rid12Encode(t *testing.T, doc map[string]any) []byte {
	t.Helper()
	raw, err := yaml.Marshal(doc)
	require.NoError(t, err)
	return raw
}

// Обе сериализации имеют одинаковые порядок/форматирование. Отличается только выбранный
// узел: удаление этого узла даёт побайтно одинаковые канонические документы.
func rid12ChangedDocument(t *testing.T, raw []byte, path []any, value any, remove bool) []byte {
	t.Helper()
	doc := rid12Document(t, raw)
	var at any = doc
	for _, step := range path[:len(path)-1] {
		switch key := step.(type) {
		case string:
			m, ok := at.(map[string]any)
			require.True(t, ok)
			var found bool
			at, found = m[key]
			require.True(t, found)
		case int:
			xs, ok := at.([]any)
			require.True(t, ok)
			require.Greater(t, len(xs), key)
			at = xs[key]
		default:
			t.Fatal("unsupported fixture path")
		}
	}
	m, ok := at.(map[string]any)
	require.True(t, ok)
	key, ok := path[len(path)-1].(string)
	require.True(t, ok)
	if remove {
		delete(m, key)
	} else {
		m[key] = value
	}
	return rid12Encode(t, doc)
}

func rid12InputCases(t *testing.T) []rid12InputCase {
	t.Helper()
	ordinary := rid12Encode(t, rid12Document(t, installruntime.NewRIDDeliveryFixture().First))
	boundary, err := installruntime.BoundaryDelivery(16, 16)
	require.NoError(t, err)
	boundary = rid12Encode(t, rid12Document(t, boundary))
	var cases []rid12InputCase
	add := func(name, field string, good []byte, path []any, bad any) {
		cases = append(cases, rid12InputCase{Name: name, Field: field, Changed: path,
			Invalid: rid12ChangedDocument(t, good, path, bad, false), Twin: good})
	}
	axis := func(name string) []any { return []any{"seed", "grantDelegations", 0, name} }
	add("unknown-field", "seed.grantDelegations[0].mystery", ordinary, axis("mystery"), "rid12-unknown-field")
	for _, tc := range []struct{ name, value string }{
		{"roleIds", "ridfirst.reader"},
		{"targetTypes", "ridfirst.objects"},
		{"subjectTypes", "SUBJECT_TYPE_SERVICE_ACCOUNT"},
	} {
		add("empty-"+tc.name, "seed.grantDelegations[0]."+tc.name, ordinary, axis(tc.name), []string{})
		add("duplicate-"+tc.name, "seed.grantDelegations[0]."+tc.name, ordinary, axis(tc.name), []string{tc.value, tc.value})
	}
	roles := make([]string, 17)
	types := make([]string, 17)
	for i := range roles {
		roles[i] = fmt.Sprintf("ridbounds.reader%02d", i)
		types[i] = fmt.Sprintf("ridbounds.objects%02d", i)
	}
	add("roles17", "seed.grantDelegations[0].roleIds", boundary, axis("roleIds"), roles)
	add("types17", "seed.grantDelegations[0].targetTypes", boundary, axis("targetTypes"), types)
	// Разрешены четыре значения. Пятое намеренно повторяет USER;
	// мощность множества — первый заявленный отказ, без вымышленного допустимого перечисления.
	add("subjects5", "seed.grantDelegations[0].subjectTypes", boundary, axis("subjectTypes"), []string{
		"SUBJECT_TYPE_USER", "SUBJECT_TYPE_SERVICE_ACCOUNT", "SUBJECT_TYPE_GROUP", "SUBJECT_TYPE_SYSTEM_CLASS", "SUBJECT_TYPE_USER",
	})
	add("subject-unspecified", "seed.grantDelegations[0].subjectTypes", ordinary, axis("subjectTypes"), []string{"SUBJECT_TYPE_UNSPECIFIED"})
	add("subject-unknown", "seed.grantDelegations[0].subjectTypes", ordinary, axis("subjectTypes"), []string{"SUBJECT_TYPE_RID12_UNKNOWN"})
	add("iam-role", "seed.grantDelegations[0].roleIds", ordinary, axis("roleIds"), []string{"iam.admin"})
	add("iam-type", "seed.grantDelegations[0].targetTypes", ordinary, axis("targetTypes"), []string{"iam.accounts"})
	// Изменение только модуля меняет ровно module, сохраняя каждый другой канонический байт.
	// Штатный парсер сначала отклоняет сохранённый префикс собственной роли в roles[0].id;
	// это отдельно от координат отказа роли/типа iam в GD.
	add("iam-module", "roles[0].id", ordinary, []any{"module"}, "iam")
	cases[len(cases)-1].FieldCensus = false
	return cases
}

func rid12WithoutField(t *testing.T, raw []byte, path []any) []byte {
	t.Helper()
	return rid12ChangedDocument(t, raw, path, nil, true)
}

// TestRID12InputFixturePremise намеренно отделён от держателя RID12.
// Он может выполняться до любой аренды PostgreSQL. Его успех не подключает нативный
// обратный вызов и не удовлетворяет предикат поставки/исполнения.
func TestRID12InputFixturePremise(t *testing.T) {
	cases := rid12InputCases(t)
	require.Len(t, cases, 15, "accepted RID12 negative input inventory")
	seen := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			require.False(t, seen[tc.Name])
			seen[tc.Name] = true
			require.NotEqual(t, string(tc.Invalid), string(tc.Twin))
			require.Equal(t, string(rid12WithoutField(t, tc.Invalid, tc.Changed)), string(rid12WithoutField(t, tc.Twin, tc.Changed)),
				"negative and lawful twin must differ only at the declared node")
			valid, err := manifest.Load(tc.Twin)
			require.NoError(t, err, "lawful input twin must parse before a native world is allocated")
			require.NotNil(t, valid)
			invalid, err := manifest.Load(tc.Invalid)
			require.Error(t, err)
			require.Nil(t, invalid)
			var field interface{ FieldPath() string }
			require.True(t, errors.As(err, &field), "normal parser must retain a structured field coordinate")
			if tc.FieldCensus {
				// Наблюдение переписи не является утверждённым ожидаемым полем. Основной агент должен
				// разрешить этот случай до признания нативного RID12 готовым.
				t.Logf("SOURCE_CENSUS: module-only first coordinate=%s", field.FieldPath())
			} else {
				require.Equal(t, tc.Field, field.FieldPath())
			}
			if tc.Name == "roles17" || tc.Name == "types17" {
				bad := rid12Document(t, tc.Invalid)
				good := rid12Document(t, tc.Twin)
				require.Len(t, bad["roles"], 17)
				require.Len(t, bad["resources"], 17)
				require.Equal(t, good["roles"], bad["roles"])
				require.Equal(t, good["resources"], bad["resources"])
			}
		})
	}
	t.Run("absent-and-empty", func(t *testing.T) {
		base := installruntime.NewRIDDeliveryFixture().First
		path := []any{"seed", "grantDelegations"}
		for _, tc := range []struct {
			name   string
			remove bool
		}{{"absent", true}, {"empty", false}} {
			t.Run(tc.name, func(t *testing.T) {
				raw := rid12ChangedDocument(t, base, path, []any{}, tc.remove)
				got, err := manifest.Load(raw)
				require.NoError(t, err)
				require.NotNil(t, got.Seed)
				require.Empty(t, got.Seed.GrantDelegations)
				require.Len(t, got.Seed.ServiceAccounts, 1)
				require.Len(t, got.Seed.Groups, 1)
				require.Len(t, got.Seed.AccessBindings, 1)
				require.Len(t, got.Seed.Joins, 1)
			})
		}
	})
	t.Run("boundary17-declared16-selected4-subjects", func(t *testing.T) {
		raw, err := installruntime.BoundaryDelivery(16, 16)
		require.NoError(t, err)
		m, err := manifest.Load(raw)
		require.NoError(t, err)
		require.Len(t, m.Roles, 17)
		require.Len(t, m.Resources, 17)
		require.Len(t, m.Seed.GrantDelegations, 1)
		gd := m.Seed.GrantDelegations[0]
		require.Len(t, gd.RoleIDs, 16)
		require.Len(t, gd.TargetTypes, 16)
		require.Len(t, gd.SubjectTypes, 4)
	})
}
