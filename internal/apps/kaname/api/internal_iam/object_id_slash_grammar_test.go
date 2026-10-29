// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// object_id_slash_grammar_test.go — разбор объекта `<type>:<id>`, чей
// идентификатор несёт `/` (PRO-Robotech/kaname#1004).
//
// Грамматика объекта (`validateRelationString`) требует ровно одно двоеточие и
// запрещает пробелы и `#`; о `/` она не говорит ничего. Разбор однозначен ровно
// тогда, когда идентификатор после первого двоеточия берётся ДОСЛОВНО: без
// разреза по `/`, без склейки пустых сегментов, без раскодирования
// экранированного разделителя. Здесь это мерится на входе регистрации; на всех
// частях сразу (зеркало, цепь, выдача, решение) — в
// `access_binding/slash_object_id_world_integration_test.go`.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

const slashRepoType = "registry_repository"

// TestObjectIDWithSlash_IsTakenVerbatim — законный идентификатор с `/` и каждая
// его граница проходят грамматику и разбираются в тот же идентификатор, что
// прислан; разные входы дают разные объекты.
func TestObjectIDWithSlash_IsTakenVerbatim(t *testing.T) {
	inputs := []struct{ name, id string }{
		{"законный", "reg00000000000000001/app"},
		{"законный вложенный", "reg00000000000000001/team/app"},
		{"лишний сегмент", "reg00000000000000001/app/extra"},
		{"пустой конечный сегмент", "reg00000000000000001/app/"},
		{"пустой двойной сегмент", "reg00000000000000001//app"},
		{"пустой начальный сегмент", "/reg00000000000000001/app"},
		{"только разделитель", "/"},
		{"экранированный разделитель %2F", "reg00000000000000001%2Fapp"},
		{"экранированный разделитель \\/", `reg00000000000000001\/app`},
	}
	seen := make(map[string]string, len(inputs))
	for _, c := range inputs {
		t.Run(c.name, func(t *testing.T) {
			ti, err := validateTuple(&iamv1.RegisterResourceRequest{
				SubjectId: "user:usr00000000000000001",
				Relation:  "owner",
				Object:    slashRepoType + ":" + c.id,
			})
			require.NoErrorf(t, err, "объект с идентификатором %q отвергнут грамматикой", c.id)
			typ, id := ti.splitObject()
			assert.Equal(t, slashRepoType, typ, "тип объекта")
			assert.Equal(t, c.id, id, "идентификатор объекта не дословно тот, что прислан")
			if prev, dup := seen[id]; dup {
				t.Errorf("входы %q и %q разобраны в один объект %q", prev, c.name, id)
			}
			seen[id] = c.name
		})
	}
	assert.Len(t, seen, len(inputs), "число разных объектов меньше числа входов")
}

// TestObjectIDWithSlash_GrammarStillRefuses — положительный контроль того, что
// пробы выше дошли до грамматики: те же идентификаторы с `/`, нарушающие её
// по другой оси (второе двоеточие, пробел, `#`, пустой идентификатор), — отказ
// кодом формата с именем поля.
func TestObjectIDWithSlash_GrammarStillRefuses(t *testing.T) {
	for _, v := range []string{
		slashRepoType + ":reg00000000000000001/app:latest",
		slashRepoType + ":reg00000000000000001/my app",
		slashRepoType + ":reg00000000000000001/app#member",
		slashRepoType + ":",
	} {
		t.Run(v, func(t *testing.T) {
			_, err := validateTuple(&iamv1.RegisterResourceRequest{
				SubjectId: "user:usr00000000000000001", Relation: "owner", Object: v,
			})
			require.Errorf(t, err, "объект %q принят", v)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Contains(t, status.Convert(err).Message(), "object", "отказ не называет поле")
		})
	}
}
