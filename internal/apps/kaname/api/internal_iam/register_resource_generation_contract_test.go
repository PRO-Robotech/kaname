// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// register_resource_generation_contract_test.go — контракт приёма поколения
// объекта (приёмка NTF-3, kacho#2918, сценарий NTF3-182; Р30 «Поколение и
// проекция», редакция 39; Д134 B2).
//
// Версия объекта в службе доступа — целое поколение. У регистрации и у снятия
// поле `google.protobuf.Timestamp source_version = 8` уходит в `reserved`
// номером И именем, на его месте — `int64 generation`. Проба читает дескриптор,
// а не исходник `.proto`: она судит то, что собрано и уходит на провод.
//
// Близнец по одному факту — запрет повторного использования: номер 8 и имя
// `source_version` не могут вернуться ни одним полем (`reserved` держит оба).
package internal_iam_test

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// withdrawnVersionField — номер и имя поля, которое поколение замещает.
const (
	withdrawnVersionNumber protoreflect.FieldNumber = 8
	withdrawnVersionName   protoreflect.Name        = "source_version"
	generationFieldName    protoreflect.Name        = "generation"
)

// TestRegisterResourceContract_NTF3_182_GenerationReplacesSourceVersion — у
// обоих сообщений поле `generation` типа `int64`, одиночное; номер 8 и имя
// `source_version` — в `reserved`; поля с именем `source_version` нет.
func TestRegisterResourceContract_NTF3_182_GenerationReplacesSourceVersion(t *testing.T) {
	for _, m := range []proto.Message{
		&iamv1.RegisterResourceRequest{},
		&iamv1.UnregisterResourceRequest{},
	} {
		md := m.ProtoReflect().Descriptor()
		t.Run(string(md.Name()), func(t *testing.T) {
			fd := md.Fields().ByName(generationFieldName)
			if fd == nil {
				t.Errorf("%s: поля %q нет — поколение объекта в контракт не заведено (Р30 «Поколение и проекция», NTF3-182)",
					md.FullName(), generationFieldName)
			} else {
				if fd.Kind() != protoreflect.Int64Kind {
					t.Errorf("%s.%s: тип %s, ожидается int64", md.FullName(), fd.Name(), fd.Kind())
				}
				if fd.Cardinality() == protoreflect.Repeated {
					t.Errorf("%s.%s: повторяемое, ожидается одиночное", md.FullName(), fd.Name())
				}
			}
			if old := md.Fields().ByName(withdrawnVersionName); old != nil {
				t.Errorf("%s: поле %q (номер %d) всё ещё в контракте — версия-время не снята",
					md.FullName(), withdrawnVersionName, old.Number())
			}
			if !md.ReservedRanges().Has(withdrawnVersionNumber) {
				t.Errorf("%s: номер %d не в reserved — снятое поле может вернуться под другим смыслом",
					md.FullName(), withdrawnVersionNumber)
			}
			if !md.ReservedNames().Has(withdrawnVersionName) {
				t.Errorf("%s: имя %q не в reserved", md.FullName(), withdrawnVersionName)
			}
		})
	}
}
