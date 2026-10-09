// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// register_resource_event_contract_test.go — контракт события объекта и
// публикации (приёмка NTF-3, kacho#2918, сценарии NTF3-182, NTF3-185, NTF3-186;
// Р30 «Единица поколения — событие», «Публикация для анонимного чтения»,
// редакции 40–42).
//
// # Что судится
//
// Поколение принадлежит СОБЫТИЮ объекта, а не кортежу: регистрация несёт набор
// кортежей события `repeated RegisteredTuple tuples`, снятие адресуется объектом.
// Поля кортежа у регистрации (`subject_id = 1`, `relation = 2`) и поля
// регистрации у снятия (`1`, `2`, `5`, `6`, `7`) уходят в `reserved` номером И
// именем; поле `source_version = 8` снимается у обоих сообщений полностью — версию
// публикации несёт отдельный метод `SetPublicReadPublication`
// (`publication_version`), признак воплощения — `object_generation`.
//
// Проба читает собранный дескриптор, а не исходник `.proto`: она судит то, что
// уходит на провод, и собирается на дереве, где новых имён ещё нет, — там она
// падает текстом «поля нет», а не ошибкой компиляции.
package internal_iam_test

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// contractField — ожидаемое поле сообщения: номер, вид, повторяемость и (для
// сообщения) полное имя типа.
type contractField struct {
	name     protoreflect.Name
	number   protoreflect.FieldNumber
	kind     protoreflect.Kind
	repeated bool
	message  protoreflect.FullName
}

// requireMessageShape — у сообщения ровно эти поля (имя, номер, вид), и ни одного
// сверх них: поле, принятое и не прочитанное, запрещено (`api-outcome-remove`).
func requireMessageShape(t *testing.T, md protoreflect.MessageDescriptor, want []contractField) {
	t.Helper()
	seen := map[protoreflect.Name]bool{}
	for _, w := range want {
		seen[w.name] = true
		fd := md.Fields().ByName(w.name)
		if fd == nil {
			t.Errorf("%s: поля %q нет (ожидается номер %d)", md.FullName(), w.name, w.number)
			continue
		}
		if fd.Number() != w.number {
			t.Errorf("%s.%s: номер %d, ожидается %d", md.FullName(), w.name, fd.Number(), w.number)
		}
		if fd.Kind() != w.kind {
			t.Errorf("%s.%s: вид %s, ожидается %s", md.FullName(), w.name, fd.Kind(), w.kind)
		}
		if (fd.Cardinality() == protoreflect.Repeated) != w.repeated {
			t.Errorf("%s.%s: повторяемость %v, ожидается %v", md.FullName(), w.name, fd.Cardinality() == protoreflect.Repeated, w.repeated)
		}
		if w.message != "" && (fd.Message() == nil || fd.Message().FullName() != w.message) {
			t.Errorf("%s.%s: тип сообщения %v, ожидается %s", md.FullName(), w.name, fd.Message(), w.message)
		}
	}
	for i := 0; i < md.Fields().Len(); i++ {
		if fd := md.Fields().Get(i); !seen[fd.Name()] {
			t.Errorf("%s: поле %q (номер %d) сверх контракта", md.FullName(), fd.Name(), fd.Number())
		}
	}
}

// requireReserved — номера и имена в `reserved`: снятое поле не возвращается ни под
// прежним номером, ни под прежним именем.
func requireReserved(t *testing.T, md protoreflect.MessageDescriptor, numbers []protoreflect.FieldNumber, names []protoreflect.Name) {
	t.Helper()
	for _, n := range numbers {
		if !md.ReservedRanges().Has(n) {
			t.Errorf("%s: номер %d не в reserved", md.FullName(), n)
		}
	}
	for _, n := range names {
		if !md.ReservedNames().Has(n) {
			t.Errorf("%s: имя %q не в reserved", md.FullName(), n)
		}
	}
}

// TestRegisterResourceContract_NTF3_185_RegistrationCarriesTheEventSet —
// регистрация несёт набор кортежей события и поколение; поля одиночного кортежа и
// версия-время сняты в `reserved` номером и именем.
func TestRegisterResourceContract_NTF3_185_RegistrationCarriesTheEventSet(t *testing.T) {
	md := (&iamv1.RegisterResourceRequest{}).ProtoReflect().Descriptor()
	requireMessageShape(t, md, []contractField{
		{name: "object", number: 3, kind: protoreflect.StringKind},
		{name: "trace_id", number: 4, kind: protoreflect.StringKind},
		{name: "labels", number: 5, kind: protoreflect.MessageKind, repeated: true},
		{name: "parent_project_id", number: 6, kind: protoreflect.StringKind},
		{name: "parent_account_id", number: 7, kind: protoreflect.StringKind},
		{name: "parent_chain", number: 9, kind: protoreflect.StringKind, repeated: true},
		{name: "generation", number: 10, kind: protoreflect.Int64Kind},
		{name: "tuples", number: 11, kind: protoreflect.MessageKind, repeated: true,
			message: "kaname.cloud.iam.v1.RegisteredTuple"},
	})
	requireReserved(t, md,
		[]protoreflect.FieldNumber{1, 2, 8},
		[]protoreflect.Name{"subject_id", "relation", "source_version"})

	// Кортеж набора — пара (субъект, отношение) на объекте запроса.
	tuple, err := protoregistry.GlobalFiles.FindDescriptorByName("kaname.cloud.iam.v1.RegisteredTuple")
	if err != nil {
		t.Fatalf("сообщения kaname.cloud.iam.v1.RegisteredTuple нет — набор кортежей события выразить нечем: %v", err)
	}
	requireMessageShape(t, tuple.(protoreflect.MessageDescriptor), []contractField{
		{name: "subject_id", number: 1, kind: protoreflect.StringKind},
		{name: "relation", number: 2, kind: protoreflect.StringKind},
	})
}

// TestRegisterResourceContract_NTF3_185_WithdrawalIsAddressedByObject — снятие
// несёт объект и поколение; поля кортежа и регистрации сняты в `reserved`.
func TestRegisterResourceContract_NTF3_185_WithdrawalIsAddressedByObject(t *testing.T) {
	md := (&iamv1.UnregisterResourceRequest{}).ProtoReflect().Descriptor()
	requireMessageShape(t, md, []contractField{
		{name: "object", number: 3, kind: protoreflect.StringKind},
		{name: "trace_id", number: 4, kind: protoreflect.StringKind},
		{name: "generation", number: 10, kind: protoreflect.Int64Kind},
	})
	requireReserved(t, md,
		[]protoreflect.FieldNumber{1, 2, 5, 6, 7, 8},
		[]protoreflect.Name{"subject_id", "relation", "labels", "parent_project_id", "parent_account_id", "source_version"})
}

// TestRegisterResourceContract_NTF3_186_PublicationHasItsOwnMethod — публикация
// для анонимного чтения — свой метод внутренней службы с версией публикации и
// признаком воплощения; ответ пустой.
func TestRegisterResourceContract_NTF3_186_PublicationHasItsOwnMethod(t *testing.T) {
	svc := iamv1.File_kaname_cloud_iam_v1_internal_iam_service_proto.Services().ByName("InternalIAMService")
	if svc == nil {
		t.Fatal("службы InternalIAMService нет в дескрипторе файла")
	}
	m := svc.Methods().ByName("SetPublicReadPublication")
	if m == nil {
		t.Fatal("метода InternalIAMService/SetPublicReadPublication нет — порядок публикации производить нечем " +
			"(Р30 «Публикация для анонимного чтения», NTF3-186)")
	}
	if got := m.Input().FullName(); got != "kaname.cloud.iam.v1.SetPublicReadPublicationRequest" {
		t.Errorf("вход метода %s, ожидается SetPublicReadPublicationRequest", got)
	}
	if got := m.Output().FullName(); got != "kaname.cloud.iam.v1.SetPublicReadPublicationResponse" {
		t.Errorf("выход метода %s, ожидается SetPublicReadPublicationResponse", got)
	}
	if m.IsStreamingClient() || m.IsStreamingServer() {
		t.Error("метод публикации потоковый, ожидается унарный")
	}
	requireMessageShape(t, m.Input(), []contractField{
		{name: "object", number: 1, kind: protoreflect.StringKind},
		{name: "published", number: 2, kind: protoreflect.BoolKind},
		{name: "publication_version", number: 3, kind: protoreflect.MessageKind,
			message: "google.protobuf.Timestamp"},
		{name: "trace_id", number: 4, kind: protoreflect.StringKind},
		{name: "object_generation", number: 5, kind: protoreflect.Int64Kind},
	})
	requireMessageShape(t, m.Output(), nil)
}
