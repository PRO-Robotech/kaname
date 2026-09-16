// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// injMirrorRegistry — синтетический реестр с двумя сообщениями и словарём в
// заданном состоянии. Один факт на ось: `fieldDeprecated`, `valueDeprecated`,
// `dropField` (поле снято вовсе), `dropValue` (вид снят вовсе).
func injMirrorRegistry(t *testing.T, fieldDeprecated, valueDeprecated, dropField, dropValue bool) *protoregistry.Files {
	t.Helper()
	fieldOpts := &descriptorpb.FieldOptions{Deprecated: proto.Bool(fieldDeprecated)}
	valueOpts := &descriptorpb.EnumValueOptions{Deprecated: proto.Bool(valueDeprecated)}
	msg := func(name string) *descriptorpb.DescriptorProto {
		fields := []*descriptorpb.FieldDescriptorProto{{
			Name: proto.String("id"), Number: proto.Int32(1),
			Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
		}}
		if !dropField {
			fields = append(fields, &descriptorpb.FieldDescriptorProto{
				Name: proto.String(check.ProviderMirrorFieldName), Number: proto.Int32(3),
				Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(), Options: fieldOpts,
			})
		}
		return &descriptorpb.DescriptorProto{Name: proto.String(name), Field: fields}
	}
	values := []*descriptorpb.EnumValueDescriptorProto{
		{Name: proto.String("CREDENTIAL_KIND_UNSPECIFIED"), Number: proto.Int32(0)},
		{Name: proto.String("CREDENTIAL_KIND_KEYPAIR"), Number: proto.Int32(1)},
	}
	if !dropValue {
		values = append(values, &descriptorpb.EnumValueDescriptorProto{
			Name: proto.String(string(check.ProviderMirrorLegacyValue)), Number: proto.Int32(4), Options: valueOpts,
		})
	}
	fdp := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("kaname/cloud/iam/v1/inj.proto"),
		Package: proto.String("kaname.cloud.iam.v1"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			msg("ServiceAccountOAuthClient"), msg("UserOAuthClient"),
		},
		EnumType: []*descriptorpb.EnumDescriptorProto{{
			Name: proto.String("CredentialKind"), Value: values,
		}},
	}
	fd, err := protodesc.NewFile(fdp, nil)
	if err != nil {
		t.Fatalf("синтетический дескриптор обязан собираться: %v", err)
	}
	files := &protoregistry.Files{}
	if err := files.RegisterFile(fd); err != nil {
		t.Fatalf("регистрация синтетического дескриптора: %v", err)
	}
	return files
}

func kindsOf(f []check.ProviderMirrorFinding) map[string]int {
	out := map[string]int{}
	for _, x := range f {
		out[x.Kind]++
	}
	return out
}

func TestProviderMirrorRetirement_InjectionBothWays(t *testing.T) {
	t.Parallel()

	t.Run("контракт объявляет уходящее — молчит", func(t *testing.T) {
		t.Parallel()
		f, census := check.JudgeProviderMirrorContract(injMirrorRegistry(t, true, true, false, false))
		if len(f) != 0 {
			t.Fatalf("законный близнец обязан молчать: %+v", f)
		}
		if census.MessagesFound != 2 || census.FieldsFound != 2 || !census.EnumFound || !census.ValueFound {
			t.Fatalf("перепись не сошлась: %s", census)
		}
	})
	t.Run("поле не deprecated — находка на каждом носителе", func(t *testing.T) {
		t.Parallel()
		f, _ := check.JudgeProviderMirrorContract(injMirrorRegistry(t, false, true, false, false))
		if k := kindsOf(f); k["field-not-deprecated"] != 2 || len(f) != 2 {
			t.Fatalf("ожидались две находки field-not-deprecated, получено %v", k)
		}
	})
	t.Run("вид не deprecated — находка", func(t *testing.T) {
		t.Parallel()
		f, _ := check.JudgeProviderMirrorContract(injMirrorRegistry(t, true, false, false, false))
		if k := kindsOf(f); k["value-not-deprecated"] != 1 || len(f) != 1 {
			t.Fatalf("ожидалась одна находка value-not-deprecated, получено %v", k)
		}
	})
	t.Run("поле снято вовсе — ломающее изменение, находка", func(t *testing.T) {
		t.Parallel()
		f, census := check.JudgeProviderMirrorContract(injMirrorRegistry(t, true, true, true, false))
		if k := kindsOf(f); k["field-missing"] != 2 || len(f) != 2 {
			t.Fatalf("ожидались две находки field-missing, получено %v", k)
		}
		if census.FieldsFound != 0 {
			t.Fatalf("перепись обязана показать ноль полей: %s", census)
		}
	})
	t.Run("вид снят вовсе — находка", func(t *testing.T) {
		t.Parallel()
		f, _ := check.JudgeProviderMirrorContract(injMirrorRegistry(t, true, true, false, true))
		if k := kindsOf(f); k["value-missing"] != 1 || len(f) != 1 {
			t.Fatalf("ожидалась одна находка value-missing, получено %v", k)
		}
	})
	t.Run("пустой реестр — сообщения не найдены, перепись нулевая", func(t *testing.T) {
		t.Parallel()
		f, census := check.JudgeProviderMirrorContract(&protoregistry.Files{})
		if k := kindsOf(f); k["message-missing"] != 2 || k["enum-missing"] != 1 {
			t.Fatalf("пустой реестр обязан давать message-missing×2 и enum-missing: %v", k)
		}
		if census.MessagesFound != 0 {
			t.Fatalf("перепись пустого реестра: %s", census)
		}
	})

	terms := []string{"user_oauth_clients", "kaname_x_rows", "reserved"}
	t.Run("страница называет всё — молчит", func(t *testing.T) {
		t.Parallel()
		f, census := check.JudgeProviderMirrorPage(
			"# Решение\n\nОкно: `user_oauth_clients`. Ряд: `kaname_x_rows`. Затем `reserved 3`.\n", terms)
		if len(f) != 0 || census.TermsNamed != 3 {
			t.Fatalf("законная страница обязана молчать: %+v (%s)", f, census)
		}
	})
	t.Run("страница молчит о ряде — находка с именем термина", func(t *testing.T) {
		t.Parallel()
		f, census := check.JudgeProviderMirrorPage(
			"# Решение\n\nОкно: `user_oauth_clients`. Затем `reserved 3`.\n", terms)
		if len(f) != 1 || f[0].Kind != "page-silent" || f[0].Subject != "kaname_x_rows" {
			t.Fatalf("ожидалась находка page-silent о kaname_x_rows: %+v", f)
		}
		if census.TermsNamed != 2 {
			t.Fatalf("перепись: названо обязано быть 2, %s", census)
		}
	})
	t.Run("страницы нет — page-missing, а не «терминов ноль»", func(t *testing.T) {
		t.Parallel()
		f, _ := check.JudgeProviderMirrorPage("", terms)
		if len(f) != 1 || f[0].Kind != "page-missing" {
			t.Fatalf("пустая страница обязана давать page-missing: %+v", f)
		}
	})
}
