// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// created_by_contract_test.go — контракт не вправе объявлять обязательным поле,
// которое край подставляет сам либо отвергает присланным.
//
// `(required)` — расширение `kacho.cloud.validation`, и в рантайме его не
// читает НИКТО: во всём дереве у него ноль потребителей вне сгенерированных
// стабов (предикат — в сообщении пробы ниже). Именно поэтому опция опаснее
// отсутствующей: она не отказывает, но читается машинами — генератор клиента
// объявляет параметр обязательным, а сервис отвечает вызывающему, что слать
// его не надо. То есть контракт утверждал ОБРАТНОЕ действительному, и делал это
// машиночитаемо.
//
// Проба судит ОПИСАТЕЛЬ, а не текст `.proto`: опция встречается и в
// комментариях, и проверка по подстроке краснела бы на собственном объяснении.
//
// Положительный контроль обязателен и стоит рядом: поле, которое сервис
// ДЕЙСТВИТЕЛЬНО требует (`user_id` / `service_account_id`), обязано опцию
// нести. Без него отрицание зеленело бы на читателе, который опций не видит
// вовсе, — и проба утверждала бы «опции нет» про любое дерево.
package shared

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	cloudpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

// declaredRequired отвечает две вещи: несёт ли поле опцию и НАШЛОСЬ ли поле
// вовсе. Второе отдельно, потому что «поля нет» и «поле без опции» — разные
// состояния, и на первом утверждение об опции вакуумно.
func declaredRequired(md protoreflect.MessageDescriptor, field string) (declared bool, found bool) {
	fd := md.Fields().ByName(protoreflect.Name(field))
	if fd == nil {
		return false, false
	}
	opts, _ := fd.Options().(*descriptorpb.FieldOptions)
	if opts == nil {
		return false, true
	}
	v, _ := proto.GetExtension(opts, cloudpb.E_Required).(bool)
	return v, true
}

// TestIssueRequests_DoNotDeclareCreatedByRequired — поле, которого край не
// требует, не объявляется обязательным ни на одной полосе выдачи.
func TestIssueRequests_DoNotDeclareCreatedByRequired(t *testing.T) {
	lanes := []struct {
		name string
		md   protoreflect.MessageDescriptor
		// trulyRequired — поле, без которого запрос неисполним. Положительный
		// контроль читателя опций.
		trulyRequired string
	}{
		{
			name:          "IssueUserTokenRequest",
			md:            (&iamv1.IssueUserTokenRequest{}).ProtoReflect().Descriptor(),
			trulyRequired: "user_id",
		},
		{
			name:          "IssueSAKeyRequest",
			md:            (&iamv1.IssueSAKeyRequest{}).ProtoReflect().Descriptor(),
			trulyRequired: "service_account_id",
		},
	}
	if len(lanes) != 2 {
		t.Fatalf("полос под пробой %d — сверять между собой нечего", len(lanes))
	}

	scanned := 0
	for _, l := range lanes {
		scanned += l.md.Fields().Len()

		gotRequired, found := declaredRequired(l.md, "created_by_user_id")
		if !found {
			t.Fatalf("%s: поля created_by_user_id нет — утверждение об опции беспредметно", l.name)
		}
		if gotRequired {
			t.Errorf("%s.created_by_user_id объявлен (required) = true, "+
				"тогда как край подставляет ответственного сам, а присланное сверяет и "+
				"отвергает несовпавшее. Опцию не исполняет никто (потребителей вне стабов "+
				"ноль: git grep -c 'E_Required\\b' -- '*.go'), поэтому она не отказывает, "+
				"а только объявляет клиентам обратное действительному", l.name)
		}

		ctrl, found := declaredRequired(l.md, l.trulyRequired)
		if !found {
			t.Fatalf("%s: поля %s нет — положительный контроль беспредметен", l.name, l.trulyRequired)
		}
		if !ctrl {
			t.Errorf("%s.%s обязан нести (required) = true: без положительного контроля "+
				"отрицание выше зеленело бы на читателе, который опций не видит вовсе",
				l.name, l.trulyRequired)
		}
	}
	t.Logf("перепись: полос осмотрено %d, полей в них %d", len(lanes), scanned)
}
