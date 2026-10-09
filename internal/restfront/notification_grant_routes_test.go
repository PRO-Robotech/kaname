// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package restfront

// notification_grant_routes_test.go — маршруты внутреннего края у рычага
// оператора над выдачей права на письма (решение владельца 2026-10-08, п. 1:
// отзыв и восстановление выдачи зовёт администратор кластера через внутренний
// край).
//
// Утверждается ПО МЕТОДУ, а не по службе: у `Revoke` и `Restore` ровно одна
// привязка каждая — под сегментом `/internal/`, с пространством в пути; у
// `ResolveSend` привязки нет вовсе. Его зовёт служба notify прямым gRPC по
// сертификату, право решает обработчик (освобождение внутреннего слушателя), и
// REST-двери у этого вопроса быть не должно — она дала бы краю путь к
// освобождённому методу.

import (
	"testing"

	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

func TestNotificationGrantLeversCarryInternalEdgeRoutes(t *testing.T) {
	svc := iamv1.File_kaname_cloud_iam_v1_internal_notification_grant_service_proto.
		Services().ByName("InternalNotificationGrantService")
	if svc == nil {
		t.Fatal("служба InternalNotificationGrantService в дескрипторе не найдена — сверять не с чем")
	}
	want := map[protoreflect.Name]route{
		"Revoke":  {"POST", "/iam/v1/internal/notificationGrants/{namespace}:revoke"},
		"Restore": {"POST", "/iam/v1/internal/notificationGrants/{namespace}:restore"},
	}
	inspected := 0
	for i := 0; i < svc.Methods().Len(); i++ {
		m := svc.Methods().Get(i)
		inspected++
		rule, _ := proto.GetExtension(m.Options(), annotations.E_Http).(*annotations.HttpRule)
		expected, routed := want[m.Name()]
		if !routed {
			if rule != nil {
				t.Errorf("%s: привязка %v — у метода, который зовёт служба по сертификату, "+
					"REST-двери быть не должно", m.FullName(), rule)
			}
			continue
		}
		if rule == nil {
			t.Errorf("%s: привязки нет — у края нет маршрута, человек до рычага не доходит", m.FullName())
			continue
		}
		got, ok := routeOf(rule)
		switch {
		case !ok:
			t.Errorf("%s: привязка без глагола: %v", m.FullName(), rule)
		case got != expected:
			t.Errorf("%s: привязка %s %s, ожидалась %s %s", m.FullName(), got.method, got.path,
				expected.method, expected.path)
		}
		if len(rule.GetAdditionalBindings()) != 0 {
			t.Errorf("%s: дополнительных привязок %d, ожидался ноль", m.FullName(), len(rule.GetAdditionalBindings()))
		}
		if rule.GetBody() != "*" {
			t.Errorf("%s: тело привязки %q, ожидалось \"*\" (шаблон приходит телом)", m.FullName(), rule.GetBody())
		}
	}
	t.Logf("осмотрено методов службы %d, из них с маршрутом края %d", inspected, len(want))
	if inspected != 3 {
		t.Fatalf("методов службы %d, ожидалось 3 (ResolveSend, Revoke, Restore) — "+
			"перепись разошлась с предметом пробы", inspected)
	}
}
