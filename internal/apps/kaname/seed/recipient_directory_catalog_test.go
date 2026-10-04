// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed_test

// recipient_directory_catalog_test.go — контракт и каталог прав справочника
// адресов (приёмка NTF-3, kacho#2918: Р7, Р28; NTF3-27, NTF3-30, NTF3-151;
// замысел З27, CX3B-16). Полоса X4D: `Resolve` и `ListProjectAudience`
// (`ListExpiringCredentials` вне полосы по решению Д96).
//
// Что утверждается, и почему каждое — отдельной осью:
//
//   - служба `kaname.cloud.iam.v1.InternalNotificationRecipientService` есть в
//     реестре дескрипторов образа с обоими методами полосы;
//   - у методов НЕТ HTTP-привязки (Р7, NTF3-30: «методы справочника объявлены
//     без HTTP-привязки»): маршрута края у них не бывает by construction;
//   - каждый метод — в каталоге прав службы доступа с `required_relation
//     reader` на объекте типа `notification_recipient_directory` (Р28: иначе
//     отказ старта звена, NTF-1 Р2 п.1).
//
// Положительный контроль каждой оси — `InternalNotificationGrantService/
// ResolveSend` той же формы: найден в реестре, без HTTP, есть в каталоге. Без
// него «не найдено» читалось бы и у реестра, который не загружен вовсе.

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	authzv1 "github.com/PRO-Robotech/corelib/api/corelib/authz/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	_ "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1" // регистрирует дескрипторы контракта
)

const (
	rdService      = "kaname.cloud.iam.v1.InternalNotificationRecipientService"
	rdControlSvc   = "kaname.cloud.iam.v1.InternalNotificationGrantService"
	rdControlFQN   = rdControlSvc + "/ResolveSend"
	rdDirectoryTyp = "notification_recipient_directory"
)

// rdMethods — методы полосы X4D.
var rdMethods = []string{"Resolve", "ListProjectAudience"}

func rdServiceDescriptor(t *testing.T, name string) (protoreflect.ServiceDescriptor, bool) {
	t.Helper()
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(name))
	if err != nil {
		return nil, false
	}
	sd, ok := d.(protoreflect.ServiceDescriptor)
	return sd, ok
}

func rdHasHTTP(m protoreflect.MethodDescriptor) bool {
	rule, _ := proto.GetExtension(m.Options(), annotations.E_Http).(*annotations.HttpRule)
	return rule != nil && rule.GetPattern() != nil
}

// TestNTF330_RecipientDirectoryContractHasNoHTTPBinding — служба и её методы
// объявлены контрактом, без HTTP-привязки.
func TestNTF330_RecipientDirectoryContractHasNoHTTPBinding(t *testing.T) {
	ctl, ok := rdServiceDescriptor(t, rdControlSvc)
	if !ok {
		t.Fatalf("контроль: %s не найдена в реестре дескрипторов — реестр не загружен, вопрос пробы сломан", rdControlSvc)
	}
	if m := ctl.Methods().ByName("ResolveSend"); m == nil || rdHasHTTP(m) {
		t.Fatalf("контроль: %s без HTTP-привязки не найден — различение HTTP-привязки сломано", rdControlFQN)
	}

	sd, ok := rdServiceDescriptor(t, rdService)
	if !ok {
		t.Fatalf("служба %s не объявлена контрактом (Р7): дескриптора в реестре образа нет", rdService)
	}
	for _, name := range rdMethods {
		m := sd.Methods().ByName(protoreflect.Name(name))
		if m == nil {
			t.Fatalf("метод %s/%s не объявлен контрактом", rdService, name)
		}
		if rdHasHTTP(m) {
			t.Fatalf("метод %s/%s несёт HTTP-привязку — справочник только внутренний (Р7, NTF3-30)", rdService, name)
		}
	}
}

// TestNTF3151_RecipientDirectoryMethodsAreInThePermissionCatalog — каталог прав
// несёт каждый метод полосы с `reader` на типе справочника.
func TestNTF3151_RecipientDirectoryMethodsAreInThePermissionCatalog(t *testing.T) {
	reg, err := seed.LoadPermissionRegistry(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("фикстура: каталог прав не загружен: %v", err)
	}
	if _, ok := reg.LookupFQN(rdControlFQN); !ok {
		t.Fatalf("контроль: %s нет в каталоге — поиск по каталогу сломан (записей %d)", rdControlFQN, len(reg.All()))
	}
	for _, name := range rdMethods {
		fqn := rdService + "/" + name
		e, ok := reg.LookupFQN(fqn)
		if !ok {
			t.Fatalf("метода %s нет в каталоге прав (Р28: каждый метод перечня звена — в каталоге с "+
				"`required_relation reader` на %s:root); записей в каталоге %d", fqn, rdDirectoryTyp, len(reg.All()))
		}
		if e.RequiredRelation != "reader" || e.ScopeExtractor.ObjectType != rdDirectoryTyp {
			t.Fatalf("запись каталога %s: required_relation=%q object_type=%q, ожидалось reader на %s",
				fqn, e.RequiredRelation, e.ScopeExtractor.ObjectType, rdDirectoryTyp)
		}
	}
}

// TestD121_RecipientDirectoryReadsCarryTheRoutineFloor — решение Д121: чтения
// справочника адресов вызывает служба notify по сертификату, второго фактора у
// неё нет по построению, поэтому оба метода несут рутинную полосу
// `required_acr_min = "1"`. Мутации выдачи права на письма
// (`InternalNotificationGrantService/Revoke`, `/Restore`) остаются на «2» —
// это парный контроль: проба различает полосы, а не читает одно значение у
// всех.
//
// Утверждается обе стороны цепочки: объявление в контракте (опция метода) и
// запись каталога прав, порождённая из него генератором. Расхождение двух
// мест — отдельный отказ: каталог, не пересобранный после правки контракта,
// читался бы зелёным по одному контракту.
func TestD121_RecipientDirectoryReadsCarryTheRoutineFloor(t *testing.T) {
	want := map[string]string{
		rdService + "/Resolve":             "1",
		rdService + "/ListProjectAudience": "1",
		rdControlSvc + "/Revoke":           "2",
		rdControlSvc + "/Restore":          "2",
	}

	reg, err := seed.LoadPermissionRegistry(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("фикстура: каталог прав не загружен: %v", err)
	}

	for fqn, floor := range want {
		svcName, method, _ := strings.Cut(fqn, "/")
		sd, ok := rdServiceDescriptor(t, svcName)
		if !ok {
			t.Fatalf("служба %s не найдена в реестре дескрипторов", svcName)
		}
		m := sd.Methods().ByName(protoreflect.Name(method))
		if m == nil {
			t.Fatalf("метод %s не объявлен контрактом", fqn)
		}
		declared, _ := proto.GetExtension(m.Options(), authzv1.E_RequiredAcrMin).(string)
		if declared != floor {
			t.Errorf("контракт %s: required_acr_min=%q, ожидалось %q (Д121)", fqn, declared, floor)
		}

		e, ok := reg.LookupFQN(fqn)
		if !ok {
			t.Fatalf("метода %s нет в каталоге прав (записей %d)", fqn, len(reg.All()))
		}
		if e.RequiredACRMin != floor {
			t.Errorf("каталог %s: required_acr_min=%q, ожидалось %q (Д121; каталог пересобирается генератором из контракта)",
				fqn, e.RequiredACRMin, floor)
		}
	}
}
