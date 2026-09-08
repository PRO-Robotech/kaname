// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// contractowner_injection_test.go — доказательство СПОСОБНОСТИ разбора отличать
// владельца пакета контракта, и способности СМОЛЧАТЬ на законном (#2168).
//
// Предмет — не «приставка сменилась», а форма узнавания. Разбор, ключующийся на
// ОДНОМ выписанном владельце, чужого не отвергает: он его НЕ ВИДИТ. Поэтому
// прогонов здесь три вида, и первый несущий:
//
//  1. контроль на ОБОИХ владельцах сразу — запись службы и запись платформы
//     привязываются в одном вызове. Одна замена приставки на другую этот
//     контроль ПРОВАЛИТ: полоса второго владельца станет невидимой;
//  2. инъекция по каждой оси принадлежности — приставка, которой не объявлял
//     никто; приставка платформы, ОТСТАВШАЯ от переименования; приставка
//     переименованного модуля на чужом. Все три обязаны называть КООРДИНАТУ;
//  3. законный близнец другого вида — платформенная служба без сегмента версии.
//     Она остаётся находкой ФОРМЫ, а не принадлежности: слив двух видов в один
//     отправлял бы читателя чинить не то.
package roleexport_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest/roleexport"
)

// entryOfIAM / entryOfPlatformModule — записи двух РАЗНЫХ владельцев, обе
// законные. Держатся рядом намеренно: контроль обязан утверждать обе.
const (
	entryOfIAM            = "kaname.cloud.iam.v1.AccountService/Get"
	entryOfPlatformModule = "kacho.cloud.vpc.v1.NetworkService/Get"
)

// TestAttribute_BothOwnersAreAttributedInOneCall — контроль, который ловит
// «переехали вслед за одним владельцем».
func TestAttribute_BothOwnersAreAttributedInOneCall(t *testing.T) {
	actions, faults := roleexport.Attribute([]roleexport.CatalogEntry{
		{FQN: entryOfIAM, RequiredRelation: "v_get", ScopeObjectType: "account"},
		{FQN: entryOfPlatformModule, RequiredRelation: "v_get", ScopeObjectType: "vpc_network"},
	})
	if len(faults) != 0 {
		t.Fatalf("законные записи двух владельцев дали находки: %v", faults)
	}
	byModule := map[string]roleexport.Action{}
	for _, a := range actions {
		byModule[a.Module] = a
	}
	if got, ok := byModule["iam"]; !ok || got.Resource != "account" || got.Verb != "get" {
		t.Errorf("запись службы не привязана: %+v", byModule)
	}
	if got, ok := byModule["vpc"]; !ok || got.Resource != "network" || got.Verb != "get" {
		t.Errorf("запись платформы не привязана: %+v", byModule)
	}
	t.Logf("перепись: записей подано 2 · привязано %d · находок %d · модули %v",
		len(actions), len(faults), []string{actions[0].Module, actions[1].Module})
}

// TestAttribute_OwnerNobodyDeclaredIsAFindingWithItsCoordinate — инъекция по
// трём осям принадлежности, у каждой законный близнец из контроля выше.
func TestAttribute_OwnerNobodyDeclaredIsAFindingWithItsCoordinate(t *testing.T) {
	axes := []struct {
		name string
		fqn  string
	}{
		{"приставка, которой не объявлял никто", "evilcorp.cloud.iam.v1.AccountService/Get"},
		{"приставка платформы, отставшая от переименования", "kacho.cloud.iam.v1.AccountService/Get"},
		{"приставка переименованного модуля на чужом", "kaname.cloud.vpc.v1.NetworkService/Get"},
	}
	for _, a := range axes {
		t.Run(a.name, func(t *testing.T) {
			actions, faults := roleexport.Attribute([]roleexport.CatalogEntry{{FQN: a.fqn}})
			if len(actions) != 0 {
				t.Errorf("запись с необъявленным владельцем привязана к ресурсу: %+v", actions)
			}
			if len(faults) != 1 {
				t.Fatalf("находок %d, ожидалась одна: %v", len(faults), faults)
			}
			if !errors.Is(faults[0], roleexport.ErrEntryOwnerNotDeclared) {
				t.Errorf("вид находки не назван принадлежностью: %v", faults[0])
			}
			if !strings.Contains(faults[0].Error(), a.fqn) {
				t.Errorf("находка не называет координату %q: %v", a.fqn, faults[0])
			}
		})
	}
	t.Logf("перепись: осей принадлежности %d", len(axes))
}

// TestAttribute_PlatformServiceStaysAFindingOfShapeNotOwnership — законный
// близнец ДРУГОГО вида: два вида находки не сливаются в один.
func TestAttribute_PlatformServiceStaysAFindingOfShapeNotOwnership(t *testing.T) {
	for _, fqn := range []string{
		"kacho.cloud.operation.OperationService/Get",
		"kacho.cloud.subscription.InternalSubscriptionService/Subscribe",
	} {
		_, faults := roleexport.Attribute([]roleexport.CatalogEntry{{FQN: fqn}})
		if len(faults) != 1 {
			t.Fatalf("%s: находок %d, ожидалась одна: %v", fqn, len(faults), faults)
		}
		if !errors.Is(faults[0], roleexport.ErrEntryOutsideModuleShape) {
			t.Errorf("%s: платформенная служба названа не находкой формы: %v", fqn, faults[0])
		}
		if errors.Is(faults[0], roleexport.ErrEntryOwnerNotDeclared) {
			t.Errorf("%s: платформенная служба объявлена нарушением принадлежности — "+
				"её владелец объявлен, у неё нет сегмента версии", fqn)
		}
	}
}
