// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// platform_owner_witness_injection_test.go — доказательство способности
// свидетеля упасть И смолчать.
//
// Вход синтетический ПО НЕОБХОДИМОСТИ: подать настоящий дефект значило бы
// переписать значение `platformOwner`, а оно константа пакета — на такой правке
// не собрался бы сам пакет. Поэтому инъекция подаёт ту же форму записей, что
// несёт поставляемый каталог, и меняет в мире РОВНО ОДИН факт против законного
// близнеца (`change-graph.md` §6).
package contractnaming_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/contractnaming"
)

// catalogShapeFQNs — форма записей поставляемого каталога: службы фундамента,
// модули платформы и модуль службы.
func catalogShapeFQNs(platformOwner string) []string {
	return []string{
		"corelib.operation.OperationService/Get",
		platformOwner + ".cloud.vpc.v1.NetworkService/Get",
		platformOwner + ".cloud.compute.v1.InstanceService/Create",
		"kaname.cloud.iam.v1.AccountService/Get",
	}
}

// TestPlatformOwnerWitnessRedsWhenTheCatalogNamesAnotherOwner — инъекция по
// первой оси: каталог называет владельцем МОДУЛЯ ПЛАТФОРМЫ кого-то другого.
func TestPlatformOwnerWitnessRedsWhenTheCatalogNamesAnotherOwner(t *testing.T) {
	findings, byOwner, _ := catalogOwnerFindings(catalogShapeFQNs("someoneelse"))
	if len(findings) != 2 {
		t.Fatalf("каталог, называющий чужого владельца двух модулей платформы, НЕ дал двух "+
			"находок: их %d при переписи %v\nСвидетель, не краснеющий на расхождении, не "+
			"удерживает ничего", len(findings), byOwner)
	}
	for _, f := range findings {
		if !strings.Contains(f, "someoneelse") || !strings.Contains(f, contractnaming.PlatformOwner()) {
			t.Errorf("находка не называет ОБОИХ владельцев: %q", f)
		}
	}
	// Модуль службы разошедшимся НЕ объявлен: его владелец объявлен ведомостью и
	// каталогом подтверждается. Иначе инъекция роняла бы соседа, а не предмет
	// (`testing.md` §«Гейт на класс», п. 2в).
	for _, f := range findings {
		if strings.Contains(f, "модуль iam") {
			t.Errorf("инъекция уронила СОСЕДА: %q", f)
		}
	}
}

// TestPlatformOwnerWitnessRedsWhenTheLedgerDisagrees — инъекция по второй оси:
// каталог называет владельцем модуля СЛУЖБЫ платформенное имя, то есть
// ведомость переименования перестала соответствовать действительности.
func TestPlatformOwnerWitnessRedsWhenTheLedgerDisagrees(t *testing.T) {
	own := contractnaming.PlatformOwner()
	findings, _, _ := catalogOwnerFindings([]string{
		own + ".cloud.iam.v1.AccountService/Get",
	})
	if len(findings) != 1 {
		t.Fatalf("каталог, отдавший модуль службы платформе, находкой не стал: %v", findings)
	}
	if !strings.Contains(findings[0], "модуль iam") {
		t.Errorf("находка не называет модуль: %q", findings[0])
	}
}

// TestPlatformOwnerWitnessStaysSilentOnTheLegalShape — законный близнец: та же
// форма с ВЕРНЫМ владельцем. Без него отрицание зеленело бы на предикате,
// отвергающем всё.
func TestPlatformOwnerWitnessStaysSilentOnTheLegalShape(t *testing.T) {
	own := contractnaming.PlatformOwner()
	findings, byOwner, modules := catalogOwnerFindings(catalogShapeFQNs(own))
	if len(findings) != 0 {
		t.Fatalf("законная форма объявлена находкой: %v", findings)
	}
	if byOwner[own] != 2 {
		t.Fatalf("записей платформы прочитано %d из двух: %v", byOwner[own], byOwner)
	}
	if byOwner["kaname"] != 1 {
		t.Fatalf("запись службы прочитана %d раз(а) из одного: %v", byOwner["kaname"], byOwner)
	}
	// Служба фундамента модулем платформы НЕ является и в пары не попадает: разбор
	// обязан её ОТЛИЧАТЬ, а не отбрасывать по счастливой случайности.
	if len(modules) != 3 {
		t.Fatalf("модулей названо %d из трёх (vpc, compute, iam): %v — служба фундамента "+
			"не должна попадать в пары", len(modules), modules)
	}
}

// TestPlatformOwnerWitnessNeedsThePlatformPresent — предпосылка. Каталог БЕЗ
// записей платформы расхождений не даёт — и именно поэтому его мало: на таком
// входе значение снова остаётся без свидетеля, при зелёном прогоне.
func TestPlatformOwnerWitnessNeedsThePlatformPresent(t *testing.T) {
	findings, byOwner, _ := catalogOwnerFindings([]string{
		"corelib.operation.OperationService/Get",
		"kaname.cloud.iam.v1.AccountService/Get",
	})
	if len(findings) != 0 {
		t.Fatalf("каталог без платформы дал находки: %v", findings)
	}
	if byOwner[contractnaming.PlatformOwner()] != 0 {
		t.Fatalf("записей платформы на входе БЕЗ платформы насчитано %d: %v",
			byOwner[contractnaming.PlatformOwner()], byOwner)
	}
	// Именно эту ситуацию гейт объявляет отказом отдельной ветвью — иначе
	// «расхождений нет» означало бы «сверять было не с чем».
}
