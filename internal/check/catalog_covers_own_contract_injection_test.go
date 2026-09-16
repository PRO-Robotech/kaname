// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_covers_own_contract_injection_test.go — доказательство, что сверка
// копии с контрактом СПОСОБНА УПАСТЬ и СМОЛЧАТЬ там, где положено. Всё на
// синтетике: настоящий контракт и настоящая копия — предмет соседнего гейта.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/authz/catalogderive"

	"github.com/PRO-Robotech/kaname/internal/check"
)

func coverageMethod(fqn, permission, relation string) check.ContractMethod {
	pkg := fqn[:strings.LastIndexByte(fqn[:strings.IndexByte(fqn, '/')], '.')]
	return check.ContractMethod{
		FullMethod: fqn,
		Package:    pkg,
		Annotations: catalogderive.Annotations{
			Permission:       permission,
			RequiredRelation: relation,
		},
	}
}

func coverageRow(fqn, permission, relation string) catalogderive.Entry {
	var e catalogderive.Entry
	e.FQN = fqn
	e.Permission = permission
	e.RequiredRelation = relation
	return e
}

const (
	coverageOwnGet    = "kaname.cloud.demo.v1.DemoService/Get"
	coverageOwnCreate = "kaname.cloud.demo.v1.DemoService/Create"
	coverageForeign   = "kacho.cloud.other.v1.OtherService/Get"
)

// coverageContract — контракт из двух глаголов одного пакета.
func coverageContract() []check.ContractMethod {
	return []check.ContractMethod{
		coverageMethod(coverageOwnCreate, "demo.create", "editor"),
		coverageMethod(coverageOwnGet, "demo.get", "viewer"),
	}
}

// coverageCopy — копия, покрывающая контракт, плюс строка ЧУЖОГО домена, чьих
// стабов в двоичном файле нет: законный близнец находки «строка без RPC».
func coverageCopy() []catalogderive.Entry {
	return []catalogderive.Entry{
		coverageRow(coverageForeign, "other.get", "viewer"),
		coverageRow(coverageOwnCreate, "demo.create", "editor"),
		coverageRow(coverageOwnGet, "demo.get", "viewer"),
	}
}

// TestCatalogCoverageIsGreenWhenTheCopyCoversTheContract — положительный
// контроль: без него всякое отрицание ниже зеленело бы и на сломанной сверке.
// Чужая строка без RPC при этом МОЛЧИТ — это законный близнец.
func TestCatalogCoverageIsGreenWhenTheCopyCoversTheContract(t *testing.T) {
	t.Parallel()
	findings, census, err := check.CompareCatalogWithContract(coverageCopy(), coverageContract())
	if err != nil {
		t.Fatalf("сверка не исполнилась: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("покрытая копия дала находки: %v", findings)
	}
	if census.Methods != 2 || census.Packages != 1 || census.Rows != 3 || census.OwnRows != 2 {
		t.Fatalf("перепись неверна: %s", census)
	}
}

// TestCatalogCoverageCatchesAMethodWithoutARow — глагол контракта, у которого в
// копии нет строки, называется по имени; остальное молчит.
func TestCatalogCoverageCatchesAMethodWithoutARow(t *testing.T) {
	t.Parallel()
	contract := append(coverageContract(), coverageMethod("kaname.cloud.demo.v1.DemoService/Resolve", "<exempt>", ""))
	findings, _, err := check.CompareCatalogWithContract(coverageCopy(), contract)
	if err != nil {
		t.Fatalf("сверка не исполнилась: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("ожидалась ровно одна находка, получено %d: %v", len(findings), findings)
	}
	if !strings.HasPrefix(findings[0], "kaname.cloud.demo.v1.DemoService/Resolve: RPC объявлен контрактом") {
		t.Fatalf("находка не называет глагол без строки: %s", findings[0])
	}
	if !strings.Contains(findings[0], "CatalogPendingEntries") {
		t.Fatalf("находка не называет исход (ведомость ожидающих края): %s", findings[0])
	}
}

// TestCatalogCoverageCatchesAnOwnRowWithoutAMethod — строка СВОЕГО пакета, у
// которой в контракте больше нет RPC, — находка; чужая строка без RPC — нет.
func TestCatalogCoverageCatchesAnOwnRowWithoutAMethod(t *testing.T) {
	t.Parallel()
	copy := append(coverageCopy(), coverageRow("kaname.cloud.demo.v1.DemoService/Retired", "demo.retired", "editor"))
	findings, census, err := check.CompareCatalogWithContract(copy, coverageContract())
	if err != nil {
		t.Fatalf("сверка не исполнилась: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("ожидалась ровно одна находка, получено %d: %v", len(findings), findings)
	}
	if !strings.HasPrefix(findings[0], "kaname.cloud.demo.v1.DemoService/Retired: строка в нашей копии есть") {
		t.Fatalf("находка не называет строку без RPC: %s", findings[0])
	}
	if census.OwnRows != 3 {
		t.Fatalf("перепись своих строк неверна: %s", census)
	}
}

// TestCatalogCoverageCatchesARowThatDisagreesWithTheAnnotation — строка есть,
// но расходится с аннотацией по оси: ось названа.
func TestCatalogCoverageCatchesARowThatDisagreesWithTheAnnotation(t *testing.T) {
	t.Parallel()
	copy := coverageCopy()
	copy[2] = coverageRow(coverageOwnGet, "demo.get", "editor") // аннотация — viewer
	findings, _, err := check.CompareCatalogWithContract(copy, coverageContract())
	if err != nil {
		t.Fatalf("сверка не исполнилась: %v", err)
	}
	if len(findings) != 1 || !strings.Contains(findings[0], "required_relation — аннотация \"viewer\", копия \"editor\"") {
		t.Fatalf("ось расхождения не названа: %v", findings)
	}
}

// TestCatalogCoverageRefusesAnEmptyWalk — ноль методов и пустая копия суть
// третий исход, а не зелёное.
func TestCatalogCoverageRefusesAnEmptyWalk(t *testing.T) {
	t.Parallel()
	if _, _, err := check.CompareCatalogWithContract(coverageCopy(), nil); err == nil {
		t.Fatalf("пустой обход контракта прошёл за вердикт")
	}
	if _, _, err := check.CompareCatalogWithContract(nil, coverageContract()); err == nil {
		t.Fatalf("пустая копия прошла за вердикт")
	}
}

// TestOwnContractWalkIsNotEmpty — обход настоящего реестра под приставкой
// службы даёт файлы и методы: без этого гейт на настоящем дереве утверждал бы
// пустоту. Незнакомая приставка даёт ноль по обеим осям.
func TestOwnContractWalkIsNotEmpty(t *testing.T) {
	t.Parallel()
	methods, files := check.OwnContractMethods(ownContractPathPrefix)
	if files == 0 || len(methods) == 0 {
		t.Fatalf("обход контракта пуст: файлов %d, методов %d", files, len(methods))
	}
	t.Logf("перепись обхода: файлов %d, методов %d", files, len(methods))
	if m, f := check.OwnContractMethods("no-such-root/"); f != 0 || len(m) != 0 {
		t.Fatalf("незнакомая приставка дала файлов %d, методов %d", f, len(m))
	}
}
