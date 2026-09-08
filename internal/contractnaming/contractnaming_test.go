// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// contractnaming_test.go — гейт ведомости владельцев: она обязана сходиться с
// КОНТРАКТОМ, а не с чьей-то памятью.
//
// Вход настоящий — дескрипторы, которые генерация произвела из `.proto` и
// вкомпилировала в стабы. Ведомость, разошедшаяся с ними, есть ровно тот класс,
// ради которого пакет заведён: утверждение о владельце, пережившее свой
// предмет.
package contractnaming_test

import (
	"strings"
	"testing"

	operationv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	quotav1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/quota/v1"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/protobuf/proto"

	"github.com/PRO-Robotech/kaname/internal/contractnaming"
)

// declaredPackage — имя пакета контракта, каким его называет САМ контракт.
func declaredPackage(m proto.Message) string {
	return string(m.ProtoReflect().Descriptor().ParentFile().Package())
}

// TestLedgerAgreesWithTheContract — каждая запись ведомости обязана иметь
// подтверждение в дескрипторе, и подтверждение это НЕ ведомость.
//
// Записей сегодня одна, и перечень свидетелей поэтому рукописный: свидетеля
// нельзя вывести обходом — стабы модуля, которого служба не поднимает, в её
// двоичный файл не попадают вовсе. Запись без свидетеля — находка, а не
// послабление: непроверяемая запись ведомости неотличима от выдуманной.
func TestLedgerAgreesWithTheContract(t *testing.T) {
	witnesses := map[string]proto.Message{
		"iam": (*iamv1.Account)(nil),
	}

	ledger := contractnaming.RenamedModules()
	if len(ledger) == 0 {
		t.Fatal("ведомость пуста: сверять нечего, и «ноль расхождений» стало бы " +
			"неотличимо от «ноль прочитанного»")
	}

	checked := 0
	for module, owner := range ledger {
		witness, ok := witnesses[module]
		if !ok {
			t.Errorf("модуль %q объявлен переименованным, а свидетеля-дескриптора у "+
				"записи нет: подтвердить владельца %q нечем", module, owner)
			continue
		}
		got := declaredPackage(witness)
		want := contractnaming.ContractPackage(module)
		if got != want {
			t.Errorf("модуль %q: ведомость объявляет пакет %q, контракт называет %q — "+
				"ведомость пережила свой предмет", module, want, got)
			continue
		}
		gotOwner, gotModule, split := contractnaming.Split(got)
		if !split {
			t.Errorf("пакет контракта %q не разбирается формой модуля", got)
			continue
		}
		if gotOwner != owner || gotModule != module {
			t.Errorf("пакет контракта %q дал (%q, %q), ведомость — (%q, %q)",
				got, gotOwner, gotModule, owner, module)
			continue
		}
		checked++
	}
	t.Logf("перепись: записей ведомости %d · подтверждено дескриптором %d · "+
		"объявленных владельцев %v", len(ledger), checked, contractnaming.KnownOwners())
	if checked == 0 {
		t.Fatal("подтверждено дескриптором ноль записей: вердикт беспредметен")
	}
}

// TestPlatformOwnerIsTheOneTheContractDeclares — приставка платформы тоже не
// выписана «по памяти»: её называет платформенный контракт.
//
// Свидетелей ДВА, и они разной формы намеренно: `quota` несёт сегмент версии и
// разбирается как модуль, `operation` его не несёт вовсе. Один свидетель
// закрепил бы форму, а не владельца.
func TestPlatformOwnerIsTheOneTheContractDeclares(t *testing.T) {
	quotaPkg := declaredPackage((*quotav1.Quota)(nil))
	owner, module, ok := contractnaming.Split(quotaPkg)
	if !ok {
		t.Fatalf("платформенный пакет %q не разобрался формой модуля", quotaPkg)
	}
	if owner != contractnaming.PlatformOwner() {
		t.Errorf("контракт называет владельцем %q, объявлено %q", owner, contractnaming.PlatformOwner())
	}
	if !contractnaming.OwnsModule(owner, module) {
		t.Errorf("владелец %q не признан владельцем модуля %q", owner, module)
	}

	opPkg := declaredPackage((*operationv1.Operation)(nil))
	if head, _, cut := strings.Cut(opPkg, "."); !cut || head != contractnaming.PlatformOwner() {
		t.Errorf("платформенная служба %q не принадлежит объявленному владельцу %q",
			opPkg, contractnaming.PlatformOwner())
	}
	if _, _, split := contractnaming.Split(opPkg); split {
		t.Errorf("платформенная служба %q разобрана как пакет модуля: сегмента версии "+
			"она не несёт, и ресурсом модуля не является", opPkg)
	}
	t.Logf("перепись: свидетелей платформы 2 (%s · %s) · владелец %q",
		quotaPkg, opPkg, contractnaming.PlatformOwner())
}

// TestOwnsModuleRefusesAnOwnerNobodyDeclared — отрицание в паре с положительным.
//
// Три оси, и у каждой законный близнец: приставка, которой не объявлял никто;
// приставка платформы на переименованном модуле; приставка переименованного
// модуля на чужом. Без близнецов отрицание зеленело бы на реализации,
// отвергающей любой вход.
func TestOwnsModuleRefusesAnOwnerNobodyDeclared(t *testing.T) {
	cases := []struct {
		name   string
		owner  string
		module string
		want   bool
	}{
		{"близнец: платформа владеет своим модулем", contractnaming.PlatformOwner(), "vpc", true},
		{"близнец: переименованный владеет своим", "kaname", "iam", true},
		{"находка: приставка, которой никто не объявлял", "evilcorp", "iam", false},
		{"находка: приставка платформы на переименованном модуле", contractnaming.PlatformOwner(), "iam", false},
		{"находка: приставка переименованного на чужом модуле", "kaname", "vpc", false},
	}
	for _, c := range cases {
		if got := contractnaming.OwnsModule(c.owner, c.module); got != c.want {
			t.Errorf("%s: OwnsModule(%q, %q) = %v, ожидалось %v",
				c.name, c.owner, c.module, got, c.want)
		}
	}
	t.Logf("перепись: осей %d", len(cases))
}

// TestSplitKnowsTheFormsTheTreeProduces — распознаватель обязан знать ВСЕ
// законные формы записи предмета, и обе стороны названы.
func TestSplitKnowsTheFormsTheTreeProduces(t *testing.T) {
	forms := []struct {
		pkg    string
		owner  string
		module string
		ok     bool
	}{
		{"kacho.cloud.vpc.v1", "kacho", "vpc", true},
		{"kaname.cloud.iam.v1", "kaname", "iam", true},
		{"evilcorp.cloud.iam.v1", "evilcorp", "iam", true}, // форма годна, принадлежность — отдельный вопрос
		{"kacho.cloud.operation", "", "", false},
		{"kacho.cloud.subscription", "", "", false},
		{"kacho.cloud.vpc.v2", "", "", false},
		{"kacho.storage.vpc.v1", "", "", false},
		{"", "", "", false},
		{"kacho.cloud..v1", "", "", false},
	}
	for _, f := range forms {
		owner, module, ok := contractnaming.Split(f.pkg)
		if ok != f.ok || owner != f.owner || module != f.module {
			t.Errorf("Split(%q) = (%q, %q, %v), ожидалось (%q, %q, %v)",
				f.pkg, owner, module, ok, f.owner, f.module, f.ok)
		}
	}
	t.Logf("перепись: форм осмотрено %d", len(forms))
}
