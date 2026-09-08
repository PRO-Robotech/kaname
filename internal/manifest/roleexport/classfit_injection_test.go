// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// classfit_injection_test.go — доказательство способности стадии 1 УПАСТЬ и
// СМОЛЧАТЬ, тремя прогонами, а не двумя.
//
// `testing.md` §«Гейт на класс», п. 2в: инъекция обязана ронять ТОЛЬКО
// проверяемое. Годная форма — снять НОВОЕ свойство у элемента, чьё СТАРОЕ на
// месте; тогда прогонов три:
//
//	контроль          всё цело           — молчат обе проверки
//	инъекция новая    класс объявлен не тем  — краснеет ТОЛЬКО стадия 1
//	инъекция старая   класс роли пуст        — краснеет ТОЛЬКО стадия 2
//
// Третий прогон обязателен: без него молчание существующего контроля неотличимо
// от молчания мёртвого. Он же — ответ на вопрос «не сломала ли моя инъекция
// соседа»: соседняя проверка на инъецированном входе обязана вести себя ровно
// так же, как на чистом.
package roleexport_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest/roleexport"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// TestInjectionThreeRuns_ClassFitAndEmptyClassAreIndependent — три прогона.
func TestInjectionThreeRuns_ClassFitAndEmptyClassAreIndependent(t *testing.T) {
	actions := mustActions(t)

	// Прогон 1 — КОНТРОЛЬ. Фикстура как написана: стадия 1 молчит, стадия 2
	// говорит (у фикстуры есть свои пустые классы у `vpc.address_pool_admin`), и
	// это состояние берётся ЭТАЛОНОМ, а не «нулём».
	base := mustFixture(t)
	baseClassFaults, _, baseClassCensus := roleexport.CheckResourceClasses(catalogfixture.Facts(), base, actions)
	baseRuleFaults, baseRuleCensus := roleexport.CheckRoleRules(catalogfixture.Facts(), base, actions)
	t.Logf("контроль: стадия 1 — %s", baseClassCensus.Summary())
	t.Logf("контроль: стадия 2 — %s", baseRuleCensus.Summary())
	if len(baseClassFaults) != 0 {
		t.Fatalf("контроль негоден: стадия 1 краснеет на нетронутой фикстуре: %v", baseClassFaults)
	}
	if len(baseRuleFaults) == 0 {
		t.Fatal("контроль негоден: стадия 2 молчит на нетронутой фикстуре, значит её " +
			"молчание на инъекции ничего не докажет")
	}

	// Прогон 2 — ИНЪЕКЦИЯ НОВОГО свойства: у действия, чьё старое свойство
	// (класс покрывает хотя бы одно пригодное действие) на месте, снимается
	// новое — соответствие класса гейту.
	injected := mustLoadManifest(t, withNetworkListOperationsClass(t, "get"))
	newFaults, _, newCensus := roleexport.CheckResourceClasses(catalogfixture.Facts(), injected, actions)
	newRuleFaults, newRuleCensus := roleexport.CheckRoleRules(catalogfixture.Facts(), injected, actions)
	t.Logf("инъекция новая: стадия 1 — %s", newCensus.Summary())
	t.Logf("инъекция новая: стадия 2 — %s", newRuleCensus.Summary())

	if len(newFaults) != 1 {
		t.Fatalf("стадия 1 обязана краснеть ровно одним отказом, получила %d: %v",
			len(newFaults), newFaults)
	}
	var cf roleexport.ClassFinding
	if !errors.As(newFaults[0], &cf) {
		t.Fatalf("отказ не несёт координат: %v", newFaults[0])
	}
	if cf.Resource != "network" || cf.Verb != "listOperations" {
		t.Errorf("отказ называет не ту координату: %s.%s", cf.Resource, cf.Verb)
	}
	// Инъекция уронила ТОЛЬКО проверяемое: сосед ведёт себя ровно как в контроле.
	if len(newRuleFaults) != len(baseRuleFaults) {
		t.Errorf("инъекция задела соседнюю проверку: отказов стадии 2 было %d, стало %d — "+
			"красное пришло бы от соседа, и новая проверка могла бы оказаться вакуумной",
			len(baseRuleFaults), len(newRuleFaults))
	}
	if newRuleCensus.Summary() != baseRuleCensus.Summary() {
		t.Errorf("инъекция сдвинула перепись соседа:\n  было: %s\n  стало: %s",
			baseRuleCensus.Summary(), newRuleCensus.Summary())
	}

	// Прогон 3 — ИНЪЕКЦИЯ СТАРОГО свойства: у роли снимается покрытие класса.
	// Стадия 2 обязана покраснеть СВЕРХ контроля, стадия 1 — смолчать.
	old := mustLoadManifest(t, withEmptyClassRule(t))
	oldClassFaults, _, oldClassCensus := roleexport.CheckResourceClasses(catalogfixture.Facts(), old, actions)
	oldRuleFaults, oldRuleCensus := roleexport.CheckRoleRules(catalogfixture.Facts(), old, actions)
	t.Logf("инъекция старая: стадия 1 — %s", oldClassCensus.Summary())
	t.Logf("инъекция старая: стадия 2 — %s", oldRuleCensus.Summary())

	if len(oldClassFaults) != 0 {
		t.Errorf("инъекция в раздел ролей задела стадию 1: %v", oldClassFaults)
	}
	if len(oldRuleFaults) <= len(baseRuleFaults) {
		t.Fatalf("существующий контроль НЕ ЗАМЕТИЛ своей инъекции: отказов было %d, "+
			"стало %d — его молчание неотличимо от молчания мёртвого",
			len(baseRuleFaults), len(oldRuleFaults))
	}
	var sawEmpty bool
	for _, f := range oldRuleFaults {
		if errors.Is(f, roleexport.ErrClassCoversNoSuitableAction) {
			sawEmpty = true
		}
	}
	if !sawEmpty {
		t.Errorf("отказ существующего контроля не того вида: %v", oldRuleFaults)
	}
}

// TestInjection_CensusMovesWithTheDefect — перепись обязана ДВИГАТЬСЯ.
//
// Проверка, у которой находка появляется, а перепись стои́т, считает не то, что
// судит. Здесь действие переезжает из «класс удовлетворяет» в «отказ», и
// движутся ровно два счётчика — сумма остаётся прежней.
func TestInjection_CensusMovesWithTheDefect(t *testing.T) {
	actions := mustActions(t)
	_, _, before := roleexport.CheckResourceClasses(catalogfixture.Facts(), mustFixture(t), actions)
	_, _, after := roleexport.CheckResourceClasses(catalogfixture.Facts(),
		mustLoadManifest(t, withNetworkListOperationsClass(t, "get")), actions)

	if before.VerbsRead != after.VerbsRead {
		t.Fatalf("осмотренных было %d, стало %d — инъекция сменила популяцию, а не свойство",
			before.VerbsRead, after.VerbsRead)
	}
	if after.ClassSatisfies != before.ClassSatisfies-1 {
		t.Errorf("удовлетворяющих было %d, стало %d, ожидалось на одно меньше",
			before.ClassSatisfies, after.ClassSatisfies)
	}
	if after.Findings != before.Findings+1 {
		t.Errorf("отказов было %d, стало %d, ожидалось на один больше",
			before.Findings, after.Findings)
	}
	if after.Unsuitable != before.Unsuitable || after.Exempt != before.Exempt ||
		after.Unmatched != before.Unmatched {
		t.Errorf("сдвинулось состояние, которого инъекция не касалась: %s", after.Summary())
	}
}

// TestClassCheckOnAnEmptyCatalogIsVoid_NotClean — «ноль находок» при пустом
// каталоге обязано быть отличимо от «всё в порядке».
//
// Каталог пуст ⇒ сопоставить нечего ⇒ КАЖДОЕ действие раздела уходит в «не
// сопоставлено», а не в молчание. Без этого проверка, у которой отвалился порт
// каталога, зеленела бы уверенно.
func TestClassCheckOnAnEmptyCatalogIsVoid_NotClean(t *testing.T) {
	faults, notes, census := roleexport.CheckResourceClasses(catalogfixture.Facts(), mustFixture(t), nil)
	t.Logf("перепись: %s", census.Summary())
	if len(faults) != 0 {
		t.Errorf("на пустом каталоге отказов быть не может — судить нечем: %v", faults)
	}
	if census.Unmatched != census.VerbsRead || census.VerbsRead == 0 {
		t.Fatalf("осмотрено %d, не сопоставлено %d — пустой каталог обязан быть виден "+
			"переписью целиком", census.VerbsRead, census.Unmatched)
	}
	if len(notes) != census.VerbsRead {
		t.Errorf("пометок %d при %d несопоставленных: часть действий пропала молча",
			len(notes), census.Unmatched)
	}
}

// TestNoteKindsAreNamedInWords — вид пометки читается словами.
//
// Число в отчёте читателю не говорит ничего, а пометка адресована человеку,
// который открыл вывод команды и не читал этот пакет.
func TestNoteKindsAreNamedInWords(t *testing.T) {
	for _, k := range []roleexport.NoteKind{
		roleexport.NoteUnsuitableForRole,
		roleexport.NoteActionUnknownToCatalog,
		roleexport.NoteActionExemptFromGate,
	} {
		if s := k.String(); s == "" || strings.HasPrefix(s, "вид пометки") {
			t.Errorf("вид %d не назван словами: %q", int(k), s)
		}
	}
}

// withEmptyClassRule — фикстура с ОДНОЙ правкой в разделе ролей: роли
// `vpc.internal_consumer` дописывается класс, пригодного содержимого у которого
// на её ресурсах нет.
//
// Правится роль, а НЕ раздел `resources`: инъекция обязана адресовать предмет
// существующего контроля и не задевать нового.
func withEmptyClassRule(t *testing.T) string {
	t.Helper()
	// Якорь — ПРАВИЛО РОЛИ, и ключ у него `classes`: право роли пишется им, а
	// снятый `verbs` загрузчик отвергает явно. Якорь переехал вместе со своим
	// предметом; оставленный при старом ключе, он ронял бы пробу отказом «якорь
	// встречается 0 раз» — то есть говорил бы о СЕБЕ, а не о дереве.
	const anchor = "        classes: [get, list]\n"
	src := mustFixtureText(t)
	if strings.Count(src, anchor) != 1 {
		t.Fatalf("якорь правки встречается %d раз", strings.Count(src, anchor))
	}
	return strings.Replace(src, anchor, "        classes: [get, list, create]\n", 1)
}
