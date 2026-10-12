// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_copy_parity_revised_test.go — четвёртый вид записи ведомости: глагол
// есть у обеих копий, но служба СМЕНИЛА значение одного поля его записи, а край
// порождает запись из контракта службы по пину и ещё несёт прежнее (kaname#720).
//
// Инъекция по каждой оси с законным близнецом; каждая меняет РОВНО ОДИН факт.
package check

import (
	"strings"
	"testing"
)

const testRevisedFQN = "kaname.cloud.demo.v1.DemoService/Delete"

// catalogEntryACR — запись с полем `required_acr_min` в форме генератора.
func catalogEntryACR(fqn, permission, acr string) string {
	return "  {\n" +
		"    \"fqn\": \"" + fqn + "\",\n" +
		"    \"permission\": \"" + permission + "\",\n" +
		"    \"required_relation\": \"editor\",\n" +
		"    \"required_acr_min\": \"" + acr + "\"\n" +
		"  }"
}

// testRevised — ведомость проб: одна запись того же вида, что действующая.
func testRevised() []CatalogRevisedEntry {
	return []CatalogRevisedEntry{{
		FQN:       testRevisedFQN,
		Field:     "required_acr_min",
		EdgeValue: "1",
		OwnValue:  "2",
		Why:       "синтетика пробы",
		Removal:   "край несёт новое значение",
		Refs:      "kaname#720",
	}}
}

// TestDeclaredRevisedEntryExplainsAChangedField — ось ВЕДОМОСТИ ПЕРЕСМОТРЕННЫХ:
// запись, разошедшаяся одним полем, — находка, пока смена не объявлена;
// объявленная — молчит. Ровно один факт между близнецами: наличие записи.
func TestDeclaredRevisedEntryExplainsAChangedField(t *testing.T) {
	a := catalogEntry("kacho.cloud.a.v1.A/Get", "a.get")
	edge := catalogFile(a, catalogEntryACR(testRevisedFQN, "demo.delete", "1"))
	own := catalogFile(a, catalogEntryACR(testRevisedFQN, "demo.delete", "2"))

	t.Run("дефект: смена поля не объявлена", func(t *testing.T) {
		findings, _, err := compareCatalogCopiesWithAllLedgers(nil, nil, nil, nil, edge, own)
		requireFinding(t, findings, err, testRevisedFQN, CatalogFindingCopies)
	})

	t.Run("близнец: та же смена ОБЪЯВЛЕНА", func(t *testing.T) {
		findings, census, err := compareCatalogCopiesWithAllLedgers(nil, nil, nil, testRevised(), edge, own)
		requireSilent(t, findings, err)
		if census.RevisedApplied != 1 || census.RevisedDeclared != 1 {
			t.Fatalf("перепись не назвала применённую запись: %s", census)
		}
	})

	t.Run("контроль: второе разошедшееся поле той же записи остаётся находкой", func(t *testing.T) {
		own2 := catalogFile(a, catalogEntryACR(testRevisedFQN, "demo.DELETE", "2"))
		findings, _, err := compareCatalogCopiesWithAllLedgers(nil, nil, nil, testRevised(), edge, own2)
		requireFinding(t, findings, err, testRevisedFQN, CatalogFindingCopies)
	})

	t.Run("контроль: значение у нас не то, что объявлено", func(t *testing.T) {
		own3 := catalogFile(a, catalogEntryACR(testRevisedFQN, "demo.delete", "3"))
		findings, _, err := compareCatalogCopiesWithAllLedgers(nil, nil, nil, testRevised(), edge, own3)
		requireFinding(t, findings, err, testRevisedFQN, CatalogFindingLedger)
	})
}

// TestDeclaredRevisedEntryExpiresOnItsOwn — САМОИСТЕЧЕНИЕ: край несёт новое
// значение — запись обязана уйти.
func TestDeclaredRevisedEntryExpiresOnItsOwn(t *testing.T) {
	a := catalogEntry("kacho.cloud.a.v1.A/Get", "a.get")
	revised := catalogEntryACR(testRevisedFQN, "demo.delete", "2")

	t.Run("дефект: край уже несёт новое значение, запись стоит", func(t *testing.T) {
		both := catalogFile(a, revised)
		findings, census, err := compareCatalogCopiesWithAllLedgers(nil, nil, nil, testRevised(), both, both)
		requireFinding(t, findings, err, testRevisedFQN, CatalogFindingLedger)
		if census.RevisedApplied != 0 {
			t.Fatalf("запись, которой нечего объяснять, объявлена применённой: %s", census)
		}
	})

	t.Run("дефект: края нет вовсе", func(t *testing.T) {
		findings, _, err := compareCatalogCopiesWithAllLedgers(nil, nil, nil, testRevised(),
			catalogFile(a), catalogFile(a, revised))
		requireFinding(t, findings, err, testRevisedFQN, CatalogFindingLedger)
	})

	t.Run("близнец: край ещё несёт прежнее значение", func(t *testing.T) {
		findings, _, err := compareCatalogCopiesWithAllLedgers(nil, nil, nil, testRevised(),
			catalogFile(a, catalogEntryACR(testRevisedFQN, "demo.delete", "1")), catalogFile(a, revised))
		requireSilent(t, findings, err)
	})
}

// TestDeclaredRevisedEntryMustNameOurOwnVerb — запись о глаголе, которого в
// НАШЕЙ копии нет, утверждает о дереве неправду.
func TestDeclaredRevisedEntryMustNameOurOwnVerb(t *testing.T) {
	a := catalogEntry("kacho.cloud.a.v1.A/Get", "a.get")
	edge := catalogFile(a, catalogEntryACR(testRevisedFQN, "demo.delete", "1"))

	t.Run("дефект: нашей записи нет", func(t *testing.T) {
		findings, _, err := compareCatalogCopiesWithAllLedgers(nil, nil, nil, testRevised(), edge, catalogFile(a))
		requireFinding(t, findings, err, testRevisedFQN, CatalogFindingLedger)
	})

	t.Run("близнец: наша запись на месте", func(t *testing.T) {
		findings, _, err := compareCatalogCopiesWithAllLedgers(nil, nil, nil, testRevised(), edge,
			catalogFile(a, catalogEntryACR(testRevisedFQN, "demo.delete", "2")))
		requireSilent(t, findings, err)
	})
}

// TestDeclaredRevisedEntriesCarryASubject — у каждой записи названы поле, оба
// значения (разные), причина, внешний предикат снятия и номер предмета.
func TestDeclaredRevisedEntriesCarryASubject(t *testing.T) {
	revised := CatalogRevisedEntries()
	t.Logf("перепись ведомости пересмотренных записей: записей %d", len(revised))
	for _, e := range revised {
		if e.FQN == "" || e.Field == "" {
			t.Errorf("запись ведомости без глагола либо поля: %+v", e)
		}
		if e.EdgeValue == e.OwnValue {
			t.Errorf("запись ведомости объявляет смену без смены: %s (%q)", e.FQN, e.OwnValue)
		}
		if strings.TrimSpace(e.Why) == "" {
			t.Errorf("запись ведомости без причины: %s", e.FQN)
		}
		if strings.TrimSpace(e.Removal) == "" {
			t.Errorf("запись ведомости без предиката снятия: %s", e.FQN)
		}
		if !strings.Contains(e.Refs, "#") {
			t.Errorf("запись ведомости без номера предмета: %s (refs=%q)", e.FQN, e.Refs)
		}
	}
}
