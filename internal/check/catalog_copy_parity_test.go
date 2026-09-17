// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_copy_parity_test.go — сверка копий каталога прав судит СОДЕРЖИМОЕ,
// а объявленное послабление держит себя в обе стороны.
//
// Проба живёт на СИНТЕТИКЕ, а не на копии края: копии края в этом репозитории
// нет и быть не должно (`polyrepo.md` §«Копия между репозиториями ЗАПРЕЩЕНА»),
// она приезжает выборкой в конвейере. Держатель сверки настоящими деревьями —
// цель `check-permission-catalog`; предмет ЭТИХ проб — способность сверки
// падать и молчать там, где положено.
package check

import (
	"strings"
	"testing"
)

// catalogEntry — запись синтетического каталога в форме генератора.
func catalogEntry(fqn, permission string) string {
	return "  {\n" +
		"    \"fqn\": \"" + fqn + "\",\n" +
		"    \"permission\": \"" + permission + "\",\n" +
		"    \"required_relation\": \"editor\"\n" +
		"  }"
}

// catalogFile — файл из записей в форме генератора: записи отсортированы по
// `fqn`, как их и пишет порождающая сторона.
func catalogFile(entries ...string) string {
	return "[\n" + strings.Join(entries, ",\n") + "\n]\n"
}

const (
	testEdgeFQN = "kacho.cloud.demo.v1.DemoService/Subscribe"
	testOwnFQN  = "corelib.demo.DemoService/Subscribe"
)

// testRenames — ведомость проб: одна запись того же вида, что действующая.
func testRenames() []CatalogFoundationRename {
	return []CatalogFoundationRename{{
		EdgeFQN: testEdgeFQN,
		OwnFQN:  testOwnFQN,
		Why:     "синтетика пробы",
		Removal: "край назвал глагол новым именем",
		Refs:    "kaname#79",
	}}
}

// TestCatalogCopiesAreOneArtifact — зелёное: копии побайтово равны, ведомость
// пуста. Это положительный контроль: без него всякое отрицание ниже зеленело бы
// и на сломанной сверке.
func TestCatalogCopiesAreOneArtifact(t *testing.T) {
	file := catalogFile(
		catalogEntry("kacho.cloud.a.v1.A/Get", "a.get"),
		catalogEntry("kacho.cloud.b.v1.B/Get", "b.get"),
	)

	findings, census, err := compareCatalogCopiesWith(nil, nil, file, file)
	if err != nil {
		t.Fatalf("сверка НЕ ИСПОЛНИЛАСЬ: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("находки на равных копиях: %v", findings)
	}
	if !census.BytesEqual {
		t.Fatal("перепись не признала побайтового равенства")
	}
	if census.EdgeEntries != 2 || census.OwnEntries != 2 {
		t.Fatalf("перепись не назвала объёма осмотренного: %s", census)
	}
}

// TestCatalogRenameMovesTheEntryAndStillMatches — объявленное переименование
// ДВИГАЕТ запись в перечне (он сортирован по `fqn`), и сверка обязана это
// учесть. Без пересортировки проба покраснела бы на верном дереве.
func TestCatalogRenameMovesTheEntryAndStillMatches(t *testing.T) {
	edge := catalogFile(
		catalogEntry("kacho.cloud.a.v1.A/Get", "a.get"),
		catalogEntry(testEdgeFQN, "platform.demo.subscribe"),
	)
	own := catalogFile(
		catalogEntry(testOwnFQN, "platform.demo.subscribe"),
		catalogEntry("kacho.cloud.a.v1.A/Get", "a.get"),
	)

	findings, census, err := compareCatalogCopiesWith(testRenames(), nil, edge, own)
	if err != nil {
		t.Fatalf("сверка НЕ ИСПОЛНИЛАСЬ: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("объявленное переименование дало находки: %v", findings)
	}
	if census.RenamesApplied != 1 {
		t.Fatalf("переименование не применилось: %s", census)
	}
	if census.BytesEqual {
		t.Fatal("копии НЕ равны побайтово — перепись обязана это сказать")
	}
}

// TestCatalogParityCensusIsNotEmpty — перепись печатает обе величины: «ноль
// находок» обязано быть отличимо от «ноль прочитанного».
func TestCatalogParityCensusIsNotEmpty(t *testing.T) {
	file := catalogFile(catalogEntry("kacho.cloud.a.v1.A/Get", "a.get"))
	_, census, err := compareCatalogCopiesWith(nil, nil, file, file)
	if err != nil {
		t.Fatalf("сверка НЕ ИСПОЛНИЛАСЬ: %v", err)
	}
	text := census.String()
	for _, want := range []string{"записей у края 1", "записей у нас 1", "переименований объявлено 0"} {
		if !strings.Contains(text, want) {
			t.Fatalf("перепись не назвала %q: %s", want, text)
		}
	}
}

// TestEmptyCatalogIsNotAVerdict — пустой перечень: сверять нечего, и это ТРЕТИЙ
// ИСХОД, а не «копии совпали». Пустой обход, отданный зелёным, — ровно тот
// класс, который корпус ловит.
func TestEmptyCatalogIsNotAVerdict(t *testing.T) {
	if _, _, err := compareCatalogCopiesWith(nil, nil, "[\n\n]\n", "[\n\n]\n"); err == nil {
		t.Fatal("пустой перечень принят за совпадение копий")
	}
}

// TestDeclaredRenamesCarryASubject — послабление без предмета отвергается самой
// ведомостью: у записи обязаны быть обе стороны, причина, предикат снятия и
// номер, за которым кто-то отвечает.
//
// На ПУСТОЙ ведомости проба проходит — пустой перечень есть цель, ради которой
// ведомость и держит самоистечение. Поэтому перепись печатается всегда: «записей
// 0» обязано быть отличимо от «проба ведомости не читала».
func TestDeclaredRenamesCarryASubject(t *testing.T) {
	renames := CatalogFoundationRenames()
	t.Logf("перепись ведомости: записей %d", len(renames))
	for _, r := range renames {
		if r.EdgeFQN == "" || r.OwnFQN == "" {
			t.Errorf("запись ведомости без одной из сторон: %+v", r)
		}
		if r.EdgeFQN == r.OwnFQN {
			t.Errorf("запись ведомости ничего не переименовывает: %s", r.EdgeFQN)
		}
		if strings.TrimSpace(r.Why) == "" {
			t.Errorf("запись ведомости без причины: %s", r.EdgeFQN)
		}
		if strings.TrimSpace(r.Removal) == "" {
			t.Errorf("запись ведомости без предиката снятия: %s", r.EdgeFQN)
		}
		if !strings.Contains(r.Refs, "#") {
			t.Errorf("запись ведомости без номера предмета: %s (refs=%q)", r.EdgeFQN, r.Refs)
		}
	}
}

// TestDeclaredPendingEntriesCarryASubject — та же дисциплина, что у
// переименований: у каждой записи, ждущей края, названы причина, внешний
// предикат снятия и номер предмета. На пустой ведомости проходит с переписью.
func TestDeclaredPendingEntriesCarryASubject(t *testing.T) {
	pending := CatalogPendingEntries()
	t.Logf("перепись ведомости ожидающих края: записей %d", len(pending))
	for _, e := range pending {
		if e.OwnFQN == "" {
			t.Errorf("запись ведомости без глагола: %+v", e)
		}
		if strings.TrimSpace(e.Why) == "" {
			t.Errorf("запись ведомости без причины: %s", e.OwnFQN)
		}
		if strings.TrimSpace(e.Removal) == "" {
			t.Errorf("запись ведомости без предиката снятия: %s", e.OwnFQN)
		}
		if !strings.Contains(e.Refs, "#") {
			t.Errorf("запись ведомости без номера предмета: %s (refs=%q)", e.OwnFQN, e.Refs)
		}
	}
}
