// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_copy_parity_injection_test.go — доказательство, что сверка копий
// каталога прав СПОСОБНА упасть, и падает на том, что проверяет.
//
// Инъекция идёт ПО КАЖДОЙ ОСИ и в ОБЕ СТОРОНЫ: рядом с внесённым дефектом
// стоит ЗАКОННЫЙ БЛИЗНЕЦ той же формы, на котором сверка обязана молчать. Без
// близнеца проверка ловила бы форму, а не существо, и первый же ложный срабат
// её отключил бы.
//
// Каждая инъекция меняет РОВНО ОДИН факт против своего близнеца: иначе
// неизвестно, какой из двух дал красное, и доказательство недействительно.
package check

import (
	"strings"
	"testing"
)

// requireFinding — находка есть и называет координату.
func requireFinding(t *testing.T, findings []CatalogParityFinding, err error, want, kind string) {
	t.Helper()
	if err != nil {
		t.Fatalf("сверка НЕ ИСПОЛНИЛАСЬ, а ожидалась находка: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("дефект внесён, сверка молчит")
	}
	for _, f := range findings {
		if strings.Contains(f.Text, want) {
			if f.Kind != kind {
				t.Fatalf("находка о %q отнесена к виду %q, ожидался %q", want, f.Kind, kind)
			}
			return
		}
	}
	t.Fatalf("находка есть, но координаты %q не называет: %v", want, findings)
}

// requireSilent — законный близнец: находок нет.
func requireSilent(t *testing.T, findings []CatalogParityFinding, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("сверка НЕ ИСПОЛНИЛАСЬ на законном близнеце: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("законный близнец дал находки: %v", findings)
	}
}

// TestCatalogParityCatchesChangedEntry — ось СОДЕРЖИМОГО записи.
func TestCatalogParityCatchesChangedEntry(t *testing.T) {
	const fqn = "kacho.cloud.a.v1.A/Get"
	twin := catalogEntry(fqn, "a.get")
	edge := catalogFile(twin, catalogEntry("kacho.cloud.b.v1.B/Get", "b.get"))

	t.Run("дефект: право у записи подменено", func(t *testing.T) {
		own := catalogFile(catalogEntry(fqn, "a.ADMIN"), catalogEntry("kacho.cloud.b.v1.B/Get", "b.get"))
		findings, _, err := compareCatalogCopiesWith(nil, nil, edge, own)
		requireFinding(t, findings, err, fqn, CatalogFindingCopies)
	})

	t.Run("близнец: запись дословно та же", func(t *testing.T) {
		own := catalogFile(twin, catalogEntry("kacho.cloud.b.v1.B/Get", "b.get"))
		findings, _, err := compareCatalogCopiesWith(nil, nil, edge, own)
		requireSilent(t, findings, err)
	})
}

// TestCatalogParityCatchesMissingAndExtraEntries — ось СОСТАВА перечня, обе
// стороны: запись, которой у нас нет, и запись, которой нет у края.
func TestCatalogParityCatchesMissingAndExtraEntries(t *testing.T) {
	a := catalogEntry("kacho.cloud.a.v1.A/Get", "a.get")
	b := catalogEntry("kacho.cloud.b.v1.B/Get", "b.get")

	t.Run("дефект: запись есть у края, нет у нас", func(t *testing.T) {
		findings, _, err := compareCatalogCopiesWith(nil, nil, catalogFile(a, b), catalogFile(a))
		requireFinding(t, findings, err, "kacho.cloud.b.v1.B/Get", CatalogFindingCopies)
	})

	t.Run("дефект: запись есть у нас, нет у края", func(t *testing.T) {
		findings, _, err := compareCatalogCopiesWith(nil, nil, catalogFile(a), catalogFile(a, b))
		requireFinding(t, findings, err, "kacho.cloud.b.v1.B/Get", CatalogFindingCopies)
	})

	t.Run("близнец: состав тот же", func(t *testing.T) {
		findings, _, err := compareCatalogCopiesWith(nil, nil, catalogFile(a, b), catalogFile(a, b))
		requireSilent(t, findings, err)
	})
}

// TestCatalogParityCatchesUnexplainedRename — ось, ради которой ведомость и
// заведена: переименование, ведомостью НЕ объявленное, остаётся находкой.
// Без этой пробы ведомость была бы маской, а не послаблением.
func TestCatalogParityCatchesUnexplainedRename(t *testing.T) {
	edge := catalogFile(catalogEntry(testEdgeFQN, "platform.demo.subscribe"))
	own := catalogFile(catalogEntry(testOwnFQN, "platform.demo.subscribe"))

	t.Run("дефект: ведомость пуста, переименование не объяснено", func(t *testing.T) {
		findings, _, err := compareCatalogCopiesWith(nil, nil, edge, own)
		requireFinding(t, findings, err, testOwnFQN, CatalogFindingCopies)
	})

	t.Run("близнец: то же переименование ОБЪЯВЛЕНО", func(t *testing.T) {
		findings, _, err := compareCatalogCopiesWith(testRenames(), nil, edge, own)
		requireSilent(t, findings, err)
	})
}

// TestDeclaredRenameExpiresOnItsOwn — САМОИСТЕЧЕНИЕ: запись ведомости, которой
// больше нечего исключать (край догнал), обязана быть находкой. Иначе
// послабление пережило бы свой предмет и никто бы его не снял.
func TestDeclaredRenameExpiresOnItsOwn(t *testing.T) {
	t.Run("дефект: край уже назвал глагол новым именем", func(t *testing.T) {
		caught := catalogFile(catalogEntry(testOwnFQN, "platform.demo.subscribe"))
		findings, census, err := compareCatalogCopiesWith(testRenames(), nil, caught, caught)
		requireFinding(t, findings, err, testEdgeFQN, CatalogFindingLedger)
		if census.RenamesApplied != 0 {
			t.Fatalf("запись, которой нечего исключать, объявлена применённой: %s", census)
		}
	})

	t.Run("близнец: край ещё не догнал — запись при предмете", func(t *testing.T) {
		edge := catalogFile(catalogEntry(testEdgeFQN, "platform.demo.subscribe"))
		own := catalogFile(catalogEntry(testOwnFQN, "platform.demo.subscribe"))
		findings, _, err := compareCatalogCopiesWith(testRenames(), nil, edge, own)
		requireSilent(t, findings, err)
	})
}

// TestDeclaredRenameMustNameOurOwnVerb — вторая сторона ведомости: запись,
// называющая НАШ глагол, которого в нашей копии нет, утверждает о дереве
// неправду. Без этой оси ведомость прощала бы расхождение, к которому она
// отношения не имеет.
func TestDeclaredRenameMustNameOurOwnVerb(t *testing.T) {
	edge := catalogFile(catalogEntry(testEdgeFQN, "platform.demo.subscribe"))

	t.Run("дефект: нашей стороны переименования в дереве нет", func(t *testing.T) {
		own := catalogFile(catalogEntry("corelib.demo.DemoService/Other", "platform.demo.subscribe"))
		findings, _, err := compareCatalogCopiesWith(testRenames(), nil, edge, own)
		requireFinding(t, findings, err, testOwnFQN, CatalogFindingLedger)
	})

	t.Run("близнец: наша сторона на месте", func(t *testing.T) {
		own := catalogFile(catalogEntry(testOwnFQN, "platform.demo.subscribe"))
		findings, _, err := compareCatalogCopiesWith(testRenames(), nil, edge, own)
		requireSilent(t, findings, err)
	})
}

// TestCatalogParityRefusesAnUnknownFileShape — ТРЕТИЙ ИСХОД: форма файла не та,
// что разбирает сверка. Это не «копии совпали» и не находка — о совпадении не
// известно ничего, и сказать надо именно так.
func TestCatalogParityRefusesAnUnknownFileShape(t *testing.T) {
	good := catalogFile(catalogEntry("kacho.cloud.a.v1.A/Get", "a.get"))

	t.Run("дефект: перевода строки в конце нет", func(t *testing.T) {
		broken := strings.TrimSuffix(good, "\n")
		if _, _, err := compareCatalogCopiesWith(nil, nil, broken, good); err == nil {
			t.Fatal("форма файла сменилась, а сверка объявила вердикт")
		}
	})

	t.Run("дефект: запись не разбирается", func(t *testing.T) {
		broken := "[\n  {\n    \"fqn\": не строка\n  }\n]\n"
		if _, _, err := compareCatalogCopiesWith(nil, nil, broken, good); err == nil {
			t.Fatal("неразбираемая запись принята за вердикт")
		}
	})

	t.Run("близнец: форма та самая", func(t *testing.T) {
		findings, _, err := compareCatalogCopiesWith(nil, nil, good, good)
		requireSilent(t, findings, err)
	})
}

// ── ЗАПИСИ, ЖДУЩИЕ КРАЯ (kaname#181) ─────────────────────────────────────────

const testPendingFQN = "kaname.cloud.demo.v1.DemoService/Create"

// testPending — ведомость проб: одна запись того же вида, что действующая.
func testPending() []CatalogPendingEntry {
	return []CatalogPendingEntry{{
		OwnFQN:  testPendingFQN,
		Why:     "синтетика пробы",
		Removal: "край назвал глагол",
		Refs:    "kaname#181",
	}}
}

// TestDeclaredPendingEntryExplainsAnOwnOnlyVerb — ось ВЕДОМОСТИ ОЖИДАЮЩИХ: наша
// запись без пары у края — находка, пока её не объявили; объявленная — молчит.
// Ровно один факт между близнецами: наличие записи в ведомости.
func TestDeclaredPendingEntryExplainsAnOwnOnlyVerb(t *testing.T) {
	a := catalogEntry("kacho.cloud.a.v1.A/Get", "a.get")
	edge := catalogFile(a)
	own := catalogFile(a, catalogEntry(testPendingFQN, "demo.create"))

	t.Run("дефект: наш глагол не объявлен ждущим", func(t *testing.T) {
		findings, _, err := compareCatalogCopiesWith(nil, nil, edge, own)
		requireFinding(t, findings, err, testPendingFQN, CatalogFindingCopies)
	})

	t.Run("близнец: тот же глагол ОБЪЯВЛЕН ждущим края", func(t *testing.T) {
		findings, census, err := compareCatalogCopiesWith(nil, testPending(), edge, own)
		requireSilent(t, findings, err)
		if census.PendingApplied != 1 || census.PendingDeclared != 1 {
			t.Fatalf("перепись не назвала применённую запись: %s", census)
		}
	})

	t.Run("контроль: ведомость выносит ТОЛЬКО объявленное — второй лишний глагол остаётся находкой", func(t *testing.T) {
		own2 := catalogFile(a, catalogEntry("kaname.cloud.demo.v1.DemoService/Other", "demo.other"),
			catalogEntry(testPendingFQN, "demo.create"))
		findings, _, err := compareCatalogCopiesWith(nil, testPending(), edge, own2)
		requireFinding(t, findings, err, "kaname.cloud.demo.v1.DemoService/Other", CatalogFindingCopies)
	})
}

// TestDeclaredPendingEntryExpiresOnItsOwn — САМОИСТЕЧЕНИЕ: край назвал глагол —
// запись обязана уйти (и копия синхронизироваться), а не прощать дальше.
func TestDeclaredPendingEntryExpiresOnItsOwn(t *testing.T) {
	a := catalogEntry("kacho.cloud.a.v1.A/Get", "a.get")
	created := catalogEntry(testPendingFQN, "demo.create")

	t.Run("дефект: край уже несёт глагол, запись стоит", func(t *testing.T) {
		both := catalogFile(a, created)
		findings, census, err := compareCatalogCopiesWith(nil, testPending(), both, both)
		requireFinding(t, findings, err, testPendingFQN, CatalogFindingLedger)
		if census.PendingApplied != 0 {
			t.Fatalf("запись, которой нечего ждать, объявлена применённой: %s", census)
		}
	})

	t.Run("близнец: край ещё не догнал — запись при предмете", func(t *testing.T) {
		findings, _, err := compareCatalogCopiesWith(nil, testPending(), catalogFile(a), catalogFile(a, created))
		requireSilent(t, findings, err)
	})
}

// TestDeclaredPendingEntryMustNameOurOwnVerb — вторая сторона: запись ждёт края
// для глагола, которого в НАШЕЙ копии нет, — она утверждает о дереве неправду.
func TestDeclaredPendingEntryMustNameOurOwnVerb(t *testing.T) {
	a := catalogEntry("kacho.cloud.a.v1.A/Get", "a.get")

	t.Run("дефект: нашей записи нет, ведомость её ждёт", func(t *testing.T) {
		findings, _, err := compareCatalogCopiesWith(nil, testPending(), catalogFile(a), catalogFile(a))
		requireFinding(t, findings, err, testPendingFQN, CatalogFindingLedger)
	})

	t.Run("близнец: наша запись на месте", func(t *testing.T) {
		findings, _, err := compareCatalogCopiesWith(nil, testPending(), catalogFile(a),
			catalogFile(a, catalogEntry(testPendingFQN, "demo.create")))
		requireSilent(t, findings, err)
	})
}
