// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retired_monorepo_gate_ledger_injection_test.go — доказательство способности
// ведомости упасть И смолчать.
//
// Инъекция герметична: синтетические записи и синтетическое дерево подаются
// прямо в предикат, поэтому роняют ТОЛЬКО проверяемое.
//
// Оси — по одной на каждый исход, который ведомость обязана различать, плюс
// разбор объявлений: имя пробы, НАЗВАННОЕ прозой, держателем не является.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// allSubjectsAlive — подставной ответчик «предмет на месте»: изолирует ось
// держателя от оси предмета, чтобы находка приходила от одного факта, а не от
// двух сразу.
func allSubjectsAlive(string) bool { return true }

// TestRetiredLedgerRedsOnAMigratedEntryWithoutItsHolder — запись «переехал»,
// чей держатель в дереве не объявлен.
func TestRetiredLedgerRedsOnAMigratedEntryWithoutItsHolder(t *testing.T) {
	t.Parallel()
	entries := []retiredGateEntry{{
		family: "somefamily", outcome: retiredMigrated,
		holder: "TestHolderThatWasNeverDeclared", subject: "internal/domain", why: "проба",
	}}
	stale, missing := retiredLedgerFindings(entries, map[string]bool{"TestSomethingElse": true},
		allSubjectsAlive)
	if len(stale) != 0 {
		t.Fatalf("ось самоистечения сработала не на своём входе: %v", stale)
	}
	if len(missing) != 1 {
		t.Fatalf("запись «переехал» без держателя НЕ стала находкой: %d — ведомость "+
			"объявляла бы перенесённым то, чего в дереве нет", len(missing))
	}
	for _, want := range []string{"somefamily", "TestHolderThatWasNeverDeclared"} {
		if !strings.Contains(missing[0], want) {
			t.Errorf("находка не называет %q: %q", want, missing[0])
		}
	}
}

// TestRetiredLedgerRedsOnARemainsEntryWhoseHolderExists — САМОИСТЕЧЕНИЕ:
// запись «остаётся», чей держатель в дереве уже есть.
//
// Эта ось несущая. Без неё ведомость пережила бы свой предмет молча: гейт
// переехал бы, а строка продолжала держать работу, которой нет.
func TestRetiredLedgerRedsOnARemainsEntryWhoseHolderExists(t *testing.T) {
	t.Parallel()
	entries := []retiredGateEntry{{
		family: "listscanobservability", outcome: retiredRemains,
		holder: "TestRefillLoopReportsItsScan", subject: "internal/domain", why: "проба",
	}}
	stale, missing := retiredLedgerFindings(entries,
		map[string]bool{"TestRefillLoopReportsItsScan": true}, allSubjectsAlive)
	if len(missing) != 0 {
		t.Fatalf("ось предмета сработала не на своём входе: %v", missing)
	}
	if len(stale) != 1 {
		t.Fatalf("запись «остаётся» при ЖИВОМ держателе НЕ стала находкой: %d — "+
			"ведомость удерживала бы работу, которая уже сделана", len(stale))
	}
	if !strings.Contains(stale[0], "listscanobservability") {
		t.Errorf("находка не называет семейство: %q", stale[0])
	}
}

// TestRetiredLedgerRedsOnADeadSubject — запись, чей предмет из дерева исчез.
func TestRetiredLedgerRedsOnADeadSubject(t *testing.T) {
	t.Parallel()
	entries := []retiredGateEntry{{
		family: "somefamily", outcome: retiredRemains,
		holder: "TestNotDeclaredHere", subject: "internal/gone/away.go", why: "проба",
	}}
	_, missing := retiredLedgerFindings(entries, map[string]bool{}, func(string) bool { return false })
	if len(missing) != 1 {
		t.Fatalf("запись с мёртвым предметом НЕ стала находкой: %d — семейство перестало "+
			"быть нашим, а ведомость продолжала бы числить его в остатке", len(missing))
	}
	if !strings.Contains(missing[0], "internal/gone/away.go") {
		t.Errorf("находка не называет координату предмета: %q", missing[0])
	}
}

// TestRetiredLedgerStaysSilentOnCorrectEntries — ЗАКОННЫЕ БЛИЗНЕЦЫ: обе формы
// записи в верном состоянии дают молчание.
func TestRetiredLedgerStaysSilentOnCorrectEntries(t *testing.T) {
	t.Parallel()
	entries := []retiredGateEntry{
		{family: "moved", outcome: retiredMigrated, holder: "TestMovedHolder",
			subject: "internal/domain", why: "проба"},
		{family: "waiting", outcome: retiredRemains, holder: "TestNotHereYet",
			subject: "internal/domain", why: "проба"},
	}
	stale, missing := retiredLedgerFindings(entries, map[string]bool{"TestMovedHolder": true},
		allSubjectsAlive)
	if len(stale) != 0 || len(missing) != 0 {
		t.Fatalf("ведомость краснеет на верном состоянии: stale=%v missing=%v", stale, missing)
	}
}

// TestDeclaredFuncScanCountsDeclarationsNotMentions — имя пробы, НАЗВАННОЕ
// прозой или строкой, держателем не является.
//
// Ось несущая: в этом дереве имена проб стоят в приёмках, в комментариях о том,
// чем держится свойство, и в самой ведомости. Подстрочный разбор объявил бы
// держателя живым по упоминанию — ведомость доказывала бы сама себя.
func TestDeclaredFuncScanCountsDeclarationsNotMentions(t *testing.T) {
	t.Parallel()

	t.Run("объявление засчитывается", func(t *testing.T) {
		const src = `package check_test

func TestSomethingHolds(t *testing.T) {}
`
		names, census, err := check.ScanDeclaredFuncNames("internal/check/x_test.go", []byte(src))
		if err != nil {
			t.Fatalf("разбор: %v", err)
		}
		if !names["TestSomethingHolds"] {
			t.Fatalf("объявление пробы НЕ засчитано — ведомость не найдёт ни одного "+
				"держателя: %+v", names)
		}
		if census.Tests != 1 {
			t.Errorf("перепись проб: %d, ожидалась 1", census.Tests)
		}
	})

	t.Run("упоминание в комментарии и строке НЕ засчитывается", func(t *testing.T) {
		const src = `package check_test

// Свойство держит TestSomethingHolds — см. приёмку.
const why = "держатель: TestSomethingHolds"

func helper() string { return why }
`
		names, census, err := check.ScanDeclaredFuncNames("internal/check/x_test.go", []byte(src))
		if err != nil {
			t.Fatalf("разбор: %v", err)
		}
		if names["TestSomethingHolds"] {
			t.Fatalf("упоминание засчитано ОБЪЯВЛЕНИЕМ — ведомость доказывала бы сама " +
				"себя: имя держателя стоит в её же строках")
		}
		// положительный контроль: файл РАЗОБРАН, а не пропущен.
		if census.Decls == 0 {
			t.Fatalf("положительный контроль не выполнен: объявлений прочитано 0 — "+
				"отрицание выше зеленело бы на пустом разборе: %+v", census)
		}
	})

	t.Run("метод объявлением пробы не является", func(t *testing.T) {
		const src = `package check_test

type suite struct{}

func (s suite) TestSomethingHolds() {}
`
		names, _, err := check.ScanDeclaredFuncNames("internal/check/x_test.go", []byte(src))
		if err != nil {
			t.Fatalf("разбор: %v", err)
		}
		if names["TestSomethingHolds"] {
			t.Fatalf("метод засчитан объявлением пробы — держателем он не является")
		}
	})

	t.Run("неразобранный файл — отказ, а не «объявлений нет»", func(t *testing.T) {
		if _, _, err := check.ScanDeclaredFuncNames("internal/broken.go",
			[]byte("package \x00 {{{")); err == nil {
			t.Fatalf("разбор неразобранного файла вернул успех — его молчание " +
				"неотличимо от «держателя нет»")
		}
	})
}

// TestRetiredLedgerCorpusArithmetic — храповик чисел корпуса.
func TestRetiredLedgerCorpusArithmetic(t *testing.T) {
	t.Parallel()
	if retiredAdjudicatedEarlier+retiredLedgerFamilies != retiredCorpusFamilies {
		t.Fatalf("%d + %d != %d — есть семейства, чей исход не назван нигде",
			retiredAdjudicatedEarlier, retiredLedgerFamilies, retiredCorpusFamilies)
	}
	if retiredCorpusFiles < retiredCorpusFamilies {
		t.Fatalf("носителей %d меньше семейств %d — единица счёта перепутана",
			retiredCorpusFiles, retiredCorpusFamilies)
	}
	if len(retiredGateLedger) != retiredLedgerFamilies {
		t.Fatalf("перечень %d, объявлено %d", len(retiredGateLedger), retiredLedgerFamilies)
	}
	seen := map[string]bool{}
	for _, e := range retiredGateLedger {
		if seen[e.family] {
			t.Errorf("семейство %q названо дважды — перепись завышена", e.family)
		}
		seen[e.family] = true
		if e.family == "" || e.holder == "" || e.subject == "" || e.why == "" {
			t.Errorf("запись неполна: %+v", e)
		}
	}
}
