// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// known_failing_expiry_injection_test.go — способность гейта записей прощения
// упасть И СМОЛЧАТЬ, доказанная БЕЗ сети.
//
// Инъекция идёт ТРЕМЯ прогонами на ОДНОМ контрольном документе, и каждый меняет
// РОВНО ОДИН факт против него:
//
//	контроль         — запись объявлена, задача открыта  → молчат ОБЕ оси;
//	инъекция оси А   — задача ЗАКРЫТА                    → краснеет ТОЛЬКО сверка;
//	инъекция оси Б   — прощение прозой без маркера       → краснеет ТОЛЬКО объявление.
//
// Третий прогон обязателен: без него молчание оси Б в прогоне 2 неотличимо от
// молчания мёртвой оси.
package tools_regression

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/tools/knownfailingexpiry"
)

// controlDoc — документ, у которого целы ОБА свойства: запись объявлена маркером,
// прощений прозой нет.
const controlDoc = `# RESULTS

## Раздел

<!-- known-failing: #4242 — набор demo -->
Набор ` + "`demo`" + ` держит два красных утверждения по этому дефекту.

## Исторический раздел

СНЯТО 2026-08-01 — was: known failing, канарейка over-show (` + "`kacho-iam#276`" + `).
Запись снята вместе со своим предметом.
`

// undeclaredDoc — тот же документ ПЛЮС абзац, объявляющий условие живым и не
// объявивший себя маркером. Дельта одно-фактна: запись #4242 предмета не теряет.
const undeclaredDoc = controlDoc + `
## Ещё раздел

Набор ` + "`other`" + ` остаётся красным, пока не закрыт ` + "`#7777`" + `.
`

func TestInjection_ClosedIssueUnderALiveRecordIsAFinding(t *testing.T) {
	t.Parallel()

	c := knownfailingexpiry.Parse(controlDoc)
	if len(c.Records) != 1 || c.Records[0].Issue != 4242 {
		t.Fatalf("перепись контроля: записей %d (%+v) — ждали одну, #4242",
			len(c.Records), c.Records)
	}
	if c.Paragraphs == 0 || c.Lines == 0 {
		t.Fatalf("контроль прочитан пустым: строк %d, абзацев %d", c.Lines, c.Paragraphs)
	}

	// ── ПРОГОН 1: КОНТРОЛЬ. Задача ОТКРЫТА, прощений прозой нет — молчат обе оси.
	if f := knownfailingexpiry.ClosedUnderALiveRecord(c, map[int]string{4242: "OPEN"}); len(f) != 0 {
		t.Fatalf("контроль: живая запись объявлена просроченной: %v", f)
	}
	if f := knownfailingexpiry.UndeclaredForgiveness(c); len(f) != 0 {
		t.Fatalf("контроль: ось объявления краснеет на целом документе (историческое "+
			"«was: known failing» с номером — законный близнец, он обязан молчать): %v", f)
	}

	// ── ПРОГОН 2: ИНЪЕКЦИЯ ОСИ А. Единственный изменённый факт — состояние задачи.
	fClosed := knownfailingexpiry.ClosedUnderALiveRecord(c, map[int]string{4242: "CLOSED"})
	if len(fClosed) != 1 {
		t.Fatalf("закрытая задача под живой записью не найдена: находок %d (%v)",
			len(fClosed), fClosed)
	}
	if !strings.Contains(fClosed[0], "#4242") {
		t.Fatalf("находка не называет задачу: %q", fClosed[0])
	}
	if !strings.Contains(fClosed[0], "RESULTS.md:5") {
		t.Fatalf("находка не называет координату записи: %q", fClosed[0])
	}
	if f := knownfailingexpiry.UndeclaredForgiveness(c); len(f) != 0 {
		t.Fatalf("инъекция оси А уронила ось Б — дельта не одно-фактна: %v", f)
	}

	// ── ПРОГОН 3: ИНЪЕКЦИЯ ОСИ Б. Единственный изменённый факт — добавлен абзац
	// живого условия без маркера. Задача #4242 по-прежнему открыта.
	cU := knownfailingexpiry.Parse(undeclaredDoc)
	fUndecl := knownfailingexpiry.UndeclaredForgiveness(cU)
	if len(fUndecl) != 1 {
		t.Fatalf("прощение прозой не найдено: находок %d (%v)", len(fUndecl), fUndecl)
	}
	if !strings.Contains(fUndecl[0], "#7777") {
		t.Fatalf("находка не называет задачу: %q", fUndecl[0])
	}
	if f := knownfailingexpiry.ClosedUnderALiveRecord(cU, map[int]string{4242: "OPEN"}); len(f) != 0 {
		t.Fatalf("инъекция оси Б уронила ось А — дельта не одно-фактна: %v", f)
	}
}

// TestInjection_MarkerSuppressesTheBackstop — законный близнец оси Б: тот же
// абзац живого условия, но объявленный маркером, — молчание.
//
// Без этой стороны подстраховка ловила бы «здесь сказано „пока не закрыт"», а не
// «прощение себя не объявило», и объявить запись было бы нечем.
func TestInjection_MarkerSuppressesTheBackstop(t *testing.T) {
	t.Parallel()

	declared := controlDoc + `
## Ещё раздел

<!-- known-failing: #7777 — набор other -->
Набор ` + "`other`" + ` остаётся красным, пока не закрыт ` + "`#7777`" + `.
`
	c := knownfailingexpiry.Parse(declared)
	if len(c.Records) != 2 {
		t.Fatalf("перепись: записей %d — ждали две (#4242 и #7777): %+v", len(c.Records), c.Records)
	}
	if f := knownfailingexpiry.UndeclaredForgiveness(c); len(f) != 0 {
		t.Fatalf("объявленное маркером прощение сочтено необъявленным: %v", f)
	}
	// И оно по-прежнему судится сверкой — объявление не выводит запись из-под неё.
	f := knownfailingexpiry.ClosedUnderALiveRecord(c, map[int]string{4242: "OPEN", 7777: "CLOSED"})
	if len(f) != 1 || !strings.Contains(f[0], "#7777") {
		t.Fatalf("объявленная запись выведена из-под сверки — маркер стал бы способом "+
			"её отключить: %v", f)
	}
}

// TestInjection_MissingIssueCountsAsClosed — номер, которого в трекере нет вовсе,
// решается как ЗАКРЫТЫЙ: запись, ссылающаяся в пустоту, не истечёт никогда.
func TestInjection_MissingIssueCountsAsClosed(t *testing.T) {
	t.Parallel()
	c := knownfailingexpiry.Parse(controlDoc)
	// Состояние неизвестно — молчим: «не сверено» не есть «закрыто».
	if f := knownfailingexpiry.ClosedUnderALiveRecord(c, map[int]string{}); len(f) != 0 {
		t.Fatalf("несверенная запись объявлена просроченной — «не измерено» выдано за "+
			"вердикт: %v", f)
	}
	// А доказанное отсутствие номера трекер отдаёт как CLOSED (см. пробу-провязку).
	if f := knownfailingexpiry.ClosedUnderALiveRecord(c, map[int]string{4242: "CLOSED"}); len(f) != 1 {
		t.Fatalf("запись в пустоту не найдена: %v", f)
	}
}
