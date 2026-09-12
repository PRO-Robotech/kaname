// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// carried_coordinate_ledger.go — разбор ведомости координат, переносимых до
// снятия внешнего провайдера аутентификации клиента (приёмка F2, сценарий
// F2-46, §9.4).
//
// Порт с монорепо (`internal/repohygiene/carriedcoordinateledger.go`, снят
// вынесением службы — `kacho#2597`). Осталось дословно: имя функции гейта
// (`TestCarriedCoordinateLedgerExpiresOnItsOwn`), сам разбор и словарь
// исходов. Изменилось: путь ведомости без префикса `services/iam/`
// (`docs/engineering/architecture/client-assertion-carried-over-coordinates.md`)
// и область зеркальной колонки — раньше сужалась до `services/iam/` внутри
// монорепо, теперь это ВЕСЬ репозиторий службы (у неё нет больше соседей по
// дереву). Ведомость службы, будучи скопирована целиком, несла координаты со
// старым префиксом `services/iam/` — они не резолвились НИ ОДНА (кросс-репо
// staleness, а не намеренное послабление); исправлено тем же изменением,
// которым перенесён гейт.
//
// # Предмет
//
// Фаза F2 завела принимающую сторону и ничего не сносит. У каждой координаты,
// дожившей до снятия внешнего провайдера, обязан быть назван исход из
// закрытого словаря; четвёртого — «осталось как есть, потому что не
// заметили» — не существует. У исхода «оставлено» обязан быть ПРЕДИКАТ
// СНЯТИЯ.
//
// # Гейт двусторонний
//
//   - ПОЛНОТА: координата, живущая в дереве и не названная ведомостью, —
//     находка;
//   - САМОИСТЕЧЕНИЕ: запись, чьей координаты в дереве больше нет, — находка.
//
// # Кросс-репо координата — вне суждения ОБОИХ сторон
//
// Ведомость несёт координаты не только своего репозитория (напр.
// `services/registry/...` — сервис реестра остался в монорепо продукта, а не
// уехал со службой доступа). Такую координату этот гейт не проверяет НИ
// ПОЛНОТОЙ, ни САМОИСТЕЧЕНИЕМ: он не может ни подтвердить, ни опровергнуть
// существование файла в ЧУЖОМ репозитории. «В скоупе» решает первый сегмент
// пути — совпадает с одним из ФАКТИЧЕСКИ отслеживаемых верхних каталогов
// своего дерева.
package check

import (
	"fmt"
	"sort"
	"strings"
)

// Закрытый словарь исходов.
const (
	// CarriedOutcomeKept — оставлено как путь к прежнему контуру. ТОЛЬКО этот
	// исход требует предиката снятия.
	CarriedOutcomeKept = "оставлено"
	// CarriedOutcomeRemoved — снято.
	CarriedOutcomeRemoved = "снято"
	// CarriedOutcomeRewritten — переписано на наш идентификатор.
	CarriedOutcomeRewritten = "переписано"
	// CarriedOutcomeNotSubject — предметом не является.
	CarriedOutcomeNotSubject = "не предмет"
)

// carriedOutcomeVocabulary — закрытый словарь в порядке проверки. «не
// предмет» стоит первым намеренно: он длиннее прочих и содержал бы их, будь
// порядок иным.
var carriedOutcomeVocabulary = []string{
	CarriedOutcomeNotSubject,
	CarriedOutcomeRewritten,
	CarriedOutcomeRemoved,
	CarriedOutcomeKept,
}

// CarriedLedgerRow — строка ведомости.
type CarriedLedgerRow struct {
	Section     string
	Line        int
	Coordinate  string
	Outcome     string
	OutcomeCell string
}

// CarriedLedgerSection — раздел документа.
type CarriedLedgerSection struct {
	Title               string
	Line                int
	HasRemovalPredicate bool
}

// CarriedLedgerCensus — объём осмотренного.
type CarriedLedgerCensus struct {
	Lines                 int
	Sections              int
	Tables                int
	Rows                  int
	RowsWithoutCoordinate int
}

// ParseCarriedCoordinateLedger разбирает ведомость.
func ParseCarriedCoordinateLedger(body string) (
	[]CarriedLedgerRow, map[string]CarriedLedgerSection, CarriedLedgerCensus,
) {
	var (
		rows     []CarriedLedgerRow
		census   CarriedLedgerCensus
		sections = map[string]CarriedLedgerSection{}
	)
	lines := strings.Split(body, "\n")
	census.Lines = len(lines)

	section := ""
	coordCol, outcomeCol := -1, -1
	inFence := false

	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		if strings.HasPrefix(line, "#") {
			title := strings.TrimLeft(line, "# ")
			section = title
			census.Sections++
			sections[title] = CarriedLedgerSection{Title: title, Line: i + 1}
			coordCol, outcomeCol = -1, -1
			continue
		}
		if section != "" && carriedMentionsRemovalPredicate(line) {
			s := sections[section]
			s.HasRemovalPredicate = true
			sections[section] = s
		}
		if !strings.HasPrefix(line, "|") {
			coordCol, outcomeCol = -1, -1
			continue
		}
		cells := carriedSplitRow(line)
		if carriedIsDelimiterRow(cells) {
			continue
		}
		if coordCol < 0 && outcomeCol < 0 {
			for idx, c := range cells {
				lc := strings.ToLower(c)
				switch {
				case strings.Contains(lc, "координат"):
					coordCol = idx
				case strings.Contains(lc, "исход"):
					outcomeCol = idx
				}
			}
			if coordCol >= 0 && outcomeCol >= 0 {
				census.Tables++
			}
			continue
		}
		if coordCol < 0 || outcomeCol < 0 || coordCol >= len(cells) || outcomeCol >= len(cells) {
			continue
		}
		census.Rows++
		row := CarriedLedgerRow{
			Section:     section,
			Line:        i + 1,
			Coordinate:  carriedInlineCode(cells[coordCol]),
			OutcomeCell: cells[outcomeCol],
			Outcome:     carriedOutcomeOf(cells[outcomeCol]),
		}
		if row.Coordinate == "" {
			census.RowsWithoutCoordinate++
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Line < rows[j].Line })
	return rows, sections, census
}

func carriedMentionsRemovalPredicate(line string) bool {
	return strings.Contains(strings.ToLower(line), "предикат снятия")
}

func carriedSplitRow(line string) []string {
	trimmed := strings.Trim(line, "|")
	parts := strings.Split(trimmed, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

func carriedIsDelimiterRow(cells []string) bool {
	if len(cells) == 0 {
		return false
	}
	for _, c := range cells {
		if c == "" {
			continue
		}
		if strings.Trim(c, "-: ") != "" {
			return false
		}
	}
	return true
}

func carriedInlineCode(cell string) string {
	first := strings.Index(cell, "`")
	if first < 0 {
		return ""
	}
	rest := cell[first+1:]
	last := strings.Index(rest, "`")
	if last < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:last])
}

func carriedOutcomeOf(cell string) string {
	lc := strings.ToLower(cell)
	for _, o := range carriedOutcomeVocabulary {
		if strings.Contains(lc, o) {
			return o
		}
	}
	return ""
}

// AdjudicateCarriedLedger — что не так с ведомостью относительно дерева.
//
// treeHas — состав дерева; inScope — координата принадлежит СВОЕМУ
// репозиторию и подлежит суждению (кросс-репо путь пропускается обеими
// проверками — ни полнотой, ни самоистечением: этот гейт не может судить
// чужой репозиторий); mustBeNamed — координаты, которые ведомость обязана
// назвать.
func AdjudicateCarriedLedger(
	ledgerPath string,
	rows []CarriedLedgerRow,
	sections map[string]CarriedLedgerSection,
	treeHas func(string) bool,
	inScope func(string) bool,
	mustBeNamed []string,
) []string {
	var findings []string

	for _, r := range rows {
		if r.Outcome == "" {
			findings = append(findings, fmt.Sprintf(
				"%s:%d — исход %q вне закрытого словаря %v. «Прочее» не является корзиной "+
					"приёма", ledgerPath, r.Line, r.OutcomeCell, carriedOutcomeVocabulary))
			continue
		}
		if r.Coordinate == "" {
			findings = append(findings, fmt.Sprintf(
				"%s:%d — запись с исходом %q БЕЗ координаты. По прозе нельзя ни перейти, ни "+
					"проверить, что переносить ещё есть что", ledgerPath, r.Line, r.Outcome))
		}
	}

	for _, r := range rows {
		if r.Outcome != CarriedOutcomeKept || sections[r.Section].HasRemovalPredicate {
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"%s:%d — %q оставлено, а раздел «%s» предиката снятия не объявляет. Послабление, "+
				"которое не умеет истечь, переживает свой предмет",
			ledgerPath, r.Line, r.Coordinate, r.Section))
	}

	for _, r := range rows {
		if r.Coordinate == "" || r.Outcome != CarriedOutcomeKept || !inScope(r.Coordinate) {
			continue
		}
		if treeHas(r.Coordinate) {
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"%s:%d — %q оставлено, а координаты в дереве НЕТ. Записи больше нечего переносить: "+
				"она объявляет живым закрытый долг. Снятие: убрать запись тем же изменением, "+
				"которым ушла координата", ledgerPath, r.Line, r.Coordinate))
	}

	named := map[string]bool{}
	for _, r := range rows {
		if r.Coordinate != "" {
			named[r.Coordinate] = true
		}
	}
	for _, f := range mustBeNamed {
		if named[f] {
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"%s читает зеркальную колонку и в ведомости НЕ НАЗВАН. Это и есть четвёртый исход, "+
				"которого не существует: «осталось как есть, потому что не заметили»", f))
	}

	sort.Strings(findings)
	return findings
}
