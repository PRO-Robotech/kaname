// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// settings.go — ПОРОЖДЕНИЕ перечня обязательных величин в документ установки из
// таблицы, которую доказывает прогоном сам страж старта.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ БЛОК, А НЕ ВЕСЬ ФАЙЛ
//
// Документ установки — проза для человека: порядок действий, ловушки, что делать
// при отказе. Порождать его целиком значило бы порождать прозу, которую никто не
// напишет. Порождается ровно то, что обязано сходиться со стражем, — таблица
// величин; она обведена метками, и правка внутри меток уедет при регенерации.
//
// Проза вокруг блока свободна и НЕ сверяется: гейт судит согласие таблицы со
// стражем, а не качество объяснений.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ДЕЛАЕТ БЛОК ПОЛЕЗНЫМ ИМЕННО ОПЕРАТОРУ
//
// Колонка «как задать» — не украшение. У трёх ключей путь через переменную
// окружения НЕ РАБОТАЛ, при том что текст отказа стража называл именно
// переменную: оператор, повторивший имя из отказа, получал тот же отказ снова
// (задача #2040, ключи привязаны). Сегодня файлом не ограничен ни один ключ, и
// колонка это ПЕЧАТАЕТ — а не подразумевает: перепись ниже несёт величину
// «подаются только файлом», поэтому её возврат к ненулю будет виден в выводе
// цели сборки, а не обнаружится оператором на стенде.
//
// Что колонка доказывает прогоном: полный профиль, собранный ОБЪЯВЛЕННЫМИ ею
// путями, проходит стража целиком (таблица `config.RequiredSettings`, проба
// `TestRequiredSettings_TableCannotLie`, утверждение Т2).
package operatordocs

import (
	"fmt"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
)

// Метки блока. Порождённое лежит СТРОГО между ними; всё прочее — проза автора.
const (
	SettingsBeginMarker = "<!-- ПОРОЖДЕНО: обязательные величины — начало -->"
	SettingsEndMarker   = "<!-- ПОРОЖДЕНО: обязательные величины — конец -->"
)

// SettingsCensus — объём осмотренного.
type SettingsCensus struct {
	Rows      int
	ByLane    map[string]int
	BySupply  map[string]int
	Anywhere  int
	FileOnly  int
	Condition int
}

func (c SettingsCensus) String() string {
	lanes := make([]string, 0, len(c.ByLane))
	for l := range c.ByLane {
		lanes = append(lanes, l)
	}
	sort.Strings(lanes)
	parts := make([]string, 0, len(lanes))
	for _, l := range lanes {
		parts = append(parts, fmt.Sprintf("%s %d", l, c.ByLane[l]))
	}
	return fmt.Sprintf("строк %d · на любой посадке %d · полосных: %s · подаются только файлом %d · условных %d",
		c.Rows, c.Anywhere, strings.Join(parts, ", "), c.FileOnly, c.Condition)
}

// BuildSettingsBlock рендерит блок обязательных величин из таблицы стража.
func BuildSettingsBlock(table []config.RequiredSetting) (string, []string, SettingsCensus) {
	var findings []string
	census := SettingsCensus{Rows: len(table), ByLane: map[string]int{}, BySupply: map[string]int{}}

	if len(table) == 0 {
		return "", []string{"таблица обязательных величин пуста — порождённый блок был бы пуст молча"}, census
	}

	var b strings.Builder
	b.WriteString(SettingsBeginMarker)
	b.WriteString("\n\n")
	b.WriteString("Перечень порождён из таблицы стража старта и сверяется гейтом: страж изменится — ")
	b.WriteString("этот блок перестанет сходиться, и прогон покраснеет.\n\n")
	b.WriteString("| Ключ настройки | Как задать | Когда обязателен | Почему без неё не пускаемся |\n")
	b.WriteString("|---|---|---|---|\n")

	for _, s := range table {
		lanes := s.LaneNames()
		when := "на любой посадке"
		if len(lanes) > 0 {
			when = "посадка `" + strings.Join(lanes, "` либо `") + "`"
			for _, l := range lanes {
				census.ByLane[l]++
			}
		} else {
			census.Anywhere++
		}
		if s.Conditional {
			when += ", при выполненном условии"
			census.Condition++
		}

		var how string
		switch s.Supply {
		case config.SupplyEnv:
			how = "переменная `" + s.Env + "`"
			census.BySupply["окружение"]++
		case config.SupplyFile:
			census.FileOnly++
			census.BySupply["файл"]++
			how = "**только файлом настроек** — ключ `" + s.Key + "`."
			if strings.TrimSpace(s.Env) != "" {
				how += " Переменная `" + s.Env + "` до поля **не доезжает**, хотя её называет текст отказа"
			}
		default:
			findings = append(findings, s.Key+": неизвестный путь подачи — оператору нечего сказать")
			how = "—"
		}

		if strings.TrimSpace(s.Why) == "" {
			findings = append(findings, s.Key+": в таблице не сказано, почему величина обязательна")
		}

		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", s.Key, how, when, oneLine(s.Why))
	}

	b.WriteString("\n")
	b.WriteString(SettingsEndMarker)
	return b.String(), findings, census
}

// oneLine складывает многострочное объяснение в одну строку таблицы: перенос
// внутри ячейки разрушил бы разметку.
func oneLine(s string) string {
	f := strings.Join(strings.Fields(s), " ")
	return strings.ReplaceAll(f, "|", "\\|")
}

// SpliceBlock подставляет порождённый блок между метками существующего
// документа. Возвращает ошибку, если меток нет либо они стоят не по порядку:
// молча дописать блок в конец значило бы завести второе место об одном
// предмете.
func SpliceBlock(doc, block string) (string, error) {
	i := strings.Index(doc, SettingsBeginMarker)
	if i < 0 {
		return "", fmt.Errorf("в документе нет метки начала %q — порождать некуда", SettingsBeginMarker)
	}
	j := strings.Index(doc, SettingsEndMarker)
	if j < 0 {
		return "", fmt.Errorf("в документе нет метки конца %q — порождать некуда", SettingsEndMarker)
	}
	if j < i {
		return "", fmt.Errorf("метки блока стоят не по порядку: конец раньше начала")
	}
	if k := strings.Index(doc[i+len(SettingsBeginMarker):], SettingsBeginMarker); k >= 0 {
		return "", fmt.Errorf("метка начала встречается дважды — блоков об одном предмете два, и они разойдутся молча")
	}
	return doc[:i] + block + doc[j+len(SettingsEndMarker):], nil
}
