// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// documented_setting_key_exists.go — ОПИСЬ НАСТРОЕК В ПРОЗЕ НЕ ПЕРЕЖИВАЕТ СВОЙ
// ПРЕДМЕТ: всякий ключ, названный описью инженерной документации, существует в
// дереве настроек службы.
//
// # ПРЕДМЕТ
//
// Опись — таблица «переменная · ключ настройки · умолчание · описание» — живёт
// в прозе и НЕ исполняется. Настройка тем временем переезжает: группа
// `extapi.*` ушла целиком (`internal/apps/kaname/config/mode.go` объявляет её
// группой, «которой в настройке НЕТ ни одной ручки»), ручки поставщика личности
// переехали под `authn.*`. Опись осталась прежней — и читается как
// действительность.
//
// Цена не гипотетическая, и одна из строк дороже прочих: опись называла YAML-
// ключ ДЛЯ ПРЕДЪЯВИТЕЛЯ (`extapi.hydra.admin-token`). Ключа нет, а оператор,
// прочитавший опись, пишет предъявитель в YAML — то есть в файл посадки, где
// секрету не место. Ложная опись здесь не просто устарела: она ПРИГЛАШАЕТ
// сделать то, что справочник посадки прямо запрещает.
//
// # РАСПОЗНАВАТЕЛЬ — ОБЪЯВЛЕННАЯ КОЛОНКА, А НЕ ФОРМА ТОКЕНА
//
// Судится не «всё, что похоже на ключ»: в этом корпусе точкой разделены имена
// Go (`authz.go`, `logger.Warn`), поля JSON (`invite.mailRateLimit`), маски
// (`authn.*`) и пары `ключ: значение`. Измерено на этом дереве: токенов вида
// `<секция>.<что-то>` в прозе 107, из них НЕ ключей настройки 36 — то есть
// треть, и почти вся она законна.
//
// Поэтому судится то, что объявило СЕБЯ описью: колонка таблицы, чей заголовок
// называет ключ настройки. Автор описи утверждает «вот ключ» — это утверждение
// и проверяется.
//
// Промах словаря заголовков не даёт молчания: всякий заголовок, несущий слово
// `yaml` и НЕ опознанный, печатается переписью с координатой. Новое написание
// колонки видно числом, а не отсутствием вопроса.
//
// # АВТОРИТЕТ КЛЮЧЕЙ — ПРОИЗВОДИТЕЛЬ, А НЕ ПЕРЕЧЕНЬ
//
// Множество ключей приходит ПАРАМЕТРОМ и берётся у структуры настроек по её
// разметке `mapstructure` (проба строит его отражением от `config.Config`).
// Выписанный здесь перечень разошёлся бы с настройкой молча — на той строке,
// которую забыли поправить, то есть ровно на классе, который гейт и ловит.
//
// # ГРАНИЦЫ — НАЗВАНЫ, ЧТОБЫ ГЕЙТ НЕ ЧИТАЛИ ШИРЕ
//
//  1. Ключ, названный в прозе ВНЕ объявленной колонки, не судится. Это не
//     упущение, а цена отказа от формы токена (см. выше); число неосмотренных
//     токенов названо там же.
//  2. ИСТИННОСТЬ умолчания и описания не судится: здесь держится
//     СУЩЕСТВОВАНИЕ ключа, то есть возможность его перемерить.
//  3. Ячейка без токена ключевой формы (`—`, «нет», проза) — не находка:
//     автор ключа не назвал. Такие строки печатаются отдельной величиной, а не
//     растворяются в зелёном.
package check

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// settingKeyColumnNames — написания заголовка колонки, объявляющей ключ
// настройки. Словарь ЗАКРЫТ, и его промах виден переписью (`UnnamedYAMLHeaders`),
// а не молчанием.
var settingKeyColumnNames = map[string]bool{
	"yaml key":       true,
	"yaml-key":       true,
	"yaml ключ":      true,
	"yaml-ключ":      true,
	"ключ yaml":      true,
	"ключ настройки": true,
	"setting key":    true,
	"config key":     true,
}

// settingKeyToken — форма токена ключа настройки: строчные сегменты через
// точку, дефис внутри сегмента. `authn.hydra-admin-url`, `manifests`,
// `jobs.catalog-snapshot.refresh-interval`.
var settingKeyToken = regexp.MustCompile(`^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)*$`)

// tableSeparator — вторая строка таблицы markdown: только `|`, `-`, `:` и
// пробелы. Именно она отличает ЗАГОЛОВОК от обычной строки.
var tableSeparator = regexp.MustCompile(`^\s*\|[\s:|-]+\|\s*$`)

// SettingKeyFinding — ключ, названный описью и отсутствующий в настройке.
type SettingKeyFinding struct {
	// File — путь документа от корня дерева.
	File string
	// Line — номер строки описи, 1-based.
	Line int
	// Key — ключ, как его назвала опись.
	Key string
	// Nearest — ближайший существующий ключ по общему началу; пусто, если
	// общего начала нет. Находка называет, ЧЕМ чинить, а не только что сломано.
	Nearest string
}

func (f SettingKeyFinding) String() string {
	s := fmt.Sprintf("%s:%d: опись называет ключ настройки %q, которого в дереве настроек НЕТ",
		f.File, f.Line, f.Key)
	if f.Nearest != "" {
		return s + fmt.Sprintf(" (ближайший существующий — %q)", f.Nearest)
	}
	return s + " (ключа с таким началом в настройке нет вовсе)"
}

// SettingKeyCensus — объём осмотренного. «Находок ноль» читается только рядом с
// ним: ноль описей и ноль прочитанных документов — разные вердикты.
type SettingKeyCensus struct {
	// Files — документов прочитано.
	Files int
	// Tables — таблиц с объявленной колонкой ключа найдено.
	Tables int
	// Rows — строк таблиц осмотрено.
	Rows int
	// RowsWithoutKey — строк, где ключ не назван (`—`, проза): граница, не находка.
	RowsWithoutKey int
	// Matched — ключей, найденных в настройке.
	Matched int
	// Keys — величина множества ключей, полученного от производителя.
	Keys int
	// UnnamedYAMLHeaders — заголовки со словом `yaml`, словарём НЕ опознанные,
	// с координатой. Промах словаря обязан быть виден числом.
	UnnamedYAMLHeaders []string
}

func (c SettingKeyCensus) String() string {
	s := fmt.Sprintf("документов прочитано %d · описей найдено %d · строк осмотрено %d "+
		"(из них без ключа %d — граница) · ключей сошлось %d · ключей в настройке %d",
		c.Files, c.Tables, c.Rows, c.RowsWithoutKey, c.Matched, c.Keys)
	if len(c.UnnamedYAMLHeaders) > 0 {
		s += fmt.Sprintf(" · заголовков со словом yaml, словарём не опознанных: %d %v",
			len(c.UnnamedYAMLHeaders), c.UnnamedYAMLHeaders)
	}
	return s
}

// normalizeHeaderCell — ячейка заголовка к виду для сравнения: без разметки,
// строчными, с одиночными пробелами.
func normalizeHeaderCell(cell string) string {
	s := strings.ToLower(cell)
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, "*", "")
	return strings.Join(strings.Fields(s), " ")
}

// splitRow — ячейки строки таблицы markdown. Обрамляющие `|` отбрасываются.
func splitRow(line string) []string {
	s := strings.TrimSpace(line)
	s = strings.TrimPrefix(s, "|")
	s = strings.TrimSuffix(s, "|")
	parts := strings.Split(s, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// keyTokensOf — токены ключевой формы в ячейке описи. Пусто означает «автор
// ключа не назвал», а не «ключ неверен».
func keyTokensOf(cell string) []string {
	s := strings.ReplaceAll(cell, "`", " ")
	s = strings.ReplaceAll(s, "*", " ")
	s = strings.ReplaceAll(s, "/", " ")
	s = strings.ReplaceAll(s, ",", " ")
	var out []string
	for _, f := range strings.Fields(s) {
		f = strings.Trim(f, ".;:()")
		if settingKeyToken.MatchString(f) {
			out = append(out, f)
		}
	}
	return out
}

// nearestKey — существующий ключ с самым длинным общим началом. Подсказка, а не
// вердикт: пусто, когда общего начала нет.
func nearestKey(key string, keys map[string]bool) string {
	best, bestLen := "", 0
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		n := 0
		for n < len(k) && n < len(key) && k[n] == key[n] {
			n++
		}
		if n > bestLen {
			best, bestLen = k, n
		}
	}
	if bestLen < 3 {
		return ""
	}
	return best
}

// JudgeDocumentedSettingKeys — тело гейта над прочитанным. Инъекция зовёт ЕГО
// же, поэтому и корпус, и множество ключей приходят параметрами.
//
// ТРИ ИСХОДА: вердикт · отказ предпосылки (ключей ноль — судить не по чему) ·
// пустая ведомость (описей ноль) — и последняя ЗЕЛЁНАЯ: это цель, а не провал.
func JudgeDocumentedSettingKeys(corpus TreeCorpus, keys map[string]bool) ([]SettingKeyFinding, SettingKeyCensus, error) {
	census := SettingKeyCensus{Keys: len(keys)}
	if len(keys) == 0 {
		return nil, census, fmt.Errorf("предпосылка не выполнена: множество ключей настройки " +
			"пусто — всякая опись была бы находкой, и «находок много» означало бы «читать не по чему»")
	}
	if len(corpus) == 0 {
		return nil, census, fmt.Errorf("%w — документов прочитано ноль", ErrEmptyTraversal)
	}

	var findings []SettingKeyFinding
	for _, rel := range corpus.Rels() {
		census.Files++
		lines := strings.Split(corpus[rel], "\n")
		for i := 0; i+1 < len(lines); i++ {
			if !strings.HasPrefix(strings.TrimSpace(lines[i]), "|") || !tableSeparator.MatchString(lines[i+1]) {
				continue
			}
			header := splitRow(lines[i])
			col := -1
			for idx, cell := range header {
				norm := normalizeHeaderCell(cell)
				if settingKeyColumnNames[norm] {
					col = idx
					continue
				}
				if strings.Contains(norm, "yaml") {
					census.UnnamedYAMLHeaders = append(census.UnnamedYAMLHeaders,
						fmt.Sprintf("%s:%d %q", rel, i+1, norm))
				}
			}
			if col < 0 {
				continue
			}
			census.Tables++
			for j := i + 2; j < len(lines); j++ {
				if !strings.HasPrefix(strings.TrimSpace(lines[j]), "|") {
					break
				}
				row := splitRow(lines[j])
				if col >= len(row) {
					census.Rows++
					census.RowsWithoutKey++
					continue
				}
				census.Rows++
				tokens := keyTokensOf(row[col])
				if len(tokens) == 0 {
					census.RowsWithoutKey++
					continue
				}
				for _, tok := range tokens {
					if keys[tok] {
						census.Matched++
						continue
					}
					findings = append(findings, SettingKeyFinding{
						File: rel, Line: j + 1, Key: tok, Nearest: nearestKey(tok, keys)})
				}
			}
		}
	}
	return findings, census, nil
}
