// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// migration_role_subtable_writer_emits.go — разбор миграций для гейта §3.2а
// приёмки `catalog-consequence-reaches-role-readers.md` (kaname#76): раздел
// миграции, пишущий подтаблицы роли, зовёт функцию события «состав роли
// изменился» в том же разделе.
//
// # Предмет
//
// Подтаблицы роли (`role_verb`, `role_rule_ref`, `role_rule_selectors`)
// триггеров события не несут (решение #73): холостой подъём переписывает их
// целиком. Поэтому путь, меняющий состав роли без записи её строки, обязан
// звать функцию `kaname.resource_journal_emit_role_composition` сам — иначе
// отзыв права подписчику не виден. Путь последствий каталога держат пробы
// применителя; миграции — этот гейт.
//
// # Популяция и её граница — ВЫВОДЯТСЯ
//
// Популяция — файлы цепочки, чья версия больше версии миграции, заводящей
// функцию; та узнаётся по исполняемому `CREATE [OR REPLACE] FUNCTION` с этим
// именем, а не выписывается. Цепочка без неё — отказ: границу вывести не из
// чего, и молчание гейта было бы ни о чём. Писатели НИЖЕ границы печатаются
// поимённо: их набор неподвижен, и его сдвиг означает слепоту разбора.
//
// # Единица суждения — РАЗДЕЛ `goose`, а не файл
//
// `Up` и `Down` — два разных применения. Раздел — текст до маркера `Down` и
// после него; запись в одном разделе при вызове в другом — находка.
//
// # Что судится текстом и в каком виде
//
// Исполняемая часть: комментарии `--` и `/* */` сняты, кавычки идентификаторов
// сняты, регистр сведён, тела строковых литералов вынуты отдельно. Тела в
// долларовых кавычках (`DO $$ … $$`, тела подпрограмм) судятся как код: в них
// стоит исполняемый SQL. Формы записи — все, какие есть у Postgres для строк
// таблицы: `INSERT INTO`, `DELETE FROM`, `UPDATE`, `MERGE INTO` (каждая с
// `ONLY` и без), `TRUNCATE [TABLE]` списком, `COPY … FROM`; имя — со схемой
// `kaname.` и без, в кавычках и без.
//
// # Чего разбор НЕ решает — и как это выражено
//
//  1. Динамический SQL. Имя подтаблицы в СТРОКОВОМ литерале (`EXECUTE format(
//     '… %I …', 'role_verb')`) — отказ «не судится», а не молчание, даже при
//     вызове функции рядом: что записано, разбор не видит. Имя, собранное
//     склейкой частей (`'role_' || 'verb'`), литералом не названо — граница.
//  2. Множество ролей, с которым миграция зовёт функцию. Это семантика,
//     текстом не выразимая; её держит ревью миграции.
//  3. Исполнится ли вызов. Неиспользуемый `SELECT` в `WITH` база не исполняет;
//     разбор видит вызов, но не его исполнимость — это держит ревью.
//  4. Раздел под `-- +goose NO TRANSACTION`, пишущий подтаблицы, — находка и
//     при вызове: запись и событие там не атомарны.
package check

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// RoleCompositionFunction — функция события, которую обязан звать раздел.
const RoleCompositionFunction = "kaname.resource_journal_emit_role_composition"

var (
	gooseUpMarkRe   = regexp.MustCompile(`(?mi)^[ \t]*--[ \t]*\+goose[ \t]+Up\b`)
	gooseDownMarkRe = regexp.MustCompile(`(?mi)^[ \t]*--[ \t]*\+goose[ \t]+Down\b`)
	gooseNoTxRe     = regexp.MustCompile(`(?mi)^[ \t]*--[ \t]*\+goose[ \t]+NO[ \t]+TRANSACTION\b`)

	subtableNameRe = `(?:kaname\s*\.\s*)?(role_verb|role_rule_ref|role_rule_selectors)\b`
	rowWriteRe     = regexp.MustCompile(`\b(?:insert\s+into|delete\s+from|merge\s+into|update)\s+(?:only\s+)?` + subtableNameRe)
	copyFromRe     = regexp.MustCompile(`\bcopy\s+` + subtableNameRe + `[^;]*?\bfrom\b`)
	truncateRe     = regexp.MustCompile(`\btruncate\s+(?:table\s+)?([^;]*)`)
	truncateItemRe = regexp.MustCompile(`^\s*(?:only\s+)?` + subtableNameRe)
	literalNameRe  = regexp.MustCompile(`\b(role_verb|role_rule_ref|role_rule_selectors)\b`)
	emitCallRe     = regexp.MustCompile(`\bkaname\s*\.\s*resource_journal_emit_role_composition\s*\(`)
	emitDeclRe     = regexp.MustCompile(`\bcreate\s+(?:or\s+replace\s+)?function\s+kaname\s*\.\s*resource_journal_emit_role_composition\b`)
	dollarTagRe    = regexp.MustCompile(`^\$([A-Za-z_][A-Za-z0-9_]*)?\$`)
)

// RoleSubtableFinding — раздел миграции, нарушивший §3.2а.
type RoleSubtableFinding struct {
	File    string
	Section string
	// Table — подтаблица, которую раздел пишет; пусто у «не судится».
	Table string
	Why   string
}

// String — находка одной строкой: файл, раздел, таблица, причина.
func (f RoleSubtableFinding) String() string {
	return fmt.Sprintf("%s [%s] %s: %s", f.File, f.Section, f.Table, f.Why)
}

// RoleSubtableCensus — объём осмотренного.
type RoleSubtableCensus struct {
	// Files — файлов цепочки осмотрено; Sections — разделов.
	Files, Sections int
	// Floor — миграция, заводящая функцию: нижняя граница популяции.
	Floor string
	// Population — файлов в популяции (версия строго больше границы).
	Population int
	// Writers — разделов популяции, пишущих подтаблицы роли; Calling — из них
	// зовущих функцию в том же разделе.
	Writers, Calling int
	// Outside — файлы ВНЕ популяции, пишущие подтаблицы роли, по порядку.
	Outside []string
}

// roleSubtableSection — раздел миграции после разбора.
type roleSubtableSection struct {
	name     string
	tables   []string
	literal  bool
	calls    bool
	declares bool
}

// AuditRoleSubtableWriters судит цепочку миграций.
func AuditRoleSubtableWriters(corpus TreeCorpus) ([]RoleSubtableFinding, RoleSubtableCensus, error) {
	var census RoleSubtableCensus
	if len(corpus) == 0 {
		return nil, census, fmt.Errorf("цепочка миграций пуста — «находок ноль» здесь значило бы «прочитано ноль»")
	}
	type parsed struct {
		rel      string
		version  int64
		noTx     bool
		sections []roleSubtableSection
	}
	files := make([]parsed, 0, len(corpus))
	var floor *parsed
	for _, rel := range corpus.Rels() {
		v, ok := MigrationVersionOf(path.Base(rel))
		if !ok {
			continue
		}
		body := corpus[rel]
		p := parsed{rel: rel, version: v.Value, noTx: gooseNoTxRe.MatchString(body), sections: splitRoleSubtableSections(body)}
		census.Files++
		census.Sections += len(p.sections)
		files = append(files, p)
	}
	if census.Files == 0 {
		return nil, census, fmt.Errorf("в цепочке нет ни одного файла с номером версии (корпус %d)", len(corpus))
	}
	for i := range files {
		for _, s := range files[i].sections {
			if s.declares && (floor == nil || files[i].version < floor.version) {
				floor = &files[i]
			}
		}
	}
	if floor == nil {
		return nil, census, fmt.Errorf("миграции, заводящей %s, в цепочке нет — нижнюю границу "+
			"популяции вывести не из чего", RoleCompositionFunction)
	}
	census.Floor = floor.rel

	var findings []RoleSubtableFinding
	outside := map[string]bool{}
	for _, f := range files {
		inPopulation := f.version > floor.version
		if inPopulation {
			census.Population++
		}
		for _, s := range f.sections {
			writes := len(s.tables) > 0
			if !inPopulation {
				if writes {
					outside[f.rel] = true
				}
				continue
			}
			if s.literal {
				findings = append(findings, RoleSubtableFinding{File: f.rel, Section: s.name,
					Why: "имя подтаблицы роли в строковом литерале (динамический SQL) — запись не судится " +
						"разбором; перепиши оператор статически"})
			}
			if !writes {
				continue
			}
			census.Writers++
			if s.calls {
				census.Calling++
			}
			for _, tbl := range s.tables {
				switch {
				case f.noTx:
					findings = append(findings, RoleSubtableFinding{File: f.rel, Section: s.name, Table: tbl,
						Why: "раздел без транзакции (-- +goose NO TRANSACTION) пишет подтаблицу роли — запись " +
							"и событие не атомарны"})
				case !s.calls:
					findings = append(findings, RoleSubtableFinding{File: f.rel, Section: s.name, Table: tbl,
						Why: "раздел пишет подтаблицу роли и не зовёт " + RoleCompositionFunction})
				}
			}
		}
	}
	for rel := range outside {
		census.Outside = append(census.Outside, rel)
	}
	sort.Strings(census.Outside)
	return findings, census, nil
}

// splitRoleSubtableSections режет файл на разделы `goose` и судит каждый.
// Маркеры читаются в СЫРОМ тексте: они сами — комментарии.
func splitRoleSubtableSections(body string) []roleSubtableSection {
	up, down := body, ""
	if loc := gooseDownMarkRe.FindStringIndex(body); loc != nil {
		up, down = body[:loc[0]], body[loc[1]:]
	}
	if loc := gooseUpMarkRe.FindStringIndex(up); loc != nil {
		up = up[loc[1]:]
	}
	out := []roleSubtableSection{judgeRoleSubtableSection("Up", up)}
	if down != "" {
		out = append(out, judgeRoleSubtableSection("Down", down))
	}
	return out
}

// judgeRoleSubtableSection — что раздел пишет, зовёт и заводит.
func judgeRoleSubtableSection(name, text string) roleSubtableSection {
	code, literals := sqlExecutablePart(text)
	s := roleSubtableSection{name: name}
	seen := map[string]bool{}
	add := func(tbl string) {
		if !seen[tbl] {
			seen[tbl] = true
			s.tables = append(s.tables, tbl)
		}
	}
	for _, m := range rowWriteRe.FindAllStringSubmatch(code, -1) {
		add(m[1])
	}
	for _, m := range copyFromRe.FindAllStringSubmatch(code, -1) {
		add(m[1])
	}
	for _, m := range truncateRe.FindAllStringSubmatch(code, -1) {
		for _, item := range strings.Split(m[1], ",") {
			if im := truncateItemRe.FindStringSubmatch(item); im != nil {
				add(im[1])
			}
		}
	}
	for _, lit := range literals {
		if literalNameRe.MatchString(strings.ToLower(lit)) {
			s.literal = true
			break
		}
	}
	s.calls = emitCallRe.MatchString(code)
	s.declares = emitDeclRe.MatchString(code)
	return s
}

// sqlExecutablePart — исполняемая часть текста SQL и тела строковых литералов.
//
// Код: комментарии сняты, кавычки идентификаторов сняты, регистр сведён, тело
// строкового литерала заменено пробелами; ограничители долларовых кавычек
// заменены пробелами, а тело оставлено кодом. Литералы — отдельно, как есть.
func sqlExecutablePart(s string) (code string, literals []string) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			b.WriteByte('\n')
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			depth := 0
			for i < len(s) {
				if s[i] == '/' && i+1 < len(s) && s[i+1] == '*' {
					depth++
					i += 2
					continue
				}
				if s[i] == '*' && i+1 < len(s) && s[i+1] == '/' {
					depth--
					i += 2
					if depth == 0 {
						break
					}
					continue
				}
				i++
			}
			i--
			b.WriteByte(' ')
		case c == '\'':
			escaped := i > 0 && (s[i-1] == 'E' || s[i-1] == 'e') && (i < 2 || !isSQLIdentByte(s[i-2]))
			var lit strings.Builder
			j := i + 1
			for ; j < len(s); j++ {
				if escaped && s[j] == '\\' && j+1 < len(s) {
					lit.WriteByte(s[j+1])
					j++
					continue
				}
				if s[j] == '\'' {
					if j+1 < len(s) && s[j+1] == '\'' {
						lit.WriteByte('\'')
						j++
						continue
					}
					break
				}
				lit.WriteByte(s[j])
			}
			literals = append(literals, lit.String())
			b.WriteByte(' ')
			i = j
		case c == '"':
			j := i + 1
			for ; j < len(s) && s[j] != '"'; j++ {
				b.WriteByte(toLowerASCII(s[j]))
			}
			i = j
		case c == '$':
			if m := dollarTagRe.FindString(s[i:]); m != "" && (i == 0 || !isSQLIdentByte(s[i-1])) {
				b.WriteByte(' ')
				i += len(m) - 1
				continue
			}
			b.WriteByte(c)
		default:
			b.WriteByte(toLowerASCII(c))
		}
	}
	return b.String(), literals
}

func isSQLIdentByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func toLowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
