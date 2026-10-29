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
// Текст разбирается ОДНИМ проходом владельца разбора SQL миграций (`internal/migrations`,
// `SQLBlankComments`, `SQLBlankStrings`, разрез `MigrationUpText`). Исполняемая
// часть: комментарии `--` и `/* */` сняты, кавычки идентификаторов
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

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// RoleCompositionFunction — функция события, которую обязан звать раздел.
const RoleCompositionFunction = "kaname.resource_journal_emit_role_composition"

var (
	subtableNameRe = `(?:kaname\s*\.\s*)?(role_verb|role_rule_ref|role_rule_selectors)\b`
	rowWriteRe     = regexp.MustCompile(`\b(?:insert\s+into|delete\s+from|merge\s+into|update)\s+(?:only\s+)?` + subtableNameRe)
	copyFromRe     = regexp.MustCompile(`\bcopy\s+` + subtableNameRe + `[^;]*?\bfrom\b`)
	truncateRe     = regexp.MustCompile(`\btruncate\s+(?:table\s+)?([^;]*)`)
	truncateItemRe = regexp.MustCompile(`^\s*(?:only\s+)?` + subtableNameRe)
	literalNameRe  = regexp.MustCompile(`\b(role_verb|role_rule_ref|role_rule_selectors)\b`)
	emitCallRe     = regexp.MustCompile(`\bkaname\s*\.\s*resource_journal_emit_role_composition\s*\(`)
	emitDeclRe     = regexp.MustCompile(`\bcreate\s+(?:or\s+replace\s+)?function\s+kaname\s*\.\s*resource_journal_emit_role_composition\b`)
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
		p := parsed{rel: rel, version: v.Value, noTx: noTransaction(body), sections: splitRoleSubtableSections(body)}
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
						Why: "раздел файла под директивой мигратора «без транзакции» (NO TRANSACTION) пишет " +
							"подтаблицу роли — запись " +
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
// Разрез — у его ЕДИНСТВЕННОГО объявления (`migrations.MigrationUpText`,
// `migrations.SectionDownMarker`): маркеры читаются в СЫРОМ тексте, потому что
// сами они — комментарии, а второе написание директивы разошлось бы с первым
// молча.
func splitRoleSubtableSections(body string) []roleSubtableSection {
	out := []roleSubtableSection{judgeRoleSubtableSection("Up", migrations.MigrationUpText(body))}
	if i := strings.Index(body, migrations.SectionDownMarker); i >= 0 {
		out = append(out, judgeRoleSubtableSection("Down", body[i+len(migrations.SectionDownMarker):]))
	}
	return out
}

// noTransaction — файл объявляет директиву мигратора «без транзакции». Стем
// директивы берётся у владельца разреза, а не выписывается вторым местом.
func noTransaction(body string) bool {
	return strings.Contains(body, migrations.SectionMarkerStem+"NO TRANSACTION")
}

// judgeRoleSubtableSection — что раздел пишет, зовёт и заводит.
//
// Текст разбирается ОДНИМ проходом владельца (`migrations.SQLBlankComments`,
// `migrations.SQLBlankStrings`): своего разбора SQL у гейта нет. Исполняемая
// часть — текст без комментариев и без содержимого строковых литералов, без
// кавычек идентификаторов и в одном регистре. Содержимое литералов — то, чем
// исполняемая часть отличается от текста с забеленными комментариями: на его
// месте в литеральной части стоят сами знаки, вне литералов — пробелы.
//
// Граница разбора владельца названа: строку вида `E'…'` с экранированной
// кавычкой он читает по правилам обычной строки — лишняя находка либо
// пропуск ровно на такой форме, и ни одной такой миграции в цепочке нет.
func judgeRoleSubtableSection(name, text string) roleSubtableSection {
	noComments := migrations.SQLBlankComments(text)
	executable := migrations.SQLBlankStrings(noComments)
	literal := make([]byte, len(noComments))
	for i := range literal {
		literal[i] = ' '
		if executable[i] != noComments[i] {
			literal[i] = noComments[i]
		}
	}
	code := strings.ToLower(strings.ReplaceAll(executable, `"`, ""))

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
	s.literal = literalNameRe.MatchString(strings.ToLower(string(literal)))
	s.calls = emitCallRe.MatchString(code)
	s.declares = emitDeclRe.MatchString(code)
	return s
}
