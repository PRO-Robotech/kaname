// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// migration_not_a_writer_of_module_role.go — разбор миграций и манифестов:
// роль модуля, у которого ЕСТЬ манифест, пишет применитель, а не миграция.
//
// # Предмет
//
// Миграция, вставившая такую роль, заводит ВТОРОГО писателя одного предмета:
// два места разойдутся молча — правка манифеста не доедет до строки, потому что
// строку держит миграция, а перепись применителя об этом ничего не скажет.
//
// # Перечень модулей с манифестом ВЫВОДИТСЯ, а ведомость НЕ заводится
//
// Ведомость «модули без манифеста» есть второе место об одном предмете, и
// расходится оно МОЛЧА — ровно в тот день, когда у модуля появляется или
// исчезает манифест. Производный перечень истекает BY CONSTRUCTION: запись
// исчезает вместе с появлением манифеста, и истекать вручную нечему.
//
// Число манифестов здесь намеренно НЕ выписано вторым местом: оно растёт с
// каждым новым модулем и устарело бы молча. Узнаётся одной командой:
//
//	git ls-files '*manifest.yaml' | wc -l    # сколько их в дереве СЕЙЧАС
//
// # Как узнаётся манифест — по СОДЕРЖИМОМУ, а не по пути
//
// Разбор, привязанный к пути, молчал бы вечно, окажись путь другим, — и его
// молчание было бы неотличимо от чистоты. Поэтому манифест опознаётся парой
// ключей верхнего уровня: объявлением версии контракта и именем модуля.
//
// # Форм записи имени роли ДВЕ, и обе законны
//
// Рукописная выводит идентификатор ИЗ имени, поэтому имя стоит аргументом
// деривации; снимочная подставляет уже вычисленный идентификатор и перечисляет
// колонки явно. Разбор, знавший одну, извлекал ноль имён при сорока восьми
// блоках — это не находка и не молчание, а невидимость: каждая вставленная роль
// оказалась вне наблюдения. Ловят это ДВЕ величины переписи: «имён извлечено» и
// «блоков с непрочитанным именем».
//
// # Чего разбор НЕ видит — названо
//
//  1. **фикстуры проб** — они объявляют чужой модуль и сделали бы его «модулем с
//     манифестом», превратив каждую его миграцию в находку. Исключены по
//     каталогу, и это единственное исключение;
//  2. **манифест, приезжающий не файлом дерева** (карта настроек, том) — его в
//     дереве нет by construction, и разбор о нём ничего не утверждает;
//  3. **имя роли, записанное литералом идентификатора** — такие роли вне
//     закрытого набора модулей, то есть находкой быть не могут ни при каком
//     манифесте.
//
// # Порт с монорепо — пара файлов названа, а не умолчана
//
// Перенесено с
// `PRO-Robotech/kacho:internal/repohygiene/migrationnotawriterofmodulerole.go`
// (снято вынесением службы — `kacho#2598`; предмет жив здесь, задача #17).
// Разбор перенесён БЕЗ правок логики: его операнды — текст манифеста и текст
// миграции, и ни один не несёт координаты дерева. Изменились только координаты
// в гейте рядом.
//
// Близнеца в платформе нет: семейство снято там вместе со службой (ban #20).
package check

import (
	"regexp"
	"strings"
)

// ModuleManifestSite — манифест, найденный в дереве.
type ModuleManifestSite struct {
	File   string
	Module string
}

// MigrationRoleSite — роль, вставляемая миграцией.
type MigrationRoleSite struct {
	File string
	Name string
	// Owner — первый сегмент имени: модуль-владелец либо пусто.
	Owner string
}

// MigrationRoleCensus — объём осмотренного.
type MigrationRoleCensus struct {
	// Blocks — блоков `INSERT INTO kaname.roles` прочитано.
	Blocks int
	// Names — имён ролей извлечено.
	Names int
	// Unreadable — блоков, из которых имя роли извлечь НЕ УДАЛОСЬ.
	//
	// Величина отдельная и несущая: без неё «извлечено меньше, чем блоков»
	// неотличимо от «блок вставляет роль без имени», а первое означает, что
	// разбор встретил форму, которой не знает, — то есть невидимость, а не
	// находку и не молчание.
	Unreadable int
}

var (
	// manifestAPIVersionRe — ключ оболочки манифеста верхнего уровня.
	manifestAPIVersionRe = regexp.MustCompile(`(?m)^apiVersion:\s*["']?iam/v1["']?\s*$`)
	// manifestModuleRe — имя модуля в оболочке манифеста верхнего уровня.
	manifestModuleRe = regexp.MustCompile(`(?m)^module:\s*["']?([a-z][a-z0-9-]*)["']?\s*$`)
	// roleInsertRe — начало блока вставки роли.
	roleInsertRe = regexp.MustCompile(`INSERT\s+INTO\s+kaname\.roles\b`)
	// roleSeedNameRe — имя роли как аргумент деривации идентификатора
	// (рукописная форма: идентификатор ВЫВОДИТСЯ из имени).
	roleSeedNameRe = regexp.MustCompile(`md5\('([^']+)'\)`)
	// roleBlockEndRe — конец блока вставки: первая строка, оканчивающаяся `;`.
	roleBlockEndRe = regexp.MustCompile(`(?m);\s*$`)
	// valuesKeywordRe — ключевое слово перед кортежами значений.
	valuesKeywordRe = regexp.MustCompile(`(?i)\bvalues\b`)
)

// ScanModuleManifest опознаёт манифест модуля по содержимому.
func ScanModuleManifest(path string, src []byte) (ModuleManifestSite, bool) {
	s := string(src)
	if !manifestAPIVersionRe.MatchString(s) {
		return ModuleManifestSite{}, false
	}
	m := manifestModuleRe.FindStringSubmatch(s)
	if m == nil {
		return ModuleManifestSite{}, false
	}
	return ModuleManifestSite{File: path, Module: m[1]}, true
}

// ScanMigrationRoleInserts извлекает имена ролей, вставляемых миграцией.
//
// Блок — от `INSERT INTO kaname.roles` до первой строки, оканчивающейся `;`.
// Привязка к блоку обязательна: тот же образец идентификатора встречается во
// вставках в ЧУЖИЕ таблицы (селекторы, выдачи служебным учёткам), и предикат
// без привязки мерил бы упоминания идентификатора, а не строки роли.
//
// # Форм записи имени ДВЕ, и обе законны
//
//	… VALUES ('rol' || substr(md5('iam.account.admin'),1,17), …, 'iam.account.admin', …)
//	INSERT INTO kaname.roles (id, account_id, name, …) VALUES ('rol6307…', NULL, 'iam.account.admin', …)
//
// Первая — рукописная: идентификатор ВЫВОДИТСЯ из имени, поэтому имя стоит
// аргументом деривации и берётся оттуда. Вторая пришла со сводом миграций iam
// 2026-09-04: свод написан `pg_dump`, тот подставляет уже вычисленный
// идентификатор и перечисляет колонки явно — деривации в нём нет НИ ОДНОЙ, и
// разбор, знавший только её, извлекал ноль имён при 48 блоках. Это не находка и
// не молчание, а невидимость: каждая вставленная роль оказалась вне наблюдения.
//
// Вторая форма читается по ПЕРЕЧНЮ КОЛОНОК, а не по позиции: позиция колонки
// `name` в дампе не гарантирована ничем, кроме самого перечня, и выписать её
// числом значило бы завести второе место об одном предмете.
//
// Блок, из которого имя извлечь не удалось, считается ОТДЕЛЬНО
// ([MigrationRoleCensus.Unreadable]) и молча не пропускается: неизвестная форма
// обязана быть видна, иначе следующая сделает то же, что сделал дамп.
func ScanMigrationRoleInserts(path string, src []byte) (sites []MigrationRoleSite, census MigrationRoleCensus) {
	s := string(src)
	for _, loc := range roleInsertRe.FindAllStringIndex(s, -1) {
		census.Blocks++
		block := s[loc[0]:]
		if e := roleBlockEndRe.FindStringIndex(block); e != nil {
			block = block[:e[1]]
		}
		names := roleNamesInBlock(block)
		if len(names) == 0 {
			census.Unreadable++
			continue
		}
		for _, name := range names {
			census.Names++
			owner, _, hasDot := strings.Cut(name, ".")
			if !hasDot {
				owner = ""
			}
			sites = append(sites, MigrationRoleSite{File: path, Name: name, Owner: owner})
		}
	}
	return sites, census
}

// roleNamesInBlock — имена ролей одного блока вставки, в обеих законных формах.
//
// Рукописная форма спрашивается ПЕРВОЙ и, когда отвечает, единственной: в ней
// имя стоит аргументом деривации идентификатора, то есть названо самим автором
// миграции, — а перечень колонок в такой вставке бывает опущен.
func roleNamesInBlock(block string) []string {
	var out []string
	for _, m := range roleSeedNameRe.FindAllStringSubmatch(block, -1) {
		out = append(out, m[1])
	}
	if len(out) > 0 {
		return out
	}
	return roleNamesByColumnList(block)
}

// roleNamesByColumnList — имена ролей из вставки с ЯВНЫМ перечнем колонок.
//
// Пусто, если перечня нет либо в нём нет колонки `name`: угадывать позицию по
// порядку колонок таблицы запрещено — порядок дампа держится только перечнем, и
// вставка без него имени не называет ничем, что разбор вправе прочесть.
func roleNamesByColumnList(block string) []string {
	open := strings.IndexByte(block, '(')
	if open < 0 {
		return nil
	}
	cols, after, ok := sqlBalancedTuple(block, open)
	if !ok {
		return nil
	}
	idx := -1
	for i, c := range splitSQLTupleItems(cols) {
		if strings.EqualFold(strings.Trim(strings.TrimSpace(c), `"`), "name") {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil
	}
	rest := block[after:]
	vpos := valuesKeywordRe.FindStringIndex(rest)
	if vpos == nil {
		return nil
	}
	rest = rest[vpos[1]:]

	var out []string
	for {
		open = strings.IndexByte(rest, '(')
		if open < 0 {
			break
		}
		tuple, next, okTuple := sqlBalancedTuple(rest, open)
		if !okTuple {
			break
		}
		items := splitSQLTupleItems(tuple)
		if idx < len(items) {
			if lit, isLit := sqlStringLiteral(strings.TrimSpace(items[idx])); isLit {
				out = append(out, lit)
			}
		}
		rest = rest[next:]
	}
	return out
}

// sqlBalancedTuple — тело скобки, открытой в позиции open, и позиция за нею.
// Скобки считаются, строковые литералы пропускаются.
func sqlBalancedTuple(s string, open int) (body string, end int, ok bool) {
	if open < 0 || open >= len(s) || s[open] != '(' {
		return "", 0, false
	}
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '\'':
			i = sqlSkipStringLiteral(s, i)
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[open+1 : i], i + 1, true
			}
		}
	}
	return "", 0, false
}

// splitSQLTupleItems режет тело скобки по запятым ВЕРХНЕГО уровня.
//
// Счёт скобок и пропуск литералов обязательны: значение роли несёт запятые
// внутри — и в литерале (`'[{"verbs": ["*"], "module": "iam"}]'`), и в вызове
// функции, — а разбор «до первой запятой» разорвал бы кортеж посередине и сдвинул
// бы все последующие колонки.
func splitSQLTupleItems(body string) []string {
	var (
		out   []string
		depth int
		start int
	)
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '\'':
			i = sqlSkipStringLiteral(body, i)
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, body[start:i])
				start = i + 1
			}
		}
	}
	return append(out, body[start:])
}

// sqlSkipStringLiteral — позиция ЗАКРЫВАЮЩЕЙ кавычки литерала, начатого в i.
// Удвоенная кавычка внутри означает саму кавычку, а не конец литерала.
func sqlSkipStringLiteral(s string, i int) int {
	for j := i + 1; j < len(s); j++ {
		if s[j] != '\'' {
			continue
		}
		if j+1 < len(s) && s[j+1] == '\'' {
			j++
			continue
		}
		return j
	}
	return len(s)
}

// sqlStringLiteral — значение строкового литерала, если элемент кортежа им и
// является целиком. `NULL`, число и выражение литералом не являются.
func sqlStringLiteral(item string) (string, bool) {
	if len(item) < 2 || item[0] != '\'' {
		return "", false
	}
	end := sqlSkipStringLiteral(item, 0)
	if end != len(item)-1 {
		return "", false
	}
	return strings.ReplaceAll(item[1:end], "''", "'"), true
}
