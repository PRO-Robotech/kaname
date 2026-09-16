// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations

// session_expiry_declarations.go — ЯДРО гейта F4d-27: у записи сессии человека
// срок ОДИН (фаза Ф3, задача PRO-Robotech/kacho#1269; сценарий Ф3-11).
//
// # Предмет
//
// Окно бездействия рядом с абсолютным сроком — два места об одном предмете, из
// которых верно одно (F4d Р5: «окно бездействия не вводится»). Гейт считает
// ОБЪЯВЛЕНИЯ СРОКА у таблицы сессии по всем миграциям — в объявлении таблицы и
// в добавлении столбца к ней — и требует ровно одного.
//
// # Единица — столбец, и что им считается (Ф3-11, круг 1 В8)
//
// Объявление срока — столбец таблицы сессии, несущий МОМЕНТ ИСТЕЧЕНИЯ либо ОКНО
// БЕЗДЕЙСТВИЯ:
//
//   - момент истечения — `timestamp with time zone` с именем, говорящим об
//     истечении (`expires_at`, `expiry`, `valid_until`, `deadline`, …);
//   - окно бездействия — столбец типа `interval` любого имени, либо момент,
//     чьё имя говорит о бездействии (`idle_*`, `inactivity_*`, `last_activity_*`
//     с суффиксом срока).
//
// Столбцы-моменты, которые сроком НЕ являются и на которых гейт обязан молчать:
// `authenticated_at`, `last_presented_at`, `created_at`, `ended_at` — момент не
// есть срок. Ручка срока в настройке и поле структуры в коде — читатели
// столбца, а не второй срок; гейт их не судит.
//
// # Формы записи, которые распознаватель знает
//
// Обе формы, которыми столбец появляется в этом каталоге: строка внутри
// `CREATE TABLE <схема.>human_sessions (…)` и `ALTER TABLE <схема.>human_sessions
// ADD COLUMN …`. Комментарии SQL забелены до разбора (`MigrationUpSection`) —
// шапка миграции, объясняющая гейт, находкой быть не может.

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
)

// SessionTable — имя таблицы сессии человека без схемы. Одно объявление на
// пакет; адаптер называет ту же таблицу своим оператором.
const SessionTable = "human_sessions"

// ExpiryDeclaration — найденное объявление срока.
type ExpiryDeclaration struct {
	File   string
	Column string
	Form   string // "create-table" | "add-column"
	Why    string // чем распознано
}

// ExpiryCensus — перепись обхода: печатается всегда, чтобы «ноль находок» было
// отличимо от «ноль прочитанного».
type ExpiryCensus struct {
	Files          int // файлов миграций прочитано
	TableMentions  int // объявлений/изменений таблицы сессии найдено
	ColumnsSeen    int // столбцов таблицы сессии осмотрено
	MomentColumns  int // из них моментов, сроком не являющихся
	ExpiryDeclared int // объявлений срока
}

func (c ExpiryCensus) String() string {
	return fmt.Sprintf("миграций прочитано %d · объявлений таблицы %s %d · столбцов осмотрено %d · моментов без срока %d · объявлений срока %d",
		c.Files, SessionTable, c.TableMentions, c.ColumnsSeen, c.MomentColumns, c.ExpiryDeclared)
}

var (
	reCreateSessionTable = regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:[a-z_]+\.)?` + SessionTable + `\s*\(`)
	reAddSessionColumn   = regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(?:ONLY\s+)?(?:[a-z_]+\.)?` + SessionTable + `\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?("?[A-Za-z_][A-Za-z0-9_]*"?)\s+([A-Za-z][A-Za-z ]*?)(?:\s*[,;(]|\s+(?:NOT|NULL|DEFAULT|CHECK|REFERENCES|PRIMARY|UNIQUE|CONSTRAINT)\b)`)
	reExpiryName         = regexp.MustCompile(`(?i)expir|_until$|^until_|deadline|valid_to|valid_till|ttl`)
	reIdleName           = regexp.MustCompile(`(?i)idle|inactiv|last_activity`)
)

// ExpiryDeclarationsIn — объявления срока у таблицы сессии по телам миграций
// (имя файла → текст). Тело режется на секцию наката и забеливается от
// комментариев ЗДЕСЬ, а не вызывающим: иначе два вызывающих разошлись бы в том,
// что считать исполняемым.
func ExpiryDeclarationsIn(bodies map[string]string) ([]ExpiryDeclaration, ExpiryCensus) {
	var (
		found  []ExpiryDeclaration
		census ExpiryCensus
	)
	names := make([]string, 0, len(bodies))
	for name := range bodies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		census.Files++
		up := SQLBlankStrings(MigrationUpSection(bodies[name]))
		for _, loc := range reCreateSessionTable.FindAllStringIndex(up, -1) {
			census.TableMentions++
			body := parenBody(up[loc[1]:])
			for _, col := range tableColumns(body) {
				census.ColumnsSeen++
				judgeColumn(name, "create-table", col.name, col.typ, &found, &census)
			}
		}
		for _, m := range reAddSessionColumn.FindAllStringSubmatch(up, -1) {
			census.TableMentions++
			census.ColumnsSeen++
			judgeColumn(name, "add-column", strings.Trim(m[1], `"`), strings.TrimSpace(m[2]), &found, &census)
		}
	}
	census.ExpiryDeclared = len(found)
	return found, census
}

// ExpiryDeclarationsInFS — то же по встроенному каталогу миграций.
func ExpiryDeclarationsInFS(fsys fs.FS) ([]ExpiryDeclaration, ExpiryCensus, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, ExpiryCensus{}, err
	}
	bodies := make(map[string]string, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, rerr := fs.ReadFile(fsys, e.Name())
		if rerr != nil {
			return nil, ExpiryCensus{}, rerr
		}
		bodies[e.Name()] = string(b)
	}
	found, census := ExpiryDeclarationsIn(bodies)
	return found, census, nil
}

func judgeColumn(file, form, name, typ string, found *[]ExpiryDeclaration, census *ExpiryCensus) {
	lt := strings.ToLower(typ)
	isMoment := strings.HasPrefix(lt, "timestamp")
	isInterval := strings.HasPrefix(lt, "interval")
	switch {
	case isInterval:
		*found = append(*found, ExpiryDeclaration{File: file, Column: name, Form: form,
			Why: "столбец типа interval — окно бездействия"})
	case isMoment && reIdleName.MatchString(name):
		*found = append(*found, ExpiryDeclaration{File: file, Column: name, Form: form,
			Why: "момент с именем о бездействии — окно бездействия"})
	case isMoment && reExpiryName.MatchString(name):
		*found = append(*found, ExpiryDeclaration{File: file, Column: name, Form: form,
			Why: "момент с именем об истечении — срок"})
	case isMoment:
		census.MomentColumns++
	}
}

type columnDecl struct {
	name, typ string
}

// parenBody — тело от открывающей скобки (уже съеденной) до парной закрывающей.
func parenBody(s string) string {
	depth := 1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[:i]
			}
		}
	}
	return s
}

// tableColumns — строки объявления таблицы, являющиеся столбцами: первое слово
// не ключевое (`CONSTRAINT`, `PRIMARY`, `UNIQUE`, `CHECK`, `FOREIGN`, `EXCLUDE`).
func tableColumns(body string) []columnDecl {
	var out []columnDecl
	for _, item := range splitTopLevel(body) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		fields := strings.Fields(item)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN", "EXCLUDE", "LIKE":
			continue
		}
		name := strings.Trim(fields[0], `"`)
		typ := fields[1]
		// Многословные типы: `timestamp with time zone`, `double precision`.
		if strings.EqualFold(typ, "timestamp") || strings.EqualFold(typ, "time") {
			rest := strings.Join(fields[2:], " ")
			if strings.HasPrefix(strings.ToLower(rest), "with time zone") || strings.HasPrefix(strings.ToLower(rest), "without time zone") {
				typ = typ + " " + strings.Join(fields[2:5], " ")
			}
		}
		out = append(out, columnDecl{name: name, typ: typ})
	}
	return out
}

// splitTopLevel — разрез по запятым верхнего уровня (скобки CHECK/ARRAY не рвут).
func splitTopLevel(s string) []string {
	var (
		out   []string
		depth int
		start int
	)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}
