// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// seeded_service_accounts.go — разбор посева служебных учёток по цепочке
// миграций: вставка заводит строку, удаление её снимает.
//
// Порт ОБЩЕГО вспомогательного разбора с монорепо (жил как package-private
// `seededSA`/`foldSeededServiceAccounts` в
// `internal/repohygiene/moduleserviceaccounthasacomponent_test.go`, снят
// вынесением службы — `kacho#2597`). Перенесён в НЕ-тестовый файл и
// экспортирован, потому что нужен как минимум ДВУМ гейтам монорепо:
// `moduleidentityseededonlybythebaseline` (перенесён этим же изменением,
// `module_identity_seeded_only_by_baseline.go`) и
// `moduleserviceaccounthasacomponent` (семейство, НЕ входящее в батч
// `kacho#2597` этого агента — предмета оно судит компоненты дерева, отдельная
// от «когда посеяно» ось). Держать разбор внутри теста значило бы, что
// следующий перенос его продублирует, не заметив: инструкция переноса прямо
// требует проверить, не появился ли общий помощник, и переиспользовать его —
// вместо копии.
package check

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// moduleSAMarker — признак модульной учётки, объявленный самой посеянной
// строкой (дословно из монорепо).
const moduleSAMarker = "Module SA:"

var (
	reSAInsert = regexp.MustCompile(
		`(?is)^INSERT\s+INTO\s+kaname\.service_accounts\s*\(([^)]*)\)\s*VALUES\s*\((.*)\)$`)
	reSADeleteByID = regexp.MustCompile(
		`(?is)^DELETE\s+FROM\s+kaname\.service_accounts\s+WHERE\s+id\s*(?:=|IN)\s*\(?\s*(.+?)\s*\)?$`)
	reSADeleteByName = regexp.MustCompile(
		`(?is)^DELETE\s+FROM\s+kaname\.service_accounts\s+WHERE\s+name\s*(?:=|IN)\s*\(?\s*(.+?)\s*\)?$`)
	reSQLSpaceRun = regexp.MustCompile(`\s+`)
	reSQLLiteral  = regexp.MustCompile(`'((?:[^']|'')*)'`)
)

// SeededServiceAccount — посеянная служебная учётка.
type SeededServiceAccount struct {
	ID, Name, Description, Where string
}

// IsModule — учётка объявляет себя модульной.
func (s SeededServiceAccount) IsModule() bool {
	return strings.Contains(s.Description, moduleSAMarker)
}

// FoldSeededServiceAccounts складывает посев по цепочке: вставка заводит
// строку, удаление её снимает. Возвращает живые строки, находки формы и объём
// осмотренного.
//
// Формы записи названы ЯВНО, и незнакомая — находка, а не молчание: форма, о
// которой разбор не знает, уводит предмет из-под наблюдения, ничего не
// нарушив (§«Гейт на класс» п. 7).
//
// Разбор НЕ понимает PL/pgSQL-блоков `DO $$ ... $$` — наивное деление на
// `;` внутри такого блока даёт много фрагментов, большинство отбрасываются
// (не называют таблицу или несут не INSERT/UPDATE/DELETE), но статический
// `DELETE FROM kaname.service_accounts WHERE name IN (...)` внутри такого
// блока распознаётся корректно, потому что сам оператор синтаксически цел
// между соседними `;`. Динамическое снятие через переменную
// (`WHERE name = ANY(var)`) разбором НЕ узнаётся — это названо явно шапкой
// такой миграции продукта (`20260909202745_module_identities_leave_the_baseline.sql`):
// имена стоят литералами в статическом операторе именно для того, чтобы
// этот разбор их видел.
func FoldSeededServiceAccounts(ordered []string, bodies map[string]string) (
	alive map[string]SeededServiceAccount, unknownForms []string, stmtsTouched int,
) {
	alive = map[string]SeededServiceAccount{}
	byName := map[string]string{} // имя → id, чтобы снятие по имени находило строку
	for _, name := range ordered {
		// Прямой ход и только он: обратный возвращает снятое, и строки, которых
		// нет ни в одном развёрнутом дереве, посевом не являются. Разрез и снятие
		// комментариев берутся у ЕДИНСТВЕННОГО владельца разбора
		// (`migrations.MigrationUpSection`), а не переписываются здесь: шапка этого
		// же файла требует переиспользовать общий помощник вместо копии, и копия
		// разошлась бы с ним молча — на законном входе обе отвечают одинаково.
		code := migrations.MigrationUpSection(bodies[name])
		for _, raw := range strings.Split(code, ";") {
			stmt := strings.TrimSpace(reSQLSpaceRun.ReplaceAllString(raw, " "))
			if !seededServiceAccountWrite(stmt) {
				continue
			}
			stmtsTouched++
			if m := reSAInsert.FindStringSubmatch(stmt); m != nil {
				if sa, ok := saOfInsert(m[1], m[2], name); ok {
					alive[sa.ID] = sa
					byName[sa.Name] = sa.ID
					continue
				}
			}
			if m := reSADeleteByID.FindStringSubmatch(stmt); m != nil {
				for _, id := range sqlLiterals(m[1]) {
					delete(alive, id)
				}
				continue
			}
			if m := reSADeleteByName.FindStringSubmatch(stmt); m != nil {
				for _, n := range sqlLiterals(m[1]) {
					delete(alive, byName[n])
				}
				continue
			}
			unknownForms = append(unknownForms, fmt.Sprintf(
				"%s: оператор пишет служебные учётки формой, которой разбор не знает: %s",
				name, headOf(stmt)))
		}
	}
	return alive, unknownForms, stmtsTouched
}

// Судится цель leading INSERT/UPDATE/DELETE, а не таблица в SELECT/FROM/USING
// или строковом значении. Имена читает общий sqlTokens: регистр без кавычек,
// кавычки и границы идентификаторов не получают второго распознавателя.
// Это не полный SQL parser: прежний semicolon/PLpgSQL предел остаётся.
// Неразобранный DML-префикс с именем SA передаётся как unknown в старый fold.
func seededServiceAccountWrite(stmt string) bool {
	tokens := sqlTokens(stmt)
	word := func(i int, name string) bool {
		return i < len(tokens) && tokens[i].kind == sqlTokName &&
			tokens[i].form == SQLFormBare && tokens[i].name == name
	}
	unknown := func() bool { return SQLNamesRelation(stmt, "service_accounts") }
	i := 1
	switch {
	case word(0, "insert"):
		if !word(i, "into") {
			return unknown()
		}
		i++
	case word(0, "delete"):
		if !word(i, "from") {
			return unknown()
		}
		i++
		if word(i, "only") {
			i++
		}
	case word(0, "update"):
		if word(i, "only") {
			i++
		}
	default:
		return false // DDL/SELECT и оболочки PLpgSQL не были предметом fold
	}
	// ONLY (table) законен у UPDATE/DELETE. Если цель SA, row-fold ниже
	// всё равно откажет как на неизвестной форме, пока её явно не поддержат.
	parenthesized := i < len(tokens) && tokens[i].kind == sqlTokOther && tokens[i].op == '('
	if parenthesized {
		i++
	}
	if i >= len(tokens) || tokens[i].kind != sqlTokName {
		return unknown()
	}
	first := tokens[i].name
	i++
	schema, table := "", first
	if i < len(tokens) && tokens[i].kind == sqlTokOther && tokens[i].op == '.' {
		i++
		if i >= len(tokens) || tokens[i].kind != sqlTokName {
			return unknown()
		}
		schema, table = first, tokens[i].name
		i++
	}
	if i < len(tokens) && tokens[i].kind == sqlTokOther && tokens[i].op == '.' {
		return unknown() // трёхчастное имя не доказано как чужая цель
	}
	if parenthesized && (i >= len(tokens) || tokens[i].kind != sqlTokOther || tokens[i].op != ')') {
		return unknown()
	}
	return table == "service_accounts" && (schema == "" || schema == "kaname")
}

func headOf(s string) string {
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

func sqlLiterals(s string) []string {
	var out []string
	for _, m := range reSQLLiteral.FindAllStringSubmatch(s, -1) {
		out = append(out, strings.ReplaceAll(m[1], "''", "'"))
	}
	return out
}

func saOfInsert(colList, valList, where string) (SeededServiceAccount, bool) {
	cols := strings.Split(colList, ",")
	vals := splitSQLValueList(valList)
	if len(cols) != len(vals) {
		return SeededServiceAccount{}, false
	}
	byCol := map[string]string{}
	for i, c := range cols {
		byCol[strings.TrimSpace(c)] = strings.TrimSpace(vals[i])
	}
	id, okID := sqlLiteralOf(byCol["id"])
	name, okName := sqlLiteralOf(byCol["name"])
	if !okID || !okName {
		return SeededServiceAccount{}, false
	}
	desc, _ := sqlLiteralOf(byCol["description"])
	return SeededServiceAccount{ID: id, Name: name, Description: desc, Where: where}, true
}

func splitSQLValueList(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQuote && c == '\'':
			if i+1 < len(s) && s[i+1] == '\'' {
				cur.WriteString("''")
				i++
				continue
			}
			inQuote = false
			cur.WriteByte(c)
		case !inQuote && c == '\'':
			inQuote = true
			cur.WriteByte(c)
		case !inQuote && c == ',':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	out = append(out, cur.String())
	return out
}

func sqlLiteralOf(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if len(v) < 2 || v[0] != '\'' || v[len(v)-1] != '\'' {
		return "", false
	}
	return strings.ReplaceAll(v[1:len(v)-1], "''", "'"), true
}
