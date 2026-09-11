// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_expiry_immutable.go — разбор операторов правки, разложенных по
// столбцам (приёмка F2, §9.4, решение §2.10).
//
// Порт с монорепо (`internal/repohygiene/clientexpiryimmutable.go`, снят
// вынесением службы — `kacho#2597` с заявлением «снято вместе с предметом:
// таблицы user_oauth_clients в применённых миграциях дерева нет». Заявление
// было верно ТОЛЬКО для монорепо (там дерево служб доступа исчезло целиком) —
// в дереве службы обе таблицы объявлены (сегодня — в консолидированной
// `internal/migrations/0001_initial.sql`), с колонкой `expires_at`. Осталось
// дословно: имя функции гейта, сам разбор и текст находки. Изменилось: пути
// без префикса `services/iam/`.
//
// # Предмет
//
// Срок клиента неизменяем после создания. На этой предпосылке стоит
// структурная гарантия: срок выданного токена не превышает остатка срока
// клиента, и проверять это на пути запроса не нужно ровно потому, что срок
// не двигается. Сдвинь его — и гарантия держится ничем.
//
// # Что здесь считается ПРАВКОЙ СТОЛБЦА
//
//	UPDATE t SET expires_at = $2 WHERE id = $1   ← правка: столбец назван в SET
//	INSERT INTO t (…, expires_at) VALUES (…)     ← СОЗДАНИЕ: срок назначается
//	SELECT expires_at FROM t WHERE id = $1       ← чтение
//
// # Чего разбор НЕ видит — названо, а не спрятано
//
//  1. оператор, собранный из частей во время выполнения;
//  2. правка через функцию базы или триггер, а не оператором `UPDATE`;
//  3. `UPDATE` без имени таблицы в том же литерале.
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
)

// SQLUpdate — оператор правки, найденный в литерале.
type SQLUpdate struct {
	File    string
	Line    int
	Func    string
	Table   string
	Columns []string
}

// SQLUpdateCensus — объём осмотренного одним файлом.
type SQLUpdateCensus struct {
	StringLiterals        int
	SQLLiterals           int
	Updates               int
	UpdatesWithoutColumns int
}

var sqlStatementHeads = []string{"select", "insert", "update", "delete", "with"}

// ScanSQLUpdates разбирает один файл и собирает операторы правки названных
// таблиц.
func ScanSQLUpdates(path string, src []byte, tables []string) ([]SQLUpdate, SQLUpdateCensus, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, SQLUpdateCensus{}, err
	}
	want := map[string]bool{}
	for _, t := range tables {
		want[strings.ToLower(t)] = true
	}

	var (
		out    []SQLUpdate
		census SQLUpdateCensus
	)
	for _, decl := range f.Decls {
		enclosing := "уровень пакета"
		if fn, ok := decl.(*ast.FuncDecl); ok {
			enclosing = functionQualifiedName(fn)
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			census.StringLiterals++
			text, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			head := strings.ToLower(strings.TrimSpace(text))
			isSQL := false
			for _, h := range sqlStatementHeads {
				if strings.HasPrefix(head, h) {
					isSQL = true
					break
				}
			}
			if !isSQL {
				return true
			}
			census.SQLLiterals++
			for _, u := range parseSQLUpdates(text) {
				if !want[strings.ToLower(u.Table)] {
					continue
				}
				census.Updates++
				if len(u.Columns) == 0 {
					census.UpdatesWithoutColumns++
				}
				u.File = path
				u.Line = fset.Position(lit.Pos()).Line
				u.Func = enclosing
				out = append(out, u)
			}
			return true
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out, census, nil
}

func parseSQLUpdates(text string) []SQLUpdate {
	lower := strings.ToLower(text)
	var out []SQLUpdate
	for idx := 0; ; {
		rel := strings.Index(lower[idx:], "update ")
		if rel < 0 {
			break
		}
		at := idx + rel + len("update ")
		table := sqlIdentifierAt(text, at)
		idx = at
		if table == "" {
			continue
		}
		if i := strings.LastIndex(table, "."); i >= 0 {
			table = table[i+1:]
		}
		setAt := strings.Index(lower[at:], " set ")
		if setAt < 0 {
			out = append(out, SQLUpdate{Table: table})
			continue
		}
		start := at + setAt + len(" set ")
		end := len(text)
		for _, stop := range []string{" where ", " returning ", " from ", ";"} {
			if i := strings.Index(lower[start:], stop); i >= 0 && start+i < end {
				end = start + i
			}
		}
		out = append(out, SQLUpdate{Table: table, Columns: sqlSetColumns(text[start:end])})
		idx = start
	}
	return out
}

func sqlSetColumns(clause string) []string {
	var (
		out   []string
		depth int
		start int
	)
	flush := func(part string) {
		part = strings.TrimSpace(part)
		if part == "" {
			return
		}
		eq := strings.Index(part, "=")
		if eq < 0 {
			return
		}
		name := strings.TrimSpace(part[:eq])
		name = strings.Trim(name, "\"`")
		if i := strings.LastIndex(name, "."); i >= 0 {
			name = name[i+1:]
		}
		if name != "" {
			out = append(out, strings.ToLower(name))
		}
	}
	for i := 0; i < len(clause); i++ {
		switch clause[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				flush(clause[start:i])
				start = i + 1
			}
		}
	}
	flush(clause[start:])
	sort.Strings(out)
	return out
}

// sqlIdentifierAt — первый идентификатор начиная с позиции i.
func sqlIdentifierAt(s string, i int) string {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	start := i
	for i < len(s) && (s[i] == '_' || s[i] == '.' ||
		(s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') ||
		(s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	return s[start:i]
}

// SQLCreateTableBody — тело объявления таблицы, разобранное из НАКАТА
// (Up-секции без комментариев) миграции. sqlText — полный текст ФАЙЛА
// миграции (порт зовёт `migrations.MigrationUpSection` сам, чтобы не тянуть
// зависимость на пакет `migrations` из пакета `check` без нужды — вызывающий
// подаёт уже подготовленный текст наката).
func SQLCreateTableBody(upSection, table string) string {
	lower := strings.ToLower(upSection)
	needle := strings.ToLower(table)
	for idx := 0; ; {
		rel := strings.Index(lower[idx:], "create table")
		if rel < 0 {
			return ""
		}
		at := idx + rel + len("create table")
		name := sqlIdentifierAt(upSection, at)
		idx = at
		short := name
		if i := strings.LastIndex(short, "."); i >= 0 {
			short = short[i+1:]
		}
		if !strings.EqualFold(short, needle) {
			continue
		}
		open := strings.Index(upSection[at:], "(")
		if open < 0 {
			return ""
		}
		open += at
		depth := 0
		for i := open; i < len(upSection); i++ {
			switch upSection[i] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					return upSection[open+1 : i]
				}
			}
		}
		return ""
	}
}
