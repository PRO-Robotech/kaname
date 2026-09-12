// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// assertion_admission_calls.go — разбор обращений к базе, разложенных по
// функциям (приёмка F2, сценарий F2-28).
//
// Порт с монорепо (`internal/repohygiene/assertionadmissioncalls.go`, снят
// вынесением службы — `kacho#2597`). Держатель этого гейта уже цитируется
// ПРОД-КОММЕНТАРИЕМ в дереве службы:
// `internal/repo/kaname/pg/client_assertion_replay_repo.go` — «Гейт
// TestAssertionAdmissionIsASingleDatabaseCall стережёт это число». Осталось
// дословно: имя функции гейта, сам разбор и текст находки. Изменилось: путь
// без префикса `services/iam/`.
//
// # Предмет
//
// Число обращений к базе внутри одной функции. Допуск однократности обязан
// делать РОВНО ОДНО: «не предъявлялось ли уже» и «погасить» неделимы, и
// неделимыми их делает первичный ключ таблицы, а не аккуратность вызывающего.
// Пара «посмотреть — записать» проходит ВСЕ последовательные пробы: окна
// между чтением и записью при последовательном прогоне не существует.
//
// # Почему владелец соединения берётся из ОБЪЯВЛЕНИЯ ТИПА, а не из списка имён
//
// Разбор читает объявления структур файла и берёт в носители соединения те
// поля, ЧЕЙ ТИП называет драйвер базы. Переименование поля исход не меняет,
// чужое одноимённое поле находкой не становится.
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
)

// databaseCallVerbs — методы драйвера, каждый из которых есть ОБРАЩЕНИЕ К
// БАЗЕ. Перечень закрыт намеренно.
var databaseCallVerbs = map[string]bool{
	"Exec":      true,
	"Query":     true,
	"QueryRow":  true,
	"SendBatch": true,
	"CopyFrom":  true,
	"Begin":     true,
	"BeginTx":   true,
	"Acquire":   true,
}

// databaseDriverMarkers — то, чем тип поля выдаёт в себе носителя соединения.
var databaseDriverMarkers = []string{"pgx", "pgxpool", "sql.DB", "sql.Tx", "sql.Conn", "DBTX"}

// DatabaseCallSite — координата обращения к базе.
type DatabaseCallSite struct {
	File   string
	Line   int
	Verb   string
	Handle string
}

// FunctionDatabaseCalls — обращения одной функции.
type FunctionDatabaseCalls struct {
	Name  string
	Line  int
	Calls []DatabaseCallSite
}

// DatabaseCallCensus — объём осмотренного одним файлом.
type DatabaseCallCensus struct {
	Structs   int
	Handles   []string
	Functions int
	Calls     int
	DBCalls   int
}

// ScanDatabaseCallsByFunction разбирает один файл и раскладывает обращения к
// базе по функциям.
func ScanDatabaseCallsByFunction(path string, src []byte) (
	map[string]FunctionDatabaseCalls, DatabaseCallCensus, error,
) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, DatabaseCallCensus{}, err
	}

	var census DatabaseCallCensus
	handles := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		st, ok := n.(*ast.StructType)
		if !ok {
			return true
		}
		census.Structs++
		for _, fld := range st.Fields.List {
			if !isDatabaseHandleType(fld.Type) {
				continue
			}
			for _, name := range fld.Names {
				handles[name.Name] = true
			}
		}
		return true
	})
	for h := range handles {
		census.Handles = append(census.Handles, h)
	}
	sort.Strings(census.Handles)

	out := map[string]FunctionDatabaseCalls{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		census.Functions++
		entry := FunctionDatabaseCalls{
			Name: functionQualifiedName(fn),
			Line: fset.Position(fn.Pos()).Line,
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			census.Calls++
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if !databaseCallVerbs[sel.Sel.Name] {
				return true
			}
			handle, ok := databaseHandleOf(sel.X, handles)
			if !ok {
				return true
			}
			entry.Calls = append(entry.Calls, DatabaseCallSite{
				File: path, Line: fset.Position(call.Pos()).Line, Verb: sel.Sel.Name, Handle: handle,
			})
			census.DBCalls++
			return true
		})
		sort.Slice(entry.Calls, func(i, j int) bool { return entry.Calls[i].Line < entry.Calls[j].Line })
		out[entry.Name] = entry
	}
	return out, census, nil
}

// isDatabaseHandleType отвечает, называет ли тип поля драйвер базы.
func isDatabaseHandleType(expr ast.Expr) bool {
	rendered := renderTypeExpr(expr)
	for _, m := range databaseDriverMarkers {
		if strings.Contains(rendered, m) {
			return true
		}
	}
	return false
}

// renderTypeExpr — плоское представление типа: достаточно, чтобы разглядеть в
// нём имя пакета драйвера, и не требует вывода типов.
func renderTypeExpr(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return renderTypeExpr(t.X)
	case *ast.SelectorExpr:
		return renderTypeExpr(t.X) + "." + t.Sel.Name
	case *ast.ArrayType:
		return renderTypeExpr(t.Elt)
	case *ast.IndexExpr:
		return renderTypeExpr(t.X)
	default:
		return ""
	}
}

// databaseHandleOf отвечает, идёт ли вызов через поле-носитель соединения.
func databaseHandleOf(x ast.Expr, handles map[string]bool) (string, bool) {
	switch e := x.(type) {
	case *ast.SelectorExpr:
		if handles[e.Sel.Name] {
			return e.Sel.Name, true
		}
	case *ast.Ident:
		if handles[e.Name] {
			return e.Name, true
		}
	}
	return "", false
}

// functionQualifiedName — «Тип.Метод» либо «Функция».
func functionQualifiedName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	recv := renderTypeExpr(fn.Recv.List[0].Type)
	if recv == "" {
		return fn.Name.Name
	}
	return recv + "." + fn.Name.Name
}

// SortedFuncNames — имена разобранных функций для текста отказа.
func SortedFuncNames(byFunc map[string]FunctionDatabaseCalls) []string {
	out := make([]string, 0, len(byFunc))
	for name := range byFunc {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
