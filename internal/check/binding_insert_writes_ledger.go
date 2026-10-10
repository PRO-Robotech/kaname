// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// binding_insert_writes_ledger.go — разбор «каждая вставка привязки доступа
// пишет ведомость выпущенных кортежей той же функцией» (kaname#670, класс
// kaname#665).
//
// # Предмет
//
// Снятие выдачи — штатное (`AccessBinding.Delete`) и дренажом области при
// удалении проекта или аккаунта (`shared.RevokeBindingsInScope`) — снимает РОВНО
// записанное в ведомости выдачи (`access_binding_emitted_tuples`). Выдача,
// вставленная без ведомости, уходит строкой, а кортежи, которые она выпустила,
// остаются фактами модели прав на объект, которого больше нет. Дважды этот класс
// жил молча (самовыдача заведения — #665, выдача приглашения — #670), потому что
// пустая ведомость неотличима от «выпускать было нечего».
//
// # Что судится
//
// Узел вызова `<…>.AccessBindingsW().Insert(…)` — вставка строки выдачи — и
// узел вызова `<…>.InsertEmittedTuples(…)` в ТОЙ ЖЕ самой внутренней функции
// (объявление либо литерал функции: вставка приглашения стоит в замыкании
// транзакции). Вставка без записи ведомости в своей функции — находка с
// координатой. Слово в комментарии или строке находкой не становится: судится
// узел вызова, а не текст.
//
// # Граница названа
//
// Разбор не следит за вызовами между функциями: ведомость, записанная
// вспомогательной функцией, которую зовёт вставляющая, гейтом не видна и даст
// находку. Это осознанно — запись ведомости и вставка обязаны стоять рядом, в
// одной транзакции и в одном месте чтения.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
)

// BindingInsertSite — одна вставка привязки доступа с координатой.
type BindingInsertSite struct {
	File string
	Line int
	// Func — имя объемлющей функции (для литерала — «литерал в <имя>»).
	Func string
	// WritesLedger — в той же функции есть вызов InsertEmittedTuples.
	WritesLedger bool
}

func (s BindingInsertSite) String() string {
	return fmt.Sprintf("%s:%d вставка привязки доступа в %s без записи ведомости выпущенных кортежей "+
		"(InsertEmittedTuples) в той же функции", s.File, s.Line, s.Func)
}

// BindingInsertCensus — объём осмотренного.
type BindingInsertCensus struct {
	Files      int
	Inserts    int
	WithLedger int
}

// Add — сложение переписей по файлам.
func (c *BindingInsertCensus) Add(o BindingInsertCensus) {
	c.Files += o.Files
	c.Inserts += o.Inserts
	c.WithLedger += o.WithLedger
}

// isBindingInsert — `<x>.AccessBindingsW().Insert(…)`.
func isBindingInsert(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Insert" {
		return false
	}
	inner, ok := sel.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	isel, ok := inner.Fun.(*ast.SelectorExpr)
	return ok && isel.Sel.Name == "AccessBindingsW"
}

// isLedgerWrite — `<x>.InsertEmittedTuples(…)`.
func isLedgerWrite(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "InsertEmittedTuples"
}

// fnScope — самая внутренняя функция и то, что в ней найдено.
type fnScope struct {
	name    string
	inserts []token.Pos
	ledger  bool
}

// ScanBindingInsertLedger разбирает один Go-файл и возвращает каждую вставку
// привязки доступа с признаком записи ведомости в той же самой внутренней
// функции.
func ScanBindingInsertLedger(path string, src []byte) ([]BindingInsertSite, BindingInsertCensus, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, BindingInsertCensus{}, err
	}
	census := BindingInsertCensus{Files: 1}
	var (
		sites []BindingInsertSite
		stack []*fnScope
	)
	flush := func(s *fnScope) {
		for _, pos := range s.inserts {
			census.Inserts++
			if s.ledger {
				census.WithLedger++
			}
			sites = append(sites, BindingInsertSite{
				File: path, Line: fset.Position(pos).Line, Func: s.name, WritesLedger: s.ledger,
			})
		}
	}
	var visit func(n ast.Node) bool
	visit = func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncDecl:
			if x.Body == nil {
				return false
			}
			s := &fnScope{name: x.Name.Name}
			stack = append(stack, s)
			ast.Inspect(x.Body, visit)
			stack = stack[:len(stack)-1]
			flush(s)
			return false
		case *ast.FuncLit:
			outer := "файла"
			if len(stack) > 0 {
				outer = stack[len(stack)-1].name
			}
			s := &fnScope{name: "литерал в " + outer}
			stack = append(stack, s)
			ast.Inspect(x.Body, visit)
			stack = stack[:len(stack)-1]
			flush(s)
			return false
		case *ast.CallExpr:
			if len(stack) == 0 {
				return true
			}
			top := stack[len(stack)-1]
			if isBindingInsert(x) {
				top.inserts = append(top.inserts, x.Pos())
			}
			if isLedgerWrite(x) {
				top.ledger = true
			}
		}
		return true
	}
	ast.Inspect(f, visit)
	return sites, census, nil
}
