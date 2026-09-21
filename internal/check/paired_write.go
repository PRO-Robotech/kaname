// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// paired_write.go — ПАРНАЯ ЗАПИСЬ: функция, делающая одно из двух действий,
// обязана делать и второе (задача kaname#313).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// В службе есть пары действий, которые поодиночке снимают доступ НАПОЛОВИНУ и
// выглядят исполненными целиком: две записи отсечки; снятие сессии и отзыв
// выданного в ней. Половина исполняется, глагол отвечает успехом, и отличить
// это от работающего контроля наблюдением нельзя.
//
// ─────────────────────────────────────────────────────────────────────────────
// СКЛЕЙКА ПО ВЫЗОВУ — УЗКАЯ, И ЭТО РЕШЕНИЕ
//
// Второе действие часто делается ВЫЗОВОМ помощника, а не своим оператором, —
// разбор, не идущий по вызовам, дал бы ложную находку на всякой такой двери
// (измерено). Но склейка ШИРОКАЯ здесь хуже узкой, и вот почему: у соседнего
// прибора щедрость теряет находку о МЁРТВОМ коде, а здесь потеряла бы находку о
// ЖИВОМ половинном снятии доступа — у прибора, который объявлен единственным
// держателем пары.
//
// Поэтому склейка ограничена тремя условиями сразу:
//
//  1. ОДИН ПАКЕТ. Имя, объявленное в чужом пакете, вызовом отсюда не
//     разрешается; разные пакеты с одноимёнными функциями не склеиваются;
//  2. ОДНОЗНАЧНОЕ ИМЯ. Имя, объявленное в пакете больше одного раза, склейку НЕ
//     даёт: какой из одноимённых вызван, разбор без типов не знает, и
//     засчитывать любой значило бы засчитывать наугад;
//  3. ДОСТИЖИМЫЙ ВЫЗОВ. Вызов внутри заведомо мёртвой ветви (`if false`) не
//     считается: дефект, спрятанный за такой ветвью, обязан ловиться. Ровно
//     этим широкая склейка и была пробита.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО РАЗБОР НЕ ВИДИТ — НАЗВАНО, А НЕ СПРЯТАНО
//
//  1. приёмник вызова не разрешается: `a.Foo()` и `b.Foo()` при единственном в
//     пакете `Foo` склеиваются одинаково. Сузить это до типа можно только
//     разбором типов, и цена такого разбора решается отдельно;
//  2. мёртвая ветвь опознаётся по литералу `false`; ветвь, мёртвая по значению
//     переменной, здесь живая;
//  3. действие, сделанное в схеме (триггер), не Go и здесь не судится.
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
)

// PairedWriteFunc — функция и то, какие из двух действий она делает.
type PairedWriteFunc struct {
	File string
	Line int
	Pkg  string
	Name string
	// First, Second — делает ли ПРЯМО (своим оператором).
	First, Second bool
	// Calls — однозначно разрешимые имена, вызванные из ДОСТИЖИМОГО кода.
	Calls []string
}

// PairedWriteCensus — объём осмотренного.
type PairedWriteCensus struct {
	Funcs    int
	DoFirst  int
	DoSecond int
	// Ambiguous — имён, объявленных в пакете не единожды: склейку они не дают.
	Ambiguous int
	// DeadCalls — вызовов, отброшенных как стоящие в мёртвой ветви.
	DeadCalls int
}

// ScanPairedStatements собирает ОБЪЯВЛЕНИЯ операторов, вынесенные из тела:
// имя константы либо переменной → какое из двух действий она делает.
//
// ФОРМА ЭТА — НОРМА ЭТОГО ДЕРЕВА: оператор выносят ровно затем, чтобы
// исполнителей у него стало двое. Разбор, знающий только литерал В ТЕЛЕ, не
// видел бы именно тех, кого делят две полосы, — и первая редакция гейта
// действительно видела ОДИН снимающий оператор из двух (измерено).
func ScanPairedStatements(path string, src []byte, first, second *regexp.Regexp,
	into map[string][2]bool,
) error {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return err
	}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, val := range vs.Values {
				lit, ok := val.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING || i >= len(vs.Names) {
					continue
				}
				a, b := first.MatchString(lit.Value), second.MatchString(lit.Value)
				if a || b {
					cur := into[vs.Names[i].Name]
					into[vs.Names[i].Name] = [2]bool{cur[0] || a, cur[1] || b}
				}
			}
		}
	}
	return nil
}

// ScanPairedWrites разбирает ОДИН файл на пару действий, заданных образцами.
//
// statements — объявления операторов, собранные первым проходом: функция,
// назвавшая такое объявление, делает действие ровно так же, как назвавшая
// литерал.
func ScanPairedWrites(path string, src []byte, first, second *regexp.Regexp,
	statements map[string][2]bool,
) (
	[]PairedWriteFunc, PairedWriteCensus, error,
) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, PairedWriteCensus{}, err
	}
	pkg := f.Name.Name

	var out []PairedWriteFunc
	var census PairedWriteCensus
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		census.Funcs++
		rec := PairedWriteFunc{
			File: path, Line: fset.Position(fn.Pos()).Line,
			Pkg: pkg, Name: fn.Name.Name,
		}
		calls := map[string]struct{}{}
		walkReachable(fn.Body, &census, func(n ast.Node) {
			switch node := n.(type) {
			case *ast.BasicLit:
				if node.Kind != token.STRING {
					return
				}
				if first.MatchString(node.Value) {
					rec.First = true
				}
				if second.MatchString(node.Value) {
					rec.Second = true
				}
			case *ast.CallExpr:
				switch fun := node.Fun.(type) {
				case *ast.Ident:
					calls[fun.Name] = struct{}{}
				case *ast.SelectorExpr:
					calls[fun.Sel.Name] = struct{}{}
				}
			case *ast.Ident:
				does, ok := statements[node.Name]
				if !ok {
					return
				}
				rec.First = rec.First || does[0]
				rec.Second = rec.Second || does[1]
			}
		})
		rec.Calls = sortedTableSet(calls)
		if rec.First {
			census.DoFirst++
		}
		if rec.Second {
			census.DoSecond++
		}
		out = append(out, rec)
	}
	return out, census, nil
}

// walkReachable обходит тело, НЕ заходя в заведомо мёртвые ветви.
//
// Мёртвой считается ветвь `if false { … }` — условие есть литерал `false`.
// Обход считает отброшенные вызовы переписью: «мёртвых ветвей ноль» обязано
// быть отличимо от «я их не ищу».
func walkReachable(n ast.Node, census *PairedWriteCensus, visit func(ast.Node)) {
	ast.Inspect(n, func(node ast.Node) bool {
		ifs, ok := node.(*ast.IfStmt)
		if ok && isFalseLiteral(ifs.Cond) {
			ast.Inspect(ifs.Body, func(inner ast.Node) bool {
				if _, isCall := inner.(*ast.CallExpr); isCall {
					census.DeadCalls++
				}
				return true
			})
			// Мёртвую ветвь пропускаем, `else` — нет: он как раз исполняется.
			if ifs.Else != nil {
				walkReachable(ifs.Else, census, visit)
			}
			return false
		}
		if node != nil {
			visit(node)
		}
		return true
	})
}

// isFalseLiteral — условие есть литерал `false`.
func isFalseLiteral(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "false"
}

// ResolvePairedWrites достраивает второе действие ЧЕРЕЗ ВЫЗОВ — узко.
//
// Склейка идёт только по имени, объявленному в ТОМ ЖЕ пакете РОВНО ОДИН раз.
// Имя, объявленное не единожды, отбрасывается и считается переписью: молчание
// о неразличимости — та же слепота, что и молчание о находке.
func ResolvePairedWrites(funcs []PairedWriteFunc, census *PairedWriteCensus) []PairedWriteFunc {
	type key struct{ pkg, name string }
	count := map[key]int{}
	for _, f := range funcs {
		count[key{f.Pkg, f.Name}]++
	}
	does := map[key][2]bool{}
	for _, f := range funcs {
		k := key{f.Pkg, f.Name}
		cur := does[k]
		does[k] = [2]bool{cur[0] || f.First, cur[1] || f.Second}
	}
	for changed := true; changed; {
		changed = false
		for i := range funcs {
			k := key{funcs[i].Pkg, funcs[i].Name}
			cur := does[k]
			for _, callee := range funcs[i].Calls {
				ck := key{funcs[i].Pkg, callee}
				if count[ck] != 1 {
					continue
				}
				got := does[ck]
				if (got[0] && !cur[0]) || (got[1] && !cur[1]) {
					cur = [2]bool{cur[0] || got[0], cur[1] || got[1]}
					does[k] = cur
					changed = true
				}
			}
		}
	}
	for i := range funcs {
		k := key{funcs[i].Pkg, funcs[i].Name}
		for _, callee := range funcs[i].Calls {
			if count[key{funcs[i].Pkg, callee}] > 1 {
				census.Ambiguous++
			}
		}
		funcs[i].First = does[k][0]
		funcs[i].Second = does[k][1]
	}
	return funcs
}

// PairedWriteFindings — функции, делающие ПЕРВОЕ и не делающие второго.
func PairedWriteFindings(funcs []PairedWriteFunc) []PairedWriteFunc {
	var out []PairedWriteFunc
	for _, f := range funcs {
		if f.First && !f.Second {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out
}
