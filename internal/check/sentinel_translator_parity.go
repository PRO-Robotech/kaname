// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// sentinel_translator_parity.go — разбор ПЕРЕВОДЧИКОВ отказа: какие полосы
// каждый из них различает.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Переводчик отказа — то место, где признак хранилища становится кодом gRPC. У
// домена он свой: текст терминального INTERNAL называет предмет («internal SA
// key error»), и сводить их в один нельзя — текст есть часть контракта.
//
// Своим обязан быть ТЕКСТ, а не НАБОР РАЗЛИЧАЕМЫХ ПОЛОС. Полоса, которой
// переводчик не знает, уезжает в терминальный INTERNAL — то есть отказ,
// ПОВТОРЯЕМЫЙ по своей природе, приходит клиенту как поломка платформы, и
// клиент не повторит. Обратное так же плохо: отказ в правах, поданный как
// INTERNAL, прячет от вызывающего, что ему нечего чинить повтором.
//
// Класс уже закрывался ОДНАЖДЫ и вернулся. Годок канонического переводчика
// говорит дословно: «Полное покрытие 8 sentinel'ов (включая ErrPermissionDenied
// / ErrUnauthenticated, которых не было в per-resource копиях — leak'ало
// codes.Internal клиенту до этой консолидации)». Копии завелись заново и снова
// разошлись набором ветвей (kaname#114): `ErrAborted` достижим — 40001/40P01
// приходит из `pgmaperr`, — и на путях ключей и токенов уходил в INTERNAL.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СЧИТАЕТСЯ ПЕРЕВОДЧИКОМ — ПРИЗНАК СЕМАНТИЧЕСКИЙ, А НЕ ПО ИМЕНИ
//
// Предикат по имени (`mapPGErr`, `mapErr`) мерил бы соглашение об именовании:
// переводчик, названный иначе, прошёл бы мимо — ровно тот отказ, который гейт и
// заводится закрыть. Переводчиком считается функция, у которой ОБА признака:
//
//  1. она различает ДВА И БОЛЕЕ разных sentinel'а `iamerr.Err*` в условии
//     (ветвь `case` бестегового `switch` либо условие `if`);
//  2. её ПОСЛЕДНИЙ оператор — терминальный `status.Error(codes.Internal, "…")`
//     с литералом.
//
// Второй признак и есть «переводчик», а не «проверка на месте вызова»: функция,
// разбирающая одну полосу и отдающая остальное канону (`shared.MapRepoErr`),
// терминального INTERNAL не несёт и под разбор не подпадает. Без этого признака
// находкой стал бы каждый вызывающий, спрашивающий `ErrNotFound`.
//
// ─────────────────────────────────────────────────────────────────────────────
// ФОРМЫ ЗАПИСИ ПЕРЕЧИСЛЕНЫ ПОИМЁННО
//
// Форма, о которой распознаватель не знает, даёт МОЛЧАНИЕ. Читаются:
//
//	case errors.Is(err, iamerr.ErrX):        — ветвь бестегового switch
//	case stderrors.Is(err, iamerr.ErrX):     — он же под псевдонимом пакета
//	if errors.Is(err, iamerr.ErrX) { … }     — условие if
//	errors.Is(a, iamerr.ErrX) || errors.Is(…) — дизъюнкция внутри условия
//
// Псевдоним пакета `errors` разбор НЕ читает намеренно: он опознаёт sentinel по
// АРГУМЕНТУ (`iamerr.ErrX`), а не по имени вызываемого пакета. Поэтому
// `stderrors`, `goerrors` и любое другое написание опознаются одинаково.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО РАЗБОР НЕ ВИДИТ — НАЗВАНО, А НЕ СПРЯТАНО
//
//  1. **порядок ветвей**. Он несущий (у канона вложенные полосы спрашиваются до
//     общего switch'а), но это другой предмет и другой гейт;
//  2. **правильность КОДА** у ветви. Гейт судит, различает ли переводчик полосу,
//     а не в какой код он её переводит;
//  3. **переводчик БЕЗ терминального INTERNAL** — он под признак не подпадает и
//     остаётся вне наблюдения. Это осознанная граница: без неё находкой стала бы
//     всякая проверка на месте вызова.
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
)

// SentinelIAMPackage — пакет sentinel'ов, по которому они опознаются.
const SentinelIAMPackage = "iamerr"

// SentinelTranslator — один найденный переводчик отказа.
type SentinelTranslator struct {
	File string
	Line int
	Func string
	// Sentinels — имена `iamerr.Err*`, которые переводчик различает,
	// отсортированы.
	Sentinels []string
}

// Has — различает ли переводчик эту полосу.
func (t SentinelTranslator) Has(sentinel string) bool {
	for _, s := range t.Sentinels {
		if s == sentinel {
			return true
		}
	}
	return false
}

// SentinelTranslatorCensus — объём осмотренного одним файлом.
type SentinelTranslatorCensus struct {
	// Funcs — функций прочитано.
	Funcs int
	// WithSentinels — из них различающих хотя бы один `iamerr.Err*`.
	WithSentinels int
	// Translators — из них переводчиков (оба признака).
	Translators int
}

// ScanSentinelTranslators разбирает один файл и возвращает переводчиков вместе
// с объёмом осмотренного.
func ScanSentinelTranslators(path string, src []byte) (out []SentinelTranslator, census SentinelTranslatorCensus, err error) {
	fset := token.NewFileSet()
	f, perr := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if perr != nil {
		return nil, SentinelTranslatorCensus{}, perr
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		census.Funcs++
		sent := sentinelsDispatchedOn(fd.Body)
		if len(sent) > 0 {
			census.WithSentinels++
		}
		if len(sent) < 2 || !endsWithTerminalInternal(fd.Body) {
			continue
		}
		census.Translators++
		out = append(out, SentinelTranslator{
			File:      path,
			Line:      fset.Position(fd.Pos()).Line,
			Func:      fd.Name.Name,
			Sentinels: sent,
		})
	}
	return out, census, nil
}

// sentinelsDispatchedOn — sentinel'ы, различаемые В УСЛОВИИ: ветвь бестегового
// switch либо условие if. Вызов `errors.Is` в теле ветви условием не является —
// иначе делегирование канону читалось бы как собственное различение.
func sentinelsDispatchedOn(body *ast.BlockStmt) []string {
	seen := map[string]bool{}
	collect := func(e ast.Expr) {
		ast.Inspect(e, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				return true
			}
			if name, ok := sentinelName(call.Args[1]); ok {
				seen[name] = true
			}
			return true
		})
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.SwitchStmt:
			if s.Tag != nil {
				return true // switch по значению — не разбор признака
			}
			for _, st := range s.Body.List {
				cc, ok := st.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, e := range cc.List {
					collect(e)
				}
			}
		case *ast.IfStmt:
			collect(s.Cond)
		}
		return true
	})
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// sentinelName — имя `iamerr.ErrX` из выражения-аргумента. Опознаётся по
// АРГУМЕНТУ, а не по имени вызываемого пакета: псевдоним `errors` тогда
// безразличен by construction.
func sentinelName(e ast.Expr) (string, bool) {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != SentinelIAMPackage {
		return "", false
	}
	if !strings.HasPrefix(sel.Sel.Name, "Err") {
		return "", false
	}
	return sel.Sel.Name, true
}

// endsWithTerminalInternal — последний оператор тела возвращает
// `status.Error(codes.Internal, "<литерал>")`. Это и есть признак «переводчик»:
// функция, отдающая остаток канону, его не несёт.
func endsWithTerminalInternal(body *ast.BlockStmt) bool {
	if len(body.List) == 0 {
		return false
	}
	ret, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
	if !ok {
		return false
	}
	for _, res := range ret.Results {
		call, ok := res.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			continue
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Error" {
			continue
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "status" {
			continue
		}
		code, ok := call.Args[0].(*ast.SelectorExpr)
		if !ok || code.Sel.Name != "Internal" {
			continue
		}
		if _, ok := call.Args[1].(*ast.BasicLit); ok {
			return true
		}
	}
	return false
}
