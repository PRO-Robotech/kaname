// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_claim_single_source.go — разбор мест, СОБИРАЮЩИХ состав утверждений
// выданного токена (порт с монорепо
// `internal/repohygiene/tokenclaimsinglesource.go`, снят вынесением службы
// доступа — `kacho#2597`; приёмка F2, сценарий F2-42, §2.11).
//
// # Предмет
//
// Токен принципалу выдают ДВА пути: обратный вызов прежнего провайдера, пока
// он жив, и собственный эндпоинт (`internal/service/token_enrichment_own_lane.go`).
// Пока перечень утверждений и правила их вычисления живут у каждого свои,
// различие между ними НЕ ЯВЛЯЕТСЯ НИЧЬЕЙ НАХОДКОЙ: оно не выражено и потому не
// может покраснеть. Первая же правка одной стороны разойдётся с другой
// молча — у ПРИНЦИПАЛА, чей токен выдан не тем путём.
//
// # Что здесь считается СБОРКОЙ, а что ПОТРЕБЛЕНИЕМ
//
//	claims := map[string]any{"kaname_user_id": …, "kaname_account_id": …}  ← СБОРКА
//	return s.userTokenClaims(row, user, subject, hookCtx)                ← потребление
//
// Потребителей должно быть МНОГО — они и есть цель: второй способ дойти до той
// же сборки, а не второй состав. Находкой является ВТОРАЯ СБОРКА.
//
// # Почему судится ИМЯ КЛЮЧА, а не тип отображения
//
// Предмет — СЛОВАРЬ утверждений, поэтому место опознаётся по именам ключей, а
// тип значений в счёт не идёт.
//
// # Почему порог по числу ключей, а не «хоть один»
//
// Префикс утверждений встречается и вне состава — им же названы метрики и поля
// контекста. Место, назвавшее один ключ, состава не объявляет.
//
// # Что изменилось при переносе, а что осталось дословно
//
// Изменилось: пакет (`repohygiene` → `check`), путь-константа владельца (без
// префикса `services/iam/`). Осталось дословно: обе функции разбора, форма
// узла (составной литерал `map[string]…`, узел вызова), имя держателя
// `TestTokenClaimsAreAssembledInOnePlace`.
//
// # Чего разбор НЕ видит — названо, а не спрятано
//
//  1. состав, собранный присваиваниями по одному ключу за раз;
//  2. имя ключа, собранное из частей или взятое переменной;
//  3. состав, объявленный в чужом языке.
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
)

// ClaimAssembly — место, собирающее состав утверждений.
type ClaimAssembly struct {
	File string
	Line int
	Func string
	Keys []string
}

// ClaimBuilderCall — вызов сборщика состава: чем состав ПОТРЕБЛЯЕТСЯ.
type ClaimBuilderCall struct {
	File   string
	Line   int
	Func   string
	Callee string
}

// ClaimAssemblyCensus — объём осмотренного одним файлом.
type ClaimAssemblyCensus struct {
	MapLiterals      int
	EmptyMapLiterals int
	KeyedLiterals    int
	Calls            int
}

// claimFuncQualifiedName — имя объемлющей функции/метода.
func claimFuncQualifiedName(fn *ast.FuncDecl) string {
	name := fn.Name.Name
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		switch t := fn.Recv.List[0].Type.(type) {
		case *ast.StarExpr:
			if id, ok := t.X.(*ast.Ident); ok {
				name = id.Name + "." + name
			}
		case *ast.Ident:
			name = t.Name + "." + name
		}
	}
	return name
}

// ScanClaimAssemblies разбирает один файл и собирает места сборки состава.
//
// prefix — префикс имени ключа состава; minKeys — сколько РАЗНЫХ ключей делают
// место сборкой.
func ScanClaimAssemblies(path string, src []byte, prefix string, minKeys int) (
	[]ClaimAssembly, ClaimAssemblyCensus, error,
) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, ClaimAssemblyCensus{}, err
	}
	var (
		out    []ClaimAssembly
		census ClaimAssemblyCensus
	)
	for _, decl := range f.Decls {
		fn, _ := decl.(*ast.FuncDecl)
		enclosing := "уровень пакета"
		if fn != nil {
			enclosing = claimFuncQualifiedName(fn)
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			mt, ok := cl.Type.(*ast.MapType)
			if !ok {
				return true
			}
			if id, ok := mt.Key.(*ast.Ident); !ok || id.Name != "string" {
				return true
			}
			census.MapLiterals++
			keys := map[string]bool{}
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				lit, ok := kv.Key.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				name, uerr := strconv.Unquote(lit.Value)
				if uerr != nil || !strings.HasPrefix(name, prefix) {
					continue
				}
				keys[name] = true
			}
			if len(cl.Elts) == 0 {
				census.EmptyMapLiterals++
			}
			if len(keys) == 0 {
				return true
			}
			census.KeyedLiterals++
			if len(keys) < minKeys {
				return true
			}
			a := ClaimAssembly{File: path, Line: fset.Position(cl.Pos()).Line, Func: enclosing}
			for k := range keys {
				a.Keys = append(a.Keys, k)
			}
			sort.Strings(a.Keys)
			out = append(out, a)
			return true
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out, census, nil
}

// ScanClaimBuilderCalls разбирает один файл и собирает вызовы сборщиков
// состава.
func ScanClaimBuilderCalls(path string, src []byte, builders map[string]bool) (
	[]ClaimBuilderCall, ClaimAssemblyCensus, error,
) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, ClaimAssemblyCensus{}, err
	}
	var (
		out    []ClaimBuilderCall
		census ClaimAssemblyCensus
	)
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		enclosing := claimFuncQualifiedName(fn)
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			census.Calls++
			var name string
			switch fun := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = fun.Sel.Name
			case *ast.Ident:
				name = fun.Name
			default:
				return true
			}
			if !builders[name] {
				return true
			}
			out = append(out, ClaimBuilderCall{
				File: path, Line: fset.Position(call.Pos()).Line,
				Func: enclosing, Callee: name,
			})
			return true
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out, census, nil
}
