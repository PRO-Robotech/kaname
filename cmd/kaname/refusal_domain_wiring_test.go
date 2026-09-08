// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// refusal_domain_wiring_test.go — страж РАЗМЕЩЕНИЯ объявления домена отказа
// (задача продукта #2099, сценарий WIRE-3-03 приёмки WIRE-1).
//
// # Что здесь стережётся
//
// Суффикс домена отказа объявляется композиционным корнем ОДИН раз, и сборка,
// объявления не сделавшая, не поднимается. Без этого стража страж времени
// исполнения (`refusaldomain.Require`) был бы утверждением о самом себе:
// он зелен ровно тогда, когда кто-то позвал объявление, — а звал ли, не сказано
// нигде.
//
// # Почему разбор, а не поиск по образцу
//
// Имя пакета встречается в этом же дереве в комментариях и в текстах отказов.
// Поиск по подстроке краснел бы на собственном объяснении проверяемого и зеленел
// бы на упоминании в прозе. Судится УЗЕЛ вызова: селектор `refusaldomain.X` в
// теле названной функции.
//
// # Перепись печатается всегда
//
// «ноль находок» обязано быть отличимо от «ноль прочитанного».

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// refusalDomainPkg — имя пакета объявления, как оно пишется в вызове.
const refusalDomainPkg = "refusaldomain"

// refusalDomainWiring — где что обязано быть позвано.
//
// Таблица, а не две ветки: точек две, и ветка, узнавшая про одну и не узнавшая
// про другую, выглядит полной.
var refusalDomainWiring = []struct {
	file string
	fn   string
	call string
	why  string
}{
	{"main.go", "main", "Declare",
		"объявление делается ДО подъёма чего бы то ни было: производители отказа читают его на первом же запросе"},
	{"serve.go", "runServe", "Require",
		"страж стоит там, где поднимаются слушатели: сборка, собранная в обход main, обязана отказать, а не отвечать пустым доменом"},
}

func TestServe_CompositionRootDeclaresTheRefusalDomain(t *testing.T) {
	seen := 0
	for _, w := range refusalDomainWiring {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, w.file, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s не разбирается: %v", w.file, err)
		}
		var fn *ast.FuncDecl
		for _, decl := range file.Decls {
			d, ok := decl.(*ast.FuncDecl)
			if ok && d.Recv == nil && d.Name.Name == w.fn {
				fn = d
			}
		}
		if fn == nil {
			t.Fatalf("%s: функции %s нет — страж стережёт координату, которой не существует", w.file, w.fn)
		}
		seen++
		if !callsPackageFunc(fn, refusalDomainPkg, w.call) {
			t.Errorf("%s: %s не зовёт %s.%s — %s", w.file, w.fn, refusalDomainPkg, w.call, w.why)
		}
	}
	t.Logf("перепись: точек провязки объявлено %d, функций прочитано %d",
		len(refusalDomainWiring), seen)
	if seen == 0 {
		t.Fatal("обход пуст: не прочитано ни одной функции — страж судил бы о непрочитанном")
	}
}

// callsPackageFunc — тело функции зовёт `pkg.name(...)`.
func callsPackageFunc(fn *ast.FuncDecl, pkg, name string) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != name {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if ok && ident.Name == pkg {
			found = true
		}
		return true
	})
	return found
}
