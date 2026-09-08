// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// presented_credential_wiring_test.go — страж РАЗМЕЩЕНИЯ читателя предъявленного
// удостоверения (KAN-WIRE-01 приёмки KAN-AUTHN-1, задача продукта #2077).
//
// # Что здесь стережётся
//
// Читатель предъявленного обязан стоять в цепочке ПУБЛИЧНОГО слушателя и не
// стоять во внутренней. Публичный принимает арендатора, у которого нет ни
// нашего края, чтобы передать личность, ни модульного сертификата; внутренний
// принимает соседний модуль по mTLS, и предъявленное удостоверение там не
// личность, а лишний способ назваться.
//
// # Почему разбор, а не поиск по образцу
//
// Имя пакета читателя встречается в этом же файле — в комментарии, в импорте, в
// тексте отказа. Поиск по подстроке краснел бы на собственном объяснении и
// зеленел бы на строке, лежащей в комментарии. Судится УЗЕЛ разбора: параметр
// названного типа и его употребление в теле сборщика.
//
// # Перепись печатается всегда
//
// «ноль находок» обязано быть отличимо от «ноль прочитанного»: обход пустого
// дерева здесь означал бы, что страж потерял цель, а не что цель чиста.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// presentedReaderType — тип читателя предъявленного, как он пишется в сигнатуре
// сборщика цепочки. Судится ИМЕННО тип параметра, а не имя переменной: имя
// переименовывается свободно, тип — нет.
const presentedReaderType = "presentedcred.Reader"

// chainBuilders — сборщики цепочек личности и требование к каждому.
//
// Требование объявлено таблицей, а не двумя ветками кода: сборщиков четыре
// (две полосы × два слушателя), и ветка, узнавшая про одного и не узнавшая про
// другого, выглядит полной.
var chainBuilders = []struct {
	name           string
	wantsPresented bool
	why            string
}{
	{"publicIdentityUnary", true, "публичный слушатель принимает арендатора, которому нечем назваться иначе"},
	{"publicIdentityStream", true, "вторая полоса того же слушателя: полоса без читателя при полосе с читателем — различие, которого никто не принимал"},
	{"identityUnary", false, "внутренний слушатель принимает соседний модуль по mTLS; предъявленное там — лишний способ назваться"},
	{"identityStream", false, "то же на второй полосе внутреннего слушателя"},
}

// TestServe_PublicChainCarriesThePresentedCredentialReader — читатель стоит в
// публичной цепочке и не стоит во внутренней.
//
// RED до правки: сборщика `publicIdentityUnary` не существует вовсе, публичная и
// внутренняя цепочки собираются ОДНИМ вызовом и потому тождественны.
func TestServe_PublicChainCarriesThePresentedCredentialReader(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "serve.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("композиционный корень не разбирается: %v", err)
	}

	funcs := map[string]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil {
			continue
		}
		funcs[fn.Name.Name] = fn
	}
	if len(funcs) == 0 {
		t.Fatal("обход пуст: в composition root не найдено ни одной функции — страж судил бы о непрочитанном")
	}

	var carrying int
	for _, b := range chainBuilders {
		fn, ok := funcs[b.name]
		if !ok {
			t.Fatalf("serve.go: сборщик цепочки %s не объявлен — страж потерял цель, "+
				"обнови его вместе с проводкой", b.name)
		}
		param, found := paramNamedByType(fn, presentedReaderType)
		used := found && identifierUsedInBody(fn, param)
		if used {
			carrying++
		}
		switch {
		case b.wantsPresented && !found:
			t.Errorf("serve.go: %s не принимает читателя предъявленного (%s) — арендатор чужого "+
				"облака не может назваться ничем: %s", b.name, presentedReaderType, b.why)
		case b.wantsPresented && !used:
			t.Errorf("serve.go: %s принимает читателя предъявленного, но не ставит его в цепочку — "+
				"параметр объявлен и не читается, то есть проверка присутствует и не исполняется", b.name)
		case !b.wantsPresented && found:
			t.Errorf("serve.go: %s принимает читателя предъявленного, а не должен: %s", b.name, b.why)
		}
	}

	t.Logf("перепись: функций в композиционном корне %d · сборщиков цепочки осмотрено %d · "+
		"несут читателя предъявленного %d", len(funcs), len(chainBuilders), carrying)
}

// TestServe_PublicIdentityBuilderStillSeedsFromTheSharedOne — читатель
// ДОБАВЛЯЕТСЯ к общей паре извлечения личности, а не заменяет её.
//
// Без этого утверждения публичный сборщик мог бы собрать свою цепочку с нуля:
// читатель стоял бы, круг разрешённых отправителей — нет, и прежний путь
// (KAN-FWD-01…03) отвалился бы молча, оставаясь зелёным на пробах внутреннего
// слушателя.
func TestServe_PublicIdentityBuilderStillSeedsFromTheSharedOne(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "serve.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("композиционный корень не разбирается: %v", err)
	}

	want := map[string]string{
		"publicIdentityUnary":  "identityUnary",
		"publicIdentityStream": "identityStream",
	}
	seen := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil {
			continue
		}
		shared, watched := want[fn.Name.Name]
		if !watched {
			continue
		}
		seen++
		if !callsFunction(fn, shared) {
			t.Errorf("serve.go: %s не зовёт общий сборщик %s — публичная цепочка собиралась бы "+
				"мимо пары извлечения личности, и круг разрешённых отправителей перестал бы "+
				"сужать что-либо", fn.Name.Name, shared)
		}
	}
	if seen != len(want) {
		t.Fatalf("осмотрено %d публичных сборщиков из %d — страж потерял цель", seen, len(want))
	}
	t.Logf("перепись: публичных сборщиков осмотрено %d · каждый зовёт общий", seen)
}

// paramNamedByType возвращает имя параметра названного типа. Тип сверяется по
// напечатанному выражению, поэтому указатель и значение одного типа читаются
// одинаково: предмет — ЧТО принимается, а не как именно.
func paramNamedByType(fn *ast.FuncDecl, typeName string) (string, bool) {
	if fn.Type.Params == nil {
		return "", false
	}
	for _, field := range fn.Type.Params.List {
		if !strings.Contains(exprString(field.Type), typeName) {
			continue
		}
		if len(field.Names) == 0 {
			// Безымянный параметр прочитан быть не может by construction.
			return "", true
		}
		return field.Names[0].Name, true
	}
	return "", false
}

// identifierUsedInBody отвечает, читается ли имя в теле функции. Объявленный и
// нечитаемый параметр — это проверка, которая присутствует и не исполняется.
func identifierUsedInBody(fn *ast.FuncDecl, name string) bool {
	if fn.Body == nil || name == "" {
		return false
	}
	used := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == name {
			used = true
		}
		return !used
	})
	return used
}

// callsFunction отвечает, зовёт ли тело функции названную функцию по имени.
func callsFunction(fn *ast.FuncDecl, callee string) bool {
	if fn.Body == nil {
		return false
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == callee {
			found = true
		}
		return !found
	})
	return found
}

// exprString печатает выражение типа для сверки.
func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.StarExpr:
		return "*" + exprString(v.X)
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.Ident:
		return v.Name
	case *ast.ArrayType:
		return "[]" + exprString(v.Elt)
	default:
		return ""
	}
}
