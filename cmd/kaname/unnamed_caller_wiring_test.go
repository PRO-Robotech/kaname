// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// unnamed_caller_wiring_test.go — страж РАЗМЕЩЕНИЯ порта присутствия
// удостоверения (задача продукта #2103).
//
// # Что здесь стережётся
//
// Политика вызывающего отвечает «назовись» тому, кто не назвался ничем, и для
// этого спрашивает ПОРТ: приложил ли вызывающий удостоверение. Порт нейтрален
// намеренно — политика не знает про читателя, читатель не знает про политику, —
// а значит реализацию подставляет композиционный корень, и подставляет он её
// ровно здесь.
//
// # Почему это отдельный страж
//
// Неподставленный порт отвечает КОНСЕРВАТИВНО («считаем, что предъявил»), то
// есть сборка без него ведёт себя ровно как до правки — молча. Молчаливое
// невыполнение и есть предмет: поведение, которого никто не заметит, не
// проверяется поведенческой пробой.
//
// # Почему разбор, а не поиск по образцу
//
// Имя предиката стоит в этом же дереве в комментариях и в пробах. Судится УЗЕЛ:
// четвёртый аргумент вызова конструктора.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// publicPolicyCtor — конструктор политики, как он пишется в корне.
const publicPolicyCtor = "authzguard.NewPublicCallerPolicy"

// presenceArgIndex — позиция порта присутствия в списке аргументов.
const presenceArgIndex = 3

func TestServe_PublicCallerPolicyGetsTheCredentialPresencePort(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "serve.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("композиционный корень не разбирается: %v", err)
	}

	calls := 0
	wired := 0
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name+"."+sel.Sel.Name != publicPolicyCtor {
			return true
		}
		calls++
		if len(call.Args) <= presenceArgIndex {
			t.Errorf("%s зовётся с %d аргументами — порт присутствия удостоверения не подставлен вовсе",
				publicPolicyCtor, len(call.Args))
			return true
		}
		arg := call.Args[presenceArgIndex]
		if ident, isIdent := arg.(*ast.Ident); isIdent && ident.Name == "nil" {
			t.Errorf("%s: порт присутствия подставлен как nil — политика молча вернётся к прежнему тону",
				publicPolicyCtor)
			return true
		}
		wired++
		return true
	})

	t.Logf("перепись: вызовов %s найдено %d, из них с подставленным портом %d",
		publicPolicyCtor, calls, wired)
	if calls == 0 {
		t.Fatalf("вызовов %s в корне НЕТ — страж стережёт координату, которой не существует",
			publicPolicyCtor)
	}
}
