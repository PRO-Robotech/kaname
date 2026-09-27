// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// address_gate_wiring_test.go — страж РАЗМЕЩЕНИЯ рубежа адреса (приёмка
// `access-beyond-login-needs-a-verified-address.md`, kaname#456, Р4б, Р4в):
// на ОБОИХ слушателях, в ОБЕИХ полосах (однократный вызов и поток) рубеж стоит
// сразу после политики вызывающего — раньше пола системного читателя, пола
// ступени подтверждения личности, анти-анонима, двери решения и обработчика.
//
// Поведение рубежа (кого он отвергает, на каких методах, чем) держат пробы
// `internal/authzguard` над настоящей базой отметок; здесь — что именно ЭТОТ
// рубеж получают оба слушателя композиционного корня. Разбор — синтаксическим
// деревом `serve.go`, а не поиском по тексту: цепочка — узел вызова `append`,
// её звено — выражение в списке аргументов.

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"strings"
	"testing"
)

// addressGateChains — четыре цепочки корня и звено, после которого рубеж обязан
// стоять.
var addressGateChains = []struct {
	chain, after, gate string
}{
	{"publicUnary", "publicCallerPolicy.Unary()", "addressGate.Unary()"},
	{"publicStream", "publicCallerPolicy.Stream()", "addressGate.Stream()"},
	{"internalUnary", "internalCallerPolicy.Unary()", "addressGate.Unary()"},
	{"internalStream", "internalCallerPolicy.Stream()", "addressGate.Stream()"},
}

// chainLinks — звенья, дописанные к цепочке name присваиванием
// `name = append(name, …)`, печатью узла; осмотрено присваиваний — n.
func chainLinks(t *testing.T, file *ast.File, fset *token.FileSet, name string) (links []string, n int) {
	t.Helper()
	ast.Inspect(file, func(node ast.Node) bool {
		as, ok := node.(*ast.AssignStmt)
		if !ok || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		id, ok := as.Lhs[0].(*ast.Ident)
		if !ok || id.Name != name {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		if fn, ok := call.Fun.(*ast.Ident); !ok || fn.Name != "append" || len(call.Args) < 2 {
			return true
		}
		if first, ok := call.Args[0].(*ast.Ident); !ok || first.Name != name {
			return true
		}
		n++
		for _, a := range call.Args[1:] {
			var b strings.Builder
			if err := printer.Fprint(&b, fset, a); err != nil {
				t.Fatalf("печать звена: %v", err)
			}
			links = append(links, b.String())
		}
		return true
	})
	return links, n
}

// TestAddressGateStandsRightAfterTheCallerPolicyOnBothListeners — Р4б, Р4в.
func TestAddressGateStandsRightAfterTheCallerPolicyOnBothListeners(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "serve.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("разбор serve.go: %v", err)
	}
	for _, c := range addressGateChains {
		links, n := chainLinks(t, file, fset, c.chain)
		if n == 0 {
			t.Fatalf("%s: дописывания цепочки `%s = append(%s, …)` в serve.go нет — проба судит не то дерево",
				c.chain, c.chain, c.chain)
		}
		t.Logf("%s: присваиваний %d, звеньев %d: %v", c.chain, n, len(links), links)
		at := -1
		for i, l := range links {
			if l == c.after {
				at = i
			}
		}
		if at < 0 {
			t.Fatalf("%s: звена %s нет — предпосылка пробы не держится", c.chain, c.after)
		}
		if at+1 >= len(links) || links[at+1] != c.gate {
			t.Fatalf("ЧЕСТНЫЙ-КРАСНЫЙ %s: сразу после %s должен стоять рубеж адреса %s; звенья: %v",
				c.chain, c.after, c.gate, links)
		}
	}
}
