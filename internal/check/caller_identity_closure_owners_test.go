// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"testing"
)

func TestCallerIdentityClosureOwnersPreserveScan(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "owners.go", `package fixture
var packageLiteral = func() {}
func outer() {
  _ = func() { _ = func() {} }
  _ = func() {}
}
func unrelated() {}
`, 0)
	if err != nil {
		t.Fatal(err)
	}
	g := &callerGraph{bodies: map[callerNode]callerBody{}, called: map[callerNode]bool{}}
	decls := map[string]callerNode{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			node := callerNode{fn: types.NewFunc(fn.Pos(), nil, fn.Name.Name, nil)}
			decls[fn.Name.Name] = node
			g.bodies[node] = callerBody{node: fn.Body}
		}
	}
	var literals []*ast.FuncLit
	ast.Inspect(file, func(n ast.Node) bool {
		if lit, ok := n.(*ast.FuncLit); ok {
			literals = append(literals, lit)
			g.bodies[callerNode{lit: lit}] = callerBody{node: lit.Body}
		}
		return true
	})
	if len(literals) != 4 {
		t.Fatalf("literal inventory: %d", len(literals))
	}
	pkg, middle, inner, sibling := literals[0], literals[1], literals[2], literals[3]
	g.indexCallerClosureOwners()
	if owners, known := g.closureOwners[pkg]; !known || len(owners) != 0 {
		t.Fatal("package-level literal must have an explicit empty index entry")
	}
	if len(g.closureOwners[inner]) != 2 {
		t.Fatal("inner literal must retain both enclosing ancestors")
	}
	oldScan := func(graph *callerGraph, lit *ast.FuncLit) bool {
		if graph.called[callerNode{lit: lit}] {
			return true
		}
		for node, body := range graph.bodies {
			if node.lit == lit || body.node.Pos() > lit.Pos() || body.node.End() < lit.End() {
				continue
			}
			if graph.called[node] {
				return true
			}
		}
		return false
	}
	for _, tc := range []struct {
		name   string
		called []callerNode
	}{
		{"none", nil},
		{"outer", []callerNode{decls["outer"]}},
		{"middle", []callerNode{{lit: middle}}},
		{"inner-self", []callerNode{{lit: inner}}},
		{"sibling", []callerNode{{lit: sibling}}},
		{"unrelated", []callerNode{decls["unrelated"]}},
		{"package-self", []callerNode{{lit: pkg}}},
		{"multiple", []callerNode{decls["outer"], {lit: middle}, {lit: pkg}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g.called = map[callerNode]bool{}
			for _, node := range tc.called {
				g.called[node] = true
			}
			for i, lit := range literals {
				if got, want := g.callerClosureCreated(lit), oldScan(g, lit); got != want {
					t.Fatalf("literal %d indexed=%v old=%v", i, got, want)
				}
			}
		})
	}
	g.called = map[callerNode]bool{}
	if g.callerClosureCreated(inner) {
		t.Fatal("cold false")
	}
	g.called[decls["outer"]] = true
	if g.called[callerNode{lit: middle}] || !g.callerClosureCreated(inner) {
		t.Fatal("warm false must become true through the outer ancestor alone")
	}
	shared := *g // Неизменяемый индекс общий; изменяемые карты called независимы.
	shared.called = map[callerNode]bool{}
	if shared.callerClosureCreated(inner) || !g.callerClosureCreated(inner) {
		t.Fatal("shared ownership index leaked called state")
	}
	g.called = map[callerNode]bool{}
	if g.callerClosureCreated(inner) {
		t.Fatal("called reset retained true")
	}
	g.called[callerNode{lit: inner}] = true
	before := g.work.ClosureOwnershipCandidates
	if !g.callerClosureCreated(inner) || g.work.ClosureOwnershipCandidates != before {
		t.Fatal("self-called must win before owner lookup")
	}
	if g.work.ClosureOwnershipFallbacks != 0 {
		t.Fatal("known literals used fallback")
	}
	g.called = map[callerNode]bool{decls["outer"]: true}
	unknown := *inner // Новая идентичность при тех же границах синтаксиса не индексируется.
	if _, known := g.closureOwners[&unknown]; known {
		t.Fatal("unknown fixture is indexed")
	}
	before = g.work.ClosureOwnershipFallbacks
	if got, want := g.callerClosureCreated(&unknown), oldScan(g, &unknown); got != want || !got || g.work.ClosureOwnershipFallbacks != before+1 {
		t.Fatal("unknown literal must use exact old scan")
	}
	g.called = map[callerNode]bool{}
	before = g.work.ClosureOwnershipFallbacks
	if got, want := g.callerClosureCreated(&unknown), oldScan(g, &unknown); got != want || got || g.work.ClosureOwnershipFallbacks != before+1 {
		t.Fatal("unknown literal false must also use exact old scan")
	}
	g.called[decls["outer"]] = true
	manual := *g
	manual.closureOwners = nil
	before = manual.work.ClosureOwnershipFallbacks
	if got, want := manual.callerClosureCreated(inner), oldScan(&manual, inner); got != want || !got || manual.work.ClosureOwnershipFallbacks != before+1 {
		t.Fatal("nil-index manual graph must use exact old scan")
	}
}
