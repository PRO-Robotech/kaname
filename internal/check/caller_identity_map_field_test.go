// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/token"
	"testing"
)

func TestCallerIdentityLifetimeMapValueField(t *testing.T) {
	const setup = `type Entry struct{ Extract func() };type Table map[any]Entry`
	for _, tc := range []struct {
		name, init string
		mayReach   bool
	}{
		{"empty", `table:=Table{}`, false},
		{"independent_value", `table:=Table{"entry":{Extract:func(){}}}`, false},
		{"key_only_reference", `key=anchor;table:=Table{key:{Extract:func(){}}}`, false},
		{"captured_reference", `table:=Table{"entry":{Extract:func(){source.Mutate(anchor)}}}`, true},
		{"later_alias_write", `table:=Table{};alias:=table;alias["entry"]=Entry{Extract:func(){source.Mutate(anchor)}}`, true},
		{"opaque_value", `table:=Table{"entry":{Extract:source.Value().(func())}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := callerSoundnessProgram(t, setup, `anchor:=&Box{};_=anchor;var key any="entry";`+tc.init+`;_=table[key].Extract`, `&Handler{}`)
			g := newCallerGraph(p)
			g.safeExternal = map[string]bool{"fixture/source": true}
			g.lifetimeScanning = true
			var read valueSrc
			var anchor callerObjectKey
			for node, body := range g.bodies {
				if body.sp != p.root || node.fn == nil || node.fn.Name() != "RPC" {
					continue
				}
				g.markCallerCalled(node)
				ast.Inspect(body.node, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.UnaryExpr:
						if lit, ok := x.X.(*ast.CompositeLit); ok && x.Op == token.AND {
							anchor = callerObjectKey{pkg: body.sp, expr: lit}
						}
					case *ast.SelectorExpr:
						if x.Sel.Name == "Extract" {
							read = valueSrc{pkg: body.sp, fk: callerKey(node), expr: x, tuple: -1}
						}
					}
					return true
				})
			}
			if anchor.expr == nil || read.expr == nil {
				t.Fatal("фикстура не нашла выделение или чтение поля значения карты")
			}
			probe := callerLifetimeProbe{g: g, want: anchor, seen: map[callerResolveKey]bool{}, objects: map[callerObjectKey]bool{}}
			if got := probe.contains(read); got != tc.mayReach {
				t.Fatalf("достижимость выделения через поле значения карты = %t, ожидается %t", got, tc.mayReach)
			}
		})
	}
}
