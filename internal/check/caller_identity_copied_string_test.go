// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/types"
	"testing"
)

func TestCallerIdentityLifetimeCopiedStringField(t *testing.T) {
	const setup = `type Record struct{ Text string; Ref *Box }
type Copy struct{ Text string; Address *string; Ref *Box }
func collect(unknown *Record){ _=Copy{Text:unknown.Text, Address:&unknown.Text, Ref:unknown.Ref} }`
	program := callerSoundnessProgram(t, setup, `_=(&Box{})`, `&Handler{}`)
	g := newCallerGraph(program)
	g.lifetimeScanning = true
	var wanted callerObjectKey
	values := map[string]valueSrc{}
	for node, body := range g.bodies {
		if body.sp != program.root || node.fn == nil {
			continue
		}
		switch node.fn.Name() {
		case "RPC":
			ast.Inspect(body.node, func(n ast.Node) bool {
				if lit, ok := n.(*ast.CompositeLit); ok {
					wanted = callerObjectKey{pkg: body.sp, expr: lit}
				}
				return true
			})
		case "collect":
			ast.Inspect(body.node, func(n ast.Node) bool {
				if pair, ok := n.(*ast.KeyValueExpr); ok {
					values[pair.Key.(*ast.Ident).Name] = valueSrc{pkg: body.sp, fk: callerKey(node), expr: pair.Value, tuple: -1}
				}
				return true
			})
		}
	}
	if wanted.expr == nil || len(values) != 3 {
		t.Fatal("фикстура не нашла выделение или поля копии")
	}
	field := wanted.pkg.info.TypeOf(wanted.expr).Underlying().(*types.Struct).Field(0)
	contains := func(src valueSrc) bool {
		p := callerLifetimeProbe{g: g, want: wanted, field: field, seen: map[callerResolveKey]bool{}, objects: map[callerObjectKey]bool{}}
		return p.contains(src)
	}
	if contains(values["Text"]) || !contains(values["Address"]) || !contains(values["Ref"]) {
		t.Fatal("потеряно различие между копией строки, адресом ячейки и ссылочным полем")
	}
	g.copiedStringFields = nil
	if !contains(values["Text"]) {
		t.Fatal("без доказательства копии владелец должен остаться неизвестным")
	}
}
