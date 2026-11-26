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

func TestCallerIdentityLifetimeAppendCopiedStringField(t *testing.T) {
	const setup = `type Record struct{ Text string; Texts []string }
func collect(unknown *Record, texts []string) {
	copied := append([]string{}, unknown.Text)
	withBase := append(unknown.Texts, unknown.Text)
	address := append([]*string{}, &unknown.Text)
	boxed := append([]any{}, unknown.Text)
	spread := append(texts, []string{unknown.Text}...)
	_, _, _, _, _ = copied, withBase, address, boxed, spread
	{
		append := func(_ []string, text string) []string { return []string{text} }
		shadowed := append(texts, unknown.Text)
		_ = shadowed
	}
}`
	program := callerSoundnessProgram(t, setup, `_=(&Box{})`, `&Handler{}`)
	g := newCallerGraph(program)
	g.lifetimeScanning = true
	var wanted callerObjectKey
	appends := map[string]valueSrc{}
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
				assign, ok := n.(*ast.AssignStmt)
				if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
					return true
				}
				if id, ok := assign.Lhs[0].(*ast.Ident); ok {
					if call, ok := assign.Rhs[0].(*ast.CallExpr); ok {
						appends[id.Name] = valueSrc{pkg: body.sp, fk: callerKey(node), expr: call, tuple: -1}
					}
				}
				return true
			})
		}
	}
	if wanted.expr == nil || len(appends) != 6 {
		t.Fatal("фикстура не нашла выделение или выражения append")
	}
	for name, src := range appends {
		call := src.expr.(*ast.CallExpr)
		base, _ := call.Args[0].(*ast.SelectorExpr)
		if base != nil && g.copiedStringFields[base] != nil {
			t.Fatalf("%s: исходный срез попал в индекс скопированных полей", name)
		}
		var read *ast.SelectorExpr
		ast.Inspect(call.Args[1], func(n ast.Node) bool {
			if selector, ok := n.(*ast.SelectorExpr); ok {
				read = selector
			}
			return true
		})
		if read == nil || (g.copiedStringFields[read] == src.pkg) != (name == "copied" || name == "withBase") {
			t.Fatalf("%s: индекс различает только копии в стандартный append строки", name)
		}
	}
	field := wanted.pkg.info.TypeOf(wanted.expr).Underlying().(*types.Struct).Field(0)
	contains := func(src valueSrc) bool {
		p := callerLifetimeProbe{g: g, want: wanted, field: field, seen: map[callerResolveKey]bool{}, objects: map[callerObjectKey]bool{}}
		return p.contains(src)
	}
	if contains(appends["copied"]) || !contains(appends["withBase"]) {
		t.Fatal("копия строки не должна скрывать неизвестный исходный срез")
	}
	g.copiedStringFields = nil
	if !contains(appends["copied"]) {
		t.Fatal("без доказательства копии владелец должен остаться неизвестным")
	}
}
