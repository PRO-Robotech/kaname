// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"go/types"
	"strings"
	"testing"
)

func TestCallerIdentityPrivateAppendReceiver(t *testing.T) {
	const self = "r.Values=append(r.Values,v);"
	const local = "var local Rows;"
	const invoke = "local.add(v);"
	for _, tc := range []struct {
		name, setup, receiver, prefix, call string
		want                                bool
	}{
		{"zero", "", "", local, invoke, true},
		{"external_backing", "", "", "local:=Rows{Values:source.Value().([]any)};", invoke, false},
		{"injected_field", "", "", local + "local.Values=source.Value().([]any);", invoke, false},
		{"injected_receiver_field", "", "r.Values=source.Value().([]any);", local, invoke, false},
		{"injected_sibling", "", "r.Other=source.Value().([]any);", local, invoke, false},
		{"whole_write", "", "*r=source.Value().(Rows);", local, invoke, false},
		{"receiver_escape", "", "source.Mutate(r);", local, invoke, false},
		{"receiver_field_escape", "", "source.Mutate(&r.Other);", local, invoke, false},
		{"caller_escape", "", "", local + "source.Mutate(&local);", invoke, false},
		{"caller_field_escape", "", "", local + "source.Mutate(&local.N);", invoke, false},
		{"captured_local", "", "", local + "_ = func(){_=local.N};", invoke, false},
		{"captured_receiver", "", "_=func(){r.N++};", local, invoke, false},
		{"bound_value", "", "", local, "f:=local.add;f(v);", false},
		{"package_method_expression", "var indirect=(*Rows).add", "", local, invoke, false},
		{"package_bound_value", "var global Rows;var indirect=global.add", "", local, invoke, false},
		{"interface_method", "type writer interface{add(any)};func indirect(w writer){w.add(nil)}", "", local, invoke, false},
		{"second_receiver", "func more(v *Rows){v.add(nil)}", "", local, invoke, false},
		{"injected_pointer", "", "", "local:=source.Value().(*Rows);", invoke, false},
		{"promoted_method", "type OuterRows struct{Rows}", "", "var outer OuterRows;local:=outer.Rows;", "outer.add(v);", false},
		{"deferred", "", "", local, "defer local.add(v);", false},
		{"goroutine", "", "", local, "go local.add(v);", false},
		{"package_initializer", "var global Rows;var once=func()int{global.add(nil);return 1}()", "", local, invoke, false},
		{"foreign_body", "func native()", "", local, invoke, false},
		{"package_bound", "func spare(){var i int;" + strings.Repeat("_=i;", callerLifetimeStepLimit/2) + "}", "", local, invoke, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := "return local,n"
			if tc.name == "injected_pointer" {
				result = "return *local,n"
			}
			setup := "type Rows struct{Values,Other []any;N int;Totals struct{Count int}}\n" +
				"func(r *Rows)add(v any){" + tc.receiver + self + "r.Other=append(r.Other,v);r.N++;r.Totals.Count+=1}\n" +
				"func dispatch(v any)(Rows,int){" + tc.prefix + tc.call + "n:=local.N+len(local.Other);" + result + "}\n" + tc.setup
			p := callerSoundnessProgram(t, setup, "anchor:=&Box{};candidate:=[]any{};_,_=dispatch(anchor);_=anchor;_=candidate", "&Handler{}")
			g := newCallerGraph(p)
			var write callerLifetimeWrite
			for _, w := range g.lifetimeWrites {
				if w.owner.fk.fn != nil && w.owner.fk.fn.Name() == "add" {
					if sel, ok := w.owner.expr.(*ast.SelectorExpr); ok && sel.Sel.Name == "Values" {
						write = w
					}
				}
			}
			var lit ast.Expr
			for _, f := range p.root.files {
				for n := range ast.Preorder(f) {
					a, ok := n.(*ast.AssignStmt)
					if ok && len(a.Lhs) == 1 && len(a.Rhs) == 1 {
						if id, ok := a.Lhs[0].(*ast.Ident); ok && id.Name == "candidate" {
							lit = a.Rhs[0]
						}
					}
				}
			}
			if write.owner.expr == nil || lit == nil {
				t.Fatal("неполная фикстура записи")
			}
			object := callerObjectKey{pkg: p.root, expr: lit}
			probe := callerLifetimeProbe{g: g}
			if got := probe.separateLocalAppendBacking(write, object); got != tc.want {
				t.Fatalf("отдельность=%t, ожидалось %t", got, tc.want)
			}
			if !tc.want {
				return
			}
			whole := write
			whole.whole = true
			if probe.separateLocalAppendBacking(whole, object) {
				t.Fatal("пропущена запись всей ячейки")
			}
			probe.steps = callerLifetimeStepLimit + 1
			if probe.separateLocalAppendBacking(write, object) {
				t.Fatal("исчерпанный бюджет принят за доказательство")
			}
			probe.steps = 0
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			g.ctx = ctx
			if probe.separateLocalAppendBacking(write, object) {
				t.Fatal("отмена проигнорирована при попадании в кеш")
			}
			g.ctx = context.Background()
			// Повторная проверка, будто пакет импортировал unsafe: типизированный
			// импорт достаточен для отказа даже тогда, когда комментарии не разобраны.
			imports := append([]*types.Package(nil), p.root.types.Imports()...)
			p.root.types.SetImports(append(imports, types.Unsafe))
			g.localAppendBuilders = nil
			if probe.separateLocalAppendBacking(write, object) {
				t.Fatal("закрыт пакет с unsafe")
			}
			p.root.types.SetImports(imports)
		})
	}
}
