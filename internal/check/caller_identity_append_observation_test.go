// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"go/types"
	"slices"
	"testing"
)

// Повтор запроса из активного владельца видит его опубликованные refs и unknown,
// в том числе когда активный source — литерал аргумента, а не вызов append.
func TestCallerIdentityAppendBackingRetainsActiveElement(t *testing.T) {
	const setup = `type Item struct{F func()}
func quiet(){}
func observed(){}
func audit(){}
func build(base []Item, first, second bool)[]Item{
 xs:=append(base,Item{F:quiet})
 if first{xs=append(xs,Item{F:observed})}
 if second{xs=append(xs,Item{F:audit})}
 return xs
}`
	p := callerSoundnessProgram(t, setup, "_=build([]Item{},true,true)", "&Handler{}")
	g := newCallerGraph(p)
	g.ctx = context.Background()
	g.lifetimeScanning = true
	g.claimCallerFieldQueryIndex()
	field := p.root.types.Scope().Lookup("Item").Type().Underlying().(*types.Struct).Field(0)
	path := []*types.Var{field}
	var writes []valueSrc
	for v, defs := range g.assignments {
		if v.Name() == "xs" && v.Pkg() == p.root.types {
			writes = defs
			break
		}
	}
	if len(writes) != 3 {
		t.Fatalf("число определений xs: %d", len(writes))
	}
	// Все три поля — идентификаторы функций: посещение самого значения
	// не связывает вызов. Первый встретившийся источник сохраняет позицию.
	t.Run("ordered_return", func(t *testing.T) {
		fn := writes[0].fk
		ret := g.index.returns[fn][0][0]
		refs, _ := g.embeddedCallerSources(ret, path, map[callerFieldKey]bool{})
		var names []string
		for _, r := range refs {
			if id, ok := r.expr.(*ast.Ident); ok {
				names = append(names, id.Name)
			}
		}
		if !slices.Equal(names, []string{"quiet", "audit", "observed"}) {
			t.Fatalf("порядок первых источников: %v", names)
		}
	})
	backing := writes[1]
	backing.expr = backing.expr.(*ast.CallExpr).Args[0]
	active := writes[2]
	active.expr = active.expr.(*ast.CallExpr).Args[1]
	marker := active
	marker.expr = active.expr.(*ast.CompositeLit).Elts[0].(*ast.KeyValueExpr).Value
	frame, entered := g.enterCallerFieldQuery(active, path)
	if !entered {
		t.Fatal("стек до запроса непуст")
	}
	defer g.leaveCallerFieldQuery(frame)
	g.fieldQueries[frame].refs = []valueSrc{marker}
	g.fieldQueries[frame].unknown = true
	refs, unknown := g.embeddedCallerSources(backing, path, map[callerFieldKey]bool{})
	if !unknown || !slices.Contains(refs, marker) {
		t.Fatalf("пропущен опубликованный аргумент: marker=%v unknown=%v", slices.Contains(refs, marker), unknown)
	}
}
