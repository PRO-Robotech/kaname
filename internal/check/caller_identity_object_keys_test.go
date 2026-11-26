// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/types"
	"testing"
)

func TestCallerIdentityObjectSourceIDsPreserveExactCanonicalIdentity(t *testing.T) {
	g := &callerGraph{}
	base := valueSrc{pkg: &surfaceSrcPkg{}, fk: fkey{fn: new(types.Func), lit: &ast.FuncLit{}}, expr: ast.NewIdent("source"), tuple: -1}
	id := g.internObjectSource(base)
	paren := base
	paren.expr = &ast.ParenExpr{X: &ast.ParenExpr{X: base.expr}}
	if id == 0 || g.internObjectSource(base) != id || g.internObjectSource(paren) != id || g.work.ObjectSourceIDs != 1 {
		t.Fatal("equal canonical sources did not reuse one nonzero ID")
	}
	variants := []struct {
		name string
		edit func(*valueSrc)
	}{
		{"package", func(s *valueSrc) { s.pkg = &surfaceSrcPkg{} }},
		{"function", func(s *valueSrc) { s.fk.fn = new(types.Func) }},
		{"closure", func(s *valueSrc) { s.fk.lit = &ast.FuncLit{} }},
		{"expression", func(s *valueSrc) { s.expr = ast.NewIdent("source") }},
		{"tuple", func(s *valueSrc) { s.tuple = 0 }},
		{"element", func(s *valueSrc) { s.elem = true }},
		{"range_key", func(s *valueSrc) { s.rangeKey = true }},
		{"range_value", func(s *valueSrc) { s.rangeVal = true }},
		{"assignment", func(s *valueSrc) { s.opAssign = true }},
	}
	ids := map[callerObjectSourceID]bool{id: true}
	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			src := base
			variant.edit(&src)
			other := g.internObjectSource(src)
			if other == 0 || ids[other] || g.internObjectSource(src) != other {
				t.Fatal("distinct full canonical source collided or changed ID")
			}
			ids[other] = true
		})
	}
	nilID := g.internObjectSource(valueSrc{})
	if nilID == 0 || ids[nilID] || g.internObjectSource(valueSrc{}) != nilID {
		t.Fatal("nil source lost its exact identity")
	}
	if g.work.ObjectSourceIDs != len(variants)+2 || len(g.objectSourceIDs) != len(variants)+2 {
		t.Fatal("source count includes repeated canonical queries")
	}
}

func TestCallerIdentityObjectSourceIDsKeepActiveSeenAcrossNestedEpoch(t *testing.T) {
	p := callerSoundnessProgram(t, "", `left:=&Box{};right:=&Box{};_=left;_=right`, `&Handler{}`)
	g, refs := newCallerGraph(p), callerOwnershipSources(p)
	left, right := refs["left"], refs["right"]
	id := g.internObjectSource(left)
	seen := map[callerObjectSourceID]bool{id: true}
	g.callerObjects(valueSrc{}, map[callerObjectSourceID]bool{}) // Устанавливаем прежнюю эпоху ответа.
	g.addCallerLive(callerVariable(right.pkg, right.expr), left)
	// Вложенный обход сбрасывает кеши ответов, пока внешний источник остаётся активным.
	g.lifetimeScanning = true
	objects, unknown := g.callerObjects(right, seen)
	if unknown || !objects[callerOwnershipZero(right)] {
		t.Fatal("unrelated nested source falsely hit the active outer cycle")
	}
	g.lifetimeScanning = false
	if g.internObjectSource(left) != id || !seen[id] || len(seen) != 1 {
		t.Fatal("nested epoch changed the outer source ID or seen membership")
	}
	cuts := g.objectCuts
	objects, unknown = g.callerObjects(left, seen)
	if unknown || len(objects) != 0 || g.objectCuts != cuts+1 || !seen[id] {
		t.Fatal("exact outer reentry did not retain the original cycle cut")
	}
	// Сброс корня RPC очищает ответы, но ID источников всё равно нельзя переиспользовать.
	g.objectMemo, g.initialObjectMemo = nil, nil
	g.objectMemoEpoch, g.objectMemoWeight, g.bindingEpoch = 0, 0, 0
	if g.internObjectSource(left) != id || g.internObjectSource(right) == id {
		t.Fatal("root answer reset recycled an active source ID")
	}
}

func TestCallerIdentityObjectSourceIDsHaveFreshGraphNamespaces(t *testing.T) {
	p := callerSoundnessProgram(t, "", `left:=&Box{};right:=&Box{};_=left;_=right`, `&Handler{}`)
	defer callerGraphs.Delete(p)
	refs := callerOwnershipSources(p)
	first := callerGraphFor(p, nil)
	first.internObjectSource(refs["left"])
	// Даже заполненный кешированный шаблон не должен передавать изменяемую таблицу в прогон.
	cached, _ := callerGraphs.Load(p)
	template := cached.(*callerGraphMemo).graph
	template.internObjectSource(refs["left"])
	second := callerGraphFor(p, nil)
	if second.objectSourceIDs != nil || second.work.ObjectSourceIDs != 0 {
		t.Fatal("fresh graph copied the template source namespace")
	}
	if second.internObjectSource(refs["right"]) != 1 || first.internObjectSource(refs["right"]) != 2 {
		t.Fatal("graph copies share source allocation state")
	}
	if len(template.objectSourceIDs) != 1 || template.work.ObjectSourceIDs != 1 {
		t.Fatal("run source IDs escaped into the cached template")
	}
}
