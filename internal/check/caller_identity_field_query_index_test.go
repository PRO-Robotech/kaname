// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"testing"
)

func TestCallerIdentityFieldQueryIndexInterleaving(t *testing.T) {
	g, field := callerInitialObjectFixture(t)
	selector := field.expr.(*ast.SelectorExpr)
	a := field
	a.expr = selector.X
	b := field
	fields := fieldPath(field.pkg.info.Selections[selector])
	other := types.NewField(token.NoPos, field.pkg.types, "other", fields[0].Type(), false)
	second := []*types.Var{other}
	firstIndex, entered := g.enterCallerFieldQuery(a, fields)
	if !entered || firstIndex != 0 {
		t.Fatal("missing first owner")
	}
	middle, entered := g.enterCallerFieldQuery(b, fields)
	if !entered || middle != 1 {
		t.Fatal("missing unrelated middle owner")
	}
	last, entered := g.enterCallerFieldQuery(a, second)
	if !entered || last != 2 {
		t.Fatal("same source with a different path was cut")
	}
	snapshot := []valueSrc{b, a}
	g.fieldQueries[firstIndex].refs, g.fieldQueries[firstIndex].unknown = snapshot, true
	cuts, credits := g.resolveCuts, g.completedInitialSkips
	index, entered := g.enterCallerFieldQuery(a, fields)
	if entered || index != firstIndex || g.resolveCuts != cuts+1 || g.completedInitialSkips != credits || !slices.Equal(g.fieldQueries[index].refs, snapshot) || !g.fieldQueries[index].unknown {
		t.Fatal("same-source chain selected the wrong path or stale snapshot")
	}
	// Новый снимок владельца читается непосредственно из прежнего элемента стека.
	g.fieldQueries[firstIndex].refs, g.fieldQueries[firstIndex].unknown = []valueSrc{a}, false
	got, unknown := g.embeddedCallerSources(a, fields, map[callerFieldKey]bool{})
	if unknown || !slices.Equal(got, []valueSrc{a}) || g.completedInitialSkips != credits || len(g.objectMemo)+len(g.initialObjectMemo)+len(g.resolveMemo)+len(g.initialResolveMemo) != 0 {
		t.Fatal("snapshot update was stale, published, or credited")
	}
	g.leaveCallerFieldQuery(last)
	if g.fieldQueryHeads[callerResolveKeyFor(a, true)] != firstIndex+1 {
		t.Fatal("pop did not restore the previous same-source owner")
	}
	g.leaveCallerFieldQuery(middle)
	g.leaveCallerFieldQuery(firstIndex)
	if len(g.fieldQueries) != 0 || len(g.fieldQueryHeads) != 0 || g.fieldQueryIndexedDepth != 0 {
		t.Fatal("unwind retained an active index entry")
	}
	index, entered = g.enterCallerFieldQuery(a, fields)
	if !entered || index != 0 || len(g.fieldQueries[index].refs) != 0 || g.fieldQueries[index].unknown {
		t.Fatal("completed owner became a result cache")
	}
	g.leaveCallerFieldQuery(index)
}

func TestCallerIdentityFieldQueryIndexExactKeysAndOrigins(t *testing.T) {
	g, field := callerInitialObjectFixture(t)
	selector := field.expr.(*ast.SelectorExpr)
	src := field
	src.expr = selector.X
	fields := fieldPath(field.pkg.info.Selections[selector])
	root, _ := g.enterCallerFieldQuery(src, fields)
	variants := []struct {
		name   string
		change func(*valueSrc)
	}{
		{"tuple", func(s *valueSrc) { s.tuple = 0 }},
		{"element", func(s *valueSrc) { s.elem = true }},
		{"range_key", func(s *valueSrc) { s.rangeKey = true }},
		{"range_value", func(s *valueSrc) { s.rangeVal = true }},
		{"op_assign", func(s *valueSrc) { s.opAssign = true }},
		{"function", func(s *valueSrc) { s.fk.lit = &ast.FuncLit{} }},
		{"package", func(s *valueSrc) { copyPkg := *s.pkg; s.pkg = &copyPkg }},
	}
	for _, tc := range variants {
		t.Run(tc.name, func(t *testing.T) {
			different := src
			tc.change(&different)
			before := g.work.FieldQueryCandidates
			index, entered := g.enterCallerFieldQuery(different, fields)
			if !entered || index != 1 || g.work.FieldQueryCandidates != before {
				t.Fatal("distinct full source key searched or matched an unrelated frame")
			}
			g.leaveCallerFieldQuery(index)
		})
	}
	paren := src
	paren.expr = &ast.ParenExpr{X: src.expr}
	if index, entered := g.enterCallerFieldQuery(paren, fields); entered || index != root {
		t.Fatal("parentheses changed existing key equality")
	}
	other := types.NewField(token.NoPos, src.pkg.types, "reader", fields[0].Type(), false)
	paths := [][]*types.Var{{other}, {fields[0], other}, {other, fields[0]}}
	var owners []int
	for _, path := range paths {
		index, entered := g.enterCallerFieldQuery(src, path)
		if !entered {
			t.Fatal("path length, order, or distinct Origin was collapsed")
		}
		owners = append(owners, index)
	}
	for i, path := range paths {
		if duplicate, entered := g.enterCallerFieldQuery(src, path); entered || duplicate != owners[i] {
			t.Fatal("exact multi-field path lost its owner among same-source paths")
		}
	}
	for i := len(owners) - 1; i >= 0; i-- {
		g.leaveCallerFieldQuery(owners[i])
	}
	g.leaveCallerFieldQuery(root)
	p := callerSoundnessProgram(t, `type Generic[T any]struct{value T}`, `box:=Generic[int]{};_=box`, `&Handler{}`)
	named := p.root.types.Scope().Lookup("Generic").Type().(*types.Named)
	instantiated, err := types.Instantiate(nil, named, []types.Type{types.Typ[types.Int]}, true)
	if err != nil {
		t.Fatal(err)
	}
	origin := named.Underlying().(*types.Struct).Field(0)
	concrete := instantiated.Underlying().(*types.Struct).Field(0)
	if concrete == origin || concrete.Origin() != origin {
		t.Fatal("fixture lost lawful instantiated field Origin")
	}
	source := callerOwnershipSources(p)["box"]
	g = newCallerGraph(p)
	index, entered := g.enterCallerFieldQuery(source, []*types.Var{origin})
	if !entered {
		t.Fatal("missing generic owner")
	}
	if duplicate, entered := g.enterCallerFieldQuery(source, []*types.Var{concrete}); entered || duplicate != index {
		t.Fatal("lawful instantiated field did not match its Origin")
	}
	g.leaveCallerFieldQuery(index)
}

func TestCallerIdentityFieldQueryIndexSyntheticFallback(t *testing.T) {
	for _, direct := range []bool{false, true} {
		name := "seed"
		if direct {
			name = "truncate"
		}
		t.Run(name, func(t *testing.T) {
			g, field := callerInitialObjectFixture(t)
			selector := field.expr.(*ast.SelectorExpr)
			base := field
			base.expr = selector.X
			fields := fieldPath(field.pkg.info.Selections[selector])
			if direct {
				// До прямого truncate глубина равна четырём: вложенные push снова достигнут её.
				for i := 0; i < 4; i++ {
					src := base
					src.tuple = i
					g.enterCallerFieldQuery(src, fields)
				}
				g.fieldQueries = g.fieldQueries[:1]
				base.tuple = 0
			} else {
				g.fieldQueries = []callerFieldQuery{{source: callerResolveKeyFor(base, true), fields: fields}}
			}
			snapshot := []valueSrc{field}
			g.fieldQueries[0].refs, g.fieldQueries[0].unknown = snapshot, true
			for i := 4; i < 7; i++ {
				src := base
				src.tuple = i
				if _, entered := g.enterCallerFieldQuery(src, fields); !entered || g.fieldQueryIndexedDepth != -1 {
					t.Fatal("nested push escaped sticky synthetic fallback")
				}
			}
			// Длина снова четыре; sentinel всё ещё запрещает чтение прежних heads.
			if len(g.fieldQueries) != 4 || g.fieldQueryIndexedDepth != -1 {
				t.Fatal("fixture did not reach the previous tracked depth in fallback")
			}
			got, unknown := g.embeddedCallerSources(base, fields, map[callerFieldKey]bool{})
			if !unknown || !slices.Equal(got, snapshot) || g.fieldQueryIndexedDepth != -1 {
				t.Fatal("linear fallback lost the synthetic exact snapshot")
			}
			for len(g.fieldQueries) > 0 {
				g.leaveCallerFieldQuery(len(g.fieldQueries) - 1)
				if len(g.fieldQueries) > 0 && g.fieldQueryIndexedDepth != -1 {
					t.Fatal("partial unwind restored a stale index")
				}
			}
			if len(g.fieldQueryHeads) != 0 || g.fieldQueryIndexedDepth != 0 {
				t.Fatal("empty synthetic stack did not clear and resync")
			}
			owner, entered := g.enterCallerFieldQuery(base, fields)
			if !entered || owner != 0 || g.fieldQueryIndexedDepth != 1 || len(g.fieldQueryHeads) != 1 {
				t.Fatal("normal indexing did not recover after full unwind")
			}
			g.leaveCallerFieldQuery(owner)
		})
	}
}

func TestCallerIdentityFieldQueryIndexCancellationCleanup(t *testing.T) {
	for _, mode := range []string{"precancel", "active_field"} {
		t.Run(mode, func(t *testing.T) {
			g, field := callerInitialObjectFixture(t)
			selector := field.expr.(*ast.SelectorExpr)
			base := field
			base.expr = selector.X
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "precancel" {
				cancel()
			}
			trigger := &callerObjectCancelContext{Context: ctx, cancel: cancel, reached: func() bool {
				return mode == "active_field" && len(g.fieldQueries) > 0
			}}
			g.ctx = trigger
			seen := map[callerFieldKey]bool{}
			got, unknown := g.embeddedCallerSources(base, fieldPath(field.pkg.info.Selections[selector]), seen)
			if ctx.Err() != context.Canceled || got != nil || !unknown || len(seen) != 0 || len(g.fieldQueries) != 0 || len(g.fieldQueryHeads) != 0 || g.fieldQueryIndexedDepth != 0 || g.lifetimeScanning || g.effectScanning || g.completedInitialSkips != 0 || len(g.objectMemo)+len(g.initialObjectMemo)+len(g.resolveMemo)+len(g.initialResolveMemo) != 0 {
				t.Fatal("cancelled field traversal retained index, partial state, answer, or credit")
			}
			if mode != "precancel" && !trigger.triggered {
				t.Fatal("deterministic cancellation did not reach the requested active state")
			}
		})
	}
}

func TestCallerIdentityFieldQueryIndexEpochAndIndependentRuns(t *testing.T) {
	g, field := callerInitialObjectFixture(t)
	selector := field.expr.(*ast.SelectorExpr)
	base := field
	base.expr = selector.X
	fields := fieldPath(field.pkg.info.Selections[selector])
	owner, _ := g.enterCallerFieldQuery(base, fields)
	g.fieldQueries[owner].refs, g.fieldQueries[owner].unknown = []valueSrc{field}, true
	epoch, credits := g.bindingEpoch, g.completedInitialSkips
	g.addCallerLive(callerVariable(base.pkg, base.expr), field)
	if g.bindingEpoch <= epoch {
		t.Fatal("fixture did not advance binding epoch")
	}
	g.lifetimeScanning = true
	got, unknown := g.embeddedCallerSources(base, fields, map[callerFieldKey]bool{})
	if !unknown || !slices.Equal(got, []valueSrc{field}) || len(g.fieldQueries) != 1 || g.fieldQueryHeads[callerResolveKeyFor(base, true)] != owner+1 || g.completedInitialSkips != credits {
		t.Fatal("epoch or INITIAL transition dropped the active guard or credited its cut")
	}
	g.lifetimeScanning = false
	g.leaveCallerFieldQuery(owner)
	first := callerGraphFor(g.p, nil)
	firstOwner, _ := first.enterCallerFieldQuery(base, fields)
	second := callerGraphFor(g.p, nil)
	if len(second.fieldQueries) != 0 || len(second.fieldQueryHeads) != 0 || second.fieldQueryIndexedDepth != 0 {
		t.Fatal("independent graph run inherited an active index")
	}
	secondOwner, entered := second.enterCallerFieldQuery(base, fields)
	if !entered || secondOwner != 0 {
		t.Fatal("independent run reused another run's owner")
	}
	second.leaveCallerFieldQuery(secondOwner)
	if len(first.fieldQueries) != 1 || len(first.fieldQueryHeads) != 1 || first.fieldQueryIndexedDepth != 1 {
		t.Fatal("independent run cleanup changed another run's index")
	}
	first.leaveCallerFieldQuery(firstOwner)
}

func TestCallerIdentityFieldQueryIndexUnrelatedMiss(t *testing.T) {
	g, field := callerInitialObjectFixture(t)
	selector := field.expr.(*ast.SelectorExpr)
	base := field
	base.expr = selector.X
	fields := fieldPath(field.pkg.info.Selections[selector])
	for i := 0; i < 64; i++ {
		src := base
		src.tuple = i
		if index, entered := g.enterCallerFieldQuery(src, fields); !entered || index != i || g.fieldQueryIndexedDepth != i+1 {
			t.Fatal("normal source entry fell back or lost its active index")
		}
	}
	missing := base
	missing.tuple = 64
	before := g.work.FieldQueryCandidates
	index, entered := g.enterCallerFieldQuery(missing, fields)
	if !entered || index != 64 || g.work.FieldQueryCandidates != before || len(g.fieldQueryHeads) != 65 {
		t.Fatal("new source searched unrelated active frames or lost its owner")
	}
	for i := 64; i >= 0; i-- {
		g.leaveCallerFieldQuery(i)
		if g.fieldQueryIndexedDepth != i || len(g.fieldQueryHeads) != i {
			t.Fatal("normal pop retained historical keys or entered fallback")
		}
	}
}
