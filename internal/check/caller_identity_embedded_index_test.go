// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"slices"
	"testing"
)

func TestCallerIdentityEmbeddedLiteralIndexRawEquivalence(t *testing.T) {
	p := callerSoundnessProgram(t, `type Generic[T any]struct{value T;other T}`, `
	 a:=Generic[int]{value:1};b:=Generic[int]{2,3};c:=Generic[int]{};_,_,_=a,b,c`, `&Handler{}`)
	named := p.root.types.Scope().Lookup("Generic").Type().(*types.Named)
	origin := named.Underlying().(*types.Struct).Field(0)
	g := newCallerGraph(p)
	var literals []*ast.CompositeLit
	for _, file := range p.root.files {
		ast.Inspect(file, func(n ast.Node) bool {
			if literal, ok := n.(*ast.CompositeLit); ok {
				if typ := namedOf(p.root.info.TypeOf(literal)); typ != nil && typ.Origin() == named {
					literals = append(literals, literal)
				}
			}
			return true
		})
	}
	if len(literals) != 3 {
		t.Fatal("missing keyed, positional or zero generic literal")
	}
	foreign := types.NewField(token.NoPos, p.root.types, "value", types.Typ[types.Int], false)
	for _, literal := range literals {
		if _, present := g.embeddedLiterals.values[callerEmbeddedLiteralKey{p.root, literal}]; !present {
			t.Fatal("typed literal was not indexed during graph construction")
		}
		st := p.root.info.TypeOf(literal).Underlying().(*types.Struct)
		if st.Field(0) == origin || st.Field(0).Origin() != origin {
			t.Fatal("fixture lost instantiated field identity")
		}
		for _, field := range []*types.Var{origin, st.Field(0), st.Field(1), foreign} {
			for _, cycle := range []bool{false, true} {
				src := valueSrc{pkg: p.root, expr: literal, tuple: 2, elem: true, rangeVal: true, opAssign: true}
				fast, slow := &callerGraph{}, &callerGraph{}
				fast.embeddedLiterals = g.embeddedLiterals
				seen := map[callerFieldKey]bool{}
				if cycle {
					seen[callerFieldKey{callerResolveKeyFor(src, true), field.Origin()}] = true
				}
				otherSeen := maps.Clone(seen)
				got, unknown := fast.embeddedCallerSourcesRaw(src, []*types.Var{field}, seen)
				want, originalUnknown := slow.embeddedCallerSourcesRaw(src, []*types.Var{field}, otherSeen)
				if unknown != originalUnknown || !slices.Equal(got, want) || (got == nil) != (want == nil) || !maps.Equal(seen, otherSeen) || callerReuseMarks(fast) != callerReuseMarks(slow) {
					t.Fatal("index changed exact sources, UNKNOWN, nil, recursion state or semantic marks")
				}
				if !cycle && fast.work.EmbeddedLiteralHits != 1 || cycle && fast.work.EmbeddedLiteralHits != 0 {
					t.Fatal("indexed expansion bypassed the original cycle boundary or did not execute")
				}
			}
		}
	}
}

func TestCallerIdentityEmbeddedLiteralIndexMalformedAndIdentityFallback(t *testing.T) {
	field := types.NewField(token.NoPos, nil, "value", types.Typ[types.Int], false)
	other := types.NewField(token.NoPos, nil, "other", types.Typ[types.Int], false)
	key := ast.NewIdent("value")
	first, second := &ast.BasicLit{Kind: token.INT, Value: "1"}, &ast.BasicLit{Kind: token.INT, Value: "2"}
	for _, malformed := range []bool{false, true} {
		lastKey := ast.Expr(key)
		if malformed {
			lastKey = second
		}
		literal := &ast.CompositeLit{Elts: []ast.Expr{
			&ast.KeyValueExpr{Key: key, Value: first},
			&ast.KeyValueExpr{Key: lastKey, Value: second},
		}}
		sp := &surfaceSrcPkg{info: &types.Info{
			Types: map[ast.Expr]types.TypeAndValue{literal: {Type: types.NewStruct([]*types.Var{field, other}, nil)}},
			Uses:  map[*ast.Ident]types.Object{key: field},
		}}
		g := &callerGraph{}
		g.embeddedLiterals.add(sp, literal)
		_, indexed := g.embeddedLiterals.values[callerEmbeddedLiteralKey{sp, literal}]
		if indexed == malformed {
			t.Fatal("malformed literal must keep the original ordered search")
		}
		for _, query := range []*types.Var{field, other} {
			for _, clonePackage := range []bool{false, true} {
				pkg := sp
				if clonePackage {
					copyPkg := *sp
					pkg = &copyPkg
				}
				src := valueSrc{pkg: pkg, expr: literal, tuple: -1}
				before := g.work.EmbeddedLiteralHits
				got, unknown := g.embeddedCallerSourcesRaw(src, []*types.Var{query}, map[callerFieldKey]bool{})
				original := &callerGraph{}
				want, originalUnknown := original.embeddedCallerSourcesRaw(src, []*types.Var{query}, map[callerFieldKey]bool{})
				if unknown != originalUnknown || !slices.Equal(got, want) || (got == nil) != (want == nil) {
					t.Fatal("first matching value, later malformed key or package fallback changed")
				}
				if clonePackage && g.work.EmbeddedLiteralHits != before {
					t.Fatal("same AST in another package reused indexed type information")
				}
			}
		}
	}
}

func TestCallerIdentityEmbeddedLiteralIndexKeepsLifetimeBarrier(t *testing.T) {
	for _, body := range []string{
		`box:=&Box{reader:Benign{}};_=box.reader`,
		`box:=&Box{};_=box.reader`,
		`box:=&Box{reader:Benign{}};source.Mutate(box);_=box.reader`,
	} {
		prepared, field, base := callerLifetimeCompletionFixture(t, body)
		fast, slow := callerGraphFor(prepared.p, nil), callerGraphFor(prepared.p, nil)
		slow.embeddedLiterals = callerEmbeddedLiteralIndex{}
		for _, g := range []*callerGraph{fast, slow} {
			g.safeExternal = prepared.safeExternal
			g.markCallerCalled(callerNode{fn: field.fk.fn, lit: field.fk.lit})
		}
		fields := fieldPath(field.pkg.info.Selections[field.expr.(*ast.SelectorExpr)])
		got, unknown := fast.embeddedCallerSources(base, fields, map[callerFieldKey]bool{})
		want, originalUnknown := slow.embeddedCallerSources(base, fields, map[callerFieldKey]bool{})
		if unknown != originalUnknown || !slices.Equal(got, want) || (got == nil) != (want == nil) || callerReuseMarks(fast) != callerReuseMarks(slow) || fast.bindingEpoch != slow.bindingEpoch || !maps.Equal(fast.called, slow.called) {
			t.Fatal("static field index changed dynamic lifetime proof or binding effects")
		}
		if fast.work.EmbeddedLiteralHits == 0 || fast.lifetimeScanning || fast.effectScanning || len(fast.fieldQueries) != 0 {
			t.Fatal("typed proof did not use the index or left an active barrier")
		}
	}
}

func TestCallerIdentityEmbeddedLiteralIndexBoundsAndPartialTypes(t *testing.T) {
	var empty callerEmbeddedLiteralIndex
	for _, pkg := range []*surfaceSrcPkg{nil, {}, {info: &types.Info{}}} {
		empty.add(pkg, &ast.CompositeLit{})
		empty.add(pkg, nil)
	}
	untypedKey := &ast.CompositeLit{Elts: []ast.Expr{&ast.KeyValueExpr{Key: ast.NewIdent("value")}}}
	partial := &surfaceSrcPkg{info: &types.Info{Types: map[ast.Expr]types.TypeAndValue{
		untypedKey: {Type: types.NewStruct([]*types.Var{types.NewField(token.NoPos, nil, "value", types.Typ[types.Int], false)}, nil)},
	}}}
	empty.add(partial, untypedKey)
	if len(empty.values) != 0 || empty.weight != 0 {
		t.Fatal("partial type information published a literal")
	}
	for _, width := range []int{1, 9} {
		fields, elements := make([]*types.Var, width), make([]ast.Expr, width)
		for i := range fields {
			fields[i] = types.NewField(token.NoPos, nil, string(rune('a'+i)), types.Typ[types.Int], false)
			elements[i] = &ast.BasicLit{Kind: token.INT, Value: "1"}
		}
		typ := types.NewStruct(fields, nil)
		sp := &surfaceSrcPkg{info: &types.Info{Types: map[ast.Expr]types.TypeAndValue{}}}
		g := &callerGraph{}
		var refused *ast.CompositeLit
		for i := 0; i <= callerEmbeddedLiteralEntries; i++ {
			literal := &ast.CompositeLit{Elts: elements}
			sp.info.Types[literal] = types.TypeAndValue{Type: typ}
			g.embeddedLiterals.add(sp, literal)
			if _, retained := g.embeddedLiterals.values[callerEmbeddedLiteralKey{sp, literal}]; !retained {
				refused = literal
				break
			}
		}
		if refused == nil || len(g.embeddedLiterals.values) > callerEmbeddedLiteralEntries || g.embeddedLiterals.weight > callerEmbeddedLiteralValues {
			t.Fatal("literal metadata exceeded its bounded retention")
		}
		if width == 1 && len(g.embeddedLiterals.values) != callerEmbeddedLiteralEntries || width == 9 && g.embeddedLiterals.weight+width <= callerEmbeddedLiteralValues {
			t.Fatal("fixture did not reach the intended entry/value limit")
		}
		src := valueSrc{pkg: sp, expr: refused, tuple: -1}
		got, unknown := g.embeddedCallerSourcesRaw(src, fields[:1], map[callerFieldKey]bool{})
		if unknown || len(got) != 1 || got[0].expr != elements[0] || g.work.EmbeddedLiteralHits != 0 {
			t.Fatal("capacity refusal did not keep the complete original expansion")
		}
	}
}
