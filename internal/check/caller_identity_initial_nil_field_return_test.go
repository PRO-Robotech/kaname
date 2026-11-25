// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"go/token"
	"go/types"
	"testing"
)

func TestCallerIdentityInitialNilFieldReturn(t *testing.T) {
	nilID := ast.NewIdent("nil")
	sp := &surfaceSrcPkg{info: &types.Info{
		Uses:  map[*ast.Ident]types.Object{nilID: types.Universe.Lookup("nil")},
		Types: map[ast.Expr]types.TypeAndValue{nilID: {Type: types.Typ[types.UntypedNil]}},
	}}
	src := valueSrc{pkg: sp, expr: nilID, tuple: -1}
	fields := []*types.Var{types.NewField(token.NoPos, nil, "Field", types.Typ[types.String], false)}
	outer := valueSrc{pkg: sp, expr: ast.NewIdent("outer"), tuple: -1}
	graph := func() *callerGraph {
		g := &callerGraph{lifetimeScanning: true}
		g.claimCallerFieldQueryIndex()
		g.enterCallerFieldQuery(outer, fields)
		return g
	}
	original := graph()
	fast := graph()
	for i := 0; i < 15; i++ {
		refs, unknown := original.embeddedCallerSources(src, fields, map[callerFieldKey]bool{})
		if refs != nil || unknown || !fast.initialNilFieldReturn(src, fields) {
			t.Fatal("expected an empty complete initial source")
		}
	}
	if callerReuseMarks(fast) != callerReuseMarks(original) || fast.initialSkips != 15 ||
		fast.work.LifetimeInitialSkips != original.work.LifetimeInitialSkips ||
		fast.work.InitialNilFieldReturns != 15 ||
		fast.work.ContainerCalls != 0 || original.work.ContainerCalls != 15 ||
		!original.callerExecutionSnapshot().matches(fast) {
		t.Fatal("initial marks, scope or actual container work differ")
	}
	unusual := src
	unusual.rangeKey = true
	if fast.initialNilFieldReturn(unusual, fields) {
		t.Fatal("synthetic range key admitted")
	}
	collision, entered := fast.enterCallerFieldQuery(src, fields)
	if !entered {
		t.Fatal("expected a new active frame")
	}
	fast.fieldQueries[collision].refs = []valueSrc{outer}
	if fast.initialNilFieldReturn(src, fields) {
		t.Fatal("active snapshot dropped")
	}
	fast.leaveCallerFieldQuery(collision)
	fast.mutations = map[*types.Var][]callerFieldMutation{fields[0]: {{owner: outer}}}
	if fast.initialNilFieldReturn(src, fields) {
		t.Fatal("field mutation skipped")
	}
	delete(fast.mutations, fields[0])
	sp.info.Types[nilID] = types.TypeAndValue{Type: types.NewSlice(types.Typ[types.String])}
	if fast.initialNilFieldReturn(src, fields) {
		t.Fatal("typed slice admitted")
	}
	sp.info.Types[nilID] = types.TypeAndValue{Type: types.Typ[types.UntypedNil]}
	fast.resolveCuts = ^uint64(0)
	if !fast.initialNilFieldReturn(src, fields) || !fast.semanticOverflow || fast.initialSkips != 15 {
		t.Fatal("overflow did not preserve the ordinary boundary")
	}
	cancelled := graph()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled.ctx = ctx
	if cancelled.initialNilFieldReturn(src, fields) || cancelled.initialSkips != 0 {
		t.Fatal("cancelled traversal advanced initial marks")
	}
}
