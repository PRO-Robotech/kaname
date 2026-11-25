// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"slices"
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

func TestCallerIdentityInitialNilReturnPrefix(t *testing.T) {
	p := callerSoundnessProgram(t, `
func choose(i int)*Box{
 switch i {case 1:return nil;case 2:return nil;case 3:return nil;case 4:return nil;case 5:return nil}
 return &Box{reader:Concrete{}}
}
func slicesOnly(i int)[]*Box{
 switch i {case 1:return []*Box(nil);case 2:return []*Box(nil);case 3:return []*Box(nil);case 4:return []*Box(nil)}
 return nil
}`, "box:=choose(1);_=box.reader", "&Handler{}")
	t.Cleanup(func() { callerGraphs.Delete(p) })
	graph := func() *callerGraph {
		g := callerGraphFor(p, nil)
		g.lifetimeScanning = true
		g.claimCallerFieldQueryIndex()
		return g
	}
	g := graph()
	var call valueSrc
	for node, b := range g.bodies {
		if node.fn == nil || b.sp != p.root || node.fn.Name() != "RPC" {
			continue
		}
		ast.Inspect(b.node, func(n ast.Node) bool {
			if x, ok := n.(*ast.CallExpr); ok {
				if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "choose" {
					call = valueSrc{pkg: b.sp, fk: callerKey(node), expr: x, tuple: -1}
				}
			}
			return true
		})
	}
	if call.expr == nil {
		t.Fatal("missing typed call")
	}
	field := p.root.types.Scope().Lookup("Box").Type().Underlying().(*types.Struct).Field(0)
	fields := []*types.Var{field}
	results := func(name string) []valueSrc {
		fn := p.root.types.Scope().Lookup(name).(*types.Func)
		return g.index.returns[fkey{fn: fn}][0]
	}
	values := results("choose")
	containers := results("slicesOnly")
	if len(values) != 6 || g.nilReturnPrefixes[&values[0]] != 5 || g.nilReturnPrefixes[&containers[0]] != 0 {
		t.Fatal("incorrect classified return prefixes")
	}
	outer, _ := g.enterCallerFieldQuery(call, fields)
	copyOfValues := slices.Clone(values)
	if g.initialNilFieldPrefix(copyOfValues, fields) != 0 || g.initialNilFieldPrefix(values[:4], fields) != 0 || g.initialNilFieldPrefix(values, fields) != 5 {
		t.Fatal("prefix escaped immutable result slice")
	}
	g.leaveCallerFieldQuery(outer)

	for _, mode := range []string{"plain", "active_middle", "mutation", "overflow", "cancelled", "opaque", "untracked"} {
		t.Run(mode, func(t *testing.T) {
			fast, old := graph(), graph()
			old.nilReturnPrefixes = nil
			var errReads [2]int
			for i, current := range []*callerGraph{fast, old} {
				switch mode {
				case "active_middle":
					index, entered := current.enterCallerFieldQuery(values[2], fields)
					if !entered {
						t.Fatal("missing active source")
					}
					current.fieldQueries[index].refs = []valueSrc{call}
					current.fieldQueries[index].unknown = true
				case "mutation":
					current.mutations = maps.Clone(current.mutations)
					current.mutations[field.Origin()] = []callerFieldMutation{{owner: call, value: values[0]}}
				case "overflow":
					current.resolveCuts = ^uint64(0) - 2
				case "cancelled":
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					current.ctx = ctx
				case "opaque":
					current.ctx = &callerTraceOpaqueContext{Context: context.Background(), onErr: func() { errReads[i]++ }}
				case "untracked":
					current.fieldQueryIndexOwner = nil
				}
			}
			want, wu := old.embeddedCallerSources(call, fields, map[callerFieldKey]bool{})
			got, gu := fast.embeddedCallerSources(call, fields, map[callerFieldKey]bool{})
			if errReads[0] != errReads[1] || (want == nil) != (got == nil) || !slices.Equal(got, want) || gu != wu || callerReuseMarks(fast) != callerReuseMarks(old) ||
				fast.semanticOverflow != old.semanticOverflow || fast.bindingEpoch != old.bindingEpoch || fast.work.InitialNilFieldReturns != old.work.InitialNilFieldReturns ||
				fast.work.LifetimeInitialSkips != old.work.LifetimeInitialSkips || !fast.captureCallerContainerObjectScope().matches(old) {
				t.Fatalf("changed refs, UNKNOWN, scope or semantic counters in %s", mode)
			}
			switch mode {
			case "plain":
				if fast.work.InitialNilPrefixReturns != 5 || len(got) == 0 {
					t.Fatal("ordinary prefix did not leave the concrete return")
				}
			case "active_middle":
				if fast.work.InitialNilPrefixReturns != 2 || !gu || !slices.Contains(got, call) {
					t.Fatal("active middle snapshot not preserved")
				}
			case "cancelled", "mutation", "opaque", "untracked":
				if fast.work.InitialNilPrefixReturns != 0 {
					t.Fatal("ineligible prefix admitted")
				}
			}
		})
	}
}
