// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"slices"
	"testing"
)

func TestCallerIdentityContainerInactiveScanKeepsSuffixAfterEpochChange(t *testing.T) {
	sig := types.NewSignatureType(nil, nil, nil, nil, nil, false)
	earlier := callerNode{fn: types.NewFunc(token.NoPos, nil, "earlier", sig)}
	first := callerNode{fn: types.NewFunc(token.NoPos, nil, "first", sig)}
	later := callerNode{fn: types.NewFunc(token.NoPos, nil, "later", sig)}
	g := &callerGraph{
		lifetimeWriteIndex: &callerLifetimeWriteIndex{},
		lifetimeWrites: []callerLifetimeWrite{
			{owner: valueSrc{fk: callerKey(earlier)}},
			{},
			{owner: valueSrc{fk: callerKey(first)}},
			{owner: valueSrc{fk: callerKey(later)}},
		},
	}
	g.markCallerCalled(first)
	typ := types.NewSlice(types.Typ[types.Int])
	candidates := []int{0, 2, 3}
	scan := g.callerContainerActiveScan(g.ctx, typ, candidates)
	pos, ok := scan.take(g, len(candidates))
	if !ok || pos != 1 || g.work.ContainerInactiveSkippedWrites != 1 {
		t.Fatalf("first ordinal position=%d ok=%t work=%+v", pos, ok, g.work)
	}

	// An effect of processing the first write can activate both an earlier
	// and a later owner. The raw scan observes only the later change.
	g.markCallerCalled(earlier)
	g.markCallerCalled(later)
	pos, ok = scan.take(g, len(candidates))
	if !ok || pos != 2 || g.work.ContainerInactiveEpochFallbacks != 1 ||
		g.work.ContainerInactiveSkippedWrites != 1 {
		t.Fatalf("suffix position=%d ok=%t work=%+v", pos, ok, g.work)
	}
	if _, ok := scan.take(g, len(candidates)); ok {
		t.Fatal("ordered suffix was not exhausted")
	}
}

func TestCallerIdentityContainerInactiveScanUsesLiveAliasesAndRootState(t *testing.T) {
	p := callerSoundnessProgram(t, `var shelf=[]Box{{reader:Benign{}}}
func earlier(){alias:=shelf;alias[0]=Box{reader:Benign{}}}
func mutate(){alias:=shelf;alias[0]=Box{reader:Concrete{}}}`, `_=shelf[0]`, `&Handler{}`)
	defer callerGraphs.Delete(p)
	filtered := callerGraphFor(p, nil)
	var src valueSrc
	ast.Inspect(p.root.files[0], func(n ast.Node) bool {
		if spec, ok := n.(*ast.ValueSpec); ok {
			for _, id := range spec.Names {
				if id.Name == "shelf" {
					src = valueSrc{pkg: p.root, expr: id, tuple: -1}
				}
			}
		}
		return true
	})
	var earlier, mutate callerNode
	for node := range filtered.bodies {
		if node.fn == nil {
			continue
		}
		switch node.fn.Name() {
		case "earlier":
			earlier = node
		case "mutate":
			mutate = node
		}
	}
	if src.expr == nil || earlier.fn == nil || mutate.fn == nil {
		t.Fatal("missing indexed alias fixture")
	}
	query := func(g *callerGraph) ([]valueSrc, bool) {
		return g.callerContainerSources(src, nil, map[callerFieldKey]bool{})
	}
	filtered.markCallerCalled(earlier)
	query(filtered)
	query(filtered)
	if filtered.work.ContainerInactiveSkippedWrites == 0 || filtered.work.ContainerInactiveCacheHits == 0 {
		t.Fatal("inactive alias fixture did not exercise the warm filter")
	}
	epoch := filtered.bindingEpoch
	old := filtered.containerInactive

	// A fresh graph can have the same numerical epoch and the same static
	// type index while its set of called functions is entirely different.
	reset := callerGraphFor(p, nil)
	reset.markCallerCalled(mutate)
	if reset.bindingEpoch != epoch || reset.lifetimeWriteIndex != filtered.lifetimeWriteIndex || old.current(reset) {
		t.Fatal("fixture did not create a new graph at the same binding epoch")
	}
	full := callerGraphFor(p, nil)
	full.lifetimeWriteIndex = nil
	full.markCallerCalled(mutate)
	got, unknown := query(reset)
	want, rawUnknown := query(full)
	if len(want) == 0 || !slices.Equal(got, want) || unknown != rawUnknown {
		t.Fatalf("active alias lost after reset: got=%v/%t want=%v/%t", got, unknown, want, rawUnknown)
	}

	// Opaque Err can run user code and mutate called without an epoch change.
	// The warm filter must not hide the newly active alias.
	skips, probes := filtered.work.ContainerInactiveSkippedWrites, filtered.work.ContainerInactiveCandidateChecks
	opaqueCalls := 0
	filtered.ctx = &callerTraceOpaqueContext{Context: context.Background(), onErr: func() {
		opaqueCalls++
		filtered.called[mutate] = true
	}}
	full = callerGraphFor(p, nil)
	full.lifetimeWriteIndex = nil
	full.markCallerCalled(earlier)
	full.ctx = &callerTraceOpaqueContext{Context: context.Background(), onErr: func() {
		full.called[mutate] = true
	}}
	got, unknown = query(filtered)
	want, rawUnknown = query(full)
	if opaqueCalls == 0 || len(want) < 2 || !reflect.DeepEqual(got, want) || unknown != rawUnknown ||
		filtered.work.ContainerInactiveSkippedWrites != skips || filtered.work.ContainerInactiveCandidateChecks != probes {
		t.Fatalf("opaque alias differed from raw scan: got=%v/%t want=%v/%t Err=%d", got, unknown, want, rawUnknown, opaqueCalls)
	}
}
