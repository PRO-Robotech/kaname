// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"maps"
	"testing"
)

func callerInitialObjectFixture(t *testing.T) (*callerGraph, valueSrc) {
	t.Helper()
	p := callerSoundnessProgram(t, "", `box:=&Box{reader:Benign{}};source.Assign(box,Box{reader:Concrete{}});box.reader.read()`, `&Handler{}`)
	g := newCallerGraph(p)
	g.safeExternal = map[string]bool{"fixture/source": true}
	var src valueSrc
	for node, body := range g.bodies {
		if node.fn == nil || node.fn.Name() != "RPC" {
			continue
		}
		g.markCallerCalled(node)
		ast.Inspect(body.node, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "reader" {
				src = valueSrc{pkg: body.sp, fk: callerKey(node), expr: sel, tuple: -1}
			}
			return true
		})
	}
	if src.expr == nil {
		t.Fatal("missing field provenance fixture")
	}
	return g, src
}

func TestCallerIdentityInitialObjectMemoKeepsOpaqueLifetimeBarrier(t *testing.T) {
	g, src := callerInitialObjectFixture(t)
	g.lifetimeScanning = true
	initial, unknown, owned := g.callerObjectsOwned(src, map[callerObjectSourceID]bool{})
	if unknown || owned || len(initial) == 0 {
		t.Fatal("complete initial field provenance was not published")
	}
	before := maps.Clone(initial)
	hits, cuts, skips := g.work.ObjectHits, g.resolveCuts, g.initialSkips
	again, u, owned := g.callerObjectsOwned(src, map[callerObjectSourceID]bool{})
	if u || owned || !maps.Equal(again, before) || g.work.ObjectHits != hits+1 {
		t.Fatal("initial object hit changed the borrowed answer")
	}
	if g.resolveCuts != cuts+1 || g.initialSkips != skips+1 {
		t.Fatal("initial object hit erased the lifetime boundary")
	}
	g.lifetimeScanning = false
	if _, u := g.callerObjects(src, map[callerObjectSourceID]bool{}); !u {
		t.Fatal("warm initial object answer hid an opaque whole-object write")
	}
	if !maps.Equal(initial, before) {
		t.Fatal("full lifetime traversal mutated the published initial answer")
	}
}

func TestCallerIdentityInitialObjectMemoRejectsActiveFieldSnapshot(t *testing.T) {
	g, src := callerInitialObjectFixture(t)
	selector := src.expr.(*ast.SelectorExpr)
	base := src
	base.expr = selector.X
	g.fieldQueries = []callerFieldQuery{{
		source: callerResolveKeyFor(base, true),
		fields: fieldPath(src.pkg.info.Selections[selector]),
	}}
	g.lifetimeScanning = true
	partial, _, _ := g.callerObjectsOwned(src, map[callerObjectSourceID]bool{})
	before := maps.Clone(partial)
	cuts := g.resolveCuts - g.initialSkips
	g.callerObjects(src, map[callerObjectSourceID]bool{})
	if g.resolveCuts-g.initialSkips <= cuts {
		t.Fatal("active field snapshot was reused as a completed object answer")
	}
	g.fieldQueries = nil
	complete, unknown, owned := g.callerObjectsOwned(src, map[callerObjectSourceID]bool{})
	if unknown || owned || len(complete) <= len(partial) || !maps.Equal(partial, before) {
		t.Fatal("partial field snapshot escaped after its owning query returned")
	}
}

func TestCallerIdentityInitialObjectMemoRejectsRealCycles(t *testing.T) {
	p := callerSoundnessProgram(t, "", `anchor:=&Box{};var cycle *Box;cycle=anchor;cycle=cycle;var hollow *Box;hollow=hollow;_=cycle;_=hollow`, `&Handler{}`)
	g, refs := newCallerGraph(p), callerOwnershipSources(p)
	g.lifetimeScanning = true
	for _, name := range []string{"cycle", "hollow"} {
		first, unknown := g.callerObjects(refs[name], map[callerObjectSourceID]bool{})
		before := maps.Clone(first)
		cuts := g.objectCuts
		second, u, owned := g.callerObjectsOwned(refs[name], map[callerObjectSourceID]bool{})
		if unknown != (name == "hollow") || u != unknown || !owned || !maps.Equal(second, before) || g.objectCuts <= cuts {
			t.Fatalf("%s cycle became a reusable or different answer", name)
		}
	}
}

func TestCallerIdentityInitialObjectMemoInvalidatesBothModes(t *testing.T) {
	p := callerSoundnessProgram(t, "", `child:=&Box{};parent:=child;extra:=&Box{};opaque:=source.Value();_=parent;_=extra;_=opaque`, `&Handler{}`)
	g, refs := newCallerGraph(p), callerOwnershipSources(p)
	g.safeExternal = map[string]bool{"fixture/source": true}
	full, u := g.callerObjects(refs["parent"], map[callerObjectSourceID]bool{})
	if u {
		t.Fatal("full alias provenance is unknown")
	}
	fullBefore := maps.Clone(full)
	g.lifetimeScanning = true
	initial, u := g.callerObjects(refs["parent"], map[callerObjectSourceID]bool{})
	if u || !maps.Equal(initial, fullBefore) {
		t.Fatal("mode transition changed an immutable alias chain")
	}
	initialBefore := maps.Clone(initial)
	opaque, unknown, owned := g.callerObjectsOwned(refs["opaque"], map[callerObjectSourceID]bool{})
	if !unknown || owned {
		t.Fatal("complete opaque provenance was not retained with UNKNOWN")
	}
	opaqueBefore := maps.Clone(opaque)
	hits := g.work.ObjectHits
	if again, u, owned := g.callerObjectsOwned(refs["opaque"], map[callerObjectSourceID]bool{}); !u || owned || !maps.Equal(again, opaqueBefore) || g.work.ObjectHits != hits+1 {
		t.Fatal("initial memo turned an opaque source into proven absence")
	}
	g.addCallerLive(callerVariable(p.root, refs["child"].expr), refs["extra"])
	for _, initialMode := range []bool{true, false} {
		g.lifetimeScanning = initialMode
		changed, unknown := g.callerObjects(refs["parent"], map[callerObjectSourceID]bool{})
		if unknown || !changed[callerOwnershipZero(refs["extra"])] {
			t.Fatalf("mode %v retained the old live-binding epoch", initialMode)
		}
	}
	if !maps.Equal(full, fullBefore) || !maps.Equal(initial, initialBefore) {
		t.Fatal("epoch invalidation made an escaped borrowed answer writable")
	}
}

func TestCallerIdentityInitialObjectMemoSharesAdmissionBudget(t *testing.T) {
	for _, initialFirst := range []bool{false, true} {
		for _, bound := range []string{"entries", "weight"} {
			name := "full_first/" + bound
			if initialFirst {
				name = "initial_first/" + bound
			}
			t.Run(name, func(t *testing.T) {
				p := callerSoundnessProgram(t, "", `child:=&Box{};_=child`, `&Handler{}`)
				g, refs := newCallerGraph(p), callerOwnershipSources(p)
				g.objectMemo = map[callerObjectSourceID]callerObjectAnswer{}
				g.initialObjectMemo = map[callerObjectSourceID]callerObjectAnswer{}
				g.objectMemoEpoch = g.bindingEpoch
				filled := g.objectMemo
				if initialFirst {
					filled = g.initialObjectMemo
				}
				if bound == "entries" {
					for i := 0; i < 4096; i++ {
						filled[g.internObjectSource(valueSrc{tuple: i})] = callerObjectAnswer{unknown: true}
					}
				} else {
					g.objectMemoWeight = callerLifetimeStepLimit
				}
				g.lifetimeScanning = !initialFirst
				objects, unknown, owned := g.callerObjectsOwned(refs["child"], map[callerObjectSourceID]bool{})
				if unknown || !owned || len(objects) != 2 || !objects[callerOwnershipZero(refs["child"])] {
					t.Fatal("shared capacity rejection truncated or published the raw answer")
				}
				if g.work.ObjectRetained != 0 || g.work.ObjectRejectCapacity == 0 {
					t.Fatal("switching modes obtained a second object memo budget")
				}
			})
		}
	}
}

func TestCallerIdentityInitialObjectMemoDoesNotPublishAfterCancellation(t *testing.T) {
	p := callerSoundnessProgram(t, "", `child:=&Box{};_=child`, `&Handler{}`)
	g, refs := newCallerGraph(p), callerOwnershipSources(p)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	g.ctx, g.lifetimeScanning = ctx, true
	objects, unknown, owned := g.callerObjectsOwned(refs["child"], map[callerObjectSourceID]bool{})
	if !unknown || owned || len(objects) != 0 || g.work.ObjectRetained != 0 {
		t.Fatal("cancelled traversal published an initial object answer")
	}
	g.ctx = context.Background()
	current, u, owned := g.callerObjectsOwned(refs["child"], map[callerObjectSourceID]bool{})
	if u || owned || len(current) != 2 || !current[callerOwnershipZero(refs["child"])] || g.work.ObjectRetained == 0 {
		t.Fatal("cancelled admission changed later complete provenance")
	}
}
