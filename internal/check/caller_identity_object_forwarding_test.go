// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/token"
	"maps"
	"testing"
)

func TestCallerIdentityObjectForwardingBorrowedChild(t *testing.T) {
	for _, mode := range []string{"full", "initial"} {
		for _, tc := range []struct {
			name, body string
			resetTuple bool
			unknown    bool
		}{
			{name: "address", body: `child:=Box{};forwarded:=&child;_=forwarded`},
			{name: "dereference", body: `child:=&Box{};forwarded:=*child;_=forwarded`},
			{name: "assertion", body: `child:=any(&Box{});forwarded:=child.(*Box);_=forwarded`},
			{name: "index", body: `child:=[]Box{{}};forwarded:=child[0];_=forwarded`, resetTuple: true},
			{name: "slice", body: `child:=[]Box{{}};forwarded:=child[:];_=forwarded`, resetTuple: true},
			{name: "conversion", body: `child:=&Box{};forwarded:=any(child);_=forwarded`},
			{name: "append", body: `child:=[]Box{};forwarded:=append(child,Box{});_=forwarded`},
			{name: "unknown", body: `child:=source.Value();forwarded:=child.(*Box);_=forwarded`, unknown: true},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				p := callerSoundnessProgram(t, "", tc.body, `&Handler{}`)
				g, refs := newCallerGraph(p), callerOwnershipSources(p)
				g.safeExternal = map[string]bool{"fixture/source": true}
				g.lifetimeScanning = mode == "initial"
				sources := g.sources(callerVariable(p.root, refs["forwarded"].expr))
				if len(sources) != 1 {
					t.Fatal("missing single transparent expression")
				}
				parent := sources[0]
				parent.tuple, parent.elem, parent.rangeKey, parent.rangeVal, parent.opAssign = 3, true, true, true, true
				child := parent
				ast.Inspect(parent.expr, func(n ast.Node) bool {
					if id, ok := n.(*ast.Ident); ok && id.Name == "child" {
						child.expr = id
					}
					return true
				})
				if child.expr == parent.expr {
					t.Fatal("missing child expression")
				}
				if tc.resetTuple {
					child.tuple = -1
				}
				warm, unknown, owned := g.callerObjectsOwned(child, map[callerObjectSourceID]bool{})
				if unknown != tc.unknown || owned || len(warm) == 0 || !warm[callerOwnershipZero(refs["child"])] {
					t.Fatalf("child fixture was not published: %v unknown=%v owned=%v", warm, unknown, owned)
				}
				before := maps.Clone(warm)
				writes, baseline, transfers, hits := g.work.ObjectUnionWrites, g.work.ObjectUnionBaselineWrites, g.work.ObjectUnionTransfers, g.work.ObjectHits
				got, u, owned := g.callerObjectsOwned(parent, map[callerObjectSourceID]bool{})
				if u != unknown || owned || !maps.Equal(got, before) || !maps.Equal(warm, before) {
					t.Fatal("transparent parent changed the child's exact borrowed answer")
				}
				if g.work.ObjectUnionWrites != writes {
					t.Fatal("transparent parent copied a prewarmed borrowed child")
				}
				if g.work.ObjectUnionBaselineWrites != baseline+len(before) || g.work.ObjectUnionTransfers != transfers || g.work.ObjectHits != hits+1 {
					t.Fatal("forwarding changed baseline cost, invented an owned transfer, or missed the exact child memo")
				}
			})
		}
	}
}

func TestCallerIdentityObjectForwardingRejectedParentKeepsChildBorrowed(t *testing.T) {
	for _, mode := range []string{"full", "initial"} {
		for _, bound := range []string{"weight", "entries"} {
			t.Run(mode+"/"+bound, func(t *testing.T) {
				p := callerSoundnessProgram(t, "", `child:=Box{};parent:=&child;sibling:=&child;extra:=Box{};_=parent;_=sibling;_=extra`, `&Handler{}`)
				g, refs := newCallerGraph(p), callerOwnershipSources(p)
				g.lifetimeScanning = mode == "initial"
				parent := g.sources(callerVariable(p.root, refs["parent"].expr))[0]
				child := parent
				child.expr = parent.expr.(*ast.UnaryExpr).X
				warm, u, owned := g.callerObjectsOwned(child, map[callerObjectSourceID]bool{})
				if u || owned || len(warm) != 2 {
					t.Fatal("child fixture was not published")
				}
				before := maps.Clone(warm)
				if bound == "weight" {
					g.objectMemoWeight = callerLifetimeStepLimit
				} else {
					for i := 0; len(g.objectMemo)+len(g.initialObjectMemo) < 4096; i++ {
						g.objectMemo[g.internObjectSource(valueSrc{tuple: i})] = callerObjectAnswer{unknown: true}
					}
				}
				writes := g.work.ObjectUnionWrites
				forwarded, u, owned := g.callerObjectsOwned(parent, map[callerObjectSourceID]bool{})
				if u || owned || !maps.Equal(forwarded, before) || g.work.ObjectRejectCapacity == 0 || g.work.ObjectUnionWrites != writes {
					t.Fatal("capacity rejection copied or acquired ownership of a borrowed child")
				}
				left, u := g.callerObjects(refs["parent"], map[callerObjectSourceID]bool{})
				if u || len(left) != len(before)+1 || !left[callerOwnershipZero(refs["parent"])] {
					t.Fatal("nontransparent parent lost its own storage")
				}
				leftBefore := maps.Clone(left)
				right, u := g.callerObjects(refs["sibling"], map[callerObjectSourceID]bool{})
				if u || len(right) != len(before)+1 || !right[callerOwnershipZero(refs["sibling"])] || right[callerOwnershipZero(refs["parent"])] {
					t.Fatal("sibling lost its storage or inherited the parent's storage")
				}
				if !maps.Equal(warm, before) || !maps.Equal(forwarded, before) || !maps.Equal(left, leftBefore) {
					t.Fatal("an ancestor or sibling mutated a borrowed answer")
				}
				g.addCallerLive(callerVariable(p.root, refs["child"].expr), refs["extra"])
				changed, u := g.callerObjects(refs["parent"], map[callerObjectSourceID]bool{})
				if u || !changed[callerOwnershipZero(refs["extra"])] || !maps.Equal(warm, before) || !maps.Equal(forwarded, before) || !maps.Equal(left, leftBefore) {
					t.Fatal("new epoch lost a live alias or made an old borrowed answer writable")
				}
			})
		}
	}
}

func TestCallerIdentityObjectForwardingCyclesAndPublication(t *testing.T) {
	for _, mode := range []string{"full", "initial"} {
		for _, anchored := range []bool{false, true} {
			name, binding := "unanchored", ""
			if anchored {
				name, binding = "anchored", "cycle=anchor;"
			}
			t.Run(mode+"/"+name, func(t *testing.T) {
				p := callerSoundnessProgram(t, "", `anchor:=&Box{};var cycle *Box;`+binding+`cycle=&*cycle;left:=&*cycle;right:=&*cycle;_=anchor;_=left;_=right`, `&Handler{}`)
				g, refs := newCallerGraph(p), callerOwnershipSources(p)
				g.lifetimeScanning = mode == "initial"
				anchor, u := g.callerObjects(refs["anchor"], map[callerObjectSourceID]bool{})
				if u || len(anchor) != 2 {
					t.Fatal("missing concrete anchor")
				}
				anchorBefore := maps.Clone(anchor)
				first, unknown, owned := g.callerObjectsOwned(refs["left"], map[callerObjectSourceID]bool{})
				want := map[callerObjectKey]bool{callerOwnershipZero(refs["cycle"]): true, callerOwnershipZero(refs["left"]): true}
				if anchored {
					maps.Copy(want, anchorBefore)
				}
				if unknown != !anchored || !owned || !maps.Equal(first, want) {
					t.Fatalf("cycle changed exact provenance, UNKNOWN, or admission: %v unknown=%v owned=%v", first, unknown, owned)
				}
				before, cuts := maps.Clone(first), g.objectCuts
				right, u := g.callerObjects(refs["right"], map[callerObjectSourceID]bool{})
				delete(want, callerOwnershipZero(refs["left"]))
				want[callerOwnershipZero(refs["right"])] = true
				if u != !anchored || !maps.Equal(right, want) || g.objectCuts <= cuts || !maps.Equal(first, before) || !maps.Equal(anchor, anchorBefore) {
					t.Fatal("cycle cut was cached or mutated an earlier answer")
				}
			})
		}
	}
	p := callerSoundnessProgram(t, "", `child:=Box{};parent:=&child;_=parent`, `&Handler{}`)
	g, refs := newCallerGraph(p), callerOwnershipSources(p)
	parent := g.sources(callerVariable(p.root, refs["parent"].expr))[0]
	g.objectMemo = map[callerObjectSourceID]callerObjectAnswer{}
	g.objectMemoEpoch, g.objectMemoWeight = g.bindingEpoch, callerLifetimeStepLimit
	unpublished, u, owned := g.callerObjectsOwned(parent, map[callerObjectSourceID]bool{})
	if u || !owned || len(unpublished) != 2 {
		t.Fatal("unpublished child did not retain ownership through a transparent parent")
	}
	before := maps.Clone(unpublished)
	g.objectMemo = nil
	published, u, owned := g.callerObjectsOwned(parent, map[callerObjectSourceID]bool{})
	if u || owned || !maps.Equal(published, before) {
		t.Fatal("publication did not relinquish forwarded ownership")
	}
	g.callerObjects(refs["parent"], map[callerObjectSourceID]bool{})
	if !maps.Equal(unpublished, before) || !maps.Equal(published, before) {
		t.Fatal("parent storage insertion mutated an escaped forwarded answer")
	}
}

func TestCallerIdentityObjectForwardingNestedEpoch(t *testing.T) {
	for _, mode := range []string{"full", "initial"} {
		t.Run(mode, func(t *testing.T) {
			p := callerSoundnessProgram(t, `func identity(arg *Box)*Box{return arg}`, `child:=&Box{};parent:=&*identity(child);sibling:=&*identity(child);_=parent;_=sibling`, `&Handler{}`)
			g, refs := newCallerGraph(p), callerOwnershipSources(p)
			g.lifetimeScanning = mode == "initial"
			warm, u := g.callerObjects(refs["child"], map[callerObjectSourceID]bool{})
			if u || len(warm) != 2 {
				t.Fatal("missing published child before binding")
			}
			before := maps.Clone(warm)
			parent := g.sources(callerVariable(p.root, refs["parent"].expr))[0]
			// Все внешние кадры входят до смены эпохи внутри identity.
			outerSources := []valueSrc{parent}
			inner := parent
			inner.expr = parent.expr.(*ast.UnaryExpr).X
			outerSources = append(outerSources, inner)
			inner.expr = inner.expr.(*ast.StarExpr).X
			outerSources = append(outerSources, inner)
			call := inner.expr.(*ast.CallExpr)
			identity := callerFunction(inner.pkg, call.Fun)
			returnSources := g.index.returns[callerKey(callerNode{fn: identity})]
			if len(returnSources) != 1 || len(returnSources[0]) != 1 {
				t.Fatal("identity fixture lost its exact return arg source")
			}
			childSource := returnSources[0][0]
			childID := g.internObjectSource(childSource)
			var outerIDs []callerObjectSourceID
			for _, src := range outerSources {
				outerIDs = append(outerIDs, g.internObjectSource(src))
			}
			epoch, rejects := g.bindingEpoch, g.work.ObjectRejectEpoch
			seenID := g.internObjectSource(refs["sibling"])
			seen := map[callerObjectSourceID]bool{seenID: true}
			first, u, owned := g.callerObjectsOwned(parent, seen)
			want := maps.Clone(before)
			want[callerOwnershipZero(refs["arg"])] = true
			if u || owned || !maps.Equal(first, want) || g.bindingEpoch <= epoch || g.work.ObjectRejectEpoch <= rejects {
				t.Fatalf("nested borrowed answer: objects=%v want=%v unknown=%v owned=%v epoch=%d/%d rejects=%d/%d", first, want, u, owned, g.bindingEpoch, epoch, g.work.ObjectRejectEpoch, rejects)
			}
			memo := g.objectMemo
			if g.lifetimeScanning {
				memo = g.initialObjectMemo
			}
			childAnswer, published := memo[childID]
			if g.objectMemoEpoch != g.bindingEpoch || !published || childAnswer.unknown || !maps.Equal(childAnswer.objects, want) {
				t.Fatalf("new-epoch return child not published: present=%v unknown=%v objects=%v memoEpoch=%d bindingEpoch=%d", published, childAnswer.unknown, childAnswer.objects, g.objectMemoEpoch, g.bindingEpoch)
			}
			for i, id := range outerIDs {
				_, retained := memo[id]
				if retained || id == childID || g.internObjectSource(outerSources[i]) != id {
					t.Fatalf("old-epoch outer frame %d was published or changed source ID: retained=%v id=%d child=%d", i, retained, id, childID)
				}
			}
			childBefore := maps.Clone(childAnswer.objects)
			firstBefore := maps.Clone(first)
			if !seen[seenID] || len(seen) != 1 || g.internObjectSource(refs["sibling"]) != seenID {
				t.Fatal("nested answer epoch removed an outer source from seen")
			}
			left, u := g.callerObjects(refs["parent"], map[callerObjectSourceID]bool{})
			want[callerOwnershipZero(refs["parent"])] = true
			if u || !maps.Equal(left, want) {
				t.Fatal("parent storage insertion lost a bound alias")
			}
			leftBefore := maps.Clone(left)
			right, u := g.callerObjects(refs["sibling"], map[callerObjectSourceID]bool{})
			delete(want, callerOwnershipZero(refs["parent"]))
			want[callerOwnershipZero(refs["sibling"])] = true
			if u || !maps.Equal(right, want) || !maps.Equal(warm, before) || !maps.Equal(first, firstBefore) || !maps.Equal(left, leftBefore) || !maps.Equal(childAnswer.objects, childBefore) {
				t.Fatal("publication after nested binding contaminated a child or sibling answer")
			}
		})
	}
}

func TestCallerIdentityObjectForwardingActiveFieldSnapshot(t *testing.T) {
	g, field := callerInitialObjectFixture(t)
	selector := field.expr.(*ast.SelectorExpr)
	base := field
	base.expr = selector.X
	g.fieldQueries = []callerFieldQuery{{source: callerResolveKeyFor(base, true), fields: fieldPath(field.pkg.info.Selections[selector])}}
	g.lifetimeScanning = true
	parent := field
	parent.expr = &ast.UnaryExpr{Op: token.AND, X: selector}
	partial, _, owned := g.callerObjectsOwned(parent, map[callerObjectSourceID]bool{})
	if !owned || len(partial) == 0 || g.work.ObjectRejectCut == 0 {
		t.Fatal("active field snapshot did not remain an unpublished owned result")
	}
	before, cuts := maps.Clone(partial), g.resolveCuts-g.initialSkips
	g.callerObjects(parent, map[callerObjectSourceID]bool{})
	if g.resolveCuts-g.initialSkips <= cuts {
		t.Fatal("transparent parent published an active field snapshot")
	}
	g.fieldQueries = nil
	complete, unknown, owned := g.callerObjectsOwned(parent, map[callerObjectSourceID]bool{})
	if unknown || owned || len(complete) <= len(partial) || !maps.Equal(partial, before) {
		t.Fatal("completed transparent field provenance reused or mutated the active snapshot")
	}
}

func TestCallerIdentityObjectForwardingEmptyAnswer(t *testing.T) {
	p := callerSoundnessProgram(t, "", `empty:=(*Box)(nil);_=empty`, `&Handler{}`)
	for _, initial := range []bool{false, true} {
		g, refs := newCallerGraph(p), callerOwnershipSources(p)
		g.lifetimeScanning = initial
		parent := g.sources(callerVariable(p.root, refs["empty"].expr))[0]
		for i := 0; i < 2; i++ {
			objects, unknown, owned := g.callerObjectsOwned(parent, map[callerObjectSourceID]bool{})
			if len(objects) != 0 || unknown || owned {
				t.Fatal("transparent nil conversion acquired an object, UNKNOWN, or ownership")
			}
		}
	}
}
