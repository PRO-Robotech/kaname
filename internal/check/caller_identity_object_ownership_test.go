// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/types"
	"maps"
	"reflect"
	"strings"
	"testing"
)

func callerOwnershipSources(p *surfaceProgram) map[string]valueSrc {
	refs := map[string]valueSrc{}
	for id, object := range p.root.info.Defs {
		if v, ok := object.(*types.Var); ok && !v.IsField() {
			refs[id.Name] = valueSrc{pkg: p.root, expr: id, tuple: -1}
		}
	}
	return refs
}

func callerOwnershipZero(src valueSrc) callerObjectKey {
	return callerObjectKey{pkg: src.pkg, zero: callerVariable(src.pkg, src.expr).Origin()}
}

func TestCallerIdentityObjectUnionKeepsMemoAndSiblingsDisjoint(t *testing.T) {
	for _, full := range []bool{false, true} {
		name := "memo_available"
		if full {
			name = "memo_full"
		}
		t.Run(name, func(t *testing.T) {
			p := callerSoundnessProgram(t, "", `child:=&Box{};parent:=child;sibling:=child;_=parent;_=sibling`, `&Handler{}`)
			g, refs := newCallerGraph(p), callerOwnershipSources(p)
			if full {
				g.objectMemo = map[callerObjectSourceID]callerObjectAnswer{}
				g.objectMemoEpoch, g.objectMemoWeight = g.bindingEpoch, callerLifetimeStepLimit
			}
			child, u, owned := g.callerObjectsOwned(refs["child"], map[callerObjectSourceID]bool{})
			if u || owned != full || len(child) != 2 {
				t.Fatalf("child provenance: %v unknown=%v owned=%v", child, u, owned)
			}
			before := maps.Clone(child)
			parent, u := g.callerObjects(refs["parent"], map[callerObjectSourceID]bool{})
			if u || len(parent) != 3 || !parent[callerOwnershipZero(refs["parent"])] {
				t.Fatalf("parent lost its alias: %v unknown=%v", parent, u)
			}
			snapshot := maps.Clone(parent)
			sibling, u := g.callerObjects(refs["sibling"], map[callerObjectSourceID]bool{})
			if u || len(sibling) != 3 || sibling[callerOwnershipZero(refs["parent"])] || parent[callerOwnershipZero(refs["sibling"])] {
				t.Fatalf("siblings contaminated each other: parent=%v sibling=%v unknown=%v", parent, sibling, u)
			}
			if !maps.Equal(child, before) || !maps.Equal(parent, snapshot) {
				t.Fatal("a later traversal mutated a previously returned child or parent")
			}
			if full && (g.work.ObjectUnionTransfers == 0 || g.work.ObjectUnionWrites >= g.work.ObjectUnionBaselineWrites) {
				t.Fatalf("unpublished alias chain did not avoid set copies: %+v", g.work)
			}
			if !full {
				again, _, owned := g.callerObjectsOwned(refs["child"], map[callerObjectSourceID]bool{})
				if owned || !maps.Equal(again, before) {
					t.Fatal("parent adoption contaminated the cached child")
				}
			}
		})
	}
}

func TestCallerIdentityObjectOwnershipPublicationTransition(t *testing.T) {
	p := callerSoundnessProgram(t, "", `child:=&Box{};parent:=child;_=parent;extra:=&Box{};_=extra`, `&Handler{}`)
	g, refs := newCallerGraph(p), callerOwnershipSources(p)
	g.objectMemo = map[callerObjectSourceID]callerObjectAnswer{}
	g.objectMemoEpoch, g.objectMemoWeight = g.bindingEpoch, callerLifetimeStepLimit
	unpublished, u, owned := g.callerObjectsOwned(refs["child"], map[callerObjectSourceID]bool{})
	if u || !owned {
		t.Fatal("capacity rejection must leave a nonempty raw result uniquely owned")
	}
	before := maps.Clone(unpublished)
	g.objectMemo = nil
	published, u, owned := g.callerObjectsOwned(refs["child"], map[callerObjectSourceID]bool{})
	if u || owned || !maps.Equal(published, before) {
		t.Fatal("publication must relinquish ownership without changing provenance")
	}
	g.callerObjects(refs["parent"], map[callerObjectSourceID]bool{})
	if !maps.Equal(published, before) || !maps.Equal(unpublished, before) {
		t.Fatal("parent traversal mutated a published or previously returned answer")
	}
	g.addCallerLive(callerVariable(p.root, refs["child"].expr), refs["extra"])
	changed, u := g.callerObjects(refs["parent"], map[callerObjectSourceID]bool{})
	if u || !changed[callerOwnershipZero(refs["extra"])] {
		t.Fatal("warm alias chain lost a new live binding")
	}
	if !maps.Equal(published, before) || !maps.Equal(unpublished, before) {
		t.Fatal("epoch reset made an old borrowed or owned answer writable")
	}
}

func TestCallerIdentityObjectOwnershipCyclesAndUnknown(t *testing.T) {
	p := callerSoundnessProgram(t, "", `branch:=&Box{};var cycle *Box;cycle=branch;cycle=cycle;left:=cycle;right:=cycle;_=left;_=right;var hollow *Box;hollow=hollow;opaque:=source.Value();_=opaque`, `&Handler{}`)
	g, refs := newCallerGraph(p), callerOwnershipSources(p)
	g.safeExternal = map[string]bool{"fixture/source": true}
	if empty, u, owned := g.callerObjectsOwned(valueSrc{}, map[callerObjectSourceID]bool{}); len(empty) != 0 || !u || owned {
		t.Fatal("missing source became an owned value or evidence of absence")
	}
	branch, u := g.callerObjects(refs["branch"], map[callerObjectSourceID]bool{})
	if u || len(branch) != 2 {
		t.Fatal("missing concrete cycle anchor")
	}
	anchor := maps.Clone(branch)
	left, u, owned := g.callerObjectsOwned(refs["left"], map[callerObjectSourceID]bool{})
	if u || !owned || len(left) != 4 {
		t.Fatalf("anchored recursive answer changed or was published: %v %v %v", left, u, owned)
	}
	before := maps.Clone(left)
	cuts := g.objectCuts
	right, u := g.callerObjects(refs["right"], map[callerObjectSourceID]bool{})
	if u || len(right) != 4 || right[callerOwnershipZero(refs["left"])] || g.objectCuts <= cuts {
		t.Fatal("sibling query reused or contaminated a partial recursive answer")
	}
	if !maps.Equal(left, before) || !maps.Equal(branch, anchor) {
		t.Fatal("recursive ownership transfer mutated an escaped answer")
	}
	cut, u, owned := g.callerObjectsOwned(refs["cycle"], map[callerObjectSourceID]bool{g.internObjectSource(refs["cycle"]): true})
	if u || owned || len(cut) != 0 {
		t.Fatal("active recursion cut acquired ownership or changed its partial result")
	}
	if _, u := g.callerObjects(refs["hollow"], map[callerObjectSourceID]bool{}); !u {
		t.Fatal("unanchored cycle became evidence of absence")
	}
	g.addCallerLive(callerVariable(p.root, refs["cycle"].expr), refs["opaque"])
	changed, u := g.callerObjects(refs["left"], map[callerObjectSourceID]bool{})
	if !u || !changed[callerOwnershipZero(refs["opaque"])] {
		t.Fatal("anchored cycle erased a new unresolved source")
	}
	if !maps.Equal(left, before) || !maps.Equal(branch, anchor) {
		t.Fatal("new unknown source contaminated previous answers")
	}
	if g.work.ObjectUnionTransfers == 0 || g.work.ObjectUnionWrites >= g.work.ObjectUnionBaselineWrites {
		t.Fatal("recursive unpublished sets never transferred")
	}
}

func TestCallerIdentityObjectOwnershipClosureProbeIsCurrent(t *testing.T) {
	p := callerSoundnessProgram(t, `var shelf=[]Box{{reader:Benign{}}};func configure(){_=func(){alias:=shelf;alias=alias;owner:=alias;owner[0]=Box{reader:Concrete{}}}}`, ``, `&Handler{}`)
	refs := callerOwnershipSources(p)
	for _, fallback := range []bool{false, true} {
		g := newCallerGraph(p)
		g.safeExternal = map[string]bool{"fixture/source": true}
		if fallback {
			g.lifetimeWriteIndex = nil
		}
		query := func() ([]valueSrc, bool) {
			return g.callerContainerSources(refs["shelf"], nil, map[callerFieldKey]bool{})
		}
		cold, u := query()
		if u || len(cold) != 0 {
			t.Fatal("uncreated closure contributed a write")
		}
		var outer callerNode
		for node := range g.bodies {
			if node.fn != nil && node.fn.Name() == "configure" {
				outer = node
			}
		}
		if outer.fn == nil {
			t.Fatal("missing closure owner")
		}
		g.markCallerCalled(outer)
		active, u := query()
		if u || len(active) != 1 || g.work.ObjectUnionTransfers == 0 {
			t.Fatalf("warm probe lost the created closure's recursive alias: %v unknown=%v work=%+v", active, u, g.work)
		}
		if again, u := query(); u || !reflect.DeepEqual(active, again) {
			t.Fatal("warm created-closure probe changed")
		}
		g.called = map[callerNode]bool{}
		g.bindingEpoch++
		if reset, u := query(); u || len(reset) != 0 {
			t.Fatal("fresh called context retained a previous closure effect")
		}
		if fallback && g.work.ContainerIndexFallbacks == 0 {
			t.Fatal("full-scan fallback was not exercised")
		}
	}
}

func TestCallerIdentityObjectOwnershipLawfulDeclarationTwin(t *testing.T) {
	const rpc = "fixture/service/FixtureService/RPC"
	const producer = "github.com/PRO-Robotech/corelib/operations.PrincipalFromContext"
	p := callerSoundnessProgram(t, callerFluentFixture, `box:=newBox().withReader(Concrete{}).again();alias:=box;alias.reader.read()`, `&Handler{}`)
	base := []CallerReadDeclaration{{RPC: rpc, Producer: producer, Site: "fixture/app.anchor", Kind: CallerObservation, Reason: "Fixture anchor."}}
	judge := func(declarations []CallerReadDeclaration) CallerIdentityReport {
		return judgeCallerIdentity(p, declarations, map[string]bool{"fixture/source": true})
	}
	negative := judge(base)
	if negative.Invalid != "" || len(negative.Findings) != 1 || !strings.Contains(negative.Findings[0], "чтение личности без объявления") {
		t.Fatalf("alias-chain reader was not rejected: %+v", negative)
	}
	base = append(base, CallerReadDeclaration{RPC: rpc, Producer: producer, Site: "(fixture/app.Concrete).read", Kind: CallerObservation, Reason: "Same alias chain, declared read."})
	lawful := judge(base)
	if lawful.Invalid != "" || len(lawful.Findings) != 0 || !reflect.DeepEqual(lawful.Reads, negative.Reads) {
		t.Fatalf("declaration twin changed the real read population: %+v", lawful)
	}
}
