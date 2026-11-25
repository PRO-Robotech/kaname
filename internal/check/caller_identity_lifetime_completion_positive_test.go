// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"maps"
	"slices"
	"testing"
)

// Фикстура использует настоящий typed field/alias путь и штатную closure effects.
func callerLifetimeCompletionFixture(t *testing.T, body string) (*callerGraph, valueSrc, valueSrc) {
	t.Helper()
	p := callerSoundnessProgram(t, "", body, `&Handler{}`)
	g := newCallerGraph(p)
	g.safeExternal = map[string]bool{"fixture/source": true}
	var field valueSrc
	for node, b := range g.bodies {
		if node.fn == nil || node.fn.Name() != "RPC" {
			continue
		}
		g.markCallerCalled(node)
		ast.Inspect(b.node, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "reader" {
				field = valueSrc{pkg: b.sp, fk: callerKey(node), expr: sel, tuple: -1}
			}
			return true
		})
	}
	if field.expr == nil {
		t.Fatal("typed fixture has no reader field")
	}
	base := field
	base.expr = field.expr.(*ast.SelectorExpr).X
	g.closeCallerEffects()
	if g.effectIncomplete {
		t.Fatal("fixture effect closure is incomplete")
	}
	return g, field, base
}

func callerLifetimeCompletionExpectedObjects(t *testing.T, g *callerGraph, field valueSrc) map[callerObjectKey]bool {
	t.Helper()
	selector := field.expr.(*ast.SelectorExpr)
	path := fieldPath(field.pkg.info.Selections[selector])
	member := path[len(path)-1].Origin()
	refs := callerOwnershipSources(g.p)
	want := map[callerObjectKey]bool{}
	for _, name := range []string{"box", "alias"} {
		key := callerOwnershipZero(refs[name])
		key.field = member
		want[key] = true
	}
	body := g.bodies[callerNode{fn: field.fk.fn, lit: field.fk.lit}]
	ast.Inspect(body.node, func(n ast.Node) bool {
		if lit, ok := n.(*ast.CompositeLit); ok {
			if typ := namedOf(field.pkg.info.TypeOf(lit)); typ != nil {
				key := callerObjectKey{pkg: field.pkg, expr: lit}
				switch typ.Obj().Name() {
				case "Box":
					key.field = member
					want[key] = true
				case "Benign":
					want[key] = true
				}
			}
		}
		return true
	})
	if len(want) != 4 {
		t.Fatal("fixture lost exact box/alias storage, Box allocation, or Benign value")
	}
	return want
}

func TestCallerIdentityLifetimeCompletionRetainsFullObjects(t *testing.T) {
	g, field, base := callerLifetimeCompletionFixture(t, `box:=&Box{reader:Benign{}};alias:=box;_=alias.reader`)
	selector := field.expr.(*ast.SelectorExpr)
	fields := fieldPath(field.pkg.info.Selections[selector])
	if g.callerLifetimeUnknown(base, fields...) {
		t.Fatal("fixture initial lifetime proof did not complete false")
	}
	g.lifetimeScanning = true
	initial, unknown, owned := g.callerObjectsOwned(field, map[callerObjectSourceID]bool{})
	g.lifetimeScanning = false
	want := callerLifetimeCompletionExpectedObjects(t, g, field)
	if unknown || owned || !maps.Equal(initial, want) {
		t.Fatal("fixture initial field provenance was not completed and published")
	}
	expected := maps.Clone(initial)
	epoch, cuts, skips := g.bindingEpoch, g.resolveCuts, g.initialSkips
	full, unknown, owned := g.callerObjectsOwned(field, map[callerObjectSourceID]bool{})
	if unknown || !maps.Equal(full, expected) || g.bindingEpoch != epoch || g.resolveCuts <= cuts || g.initialSkips <= skips {
		t.Fatalf("completed field changed exact answer or failed to exercise initial marks: unknown=%v objects=%v epoch=%d/%d cuts=%d/%d skips=%d/%d", unknown, full, g.bindingEpoch, epoch, g.resolveCuts, cuts, g.initialSkips, skips)
	}
	answer, retained := g.objectMemo[g.internObjectSource(field)]
	if !retained || owned || answer.unknown || !maps.Equal(answer.objects, expected) {
		t.Fatalf("completed full field answer was not retained: retained=%v owned=%v answer=%v", retained, owned, answer)
	}
	queries, hits, proofs, kept := g.work.ObjectQueries, g.work.ObjectHits, g.work.LifetimeProofs, g.work.ObjectRetained
	again, u, owned := g.callerObjectsOwned(field, map[callerObjectSourceID]bool{})
	if u || owned || !maps.Equal(again, expected) || !maps.Equal(initial, expected) || g.work.ObjectQueries != queries+1 || g.work.ObjectHits != hits+1 || g.work.LifetimeProofs != proofs || g.work.ObjectRetained != kept {
		t.Fatal("completed full object query repeated lifetime work or changed borrowed provenance")
	}
}

func TestCallerIdentityLifetimeCompletionRetainsFullResolve(t *testing.T) {
	g, field, base := callerLifetimeCompletionFixture(t, `box:=&Box{reader:Benign{}};alias:=box;_=alias.reader`)
	selector := field.expr.(*ast.SelectorExpr)
	if g.callerLifetimeUnknown(base, fieldPath(field.pkg.info.Selections[selector])...) {
		t.Fatal("fixture initial lifetime proof did not complete false")
	}
	g.lifetimeScanning = true
	initial, unknown := g.resolve(field, true, map[callerResolveKey]bool{})
	g.lifetimeScanning = false
	if unknown || len(initial) != 1 || initial[0].nilValue || initial[0].foreign || namedOf(initial[0].typ) == nil || namedOf(initial[0].typ).Obj().Name() != "Benign" {
		t.Fatalf("fixture did not resolve the exact Benign field: unknown=%v values=%v", unknown, initial)
	}
	expected := slices.Clone(initial)
	epoch, cuts, skips := g.bindingEpoch, g.resolveCuts, g.initialSkips
	full, unknown := g.resolve(field, true, map[callerResolveKey]bool{})
	if unknown || !slices.Equal(full, expected) || g.bindingEpoch != epoch || g.resolveCuts <= cuts || g.initialSkips <= skips {
		t.Fatalf("full resolve changed field answer or missed initial marks: unknown=%v values=%v epoch=%d/%d cuts=%d/%d skips=%d/%d", unknown, full, g.bindingEpoch, epoch, g.resolveCuts, cuts, g.initialSkips, skips)
	}
	answer, retained := g.resolveMemo[callerResolveKeyFor(field, true)]
	if !retained || answer.unknown || !slices.Equal(answer.values, expected) {
		t.Fatalf("completed full resolve was not retained: retained=%v answer=%v", retained, answer)
	}
	queries, hits, evaluations, proofs := g.work.ResolveQueries, g.work.ResolveHits, g.work.ResolveEvaluations, g.work.LifetimeProofs
	again, u := g.resolve(field, true, map[callerResolveKey]bool{})
	if u || !slices.Equal(again, expected) || !slices.Equal(initial, expected) || g.work.ResolveQueries != queries+1 || g.work.ResolveHits != hits+1 || g.work.ResolveEvaluations != evaluations || g.work.LifetimeProofs != proofs {
		t.Fatal("completed full resolver repeated work or changed its immutable initial answer")
	}
}
