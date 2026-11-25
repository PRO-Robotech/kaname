// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"maps"
	"testing"
)

func TestCallerIdentityLifetimeCompletionInitialNeverCredits(t *testing.T) {
	g, field, base := callerLifetimeCompletionFixture(t, `box:=&Box{reader:Benign{}};alias:=box;_=alias.reader`)
	g.lifetimeScanning = true
	credits, cuts, skips := g.completedInitialSkips, g.resolveCuts, g.initialSkips
	for i := 0; i < 2; i++ {
		if g.callerLifetimeUnknown(base) {
			t.Fatal("nested initial branch unexpectedly returned UNKNOWN")
		}
	}
	initial, unknown, owned := g.callerObjectsOwned(field, map[callerObjectSourceID]bool{})
	if unknown || owned || len(initial) == 0 || g.completedInitialSkips != credits || g.resolveCuts-cuts != g.initialSkips-skips || g.initialSkips-skips < 2 {
		t.Fatal("initial-only work credited marks or changed initial admission")
	}
	if _, full := g.objectMemo[g.internObjectSource(field)]; full {
		t.Fatal("initial-only answer entered full memo")
	}
	before := maps.Clone(initial)
	hits := g.work.ObjectHits
	again, u, owned := g.callerObjectsOwned(field, map[callerObjectSourceID]bool{})
	if u || owned || !maps.Equal(again, before) || g.work.ObjectHits != hits+1 || g.completedInitialSkips != credits {
		t.Fatal("initial memo hit lost its boundary or acquired full completion credit")
	}
}

func TestCallerIdentityLifetimeCompletionRejectsUnsafeBarriers(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		unknown    bool
	}{
		{"escape", `box:=&Box{reader:Benign{}};source.Mutate(box);_=box.reader`, true},
		{"unknown", `box:=source.Value().(*Box);_=box.reader`, true},
		{"anchored_cycle", `box:=&Box{reader:Benign{}};box=box;_=box.reader`, false},
		{"unanchored_cycle", `var box *Box;box=box;_=box.reader`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, field, base := callerLifetimeCompletionFixture(t, tc.body)
			g.lifetimeScanning = true
			g.callerObjects(base, map[callerObjectSourceID]bool{})
			g.lifetimeScanning = false
			credits, cuts, skips := g.completedInitialSkips, g.resolveCuts, g.initialSkips
			unknown := g.callerLifetimeUnknown(base)
			if unknown != tc.unknown || g.completedInitialSkips != credits || g.resolveCuts < cuts || g.initialSkips < skips || g.lifetimeScanning || g.effectScanning {
				t.Fatalf("unsafe barrier credited or changed semantics: unknown=%v want=%v credits=%d/%d", unknown, tc.unknown, g.completedInitialSkips, credits)
			}
			if tc.name == "anchored_cycle" || tc.name == "unanchored_cycle" {
				if g.resolveCuts-cuts <= g.initialSkips-skips {
					t.Fatal("cycle fixture did not exercise a real cut")
				}
			}
			g.callerObjects(field, map[callerObjectSourceID]bool{})
			if _, retained := g.objectMemo[g.internObjectSource(field)]; retained {
				t.Fatal("unsafe field traversal laundered its marks into full object memo")
			}
			g.resolve(field, true, map[callerResolveKey]bool{})
			if _, retained := g.resolveMemo[callerResolveKeyFor(field, true)]; retained {
				t.Fatal("unsafe field traversal laundered its marks into full resolve memo")
			}
		})
	}
}

func TestCallerIdentityLifetimeCompletionRejectsSnapshotAndIncompleteEffects(t *testing.T) {
	g, field, base := callerLifetimeCompletionFixture(t, `box:=&Box{reader:Benign{}};_=box.reader`)
	selector := field.expr.(*ast.SelectorExpr)
	g.fieldQueries = []callerFieldQuery{{source: callerResolveKeyFor(base, true), fields: fieldPath(field.pkg.info.Selections[selector])}}
	credits, cuts, skips := g.completedInitialSkips, g.resolveCuts, g.initialSkips
	g.callerLifetimeUnknown(field)
	if g.completedInitialSkips != credits || g.resolveCuts-cuts <= g.initialSkips-skips || len(g.fieldQueries) != 1 || g.lifetimeScanning {
		t.Fatal("active snapshot cut was credited or its owning query was removed")
	}
	if _, retained := g.initialObjectMemo[g.internObjectSource(field)]; retained {
		t.Fatal("active snapshot was published even in initial memo")
	}
	g.fieldQueries = nil
	g.effectScanning, g.effectIncomplete = true, true
	g.effectEpoch = -1
	if !g.callerLifetimeUnknown(base) || g.completedInitialSkips != credits || g.lifetimeScanning {
		t.Fatal("in-progress incomplete effects became a completed lifetime proof")
	}
	g.effectScanning = false
}

func TestCallerIdentityLifetimeCompletionStepLimitNeverCredits(t *testing.T) {
	g, _, base := callerLifetimeCompletionFixture(t, `box:=&Box{reader:Benign{}};other:=&Box{};source.Mutate(other);_=box.reader`)
	var site callSrc
	for _, candidate := range g.lifetimeCalls {
		if fn := callerFunction(candidate.pkg, candidate.call.Fun); fn != nil && fn.Name() == "Mutate" {
			site = candidate
		}
	}
	if site.call == nil {
		t.Fatal("missing real typed disjoint effect site")
	}
	// Повторяем настоящий disjoint site до штатного лимита probe, не меняя steps.
	g.lifetimeCalls = nil
	for i := 0; i <= callerLifetimeStepLimit; i++ {
		g.lifetimeCalls = append(g.lifetimeCalls, site)
	}
	g.lifetimeScanning = true
	objects, u := g.callerObjects(base, map[callerObjectSourceID]bool{})
	g.lifetimeScanning = false
	if u || len(objects) == 0 {
		t.Fatal("step-limit fixture base is unknown")
	}
	credits, steps := g.completedInitialSkips, g.work.LifetimeProbeSteps
	if !g.callerLifetimeUnknown(base) || g.completedInitialSkips != credits || g.work.LifetimeProbeSteps-steps <= callerLifetimeStepLimit || g.lifetimeScanning {
		t.Fatal("step-limit UNKNOWN was credited as completed false")
	}
}

func TestCallerIdentityLifetimeCompletionEpochAndSequentialAccounting(t *testing.T) {
	prepared, field, base := callerLifetimeCompletionFixture(t, `box:=&Box{reader:Benign{}};other:=&Box{reader:Concrete{}};alias:=box;_=other;_=alias.reader`)
	g := newCallerGraph(prepared.p)
	g.safeExternal = prepared.safeExternal
	g.markCallerCalled(callerNode{fn: base.fk.fn, lit: base.fk.lit})
	epoch, credits := g.bindingEpoch, g.completedInitialSkips
	g.callerLifetimeUnknown(base)
	if g.bindingEpoch <= epoch || g.completedInitialSkips != credits || g.lifetimeScanning {
		t.Fatal("binding changes during actual effect closure received completion credit")
	}
	// Холодный field proof содержит вложенные initial boundaries; тёплый — hit.
	for i := 0; i < 3; i++ {
		cuts, skips, completed, epoch := g.resolveCuts, g.initialSkips, g.completedInitialSkips, g.bindingEpoch
		if g.callerLifetimeUnknown(field) {
			t.Fatal("stable sequential barrier did not complete false")
		}
		if g.bindingEpoch != epoch || g.initialSkips <= skips || g.resolveCuts-cuts != g.initialSkips-skips || g.completedInitialSkips-completed != g.initialSkips-skips || g.completedInitialSkips > g.initialSkips || g.lifetimeScanning {
			t.Fatalf("barrier %d double-credited, lost marks, or changed epoch", i)
		}
	}
	// Реальный cut за пределами интервала не поглощается следующим false proof.
	selector := field.expr.(*ast.SelectorExpr)
	fields := fieldPath(field.pkg.info.Selections[selector])
	index, entered := g.enterCallerFieldQuery(base, fields)
	if !entered {
		t.Fatal("fresh field query was already active")
	}
	_, entered = g.enterCallerFieldQuery(base, fields)
	if entered {
		t.Fatal("duplicate field query did not create real cut")
	}
	g.fieldQueries = g.fieldQueries[:index]
	realCuts := g.resolveCuts - g.completedInitialSkips
	if g.callerLifetimeUnknown(field) || g.resolveCuts-g.completedInitialSkips != realCuts {
		t.Fatal("later completed barrier laundered an earlier snapshot cut")
	}
	before, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
	if unknown || len(before) == 0 {
		t.Fatal("stable pre-epoch field query did not complete")
	}
	snapshot := maps.Clone(before)
	refs := callerOwnershipSources(g.p)
	credits = g.completedInitialSkips
	g.addCallerLive(callerVariable(field.pkg, refs["alias"].expr), refs["other"])
	changed, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
	other := callerOwnershipZero(refs["other"])
	other.field = fields[len(fields)-1].Origin()
	if unknown || !changed[other] || before[other] || len(changed) <= len(before) || !maps.Equal(before, snapshot) || g.completedInitialSkips < credits {
		t.Fatal("new epoch lost live alias, reset credits mid-run, or mutated borrowed old answer")
	}
}

func TestCallerIdentityLifetimeCompletionCancellationNeverCredits(t *testing.T) {
	for _, mid := range []bool{false, true} {
		name := "pre"
		if mid {
			name = "mid"
		}
		t.Run(name, func(t *testing.T) {
			g, field, base := callerLifetimeCompletionFixture(t, `box:=&Box{reader:Benign{}};_=box.reader`)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			queries := g.work.ObjectQueries
			if mid {
				g.ctx = &callerObjectCancelContext{Context: ctx, cancel: cancel, reached: func() bool { return g.lifetimeScanning && g.work.ObjectQueries > queries }}
			} else {
				cancel()
				g.ctx = ctx
			}
			credits, retained := g.completedInitialSkips, g.work.ObjectRetained
			if !g.callerLifetimeUnknown(base) || g.completedInitialSkips != credits || g.lifetimeScanning || g.effectScanning || len(g.fieldQueries) != 0 || g.work.ObjectRetained != retained {
				t.Fatal("cancelled proof credited or published partial work or leaked state")
			}
			seen := map[callerObjectSourceID]bool{}
			objects, unknown, owned := g.callerObjectsOwned(field, seen)
			values, unresolved := g.resolve(field, true, map[callerResolveKey]bool{})
			if objects != nil || !unknown || owned || len(seen) != 0 || values != nil || !unresolved || g.completedInitialSkips != credits {
				t.Fatal("cancelled full admission changed completion or incomplete result contract")
			}
		})
	}
}

func TestCallerIdentityLifetimeCompletionCapacityAndBorrowedSafety(t *testing.T) {
	g, field, base := callerLifetimeCompletionFixture(t, `box:=&Box{reader:Benign{}};alias:=box;_=alias.reader`)
	g.callerLifetimeUnknown(base)
	g.lifetimeScanning = true
	initial, u := g.callerObjects(field, map[callerObjectSourceID]bool{})
	g.resolve(field, true, map[callerResolveKey]bool{})
	g.lifetimeScanning = false
	if u || len(initial) == 0 {
		t.Fatal("missing initial borrowed field provenance")
	}
	before := maps.Clone(initial)
	g.objectMemoWeight = callerLifetimeStepLimit
	g.resolveEntryCap, g.resolveValueCap = 1, 1
	objects, unknown, owned := g.callerObjectsOwned(field, map[callerObjectSourceID]bool{})
	if unknown || !owned || !maps.Equal(objects, before) || g.work.ObjectRejectCapacity == 0 {
		t.Fatal("completed barrier bypassed object capacity or lost exact field answer")
	}
	if _, retained := g.objectMemo[g.internObjectSource(field)]; retained {
		t.Fatal("full object capacity rejection published answer")
	}
	g.resolve(field, true, map[callerResolveKey]bool{})
	if _, retained := g.resolveMemo[callerResolveKeyFor(field, true)]; retained || g.work.ResolveRejected == 0 {
		t.Fatal("completed barrier bypassed full resolver capacity")
	}
	clear(objects)
	if !maps.Equal(initial, before) {
		t.Fatal("capacity-rejected owned field result mutated initial borrowed memo")
	}
}
