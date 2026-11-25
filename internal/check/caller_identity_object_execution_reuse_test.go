// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"maps"
	"slices"
	"testing"
)

// Используется настоящая фабрика запуска, как в judge; source и типы принадлежат
// прежней typed-фикстуре. Изолированный newCallerGraph служит лишь её загрузчиком.
func callerExecutionSnapshotFixture(t *testing.T) (*callerGraph, valueSrc, valueSrc, map[string]valueSrc) {
	t.Helper()
	prepared, field, base, literals := callerEffectCertificateSnapshotFixture(t)
	g := callerGraphFor(prepared.p, nil)
	t.Cleanup(func() { callerGraphs.Delete(prepared.p) })
	g.safeExternal = prepared.safeExternal
	g.markCallerCalled(callerNode{fn: field.fk.fn, lit: field.fk.lit})
	g.lifetimeScanning = true
	g.callerObjects(base, map[callerObjectSourceID]bool{})
	for _, name := range []string{"Box", "Benign", "Concrete"} {
		g.callerObjects(literals[name], map[callerObjectSourceID]bool{})
	}
	selector := field.expr.(*ast.SelectorExpr)
	index, entered := g.enterCallerFieldQuery(base, fieldPath(field.pkg.info.Selections[selector]))
	if !entered {
		t.Fatal("typed snapshot owner was already active")
	}
	g.fieldQueries[index].refs = []valueSrc{literals["Benign"]}
	t.Cleanup(func() { g.leaveCallerFieldQuery(index) })
	return g, field, base, literals
}

func callerPrimeObjectExecution(t *testing.T, g *callerGraph, src valueSrc) map[callerObjectKey]bool {
	t.Helper()
	first, unknown := g.callerObjects(src, map[callerObjectSourceID]bool{})
	before := maps.Clone(first)
	g.callerObjects(src, map[callerObjectSourceID]bool{})
	hits, raw, marks := g.work.ObjectExecutionHits, g.work.ObjectRawEvaluations, callerReuseMarks(g)
	third, otherUnknown := g.callerObjects(src, map[callerObjectSourceID]bool{})
	if unknown != otherUnknown || !maps.Equal(third, before) || !maps.Equal(first, before) || g.work.ObjectExecutionHits != hits+1 || g.work.ObjectRawEvaluations != raw {
		t.Fatal("stable typed initial execution did not replay its exact immutable answer")
	}
	if delta := callerReuseDelta(g, marks); delta[0] <= delta[1] || delta[2] != 0 {
		t.Fatal("execution summary lost its uncovered cut or manufactured completion credit")
	}
	if _, complete := g.initialObjectMemo[g.internObjectSource(src)]; complete {
		t.Fatal("execution summary became completed initial provenance")
	}
	return third
}

func TestCallerIdentityObjectExecutionRepeatedDiamondWork(t *testing.T) {
	prepared, owner, _, expected := callerRepeatedContainerOwners(t)
	t.Cleanup(func() { callerGraphs.Delete(prepared.p) })
	selector := owner.expr.(*ast.SelectorExpr)
	base := owner
	base.expr = selector.X
	makeGraph := func(reference bool) *callerGraph {
		g := callerGraphFor(prepared.p, nil)
		g.markCallerCalled(callerNode{fn: owner.fk.fn, lit: owner.fk.lit})
		g.lifetimeScanning = true
		index, entered := g.enterCallerFieldQuery(base, fieldPath(owner.pkg.info.Selections[selector]))
		if !entered {
			t.Fatal("missing typed append-owner field frame")
		}
		t.Cleanup(func() { g.leaveCallerFieldQuery(index) })
		if reference {
			// Утрата namespace имеет штатный полный fallback; ответы не подменяются.
			g.objectExecutions = nil
		}
		return g
	}
	fast, reference := makeGraph(false), makeGraph(true)
	query := func(g *callerGraph) {
		refs, unknown := g.callerContainerSources(owner, nil, map[callerFieldKey]bool{})
		if unknown || !slices.Equal(refs, expected) {
			t.Fatal("typed matched writes changed exact ordered provenance or UNKNOWN")
		}
	}
	// Прогрев отделён от измеряемого повтора. Каждый matched value сбрасывает
	// прежний локальный reuse, но возвращает тот же полный контекст глобальному слою.
	for range 2 {
		query(fast)
		query(reference)
	}
	oldObjects, oldUnknown := reference.callerObjects(owner, map[callerObjectSourceID]bool{})
	newObjects, newUnknown := fast.callerObjects(owner, map[callerObjectSourceID]bool{})
	if oldUnknown != newUnknown || !maps.Equal(newObjects, oldObjects) || len(newObjects) == 0 {
		t.Fatal("diamond lost typed allocation/storage aliases")
	}
	const repetitions = 8
	fastRaw, oldRaw := fast.work.ObjectRawEvaluations, reference.work.ObjectRawEvaluations
	fastMarks, oldMarks := callerReuseMarks(fast), callerReuseMarks(reference)
	hits, stores := fast.work.ObjectExecutionHits, fast.work.ObjectExecutionStores
	matched := fast.work.ContainerMatchedWrites
	for range repetitions {
		query(fast)
		query(reference)
	}
	if callerReuseDelta(fast, fastMarks) != callerReuseDelta(reference, oldMarks) {
		t.Fatal("same-state diamond changed cut/skip/cycle/completion effects")
	}
	// Единственный уже прогретый owner/context обслуживает все рёбра diamond.
	// Контроль вакуозности: тот же production fallback обязан нарушить этот предел.
	const warmedDistinctRawStates = 0
	actual := fast.work.ObjectRawEvaluations - fastRaw
	baseline := reference.work.ObjectRawEvaluations - oldRaw
	if actual != warmedDistinctRawStates || baseline <= repetitions*len(expected) || fast.work.ObjectExecutionHits-hits != repetitions*(len(expected)+1) || fast.work.ObjectExecutionStores != stores || fast.work.ContainerMatchedWrites-matched != repetitions*len(expected) {
		t.Fatalf("diamond work: actual=%d baseline=%d hits=%d stores=%d matched=%d", actual, baseline, fast.work.ObjectExecutionHits-hits, fast.work.ObjectExecutionStores-stores, fast.work.ContainerMatchedWrites-matched)
	}
}

func TestCallerIdentityObjectExecutionSnapshotContentAndPop(t *testing.T) {
	g, field, base, literals := callerExecutionSnapshotFixture(t)
	old := callerPrimeObjectExecution(t, g, field)
	before := maps.Clone(old)
	epoch := g.bindingEpoch
	for _, name := range []string{"Concrete", "Benign"} {
		g.fieldQueries[0].refs[0] = literals[name]
		got := callerPrimeObjectExecution(t, g, field)
		if !maps.Equal(got, callerEffectCertificateObjects(t, field, base, literals, name)) || g.bindingEpoch != epoch || !maps.Equal(old, before) {
			t.Fatal("same-length same-epoch snapshot update retained a stale answer or changed an old map")
		}
	}
	g.fieldQueries[0].unknown = true
	got := callerPrimeObjectExecution(t, g, field)
	if _, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{}); !unknown || !maps.Equal(got, before) {
		t.Fatal("snapshot UNKNOWN disappeared in execution replay")
	}
	g.fieldQueries[0].unknown = false
	hits := g.work.ObjectExecutionHits
	if _, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{}); unknown || g.work.ObjectExecutionHits != hits+1 {
		t.Fatal("restored content did not recover its previous execution identity")
	}
	other := base
	other.tuple = 7
	index, entered := g.enterCallerFieldQuery(other, g.fieldQueries[0].fields)
	if !entered {
		t.Fatal("missing distinct nested frame")
	}
	hits = g.work.ObjectExecutionHits
	g.callerObjects(field, map[callerObjectSourceID]bool{})
	if g.work.ObjectExecutionHits != hits {
		t.Fatal("different active stack reused its parent's context")
	}
	g.leaveCallerFieldQuery(index)
	raw := g.work.ObjectRawEvaluations
	g.callerObjects(field, map[callerObjectSourceID]bool{})
	if g.work.ObjectExecutionHits != hits+1 || g.work.ObjectRawEvaluations != raw {
		t.Fatal("pop failed to restore the earlier content identity")
	}
}

func TestCallerIdentityObjectExecutionGuardsAndSyntheticFallback(t *testing.T) {
	g, field, base, _ := callerExecutionSnapshotFixture(t)
	callerPrimeObjectExecution(t, g, field)
	for _, kind := range []string{"container", "mutation"} {
		hits, marks := g.work.ObjectExecutionHits, callerReuseMarks(g)
		container := callerResolveKeyFor(base, true)
		mutation := callerFieldKey{container, g.fieldQueries[0].fields[0].Origin()}
		if kind == "container" {
			g.containerScanning = map[callerResolveKey]bool{container: true}
		} else {
			g.mutationScanning = map[callerFieldKey]bool{mutation: true}
		}
		got, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
		if g.work.ObjectExecutionHits != hits {
			t.Fatal("active guard reused the unguarded context")
		}
		delta := callerReuseDelta(g, marks)
		marks = callerReuseMarks(g)
		want, u, _ := g.callerObjectsOwned(field, map[callerObjectSourceID]bool{})
		if unknown != u || !maps.Equal(got, want) || callerReuseDelta(g, marks) != delta {
			t.Fatal("guarded summary admission changed the original guarded execution")
		}
		delete(g.containerScanning, container)
		delete(g.mutationScanning, mutation)
		g.callerObjects(field, map[callerObjectSourceID]bool{})
		if g.work.ObjectExecutionHits != hits+1 {
			t.Fatal("guard removal did not recover the earlier exact context")
		}
	}
	// Прямой синтетический стек не становится отслеженным из-за одной длины.
	key := callerResolveKeyFor(base, true)
	oldHead := g.fieldQueryHeads[key]
	g.fieldQueryHeads[key] = 0
	if g.callerExecutionScopeTracked() {
		t.Fatal("equal depth accepted a malformed source-head chain")
	}
	hits, stores := g.work.ObjectExecutionHits, g.work.ObjectExecutionStores
	g.fieldQueryIndexedDepth = -1
	got, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
	if unknown || len(got) == 0 || g.work.ObjectExecutionHits != hits || g.work.ObjectExecutionStores != stores {
		t.Fatal("synthetic stack escaped full fallback")
	}
	g.fieldQueryHeads[key] = oldHead
	g.fieldQueryIndexedDepth = len(g.fieldQueries)
}

func TestCallerIdentityObjectExecutionCyclesAndSeen(t *testing.T) {
	p := callerSoundnessProgram(t, "", `anchor:=&Box{};var cycle *Box;cycle=anchor;cycle=cycle;var hollow *Box;hollow=hollow;_=cycle;_=hollow`, `&Handler{}`)
	t.Cleanup(func() { callerGraphs.Delete(p) })
	g, refs := callerGraphFor(p, nil), callerOwnershipSources(p)
	g.lifetimeScanning = true
	for _, name := range []string{"cycle", "hollow"} {
		got := callerPrimeObjectExecution(t, g, refs[name])
		marks, hits := callerReuseMarks(g), g.work.ObjectExecutionHits
		_, unknown := g.callerObjects(refs[name], map[callerObjectSourceID]bool{})
		delta := callerReuseDelta(g, marks)
		marks = callerReuseMarks(g)
		want, otherUnknown, owned := g.callerObjectsOwned(refs[name], map[callerObjectSourceID]bool{})
		if unknown != (name == "hollow") || otherUnknown != unknown || !owned || !maps.Equal(got, want) || delta != callerReuseDelta(g, marks) || delta[3] == 0 || g.work.ObjectExecutionHits != hits+1 {
			t.Fatal("anchored/hollow cycle changed UNKNOWN, ownership, or real cycle effects")
		}
		seen := map[callerObjectSourceID]bool{g.internObjectSource(refs[name]): true}
		hits = g.work.ObjectExecutionHits
		objects, u := g.callerObjects(refs[name], seen)
		want, otherUnknown, _ = g.callerObjectsOwned(refs[name], seen)
		if u != otherUnknown || !maps.Equal(objects, want) || len(objects) != 0 || g.work.ObjectExecutionHits != hits || len(seen) != 1 {
			t.Fatal("nonempty object seen set used fresh-query replay")
		}
	}
}

func TestCallerIdentityObjectExecutionEpochRootAndGraph(t *testing.T) {
	g, field, base, literals := callerExecutionSnapshotFixture(t)
	old := callerPrimeObjectExecution(t, g, field)
	before := maps.Clone(old)
	clone := *g
	hits, raw := clone.work.ObjectExecutionHits, clone.work.ObjectRawEvaluations
	clone.callerObjects(field, map[callerObjectSourceID]bool{})
	if clone.work.ObjectExecutionHits != hits || clone.work.ObjectRawEvaluations <= raw || !maps.Equal(old, before) {
		t.Fatal("graph copy reused another owner's execution store")
	}
	previous := g.objectExecutions
	g.resetCallerObjectExecutions()
	hits = g.work.ObjectExecutionHits
	g.callerObjects(field, map[callerObjectSourceID]bool{})
	if g.objectExecutions == previous || g.work.ObjectExecutionHits != hits {
		t.Fatal("root namespace reset retained an earlier execution")
	}
	callerPrimeObjectExecution(t, g, field)
	g.addCallerLive(callerVariable(base.pkg, base.expr), literals["Box"])
	hits = g.work.ObjectExecutionHits
	g.callerObjects(field, map[callerObjectSourceID]bool{})
	if g.work.ObjectExecutionHits != hits || !maps.Equal(old, before) {
		t.Fatal("new binding epoch reused or mutated an old summary")
	}
	fresh := callerGraphFor(g.p, nil)
	if fresh.objectExecutions == g.objectExecutions || fresh.objectExecutions.graph != fresh || len(fresh.objectExecutions.answers) != 0 || len(fresh.objectExecutions.scopes) != 0 {
		t.Fatal("new run inherited a previous root's summaries or scope nodes")
	}
}

func TestCallerIdentityObjectExecutionCancellation(t *testing.T) {
	for _, phase := range []string{"hit", "publish"} {
		t.Run(phase, func(t *testing.T) {
			g, field, _, _ := callerExecutionSnapshotFixture(t)
			callerPrimeObjectExecution(t, g, field)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hits, stores, credits := g.work.ObjectExecutionHits, g.work.ObjectExecutionStores, g.completedInitialSkips
			if phase == "hit" {
				cancel()
				g.ctx = ctx
			} else {
				g.fieldQueries[0].unknown = true
				raw := g.work.ObjectRawEvaluations
				g.ctx = &callerObjectCancelContext{Context: ctx, cancel: cancel, reached: func() bool { return g.work.ObjectRawEvaluations > raw }}
			}
			got, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
			if ctx.Err() != context.Canceled || got != nil || !unknown || g.work.ObjectExecutionHits != hits || g.work.ObjectExecutionStores != stores || g.completedInitialSkips != credits || len(g.fieldQueries) != 1 {
				t.Fatal("cancelled execution replayed, published, credited, or damaged its caller frame")
			}
		})
	}
}

func TestCallerIdentityObjectExecutionOpaqueAliasAndFullBarrier(t *testing.T) {
	for _, effect := range []string{"", "source.Mutate(alias);"} {
		prepared, field, base := callerLifetimeCompletionFixture(t, `box:=&Box{reader:Benign{}};alias:=box;_ = alias;`+effect+`_ = box.reader`)
		g := callerGraphFor(prepared.p, nil)
		t.Cleanup(func() { callerGraphs.Delete(prepared.p) })
		g.safeExternal = prepared.safeExternal
		g.markCallerCalled(callerNode{fn: field.fk.fn, lit: field.fk.lit})
		g.closeCallerEffects()
		if g.effectIncomplete {
			t.Fatal("typed effect closure failed before summary test")
		}
		g.lifetimeScanning = true
		selector := field.expr.(*ast.SelectorExpr)
		fields := fieldPath(field.pkg.info.Selections[selector])
		owner, entered := g.enterCallerFieldQuery(base, fields)
		if !entered {
			t.Fatal("missing initial owner")
		}
		g.fieldQueries[owner].refs, g.fieldQueries[owner].unknown = g.embeddedCallerSourcesRaw(base, fields, map[callerFieldKey]bool{})
		old := callerPrimeObjectExecution(t, g, field)
		before := maps.Clone(old)
		g.leaveCallerFieldQuery(owner)
		g.lifetimeScanning = false
		hits := g.work.ObjectExecutionHits
		proofs := g.work.LifetimeProofs
		got, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
		if unknown != (effect != "") || !maps.Equal(got, before) || !maps.Equal(old, before) {
			t.Fatal("initial execution summary replaced the real alias lifetime barrier")
		}
		// Внутренние initial-подзапросы барьера могут законно воспользоваться слоем;
		// полный field answer обязан всё равно исполнить прежний lifetime proof.
		if g.work.LifetimeProofs <= proofs || g.work.ObjectExecutionHits < hits {
			t.Fatal("full mode did not perform a lifetime proof")
		}
		if effect != "" {
			if _, complete := g.objectMemo[g.internObjectSource(field)]; complete {
				t.Fatal("opaque alias escape became completed provenance")
			}
		}
	}
}

func TestCallerIdentityObjectExecutionBudgetAndImmutableCopies(t *testing.T) {
	g, field, base, literals := callerExecutionSnapshotFixture(t)
	old := callerPrimeObjectExecution(t, g, field)
	before := maps.Clone(old)
	for i := 0; i <= callerObjectExecutionEntries; i++ {
		extra := base
		extra.tuple = i + 100
		index, entered := g.enterCallerFieldQuery(extra, g.fieldQueries[0].fields)
		if !entered {
			t.Fatal("distinct typed context did not enter")
		}
		got, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
		if unknown || !maps.Equal(got, before) {
			t.Fatal("capacity fallback changed the original object answer")
		}
		g.leaveCallerFieldQuery(index)
	}
	c := g.objectExecutions
	entries, weight := len(c.answers), 0
	for _, answer := range c.answers {
		weight += 1 + len(answer.answer.objects)
	}
	traceEntries, traceWeight, _ := callerTraceAccount(t, c)
	entries += traceEntries
	weight += traceWeight
	for _, head := range c.scopes {
		for node := head; node != nil; node = node.next {
			entries++
			scope := node.snapshot
			weight += 1 + len(scope.queries) + len(scope.heads) + len(scope.containers) + len(scope.mutations)
			if cap(scope.queries) != len(scope.queries) {
				t.Fatal("scope retained unaccounted frame capacity")
			}
			for _, query := range scope.queries {
				weight += len(query.fields) + len(query.refs)
				if cap(query.fields) != len(query.fields) || cap(query.refs) != len(query.refs) {
					t.Fatal("scope retained unaccounted field/ref capacity")
				}
			}
		}
	}
	if entries != c.entries || weight != c.weight || entries > callerObjectExecutionEntries || weight > callerObjectExecutionValues || g.work.ObjectExecutionCapacityFallbacks == 0 || g.work.ObjectExecutionPeakEntries > callerObjectExecutionEntries || g.work.ObjectExecutionPeakValues > callerObjectExecutionValues {
		t.Fatalf("retention budget differs from all retained objects: entries=%d/%d weight=%d/%d", entries, c.entries, weight, c.weight)
	}
	extra := base
	extra.tuple = callerObjectExecutionEntries + 1000
	index, _ := g.enterCallerFieldQuery(extra, g.fieldQueries[0].fields)
	raw, marks := g.work.ObjectRawEvaluations, callerReuseMarks(g)
	got, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
	delta := callerReuseDelta(g, marks)
	marks = callerReuseMarks(g)
	want, u, _ := g.callerObjectsOwned(field, map[callerObjectSourceID]bool{})
	if g.work.ObjectRawEvaluations <= raw || unknown != u || !maps.Equal(got, want) || delta != callerReuseDelta(g, marks) || !maps.Equal(old, before) {
		t.Fatal("exhausted execution budget changed answer/effects or skipped the original traversal")
	}
	g.leaveCallerFieldQuery(index)
	hits := g.work.ObjectExecutionHits
	g.callerObjects(field, map[callerObjectSourceID]bool{})
	if g.work.ObjectExecutionHits != hits+1 {
		t.Fatal("capacity exhaustion invalidated an existing exact-context answer")
	}
	invalidations := g.work.ObjectExecutionInvalidations
	g.addCallerLive(callerVariable(base.pkg, base.expr), literals["Box"])
	callerPrimeObjectExecution(t, g, field)
	if g.work.ObjectExecutionInvalidations <= invalidations || c.entries >= entries || c.active != 0 || !maps.Equal(old, before) {
		t.Fatal("monotone binding/memo advance retained unreachable budget or damaged an escaped answer")
	}
}

func TestCallerIdentityObjectExecutionRejectsNestedBinding(t *testing.T) {
	p := callerSoundnessProgram(t, `func identity(arg *Box)*Box{return arg}`, `box:=&Box{reader:Benign{}};alias:=identity(box);_ = alias.reader`, `&Handler{}`)
	t.Cleanup(func() { callerGraphs.Delete(p) })
	g, refs := callerGraphFor(p, nil), callerOwnershipSources(p)
	g.lifetimeScanning = true
	var field valueSrc
	for node, body := range g.bodies {
		if body.sp != p.root || node.fn == nil || node.fn.Name() != "RPC" {
			continue
		}
		g.markCallerCalled(node)
		ast.Inspect(body.node, func(n ast.Node) bool {
			if selector, ok := n.(*ast.SelectorExpr); ok && selector.Sel.Name == "reader" {
				field = valueSrc{pkg: body.sp, fk: callerKey(node), expr: selector, tuple: -1}
			}
			return true
		})
	}
	if field.expr == nil {
		t.Fatal("missing typed nested binding query")
	}
	g.callerObjects(refs["box"], map[callerObjectSourceID]bool{})
	g.internObjectSource(field)
	epoch, queries := g.bindingEpoch, g.work.ObjectExecutionQueries
	before := g.callerObjectExecutionState()
	objects, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
	if unknown || len(objects) == 0 || g.bindingEpoch <= epoch || g.work.ObjectExecutionQueries <= queries || before == g.callerObjectExecutionState() || g.objectExecutions.active != 0 {
		t.Fatal("fixture did not exercise a real nested binding inside eligible initial expansion")
	}
	key := callerResolveKeyFor(field, true)
	for retained := range g.objectExecutions.answers {
		if retained.source == key && retained.state == before {
			t.Fatal("unstable before/after execution was retained in its old state")
		}
	}
	if len(g.live[callerVariable(p.root, refs["arg"].expr).Origin()]) == 0 {
		t.Fatal("nested identity call did not bind its actual argument")
	}
}

func TestCallerIdentityObjectExecutionSemanticOverflow(t *testing.T) {
	assertRefusal := func(t *testing.T, g *callerGraph, src valueSrc, marks [4]uint64, stores, hits int) {
		t.Helper()
		if !g.semanticOverflow || g.work.ObjectSemanticOverflows != 1 || callerReuseMarks(g) != marks || g.work.ObjectExecutionStores != stores || g.work.ObjectExecutionHits != hits {
			t.Fatal("semantic overflow wrapped, partially added, or published an execution")
		}
		if !g.callerLifetimeUnknown(src) || callerReuseMarks(g) != marks {
			t.Fatal("failed arithmetic became a completed lifetime proof")
		}
		report := CallerIdentityReport{}
		g.refuseCallerSemanticOverflow(&report)
		if report.Invalid == "" || report.Work.ObjectSemanticOverflows != 1 {
			t.Fatal("judge finalizer accepted semantic overflow")
		}
		report.Invalid = "prior failure"
		g.refuseCallerSemanticOverflow(&report)
		if report.Invalid != "prior failure" {
			t.Fatal("overflow finalizer replaced an existing failure")
		}
		g.resetCallerObjectExecutions()
		if !g.semanticOverflow {
			t.Fatal("RPC namespace reset erased run-wide arithmetic failure")
		}
		objects, unknown := g.callerObjects(src, map[callerObjectSourceID]bool{})
		if objects != nil || !unknown || callerReuseMarks(g) != marks {
			t.Fatal("later RPC work escaped sticky arithmetic refusal")
		}
		fresh := callerGraphFor(g.p, nil)
		if fresh.semanticOverflow {
			t.Fatal("a true new run inherited arithmetic failure")
		}
	}
	t.Run("replay_cut", func(t *testing.T) {
		g, field, _, _ := callerExecutionSnapshotFixture(t)
		callerPrimeObjectExecution(t, g, field)
		g.resolveCuts = ^uint64(0)
		marks, stores, hits := callerReuseMarks(g), g.work.ObjectExecutionStores, g.work.ObjectExecutionHits
		objects, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
		if objects != nil || !unknown {
			t.Fatal("overflowing replay returned cached provenance")
		}
		assertRefusal(t, g, field, marks, stores, hits)
	})
	t.Run("replay_cycle", func(t *testing.T) {
		p := callerSoundnessProgram(t, "", `var hollow *Box;hollow=hollow;_=hollow`, `&Handler{}`)
		t.Cleanup(func() { callerGraphs.Delete(p) })
		g, refs := callerGraphFor(p, nil), callerOwnershipSources(p)
		g.lifetimeScanning = true
		callerPrimeObjectExecution(t, g, refs["hollow"])
		g.objectCuts = ^uint64(0)
		marks, stores, hits := callerReuseMarks(g), g.work.ObjectExecutionStores, g.work.ObjectExecutionHits
		objects, unknown := g.callerObjects(refs["hollow"], map[callerObjectSourceID]bool{})
		if objects != nil || !unknown {
			t.Fatal("overflow removed hollow-cycle UNKNOWN")
		}
		assertRefusal(t, g, refs["hollow"], marks, stores, hits)
	})
	t.Run("raw_after_replay", func(t *testing.T) {
		g, field, base, _ := callerExecutionSnapshotFixture(t)
		want := maps.Clone(callerPrimeObjectExecution(t, g, field))
		before := callerReuseMarks(g)
		g.callerObjects(field, map[callerObjectSourceID]bool{})
		effects := callerReuseDelta(g, before)
		if effects[0] == 0 {
			t.Fatal("typed execution did not produce real cut effects")
		}
		g.resolveCuts = ^uint64(0) - effects[0]
		hits := g.work.ObjectExecutionHits
		objects, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
		if unknown || !maps.Equal(objects, want) || g.semanticOverflow || g.resolveCuts != ^uint64(0) || g.work.ObjectExecutionHits != hits+1 {
			t.Fatal("representable near-limit replay changed the lawful answer")
		}
		marks, stores := callerReuseMarks(g), g.work.ObjectExecutionStores
		hits = g.work.ObjectExecutionHits
		objects, unknown, _ = g.callerObjectsOwned(base, map[callerObjectSourceID]bool{})
		if objects != nil || !unknown {
			t.Fatal("ordinary initial boundary increment wrapped after successful replay")
		}
		assertRefusal(t, g, base, marks, stores, hits)
	})
	t.Run("completion_credit", func(t *testing.T) {
		g, _, base, _ := callerExecutionSnapshotFixture(t)
		g.lifetimeScanning = false
		for i := 0; i < 2; i++ {
			if g.callerLifetimeUnknown(base) {
				t.Fatal("lawful typed base did not complete its lifetime barrier")
			}
		}
		before := callerReuseMarks(g)
		if g.callerLifetimeUnknown(base) || callerReuseDelta(g, before)[2] == 0 {
			t.Fatal("completion overflow fixture did not exercise real positive credit")
		}
		// Только арифметическая отметка помещается у границы; граф, результат
		// и путь начисления кредита остаются теми же, что у положительного двойника.
		g.completedInitialSkips = ^uint64(0)
		stores, hits := g.work.ObjectExecutionStores, g.work.ObjectExecutionHits
		if !g.callerLifetimeUnknown(base) || !g.semanticOverflow || g.completedInitialSkips != ^uint64(0) {
			t.Fatal("completion credit wrapped or became a positive proof")
		}
		assertRefusal(t, g, base, callerReuseMarks(g), stores, hits)
	})
}

// Контрольная точка исполняется внутри настоящего обхода, не отменяя контекст.
type callerExecutionResetContext struct {
	context.Context
	checkpoint func()
}

func (c *callerExecutionResetContext) Err() error {
	c.checkpoint()
	return c.Context.Err()
}

func TestCallerIdentityObjectExecutionRepeatedActiveReset(t *testing.T) {
	g, field, _, _ := callerExecutionSnapshotFixture(t)
	oldAnswer := callerPrimeObjectExecution(t, g, field)
	oldCopy := maps.Clone(oldAnswer)
	old := g.objectExecutions
	if old.active != 0 || old.entries == 0 || old.weight == 0 || len(old.answers) == 0 {
		t.Fatal("typed warmup did not retain a real idle execution store")
	}
	// Новый UNKNOWN сохраняет реальные refs, но требует другого exact context.
	// Эталон проходит исходный owned body; готовый summary не подставляется.
	g.fieldQueries[0].unknown = true
	marks := callerReuseMarks(g)
	want, wantUnknown, _ := g.callerObjectsOwned(field, map[callerObjectSourceID]bool{})
	want = maps.Clone(want)
	effects := callerReuseDelta(g, marks)
	if !wantUnknown || len(want) == 0 || effects[0] <= effects[1] || effects[2] != 0 {
		t.Fatal("reference did not exercise the changed typed snapshot with an uncovered cut")
	}
	hits, stores, raw := g.work.ObjectExecutionHits, g.work.ObjectExecutionStores, g.work.ObjectRawEvaluations
	queries := g.work.ObjectExecutionQueries
	// Lifecycle проверяется через настоящий acquire; opaque Err больше не
	// допускается к replay и не создаёт дополнительных scope checkpoints.
	pinned := old.scope(g)
	if pinned == nil || old.active != 1 {
		t.Fatal("real scope acquisition did not create its single ticket")
	}
	marks = callerReuseMarks(g)
	triggered := false
	entries, weight, nestedRaw := 0, 0, 0
	g.ctx = &callerExecutionResetContext{Context: context.Background(), checkpoint: func() {
		if triggered || old.active == 0 {
			return
		}
		triggered = true
		if g.objectExecutions != old || old.graph != g || old.active != 1 {
			t.Fatal("checkpoint was not reached inside the real outer execution ticket")
		}
		entries, weight = old.entries, old.weight
		objectGeneration, resolveGeneration := g.objectMemoGeneration, g.resolveMemoGeneration
		for i := 0; i < 2; i++ {
			g.resetCallerObjectExecutions()
			if g.objectExecutions != old || old.graph != nil || old.active != 1 || old.entries != entries || old.weight != weight || g.objectMemoGeneration != objectGeneration+uint64(i+1) || g.resolveMemoGeneration != resolveGeneration+uint64(i+1) {
				t.Fatal("active reset lost the single store/account, reenabled reuse, or skipped generations")
			}
		}
		nestedMarks, nestedStart := callerReuseMarks(g), g.work.ObjectRawEvaluations
		objects, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
		nestedRaw = g.work.ObjectRawEvaluations - nestedStart
		if unknown != wantUnknown || !maps.Equal(objects, want) || callerReuseDelta(g, nestedMarks) != effects || nestedRaw == 0 || g.objectExecutions != old || old.active != 1 || old.entries != entries || old.weight != weight || g.work.ObjectExecutionHits != hits || g.work.ObjectExecutionStores != stores {
			t.Fatal("disabled active namespace escaped full fallback or allocated a second budget")
		}
	}}
	got, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
	old.releaseTicket(g, pinned)
	g.ctx = nil
	delta := callerReuseDelta(g, marks)
	for i := range delta {
		if delta[i] != 2*effects[i] {
			t.Fatal("outer and nested fallback changed semantic effects or manufactured credit")
		}
	}
	if !triggered || unknown != wantUnknown || !maps.Equal(got, want) || !maps.Equal(oldAnswer, oldCopy) || g.work.ObjectExecutionQueries != queries || g.work.ObjectRawEvaluations-raw <= nestedRaw || g.work.ObjectExecutionHits != hits || g.work.ObjectExecutionStores != stores || g.objectExecutions != old || old.graph != nil || old.active != 0 || old.entries != entries || old.weight != weight {
		t.Fatal("real invalidated ticket did not drain without publication and with its original answer/account")
	}
	// После drain запрет сохраняется до штатного idle reset, который теперь
	// может заменить единственный store новым пустым ограниченным namespace.
	marks = callerReuseMarks(g)
	got, unknown = g.callerObjects(field, map[callerObjectSourceID]bool{})
	if unknown != wantUnknown || !maps.Equal(got, want) || callerReuseDelta(g, marks) != effects || g.work.ObjectExecutionHits != hits || g.work.ObjectExecutionStores != stores || g.objectExecutions != old {
		t.Fatal("drained disabled namespace resumed reuse before an idle reset")
	}
	g.resetCallerObjectExecutions()
	fresh := g.objectExecutions
	if fresh == old || fresh.graph != g || fresh.active != 0 || fresh.entries != 0 || fresh.weight != 0 || len(fresh.answers) != 0 || len(fresh.scopes) != 0 {
		t.Fatal("idle reset did not create a fresh empty namespace after all tickets returned")
	}
	callerPrimeObjectExecution(t, g, field)
	if fresh.entries > callerObjectExecutionEntries || fresh.weight > callerObjectExecutionValues || fresh.active != 0 || !maps.Equal(oldAnswer, oldCopy) {
		t.Fatal("fresh namespace exceeded its budget or changed an escaped immutable answer")
	}
}
