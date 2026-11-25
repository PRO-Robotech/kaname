// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"go/types"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func callerContainerReuseSnapshot(t *testing.T) (*callerGraph, valueSrc, valueSrc, map[string]valueSrc) {
	t.Helper()
	g, field, base, literals := callerEffectCertificateSnapshotFixture(t)
	g.lifetimeScanning = true
	selector := field.expr.(*ast.SelectorExpr)
	index, entered := g.enterCallerFieldQuery(base, fieldPath(field.pkg.info.Selections[selector]))
	if !entered {
		t.Fatal("snapshot owner was already active")
	}
	g.fieldQueries[index].refs = []valueSrc{literals["Benign"]}
	t.Cleanup(func() { g.leaveCallerFieldQuery(index) })
	return g, field, base, literals
}

func callerPrimeContainerReuse(t *testing.T, g *callerGraph, src valueSrc) (*callerContainerObjectReuse, map[callerObjectKey]bool) {
	t.Helper()
	reuse := &callerContainerObjectReuse{}
	first, unknown := reuse.objects(g, src)
	before := maps.Clone(first)
	second, otherUnknown := reuse.objects(g, src)
	if unknown != otherUnknown || !maps.Equal(second, before) || !maps.Equal(first, before) || !reuse.ready {
		t.Fatal("two stable initial traversals did not establish an exact reusable cut answer")
	}
	return reuse, second
}

func callerReuseMarks(g *callerGraph) [4]uint64 {
	return [4]uint64{g.resolveCuts, g.initialSkips, g.completedInitialSkips, g.objectCuts}
}

func callerReuseDelta(g *callerGraph, before [4]uint64) [4]uint64 {
	after := callerReuseMarks(g)
	for i := range after {
		after[i] -= before[i]
	}
	return after
}

func TestCallerIdentityContainerEffectReuseSnapshotAndActualWork(t *testing.T) {
	g, field, base, literals := callerContainerReuseSnapshot(t)
	reuse, old := callerPrimeContainerReuse(t, g, field)
	want := callerEffectCertificateObjects(t, field, base, literals, "Benign")
	work, marks := g.work, callerReuseMarks(g)
	got, unknown := reuse.objects(g, field)
	delta := callerReuseDelta(g, marks)
	if unknown || !maps.Equal(got, want) || !maps.Equal(old, want) || g.work != work {
		t.Fatal("reuse changed aliases or manufactured work for an unperformed traversal")
	}
	marks = callerReuseMarks(g)
	recomputed, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
	if unknown || !maps.Equal(recomputed, want) || callerReuseDelta(g, marks) != delta || delta[0] <= delta[1] || delta[2] != 0 {
		t.Fatal("semantic certificate differs from the same-state original traversal")
	}
	if _, published := g.initialObjectMemo[g.internObjectSource(field)]; published {
		t.Fatal("local cut reuse published completed initial provenance")
	}
}

func TestCallerIdentityContainerEffectReuseSnapshotInvalidation(t *testing.T) {
	g, field, base, literals := callerContainerReuseSnapshot(t)
	reuse, old := callerPrimeContainerReuse(t, g, field)
	before, epoch, queries := maps.Clone(old), g.bindingEpoch, g.work.ObjectQueries
	// Длина, исходный массив и epoch прежние: проверяется именно содержимое снимка.
	g.fieldQueries[0].refs[0] = literals["Concrete"]
	got, unknown := reuse.objects(g, field)
	if unknown || !maps.Equal(got, callerEffectCertificateObjects(t, field, base, literals, "Concrete")) || g.work.ObjectQueries == queries {
		t.Fatal("in-place same-epoch snapshot update used the previous answer")
	}
	reuse, _ = callerPrimeContainerReuse(t, g, field)
	queries = g.work.ObjectQueries
	g.fieldQueries[0].unknown = true
	changed, unknown := reuse.objects(g, field)
	if !unknown || !maps.Equal(changed, got) || g.work.ObjectQueries == queries || g.bindingEpoch != epoch || !maps.Equal(old, before) {
		t.Fatal("snapshot UNKNOWN was lost or an escaped old map was modified")
	}
}

func TestCallerIdentityContainerEffectReuseExactSourceAndState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*callerGraph, *valueSrc, valueSrc, map[string]valueSrc)
	}{
		{"tuple", func(_ *callerGraph, src *valueSrc, _ valueSrc, _ map[string]valueSrc) { src.tuple = 0 }},
		{"element", func(_ *callerGraph, src *valueSrc, _ valueSrc, _ map[string]valueSrc) { src.elem = true }},
		{"range_key", func(_ *callerGraph, src *valueSrc, _ valueSrc, _ map[string]valueSrc) { src.rangeKey = true }},
		{"range_value", func(_ *callerGraph, src *valueSrc, _ valueSrc, _ map[string]valueSrc) { src.rangeVal = true }},
		{"assignment", func(_ *callerGraph, src *valueSrc, _ valueSrc, _ map[string]valueSrc) { src.opAssign = true }},
		{"function", func(_ *callerGraph, src *valueSrc, _ valueSrc, _ map[string]valueSrc) { src.fk.lit = &ast.FuncLit{} }},
		{"package", func(_ *callerGraph, src *valueSrc, _ valueSrc, _ map[string]valueSrc) {
			pkg := *src.pkg
			src.pkg = &pkg
		}},
		{"binding", func(g *callerGraph, _ *valueSrc, base valueSrc, literals map[string]valueSrc) {
			g.addCallerLive(callerVariable(base.pkg, base.expr), literals["Box"])
		}},
		{"effect_epoch", func(g *callerGraph, _ *valueSrc, _ valueSrc, _ map[string]valueSrc) { g.effectEpoch++ }},
		{"effect_incomplete", func(g *callerGraph, _ *valueSrc, _ valueSrc, _ map[string]valueSrc) { g.effectIncomplete = true }},
		{"effect_scanning", func(g *callerGraph, _ *valueSrc, _ valueSrc, _ map[string]valueSrc) { g.effectScanning = true }},
		{"field_path", func(g *callerGraph, _ *valueSrc, _ valueSrc, _ map[string]valueSrc) {
			g.fieldQueries[0].fields[0] = g.p.root.types.Scope().Lookup("Handler").Type().Underlying().(*types.Struct).Field(0)
		}},
		{"container_guard", func(g *callerGraph, src *valueSrc, _ valueSrc, _ map[string]valueSrc) {
			g.containerScanning = map[callerResolveKey]bool{callerResolveKeyFor(*src, true): true}
		}},
		{"mutation_guard", func(g *callerGraph, _ *valueSrc, base valueSrc, _ map[string]valueSrc) {
			g.mutationScanning = map[callerFieldKey]bool{{callerResolveKeyFor(base, true), g.fieldQueries[0].fields[0]}: true}
		}},
		{"resolve_capacity", func(g *callerGraph, _ *valueSrc, _ valueSrc, _ map[string]valueSrc) { g.resolveEntryCap = 1 }},
		{"source_identity", func(g *callerGraph, _ *valueSrc, _ valueSrc, _ map[string]valueSrc) {
			g.internObjectSource(valueSrc{tuple: 12345})
		}},
		{"memo_warming", func(g *callerGraph, _ *valueSrc, _ valueSrc, literals map[string]valueSrc) {
			g.callerObjects(literals["Concrete"], map[callerObjectSourceID]bool{})
		}},
		{"memo_reset", func(g *callerGraph, _ *valueSrc, _ valueSrc, _ map[string]valueSrc) { g.objectMemo = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, field, base, literals := callerContainerReuseSnapshot(t)
			reuse, old := callerPrimeContainerReuse(t, g, field)
			before := maps.Clone(old)
			tc.change(g, &field, base, literals)
			queries := g.work.ObjectQueries
			got, unknown := reuse.objects(g, field)
			if g.work.ObjectQueries == queries {
				t.Fatal("changed dependency reused a previous traversal")
			}
			expected, expectedUnknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
			if unknown != expectedUnknown || !maps.Equal(got, expected) || !maps.Equal(old, before) {
				t.Fatal("invalidation changed the original answer or old borrowed map")
			}
		})
	}
}

func TestCallerIdentityContainerEffectReuseCycleEvents(t *testing.T) {
	p := callerSoundnessProgram(t, "", `anchor:=&Box{};var cycle *Box;cycle=anchor;cycle=cycle;var hollow *Box;hollow=hollow;_=cycle;_=hollow`, `&Handler{}`)
	for _, name := range []string{"cycle", "hollow"} {
		g, refs := newCallerGraph(p), callerOwnershipSources(p)
		g.lifetimeScanning = true
		reuse, before := callerPrimeContainerReuse(t, g, refs[name])
		work, marks := g.work, callerReuseMarks(g)
		got, unknown := reuse.objects(g, refs[name])
		delta := callerReuseDelta(g, marks)
		if unknown != (name == "hollow") || !maps.Equal(got, before) || g.work != work || delta[3] == 0 || delta[2] != 0 {
			t.Fatal("object-cycle event or unanchored UNKNOWN disappeared on reuse")
		}
		marks = callerReuseMarks(g)
		actual, actualUnknown := g.callerObjects(refs[name], map[callerObjectSourceID]bool{})
		if actualUnknown != unknown || !maps.Equal(actual, got) || callerReuseDelta(g, marks) != delta {
			t.Fatal("replayed cycle effects differ from actual recomputation")
		}
	}
}

func TestCallerIdentityContainerEffectReuseCancellationAndCapacity(t *testing.T) {
	for _, mode := range []string{"cancel", "entries", "weight"} {
		t.Run(mode, func(t *testing.T) {
			g, field, _, _ := callerContainerReuseSnapshot(t)
			reuse, old := callerPrimeContainerReuse(t, g, field)
			before, retained := maps.Clone(old), g.work.ObjectRetained
			switch mode {
			case "cancel":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				g.ctx = ctx
			case "entries":
				for i := len(g.objectMemo) + len(g.initialObjectMemo); i < 4096; i++ {
					g.objectMemo[g.internObjectSource(valueSrc{tuple: 10000 + i})] = callerObjectAnswer{unknown: true}
				}
			case "weight":
				g.objectMemoWeight = callerLifetimeStepLimit
			}
			queries := g.work.ObjectQueries
			got, unknown := reuse.objects(g, field)
			if reuse.ready || !maps.Equal(old, before) || g.work.ObjectRetained != retained {
				t.Fatal("cancelled or capacity-rejected query retained a certificate or changed an old answer")
			}
			if mode == "cancel" {
				if got != nil || !unknown {
					t.Fatal("cancelled reuse supplied an answer")
				}
			} else if unknown || !maps.Equal(got, before) || g.work.ObjectQueries == queries {
				t.Fatal("capacity fallback changed or truncated the recomputed answer")
			} else {
				owned, u, writable := g.callerObjectsOwned(field, map[callerObjectSourceID]bool{})
				if u || !writable || !maps.Equal(owned, before) {
					t.Fatal("capacity fallback lost the independent caller-owned raw answer")
				}
				clear(owned)
				if !maps.Equal(old, before) || !maps.Equal(got, before) {
					t.Fatal("mutating a caller-owned result modified local or global borrowed provenance")
				}
			}
		})
	}
}

func TestCallerIdentityContainerEffectReuseDoesNotCompleteLifetime(t *testing.T) {
	for _, effect := range []string{"", "source.Mutate(box);"} {
		g, field, base := callerLifetimeCompletionFixture(t, `box:=&Box{reader:Benign{}};`+effect+`_=box.reader`)
		selector := field.expr.(*ast.SelectorExpr)
		fields := fieldPath(field.pkg.info.Selections[selector])
		g.lifetimeScanning = true
		owner, entered := g.enterCallerFieldQuery(base, fields)
		if !entered {
			t.Fatal("missing initial snapshot owner")
		}
		g.fieldQueries[owner].refs, _ = g.embeddedCallerSourcesRaw(base, fields, map[callerFieldKey]bool{})
		reuse, old := callerPrimeContainerReuse(t, g, field)
		marks := callerReuseMarks(g)
		reuse.objects(g, field)
		if delta := callerReuseDelta(g, marks); delta[0] <= delta[1] || delta[2] != 0 {
			t.Fatal("initial snapshot reuse discharged an uncovered lifetime obligation")
		}
		g.leaveCallerFieldQuery(owner)
		g.lifetimeScanning = false
		got, unknown := reuse.objects(g, field)
		if unknown != (effect != "") || !maps.Equal(got, old) || reuse.ready {
			t.Fatal("initial reuse bypassed the later full lifetime barrier")
		}
		if effect != "" {
			if _, retained := g.objectMemo[g.internObjectSource(field)]; retained {
				t.Fatal("opaque full-lifetime answer was published after initial reuse")
			}
		}
	}
}

func callerRepeatedContainerOwners(t *testing.T) (*callerGraph, valueSrc, valueSrc, []valueSrc) {
	t.Helper()
	p := callerSoundnessProgram(t, `type Holder struct{items []Box}`, `holder:=&Holder{};other:=[]Box{};_=append(holder.items,Box{},Box{},Box{},Box{});_=other`, `&Handler{}`)
	g := newCallerGraph(p)
	var owner valueSrc
	var expected []valueSrc
	for node, body := range g.bodies {
		if body.sp != p.root || node.fn == nil || node.fn.Name() != "RPC" {
			continue
		}
		g.markCallerCalled(node)
		ast.Inspect(body.node, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			builtin, ok := body.sp.info.Uses[id].(*types.Builtin)
			if !ok || builtin.Name() != "append" {
				return true
			}
			if owner.expr != nil || len(call.Args) != 5 {
				t.Fatal("fixture needs one typed append with four values")
			}
			owner = valueSrc{pkg: body.sp, fk: callerKey(node), expr: call.Args[0], tuple: -1}
			for _, value := range call.Args[1:] {
				ref := owner
				ref.expr = value
				expected = append(expected, ref)
			}
			return true
		})
	}
	if len(expected) != 4 {
		t.Fatal("fixture is missing the typed RPC append")
	}
	// Общие помощники фикстуры добавляют неактивные записи через указатели.
	// Сохраняем полный граф и сверяем активные записи RPC с типизированным append.
	var active []valueSrc
	for _, write := range g.lifetimeWrites {
		if !g.callerLifetimeEffectPossible(write.owner) {
			continue
		}
		if write.whole || write.owner != owner {
			t.Fatal("active append writes lost their exact common owner")
		}
		active = append(active, write.value)
	}
	if !slices.Equal(active, expected) {
		t.Fatal("typed append did not produce exactly its four active writes in order")
	}
	selector := owner.expr.(*ast.SelectorExpr)
	base := owner
	base.expr = selector.X
	g.lifetimeScanning = true
	index, entered := g.enterCallerFieldQuery(base, fieldPath(owner.pkg.info.Selections[selector]))
	if !entered {
		t.Fatal("missing append-owner snapshot")
	}
	t.Cleanup(func() { g.leaveCallerFieldQuery(index) })
	return g, owner, callerOwnershipSources(p)["other"], expected
}

func TestCallerIdentityContainerEffectReuseRealRepeatedOwners(t *testing.T) {
	for _, matched := range []bool{false, true} {
		g, owner, other, expected := callerRepeatedContainerOwners(t)
		g.callerObjects(owner, map[callerObjectSourceID]bool{})
		g.callerObjects(other, map[callerObjectSourceID]bool{})
		queries, marks := g.work.ObjectQueries, callerReuseMarks(g)
		g.callerObjects(owner, map[callerObjectSourceID]bool{})
		cost, effects := g.work.ObjectQueries-queries, callerReuseDelta(g, marks)
		if cost <= 1 || effects[0] <= effects[1] || effects[2] != 0 {
			t.Fatal("fixture has no repeated incomplete owner traversal")
		}
		query := other
		if matched {
			query = owner
		}
		queries, marks = g.work.ObjectQueries, callerReuseMarks(g)
		refs, unknown := g.callerContainerSources(query, nil, map[callerFieldKey]bool{})
		delta := callerReuseDelta(g, marks)
		if unknown {
			t.Fatal("container repetition introduced UNKNOWN")
		}
		if matched {
			if !slices.Equal(refs, expected) || g.work.ObjectQueries-queries != 5*cost {
				t.Fatal("matched value traversal did not discard the local reuse scope")
			}
		} else if len(refs) != 0 || g.work.ObjectQueries-queries != 1+2*cost || delta[0] != 1+4*effects[0] || delta[1] != 1+4*effects[1] || delta[2] != 0 || delta[3] != 4*effects[3] {
			t.Fatal("four unmatched writes did not preserve effects while executing only two owner traversals")
		}
	}
}

func TestCallerIdentityLifetimeObjectWritesReusesAdjacentOwners(t *testing.T) {
	for _, opaque := range []bool{false, true} {
		g, owner, other, _ := callerRepeatedContainerOwners(t)
		object := callerOwnershipZero(other)
		objects, unknown := g.callerObjects(other, map[callerObjectSourceID]bool{})
		if unknown || !objects[object] {
			t.Fatalf("fixture lost the separate variable allocation, unknown=%v, object count=%d", unknown, len(objects))
		}
		g.callerObjects(owner, map[callerObjectSourceID]bool{})
		if opaque {
			g.ctx = &callerTraceOpaqueContext{Context: context.Background()}
		}
		queries, marks := g.work.ObjectQueries, callerReuseMarks(g)
		owners, unknown := g.callerObjects(owner, map[callerObjectSourceID]bool{})
		cost, effects := g.work.ObjectQueries-queries, callerReuseDelta(g, marks)
		if unknown || owners[object] || cost <= 1 || effects[0] <= effects[1] || effects[2] != 0 {
			t.Fatal("fixture needs an incomplete owner traversal known to be disjoint")
		}

		queries, marks = g.work.ObjectQueries, callerReuseMarks(g)
		probe := callerLifetimeProbe{g: g, seen: map[callerResolveKey]bool{}, objects: map[callerObjectKey]bool{}}
		if probe.objectWrites(object) || probe.steps != 0 {
			t.Fatal("disjoint writes changed the proof or inspected values")
		}
		wantQueries := 2 * cost
		if opaque {
			wantQueries = 4 * cost
		}
		for i := range effects {
			effects[i] *= 4
		}
		if got := g.work.ObjectQueries - queries; got != wantQueries || callerReuseDelta(g, marks) != effects {
			t.Fatalf("opaque=%v: owner queries=%d, want %d; semantic marks=%v, want %v", opaque, got, wantQueries, callerReuseDelta(g, marks), effects)
		}
	}
}

func TestCallerIdentityContainerEffectReuseDeclarationAndEscapeTwins(t *testing.T) {
	const producer = "github.com/PRO-Robotech/corelib/operations.PrincipalFromContext"
	base := []CallerReadDeclaration{{RPC: "fixture/service/FixtureService/RPC", Producer: producer, Site: "fixture/app.anchor", Kind: CallerObservation, Reason: "Nonempty fixture anchor."}}
	for _, effect := range []string{"", "source.Mutate(boxes);"} {
		p := callerSoundnessProgram(t, "", `boxes:=[]Box{{reader:Concrete{}}};other:=[]Box{};owner:=other;owner=owner;_=append(owner,Box{},Box{},Box{},Box{});`+effect+`boxes[0].reader.read()`, `&Handler{}`)
		negative := judgeCallerIdentity(p, base, map[string]bool{"fixture/source": true})
		declared := append(slices.Clone(base), CallerReadDeclaration{RPC: base[0].RPC, Producer: producer, Site: "(fixture/app.Concrete).read", Kind: CallerObservation, Reason: "Same read, declared."})
		lawful := judgeCallerIdentity(p, declared, map[string]bool{"fixture/source": true})
		if negative.Invalid != "" || lawful.Invalid != "" || negative.RPCs != 1 || len(negative.Reads) < 2 || !reflect.DeepEqual(negative.Reads, lawful.Reads) {
			t.Fatal("container reuse changed or failed to inspect real reads")
		}
		undeclared, unresolved := false, false
		for _, finding := range negative.Findings {
			undeclared = undeclared || strings.Contains(finding, "чтение личности без объявления")
		}
		for _, finding := range lawful.Findings {
			if strings.Contains(finding, "чтение личности без объявления") {
				t.Fatal("lawful declaration did not discharge its read")
			}
			unresolved = unresolved || strings.Contains(finding, "неразрешённый вызов")
		}
		if !undeclared || effect == "" && len(lawful.Findings) != 0 || effect != "" && !unresolved {
			t.Fatal("reuse weakened undeclared-read or opaque-escape findings")
		}
	}
}

func TestCallerIdentityContainerEffectReuseCannotSpendLifetimeProofBudget(t *testing.T) {
	g, field, base := callerLifetimeCompletionFixture(t, `box:=&Box{reader:Benign{}};other:=&Box{};source.Mutate(other);_=box.reader`)
	var site callSrc
	for _, candidate := range g.lifetimeCalls {
		if fn := callerFunction(candidate.pkg, candidate.call.Fun); fn != nil && fn.Name() == "Mutate" {
			site = candidate
		}
	}
	if site.call == nil {
		t.Fatal("missing typed disjoint opaque effect")
	}
	// Настоящие вызовы contains исчерпывают прежний лимит отдельного доказательства;
	// счётчик и лимит не подменяются. Сертификат не вправе расходовать этот бюджет.
	g.lifetimeCalls = nil
	for i := 0; i <= callerLifetimeStepLimit; i++ {
		g.lifetimeCalls = append(g.lifetimeCalls, site)
	}
	selector := field.expr.(*ast.SelectorExpr)
	fields := fieldPath(field.pkg.info.Selections[selector])
	owner, entered := g.enterCallerFieldQuery(base, fields)
	if !entered {
		t.Fatal("missing snapshot owner")
	}
	g.lifetimeScanning = true
	g.fieldQueries[owner].refs, _ = g.embeddedCallerSourcesRaw(base, fields, map[callerFieldKey]bool{})
	reuse, _ := callerPrimeContainerReuse(t, g, field)
	steps, marks := g.work.LifetimeProbeSteps, callerReuseMarks(g)
	reuse.objects(g, field)
	if g.work.LifetimeProbeSteps != steps || callerReuseDelta(g, marks)[2] != 0 {
		t.Fatal("initial reuse consumed proof steps or credited initial obligations")
	}
	g.leaveCallerFieldQuery(owner)
	g.lifetimeScanning = false
	marks = callerReuseMarks(g)
	if !g.callerLifetimeUnknown(base) || g.work.LifetimeProbeSteps-steps <= callerLifetimeStepLimit || callerReuseDelta(g, marks)[2] != 0 {
		t.Fatal("initial certificate bypassed the actual full proof budget or credited its early return")
	}
}

func TestCallerIdentityContainerEffectReuseCannotCrossGraphs(t *testing.T) {
	g, field, base, literals := callerContainerReuseSnapshot(t)
	reuse, old := callerPrimeContainerReuse(t, g, field)
	before, work := maps.Clone(old), g.work
	other := newCallerGraph(g.p)
	other.safeExternal, other.lifetimeScanning = g.safeExternal, true
	other.markCallerCalled(callerNode{fn: field.fk.fn, lit: field.fk.lit})
	selector := field.expr.(*ast.SelectorExpr)
	owner, entered := other.enterCallerFieldQuery(base, fieldPath(field.pkg.info.Selections[selector]))
	if !entered {
		t.Fatal("independent graph inherited an active query")
	}
	defer other.leaveCallerFieldQuery(owner)
	other.fieldQueries[owner].refs = []valueSrc{literals["Concrete"]}
	got, unknown := reuse.objects(other, field)
	if unknown || !maps.Equal(got, callerEffectCertificateObjects(t, field, base, literals, "Concrete")) || other.work.ObjectQueries == 0 || g.work != work || !maps.Equal(old, before) {
		t.Fatal("independent graph reused or changed another solve's answer")
	}
}
