// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"maps"
	"testing"
)

// Порядок присваиваний задаёт две зависимые ветви и затем независимый цикл.
// Общий ребёнок прогревается настоящим обходом selector и self-append.
func TestCallerIdentityScopeProofFrontierTypedComposition(t *testing.T) {
	p := callerTraceTypedProgram(t, "holder:=&Holder{items:[]Box{}};field:=holder.items;field=append(field,Box{});field=append(field,Box{});shared:=field;cycle:=[]Box{};cycle=append(cycle,Box{});cycle=append(cycle,Box{});left:=shared;later:=shared;later=cycle;mixed:=left;mixed=later;top:=mixed;_=top;")
	type fixture struct {
		callerTransparentFixture
		left, later, transparent valueSrc
	}
	makeGraph := func() fixture {
		g, _, refs := callerTraceTypedGraph(t, p, "top")
		g.ctx = context.Background()
		sources := func(name string, expected ...string) []valueSrc {
			t.Helper()
			definition := refs[name]
			if definition.expr == nil {
				t.Fatalf("typed definition missing: %s", name)
			}
			values := g.sources(callerVariable(definition.pkg, definition.expr))
			if len(values) != len(expected) {
				t.Fatalf("ordered sources for %s: got %d want %d", name, len(values), len(expected))
			}
			for i, value := range values {
				id, ok := value.expr.(*ast.Ident)
				if !ok || id.Name != expected[i] || callerVariable(value.pkg, value.expr) != callerVariable(refs[expected[i]].pkg, refs[expected[i]].expr) {
					t.Fatalf("ordered typed RHS %s[%d] is not %s", name, i, expected[i])
				}
			}
			return values
		}
		target := sources("top", "mixed")[0]
		child := sources("shared", "field")[0]
		branches := sources("mixed", "left", "later")
		later := sources("later", "shared", "cycle")
		sources("left", "shared")
		if len(g.fieldQueries) != 1 || g.fieldQueries[0].unknown || len(g.fieldQueries[0].refs) != 1 || !g.callerExecutionScopeTracked() {
			t.Fatal("real active typed field frame is missing")
		}
		return fixture{callerTransparentFixture: callerTransparentFixture{g: g, target: target, child: child, anchor: refs["top"]}, left: branches[0], later: branches[1], transparent: later[1]}
	}
	a, b := makeGraph(), makeGraph()
	callerTransparentPrime(t, a.callerTransparentFixture, b.callerTransparentFixture, a.child)
	children := callerTransparentRecords(t, a.callerTransparentFixture, a.child, false)
	if len(children) == 0 || len(callerTransparentRecords(t, a.callerTransparentFixture, a.child, true)) != 0 {
		t.Fatal("actual field-dependent child did not retain an unproven certificate")
	}
	escaped, saved := children[0].objects, maps.Clone(children[0].objects)
	probe := callerTransparentRun(t, a.callerTransparentFixture, a.child, false)
	original := callerTransparentRun(t, b.callerTransparentFixture, b.child, true)
	callerTransparentEqual(t, probe, original)
	if probe.raw != 0 || probe.hits != 1 || original.raw <= 0 || len(probe.objects) == 0 || probe.marks[1] == 0 || probe.marks[3] == 0 || probe.marks[2] != 0 {
		t.Fatal("unproven child hit lacks real field/cycle/original-work evidence")
	}
	for _, src := range []valueSrc{a.target, a.left, a.later, a.transparent} {
		if len(callerTransparentRecords(t, a.callerTransparentFixture, src, false))+len(callerTransparentRecords(t, a.callerTransparentFixture, src, true)) != 0 {
			t.Fatal("parent/branch cache makes the live-frontier witness vacuous")
		}
	}
	state := a.g.callerObjectExecutionState()
	evictions, capacity := a.g.work.ObjectTraceEvictions, a.g.work.ObjectTraceCapacityFallbacks
	got := callerTransparentRun(t, a.callerTransparentFixture, a.target, false)
	want := callerTransparentRun(t, b.callerTransparentFixture, b.target, true)
	callerTransparentEqual(t, got, want)
	if got.hits < 2 || got.raw <= 0 || got.raw >= want.raw || len(got.objects) < 2 || got.marks[1] == 0 || got.marks[3] == 0 || got.marks[2] != 0 {
		t.Fatal("ordered composition did not execute real child hits and both concrete branches")
	}
	concrete := 0
	for object := range got.objects {
		if object.expr != nil {
			concrete++
		}
	}
	if concrete < 2 {
		t.Fatal("both branches lost their concrete object provenance")
	}
	if a.g.callerObjectExecutionState() != state || a.g.work.ObjectTraceEvictions != evictions || a.g.work.ObjectTraceCapacityFallbacks != capacity {
		t.Fatal("state change or pressure invalidated the frontier witness")
	}
	// Первая ветвь снимает доказательство у mixed. Позже создаваемая later
	// начинает с true, но тот же exact hit обязан снять и её доказательство.
	for _, src := range []valueSrc{a.target, a.left, a.later} {
		if len(callerTransparentRecords(t, a.callerTransparentFixture, src, false)) == 0 || len(callerTransparentRecords(t, a.callerTransparentFixture, src, true)) != 0 {
			t.Fatal("field-dependent branch retained a false scope-independent proof")
		}
	}
	// Независимый ребёнок создаётся под false-предками; их состояние не должно
	// переноситься вниз. Его собственный self-append остаётся доказанным.
	if len(callerTransparentRecords(t, a.callerTransparentFixture, a.transparent, true)) == 0 || len(callerTransparentRecords(t, a.callerTransparentFixture, a.transparent, false)) != 0 {
		t.Fatal("transparent descendant lost its own proof below the false frontier")
	}
	transparent := callerTransparentRun(t, a.callerTransparentFixture, a.transparent, false)
	transparentOriginal := callerTransparentRun(t, b.callerTransparentFixture, b.transparent, true)
	callerTransparentEqual(t, transparent, transparentOriginal)
	if transparent.raw != 0 || transparent.hits != 1 || transparentOriginal.raw <= 0 {
		t.Fatal("transparent descendant retained no reusable real execution")
	}
	for _, child := range children {
		if child.phase != callerTraceRetained || child.scopeIndependent {
			t.Fatal("existing unproven child was retired or upgraded")
		}
	}
	if !maps.Equal(escaped, saved) {
		t.Fatal("borrowed child answer changed during composition")
	}
	for _, f := range []fixture{a, b} {
		if f.g.objectExecutions.active != 0 || f.g.semanticOverflow {
			t.Fatal("live ticket or semantic overflow survived the query")
		}
		callerAssertExecutionRetention(t, f.g.objectExecutions, nil)
	}
}
