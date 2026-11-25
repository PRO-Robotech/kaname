// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"testing"
)

func callerInheritedScopeProgram(t *testing.T) *surfaceProgram {
	t.Helper()
	var body strings.Builder
	for i := range 12 {
		fmt.Fprintf(&body, "extra%d:=&Holder{items:[]Box{}};_=extra%d;", i, i)
	}
	body.WriteString(callerTraceDiamondBody(5))
	return callerTraceTypedProgram(t, body.String())
}

// Дополнительные кадры относятся к настоящим Holder.items той же typed-программы.
// Они увеличивают точный scope, не подставляя object answers или semantic counters.
func callerInheritedScopeGraph(t *testing.T, p *surfaceProgram) (*callerGraph, valueSrc) {
	t.Helper()
	g, root, refs := callerTraceTypedGraph(t, p, "x5")
	fields := g.fieldQueries[0].fields
	for i := range 12 {
		src := refs[fmt.Sprintf("extra%d", i)]
		index, entered := g.enterCallerFieldQuery(src, fields)
		if src.expr == nil || !entered {
			t.Fatal("typed additional field owner missing")
		}
		t.Cleanup(func() { g.leaveCallerFieldQuery(index) })
		g.fieldQueries[index].refs, g.fieldQueries[index].unknown = g.embeddedCallerSourcesRaw(src, fields, map[callerFieldKey]bool{})
		if g.fieldQueries[index].unknown || len(g.fieldQueries[index].refs) != 1 {
			t.Fatal("additional typed field has no concrete initial slice")
		}
	}
	// False-ключ тоже входит в точный scope; это данные стража, не ответ кеша.
	g.containerScanning = map[callerResolveKey]bool{
		callerResolveKeyFor(refs["extra0"], true): true,
		callerResolveKeyFor(refs["extra1"], true): false,
	}
	g.mutationScanning = map[callerFieldKey]bool{
		{callerResolveKeyFor(refs["extra2"], true), fields[0]}: true,
		{callerResolveKeyFor(refs["extra3"], true), fields[0]}: false,
	}
	g.ctx = context.Background()
	g.resetCallerObjectExecutions()
	return g, root
}

func TestCallerIdentityInheritedScopeDeepContentAndOwnership(t *testing.T) {
	p := callerInheritedScopeProgram(t)
	fast, root := callerInheritedScopeGraph(t, p)
	slow, other := callerInheritedScopeGraph(t, p)
	slow.objectExecutions = nil
	snapshot := fast.callerExecutionSnapshot()
	state := fast.callerObjectExecutionState()
	if len(snapshot.queries) != 13 || len(snapshot.containers) != 2 || len(snapshot.mutations) != 2 || !snapshot.matches(fast) {
		t.Fatal("deep exact scope fixture is incomplete")
	}
	fm, sm := callerReuseMarks(fast), callerReuseMarks(slow)
	fr, sr := fast.work.ObjectRawEvaluations, slow.work.ObjectRawEvaluations
	got, unknown, _ := fast.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	want, otherUnknown, _ := slow.callerObjectsOwned(other, map[callerObjectSourceID]bool{})
	if len(got) == 0 || unknown != otherUnknown || !maps.Equal(got, want) || callerReuseDelta(fast, fm) != callerReuseDelta(slow, sm) {
		t.Fatal("nested exact scope changed objects, UNKNOWN or four semantic marks")
	}
	if fast.work.ObjectTraceStores < 2 || fast.work.ObjectTraceHits == 0 || fast.work.ObjectRawEvaluations-fr >= slow.work.ObjectRawEvaluations-sr || state != fast.callerObjectExecutionState() || !snapshot.matches(fast) {
		t.Fatal("nested typed witness did not retain real traces in an unchanged exact scope")
	}
	var scope *callerObjectExecutionScope
	retained := 0
	for record := fast.objectExecutions.traceRecords; record != nil; record = record.next {
		if record.phase != callerTraceRetained || !record.holdsScope || record.ticket || !record.scope.snapshot.matches(fast) {
			t.Fatal("completed nested record lost its own immutable scope reference")
		}
		if scope != nil && record.scope != scope {
			t.Fatal("one exact context acquired multiple scope identities")
		}
		scope = record.scope
		retained++
	}
	if retained < 2 || fast.objectExecutions.active != 0 {
		t.Fatal("nested scope tickets failed to drain")
	}
	callerAssertExecutionRetention(t, fast.objectExecutions, nil)
}

func TestCallerIdentityInheritedScopeNewChainRechecksSameEpoch(t *testing.T) {
	for _, change := range []string{"refs", "unknown", "container", "mutation"} {
		t.Run(change, func(t *testing.T) {
			p := callerInheritedScopeProgram(t)
			fast, root := callerInheritedScopeGraph(t, p)
			slow, other := callerInheritedScopeGraph(t, p)
			slow.objectExecutions = nil
			c := fast.objectExecutions
			pin := c.scope(fast)
			if pin == nil {
				t.Fatal("real initial scope ticket missing")
			}
			defer c.releaseTicket(fast, pin)
			epoch := fast.bindingEpoch
			mutate := func(g *callerGraph) {
				switch change {
				case "refs":
					g.fieldQueries[0].refs = []valueSrc{g.fieldQueries[1].refs[0]}
				case "unknown":
					g.fieldQueries[0].unknown = true
				case "container":
					g.containerScanning[g.fieldQueries[2].source] = true
				case "mutation":
					g.mutationScanning[callerFieldKey{g.fieldQueries[4].source, g.fieldQueries[4].fields[0]}] = true
				}
			}
			mutate(fast)
			mutate(slow)
			if fast.bindingEpoch != epoch || pin.snapshot.matches(fast) || !fast.callerExecutionScopeTracked() {
				t.Fatal("same-epoch exact content change was vacuous or malformed")
			}
			fm, sm := callerReuseMarks(fast), callerReuseMarks(slow)
			got, unknown, _ := fast.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
			want, otherUnknown, _ := slow.callerObjectsOwned(other, map[callerObjectSourceID]bool{})
			if len(got) == 0 || unknown != otherUnknown || !maps.Equal(got, want) || callerReuseDelta(fast, fm) != callerReuseDelta(slow, sm) {
				t.Fatal("new chain inherited an obsolete field scope")
			}
			if fast.work.ObjectTraceQueries < 2 || fast.work.ObjectTraceStores == 0 || c.active != 1 {
				t.Fatal("changed scope did not execute nested trace ownership")
			}
			for record := c.traceRecords; record != nil; record = record.next {
				if record.scope == pin || !record.scope.snapshot.matches(fast) {
					t.Fatal("new chain published against the old pinned snapshot")
				}
			}
			callerAssertExecutionRetention(t, c, pin)
		})
	}
}

func TestCallerIdentityInheritedScopeGeneralBranchesKeepOriginalEffects(t *testing.T) {
	for _, branch := range []string{"call", "field"} {
		t.Run(branch, func(t *testing.T) {
			prefix, last := "", "identity(x4)"
			if branch == "field" {
				// Последний selector в синтаксисе принадлежит holder из diamond;
				// other.items остаётся настоящим новым запросом во время исполнения top.
				prefix = "other:=&Holder{items:[]Box{{reader:Concrete{}}}};outside:=other.items;"
				last = "outside"
			}
			body := prefix + callerTraceDiamondBody(4) + "top:=x4;top=" + last + ";_=append(top,Box{});"
			p := callerSoundnessProgram(t, "type Holder struct{items []Box};func identity(items []Box)[]Box{return items}", body, "&Handler{}")
			t.Cleanup(func() { callerGraphs.Delete(p) })
			fast, root, _ := callerTraceTypedGraph(t, p, "top")
			slow, other, _ := callerTraceTypedGraph(t, p, "top")
			// Сбрасываем только необязательный обычный memo у обоих близнецов:
			// новый запрос поля/общий вызов обязан реально исполниться в этом опыте.
			for _, g := range []*callerGraph{fast, slow} {
				g.objectMemo, g.initialObjectMemo = nil, nil
				g.ctx = context.Background()
			}
			slow.objectExecutions = nil
			fm, sm := callerReuseMarks(fast), callerReuseMarks(slow)
			queries, resolves, containers := fast.work.ObjectTraceQueries, fast.work.ResolveQueries, fast.work.ContainerCalls
			snapshot := fast.callerExecutionSnapshot()
			got, unknown, _ := fast.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
			want, otherUnknown, _ := slow.callerObjectsOwned(other, map[callerObjectSourceID]bool{})
			if len(got) == 0 || unknown != otherUnknown || !maps.Equal(got, want) || callerReuseDelta(fast, fm) != callerReuseDelta(slow, sm) || !snapshot.matches(fast) {
				t.Fatal("general branch changed original provenance, effects or restored outer scope")
			}
			if fast.work.ObjectTraceQueries-queries < 2 || branch == "call" && fast.work.ResolveQueries == resolves || branch == "field" && fast.work.ContainerCalls == containers {
				t.Fatal("fixture missed its nested parent or real scope-changing boundary")
			}
			if fast.objectExecutions.active != 0 {
				t.Fatal("general branch leaked a nested scope ticket")
			}
			callerAssertExecutionRetention(t, fast.objectExecutions, nil)
		})
	}
}
