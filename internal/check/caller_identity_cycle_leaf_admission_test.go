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

// Настоящий typed source и production begin/push/pop. Готовые ответы,
// trace records и значения счётчиков в граф не внедряются.
func TestCallerIdentityInteriorCycleLeafNoAdmission(t *testing.T) {
	g, slow, roots, _ := callerTraceIndexPairSize(t, true, callerTracePressureSources())
	for _, root := range roots {
		callerTraceIndexQueryPair(t, g, slow, root)
	}
	root, other := roots[len(roots)-1], roots[len(roots)-1]
	c := g.objectExecutions
	seen := map[callerObjectSourceID]bool{}
	chain := g.beginCallerTrace(seen)
	if chain == nil || c.traceRecords == nil {
		t.Fatal("fixture lacks a real chain and previously retained certificates")
	}
	id, otherID := g.internObjectSource(root), slow.internObjectSource(other)
	frame := g.callerTracePush(chain, id)
	if frame == nil {
		t.Fatal("real cycle-entry frame was not admitted")
	}
	seen[id] = true
	frames := []*callerTraceFrame{frame}
	defer func() {
		for i := len(frames) - 1; i >= 0; i-- {
			delete(seen, frames[i].source)
			g.callerTracePop(chain, frames[i])
		}
		g.endCallerTrace(chain)
		callerAssertExecutionRetention(t, c, nil)
	}()
	// Begin/push мог освободить старого FIFO-жертву. Остаток занимают
	// только настоящие учтённые frames других typed sources, не fake weight.
	for _, ancestor := range roots {
		if !c.traceRoom(1, callerTraceLiveRecordUnits+callerTraceGuardUnits+1) {
			break
		}
		ancestorID := g.objectSourceIDs[callerResolveKeyFor(ancestor, true)]
		if ancestorID == 0 || seen[ancestorID] {
			continue
		}
		parent := g.callerTracePush(chain, ancestorID)
		if parent == nil {
			t.Fatal("real pressure ancestor frame was refused")
		}
		seen[ancestorID] = true
		frames = append(frames, parent)
	}
	if g.work.ObjectTraceEvictions == 0 || c.traceRoom(1, callerTraceLiveRecordUnits+callerTraceGuardUnits+1) {
		t.Fatal("real typed fill did not exhaust the space required by a cycle certificate")
	}
	entries, weight, active := c.entries, c.weight, c.active
	first, oldest, buckets := c.traceRecords, c.oldestCallerTrace(), *c.traceBuckets
	if oldest == nil {
		t.Fatal("no eligible FIFO victim to protect from redundant leaf admission")
	}
	for range 3 {
		before, fm, sm := g.work, callerReuseMarks(g), callerReuseMarks(slow)
		got, unknown, owned := g.callerInteriorRaw(root, seen, id, chain)
		want, otherUnknown, otherOwned := slow.callerObjectsRaw(other, map[callerObjectSourceID]bool{otherID: true}, otherID, nil)
		if !maps.Equal(got, want) || unknown != otherUnknown || owned != otherOwned || len(got) != 0 || unknown || owned || callerReuseDelta(g, fm) != [4]uint64{1, 0, 0, 1} || callerReuseDelta(g, fm) != callerReuseDelta(slow, sm) {
			t.Fatal("cycle fallback changed the raw answer, ownership or four semantic marks")
		}
		if g.work.ObjectTraceCycleBypasses != before.ObjectTraceCycleBypasses+1 || g.work.ObjectRawEvaluations != before.ObjectRawEvaluations+1 || g.work.ObjectTraceSeenReads != before.ObjectTraceSeenReads+1 {
			t.Fatal("real raw cycle and its dependency read were not executed exactly once")
		}
		if g.work.ObjectTraceQueries != before.ObjectTraceQueries || g.work.ObjectTraceHits != before.ObjectTraceHits || g.work.ObjectTraceStores != before.ObjectTraceStores || g.work.ObjectTraceEvictions != before.ObjectTraceEvictions || g.work.ObjectTraceEvictedValues != before.ObjectTraceEvictedValues || g.work.ObjectTraceCapacityFallbacks != before.ObjectTraceCapacityFallbacks || g.work.ObjectExecutionReleasedScopes != before.ObjectExecutionReleasedScopes || c.entries != entries || c.weight != weight || c.active != active || c.traceRecords != first || c.oldestCallerTrace() != oldest || *c.traceBuckets != buckets {
			t.Fatal("terminal cycle performed trace lookup/admission or changed retained FIFO ownership")
		}
		callerAssertExecutionRetention(t, c, nil)
	}
}

func TestCallerIdentityInteriorCycleLeafParentDependencies(t *testing.T) {
	count := callerTracePressureSources()
	var body strings.Builder
	body.WriteString("holder:=&Holder{items:[]Box{}};base:=holder.items;")
	for i := 0; i < count; i++ {
		fmt.Fprintf(&body, "x%d:=base;l%d:=x%d;r%d:=x%d;x%d=l%d;root%d:=l%d;root%d=r%d;outer%d:=root%d;_=outer%d;", i, i, i, i, i, i, i, i, i, i, i, i, i, i)
	}
	p := callerTraceTypedProgram(t, body.String())
	makeGraph := func() (*callerGraph, map[string]valueSrc) {
		g, _, refs := callerTraceTypedGraph(t, p, "outer0")
		// Прогреваем те же корни, что исполняются ниже: новый AST-use source
		// иначе меняет namespace и снимает записи раньше достижения давления.
		for i := 0; i < count; i++ {
			for _, prefix := range []string{"l", "r", "outer"} {
				g.callerObjectsOwned(refs[fmt.Sprintf("%s%d", prefix, i)], map[callerObjectSourceID]bool{})
			}
		}
		g.resetCallerObjectExecutions()
		g.ctx = context.Background()
		return g, refs
	}
	fast, refs := makeGraph()
	slow, _ := makeGraph()
	slow.objectExecutions = nil
	pressureParent := false
	for i := 0; i < count; i++ {
		before := fast.work.ObjectTraceCycleBypasses
		for _, prefix := range []string{"l", "r", "outer", "l", "r", "outer"} {
			root := refs[fmt.Sprintf("%s%d", prefix, i)]
			got, unknown := callerTraceIndexQueryPair(t, fast, slow, root)
			if len(got) == 0 || unknown {
				t.Fatal("typed anchored cyclic group lost its concrete answer")
			}
		}
		if fast.work.ObjectTraceCycleBypasses == before {
			continue
		}
		// Только sources текущей группы: старый low-pressure leaf не может
		// подменить доказательство передачи predicate от нового pressure bypass.
		group := map[callerObjectSourceID]bool{}
		for _, prefix := range []string{"x", "l", "r", "root", "outer"} {
			src := refs[fmt.Sprintf("%s%d", prefix, i)]
			for _, ref := range fast.sources(callerVariable(src.pkg, src.expr)) {
				id := fast.objectSourceIDs[callerResolveKeyFor(ref, true)]
				if id != 0 {
					group[id] = true
				}
			}
		}
		positive, negative := false, false
		for record := fast.objectExecutions.traceRecords; record != nil; record = record.next {
			if !group[record.source] {
				continue
			}
			for j := 0; j < int(record.count); j++ {
				dep := record.dependencies[j]
				positive = positive || dep.want == 1 && dep.source != record.source && group[dep.source]
				negative = negative || dep.want == 0
			}
		}
		pressureParent = pressureParent || positive && negative
		callerAssertExecutionRetention(t, fast.objectExecutions, nil)
	}
	if !pressureParent || fast.work.ObjectTraceCycleBypasses == 0 || fast.work.ObjectTraceHits == 0 || fast.work.ObjectTraceEvictions == 0 {
		t.Fatal("real pool pressure did not exercise bypass with inherited parent predicates, replay and eviction")
	}
	callerAssertExecutionRetention(t, fast.objectExecutions, nil)
}
