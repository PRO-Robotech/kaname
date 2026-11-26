// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"strings"
	"testing"
)

// Все ID получаются настоящим nil-context прогревом typed присваиваний.
// Независимый twin сохраняет полный raw путь; tick связывает реальный аргумент.
func callerTraceIndexPair(t *testing.T, cycle bool) (*callerGraph, *callerGraph, []valueSrc, valueSrc) {
	t.Helper()
	return callerTraceIndexPairSize(t, cycle, 128)
}

func callerTraceIndexPairSize(t *testing.T, cycle bool, count int) (*callerGraph, *callerGraph, []valueSrc, valueSrc) {
	t.Helper()
	var body strings.Builder
	if cycle {
		body.WriteString("var x *Box;x=x;x=&Box{};")
	} else {
		body.WriteString("holder:=&Holder{items:[]Box{}};x0:=holder.items;")
	}
	for i := 0; i < count; i++ {
		if cycle {
			fmt.Fprintf(&body, "u%d:=x;q%d:=u%d;_=q%d;", i, i, i, i)
		} else {
			fmt.Fprintf(&body, "q%d:=x0;_=q%d;", i, i)
		}
	}
	body.WriteString("epoch:=tick(&Box{});_=epoch;")
	p := callerSoundnessProgram(t, "type Holder struct{items []Box};func tick(value *Box)*Box{return &Box{}}", body.String(), "&Handler{}")
	t.Cleanup(func() { callerGraphs.Delete(p) })
	makeGraph := func() (*callerGraph, []valueSrc, valueSrc) {
		g, _, refs := callerTraceTypedGraph(t, p, "q0")
		roots := make([]valueSrc, count)
		for i := range roots {
			roots[i] = refs[fmt.Sprintf("q%d", i)]
			if roots[i].expr == nil {
				t.Fatal("real typed source is missing")
			}
			g.callerObjectsOwned(roots[i], map[callerObjectSourceID]bool{})
		}
		g.resetCallerObjectExecutions()
		g.ctx = context.Background()
		if g.objectExecutions.entries != 0 || g.objectExecutions.traceBuckets != nil || refs["epoch"].expr == nil {
			t.Fatal("warmup injected index storage or lost the real binding call")
		}
		return g, roots, refs["epoch"]
	}
	g, roots, epoch := makeGraph()
	original, _, _ := makeGraph()
	original.objectExecutions = nil
	return g, original, roots, epoch
}

func callerTraceIndexQueryPair(t *testing.T, g, original *callerGraph, root valueSrc) (map[callerObjectKey]bool, bool) {
	t.Helper()
	gm, om := callerReuseMarks(g), callerReuseMarks(original)
	got, unknown, _ := g.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	want, otherUnknown, _ := original.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	if unknown != otherUnknown || !maps.Equal(got, want) || callerReuseDelta(g, gm) != callerReuseDelta(original, om) {
		t.Fatal("indexed typed execution changed answer, UNKNOWN or four semantic marks")
	}
	return got, unknown
}

// Oracle читает только прежний global next. Он считает старый полный prefix
// и его source-bucket подпоследовательность до первого exact valid record.
func callerTraceIndexExpected(t *testing.T, g *callerGraph, source callerObjectSourceID, scope *callerObjectExecutionScope, seen map[callerObjectSourceID]bool) (*callerTraceRecord, int, int, int) {
	t.Helper()
	full, bucket, dependencies := 0, 0, 0
	state := g.callerObjectExecutionState()
	for record := g.objectExecutions.traceRecords; record != nil; record = record.next {
		full++
		if record.source%16 != source%16 {
			continue
		}
		bucket++
		if record.phase != callerTraceRetained || record.source != source || record.guard.state != state || !callerTraceSameContext(record.ctx, g.ctx) {
			continue
		}
		if record.scope != scope && (!record.scopeIndependent || len(record.scope.snapshot.queries) != len(scope.snapshot.queries)) {
			continue
		}
		matches := true
		for i := 0; i < int(record.count); i++ {
			dependencies++
			dependency := record.dependencies[i]
			if seen[dependency.source] != (dependency.want == 1) {
				matches = false
				break
			}
		}
		if matches {
			return record, full, bucket, dependencies
		}
	}
	t.Fatal("independent full walk has no exact retained hit")
	return nil, 0, 0, 0
}

func TestCallerIdentityTraceLookupIndexProductionWork(t *testing.T) {
	for _, mode := range []string{"known", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			g, original, roots, _ := callerTraceIndexPair(t, false)
			if mode == "unknown" {
				g.fieldQueries[0].unknown, original.fieldQueries[0].unknown = true, true
			}
			c := g.objectExecutions
			pin := c.scope(g)
			if pin == nil {
				t.Fatal("real outer scope pin was refused")
			}
			defer c.releaseTicket(g, pin)
			state := g.callerObjectExecutionState()
			for _, root := range roots[:48] {
				callerTraceIndexQueryPair(t, g, original, root)
			}
			if state != g.callerObjectExecutionState() || !pin.snapshot.matches(g) || len(callerReverseFIFORecords(t, c)) < 48 || g.work.ObjectTraceEvictions != 0 {
				t.Fatal("distinct-source work fixture changed state or exhausted retention")
			}
			callerAssertExecutionRetention(t, c, pin)
			rhs := g.sources(callerVariable(roots[0].pkg, roots[0].expr))
			rootID := g.objectSourceIDs[callerResolveKeyFor(roots[0], true)]
			if len(rhs) != 1 || rootID == 0 {
				t.Fatal("production root has no exact warmed RHS")
			}
			source := g.objectSourceIDs[callerResolveKeyFor(rhs[0], true)]
			// Это только expected input oracle, не seen, передаваемый решателю.
			expected, full, bucket, dependencies := callerTraceIndexExpected(t, g, source, pin, map[callerObjectSourceID]bool{rootID: true})
			if source == 0 || source == rootID || full-bucket < 16 || expected.scope != pin || expected.count == 0 {
				t.Fatal("real source partition did not remove a material full-list prefix")
			}
			before := g.work
			got, unknown := callerTraceIndexQueryPair(t, g, original, roots[0])
			// Raw исполняет только внешний root; child hit выполняет две проверки
			// одноэлементного owned stack. Остальные шаги выведены из global oracle.
			if len(got) == 0 || unknown != (mode == "unknown") || g.work.ObjectRawEvaluations-before.ObjectRawEvaluations != 1 || g.work.ObjectTraceQueries-before.ObjectTraceQueries != 1 || g.work.ObjectTraceHits-before.ObjectTraceHits != 1 || g.work.ObjectTraceStores != before.ObjectTraceStores || g.work.ObjectTraceValidationSteps-before.ObjectTraceValidationSteps != bucket+dependencies+2 {
				t.Fatal("actual production lookup did not perform the exact indexed work")
			}
			t.Logf("candidate visits: indexed=%d old full-prefix=%d; exact dependency steps=%d", bucket, full, dependencies)
			escaped := maps.Clone(got)
			callerTraceIndexQueryPair(t, g, original, roots[1])
			if !maps.Equal(got, escaped) || c.active != 1 || c.traceChains != nil || c.traceFrames != nil {
				t.Fatal("indexed hit changed a readonly result or leaked a ticket")
			}
			callerAssertExecutionRetention(t, c, pin)
		})
	}
}

func TestCallerIdentityTraceLookupIndexCollisionOrder(t *testing.T) {
	for _, mode := range []string{"absent", "present"} {
		t.Run(mode, func(t *testing.T) {
			g, original, roots, _ := callerTraceIndexPair(t, true)
			for _, root := range roots[:32] {
				callerTraceIndexQueryPair(t, g, original, root)
			}
			negative, positive := callerExitDedupTwins(t, g)
			var target valueSrc
			// Canonical key хранит тот же настоящий AST source; значения ID не сеются.
			for key, id := range g.objectSourceIDs {
				if id == negative.source {
					target = key.source
				}
			}
			collisions := 0
			for record := g.objectExecutions.traceRecords; record != nil; record = record.next {
				if record.source != negative.source && record.source%16 == negative.source%16 {
					collisions++
				}
			}
			if target.expr == nil || collisions == 0 || g.work.ObjectTraceEvictions != 0 {
				t.Fatal("real retained sources did not force a target-bucket collision")
			}
			ancestor := g.objectSourceIDs[callerResolveKeyFor(roots[0], true)]
			want := negative
			if mode == "present" {
				ancestor, want = positive.source, positive
			}
			seen := map[callerObjectSourceID]bool{}
			chain := g.beginCallerTrace(seen)
			if chain == nil || chain.executing || ancestor == 0 {
				t.Fatal("real open owner was not admitted")
			}
			defer g.endCallerTrace(chain)
			frame := g.callerTracePush(chain, ancestor)
			if frame == nil {
				t.Fatal("actual typed ancestor push was refused")
			}
			seen[ancestor] = true
			defer func() { delete(seen, ancestor); g.callerTracePop(chain, frame) }()
			c := g.objectExecutions
			pin := c.scope(g)
			if pin == nil {
				t.Fatal("manual exact scope pin was refused")
			}
			defer c.releaseTicket(g, pin)
			expected, full, bucket, dependencies := callerTraceIndexExpected(t, g, negative.source, pin, seen)
			if expected != want || full <= bucket || dependencies == 0 {
				t.Fatal("full oracle lost source collision or false/true dependency order")
			}
			before, marks := g.work, callerReuseMarks(g)
			objects, unknown, owned := g.callerObjectsTracked(target, seen, chain)
			if owned || unknown != want.unknown || !maps.Equal(objects, want.objects) || callerReuseDelta(g, marks) != [4]uint64{want.effects.cuts, want.effects.skips, 0, want.effects.cycles} || g.work.ObjectRawEvaluations != before.ObjectRawEvaluations || g.work.ObjectTraceHits-before.ObjectTraceHits != 1 || g.work.ObjectTraceValidationSteps-before.ObjectTraceValidationSteps != bucket+dependencies+2 {
				t.Fatal("collision lookup changed first-valid result, effects or exact manual work")
			}
			callerAssertExecutionRetention(t, c, pin)
		})
	}
}

func TestCallerIdentityTraceLookupIndexReleaseRetirement(t *testing.T) {
	g, original, roots, epoch := callerTraceIndexPair(t, false)
	c := g.objectExecutions
	pin := c.scope(g)
	if pin == nil {
		t.Fatal("real outer scope pin was refused")
	}
	defer c.releaseTicket(g, pin)
	for _, root := range roots[:48] {
		callerTraceIndexQueryPair(t, g, original, root)
	}
	records := callerReverseFIFORecords(t, c)
	if len(records) < 48 || c.traceBuckets == nil {
		t.Fatal("release fixture has no charged index with many real records")
	}
	oldIndex := c.traceBuckets
	escaped, immutable := records[0].objects, maps.Clone(records[0].objects)
	victim := records[len(records)-1]
	evictions := g.work.ObjectTraceEvictions
	if !c.admit(g, 0, callerObjectExecutionValues-c.weight+1, false) || g.work.ObjectTraceEvictions != evictions+1 || !reflect.DeepEqual(*victim, callerTraceRecord{}) {
		t.Fatal("index changed exact FIFO eviction or complete record detachment")
	}
	callerAssertExecutionRetention(t, c, pin)
	var group []*callerTraceRecord
	for _, head := range c.traceBuckets {
		var current []*callerTraceRecord
		for record := head; record != nil; record = record.bucketNext {
			current = append(current, record)
		}
		if len(current) >= 3 {
			group = current
			break
		}
	}
	if len(group) < 3 {
		t.Fatal("real collision group cannot exercise head/middle/tail unlink")
	}
	for _, record := range []*callerTraceRecord{group[0], group[len(group)/2], group[len(group)-1]} {
		c.releaseCallerTrace(g, record)
		if !reflect.DeepEqual(*record, callerTraceRecord{}) {
			t.Fatal("bucket unlink retained an owned pointer")
		}
		callerAssertExecutionRetention(t, c, pin)
	}
	for c.traceRecords != nil {
		record := c.traceRecords
		c.releaseCallerTrace(g, record)
		if !reflect.DeepEqual(*record, callerTraceRecord{}) {
			t.Fatal("last-record removal retained an index link")
		}
		callerAssertExecutionRetention(t, c, pin)
	}
	if c.traceBuckets != nil || *oldIndex != [16]*callerTraceRecord{} || c.traceAccount || !maps.Equal(escaped, immutable) {
		t.Fatal("drained header kept the table or mutated escaped readonly data")
	}
	for _, root := range roots[:8] {
		callerTraceIndexQueryPair(t, g, original, root)
	}
	records = callerReverseFIFORecords(t, c)
	if len(records) < 8 {
		t.Fatal("drained production index was not rebuilt")
	}
	oldState, binding := g.callerObjectExecutionState(), g.bindingEpoch
	callerTraceIndexQueryPair(t, g, original, epoch)
	if g.bindingEpoch <= binding || oldState == g.callerObjectExecutionState() {
		t.Fatal("real typed call did not change the guarded execution state")
	}
	c.advance(g)
	for _, record := range records {
		if !reflect.DeepEqual(*record, callerTraceRecord{}) {
			t.Fatal("actual version retirement left an old indexed certificate")
		}
	}
	callerAssertExecutionRetention(t, c, pin)
}

func TestCallerIdentityTraceLookupIndexQuarantine(t *testing.T) {
	g, original, roots, _ := callerTraceIndexPair(t, false)
	c := g.objectExecutions
	pin := c.scope(g)
	if pin == nil {
		t.Fatal("real outer scope pin was refused")
	}
	defer func() {
		if pin != nil {
			c.releaseTicket(g, pin)
		}
	}()
	callerTraceIndexQueryPair(t, g, original, roots[0])
	records := callerReverseFIFORecords(t, c)
	if len(records) == 0 || c.traceBuckets == nil {
		t.Fatal("quarantine has no real indexed certificates")
	}
	seen := map[callerObjectSourceID]bool{}
	chain := g.beginCallerTrace(seen)
	if chain == nil {
		t.Fatal("live trace owner was refused")
	}
	defer func() {
		if chain.live {
			g.endCallerTrace(chain)
		}
	}()
	id := g.objectSourceIDs[callerResolveKeyFor(roots[0], true)]
	frame := g.callerTracePush(chain, id)
	if id == 0 || frame == nil {
		t.Fatal("real typed live frame was refused")
	}
	seen[id] = true
	defer func() {
		if frame.live {
			delete(seen, id)
			g.callerTracePop(chain, frame)
		}
	}()
	index, contents := c.traceBuckets, *c.traceBuckets
	entries, units := c.entries, c.weight
	g.resetCallerObjectExecutions()
	g.resetCallerObjectExecutions()
	victim := records[0]
	c.releaseCallerTrace(g, victim)
	if c.graph != nil || c.traceBuckets != index || *index != contents || c.entries != entries || c.weight != units || victim.phase != callerTraceDead || victim.holdsScope || c.admit(g, 0, 1, false) {
		t.Fatal("B1 release changed frozen topology/account or admitted another owner")
	}
	hits := g.work.ObjectTraceHits
	callerTraceIndexQueryPair(t, g, original, roots[1])
	if g.work.ObjectTraceHits != hits || *index != contents || !chain.bad {
		t.Fatal("disabled owner reused the index or hid suspended-chain taint")
	}
	delete(seen, id)
	g.callerTracePop(chain, frame)
	g.endCallerTrace(chain)
	c.releaseTicket(g, pin)
	pin = nil
	if c.active != 0 || c.entries != entries || c.weight != units {
		t.Fatal("quarantined live tickets changed paid frozen storage before drain")
	}
	callerAssertExecutionRetention(t, c, nil)
	g.resetCallerObjectExecutions()
	if g.objectExecutions == c || g.objectExecutions.traceBuckets != nil || g.objectExecutions.entries != 0 || g.objectExecutions.weight != 0 {
		t.Fatal("idle reset retained a foreign index in the new namespace")
	}
}

func TestCallerIdentityTraceLookupIndexGuards(t *testing.T) {
	for _, mode := range []string{"scope", "unknown", "context_identity", "opaque", "opaque_cancel", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			a, b := callerTransparentPair(t, true)
			callerTransparentPrime(t, a, b, a.target)
			old := callerTransparentRecords(t, a, a.target, false)
			if len(old) == 0 || a.g.objectExecutions.traceBuckets == nil {
				t.Fatal("guard probe has no real indexed exact-scope target")
			}
			if mode == "scope" || mode == "unknown" || mode == "context_identity" {
				for _, f := range []callerTransparentFixture{a, b} {
					switch mode {
					case "scope":
						f.g.fieldQueries[0].refs = f.alternate
					case "unknown":
						f.g.fieldQueries[0].unknown = true
					case "context_identity":
						ctx, cancel := context.WithCancel(context.Background())
						t.Cleanup(cancel)
						f.g.ctx = ctx
					}
				}
				if mode != "context_identity" && old[0].scope.snapshot.matches(a.g) || mode == "context_identity" && callerTraceSameContext(old[0].ctx, a.g.ctx) {
					t.Fatal("exact guard change was vacuous")
				}
				got, want := callerTransparentRun(t, a, a.target, false), callerTransparentRun(t, b, b.target, true)
				callerTransparentEqual(t, got, want)
				if got.raw == 0 || want.raw == 0 || mode == "unknown" && !got.unknown {
					t.Fatal("index bypassed exact scope/context refusal or lost UNKNOWN")
				}
			} else {
				calls := [2]int{}
				for i, f := range []callerTransparentFixture{a, b} {
					ctx, cancel := context.WithCancel(context.Background())
					t.Cleanup(cancel)
					if mode == "cancel" {
						cancel()
						f.g.ctx = ctx
					} else {
						f.g.ctx = &callerTraceOpaqueContext{Context: ctx, onErr: func() {
							calls[i]++
							if mode == "opaque_cancel" {
								cancel()
							}
						}}
					}
				}
				before, am, bm := a.g.work, callerReuseMarks(a.g), callerReuseMarks(b.g)
				got, unknown, _ := a.g.callerObjectsOwned(a.target, map[callerObjectSourceID]bool{})
				want, other, _ := b.g.callerObjectsOwned(b.target, map[callerObjectSourceID]bool{})
				if unknown != other || !maps.Equal(got, want) || callerReuseDelta(a.g, am) != callerReuseDelta(b.g, bm) || calls[0] != calls[1] || a.g.work.ObjectTraceHits != before.ObjectTraceHits || a.g.work.ObjectTraceValidationSteps != before.ObjectTraceValidationSteps {
					t.Fatal("index touched an inadmissible context or changed actual Err checkpoints")
				}
				if mode == "opaque" && calls[0] == 0 || mode == "opaque_cancel" && (calls[0] != 1 || !unknown) || mode == "cancel" && !unknown {
					t.Fatal("observer/cancellation preservation was vacuous")
				}
			}
			callerAssertExecutionRetention(t, a.g.objectExecutions, nil)
			callerAssertExecutionRetention(t, b.g.objectExecutions, nil)
		})
	}
}
