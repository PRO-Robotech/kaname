// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Ожидаемый порядок берётся только из конечного прямого списка. Обратная
// структура проверяется отдельно, в том числе у единственной записи.
func callerReverseFIFORecords(t *testing.T, c *callerObjectExecutions) []*callerTraceRecord {
	t.Helper()
	var records []*callerTraceRecord
	for record := c.traceRecords; record != nil; record = record.next {
		if len(records) == callerObjectExecutionEntries {
			t.Fatal("forward trace list is cyclic or exceeds its charged entry bound")
		}
		records = append(records, record)
	}
	for i, record := range records {
		previous := records[len(records)-1]
		if i != 0 {
			previous = records[i-1]
		}
		if record.previous != previous {
			t.Fatal("reverse trace ownership differs from the independent forward order")
		}
	}
	return records
}

func TestCallerIdentityReverseFIFOAllocationOrderAndRelease(t *testing.T) {
	p := callerTraceTypedProgram(t, "holder:=&Holder{items:[]Box{}};x0:=holder.items;x1:=x0;x2:=x1;x3:=x2;_=x3;")
	fast, root, refs := callerTraceTypedGraph(t, p, "x3")
	slow, other, _ := callerTraceTypedGraph(t, p, "x3")
	fast.ctx, slow.ctx = context.Background(), context.Background()
	slow.objectExecutions = nil
	c := fast.objectExecutions
	pin := c.scope(fast)
	if pin == nil {
		t.Fatal("typed scope was not admitted")
	}
	defer c.releaseTicket(fast, pin)
	state, scope := fast.callerObjectExecutionState(), fast.callerExecutionSnapshot()
	query := func() {
		fm, sm := callerReuseMarks(fast), callerReuseMarks(slow)
		got, unknown, _ := fast.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
		want, otherUnknown, _ := slow.callerObjectsOwned(other, map[callerObjectSourceID]bool{})
		if len(got) == 0 || unknown != otherUnknown || !maps.Equal(got, want) || callerReuseDelta(fast, fm) != callerReuseDelta(slow, sm) || state != fast.callerObjectExecutionState() || !scope.matches(fast) {
			t.Fatal("typed nested admission changed objects, UNKNOWN, semantic marks or exact state")
		}
	}
	query()
	records := callerReverseFIFORecords(t, c)
	outer := fast.sources(callerVariable(refs["x3"].pkg, refs["x3"].expr))
	if len(records) < 3 || len(outer) != 1 || fast.work.ObjectTraceStores < len(records) {
		t.Fatal("typed nested fixture did not retain distinct parent and child executions")
	}
	// Родитель создаётся первым, завершается после детей, но остаётся FIFO-хвостом.
	parentID := fast.objectSourceIDs[callerResolveKeyFor(outer[0], true)]
	if parentID == 0 || records[len(records)-1].source != parentID || c.oldestCallerTrace() != records[len(records)-1] {
		t.Fatal("FIFO selected completion order instead of the oldest allocated parent")
	}
	escaped := map[*callerTraceRecord]map[callerObjectKey]bool{}
	immutable := map[*callerTraceRecord]map[callerObjectKey]bool{}
	for _, record := range records {
		escaped[record], immutable[record] = record.objects, maps.Clone(record.objects)
	}
	check := func() {
		if !slices.Equal(callerReverseFIFORecords(t, c), records) {
			t.Fatal("removal changed surviving forward allocation order")
		}
		for record, objects := range escaped {
			if !maps.Equal(objects, immutable[record]) {
				t.Fatal("removal mutated an escaped readonly result")
			}
		}
		callerAssertExecutionRetention(t, c, pin)
	}
	victim := records[len(records)-1]
	entries, units, evictions := c.entries, c.weight, fast.work.ObjectTraceEvictions
	removedUnits := callerTraceRecordPhysicalUnits(t, victim) + 1 + len(victim.objects)
	if !c.admit(fast, 0, callerObjectExecutionValues-c.weight+1, false) {
		t.Fatal("one-unit deficit did not evict the actual typed oldest certificate")
	}
	records = records[:len(records)-1]
	if c.entries != entries-1 || c.weight != units-removedUnits || fast.work.ObjectTraceEvictions != evictions+1 || !reflect.DeepEqual(*victim, callerTraceRecord{}) {
		t.Fatal("FIFO admission changed the victim, exact charge or complete detachment")
	}
	check()
	// Прямые удаления используют тот же производственный примитив: голова,
	// середина, хвост и последний узел не должны оставлять обратные ссылки.
	for len(records) != 0 {
		index := len(records) / 2
		if len(records)%2 == 0 {
			index = 0
		}
		victim = records[index]
		c.releaseCallerTrace(fast, victim)
		records = append(records[:index], records[index+1:]...)
		if !reflect.DeepEqual(*victim, callerTraceRecord{}) {
			t.Fatal("detached record still owns a reverse link or certificate")
		}
		check()
	}
	if c.oldestCallerTrace() != nil {
		t.Fatal("empty store returned an eviction victim")
	}
	query()
	records = callerReverseFIFORecords(t, c)
	if len(records) < 3 {
		t.Fatal("typed evaluation did not rebuild the drained list")
	}
	hits := fast.work.ObjectTraceHits
	query()
	if fast.work.ObjectTraceHits <= hits {
		t.Fatal("surviving exact-state trace was not replayed")
	}
	// Массовое штатное retirement использует сохранённый next при удалении
	// головы и не оставляет хвост, ссылающийся на уже обнулённую запись.
	fast.bindingEpoch++
	c.advance(fast)
	if c.traceRecords != nil {
		t.Fatal("version retirement left reverse-linked certificates")
	}
	for _, record := range records {
		if !reflect.DeepEqual(*record, callerTraceRecord{}) {
			t.Fatal("version retirement did not clear all record ownership")
		}
	}
	callerAssertExecutionRetention(t, c, pin)
}

func TestCallerIdentityReverseFIFOEligibilityAndQuarantine(t *testing.T) {
	p := callerRetainedAdmissionProgram(t)
	g, roots := callerRetainedAdmissionGraph(t, p)
	c := g.objectExecutions
	pin := c.scope(g)
	if pin == nil {
		t.Fatal("typed scope was not admitted")
	}
	defer func() {
		if pin != nil {
			c.releaseTicket(g, pin)
		}
	}()
	for _, root := range roots[:4] {
		g.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	}
	records := callerReverseFIFORecords(t, c)
	if len(records) < 3 {
		t.Fatal("typed fixture did not retain enough independent FIFO candidates")
	}
	tail, next := records[len(records)-1], records[len(records)-2]
	// Старый helper независимо проверяет все восемь условий каждой записи.
	// Непустой указатель objects обязателен для невакуозной подмены pending.
	if !slices.Equal(records, callerUnlinkRecords(t, c)) || tail.objects == nil || c.oldestCallerTrace() != tail {
		t.Fatal("guard probes lack an initially eligible tail with a non-nil result")
	}
	// Это изолированные отрицательные пробы чистого eligibility-предиката.
	// Каждый record получен решателем; после одной подмены запись полностью
	// восстанавливается до любого изменения account или фактического удаления.
	for _, tc := range []struct {
		name   string
		change func(*callerTraceRecord)
	}{
		{"live", func(r *callerTraceRecord) { r.phase = callerTraceLive }},
		{"ticket", func(r *callerTraceRecord) { r.ticket = true }},
		{"scope", func(r *callerTraceRecord) { r.holdsScope = false }},
		{"result", func(r *callerTraceRecord) { r.resultReserved = false }},
		{"pending", func(r *callerTraceRecord) { r.pending = r.objects }},
		{"parent", func(r *callerTraceRecord) { r.parent = records[0] }},
		{"entry", func(r *callerTraceRecord) { r.entry = &callerTraceFrame{} }},
		{"chain", func(r *callerTraceRecord) { r.chain = &callerTraceChain{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := *tail
			defer func() { *tail = before }()
			tc.change(tail)
			if c.oldestCallerTrace() != next {
				t.Fatal("reverse search weakened a guard or skipped the next oldest eligible record")
			}
		})
	}
	for _, record := range records {
		record.ticket = true
	}
	victim := c.oldestCallerTrace()
	for _, record := range records {
		record.ticket = false
	}
	if victim != nil || c.oldestCallerTrace() != tail {
		t.Fatal("all-ineligible reverse search failed to terminate or changed allocation order")
	}
	callerAssertExecutionRetention(t, c, pin)
	entries, units, evictions := c.entries, c.weight, g.work.ObjectTraceEvictions
	objects, immutable, scope, refs := tail.objects, maps.Clone(tail.objects), tail.scope, tail.scope.references
	g.resetCallerObjectExecutions()
	g.resetCallerObjectExecutions()
	if c.admit(g, 0, 1, false) || g.work.ObjectTraceEvictions != evictions {
		t.Fatal("disabled owner searched or evicted quarantined storage")
	}
	c.releaseCallerTrace(g, tail)
	if c.graph != nil || g.objectExecutions != c || c.entries != entries || c.weight != units || tail.phase != callerTraceDead || tail.holdsScope || scope.references != refs-1 || !slices.Equal(callerReverseFIFORecords(t, c), records) || !maps.Equal(objects, immutable) {
		t.Fatal("disabled release changed reverse topology, quarantine charge or escaped result")
	}
	c.releaseTicket(g, pin)
	pin = nil
	g.resetCallerObjectExecutions()
	if g.objectExecutions == c || g.objectExecutions.entries != 0 || g.objectExecutions.weight != 0 || g.objectExecutions.traceRecords != nil || !maps.Equal(objects, immutable) {
		t.Fatal("idle reset retained the quarantined namespace or changed its old answer")
	}
}

func TestCallerIdentityReverseFIFOObserverCancellationAndLawfulTwin(t *testing.T) {
	p := callerRetainedAdmissionProgram(t)
	fast, roots := callerRetainedAdmissionGraph(t, p)
	slow, otherRoots := callerRetainedAdmissionGraph(t, p)
	slow.objectExecutions = nil
	c := fast.objectExecutions
	pin := c.scope(fast)
	if pin == nil {
		t.Fatal("typed scope was not admitted")
	}
	defer c.releaseTicket(fast, pin)
	fast.callerObjectsOwned(roots[0], map[callerObjectSourceID]bool{})
	if len(callerReverseFIFORecords(t, c)) == 0 {
		t.Fatal("typed execution did not produce a real eviction candidate")
	}
	fastCalls, slowCalls := 0, 0
	fast.ctx = &callerTraceOpaqueContext{Context: context.Background(), onErr: func() { fastCalls++ }}
	slow.ctx = &callerTraceOpaqueContext{Context: context.Background(), onErr: func() { slowCalls++ }}
	evictions := fast.work.ObjectTraceEvictions
	if !c.admit(fast, 0, callerObjectExecutionValues-c.weight+1, false) || fast.work.ObjectTraceEvictions != evictions+1 || fastCalls != 0 {
		t.Fatal("real admission changed FIFO progress or called an observer-valued context")
	}
	fm, sm := callerReuseMarks(fast), callerReuseMarks(slow)
	got, unknown := fast.callerObjects(roots[0], map[callerObjectSourceID]bool{})
	want, other := slow.callerObjects(otherRoots[0], map[callerObjectSourceID]bool{})
	if fastCalls == 0 || fastCalls != slowCalls || unknown != other || !maps.Equal(got, want) || callerReuseDelta(fast, fm) != callerReuseDelta(slow, sm) {
		t.Fatal("opaque production entry changed actual checkpoint count, answer or semantic effects")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fast.ctx, slow.ctx = ctx, ctx
	fm, sm = callerReuseMarks(fast), callerReuseMarks(slow)
	got, unknown = fast.callerObjects(roots[0], map[callerObjectSourceID]bool{})
	want, other = slow.callerObjects(otherRoots[0], map[callerObjectSourceID]bool{})
	if got != nil || want != nil || !unknown || !other || callerReuseDelta(fast, fm) != callerReuseDelta(slow, sm) || c.active != 1 {
		t.Fatal("cancelled production entry fabricated a proof or leaked a live ticket")
	}
	callerReverseFIFORecords(t, c)
	callerAssertExecutionRetention(t, c, pin)
	const rpc = "fixture/service/FixtureService/RPC"
	const producer = "github.com/PRO-Robotech/corelib/operations.PrincipalFromContext"
	product := callerSoundnessProgram(t, callerFluentFixture, `first:=newBox().withReader(Concrete{});second:=first.again();alias:=second;alias.reader.read()`, `&Handler{}`)
	t.Cleanup(func() { callerGraphs.Delete(product) })
	declarations := []CallerReadDeclaration{{RPC: rpc, Producer: producer, Site: "fixture/app.anchor", Kind: CallerObservation, Reason: "Fixture anchor."}}
	negative := judgeCallerIdentity(product, declarations, map[string]bool{"fixture/source": true})
	if negative.Invalid != "" || len(negative.Findings) != 1 || !strings.Contains(negative.Findings[0], "чтение личности без объявления") {
		t.Fatalf("production entry failed to reject the actual undeclared alias reader: %+v", negative)
	}
	declarations = append(declarations, CallerReadDeclaration{RPC: rpc, Producer: producer, Site: "(fixture/app.Concrete).read", Kind: CallerObservation, Reason: "Same reader, declared."})
	lawful := judgeCallerIdentity(product, declarations, map[string]bool{"fixture/source": true})
	if lawful.Invalid != "" || len(lawful.Findings) != 0 || !reflect.DeepEqual(lawful.Reads, negative.Reads) {
		t.Fatalf("lawful production twin changed the actual reader population: %+v", lawful)
	}
}
