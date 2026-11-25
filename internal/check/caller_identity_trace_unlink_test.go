// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Записи получены только от типизированного решателя через настоящий путь допуска.
// Ожидания используют прямой порядок и ответы, удерживаемые снаружи,
// без обращения к внутреннему представлению входящей ссылки.
func callerUnlinkRecords(t *testing.T, c *callerObjectExecutions) []*callerTraceRecord {
	t.Helper()
	var records []*callerTraceRecord
	for record := c.traceRecords; record != nil; record = record.next {
		if len(records) >= callerObjectExecutionEntries {
			t.Fatal("trace list cycles or exceeds its entry budget")
		}
		if record.phase != callerTraceRetained || record.ticket || !record.holdsScope || !record.resultReserved || record.pending != nil || record.parent != nil || record.entry != nil || record.chain != nil {
			t.Fatal("typed solver did not leave detached retained certificates")
		}
		records = append(records, record)
	}
	return records
}

func TestCallerIdentityTraceUnlinkTypedOrderAndRetirement(t *testing.T) {
	p := callerRetainedAdmissionProgram(t)
	g, roots := callerRetainedAdmissionGraph(t, p)
	slow, otherRoots := callerRetainedAdmissionGraph(t, p)
	slow.objectExecutions = nil
	c := g.objectExecutions
	pinned := c.scope(g)
	if pinned == nil {
		t.Fatal("real outer scope acquisition failed")
	}
	state, snapshot := g.callerObjectExecutionState(), g.callerExecutionSnapshot()
	query := func(i int) {
		gm, sm := callerReuseMarks(g), callerReuseMarks(slow)
		got, unknown, _ := g.callerObjectsOwned(roots[i], map[callerObjectSourceID]bool{})
		want, other, _ := slow.callerObjectsOwned(otherRoots[i], map[callerObjectSourceID]bool{})
		if len(got) == 0 || !maps.Equal(got, want) || unknown != other || callerReuseDelta(g, gm) != callerReuseDelta(slow, sm) {
			t.Fatal("unlink/replay changed typed answers, unknown or semantic marks")
		}
		if g.callerObjectExecutionState() != state || !snapshot.matches(g) || g.semanticOverflow {
			t.Fatal("unchanged-state witness changed its certificate")
		}
	}
	for i := 0; i < 16; i++ {
		query(i)
		hits := g.work.ObjectTraceHits
		query(i)
		if g.work.ObjectTraceHits <= hits {
			t.Fatal("unchanged typed state did not replay a retained certificate")
		}
	}
	records := callerUnlinkRecords(t, c)
	if len(records) < 4 {
		t.Fatal("typed fixture did not create head, middle and tail candidates")
	}
	type certificate struct {
		guard   *callerTraceGuard
		value   callerTraceGuard
		objects map[callerObjectKey]bool
		copy    map[callerObjectKey]bool
		source  callerObjectSourceID
		effects callerInitialObjectEffects
		unknown bool
	}
	saved := map[*callerTraceRecord]certificate{}
	for _, record := range records {
		saved[record] = certificate{record.guard, *record.guard, record.objects, maps.Clone(record.objects), record.source, record.effects, record.unknown}
	}
	check := func() {
		if !slices.Equal(callerUnlinkRecords(t, c), records) {
			t.Fatal("unlink changed the surviving forward order")
		}
		for _, record := range records {
			old := saved[record]
			if record.guard != old.guard || *record.guard != old.value || record.source != old.source || record.effects != old.effects || record.unknown != old.unknown || !maps.Equal(record.objects, old.copy) {
				t.Fatal("unlink changed a surviving certificate")
			}
		}
		for _, old := range saved {
			if !maps.Equal(old.objects, old.copy) {
				t.Fatal("unlink mutated an escaped readonly answer")
			}
		}
		callerAssertExecutionRetention(t, c, pinned)
	}
	// Дефицит одной единицы должен вытеснить ровно самый старый допустимый
	// сертификат; тест не вставляет записи и не подделывает учёт ресурсов.
	victim := records[len(records)-1]
	evictions, entries, units := g.work.ObjectTraceEvictions, c.entries, c.weight
	victimUnits := callerTraceRecordPhysicalUnits(t, victim) + 1 + len(victim.objects)
	if !c.admit(g, 0, callerObjectExecutionValues-c.weight+1, false) {
		t.Fatal("bounded admission did not reclaim an idle certificate")
	}
	records = records[:len(records)-1]
	if g.work.ObjectTraceEvictions != evictions+1 || c.entries != entries-1 || c.weight != units-victimUnits || !reflect.DeepEqual(*victim, callerTraceRecord{}) {
		t.Fatal("admission changed FIFO victim, reservation or complete ownership release")
	}
	check()
	// Проверяется общий примитив удаления настоящих допущенных записей
	// на каждой позиции, включая предшественников после предыдущего удаления.
	for _, position := range []string{"head", "middle", "tail"} {
		index := 0
		if position == "middle" {
			index = len(records) / 2
		} else if position == "tail" {
			index = len(records) - 1
		}
		victim = records[index]
		c.releaseCallerTrace(g, victim)
		records = append(records[:index], records[index+1:]...)
		if !reflect.DeepEqual(*victim, callerTraceRecord{}) {
			t.Fatalf("%s removal retained owned references", position)
		}
		check()
	}
	for i := 0; i < 16; i++ {
		query(i)
	}
	// Настоящее изменение устойчивой версии освобождает оставшиеся сертификаты
	// обходом advance с сохранением next, включая заново допущенные записи.
	retired := callerUnlinkRecords(t, c)
	g.bindingEpoch++
	c.advance(g)
	if c.traceRecords != nil {
		t.Fatal("version advance left stale certificates linked")
	}
	for _, record := range retired {
		if !reflect.DeepEqual(*record, callerTraceRecord{}) {
			t.Fatal("version retirement retained owned references")
		}
	}
	for _, old := range saved {
		if !maps.Equal(old.objects, old.copy) {
			t.Fatal("version retirement mutated an escaped answer")
		}
	}
	callerAssertExecutionRetention(t, c, pinned)
	c.releaseTicket(g, pinned)
	if c.active != 0 || c.entries != 0 || c.weight != 0 {
		t.Fatal("final ticket did not drain retained storage")
	}
}

func TestCallerIdentityTraceUnlinkDisabledOwner(t *testing.T) {
	p := callerRetainedAdmissionProgram(t)
	g, roots := callerRetainedAdmissionGraph(t, p)
	slow, otherRoots := callerRetainedAdmissionGraph(t, p)
	slow.objectExecutions = nil
	c := g.objectExecutions
	pinned := c.scope(g)
	if pinned == nil {
		t.Fatal("real outer scope acquisition failed")
	}
	for _, root := range roots[:4] {
		g.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	}
	records := callerUnlinkRecords(t, c)
	if len(records) < 2 {
		t.Fatal("typed fixture did not retain multiple certificates")
	}
	entries, units, head := c.entries, c.weight, c.traceRecords
	g.resetCallerObjectExecutions()
	g.resetCallerObjectExecutions()
	victim := records[len(records)/2]
	escaped, before := victim.objects, maps.Clone(victim.objects)
	scope, refs := victim.scope, victim.scope.references
	c.releaseCallerTrace(g, victim)
	if c.graph != nil || g.objectExecutions != c || victim.phase != callerTraceDead || victim.holdsScope || scope.references != refs-1 || c.traceRecords != head || c.entries != entries || c.weight != units || !maps.Equal(escaped, before) {
		t.Fatal("disabled owner unlinked storage, lost accounting or changed an escaped answer")
	}
	for i, record := range records {
		var next *callerTraceRecord
		if i+1 < len(records) {
			next = records[i+1]
		}
		if record.next != next {
			t.Fatal("disabled release changed the quarantined list")
		}
	}
	c.releaseTicket(g, pinned)
	g.resetCallerObjectExecutions()
	if g.objectExecutions == c || g.objectExecutions.entries != 0 || g.objectExecutions.weight != 0 || g.objectExecutions.traceRecords != nil {
		t.Fatal("idle reset did not detach the disabled namespace")
	}
	gm, sm := callerReuseMarks(g), callerReuseMarks(slow)
	got, unknown, _ := g.callerObjectsOwned(roots[0], map[callerObjectSourceID]bool{})
	want, other, _ := slow.callerObjectsOwned(otherRoots[0], map[callerObjectSourceID]bool{})
	if len(got) == 0 || unknown != other || !maps.Equal(got, want) || callerReuseDelta(g, gm) != callerReuseDelta(slow, sm) || !maps.Equal(escaped, before) {
		t.Fatal("fresh owner failed typed evaluation or mutated the old answer")
	}
}

func TestCallerIdentityTraceUnlinkLawfulDeclarationTwin(t *testing.T) {
	const rpc = "fixture/service/FixtureService/RPC"
	const producer = "github.com/PRO-Robotech/corelib/operations.PrincipalFromContext"
	p := callerSoundnessProgram(t, callerFluentFixture, `box:=newBox().withReader(Concrete{}).again();alias:=box;alias.reader.read()`, `&Handler{}`)
	t.Cleanup(func() { callerGraphs.Delete(p) })
	declarations := []CallerReadDeclaration{{RPC: rpc, Producer: producer, Site: "fixture/app.anchor", Kind: CallerObservation, Reason: "Fixture anchor."}}
	negative := judgeCallerIdentity(p, declarations, map[string]bool{"fixture/source": true})
	if negative.Invalid != "" || len(negative.Findings) != 1 || !strings.Contains(negative.Findings[0], "чтение личности без объявления") {
		t.Fatalf("actual undeclared alias-chain reader was not rejected: %+v", negative)
	}
	declarations = append(declarations, CallerReadDeclaration{RPC: rpc, Producer: producer, Site: "(fixture/app.Concrete).read", Kind: CallerObservation, Reason: "Same reader, declared."})
	lawful := judgeCallerIdentity(p, declarations, map[string]bool{"fixture/source": true})
	if lawful.Invalid != "" || len(lawful.Findings) != 0 || !reflect.DeepEqual(lawful.Reads, negative.Reads) {
		t.Fatalf("lawful twin changed the actual reader population: %+v", lawful)
	}
}
