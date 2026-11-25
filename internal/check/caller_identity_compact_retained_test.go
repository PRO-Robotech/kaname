// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"maps"
	"testing"
)

// Рабочий набор из 128 разных typed RHS должен сохранить первый полезный
// сертификат в прежнем общем бюджете. Прогрев и сброс execution namespace
// выполняет штатная fixture; обычные memo, IDs и semantic marks не подменяются.
func TestCallerIdentityCompactRetainedTypedWorkingSet(t *testing.T) {
	p := callerRetainedAdmissionProgram(t)
	fast, roots := callerRetainedAdmissionGraph(t, p)
	reference, otherRoots := callerRetainedAdmissionGraph(t, p)
	reference.objectExecutions = nil
	c := fast.objectExecutions
	pinned := c.scope(fast)
	if pinned == nil {
		t.Fatal("не удалось получить настоящий внешний scope ticket")
	}
	defer c.releaseTicket(fast, pinned)
	state, snapshot := fast.callerObjectExecutionState(), fast.callerExecutionSnapshot()
	otherState, otherSnapshot := reference.callerObjectExecutionState(), reference.callerExecutionSnapshot()
	var escaped, immutable map[callerObjectKey]bool
	// Проверка не знает fixed/slice представление dependencies и не вызывает
	// старый layout-specific account helper. Границы бюджета остаются прежними.
	check := func() {
		t.Helper()
		if callerObjectExecutionValues != 16384 || c != fast.objectExecutions || c.graph != fast || c.active != 1 || c.weight > callerObjectExecutionValues || c.entries > callerObjectExecutionEntries || len(c.answers) != 0 {
			t.Fatal("обход изменил бюджет, владельца, внешний ticket или fresh answer cache")
		}
		if fast.callerObjectExecutionState() != state || !snapshot.matches(fast) || !pinned.snapshot.matches(fast) || pinned.references < 1 || fast.semanticOverflow || reference.callerObjectExecutionState() != otherState || !otherSnapshot.matches(reference) || reference.semanticOverflow {
			t.Fatal("обход изменил точное состояние или снимок активного поля")
		}
		if escaped != nil && !maps.Equal(escaped, immutable) {
			t.Fatal("последующие обходы изменили ранее выданную readonly карту")
		}
	}
	query := func(index int) (map[callerObjectKey]bool, int, int, int) {
		t.Helper()
		fm, rm := callerReuseMarks(fast), callerReuseMarks(reference)
		fr, rr, hits := fast.work.ObjectRawEvaluations, reference.work.ObjectRawEvaluations, fast.work.ObjectTraceHits
		// Owned намеренно обходит fresh-answer lookup: работа здесь может
		// исчезнуть только вследствие настоящего interior replay.
		got, unknown, _ := fast.callerObjectsOwned(roots[index], map[callerObjectSourceID]bool{})
		want, otherUnknown, _ := reference.callerObjectsOwned(otherRoots[index], map[callerObjectSourceID]bool{})
		delta := callerReuseDelta(fast, fm)
		if len(got) == 0 || unknown != otherUnknown || !maps.Equal(got, want) || delta != callerReuseDelta(reference, rm) || delta[0] <= delta[1] || delta[2] != 0 || delta[3] != 0 {
			t.Fatalf("root %d: изменены объекты, UNKNOWN или четыре semantic delta", index)
		}
		check()
		return got, fast.work.ObjectRawEvaluations - fr, reference.work.ObjectRawEvaluations - rr, fast.work.ObjectTraceHits - hits
	}
	query(0)
	firstSources := fast.sources(callerVariable(roots[0].pkg, roots[0].expr))
	if len(firstSources) != 1 {
		t.Fatal("первый typed root не имеет единственного RHS")
	}
	firstSource := fast.objectSourceIDs[callerResolveKeyFor(firstSources[0], true)]
	var firstCertificate *callerTraceRecord
	for record := c.traceRecords; record != nil; record = record.next {
		if firstSource != 0 && record.source == firstSource && record.phase == callerTraceRetained {
			if firstCertificate != nil {
				t.Fatal("первый RHS имеет неоднозначный retained сертификат")
			}
			firstCertificate = record
		}
	}
	if firstCertificate == nil {
		t.Fatal("первый RHS не создал собственного retained сертификата")
	}
	// Проверяем точную стоимость немедленного replay первого RHS.
	// После pressure одного попадания в общего потомка недостаточно:
	// повторное раскрытие первого RHS увеличит raw относительно этого baseline.
	var replayRaw, referenceRaw, replayHits int
	escaped, replayRaw, referenceRaw, replayHits = query(0)
	immutable = maps.Clone(escaped)
	// Единственный raw — внешний Ident q0: default-ветка raw читает
	// единственный RHS x0 через through. Его собственный retained hit
	// возвращается из callerInteriorRaw до original(), исключая raw RHS.
	if replayHits != 1 || replayRaw != 1 || replayRaw >= referenceRaw {
		t.Fatal("первый typed root не установил полезный interior replay")
	}
	seen := map[callerObjectSourceID]bool{}
	for index, root := range roots {
		if index != 0 {
			query(index)
		}
		sources := fast.sources(callerVariable(root.pkg, root.expr))
		if len(sources) != 1 {
			t.Fatal("typed root не имеет единственного фактически посещаемого RHS")
		}
		id := fast.objectSourceIDs[callerResolveKeyFor(sources[0], true)]
		if id == 0 || seen[id] {
			t.Fatal("рабочий набор содержит нулевой или повторный source ID")
		}
		seen[id] = true
	}
	if len(seen) != 128 {
		t.Fatal("typed pressure не посетил 128 различных RHS")
	}
	// Наличие именно исходного сертификата проверяем до повторного q0:
	// сам повтор при miss мог бы заново создать запись с тем же source.
	retainedBeforeReplay := false
	for record := c.traceRecords; record != nil; record = record.next {
		if record == firstCertificate && record.source == firstSource && record.phase == callerTraceRetained {
			retainedBeforeReplay = true
		}
	}
	// Сначала полная semantic equality; RED должен свидетельствовать о лишнем
	// исполнении тела, даже если общий дочерний сертификат ещё даёт trace hit.
	_, finalRaw, finalReferenceRaw, finalHits := query(0)
	if !retainedBeforeReplay || finalRaw != 1 || finalReferenceRaw != referenceRaw || finalHits != 1 {
		t.Fatalf("первый interior сертификат потерян после 128 typed roots: retained до replay=%t, raw=%d, немедленный replay raw=%d, reference raw=%d/%d, trace hits=%d/%d", retainedBeforeReplay, finalRaw, replayRaw, finalReferenceRaw, referenceRaw, finalHits, replayHits)
	}
	check()
}
