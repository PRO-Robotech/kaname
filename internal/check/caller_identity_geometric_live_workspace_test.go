// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"testing"
	"unsafe"
)

// Компонентные фикстуры используют настоящий конструктор, хранилище, tickets и
// begin/push/pop. Числовые predicates проверяют хранение, а не полномочия;
// независимые типизированные графы ниже проверяют происхождение источников.
// Вес, счётчики работы, ответы и память зависимостей не подменяются.
type callerGeometricFixture struct {
	g       *callerGraph
	c       *callerObjectExecutions
	chain   *callerTraceChain
	records []*callerTraceRecord
	frames  []*callerTraceFrame
	closed  bool
}

func callerGeometricNewFixture(t *testing.T) *callerGeometricFixture {
	t.Helper()
	p := callerTraceTypedProgram(t, callerTraceDiamondBody(4))
	g, _, _ := callerTraceTypedGraph(t, p, "x4")
	g.ctx = context.Background()
	f := &callerGeometricFixture{g: g, c: g.objectExecutions}
	f.chain = g.beginCallerTrace(map[callerObjectSourceID]bool{})
	if f.chain == nil || f.chain.bad || f.chain.executing || f.c.traceRecords != nil || len(f.c.answers) != 0 {
		t.Fatal("fixture did not begin an empty real manual store")
	}
	t.Cleanup(func() { f.close(t) })
	return f
}

func (f *callerGeometricFixture) close(t *testing.T) {
	t.Helper()
	if f.closed {
		return
	}
	for i := len(f.frames) - 1; i >= 0; i-- {
		frame := f.frames[i]
		delete(f.chain.seen, frame.source)
		f.g.callerTracePop(f.chain, frame)
	}
	for i := len(f.records) - 1; i >= 0; i-- {
		record := f.records[i]
		scope := record.scope
		f.chain.record = record.parent
		record.ticket = false
		f.c.releaseCallerTrace(f.g, record)
		f.c.releaseTicket(f.g, scope)
	}
	f.g.endCallerTrace(f.chain)
	f.closed = true
	callerAssertExecutionRetention(t, f.c, nil)
}

// Фикстура создаёт собственный объект и оплачивает его фактическую память
// до передачи владения хранилищу. Это работает для eager64 и постепенного
// роста; допуск production cache miss эта подготовка не проверяет.
// Рост, вставка и освобождение используют production-функции; независимый
// физический пересчёт проверяет каждый объект. Новый API роста не вызывается.
func (f *callerGeometricFixture) record(t *testing.T) *callerTraceRecord {
	t.Helper()
	scope := f.c.scope(f.g)
	if scope == nil {
		t.Fatal("fixture scope ticket unavailable")
	}
	if !f.c.admit(f.g, 1, callerTraceLiveRecordUnits+callerTraceGuardUnits, false) {
		f.c.releaseTicket(f.g, scope)
		t.Fatal("fixture record reservation unavailable")
	}
	record := f.c.newCallerTraceLiveRecord(f.g, f.chain, scope, callerObjectSourceID(1000+len(f.records)))
	f.c.retained(f.g, callerTraceRecordUnits+callerTraceGuardUnits+cap(record.dependencies)*callerTraceDependencyUnits)
	record.guard = &callerTraceGuard{state: f.g.callerObjectExecutionState()}
	scope.references++
	if record.next != nil {
		record.previous = record.next.previous
		record.next.previous = record
	} else {
		record.previous = record
	}
	f.c.traceRecords, f.chain.record = record, record
	bucket := record.source % callerTraceBucketCount
	record.bucketNext = f.c.traceBuckets[bucket]
	if record.bucketNext != nil {
		record.bucketNext.bucketPrevious = record
	}
	f.c.traceBuckets[bucket] = record
	f.records = append(f.records, record)
	callerAssertExecutionRetention(t, f.c, nil)
	return record
}

func (f *callerGeometricFixture) push(t *testing.T, source callerObjectSourceID) {
	t.Helper()
	if f.chain.seen[source] {
		t.Fatal("fixture reused an active frame identity")
	}
	frame := f.g.callerTracePush(f.chain, source)
	if frame == nil {
		t.Fatal("fixture real pressure frame was refused")
	}
	f.chain.seen[source] = true
	f.frames = append(f.frames, frame)
}

func (f *callerGeometricFixture) pressure(t *testing.T, remaining int) {
	t.Helper()
	// Каждый frame действительно занимает оплаченные 8 единиц; вес не подменён.
	for callerObjectExecutionValues-f.c.weight >= remaining+8 {
		f.push(t, callerObjectSourceID(1000000+len(f.frames)))
	}
	room := callerObjectExecutionValues - f.c.weight
	if room < remaining || room >= remaining+8 || f.chain.bad {
		t.Fatal("fixture did not reach the requested real storage interval")
	}
	callerAssertExecutionRetention(t, f.c, nil)
}

func callerGeometricCap(count int) int {
	capacity := 0
	if count != 0 {
		capacity = 1
		for capacity < count {
			capacity *= 2
		}
	}
	return capacity
}

func callerGeometricDependencyUnits() int {
	return int((unsafe.Sizeof(callerTraceDependency{}) + 7) / 8)
}

func callerGeometricInsert(t *testing.T, f *callerGeometricFixture, source callerObjectSourceID) {
	t.Helper()
	f.g.callerTraceDependency(f.chain, callerTraceDependency{source: source})
	if f.chain.record.bad {
		t.Fatal("ordinary component insertion unexpectedly refused")
	}
}

func TestCallerIdentityGeometricLiveWorkspaceGrowthAndPeak(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reverse_%t", reverse), func(t *testing.T) {
			f := callerGeometricNewFixture(t)
			record := f.record(t)
			if record.count != 0 {
				t.Fatal("fixture constructor did not start with an empty predicate set")
			}
			var expected []callerTraceDependency
			for k := 1; k <= 64; k++ {
				source := callerObjectSourceID(k)
				if reverse {
					source = callerObjectSourceID(65 - k)
				}
				old := record.dependencies
				oldCopy := slices.Clone(old)
				entries, weight, peak := f.c.entries, f.c.weight, f.g.work.ObjectExecutionPeakValues
				callerGeometricInsert(t, f, source)
				expected = append(expected, callerTraceDependency{source: source})
				sort.Slice(expected, func(i, j int) bool { return expected[i].source < expected[j].source })
				capacity := callerGeometricCap(k)
				if int(record.count) != k || len(record.dependencies) != capacity || cap(record.dependencies) != capacity || !slices.Equal(record.dependencies[:k], expected) {
					t.Fatalf("k=%d after real insertion: count=%d len=%d cap=%d wantCapacity=%d; predicates must remain exact", k, record.count, len(record.dependencies), cap(record.dependencies), capacity)
				}
				units := callerGeometricDependencyUnits()
				wantPeak := peak
				if capacity != cap(old) {
					wantPeak = max(peak, weight+capacity*units)
					if len(old) > 0 && &old[0] == &record.dependencies[0] || !slices.Equal(old, oldCopy) {
						t.Fatal("growth reused or mutated the old backing")
					}
				}
				if f.c.entries != entries || f.c.weight != weight+(capacity-cap(old))*units || f.g.work.ObjectExecutionPeakValues != wantPeak {
					t.Fatal("growth did not charge both full backings at peak and release only the old one")
				}
				backing := &record.dependencies[0]
				duplicateWork := f.g.work
				f.g.callerTraceDependency(f.chain, callerTraceDependency{source: source})
				if &record.dependencies[0] != backing || int(record.count) != k || f.c.weight != weight+(capacity-cap(old))*units || f.g.work.ObjectExecutionPeakValues != wantPeak || f.g.work.ObjectTraceCapacityFallbacks != duplicateWork.ObjectTraceCapacityFallbacks {
					t.Fatal("equal duplicate changed storage or reservation")
				}
				callerAssertExecutionRetention(t, f.c, nil)
			}
			before := slices.Clone(record.dependencies)
			weight, fallbacks := f.c.weight, f.g.work.ObjectTraceCapacityFallbacks
			f.g.callerTraceDependency(f.chain, callerTraceDependency{source: 65})
			if !record.bad || record.count != 64 || !slices.Equal(record.dependencies, before) || f.c.weight != weight || f.g.work.ObjectTraceCapacityFallbacks != fallbacks {
				t.Fatal("65th distinct predicate bypassed the unchanged logical limit")
			}
		})
	}
}

func TestCallerIdentityGeometricLiveWorkspaceRefusalAndPropagation(t *testing.T) {
	t.Run("full_new_backing_required", func(t *testing.T) {
		f := callerGeometricNewFixture(t)
		// Настоящий frame владельца позволяет итоговому противоречию want=true достичь
		// записей, чей вход включает владельца; frames для давления находятся глубже.
		f.push(t, 1)
		parent := f.record(t)
		for i := 1; i <= 33; i++ {
			callerGeometricInsert(t, f, callerObjectSourceID(i))
		}
		middle := f.record(t)
		middle.bad = true
		child := f.record(t)
		for i := 1; i <= 32; i++ {
			callerGeometricInsert(t, f, callerObjectSourceID(i))
		}
		if cap(parent.dependencies) != 64 || cap(child.dependencies) != 32 || parent.count != 33 {
			t.Fatal("fixture did not create distinct parent spare room and child growth boundary")
		}
		f.pressure(t, 96)
		room := callerObjectExecutionValues - f.c.weight
		if room < (64-32)*callerGeometricDependencyUnits() || room >= 64*callerGeometricDependencyUnits() {
			t.Fatal("fixture does not distinguish net growth from simultaneous reservation")
		}
		old := child.dependencies
		oldCopy := slices.Clone(old)
		entries, weight, peak := f.c.entries, f.c.weight, f.g.work.ObjectExecutionPeakValues
		work := f.g.work
		f.g.callerTraceDependency(f.chain, callerTraceDependency{source: 34})
		if !child.bad || child.count != 32 || &child.dependencies[0] != &old[0] || !slices.Equal(child.dependencies, oldCopy) || !middle.bad || parent.bad || parent.count != 34 || parent.dependencies[33].source != 34 {
			t.Fatal("growth refusal lost old predicates or stopped propagation past the bad middle")
		}
		if f.c.entries != entries || f.c.weight != weight || f.g.work.ObjectExecutionPeakValues != peak || f.g.work.ObjectTraceCapacityFallbacks != work.ObjectTraceCapacityFallbacks+1 || f.g.work.ObjectTraceEvictions != work.ObjectTraceEvictions || f.g.work.ObjectExecutionEvictions != work.ObjectExecutionEvictions {
			t.Fatal("refused growth allocated, reclaimed storage or changed its exact fallback count")
		}
		f.g.callerTraceDependency(f.chain, callerTraceDependency{source: 1, want: 1})
		if !parent.bad || parent.dependencies[0].want != 0 || parent.count != 34 {
			t.Fatal("contradiction did not invalidate the eligible ancestor past failed/bad records")
		}
		callerAssertExecutionRetention(t, f.c, nil)
	})
	t.Run("full_new_backing_fits", func(t *testing.T) {
		f := callerGeometricNewFixture(t)
		record := f.record(t)
		for i := 1; i <= 32; i++ {
			callerGeometricInsert(t, f, callerObjectSourceID(i))
		}
		f.pressure(t, 128)
		entries, weight, peak := f.c.entries, f.c.weight, f.g.work.ObjectExecutionPeakValues
		callerGeometricInsert(t, f, 33)
		if record.count != 33 || cap(record.dependencies) != 64 || f.c.entries != entries || f.c.weight != weight+32*callerGeometricDependencyUnits() || f.g.work.ObjectExecutionPeakValues != max(peak, weight+64*callerGeometricDependencyUnits()) || f.g.work.ObjectExecutionPeakValues > callerObjectExecutionValues {
			t.Fatal("legitimate simultaneous reservation refused or exceeded the unchanged budget")
		}
		callerAssertExecutionRetention(t, f.c, nil)
	})
}

func TestCallerIdentityGeometricLiveWorkspaceOwnershipAndLifecycle(t *testing.T) {
	for _, count := range []int{1, 3, 33, 64} {
		t.Run(fmt.Sprintf("prefix_%d", count), func(t *testing.T) {
			f := callerGeometricNewFixture(t)
			record := f.record(t)
			for i := 1; i <= count; i++ {
				callerGeometricInsert(t, f, callerObjectSourceID(i))
			}
			live := record.dependencies
			want := slices.Clone(live[:count])
			// Тестовая копия проверяет настоящий primitive prefix. Она не помещается
			// в кэш и не оплачивается как его собственность. Production-учёт завершения
			// независимо проверяется типизированным выполнением.
			weight := f.c.weight
			prefix := callerTraceDependencyPrefix(live, count)
			if len(prefix) != count || cap(prefix) != count || &prefix[0] == &live[0] || !slices.Equal(prefix, want) {
				t.Fatal("compact prefix is not a separate exact allocation")
			}
			// Эта компонентная проба не устанавливает и не публикует prefix.
			clear(prefix)
			if !slices.Equal(live[:count], want) {
				t.Fatal("prefix aliases live storage")
			}
			if f.c.weight != weight {
				t.Fatal("test-owned prefix changed cache accounting")
			}
			callerAssertExecutionRetention(t, f.c, nil)
			f.close(t)
			if f.c.entries != 0 || f.c.weight != 0 || f.c.active != 0 {
				t.Fatal("normal release leaked grown storage or tickets")
			}
		})
	}
	t.Run("quarantine", func(t *testing.T) {
		f := callerGeometricNewFixture(t)
		record := f.record(t)
		for i := 1; i <= 8; i++ {
			callerGeometricInsert(t, f, callerObjectSourceID(i))
		}
		old := record.dependencies
		entries, weight, peak := f.c.entries, f.c.weight, f.g.work.ObjectExecutionPeakValues
		f.g.resetCallerObjectExecutions()
		f.g.resetCallerObjectExecutions()
		if f.g.objectExecutions != f.c || f.c.graph != nil {
			t.Fatal("fixture failed to detach its active owner")
		}
		f.g.callerTraceDependency(f.chain, callerTraceDependency{source: 9})
		if !record.bad || record.count != 8 || &record.dependencies[0] != &old[0] || f.c.weight != weight || f.c.entries != entries || f.g.work.ObjectExecutionPeakValues != peak {
			t.Fatal("detached owner allocated or prematurely released its grown workspace")
		}
		f.close(t)
		if f.c.active != 0 || f.c.entries != entries || f.c.weight != weight || record.phase != callerTraceDead {
			t.Fatal("quarantine lost accounting before idle reset")
		}
		f.g.resetCallerObjectExecutions()
		if f.g.objectExecutions == f.c || f.g.objectExecutions.entries != 0 || f.g.objectExecutions.weight != 0 {
			t.Fatal("idle reset failed to create an empty namespace")
		}
	})
}

func TestCallerIdentityGeometricLiveWorkspaceTypedSemantics(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(fmt.Sprintf("unknown_%t", unknown), func(t *testing.T) {
			p := callerTraceTypedProgram(t, callerTraceDiamondBody(4))
			owned, root, _ := callerTraceTypedGraph(t, p, "x4")
			manual, manualRoot, _ := callerTraceTypedGraph(t, p, "x4")
			reference, referenceRoot, _ := callerTraceTypedGraph(t, p, "x4")
			reference.objectExecutions = nil
			for _, g := range []*callerGraph{owned, manual, reference} {
				g.ctx = context.Background()
				if len(g.fieldQueries) != 1 {
					t.Fatal("fixture lacks its real typed field snapshot")
				}
				g.fieldQueries[0].unknown = unknown
			}
			var escaped, immutable [3]map[callerObjectKey]bool
			for run := 0; run < 2; run++ {
				a := callerOwnedChainRun(t, owned, root, false)
				b := callerOwnedChainRun(t, manual, manualRoot, true)
				want := callerOwnedChainRun(t, reference, referenceRoot, false)
				if len(a.objects) == 0 || !maps.Equal(a.objects, b.objects) || !maps.Equal(a.objects, want.objects) || a.unknown != unknown || b.unknown != unknown || want.unknown != unknown || a.marks != b.marks || a.marks != want.marks || a.owned != b.owned {
					t.Fatal("geometric storage changed independent typed semantic results")
				}
				if a.hits == 0 || b.hits == 0 || want.hits != 0 || want.stores != 0 || want.raw == 0 || run == 0 && (a.stores == 0 || b.stores == 0) {
					t.Fatal("fixture lacks actual cold stores, warm hits or cache-disabled work")
				}
				for i, objects := range [3]map[callerObjectKey]bool{a.objects, b.objects, want.objects} {
					if run == 0 {
						escaped[i], immutable[i] = objects, maps.Clone(objects)
					} else if !maps.Equal(escaped[i], immutable[i]) || !maps.Equal(objects, immutable[i]) {
						t.Fatal("later execution changed an escaped result map")
					}
				}
			}
		})
	}
	t.Run("replay_pressure", func(t *testing.T) {
		p := callerTraceTypedProgram(t, callerTraceDiamondBody(4))
		g, root, _ := callerTraceTypedGraph(t, p, "x4")
		reference, _, _ := callerTraceTypedGraph(t, p, "x4")
		g.ctx, reference.ctx = context.Background(), context.Background()
		reference.objectExecutions = nil
		warm := callerOwnedChainRun(t, g, root, false)
		if warm.stores == 0 || warm.hits == 0 {
			t.Fatal("fixture did not execute and retain real typed certificates")
		}
		c := g.objectExecutions
		var selected *callerTraceRecord
		var source valueSrc
		// Используем настоящий interned key с точным выражением RHS/use;
		// ссылка на объявление переменной может отличаться от записанного источника.
		if len(g.objectSourceIDs) >= 1000 || len(reference.objectSourceIDs) >= 1000 {
			t.Fatal("fixture source IDs overlap component-only pressure identities")
		}
		for record := c.traceRecords; record != nil; record = record.next {
			if record.phase != callerTraceRetained || record.count == 0 || len(record.objects) == 0 || record.guard.state != g.callerObjectExecutionState() || !record.scope.snapshot.matches(g) || selected != nil && record.source >= selected.source {
				continue
			}
			for key, id := range g.objectSourceIDs {
				if id == record.source && key.receiver {
					selected, source = record, key.source
					break
				}
			}
		}
		if selected == nil || source.expr == nil {
			t.Fatal("fixture has no retained nonempty certificate with a real interned source")
		}
		f := &callerGeometricFixture{g: g, c: c, chain: g.beginCallerTrace(map[callerObjectSourceID]bool{})}
		if f.chain == nil {
			t.Fatal("fixture replay chain unavailable")
		}
		t.Cleanup(func() { f.close(t) })
		referenceSeen := map[callerObjectSourceID]bool{}
		for _, dep := range selected.dependencies {
			if dep.want != 1 {
				continue
			}
			f.push(t, dep.source)
			matched := false
			for key, id := range g.objectSourceIDs {
				if id == dep.source {
					otherID := reference.objectSourceIDs[key]
					if otherID == 0 {
						t.Fatal("independent reference lacks a required real source identity")
					}
					referenceSeen[otherID] = true
					matched = true
					break
				}
			}
			if !matched {
				t.Fatal("retained predicate did not name a real source")
			}
		}
		if f.chain.seen[selected.source] {
			t.Fatal("fixture selected a cycle leaf rather than a replayable nonempty source")
		}
		consumer := f.record(t)
		for i := 0; i < 32; i++ {
			callerGeometricInsert(t, f, callerObjectSourceID(2000000+i))
		}
		f.pressure(t, 96)
		if c.oldestCallerTrace() == nil || consumer.count != 32 || cap(consumer.dependencies) != 32 || f.chain.bad {
			t.Fatal("fixture lost its reclaimable source or consumer growth boundary")
		}
		for _, dep := range selected.dependencies {
			if f.chain.seen[dep.source] != (dep.want == 1) {
				t.Fatal("fixture does not satisfy actual retained predicates")
			}
		}
		type certificate struct {
			dependencies []callerTraceDependency
			objects      map[callerObjectKey]bool
		}
		retained := map[*callerTraceRecord]certificate{}
		for record := c.traceRecords; record != nil; record = record.next {
			if record.phase == callerTraceRetained {
				retained[record] = certificate{slices.Clone(record.dependencies), maps.Clone(record.objects)}
			}
		}
		// Сохраняем и непустой внешний контекст; идентификаторы для давления
		// находятся вне обеих intern-таблиц и не могут обозначать обходимый источник.
		for id := range f.chain.seen {
			if id >= 1000000 {
				referenceSeen[id] = true
			}
		}
		otherSource := reference.objectSourceIDs[callerResolveKeyFor(source, true)]
		if otherSource == 0 {
			t.Fatal("reference source unavailable")
		}
		before, fm, sm := g.work, callerReuseMarks(g), callerReuseMarks(reference)
		weight, entries := c.weight, c.entries
		got, unknown, _ := g.callerInteriorRaw(source, f.chain.seen, selected.source, f.chain)
		want, otherUnknown, _ := reference.callerObjectsRaw(source, referenceSeen, otherSource, nil)
		if !maps.Equal(got, want) || unknown != otherUnknown || callerReuseDelta(g, fm) != callerReuseDelta(reference, sm) || len(got) == 0 {
			t.Fatal("pressured replay changed actual raw semantics")
		}
		if !consumer.bad || consumer.count != 32 || c.weight != weight || c.entries != entries || g.work.ObjectTraceHits != before.ObjectTraceHits+1 || g.work.ObjectRawEvaluations != before.ObjectRawEvaluations || g.work.ObjectTraceCapacityFallbacks != before.ObjectTraceCapacityFallbacks+1 || g.work.ObjectTraceEvictions != before.ObjectTraceEvictions || g.work.ObjectExecutionEvictions != before.ObjectExecutionEvictions || g.work.ObjectTraceStores != before.ObjectTraceStores {
			t.Fatal("replay did not refuse only consumer growth, or evicted/changed its retained source")
		}
		for record, prior := range retained {
			if record.phase != callerTraceRetained || !slices.Equal(record.dependencies, prior.dependencies) || !maps.Equal(record.objects, prior.objects) {
				t.Fatal("growth invalidated a retained certificate still used by replay")
			}
		}
		callerAssertExecutionRetention(t, c, nil)
	})
}
