// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"maps"
	"slices"
	"testing"
)

// Обе записи создаёт настоящий typed object traversal. Проверка сохраняет
// идентичности старых trace и полные immutable fresh answers до origin pressure.
func callerOriginAdmissionObjects(t *testing.T) (*callerGraph, *callerGraph, valueSrc, func()) {
	t.Helper()
	p := callerRetainedAdmissionProgramSize(t, 2)
	g, roots := callerRetainedAdmissionGraphSize(t, p, 2)
	original, _ := callerRetainedAdmissionGraphSize(t, p, 2)
	original.objectExecutions = nil
	root := roots[0]
	g.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	callerPrimeObjectExecution(t, g, root)
	c := g.objectExecutions
	if len(c.answers) == 0 || c.traceRecords == nil || c.originRecords != nil || c.originOwners != nil || c.active != 0 {
		t.Fatal("typed fixture did not retain independent trace and fresh summaries")
	}
	answers := maps.Clone(c.answers)
	for key, answer := range answers {
		answer.answer.objects = maps.Clone(answer.answer.objects)
		answers[key] = answer
	}
	traces := map[*callerTraceRecord]bool{}
	for record := c.traceRecords; record != nil; record = record.next {
		traces[record] = true
	}
	state := g.callerObjectExecutionState()
	traceEvictions, freshEvictions := g.work.ObjectTraceEvictions, g.work.ObjectExecutionEvictions
	check := func() {
		t.Helper()
		if g.callerObjectExecutionState() != state || g.work.ObjectTraceEvictions != traceEvictions || g.work.ObjectExecutionEvictions != freshEvictions || len(c.answers) != len(answers) {
			t.Fatal("origin admission retired or evicted another execution layer")
		}
		for key, want := range answers {
			got, exists := c.answers[key]
			if !exists || got.answer.unknown != want.answer.unknown || got.effects != want.effects || !maps.Equal(got.answer.objects, want.answer.objects) {
				t.Fatal("origin pressure lost or mutated a real fresh summary")
			}
		}
		count := 0
		for record := c.traceRecords; record != nil; record = record.next {
			count++
			if !traces[record] || record.phase != callerTraceRetained || record.ticket || !record.holdsScope {
				t.Fatal("origin pressure replaced or reclaimed a real retained trace")
			}
		}
		if count != len(traces) {
			t.Fatal("origin pressure removed an earlier trace identity")
		}
		callerOriginAccount(t, c)
	}
	check()
	return g, original, root, check
}

// Давление создают только настоящие begin/end owners, разделяющие точный scope.
// Чужие cache entries, счётчики и ёмкость не внедряются и не подменяются.
func callerOriginAdmissionPressure(t *testing.T, g *callerGraph) ([]*callerOriginOwner, func()) {
	t.Helper()
	var owners []*callerOriginOwner
	drain := func() {
		for i := len(owners) - 1; i >= 0; i-- {
			if owners[i].live {
				g.endCallerOrigin(owners[i])
			}
		}
	}
	t.Cleanup(drain)
	for len(owners) < callerObjectExecutionEntries {
		owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
		if owner == nil {
			if len(owners) == 0 {
				t.Fatal("no real origin owner was admitted before pressure refusal")
			}
			return owners, drain
		}
		owners = append(owners, owner)
	}
	t.Fatal("origin pressure did not reach the unchanged physical limit")
	return nil, drain
}

func TestCallerIdentityOriginTransferAdmissionPreservesObjectSummaries(t *testing.T) {
	g, original, root, check := callerOriginAdmissionObjects(t)
	owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
	if owner == nil {
		t.Fatal("initial origin owner was refused")
	}
	defer g.endCallerOrigin(owner)
	parent := g.beginCallerOriginFrame(owner, callerResolveKeyFor(root, false))
	if parent == nil {
		t.Fatal("initial origin parent was refused")
	}
	defer g.endCallerOriginFrame(owner, parent, nil, true)
	_, drain := callerOriginAdmissionPressure(t, g)
	check()
	child := g.beginCallerOriginFrame(owner, callerResolveKeyFor(root, true))
	if child != nil {
		g.endCallerOriginFrame(owner, child, nil, true)
		t.Fatal("live pressure failed to refuse a new origin frame")
	}
	if owner.bad || !parent.bad || parent.dependencies != nil || parent.count != 0 || owner.capacityBoundary != parent {
		t.Fatal("frame refusal lost parent rejection or permanently disabled recovery")
	}
	check()
	// Уже известный fresh scope и answer остаются полезны даже до drain.
	marks, otherMarks := callerReuseMarks(g), callerReuseMarks(original)
	raw, hits := g.work.ObjectRawEvaluations, g.work.ObjectExecutionHits
	got, unknown := g.callerObjects(root, map[callerObjectSourceID]bool{})
	want, otherUnknown := original.callerObjects(root, map[callerObjectSourceID]bool{})
	if unknown != otherUnknown || !maps.Equal(got, want) || callerReuseDelta(g, marks) != callerReuseDelta(original, otherMarks) || g.work.ObjectRawEvaluations != raw || g.work.ObjectExecutionHits != hits+1 {
		t.Fatal("origin pressure destroyed exact fresh replay or changed its semantics")
	}
	check()
	drain()
	// Owned обходит fresh lookup: выигрыш после drain даёт именно прежний trace.
	marks, otherMarks = callerReuseMarks(g), callerReuseMarks(original)
	raw, hits = g.work.ObjectRawEvaluations, g.work.ObjectTraceHits
	otherRaw := original.work.ObjectRawEvaluations
	got, unknown, _ = g.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	want, otherUnknown, _ = original.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	if unknown != otherUnknown || !maps.Equal(got, want) || callerReuseDelta(g, marks) != callerReuseDelta(original, otherMarks) || g.work.ObjectTraceHits <= hits || g.work.ObjectRawEvaluations-raw >= original.work.ObjectRawEvaluations-otherRaw {
		t.Fatal("retained interior trace lost its useful replay after origin drain")
	}
	check()
}

func TestCallerIdentityOriginTransferScopeAdmissionPreservesObjectSummaries(t *testing.T) {
	g, _, root, check := callerOriginAdmissionObjects(t)
	c := g.objectExecutions
	owners, drain := callerOriginAdmissionPressure(t, g)
	check()
	// Освобождаем ровно один owner: на новый owner место есть, на новый
	// широкий snapshot — нет. Все refs принадлежат настоящему typed RPC.
	g.endCallerOrigin(owners[len(owners)-1])
	beforeEntries, beforeUnits := c.entries, c.weight
	oldRefs := g.fieldQueries[0].refs
	defer func() { g.fieldQueries[0].refs = oldRefs }()
	g.fieldQueries[0].refs = make([]valueSrc, 64)
	for i := range g.fieldQueries[0].refs {
		g.fieldQueries[0].refs[i] = root
	}
	owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
	g.fieldQueries[0].refs = oldRefs
	if owner != nil {
		g.endCallerOrigin(owner)
		t.Fatal("new origin scope displaced retained summaries under live pressure")
	}
	if c.entries != beforeEntries || c.weight != beforeUnits {
		t.Fatal("refused origin scope retained an unpaid owner or removed another layer")
	}
	check()
	drain()
	check()
}

func TestCallerIdentityOriginTransferOwnEvictionAndRecovery(t *testing.T) {
	p, root, cycle, _ := callerOriginTransferProgram(t, 4)
	g, original := callerOriginTransferPair(t, p, root)
	g.ctx, original.ctx = context.Background(), context.Background()
	base := callerOriginObserve(original, root, map[callerResolveKey]bool{})
	callerOriginSame(t, callerOriginObserve(g, root, map[callerResolveKey]bool{}), base)
	if g.work.OriginTransferHits == 0 || g.work.OriginTransferStores == 0 {
		t.Fatal("real constructor diamond did not create useful origin reuse")
	}
	c := g.objectExecutions
	var escaped []callerOrigin
	for record := c.originRecords; record != nil; record = record.next {
		if record.retained && record.key == callerResolveKeyFor(root, false) {
			escaped = record.values
		}
	}
	if len(escaped) == 0 {
		t.Fatal("real retained origin result is missing")
	}
	immutable := slices.Clone(escaped)
	evictions := g.work.OriginTransferEvictions
	_, drain := callerOriginAdmissionPressure(t, g)
	if g.work.OriginTransferEvictions <= evictions || c.originRecords != nil || !slices.Equal(escaped, immutable) {
		t.Fatal("origin pressure failed to reclaim its own detached records safely")
	}
	callerOriginAccount(t, c)
	drain()
	stores, hits := g.work.OriginTransferStores, g.work.OriginTransferHits
	recovered := callerOriginObserve(g, root, map[callerResolveKey]bool{})
	callerOriginSame(t, recovered, callerOriginObserve(original, root, map[callerResolveKey]bool{}))
	if recovered.raw >= base.raw || g.work.OriginTransferStores <= stores || g.work.OriginTransferHits <= hits || !slices.Equal(escaped, immutable) {
		t.Fatal("origin reuse did not recover after real ownership pressure drained")
	}
	// Иное seen обязательство проверяется после recovery, включая порядок
	// конкретных origins, UNKNOWN, цикл и все четыре semantic marks.
	key := callerResolveKeyFor(cycle, true)
	seen, otherSeen := map[callerResolveKey]bool{key: true}, map[callerResolveKey]bool{key: true}
	changed := callerOriginObserve(g, root, seen)
	callerOriginSame(t, changed, callerOriginObserve(original, root, otherSeen))
	if !maps.Equal(seen, otherSeen) || changed.marks == recovered.marks {
		t.Fatal("recovered certificate ignored a different external seen obligation")
	}
	// Отмена не становится ни replay, ни новым certificate после освобождения.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	g.ctx, original.ctx = ctx, ctx
	stores, hits = g.work.OriginTransferStores, g.work.OriginTransferHits
	stopped := callerOriginObserve(g, root, map[callerResolveKey]bool{})
	callerOriginSame(t, stopped, callerOriginObserve(original, root, map[callerResolveKey]bool{}))
	if !stopped.unknown || stopped.raw != 0 || g.work.OriginTransferStores != stores || g.work.OriginTransferHits != hits {
		t.Fatal("cancelled recovery admitted origin execution or reuse")
	}
	callerOriginAccount(t, c)
}

// Настоящие owner reservations заполняют только свободное место: старые
// сертификаты нужны, чтобы отличить отказ нового frame от прежнего eviction.
func TestCallerIdentityOriginTransferFrameAdmissionPreservesRetained(t *testing.T) {
	p, root, cycle, _ := callerOriginTransferProgram(t, 4)
	g, original := callerOriginTransferPair(t, p, root)
	want := callerOriginObserve(original, root, map[callerResolveKey]bool{})
	callerOriginSame(t, callerOriginObserve(g, root, map[callerResolveKey]bool{}), want)
	c := g.objectExecutions
	retained := map[*callerOriginRecord]bool{}
	var rootRecord *callerOriginRecord
	for record := c.originRecords; record != nil; record = record.next {
		if !record.retained || record.live || record.pins != 0 || record.owner != nil || record.parent != nil {
			t.Fatal("constructor diamond left a non-evictable record")
		}
		retained[record] = true
		if record.key == callerResolveKeyFor(root, false) {
			rootRecord = record
		}
	}
	if rootRecord == nil || len(rootRecord.values) != 2 || want.raw == 0 {
		t.Fatal("real retained root or original work witness missing")
	}
	immutable := slices.Clone(rootRecord.values)
	state, evictions := g.callerObjectExecutionState(), g.work.OriginTransferEvictions
	owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
	if owner == nil || owner.scope != rootRecord.scope {
		t.Fatal("existing exact scope did not admit the replay owner")
	}
	defer g.endCallerOrigin(owner)
	var pressure []*callerOriginOwner
	drain := func() {
		for i := len(pressure) - 1; i >= 0; i-- {
			if pressure[i].live {
				g.endCallerOrigin(pressure[i])
			}
		}
	}
	defer drain()
	// Останавливаемся до первого admission, которому понадобилось бы eviction.
	for c.traceRoom(1, callerOriginOwnerUnits) {
		next := g.beginCallerOrigin(map[callerResolveKey]bool{})
		if next == nil {
			t.Fatal("free owner capacity unexpectedly refused admission")
		}
		pressure = append(pressure, next)
		if next.scope != owner.scope {
			t.Fatal("owner pressure allocated a different scope")
		}
	}
	if len(pressure) == 0 || c.traceRoom(1, callerOriginRecordUnits) || g.work.OriginTransferEvictions != evictions || state != g.callerObjectExecutionState() {
		t.Fatal("owner reservations did not establish non-evicting frame pressure")
	}
	callerOriginAccount(t, c)
	entries, units, active := c.entries, c.weight, c.active
	fallbacks := g.work.OriginTransferCapacityFallbacks
	frame := g.beginCallerOriginFrame(owner, callerResolveKeyFor(cycle, false))
	if frame != nil {
		defer g.endCallerOriginFrame(owner, frame, nil, true)
	}
	if g.work.OriginTransferEvictions != evictions {
		t.Fatal("new frame evicted a useful retained origin certificate")
	}
	if frame != nil || owner.bad || owner.top != nil || owner.capacityBoundary != nil || c.entries != entries || c.weight != units || c.active != active || g.work.OriginTransferCapacityFallbacks != fallbacks+1 {
		t.Fatal("frame pressure did not preserve exact fallback and physical accounting")
	}
	survivors := map[*callerOriginRecord]bool{}
	for record := c.originRecords; record != nil; record = record.next {
		survivors[record] = true
	}
	if !maps.Equal(retained, survivors) || !slices.Equal(rootRecord.values, immutable) {
		t.Fatal("frame refusal changed retained identities or immutable results")
	}
	// Тот же owner исключает отдельный admission перед проверкой полезного replay.
	marks, raw, hits := callerReuseMarks(g), g.work.ResolveEvaluations, g.work.OriginTransferHits
	values, unknown := g.resolveOwned(root, false, owner.seen, owner)
	got := callerOriginObservation{slices.Clone(values), unknown, callerReuseDelta(g, marks), g.work.ResolveEvaluations - raw}
	callerOriginSame(t, got, want)
	if got.raw != 0 || g.work.OriginTransferHits != hits+1 || len(owner.seen) != 0 || state != g.callerObjectExecutionState() {
		t.Fatal("pressure lost useful exact replay or changed seen cleanup")
	}
	callerOriginAccount(t, c)
	drain()
	fresh := g.beginCallerOriginFrame(owner, callerResolveKeyFor(cycle, false))
	if fresh == nil {
		t.Fatal("frame admission did not recover after pressure drain")
	}
	if fresh.bad || fresh.count != 1 {
		g.endCallerOriginFrame(owner, fresh, nil, true)
		t.Fatal("recovered frame lost its mandatory dependency")
	}
	g.endCallerOriginFrame(owner, fresh, nil, true)
	callerOriginAccount(t, c)
}
