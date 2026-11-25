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

// Источники обоих корней и всех refs принадлежат настоящему typed RPC.
// Перестановки refs проверяют протокол точных снимков активного поля; ответы,
// seen, поколения и счётчики тест не внедряет. Nil context исключает trace replay.
func callerFreshReclamationGraphs(t *testing.T) (*callerGraph, *callerGraph, [2]valueSrc, []valueSrc) {
	t.Helper()
	var body strings.Builder
	body.WriteString("holder:=&Holder{items:[]Box{}};x0:=holder.items;left:=x0;right:=x0;_=left;_=right;")
	for i := 0; i < 64; i++ {
		fmt.Fprintf(&body, "v%d:=[]Box{};_=v%d;", i, i)
	}
	p := callerTraceTypedProgram(t, body.String())
	fast, left, refs := callerTraceTypedGraph(t, p, "left")
	reference, _, _ := callerTraceTypedGraph(t, p, "left")
	roots := [2]valueSrc{left, refs["right"]}
	values := make([]valueSrc, 64)
	for i := range values {
		values[i] = refs[fmt.Sprintf("v%d", i)]
		if values[i].expr == nil {
			t.Fatal("typed snapshot source is missing")
		}
	}
	for _, g := range []*callerGraph{fast, reference} {
		g.fieldQueries[0].refs = values
		for _, value := range values {
			g.callerObjectsOwned(value, map[callerObjectSourceID]bool{})
		}
		for range 3 {
			for _, root := range roots {
				g.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
			}
		}
		g.resetCallerObjectExecutions()
	}
	reference.objectExecutions = nil
	return fast, reference, roots, values
}

// Два ответа разделяют первый scope с настоящим внешним ticket. Новые
// optional контексты могут получить отказ, но не вытесняют удержанные ответы.
// Исходный factory twin проверяет и hit, и каждый настоящий capacity fallback.
func callerFillFreshReclamation(t *testing.T) (*callerGraph, *callerGraph, [2]valueSrc, *callerObjectExecutionScope, map[callerObjectKey]bool, map[callerObjectKey]bool, func()) {
	t.Helper()
	fast, reference, roots, values := callerFreshReclamationGraphs(t)
	c := fast.objectExecutions
	pin := c.scope(fast)
	if pin == nil {
		t.Fatal("real external scope ticket was not acquired")
	}
	pinHeld := true
	releasePin := func() {
		if pinHeld {
			pinHeld = false
			c.releaseTicket(fast, pin)
		}
	}
	t.Cleanup(releasePin)
	if c.active != 1 {
		t.Fatal("external acquisition did not create exactly one real ticket")
	}
	var escaped, immutable map[callerObjectKey]bool
	retained := map[callerObjectExecutionKey]callerObjectAnswer{}
	demand, admitted, refused := 0, 0, 0
	raw := fast.work.ObjectRawEvaluations
	for contextIndex := 0; contextIndex < 128; contextIndex++ {
		rotation := contextIndex % len(values)
		ordered := append(append([]valueSrc{}, values[rotation:]...), values[:rotation]...)
		for _, g := range []*callerGraph{fast, reference} {
			g.fieldQueries[0].refs = ordered
			g.fieldQueries[0].unknown = contextIndex >= len(values)
		}
		demand += 1 + fast.callerContainerObjectScopeWeight()
		for rootIndex, root := range roots {
			state := fast.callerObjectExecutionState()
			marks, referenceMarks := callerReuseMarks(fast), callerReuseMarks(reference)
			beforeFallback := fast.work.ObjectExecutionCapacityFallbacks
			firstRaw, firstReferenceRaw := fast.work.ObjectRawEvaluations, reference.work.ObjectRawEvaluations
			got, unknown := fast.callerObjects(root, map[callerObjectSourceID]bool{})
			want, wantUnknown := reference.callerObjects(root, map[callerObjectSourceID]bool{})
			delta := callerReuseDelta(fast, marks)
			if len(got) < len(values) || unknown != (contextIndex >= len(values)) || unknown != wantUnknown || !maps.Equal(got, want) || delta != callerReuseDelta(reference, referenceMarks) || delta[0] <= delta[1] || delta[2] != 0 || delta[3] != 0 || state != fast.callerObjectExecutionState() {
				t.Fatal("real snapshot traversal lost objects, cuts, exact effects or stable durable state")
			}
			firstActual, firstExpected := fast.work.ObjectRawEvaluations-firstRaw, reference.work.ObjectRawEvaluations-firstReferenceRaw
			demand += 1 + len(got)
			stored := false
			id := fast.objectSourceIDs[callerResolveKeyFor(root, true)]
			if id == 0 {
				t.Fatal("expanded source has no graph-local ID")
			}
			for key, answer := range c.answers {
				if key.source == id && key.state == state && key.scope.snapshot.matches(fast) {
					stored = true
					retained[key] = callerObjectAnswer{maps.Clone(answer.answer.objects), answer.answer.unknown}
				}
			}
			beforeRaw, beforeHits := fast.work.ObjectRawEvaluations, fast.work.ObjectExecutionHits
			marks, referenceMarks = callerReuseMarks(fast), callerReuseMarks(reference)
			referenceRaw := reference.work.ObjectRawEvaluations
			again, againUnknown := fast.callerObjects(root, map[callerObjectSourceID]bool{})
			want, wantUnknown = reference.callerObjects(root, map[callerObjectSourceID]bool{})
			if reference.work.ObjectRawEvaluations <= referenceRaw || againUnknown != wantUnknown || !maps.Equal(again, want) || callerReuseDelta(fast, marks) != callerReuseDelta(reference, referenceMarks) {
				t.Fatal("optional refusal or admitted replay changed exact original semantics")
			}
			if stored {
				admitted++
				if fast.work.ObjectExecutionHits != beforeHits+1 || fast.work.ObjectRawEvaluations != beforeRaw {
					t.Fatal("admitted answer did not serve its immediate repeat without raw work")
				}
			} else {
				refused++
				if firstActual <= 0 || firstActual != firstExpected || fast.work.ObjectExecutionHits != beforeHits || fast.work.ObjectRawEvaluations-beforeRaw != reference.work.ObjectRawEvaluations-referenceRaw || fast.work.ObjectExecutionCapacityFallbacks <= beforeFallback {
					t.Fatal("non-forcing refusal did not execute the complete original traversal")
				}
			}
			if contextIndex == 0 && rootIndex == 0 {
				escaped, immutable = again, maps.Clone(again)
			}
		}
		if contextIndex == 0 {
			holds := 0
			for key := range c.answers {
				if key.scope == pin {
					holds++
				}
			}
			if holds != 2 || pin.references != 3 {
				t.Fatal("two real answers did not share the externally pinned snapshot")
			}
		}
		for key, saved := range retained {
			answer, exists := c.answers[key]
			if !exists || saved.unknown != answer.answer.unknown || !maps.Equal(saved.objects, answer.answer.objects) {
				t.Fatal("fresh-only pressure evicted or mutated a retained answer")
			}
		}
		callerAssertExecutionRetention(t, c, pin)
		if !maps.Equal(escaped, immutable) {
			t.Fatal("pressure mutated an escaped read-only map")
		}
	}
	if demand <= callerObjectExecutionValues || admitted == 0 || refused == 0 || fast.work.ObjectExecutionEvictions != 0 || fast.work.ObjectTraceEvictions != 0 || fast.work.ObjectExecutionCapacityFallbacks == 0 || fast.work.ObjectRawEvaluations <= raw || c.active != 1 || c.traceRecords != nil {
		t.Fatal("typed workload failed to preserve admitted answers while refusing fresh-only pressure")
	}
	// Возвращаемся к раннему exact scope при заполненном бюджете. Его поиск
	// обязан использовать прежний ticket, без нового snapshot или вытеснения.
	lastRefs, lastUnknown := fast.fieldQueries[0].refs, fast.fieldQueries[0].unknown
	for _, g := range []*callerGraph{fast, reference} {
		g.fieldQueries[0].refs = append([]valueSrc{}, pin.snapshot.queries[0].refs...)
		g.fieldQueries[0].unknown = pin.snapshot.queries[0].unknown
	}
	entries, units, hits := c.entries, c.weight, fast.work.ObjectExecutionHits
	marks, referenceMarks := callerReuseMarks(fast), callerReuseMarks(reference)
	raw, referenceRaw := fast.work.ObjectRawEvaluations, reference.work.ObjectRawEvaluations
	got, unknown := fast.callerObjects(roots[0], map[callerObjectSourceID]bool{})
	want, otherUnknown := reference.callerObjects(roots[0], map[callerObjectSourceID]bool{})
	if fast.work.ObjectExecutionHits != hits+1 || fast.work.ObjectRawEvaluations != raw || reference.work.ObjectRawEvaluations <= referenceRaw || unknown != otherUnknown || !maps.Equal(got, want) || callerReuseDelta(fast, marks) != callerReuseDelta(reference, referenceMarks) || c.entries != entries || c.weight != units || pin.references != 3 {
		t.Fatal("existing exact scope needed destructive admission or lost its real repeat benefit")
	}
	for _, g := range []*callerGraph{fast, reference} {
		g.fieldQueries[0].refs, g.fieldQueries[0].unknown = lastRefs, lastUnknown
	}
	return fast, reference, roots, pin, escaped, immutable, releasePin
}

// Список tickets содержит только результаты реальных acquire. Пересчёт ниже
// независим от entries/weight/active и покрывает каждую ссылку до release.
func callerAssertFreshPressurePins(t *testing.T, c *callerObjectExecutions, pins []*callerObjectExecutionScope) {
	t.Helper()
	entries, units := len(c.answers), 0
	holds := map[*callerObjectExecutionScope]int{}
	for _, pin := range pins {
		holds[pin]++
	}
	for key, answer := range c.answers {
		units += 1 + len(answer.answer.objects)
		holds[key.scope]++
	}
	te, tu, tr := callerTraceAccount(t, c)
	entries, units = entries+te, units+tu
	for scope, count := range tr {
		holds[scope] += count
	}
	if c.traceChains != nil || c.traceFrames != nil {
		t.Fatal("typed traversal did not drain its real chain/frames")
	}
	for record := c.traceRecords; record != nil; record = record.next {
		if record.ticket {
			t.Fatal("returned typed traversal retained a live record ticket")
		}
	}
	for _, head := range c.scopes {
		for scope := head; scope != nil; scope = scope.next {
			s := scope.snapshot
			weight := 1 + len(s.queries) + len(s.heads) + len(s.containers) + len(s.mutations)
			for _, query := range s.queries {
				weight += len(query.fields) + len(query.refs)
			}
			if weight != scope.weight || scope.references != holds[scope] {
				t.Fatal("scope ownership differs from all real tickets and cache holds")
			}
			entries++
			units += weight
			delete(holds, scope)
		}
	}
	if len(holds) != 0 || entries != c.entries || units != c.weight || c.active != len(pins) || entries > callerObjectExecutionEntries || units > callerObjectExecutionValues {
		t.Fatal("independent multi-ticket census differs from the full bounded account")
	}
}

func TestCallerIdentityFreshReclamationPressureAndPins(t *testing.T) {
	g, reference, roots, pin, escaped, immutable, releasePin := callerFillFreshReclamation(t)
	c := g.objectExecutions
	entries, units, evictions := c.entries, c.weight, g.work.ObjectExecutionEvictions
	for _, request := range [][3]int{{1, callerObjectExecutionValues + 1, 0}, {callerObjectExecutionEntries + 1, 1, 0}, {1, callerObjectExecutionValues, 1}} {
		if c.admit(g, request[0], request[1], request[2] != 0) || c.entries != entries || c.weight != units || g.work.ObjectExecutionEvictions != evictions {
			t.Fatal("intrinsically impossible request destroyed useful fresh answers")
		}
	}
	// Остаток занят настоящими non-forcing scope tickets того же typed графа.
	// Их размер меньше frame8; реальный отказ acquire доказывает room<8.
	// Никакие entries/weight/seen/chain здесь не внедряются.
	extraPins := []*callerObjectExecutionScope{}
	releaseExtra := func() {
		for _, scope := range extraPins {
			c.releaseTicket(g, scope)
		}
		extraPins = nil
	}
	defer releaseExtra()
	savedRefs, savedUnknown := g.fieldQueries[0].refs, g.fieldQueries[0].unknown
	snapshot, state := g.callerExecutionSnapshot(), g.callerObjectExecutionState()
	refused := false
	for _, value := range savedRefs {
		g.fieldQueries[0].refs, g.fieldQueries[0].unknown = []valueSrc{value}, false
		weight := 1 + g.callerContainerObjectScopeWeight()
		if weight >= callerTraceFrameUnits {
			t.Fatal("real small snapshot cannot prove the frame admission boundary")
		}
		scope := c.freshScope(g)
		if scope == nil {
			if c.freshRoom(g, weight) {
				t.Fatal("small snapshot refused without genuine pressure")
			}
			refused = true
			break
		}
		extraPins = append(extraPins, scope)
		callerAssertFreshPressurePins(t, c, append([]*callerObjectExecutionScope{pin}, extraPins...))
	}
	g.fieldQueries[0].refs, g.fieldQueries[0].unknown = savedRefs, savedUnknown
	if !refused || len(extraPins) == 0 || c.traceRoom(1, callerTraceFrameUnits) || c.traceAccount || c.traceRecords != nil || !snapshot.matches(g) || state != g.callerObjectExecutionState() || g.work.ObjectExecutionEvictions != evictions {
		t.Fatal("real pinned snapshots did not establish pressure without destructive fresh admission")
	}
	version := callerObjectExecutionVersion{g.bindingEpoch, g.effectEpoch, len(g.objectSourceIDs), len(g.identityFree), g.objectMemoGeneration, g.resolveMemoGeneration}
	if c.version != version {
		t.Fatal("begin would retire a stale generation instead of exercising admission")
	}
	callerAssertFreshPressurePins(t, c, append([]*callerObjectExecutionScope{pin}, extraPins...))
	// Теперь именно настоящий begin внутри typed callerObjectsOwned требует
	// chain9+header21. До него нет другого admit; first room<8 обязан вызвать
	// fresh reclamation. Тело и все четыре marks сверяются с original twin.
	g.ctx, reference.ctx = context.Background(), context.Background()
	marks, referenceMarks := callerReuseMarks(g), callerReuseMarks(reference)
	raw, referenceRaw := g.work.ObjectRawEvaluations, reference.work.ObjectRawEvaluations
	reads, capacity := g.work.ObjectTraceSeenReads, g.work.ObjectTraceCapacityFallbacks
	got, unknown, _ := g.callerObjectsOwned(roots[0], map[callerObjectSourceID]bool{})
	want, otherUnknown, _ := reference.callerObjectsOwned(roots[0], map[callerObjectSourceID]bool{})
	if g.work.ObjectExecutionEvictions <= evictions || g.work.ObjectExecutionEvictedValues == 0 || g.work.ObjectTraceSeenReads <= reads || g.work.ObjectTraceCapacityFallbacks != capacity || g.work.ObjectRawEvaluations <= raw || reference.work.ObjectRawEvaluations <= referenceRaw || unknown != otherUnknown || !maps.Equal(got, want) || callerReuseDelta(g, marks) != callerReuseDelta(reference, referenceMarks) || !maps.Equal(escaped, immutable) {
		t.Fatal("real trace admission failed to reclaim fresh ownership with exact original semantics")
	}
	callerAssertFreshPressurePins(t, c, append([]*callerObjectExecutionScope{pin}, extraPins...))
	releaseExtra()
	callerAssertExecutionRetention(t, c, pin)
	evictions = g.work.ObjectExecutionEvictions
	evictedValues := g.work.ObjectExecutionEvictedValues
	remainingAnswers, remainingValues := len(c.answers), 0
	for _, answer := range c.answers {
		remainingValues += 1 + len(answer.answer.objects)
	}
	// Отдельный primitive проверяет исчерпание всех optional жертв: запрос
	// сам допустим, но настоящий внешний pin запрещает освободить весь бюджет.
	if c.admit(g, callerObjectExecutionEntries, callerObjectExecutionValues, false) || len(c.answers) != 0 || c.traceRecords != nil || c.entries != 1 || c.weight != pin.weight || pin.references != 1 || c.active != 1 || g.work.ObjectExecutionEvictions-evictions != remainingAnswers || g.work.ObjectExecutionEvictedValues-evictedValues != remainingValues || !maps.Equal(escaped, immutable) {
		t.Fatal("fresh reclamation failed to detach answers or reclaimed a live scope")
	}
	callerAssertExecutionRetention(t, c, pin)
	releasePin()
	callerAssertExecutionRetention(t, c, nil)
	if c.entries != 0 || c.weight != 0 || c.active != 0 || !maps.Equal(escaped, immutable) {
		t.Fatal("last real hold did not release the complete snapshot account")
	}
}

func TestCallerIdentityFreshReclamationDisabledOwner(t *testing.T) {
	g, _, _, pin, escaped, immutable, releasePin := callerFillFreshReclamation(t)
	c := g.objectExecutions
	entries, units, answers, evictions := c.entries, c.weight, len(c.answers), g.work.ObjectExecutionEvictions
	g.resetCallerObjectExecutions()
	g.resetCallerObjectExecutions()
	if c.admit(g, 1, callerObjectExecutionValues, false) || g.objectExecutions != c || c.graph != nil || c.active != 1 || c.entries != entries || c.weight != units || len(c.answers) != answers || g.work.ObjectExecutionEvictions != evictions {
		t.Fatal("disabled repeated-reset owner reclaimed or replaced the live account")
	}
	callerAssertExecutionRetention(t, c, pin)
	releasePin()
	if c.active != 0 || c.entries != entries || c.weight != units || !maps.Equal(escaped, immutable) {
		t.Fatal("disabled drain changed the B1 account or escaped result")
	}
	callerAssertExecutionRetention(t, c, nil)
	g.resetCallerObjectExecutions()
	if g.objectExecutions == c || g.objectExecutions.entries != 0 || g.objectExecutions.weight != 0 {
		t.Fatal("idle reset failed to create a fresh bounded owner")
	}
}

func TestCallerIdentityFreshReclamationCancellation(t *testing.T) {
	for _, mode := range []string{"cancelled", "opaque_delayed"} {
		t.Run(mode, func(t *testing.T) {
			type point struct {
				raw   int
				marks [4]uint64
			}
			type observation struct {
				answer  map[callerObjectKey]bool
				unknown bool
				marks   [4]uint64
				raw     int
				trace   []point
			}
			// Один typed program нужен обеим сторонам для точного равенства ключей.
			g, reference, roots, _, escaped, immutable, releasePin := callerFillFreshReclamation(t)
			releasePin()
			run := func(g *callerGraph, original bool) observation {
				c := g.objectExecutions
				if original {
					c = nil
				}
				// Перед отменой выполняется настоящий query; optional publication
				// может получить отказ. Обе стороны уже прошли реальное давление.
				g.callerObjects(roots[0], map[callerObjectSourceID]bool{})
				marks, raw := callerReuseMarks(g), g.work.ObjectRawEvaluations
				evictions, hits, stores := g.work.ObjectExecutionEvictions, g.work.ObjectExecutionHits, g.work.ObjectExecutionStores
				entries, units := 0, 0
				if c != nil {
					entries, units = c.entries, c.weight
				}
				var out observation
				calls := 0
				if mode == "cancelled" {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					g.ctx = ctx
				} else {
					g.ctx = &callerTraceDelayedContext{Context: context.Background(), step: func() error {
						calls++
						out.trace = append(out.trace, point{g.work.ObjectRawEvaluations - raw, callerReuseDelta(g, marks)})
						if calls >= 3 {
							return context.Canceled
						}
						return nil
					}}
				}
				out.answer, out.unknown = g.callerObjects(roots[0], map[callerObjectSourceID]bool{})
				out.raw, out.marks = g.work.ObjectRawEvaluations-raw, callerReuseDelta(g, marks)
				if mode == "opaque_delayed" && calls < 3 || !out.unknown || g.work.ObjectExecutionEvictions != evictions || g.work.ObjectExecutionHits != hits || g.work.ObjectExecutionStores != stores || c != nil && (c.entries != entries || c.weight != units) {
					t.Fatal("cancellation changed optional ownership or bypassed original Err checkpoints")
				}
				if c != nil {
					callerAssertExecutionRetention(t, c, nil)
				}
				return out
			}
			got, want := run(g, false), run(reference, true)
			if got.unknown != want.unknown || !maps.Equal(got.answer, want.answer) || got.raw != want.raw || got.marks != want.marks || !reflect.DeepEqual(got.trace, want.trace) || !maps.Equal(escaped, immutable) {
				t.Fatal("fresh reclamation changed cancellation semantics or actual opaque Err trace")
			}
		})
	}
}
