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

// Каждый q имеет собственное посещаемое чтение x0 справа от присваивания. Общая
// активная граница поля даёт настоящий cut; прогрев обходит все источники,
// поэтому новые IDs и публикации ordinary memo не имитируют вытеснение.
func callerRetainedAdmissionProgram(t *testing.T) *surfaceProgram {
	t.Helper()
	return callerRetainedAdmissionProgramSize(t, 128)
}

func callerRetainedAdmissionProgramSize(t *testing.T, count int) *surfaceProgram {
	t.Helper()
	var body strings.Builder
	body.WriteString("holder:=&Holder{items:[]Box{}};x0:=holder.items;")
	for i := 0; i < count; i++ {
		fmt.Fprintf(&body, "q%d:=x0;_=q%d;", i, i)
	}
	fmt.Fprintf(&body, "_=append(q%d,Box{});", count-1)
	return callerTraceTypedProgram(t, body.String())
}

func callerRetainedAdmissionGraph(t *testing.T, p *surfaceProgram) (*callerGraph, []valueSrc) {
	t.Helper()
	return callerRetainedAdmissionGraphSize(t, p, 128)
}

func callerRetainedAdmissionGraphSize(t *testing.T, p *surfaceProgram, count int) (*callerGraph, []valueSrc) {
	t.Helper()
	g, _, refs := callerTraceTypedGraph(t, p, "q0")
	roots := make([]valueSrc, count)
	for i := range roots {
		roots[i] = refs[fmt.Sprintf("q%d", i)]
		if roots[i].expr == nil {
			t.Fatal("typed admission root is absent")
		}
		g.callerObjectsOwned(roots[i], map[callerObjectSourceID]bool{})
	}
	g.resetCallerObjectExecutions()
	g.ctx = context.Background()
	return g, roots
}

// Число отдельных typed sources превышает физическую ёмкость новых headers
// даже без prefix, снимка и результатов. Давление обязано реально вытеснять.
// Настоящий типизированный путь должен каждый раз сохранить новое чтение и повторить его.
func TestCallerIdentityRetainedAdmissionTypedPressure(t *testing.T) {
	count := callerTracePressureSources()
	p := callerRetainedAdmissionProgramSize(t, count)
	fast, roots := callerRetainedAdmissionGraphSize(t, p, count)
	slow, otherRoots := callerRetainedAdmissionGraphSize(t, p, count)
	slow.objectExecutions = nil
	state, snapshot := fast.callerObjectExecutionState(), fast.callerExecutionSnapshot()
	// Настоящий внешний ticket удерживает этот снимок через все вытеснения.
	pinned := fast.objectExecutions.scope(fast)
	if pinned == nil {
		t.Fatal("real outer scope acquisition failed")
	}
	stores, raw := fast.work.ObjectTraceStores, fast.work.ObjectRawEvaluations
	seenCandidates := map[callerObjectSourceID]bool{}
	var escaped, copyEscaped map[callerObjectKey]bool
	var removed *callerTraceRecord
	for i, root := range roots {
		for attempt := 0; attempt < 2; attempt++ {
			fm, sm := callerReuseMarks(fast), callerReuseMarks(slow)
			fr, sr, hits := fast.work.ObjectRawEvaluations, slow.work.ObjectRawEvaluations, fast.work.ObjectTraceHits
			got, unknown, _ := fast.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
			want, other, _ := slow.callerObjectsOwned(otherRoots[i], map[callerObjectSourceID]bool{})
			delta := callerReuseDelta(fast, fm)
			if unknown != other || !maps.Equal(got, want) || len(got) == 0 || delta != callerReuseDelta(slow, sm) || delta[0] <= delta[1] || delta[2] != 0 || delta[3] != 0 {
				t.Fatal("retained pressure changed the actual answer, unknown or four semantic marks")
			}
			if fast.callerObjectExecutionState() != state || !snapshot.matches(fast) || fast.semanticOverflow {
				t.Fatal("pressure witness changed its exact durable/scope certificate")
			}
			if attempt == 1 && (fast.work.ObjectTraceHits <= hits || fast.work.ObjectRawEvaluations-fr >= slow.work.ObjectRawEvaluations-sr) {
				t.Fatal("newly admitted typed candidate was not replayed with less actual body work")
			}
			callerAssertExecutionRetention(t, fast.objectExecutions, pinned)
		}
		sources := fast.sources(callerVariable(root.pkg, root.expr))
		if len(sources) != 1 {
			t.Fatal("typed candidate is not the single actually traversed RHS")
		}
		id := fast.objectSourceIDs[callerResolveKeyFor(sources[0], true)]
		if id == 0 || seenCandidates[id] {
			t.Fatal("pressure reused a zero or duplicate candidate identity")
		}
		seenCandidates[id] = true
		found := false
		for record := fast.objectExecutions.traceRecords; record != nil; record = record.next {
			if record.phase != callerTraceRetained || record.ticket || record.parent != nil || record.entry != nil || record.chain != nil {
				t.Fatal("idle cache retains a live or ticket-owned trace")
			}
			if record.source == id {
				found = true
				if i == 0 {
					removed, escaped = record, record.objects
					copyEscaped = maps.Clone(escaped)
				}
			}
		}
		if !found {
			t.Fatal("new candidate was refused instead of replacing detached retained storage")
		}
	}
	c := fast.objectExecutions
	if fast.work.ObjectTraceStores-stores < len(roots) || len(seenCandidates) < callerTracePressureSources() || fast.work.ObjectTraceEvictions == 0 || fast.work.ObjectTraceEvictedValues < (callerTraceRecordUnits+callerTraceGuardUnits)*fast.work.ObjectTraceEvictions || fast.work.ObjectRawEvaluations <= raw || c.active != 1 {
		t.Fatal("work witness did not exceed actual physical retained capacity through real executions")
	}
	if removed == nil || removed.next != nil || removed.parent != nil || removed.entry != nil || removed.chain != nil || removed.scope != nil || removed.guard != nil || removed.ctx != nil || removed.objects != nil || removed.pending != nil || removed.holdsScope || removed.resultReserved || removed.ticket || !maps.Equal(escaped, copyEscaped) || len(escaped) == 0 {
		t.Fatal("evicted record still retains cache storage or mutated its escaped readonly map")
	}
	// Невозможная заявка не должна разрушать полезный кеш до отказа.
	entries, units, evictions, head := c.entries, c.weight, fast.work.ObjectTraceEvictions, c.traceRecords
	for _, request := range [][3]int{{1, callerObjectExecutionValues + 1, 0}, {callerObjectExecutionEntries + 1, 0, 0}, {1, callerObjectExecutionValues, 1}} {
		if c.admit(fast, request[0], request[1], request[2] != 0) || c.entries != entries || c.weight != units || fast.work.ObjectTraceEvictions != evictions || c.traceRecords != head {
			t.Fatal("intrinsically impossible admission destroyed retained certificates")
		}
	}
	callerAssertExecutionRetention(t, c, pinned)
	// Заявка укладывается в общие пределы, но не вместе с живым ticket.
	// Все необязательные записи могут уйти; сам снимок и его учёт обязаны остаться.
	if c.admit(fast, callerObjectExecutionEntries, callerObjectExecutionValues, false) || c.active != 1 || pinned.references != 1 || c.traceRecords != nil || c.entries != 1 || c.weight != pinned.weight {
		t.Fatal("admission reclaimed pinned scope storage to satisfy an impossible live combination")
	}
	callerAssertExecutionRetention(t, c, pinned)
	c.releaseTicket(fast, pinned)
	if c.active != 0 || c.entries != 0 || c.weight != 0 {
		t.Fatal("real final ticket did not drain its scope")
	}
	callerAssertExecutionRetention(t, c, nil)
}

// Это отдельная проверка настоящего протокола begin/end, не типизированный обход.
// Весь учёт создан обычным begin, без присвоения account/active.
func TestCallerIdentityRetainedAdmissionLiveAndReset(t *testing.T) {
	p := callerTraceTypedProgram(t, callerTraceDiamondBody(3))
	g, root, _ := callerTraceTypedGraph(t, p, "x3")
	slow, other, _ := callerTraceTypedGraph(t, p, "x3")
	g.ctx, slow.ctx = context.Background(), context.Background()
	slow.objectExecutions = nil
	c := g.objectExecutions
	var chains []*callerTraceChain
	var residual *callerObjectExecutionScope
	// Даже ранний Fatal освобождает только действительно полученные билеты.
	defer func() {
		if residual != nil {
			c.releaseTicket(g, residual)
		}
		for i := len(chains) - 1; i >= 0; i-- {
			g.endCallerTrace(chains[i])
		}
	}()
	if len(c.scopes) != 0 || len(c.answers) != 0 {
		t.Fatal("all-live fixture already contains optional scope/answer storage")
	}
	for len(chains) < callerObjectExecutionEntries {
		chain := g.beginCallerTrace(map[callerObjectSourceID]bool{})
		if chain == nil {
			break
		}
		chains = append(chains, chain)
	}
	// Реальный стек содержит один query/field/ref. Полный chain9 оплачивает
	// borrowed pointer отдельно от frame8; остаток определяется этим layout.
	// Размер берём из фактического снимка, не из константы старого представления.
	original := g.callerExecutionSnapshot()
	scopeUnits := 1 + len(original.queries) + len(original.heads) + len(original.containers) + len(original.mutations)
	for _, query := range original.queries {
		scopeUnits += len(query.fields) + len(query.refs)
	}
	if len(original.queries) != 1 || len(g.fieldQueryHeads) != 1 || len(original.queries[0].fields) != 1 || len(original.queries[0].refs) != 1 || len(original.containers) != 0 || len(original.mutations) != 0 || !original.matches(g) {
		t.Fatal("typed all-live fixture lost its concrete one-field snapshot")
	}
	chainEntries, chainUnits, chainRefs := callerTraceAccount(t, c)
	if len(chains) != (callerObjectExecutionValues-callerTraceHeaderUnits)/9 || chainEntries != 1+len(chains) || chainUnits != callerTraceHeaderUnits+len(chains)*9 || len(chainRefs) != 0 || c.entries != chainEntries || c.weight != chainUnits || c.active != len(chains) || c.traceRecords != nil || g.work.ObjectTraceCapacityFallbacks == 0 {
		t.Fatal("all-live chain occupancy was fabricated or did not reach admission refusal")
	}
	roomBefore := c.room(scopeUnits)
	func() {
		unknown := g.fieldQueries[0].unknown
		defer func() { g.fieldQueries[0].unknown = unknown }()
		g.fieldQueries[0].unknown = !unknown
		// Это другой exact context того же typed поля. Его настоящий ticket
		// заполняет остаток, если новый компактный снимок туда помещается.
		residual = c.scope(g)
	}()
	pinned := 0
	if residual != nil {
		pinned = 1
		if !roomBefore || residual.weight != scopeUnits || residual.references != 1 || residual.snapshot.matches(g) {
			t.Fatal("residual ticket does not own a distinct exact snapshot of the expected size")
		}
	} else if roomBefore {
		t.Fatal("real residual acquisition refused despite available room")
	}
	if !original.matches(g) || c.entries != chainEntries+pinned || c.weight != chainUnits+pinned*scopeUnits || c.active != len(chains)+pinned {
		t.Fatal("residual acquisition changed the original state or fabricated retained ownership")
	}
	callerAssertExecutionRetention(t, c, residual)
	fallbacks := g.work.ObjectExecutionCapacityFallbacks
	if unexpected := c.scope(g); unexpected != nil {
		c.releaseTicket(g, unexpected)
		t.Fatal("original uncached scope was admitted while all available storage was pinned")
	}
	if c.room(scopeUnits) || g.work.ObjectExecutionCapacityFallbacks != fallbacks+1 || g.work.ObjectTraceEvictions != 0 || g.work.ObjectExecutionEvictions != 0 || c.active != len(chains)+pinned {
		t.Fatal("all-live scope refusal was waived, reclaimed live storage or lost a ticket")
	}
	fm, sm := callerReuseMarks(g), callerReuseMarks(slow)
	got, unknown, _ := g.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	want, otherUnknown, _ := slow.callerObjectsOwned(other, map[callerObjectSourceID]bool{})
	if unknown != otherUnknown || !maps.Equal(got, want) || len(got) == 0 || callerReuseDelta(g, fm) != callerReuseDelta(slow, sm) {
		t.Fatal("all-live refusal changed original typed execution")
	}
	callerAssertExecutionRetention(t, c, residual)
	entries, units := c.entries, c.weight
	g.resetCallerObjectExecutions()
	g.resetCallerObjectExecutions()
	if g.objectExecutions != c || c.graph != nil || c.entries != entries || c.weight != units || c.admit(g, 1, 1, false) {
		t.Fatal("repeated live reset created a second account or admitted a disabled owner")
	}
	if residual != nil {
		released := residual
		c.releaseTicket(g, released)
		residual = nil
		if released.references != 0 {
			t.Fatal("disabled residual ticket did not release its real hold")
		}
	}
	for i := len(chains) - 1; i >= 0; i-- {
		g.endCallerTrace(chains[i])
	}
	chains = nil
	if c.active != 0 || c.entries != entries || c.weight != units || g.work.ObjectTraceEvictions != 0 {
		t.Fatal("B1 disabled account changed before idle reset or failed to drain")
	}
	callerAssertExecutionRetention(t, c, nil)
	g.resetCallerObjectExecutions()
	if g.objectExecutions == c || g.objectExecutions.entries != 0 || g.objectExecutions.weight != 0 {
		t.Fatal("idle reset did not create a fresh bounded namespace")
	}
}

func TestCallerIdentityRetainedAdmissionCancellation(t *testing.T) {
	for _, mode := range []string{"cancelled", "opaque_delayed"} {
		t.Run(mode, func(t *testing.T) {
			count := callerTracePressureSources()
			p := callerRetainedAdmissionProgramSize(t, count)
			type point struct {
				raw   int
				marks [4]uint64
			}
			type result struct {
				answer  map[callerObjectKey]bool
				unknown bool
				marks   [4]uint64
				raw     int
				trace   []point
			}
			run := func(reference bool) result {
				g, roots := callerRetainedAdmissionGraphSize(t, p, count)
				for _, root := range roots {
					g.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
				}
				if g.work.ObjectTraceEvictions == 0 {
					t.Fatal("cancellation twin did not begin with actual retained pressure")
				}
				c := g.objectExecutions
				if reference {
					g.objectExecutions = nil
				}
				marks, raw := callerReuseMarks(g), g.work.ObjectRawEvaluations
				evictions, hits, stores := g.work.ObjectTraceEvictions, g.work.ObjectTraceHits, g.work.ObjectTraceStores
				entries, units := c.entries, c.weight
				var out result
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
				out.answer, out.unknown = g.callerObjects(roots[len(roots)-1], map[callerObjectSourceID]bool{})
				out.raw, out.marks = g.work.ObjectRawEvaluations-raw, callerReuseDelta(g, marks)
				if mode == "opaque_delayed" && calls < 3 || !out.unknown || g.work.ObjectTraceEvictions != evictions || g.work.ObjectTraceHits != hits || g.work.ObjectTraceStores != stores || c.entries != entries || c.weight != units {
					t.Fatal("cancellation changed retained ownership or bypassed the actual delayed Err")
				}
				callerAssertExecutionRetention(t, c, nil)
				return out
			}
			got, want := run(false), run(true)
			if got.unknown != want.unknown || !maps.Equal(got.answer, want.answer) || got.raw != want.raw || got.marks != want.marks || !reflect.DeepEqual(got.trace, want.trace) {
				t.Fatal("admission changed original cancellation checkpoints, raw points or semantic result")
			}
		})
	}
}
