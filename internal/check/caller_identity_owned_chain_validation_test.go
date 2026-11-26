// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"fmt"
	"maps"
	"testing"
	"unsafe"
)

type callerOwnedChainResult struct {
	objects                   map[callerObjectKey]bool
	unknown, owned            bool
	marks                     [4]uint64
	raw, queries, reads, deps int
	validation, hits, stores  int
	evictions, capacity       int
}

// Эталон исполняет те же typed источники, кеши и push/pop, но ручной begin
// оставляет все проверки стека полными. Результаты и counters не внедряются.
func callerOwnedChainRun(t *testing.T, g *callerGraph, root valueSrc, full bool) callerOwnedChainResult {
	t.Helper()
	before, marks := g.work, callerReuseMarks(g)
	seen := map[callerObjectSourceID]bool{}
	var out callerOwnedChainResult
	if full {
		func() {
			chain := g.beginCallerTrace(seen)
			defer g.endCallerTrace(chain)
			if chain != nil && chain.executing {
				t.Fatal("manual begin granted closed execution")
			}
			out.objects, out.unknown, out.owned = g.callerObjectsTracked(root, seen, chain)
		}()
	} else {
		out.objects, out.unknown, out.owned = g.callerObjectsOwned(root, seen)
	}
	if len(seen) != 0 {
		t.Fatal("root did not restore its input seen map")
	}
	out.marks = callerReuseDelta(g, marks)
	out.raw = g.work.ObjectRawEvaluations - before.ObjectRawEvaluations
	out.queries = g.work.ObjectTraceQueries - before.ObjectTraceQueries
	out.reads = g.work.ObjectTraceSeenReads - before.ObjectTraceSeenReads
	out.deps = g.work.ObjectTraceDependencySteps - before.ObjectTraceDependencySteps
	out.validation = g.work.ObjectTraceValidationSteps - before.ObjectTraceValidationSteps
	out.hits = g.work.ObjectTraceHits - before.ObjectTraceHits
	out.stores = g.work.ObjectTraceStores - before.ObjectTraceStores
	out.evictions = g.work.ObjectTraceEvictions - before.ObjectTraceEvictions
	out.capacity = g.work.ObjectTraceCapacityFallbacks - before.ObjectTraceCapacityFallbacks
	if c := g.objectExecutions; c != nil {
		if c.active != 0 || c.traceChains != nil || c.traceFrames != nil {
			t.Fatal("closed execution retained a live owner or frame")
		}
		callerAssertExecutionRetention(t, c, nil)
	}
	return out
}

func callerOwnedChainEqual(t *testing.T, a, b callerOwnedChainResult) {
	t.Helper()
	if !maps.Equal(a.objects, b.objects) || a.unknown != b.unknown || a.owned != b.owned || a.marks != b.marks {
		t.Fatalf("owned-stack validation changed the answer or semantic marks: fast=%+v full=%+v", a, b)
	}
	if a.raw != b.raw || a.queries != b.queries || a.reads != b.reads || a.hits != b.hits || a.stores != b.stores || a.evictions != b.evictions || a.capacity != b.capacity {
		t.Fatalf("work outside stack validation changed: fast=%+v full=%+v", a, b)
	}
	// Закрытый путь может закончить повторную передачу predicate раньше.
	// Остальные work/semantic поля выше равны; строгую экономию для depth4/6/8
	// отдельно требует неизменённый OwnedDependencyPropagationWork из RED r2.
	if a.deps > b.deps {
		t.Fatalf("owned dependency propagation exceeded manual work: fast=%d full=%d", a.deps, b.deps)
	}
}

func TestCallerIdentityOwnedChainValidationProductionWork(t *testing.T) {
	if !callerTraceContext(context.Background()) {
		t.Fatal("test requires the source-pinned standard context admission")
	}
	if unsafe.Sizeof(callerTraceChain{}) > 9*8 || unsafe.Sizeof(callerTraceFrame{}) > 8*8 || unsafe.Sizeof(callerTraceRecord{}) > 146*8 || unsafe.Sizeof(callerTraceGuard{}) > 24*8 {
		t.Fatal("closed execution exceeded existing physical reservations")
	}
	for _, depth := range []int{4, 6, 8} {
		t.Run(fmt.Sprintf("depth_%d", depth), func(t *testing.T) {
			p := callerTraceTypedProgram(t, callerTraceDiamondBody(depth))
			name := fmt.Sprintf("x%d", depth)
			fast, root, _ := callerTraceTypedGraph(t, p, name)
			full, _, _ := callerTraceTypedGraph(t, p, name)
			fast.ctx, full.ctx = context.Background(), context.Background()
			a := callerOwnedChainRun(t, fast, root, false)
			b := callerOwnedChainRun(t, full, root, true)
			callerOwnedChainEqual(t, a, b)
			if a.raw == 0 || a.queries == 0 || a.reads == 0 || a.hits == 0 || a.stores == 0 {
				t.Fatal("typed recursive trace path was not exercised")
			}
			// Уже один глубокий путь содержит эту нижнюю границу снятых
			// повторных проверок предков; прочая trace-работа у близнецов равна.
			if b.validation-a.validation < depth*(depth-1) {
				t.Fatalf("whole ancestor walks remain: fast=%d full=%d depth=%d", a.validation, b.validation, depth)
			}
			borrowed := maps.Clone(a.objects)
			a2 := callerOwnedChainRun(t, fast, root, false)
			b2 := callerOwnedChainRun(t, full, root, true)
			callerOwnedChainEqual(t, a2, b2)
			if !maps.Equal(a.objects, borrowed) || !maps.Equal(a2.objects, borrowed) {
				t.Fatal("later trace reuse mutated an earlier result")
			}
		})
	}
}

func TestCallerIdentityOwnedChainValidationExposedStack(t *testing.T) {
	for _, mode := range []string{"false_ancestor", "swapped_ancestor", "false_extra", "foreign_ancestor", "dead_ancestor", "context_identity", "reentry", "reset"} {
		t.Run(mode, func(t *testing.T) {
			p := callerTraceTypedProgram(t, callerTraceDiamondBody(4))
			g, root, refs := callerTraceTypedGraph(t, p, "x4")
			g.ctx = context.Background()
			bottomID := g.internObjectSource(refs["x0"])
			topID := g.internObjectSource(refs["x1"])
			extraID := g.internObjectSource(refs["r1"])
			if bottomID == topID || bottomID == extraID || topID == extraID {
				t.Fatal("typed sources are not distinct")
			}
			seen := map[callerObjectSourceID]bool{}
			chain := g.beginCallerTrace(seen)
			if chain == nil || chain.executing {
				t.Fatal("manual owner admission changed")
			}
			c := g.objectExecutions
			disabledEntries, disabledUnits := -1, -1
			defer func() {
				if chain.live || chain.executing || c.active != 0 || len(seen) != 0 {
					t.Fatal("manual owner failed to drain")
				}
				if disabledEntries >= 0 && (c.entries != disabledEntries || c.weight != disabledUnits) {
					t.Fatal("B1 drain uncharged quarantined metadata")
				}
				callerAssertExecutionRetention(t, c, nil)
			}()
			defer g.endCallerTrace(chain)
			bottom := g.callerTracePush(chain, bottomID)
			if bottom == nil {
				t.Fatal("bottom reservation failed")
			}
			seen[bottomID] = true
			defer func() { delete(seen, bottomID); g.callerTracePop(chain, bottom) }()
			top := g.callerTracePush(chain, topID)
			if top == nil {
				t.Fatal("top reservation failed")
			}
			seen[topID] = true
			defer func() { delete(seen, topID); g.callerTracePop(chain, top) }()
			if chain.executing || !g.callerTraceExecutionValid(chain) || !g.callerTraceValid(chain) {
				t.Fatal("manual push either granted closed execution or broke the full stack")
			}
			callerAssertExecutionRetention(t, c, nil)
			undo := func() {}
			defer func() { undo() }()
			switch mode {
			case "false_ancestor":
				seen[bottomID] = false
				undo = func() { seen[bottomID] = true }
			case "swapped_ancestor":
				delete(seen, bottomID)
				seen[extraID] = true
				undo = func() { delete(seen, extraID); seen[bottomID] = true }
			case "false_extra":
				seen[extraID] = false
				undo = func() { delete(seen, extraID) }
			case "foreign_ancestor":
				bottom.chain = &callerTraceChain{}
				undo = func() { bottom.chain = chain }
			case "dead_ancestor":
				bottom.live = false
				undo = func() { bottom.live = true }
			case "context_identity":
				other, cancel := context.WithCancel(context.Background())
				defer cancel()
				g.ctx = other
				undo = func() { g.ctx = context.Background() }
			case "reentry":
				g.callerObjects(root, map[callerObjectSourceID]bool{})
			case "reset":
				entries, units, active := c.entries, c.weight, c.active
				g.resetCallerObjectExecutions()
				g.resetCallerObjectExecutions()
				if g.objectExecutions != c || c.graph != nil || c.entries != entries || c.weight != units || c.active != active {
					t.Fatal("reset lost the live B1 account")
				}
				disabledEntries, disabledUnits = c.entries, c.weight
			}
			// В первых двух вариантах длина и исправная вершина сохранены:
			// отказ требует полного просмотра открытого внешнему коду предка.
			if g.callerTraceExecutionValid(chain) || !chain.bad || g.callerTraceValid(chain) {
				t.Fatal("exposed ancestor or hostile lifecycle boundary was accepted")
			}
			undo()
			undo = func() {}
			if g.callerTraceExecutionValid(chain) || g.callerTraceValid(chain) || chain.executing {
				t.Fatal("restoration erased sticky taint or granted execution")
			}
			callerAssertExecutionRetention(t, c, nil)
		})
	}
}

func TestCallerIdentityOwnedChainValidationContextCheckpoints(t *testing.T) {
	for _, mode := range []string{"nil", "opaque", "opaque_cancel", "standard_cancel"} {
		t.Run(mode, func(t *testing.T) {
			p := callerTraceTypedProgram(t, callerTraceDiamondBody(4))
			fast, root, _ := callerTraceTypedGraph(t, p, "x4")
			full, _, _ := callerTraceTypedGraph(t, p, "x4")
			configure := func(g *callerGraph, calls *int) {
				if mode == "nil" {
					g.ctx = nil
					return
				}
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				if mode == "standard_cancel" {
					cancel()
					g.ctx = ctx
					return
				}
				g.ctx = &callerTraceOpaqueContext{Context: ctx, onErr: func() {
					*calls = *calls + 1
					if c := g.objectExecutions; c != nil {
						for chain := c.traceChains; chain != nil; chain = chain.next {
							if chain.executing {
								t.Fatal("observer-valued Err entered a closed stack")
							}
						}
					}
					if mode == "opaque_cancel" && *calls == 17 {
						cancel()
					}
				}}
			}
			fastCalls, fullCalls := 0, 0
			configure(fast, &fastCalls)
			configure(full, &fullCalls)
			a := callerOwnedChainRun(t, fast, root, false)
			b := callerOwnedChainRun(t, full, root, true)
			callerOwnedChainEqual(t, a, b)
			if fastCalls != fullCalls || a.validation != b.validation || a.queries != 0 || a.hits != 0 || a.stores != 0 {
				t.Fatalf("context checkpoints or trace admission changed: calls=%d/%d fast=%+v full=%+v", fastCalls, fullCalls, a, b)
			}
			if mode == "opaque" && fastCalls == 0 || mode == "opaque_cancel" && (fastCalls < 17 || !a.unknown) || mode == "standard_cancel" && (!a.unknown || a.raw != 0) {
				t.Fatal("context boundary was not exercised")
			}
		})
	}
}
