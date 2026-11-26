// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"maps"
	"slices"
	"testing"
)

// Один настоящий typed граф даёт одинаковые source identities обоим решениям.
// Прогрев fixture не создаёт fresh answers и не внедряет work/seen/effects.
func callerPinnedScopePair(t *testing.T) (*callerGraph, *callerGraph, valueSrc) {
	t.Helper()
	p := callerInheritedScopeProgram(t)
	a, root := callerInheritedScopeGraph(t, p)
	b, _ := callerInheritedScopeGraph(t, p)
	for _, g := range []*callerGraph{a, b} {
		id := g.objectSourceIDs[callerResolveKeyFor(root, true)]
		_, complete := g.initialObjectMemo[id]
		if id == 0 || complete || g.objectMemo == nil || g.initialObjectMemo == nil || g.objectMemoEpoch != g.bindingEpoch || g.objectExecutions.entries != 0 {
			t.Fatal("typed root is not a warm partial source in an empty execution store")
		}
	}
	return a, b, root
}

func TestCallerIdentityPinnedScopeHandoffProduction(t *testing.T) {
	for _, mode := range []string{"known", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			fast, original, root := callerPinnedScopePair(t)
			if mode == "unknown" {
				fast.fieldQueries[0].unknown, original.fieldQueries[0].unknown = true, true
			}
			snapshot := fast.callerExecutionSnapshot()
			if len(snapshot.queries) != 13 || len(snapshot.containers) != 2 || len(snapshot.mutations) != 2 || !snapshot.matches(fast) {
				t.Fatal("handoff fixture lost its complete nonempty scope")
			}
			fw, ow := fast.work, original.work
			fm, om := callerReuseMarks(fast), callerReuseMarks(original)
			// Именно публичный production dispatcher: fresh lookup → Owned → interior.
			got, unknown := fast.callerObjects(root, map[callerObjectSourceID]bool{})
			want, otherUnknown, _ := original.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
			if len(got) == 0 || unknown != (mode == "unknown") || unknown != otherUnknown || !maps.Equal(got, want) || callerReuseDelta(fast, fm) != callerReuseDelta(original, om) {
				t.Fatal("production handoff changed the typed answer, UNKNOWN or semantic effects")
			}
			if fast.work.ObjectScopeHandoffs-fw.ObjectScopeHandoffs != 1 || original.work.ObjectScopeHandoffs != ow.ObjectScopeHandoffs || fast.work.ObjectExecutionQueries-fw.ObjectExecutionQueries != 1 || fast.work.ObjectExecutionStores-fw.ObjectExecutionStores != 1 || fast.work.ObjectTraceHits == fw.ObjectTraceHits || fast.work.ObjectTraceStores == fw.ObjectTraceStores || fast.work.ObjectRawEvaluations-fw.ObjectRawEvaluations != original.work.ObjectRawEvaluations-ow.ObjectRawEvaluations {
				t.Fatal("real fresh miss did not hand off exactly one scope with unchanged raw work")
			}
			// Каждый элемент раньше входил в повторный scopeHash. Полное matches
			// по-прежнему исполняется; этот нижний предел не является CPU-измерением.
			hashed := len(snapshot.queries)*3 + 2*(len(snapshot.containers)+len(snapshot.mutations))
			for _, query := range snapshot.queries {
				hashed += len(query.fields) + len(query.refs)
			}
			if hashed <= len(snapshot.queries) || callerReuseDelta(fast, fm)[0] <= callerReuseDelta(fast, fm)[1] || !snapshot.matches(fast) {
				t.Fatal("nonempty hash work or the real partial-execution boundary was vacuous")
			}
			t.Logf("one real handoff removes %d full-scope hash inputs; exact content checks remain", hashed)
			for _, g := range []*callerGraph{fast, original} {
				if g.objectExecutions.active != 0 || g.objectExecutions.traceChains != nil || g.objectExecutions.traceFrames != nil {
					t.Fatal("completed handoff retained a live ticket or borrowed chain")
				}
				callerAssertExecutionRetention(t, g.objectExecutions, nil)
			}
			escaped := maps.Clone(got)
			before, marks := fast.work, callerReuseMarks(fast)
			again, againUnknown := fast.callerObjects(root, map[callerObjectSourceID]bool{})
			if againUnknown != unknown || !maps.Equal(again, escaped) || !maps.Equal(got, escaped) || fast.work.ObjectExecutionHits != before.ObjectExecutionHits+1 || fast.work.ObjectScopeHandoffs != before.ObjectScopeHandoffs || fast.work.ObjectRawEvaluations != before.ObjectRawEvaluations || callerReuseDelta(fast, marks) != callerReuseDelta(original, om) {
				t.Fatal("fresh hit changed readonly data/effects or manufactured another handoff")
			}
		})
	}
}

func TestCallerIdentityPinnedScopeHandoffExactSnapshot(t *testing.T) {
	for _, mode := range []string{"refs_order", "refs_content", "unknown", "container_value", "mutation_value", "heads", "previous", "indexed_depth"} {
		t.Run(mode, func(t *testing.T) {
			g, original, root := callerPinnedScopePair(t)
			for _, graph := range []*callerGraph{g, original} {
				first, second := graph.fieldQueries[0].refs[0], graph.fieldQueries[1].refs[0]
				if first == second {
					t.Fatal("snapshot mutation lacks two distinct typed values")
				}
				graph.fieldQueries[0].refs = []valueSrc{first, second}
				queries, heads, depth := slices.Clone(graph.fieldQueries), maps.Clone(graph.fieldQueryHeads), graph.fieldQueryIndexedDepth
				containers, mutations := maps.Clone(graph.containerScanning), maps.Clone(graph.mutationScanning)
				defer func() {
					graph.fieldQueries, graph.fieldQueryHeads, graph.fieldQueryIndexedDepth = queries, heads, depth
					graph.containerScanning, graph.mutationScanning = containers, mutations
				}()
			}
			c := g.objectExecutions
			pin := c.scope(g)
			if pin == nil || !pin.snapshot.matches(g) {
				t.Fatal("old exact snapshot lacks its real outer ticket")
			}
			defer c.releaseTicket(g, pin)
			epoch := g.bindingEpoch
			for _, graph := range []*callerGraph{g, original} {
				first, second := graph.fieldQueries[0].refs[0], graph.fieldQueries[0].refs[1]
				switch mode {
				case "refs_order":
					graph.fieldQueries[0].refs = []valueSrc{second, first}
				case "refs_content":
					graph.fieldQueries[0].refs = []valueSrc{second, second}
				case "unknown":
					graph.fieldQueries[0].unknown = true
				case "container_value":
					for key, value := range graph.containerScanning {
						if !value {
							graph.containerScanning[key] = true
						}
					}
				case "mutation_value":
					for key, value := range graph.mutationScanning {
						if !value {
							graph.mutationScanning[key] = true
						}
					}
				case "heads":
					graph.fieldQueryHeads[graph.fieldQueries[0].source] = len(graph.fieldQueries)
				case "previous":
					graph.fieldQueries[0].previousSourceQuery = 1
				case "indexed_depth":
					graph.fieldQueryIndexedDepth--
				}
			}
			if g.bindingEpoch != epoch || pin.snapshot.matches(g) {
				t.Fatal("same-epoch negative snapshot mutation was vacuous")
			}
			before := g.work.ObjectScopeHandoffs
			gm, om := callerReuseMarks(g), callerReuseMarks(original)
			got, unknown, owned := g.callerObjectsOwnedScope(root, map[callerObjectSourceID]bool{}, pin)
			want, otherUnknown, otherOwned := original.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
			if len(got) == 0 || unknown != otherUnknown || owned != otherOwned || !maps.Equal(got, want) || callerReuseDelta(g, gm) != callerReuseDelta(original, om) || g.work.ObjectScopeHandoffs != before || c.active != 1 || c.traceChains != nil {
				t.Fatal("stale handoff bypassed full snapshot checks or changed fallback ownership")
			}
			for record := c.traceRecords; record != nil; record = record.next {
				if record.scope == pin || !record.scope.snapshot.matches(g) {
					t.Fatal("changed scope published a record against the stale borrowed node")
				}
			}
			callerAssertExecutionRetention(t, c, pin)
		})
	}
}

func TestCallerIdentityPinnedScopeHandoffOwnership(t *testing.T) {
	for _, mode := range []string{"foreign", "released", "reset", "manual", "reentry", "context_identity"} {
		t.Run(mode, func(t *testing.T) {
			g, original, root := callerPinnedScopePair(t)
			c := g.objectExecutions
			owner, graph := c, g
			if mode == "foreign" {
				foreign, _ := callerInheritedScopeGraph(t, g.p)
				owner, graph = foreign.objectExecutions, foreign
			}
			pin := owner.scope(graph)
			if pin == nil || !pin.snapshot.matches(g) {
				t.Fatal("ownership negative lacks a real equal-content scope")
			}
			held := true
			defer func() {
				if held {
					owner.releaseTicket(graph, pin)
				}
			}()
			if mode == "released" {
				owner.releaseTicket(graph, pin)
				held = false
			}
			before := g.work.ObjectScopeHandoffs
			if mode == "manual" || mode == "reentry" || mode == "context_identity" {
				chain := g.beginCallerTrace(map[callerObjectSourceID]bool{})
				if chain == nil || chain.executing {
					t.Fatal("manual constructor granted closed execution")
				}
				chain.entryScope = pin
				if mode == "reentry" {
					g.callerObjects(root, map[callerObjectSourceID]bool{})
					if !chain.bad {
						t.Fatal("production reentry did not taint the suspended chain")
					}
				} else if mode == "context_identity" {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					g.ctx = ctx
					if g.callerTraceValid(chain) {
						t.Fatal("manual chain accepted another exact context")
					}
				}
				afterBody := g.work.ObjectScopeHandoffs
				if c.callerTraceEntryScope(g, chain) != nil || chain.entryScope != nil || g.work.ObjectScopeHandoffs != afterBody {
					t.Fatal("open/reentered chain consumed a borrowed ticket")
				}
				// И B1 exit обязан убрать borrow до последующего release outer pin.
				chain.entryScope = pin
				g.resetCallerObjectExecutions()
				g.endCallerTrace(chain)
				if chain.entryScope != nil || chain.live || c.active != 1 || c.graph != nil {
					t.Fatal("quarantined end retained a borrowed entry scope")
				}
				return
			}
			if mode == "reset" {
				g.resetCallerObjectExecutions()
				if c.graph != nil || g.objectExecutions != c {
					t.Fatal("live reset failed to quarantine the actual ticket owner")
				}
			}
			gm, om := callerReuseMarks(g), callerReuseMarks(original)
			got, unknown, owned := g.callerObjectsOwnedScope(root, map[callerObjectSourceID]bool{}, pin)
			want, otherUnknown, otherOwned := original.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
			if len(got) == 0 || unknown != otherUnknown || owned != otherOwned || !maps.Equal(got, want) || callerReuseDelta(g, gm) != callerReuseDelta(original, om) || g.work.ObjectScopeHandoffs != before || c.traceChains != nil {
				t.Fatal("foreign/released/quarantined scope changed the original typed result")
			}
			if mode == "foreign" && pin.references != 1 || mode == "released" && pin.references != 0 || mode == "reset" && (pin.references != 1 || c.active != 1) {
				t.Fatal("rejected handoff changed another ticket's ownership")
			}
			if mode == "reset" {
				callerAssertExecutionRetention(t, c, pin)
			} else {
				callerAssertExecutionRetention(t, c, nil)
			}
		})
	}
}

func TestCallerIdentityPinnedScopeHandoffContext(t *testing.T) {
	for _, mode := range []string{"nil", "opaque", "opaque_cancel", "standard_cancel"} {
		t.Run(mode, func(t *testing.T) {
			g, original, root := callerPinnedScopePair(t)
			c := g.objectExecutions
			pin := c.scope(g)
			if pin == nil {
				t.Fatal("context boundary has no real prior ticket")
			}
			defer c.releaseTicket(g, pin)
			calls := [2]int{}
			for i, graph := range []*callerGraph{g, original} {
				if mode == "nil" {
					graph.ctx = nil
					continue
				}
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				if mode == "standard_cancel" {
					cancel()
					graph.ctx = ctx
				} else {
					graph.ctx = &callerTraceOpaqueContext{Context: ctx, onErr: func() {
						calls[i]++
						if mode == "opaque_cancel" {
							cancel()
						}
					}}
				}
			}
			before := g.work.ObjectScopeHandoffs
			gm, om := callerReuseMarks(g), callerReuseMarks(original)
			got, unknown, owned := g.callerObjectsOwnedScope(root, map[callerObjectSourceID]bool{}, pin)
			want, otherUnknown, otherOwned := original.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
			if unknown != otherUnknown || owned != otherOwned || !maps.Equal(got, want) || callerReuseDelta(g, gm) != callerReuseDelta(original, om) || calls[0] != calls[1] || g.work.ObjectScopeHandoffs != before || c.active != 1 || c.traceChains != nil {
				t.Fatal("inadmissible context changed checkpoints, effects or borrowed ownership")
			}
			if mode == "opaque" && calls[0] == 0 || mode == "opaque_cancel" && (calls[0] != 1 || !unknown) || mode == "standard_cancel" && !unknown {
				t.Fatal("cancellation/checkpoint negative was vacuous")
			}
			callerAssertExecutionRetention(t, c, pin)
		})
	}
}

func TestCallerIdentityPinnedScopeHandoffWriterBoundary(t *testing.T) {
	for _, mode := range []string{"call", "getter", "field"} {
		t.Run(mode, func(t *testing.T) {
			last := "identity(x2)"
			if mode == "getter" {
				last = "holder.Items()"
			} else if mode == "field" {
				last = "other.items"
			}
			body := "other:=&Holder{items:[]Box{}};_=other;" + callerTraceDiamondBody(2) + "top:=" + last + ";_=top;"
			p := callerSoundnessProgram(t, "type Holder struct{items []Box};func identity(items []Box)[]Box{return items};func(h *Holder)Items()[]Box{return h.items}", body, "&Handler{}")
			t.Cleanup(func() { callerGraphs.Delete(p) })
			g, top, refs := callerTraceTypedGraph(t, p, "top")
			original, _, _ := callerTraceTypedGraph(t, p, "top")
			// Сам typed call/новый field должен стоять до первого interior,
			// поэтому берём настоящий assignment RHS, а не внешний Ident top.
			values := g.sources(callerVariable(top.pkg, top.expr))
			if len(values) != 1 {
				t.Fatal("writer boundary has no unique real assignment RHS")
			}
			root := values[0]
			for _, graph := range []*callerGraph{g, original} {
				graph.ctx = context.Background()
				graph.resetCallerObjectExecutions()
			}
			if mode == "field" {
				// Fixture выбирает последний selector. Для нового поля нужен
				// активный snapshot другого настоящего Holder из того же RPC.
				for _, graph := range []*callerGraph{g, original} {
					fields := graph.fieldQueries[0].fields
					graph.leaveCallerFieldQuery(0)
					index, entered := graph.enterCallerFieldQuery(refs["holder"], fields)
					if !entered || index != 0 {
						t.Fatal("replacement typed field owner was not entered")
					}
					graph.fieldQueries[index].refs, graph.fieldQueries[index].unknown = graph.embeddedCallerSourcesRaw(refs["holder"], fields, map[callerFieldKey]bool{})
				}
			}
			for _, graph := range []*callerGraph{g, original} {
				// Холодный обычный memo гарантирует фактическое выполнение writer,
				// а не ранее завершённый ответ; никаких ответов/marks не внедряется.
				graph.objectMemo, graph.initialObjectMemo = nil, nil
				graph.resetCallerObjectExecutions()
			}
			c := g.objectExecutions
			pin := c.scope(g)
			if pin == nil {
				t.Fatal("writer boundary lacks a real entry scope")
			}
			defer c.releaseTicket(g, pin)
			gm, om := callerReuseMarks(g), callerReuseMarks(original)
			before := g.work
			got, unknown, owned := g.callerObjectsOwnedScope(root, map[callerObjectSourceID]bool{}, pin)
			want, otherUnknown, otherOwned := original.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
			if unknown != otherUnknown || owned != otherOwned || !maps.Equal(got, want) || callerReuseDelta(g, gm) != callerReuseDelta(original, om) || g.work.ObjectScopeHandoffs != before.ObjectScopeHandoffs || c.active != 1 || c.traceChains != nil {
				t.Fatal("writer/field reentry inherited a borrowed scope past taint")
			}
			if mode == "field" && g.work.ContainerCalls == before.ContainerCalls || mode != "field" && g.work.ResolveQueries == before.ResolveQueries {
				t.Fatal("real typed writer path was not reached")
			}
			callerAssertExecutionRetention(t, c, pin)
		})
	}
}
