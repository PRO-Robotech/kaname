// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"maps"
	"slices"
	"testing"
)

func TestCallerIdentityOwnedScopeProofTypedContinuation(t *testing.T) {
	p := callerInheritedScopeProgram(t)
	fast, root := callerInheritedScopeGraph(t, p)
	full, other := callerInheritedScopeGraph(t, p)
	snapshot := fast.callerExecutionSnapshot()
	if !callerTraceContext(fast.ctx) || len(snapshot.queries) != 13 || len(snapshot.containers) != 2 || len(snapshot.mutations) != 2 || !snapshot.matches(fast) {
		t.Fatal("typed continuation lacks its nonempty exact scope")
	}
	payload := len(snapshot.queries) + len(snapshot.containers) + len(snapshot.mutations)
	for _, query := range snapshot.queries {
		payload += len(query.fields) + len(query.refs)
	}
	a := callerOwnedChainRun(t, fast, root, false)
	b := callerOwnedChainRun(t, full, other, true)
	callerOwnedChainEqual(t, a, b)
	if len(a.objects) == 0 || a.hits == 0 || a.stores < 2 || a.queries == 0 || a.marks[0] <= a.marks[1] || a.marks[2] != 0 || !snapshot.matches(fast) || !snapshot.matches(full) {
		t.Fatal("typed owned continuation did not exercise real hit and publication guards")
	}
	// Это нижняя SOURCE-граница, а не новый runtime-счётчик: каждый реальный
	// hit и store прошёл соответствующий guard; раньше каждый сравнивал весь
	// неизменный payload. Lookup/dependency steps в эту оценку не включены.
	guardSites := a.hits + a.stores
	if guardSites*payload <= payload || payload <= len(snapshot.queries) {
		t.Fatal("scope comparison work witness is empty")
	}
	t.Logf("source lower bound: %d exact hit/exit matches over %d payload elements", guardSites, payload)
	dependent := false
	for record := fast.objectExecutions.traceRecords; record != nil; record = record.next {
		if record.phase != callerTraceRetained || record.scope == nil || !record.scope.snapshot.matches(fast) {
			t.Fatal("retained continuation lost its exact pinned scope")
		}
		dependent = dependent || !record.scopeIndependent
	}
	if !dependent {
		t.Fatal("duplicate field selector did not reach the scope-dependent path")
	}
	borrowed := maps.Clone(a.objects)
	a2 := callerOwnedChainRun(t, fast, root, false)
	b2 := callerOwnedChainRun(t, full, other, true)
	callerOwnedChainEqual(t, a2, b2)
	if !maps.Equal(a.objects, borrowed) || !maps.Equal(a2.objects, borrowed) {
		t.Fatal("later continuation mutated an earlier borrowed result")
	}
	// Следующий закрытый вход обязан заново доказать content: remember может
	// менять unknown между вызовами без смены bindingEpoch.
	epoch := fast.bindingEpoch
	fast.fieldQueries[0].unknown, full.fieldQueries[0].unknown = true, true
	if fast.bindingEpoch != epoch || snapshot.matches(fast) || snapshot.matches(full) {
		t.Fatal("same-epoch boundary mutation was vacuous")
	}
	changed := fast.callerExecutionSnapshot()
	a3 := callerOwnedChainRun(t, fast, root, false)
	b3 := callerOwnedChainRun(t, full, other, true)
	callerOwnedChainEqual(t, a3, b3)
	if !a3.unknown || !changed.matches(fast) || !changed.matches(full) || !maps.Equal(a.objects, borrowed) {
		t.Fatal("new owned span inherited an old field snapshot or changed an escaped result")
	}
}

func TestCallerIdentityOwnedScopeProofManualBoundaries(t *testing.T) {
	for _, mode := range []string{"refs_order", "refs_content", "unknown", "container_value", "mutation_value", "heads", "previous", "indexed_depth"} {
		t.Run(mode, func(t *testing.T) {
			g, _ := callerInheritedScopeGraph(t, callerInheritedScopeProgram(t))
			first, second := g.fieldQueries[0].refs[0], g.fieldQueries[1].refs[0]
			if first == second {
				t.Fatal("distinct typed field owners have the same source")
			}
			g.fieldQueries[0].refs = []valueSrc{first, second}
			queries, heads, depth := slices.Clone(g.fieldQueries), maps.Clone(g.fieldQueryHeads), g.fieldQueryIndexedDepth
			containers, mutations := maps.Clone(g.containerScanning), maps.Clone(g.mutationScanning)
			defer func() {
				g.fieldQueries, g.fieldQueryHeads, g.fieldQueryIndexedDepth = queries, heads, depth
				g.containerScanning, g.mutationScanning = containers, mutations
			}()
			c := g.objectExecutions
			pin := c.scope(g)
			if pin == nil || !pin.snapshot.matches(g) {
				t.Fatal("manual boundary lacks a real exact scope ticket")
			}
			defer c.releaseTicket(g, pin)
			chain := g.beginCallerTrace(map[callerObjectSourceID]bool{})
			if chain == nil || chain.executing || !g.callerTraceValid(chain) {
				t.Fatal("manual begin granted a closed span or lacked a valid owner")
			}
			defer g.endCallerTrace(chain)
			epoch := g.bindingEpoch
			switch mode {
			case "refs_order":
				g.fieldQueries[0].refs = []valueSrc{second, first}
			case "refs_content":
				g.fieldQueries[0].refs = []valueSrc{second, second}
			case "unknown":
				g.fieldQueries[0].unknown = true
			case "container_value":
				for key, value := range g.containerScanning {
					if !value {
						g.containerScanning[key] = true
					}
				}
			case "mutation_value":
				for key, value := range g.mutationScanning {
					if !value {
						g.mutationScanning[key] = true
					}
				}
			case "heads":
				g.fieldQueryHeads[g.fieldQueries[0].source] = len(g.fieldQueries)
			case "previous":
				g.fieldQueries[0].previousSourceQuery = 1
			case "indexed_depth":
				g.fieldQueryIndexedDepth--
			}
			if g.bindingEpoch != epoch || chain.executing || !g.callerTraceValid(chain) || pin.snapshot.matches(g) {
				t.Fatal("manual same-epoch mutation bypassed the full direct scope guard")
			}
			structural := mode == "heads" || mode == "previous" || mode == "indexed_depth"
			fresh := c.scope(g)
			if structural {
				if fresh != nil || g.callerExecutionScopeTracked() {
					t.Fatal("malformed manual structure acquired a scope ticket")
				}
			} else {
				if fresh == nil || fresh == pin || !fresh.snapshot.matches(g) || pin.snapshot.matches(g) {
					t.Fatal("manual content change reused the old exact scope")
				}
				c.releaseTicket(g, fresh)
			}
			callerAssertExecutionRetention(t, c, pin)
		})
	}
}

func TestCallerIdentityOwnedScopeProofWriterBoundaries(t *testing.T) {
	for _, branch := range []string{"call", "getter", "field"} {
		t.Run(branch, func(t *testing.T) {
			prefix, last := "", "identity(x4)"
			if branch == "getter" {
				last = "holder.Items()"
			} else if branch == "field" {
				prefix = "other:=&Holder{items:[]Box{{reader:Concrete{}}}};outside:=other.items;"
				last = "outside"
			}
			body := prefix + callerTraceDiamondBody(4) + "top:=x4;top=" + last + ";_=append(top,Box{});"
			p := callerSoundnessProgram(t, "type Holder struct{items []Box};func identity(items []Box)[]Box{return items};func(h *Holder)Items()[]Box{return h.items}", body, "&Handler{}")
			t.Cleanup(func() { callerGraphs.Delete(p) })
			fast, root, _ := callerTraceTypedGraph(t, p, "top")
			full, other, _ := callerTraceTypedGraph(t, p, "top")
			for _, g := range []*callerGraph{fast, full} {
				g.objectMemo, g.initialObjectMemo = nil, nil
				g.ctx = context.Background()
			}
			snapshot := fast.callerExecutionSnapshot()
			resolves, containers := fast.work.ResolveQueries, fast.work.ContainerCalls
			a := callerOwnedChainRun(t, fast, root, false)
			b := callerOwnedChainRun(t, full, other, true)
			callerOwnedChainEqual(t, a, b)
			if len(a.objects) == 0 || a.queries < 2 || !snapshot.matches(fast) || !snapshot.matches(full) {
				t.Fatal("writer boundary changed restored scope, answer or nested execution")
			}
			if branch == "field" && fast.work.ContainerCalls == containers || branch != "field" && fast.work.ResolveQueries == resolves {
				t.Fatal("typed writer boundary was not reached")
			}
			callerAssertExecutionRetention(t, fast.objectExecutions, nil)
			callerAssertExecutionRetention(t, full.objectExecutions, nil)
		})
	}
}
