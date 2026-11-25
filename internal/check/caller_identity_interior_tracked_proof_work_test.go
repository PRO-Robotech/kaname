// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"maps"
	"testing"
)

// This runner observes real production/manual executions. It never changes
// answers, work, seen, executing, admission limits or retained records.
func callerInteriorProofRun(t *testing.T, g *callerGraph, root valueSrc, pin *callerObjectExecutionScope, manual bool) (callerOwnedChainResult, int) {
	t.Helper()
	before, marks := g.work, callerReuseMarks(g)
	seen := map[callerObjectSourceID]bool{}
	var out callerOwnedChainResult
	if manual {
		func() {
			chain := g.beginCallerTrace(seen)
			defer g.endCallerTrace(chain)
			if chain == nil || chain.executing {
				t.Fatal("manual reference lacks its open real chain")
			}
			out.objects, out.unknown, out.owned = g.callerObjectsTracked(root, seen, chain)
		}()
	} else {
		out.objects, out.unknown, out.owned = g.callerObjectsOwnedScope(root, seen, pin)
	}
	visits := g.work.ObjectScopeTrackedFrameVisits - before.ObjectScopeTrackedFrameVisits
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
	if len(seen) != 0 {
		t.Fatal("real traversal failed to restore seen")
	}
	if c := g.objectExecutions; c != nil {
		active := 0
		if pin != nil {
			active = 1
		}
		if c.active != active || c.traceChains != nil || c.traceFrames != nil {
			t.Fatal("finished traversal retained an active chain, frame or extra ticket")
		}
		callerAssertExecutionRetention(t, c, pin)
	}
	return out, visits
}

// N comes from the typed field stack; B from the root's real source edges.
// The fixture has a pure identifier diamond with one terminal field selector.
func callerInteriorProofShape(t *testing.T, g *callerGraph, root valueSrc) (int, int, callerObjectSourceID) {
	t.Helper()
	n := len(g.fieldQueries)
	v := callerVariable(root.pkg, ast.Unparen(root.expr))
	if v == nil {
		t.Fatal("typed root is not a variable")
	}
	branches := g.sources(v)
	if n != 13 || len(branches) != 2 || branches[0] == branches[1] || len(g.containerScanning) != 2 || len(g.mutationScanning) != 2 {
		t.Fatal("typed nonempty scope or distinct root source edges disappeared")
	}
	for _, ref := range branches {
		if _, ok := ast.Unparen(ref.expr).(*ast.Ident); !ok {
			t.Fatal("root edge is no longer a transparent identifier")
		}
	}
	selector := callerObjectSourceID(0)
	for key, id := range g.objectSourceIDs {
		if _, ok := ast.Unparen(key.source.expr).(*ast.SelectorExpr); ok {
			if selector != 0 && selector != id {
				t.Fatal("typed fixture has more than one terminal selector")
			}
			selector = id
		}
	}
	before := g.work.ObjectScopeTrackedFrameVisits
	if selector == 0 || !g.callerExecutionScopeTracked() || g.work.ObjectScopeTrackedFrameVisits-before != n {
		t.Fatal("real structural proof did not visit every typed frame exactly once")
	}
	return n, len(branches), selector
}

func TestCallerIdentityInteriorTrackedSingleProofWarm(t *testing.T) {
	for _, mode := range []string{"lookup", "handoff"} {
		for _, unknown := range []bool{false, true} {
			name := mode + "/known"
			if unknown {
				name = mode + "/unknown"
			}
			t.Run(name, func(t *testing.T) {
				fast, manual, root := callerPinnedScopePair(t)
				slow, slowRoot := callerInheritedScopeGraph(t, fast.p)
				slow.objectExecutions = nil
				for _, g := range []*callerGraph{fast, manual, slow} {
					g.fieldQueries[0].unknown = unknown
				}
				n, branches, _ := callerInteriorProofShape(t, fast, root)
				a, _ := callerInteriorProofRun(t, fast, root, nil, false)
				b, _ := callerInteriorProofRun(t, manual, root, nil, true)
				callerOwnedChainEqual(t, a, b)
				if a.hits == 0 || a.stores < branches || len(a.objects) == 0 {
					t.Fatal("warmup did not produce real retained interior answers")
				}
				escaped := maps.Clone(a.objects)
				c := fast.objectExecutions
				var pin *callerObjectExecutionScope
				if mode == "handoff" {
					pin = c.scope(fast)
					if pin == nil || !pin.snapshot.matches(fast) {
						t.Fatal("real retained scope could not acquire an outer pin")
					}
					defer c.releaseTicket(fast, pin)
				}
				snapshot, state := fast.callerExecutionSnapshot(), fast.callerObjectExecutionState()
				before := fast.work
				got, visits := callerInteriorProofRun(t, fast, root, pin, false)
				full, fullVisits := callerInteriorProofRun(t, manual, root, nil, true)
				want, _ := callerInteriorProofRun(t, slow, slowRoot, nil, false)
				callerOwnedChainEqual(t, got, full)
				if got.unknown != unknown || want.unknown != unknown || !maps.Equal(got.objects, want.objects) || got.marks != want.marks || !maps.Equal(a.objects, escaped) || !maps.Equal(got.objects, escaped) {
					t.Fatal("warm interior changed objects, UNKNOWN, marks or an escaped answer")
				}
				if got.raw != 1 || got.queries != branches || got.hits != branches || got.stores != 0 || got.evictions != 0 || got.capacity != 0 || want.raw <= got.raw || got.marks[0] <= got.marks[1] || got.marks[2] != 0 {
					t.Fatal("measurement is not one raw root with real hits at every typed source edge")
				}
				handoffs := 0
				if mode == "handoff" {
					handoffs = 1
				}
				if fast.work.ObjectScopeHandoffs-before.ObjectScopeHandoffs != handoffs || fast.work.ObjectExecutionHits != before.ObjectExecutionHits || fast.work.ObjectExecutionStores != before.ObjectExecutionStores || fast.callerObjectExecutionState() != state || !snapshot.matches(fast) {
					t.Fatal("wrong handoff branch, fresh execution activity or changed exact scope/state")
				}
				// An open manual chain must still prove entry and post-Err hit
				// structure. Removing that final proof is not this optimization.
				if fullVisits < 2*n*branches {
					t.Fatal("manual reference skipped its independent post-checkpoint scope proof")
				}
				callerAssertExecutionRetention(t, c, pin)
				t.Logf("semantic checks passed: mode=%s unknown=%v frames=%d rootEdges=%d visits=%d manualVisits=%d raw=%d hits=%d marks=%v", mode, unknown, n, branches, visits, fullVisits, got.raw, got.hits, got.marks)
				// Every root edge has no live trace parent. Its entry needs one
				// proof; cached acquisition before the hit checkpoint needs none.
				if visits != n*branches {
					t.Fatalf("redundant interior tracked proof: visits=%d want=%d frames=%d rootEdges=%d", visits, n*branches, n, branches)
				}
			})
		}
	}
}

func TestCallerIdentityInteriorTrackedSingleProofCold(t *testing.T) {
	fast, manual, root := callerPinnedScopePair(t)
	slow, slowRoot := callerInheritedScopeGraph(t, fast.p)
	slow.objectExecutions = nil
	n, branches, selector := callerInteriorProofShape(t, fast, root)
	c := fast.objectExecutions
	if c.entries != 0 || len(c.scopes) != 0 || c.traceRecords != nil {
		t.Fatal("cold lookup already has a scope or trace answer")
	}
	snapshot, state := fast.callerExecutionSnapshot(), fast.callerObjectExecutionState()
	before := fast.work
	got, visits := callerInteriorProofRun(t, fast, root, nil, false)
	full, _ := callerInteriorProofRun(t, manual, root, nil, true)
	want, _ := callerInteriorProofRun(t, slow, slowRoot, nil, false)
	callerOwnedChainEqual(t, got, full)
	if got.unknown || want.unknown || len(got.objects) == 0 || !maps.Equal(got.objects, want.objects) || got.marks != want.marks || got.marks[0] <= got.marks[1] || got.marks[2] != 0 {
		t.Fatal("cold traversal changed typed answer, UNKNOWN or semantic marks")
	}
	if got.stores < branches || got.hits == 0 || got.queries <= branches || got.raw >= want.raw || got.evictions != 0 || got.capacity != 0 || fast.work.ObjectScopeHandoffs != before.ObjectScopeHandoffs || fast.work.ObjectExecutionHits != before.ObjectExecutionHits || fast.callerObjectExecutionState() != state || !snapshot.matches(fast) {
		t.Fatal("cold traversal lacks real nested reuse in an unchanged scope")
	}
	nodes, selectorRecords := 0, 0
	for _, head := range c.scopes {
		for node := head; node != nil; node = node.next {
			nodes++
			if !node.snapshot.matches(fast) {
				t.Fatal("cold allocation published an inexact snapshot")
			}
		}
	}
	for record := c.traceRecords; record != nil; record = record.next {
		if record.source == selector {
			selectorRecords++
			if record.phase != callerTraceRetained || record.scopeIndependent || record.ticket || !record.holdsScope {
				t.Fatal("terminal field did not produce a real scope-dependent retained trace")
			}
		}
	}
	if nodes != 1 || selectorRecords != 1 {
		t.Fatal("typed cold witness lacks one shared scope and one terminal selector")
	}
	escaped := maps.Clone(got.objects)
	again, _ := callerInteriorProofRun(t, fast, root, nil, false)
	if !maps.Equal(got.objects, escaped) || !maps.Equal(again.objects, escaped) || again.unknown != got.unknown || again.marks != got.marks || again.hits != branches || again.stores != 0 || again.raw != 1 {
		t.Fatal("cold result was mutated or did not become a real warm replay")
	}
	callerAssertExecutionRetention(t, c, nil)
	// Root's B source edges start sibling spans. All deeper entries inherit
	// their live parent's scope. One actual selector proves duplicate-field
	// admission; one cold allocation needs BOTH post-Err structural proofs.
	bound := n * (branches + 1 + 2)
	t.Logf("semantic checks passed: cold frames=%d rootEdges=%d scopes=%d terminalSelectors=%d visits=%d bound=%d raw=%d hits=%d stores=%d", n, branches, nodes, selectorRecords, visits, bound, got.raw, got.hits, got.stores)
	if visits > bound {
		t.Fatalf("redundant cold interior tracked proof: visits=%d bound=%d frames=%d rootEdges=%d", visits, bound, n, branches)
	}
}
