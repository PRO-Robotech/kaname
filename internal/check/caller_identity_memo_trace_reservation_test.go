// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"maps"
	"testing"
)

func callerMemoTraceGraphs(t *testing.T) (*callerGraph, *callerGraph, valueSrc) {
	t.Helper()
	p := callerTraceTypedProgram(t, "value:=&Box{};_=value;")
	a, root, _ := callerTraceTypedGraph(t, p, "value")
	b, _, _ := callerTraceTypedGraph(t, p, "value")
	for _, g := range []*callerGraph{a, b} {
		id := g.objectSourceIDs[callerResolveKeyFor(root, true)]
		answer, ok := g.initialObjectMemo[id]
		if id == 0 || !ok || len(answer.objects) == 0 || answer.unknown || g.objectMemoEpoch != g.bindingEpoch || g.objectExecutions.entries != 0 || g.work.ObjectExecutionPeakEntries != 0 {
			t.Fatal("typed warmup did not produce a complete ordinary memo in an empty trace store")
		}
		g.ctx = context.Background()
	}
	return a, b, root
}

func TestCallerIdentityMemoHitSkipsTraceReservation(t *testing.T) {
	fast, reference, root := callerMemoTraceGraphs(t)
	fm, rm := callerReuseMarks(fast), callerReuseMarks(reference)
	fw, rw := fast.work, reference.work
	got, unknown := fast.callerObjects(root, map[callerObjectSourceID]bool{})
	want, otherUnknown, owned := reference.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	if !maps.Equal(got, want) || unknown != otherUnknown || owned || callerReuseDelta(fast, fm) != callerReuseDelta(reference, rm) || callerReuseDelta(fast, fm) != [4]uint64{1, 1, 0, 0} {
		t.Fatal("complete memo changed the existing answer, ownership or initial boundary")
	}
	if fast.work.ObjectQueries-fw.ObjectQueries != 1 || fast.work.ObjectHits-fw.ObjectHits != 1 || fast.work.ObjectRawEvaluations != fw.ObjectRawEvaluations || reference.work.ObjectHits-rw.ObjectHits != 1 || reference.work.ObjectRawEvaluations != rw.ObjectRawEvaluations || fast.work.ObjectExecutionFallbacks-fw.ObjectExecutionFallbacks != 1 {
		t.Fatal("real production fallback and the original memo twin were not exercised")
	}
	// Оба магазина пусты до запроса. Старый Owned обязан оплатить header21 и
	// chain9, хотя raw не вызывается; новый вход не резервирует их вообще.
	if fast.work.ObjectExecutionPeakEntries != 0 || fast.work.ObjectExecutionPeakValues != 0 || reference.work.ObjectExecutionPeakEntries != 2 || reference.work.ObjectExecutionPeakValues != 30 {
		t.Fatal("complete memo still reserves an unused trace owner")
	}
	before := maps.Clone(got)
	for range 3 {
		fast.callerObjects(root, map[callerObjectSourceID]bool{})
	}
	if !maps.Equal(got, before) || fast.work.ObjectExecutionPeakEntries != 0 {
		t.Fatal("repeated memo mutated a borrowed answer or allocated trace ownership")
	}
	for _, g := range []*callerGraph{fast, reference} {
		if g.objectExecutions.active != 0 {
			t.Fatal("memo left a live ticket")
		}
		callerAssertExecutionRetention(t, g.objectExecutions, nil)
	}
}

func TestCallerIdentityMemoHitPreservesTraceTaint(t *testing.T) {
	for _, mode := range []string{"live", "reset"} {
		t.Run(mode, func(t *testing.T) {
			g, _, root := callerMemoTraceGraphs(t)
			chain := g.beginCallerTrace(map[callerObjectSourceID]bool{})
			if chain == nil || !g.callerTraceValid(chain) {
				t.Fatal("real suspended trace owner is missing")
			}
			c := g.objectExecutions
			defer func() {
				g.endCallerTrace(chain)
				if c.active != 0 || chain.live {
					t.Fatal("suspended memo owner did not drain")
				}
				callerAssertExecutionRetention(t, c, nil)
			}()
			if mode == "reset" {
				g.resetCallerObjectExecutions()
			}
			entries, units, active := c.entries, c.weight, c.active
			marks := callerReuseMarks(g)
			got, unknown := g.callerObjects(root, map[callerObjectSourceID]bool{})
			if len(got) == 0 || unknown || !chain.bad || g.callerTraceValid(chain) || callerReuseDelta(g, marks) != [4]uint64{1, 1, 0, 0} {
				t.Fatal("memo bypassed the external-entry taint or changed semantic marks")
			}
			if c.entries != entries || c.weight != units || c.active != active || mode == "reset" && c.graph != nil {
				t.Fatal("memo changed a suspended or quarantined owner's paid storage")
			}
			callerAssertExecutionRetention(t, c, nil)
		})
	}
}

func TestCallerIdentityMemoHitContextCheckpoints(t *testing.T) {
	for _, mode := range []string{"nil", "opaque", "opaque_cancel", "standard_cancel"} {
		t.Run(mode, func(t *testing.T) {
			fast, reference, root := callerMemoTraceGraphs(t)
			calls := [2]int{}
			for i, g := range []*callerGraph{fast, reference} {
				if mode == "nil" {
					g.ctx = nil
					continue
				}
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				if mode == "standard_cancel" {
					cancel()
					g.ctx = ctx
					continue
				}
				g.ctx = &callerTraceOpaqueContext{Context: ctx, onErr: func() {
					calls[i]++
					if mode == "opaque_cancel" {
						cancel()
					}
				}}
			}
			fm, rm := callerReuseMarks(fast), callerReuseMarks(reference)
			got, unknown := fast.callerObjects(root, map[callerObjectSourceID]bool{})
			want, otherUnknown, _ := reference.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
			if !maps.Equal(got, want) || unknown != otherUnknown || calls[0] != calls[1] || callerReuseDelta(fast, fm) != callerReuseDelta(reference, rm) {
				t.Fatal("memo changed the original context checkpoint or semantic result")
			}
			if mode == "opaque" && calls[0] != 1 || mode == "opaque_cancel" && (calls[0] != 1 || !unknown) || mode == "standard_cancel" && !unknown {
				t.Fatal("context boundary was vacuous")
			}
		})
	}
}
