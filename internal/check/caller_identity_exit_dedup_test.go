// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"maps"
	"testing"
)

func callerExitDedupPair(t *testing.T, body, rootName string) (*callerGraph, *callerGraph, valueSrc) {
	t.Helper()
	p := callerTraceTypedProgram(t, body)
	a, root, _ := callerTraceTypedGraph(t, p, rootName)
	b, _, _ := callerTraceTypedGraph(t, p, rootName)
	for _, g := range []*callerGraph{a, b} {
		if g.objectExecutions.entries != 0 || g.work.ObjectTraceStores != 0 {
			t.Fatal("typed nil-context warmup retained a trace before the measured call")
		}
		g.ctx = context.Background()
	}
	return a, b, root
}

// Ручной владелец использует настоящий begin/Tracked/end, но не получает
// закрытый executing-признак. Это прежний полный путь, а не подставной флаг.
func callerExitDedupManual(g *callerGraph, root valueSrc) (map[callerObjectKey]bool, bool, bool) {
	seen := map[callerObjectSourceID]bool{}
	chain := g.beginCallerTrace(seen)
	defer g.endCallerTrace(chain)
	return g.callerObjectsTracked(root, seen, chain)
}

func callerExitDedupTwins(t *testing.T, g *callerGraph) (*callerTraceRecord, *callerTraceRecord) {
	t.Helper()
	for a := g.objectExecutions.traceRecords; a != nil; a = a.next {
		if a.phase != callerTraceRetained || a.count != 1 || a.dependencies[0].source != a.source || a.dependencies[0].want != 0 {
			continue
		}
		for b := g.objectExecutions.traceRecords; b != nil; b = b.next {
			if b.phase == callerTraceRetained && b.source == a.source && b.scope == a.scope && b.guard.state == a.guard.state && b.count == 1 && b.dependencies[0].source == b.source && b.dependencies[0].want == 1 {
				return a, b
			}
		}
	}
	t.Fatal("typed recursion did not retain incompatible false/true variants of the same AST source")
	return nil, nil
}

func TestCallerIdentityExitDedupOwnedWorkBound(t *testing.T) {
	fast, manual, root := callerExitDedupPair(t, "var x *Box;x=x;x=&Box{};root:=x;_=root;", "root")
	fw, mw := fast.work, manual.work
	fm, mm := callerReuseMarks(fast), callerReuseMarks(manual)
	got, unknown, owned := fast.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	want, otherUnknown, otherOwned := callerExitDedupManual(manual, root)
	if unknown || otherUnknown || !maps.Equal(got, want) || owned != otherOwned || callerReuseDelta(fast, fm) != callerReuseDelta(manual, mm) || callerReuseDelta(fast, fm) != [4]uint64{3, 2, 0, 1} {
		t.Fatal("owned dedup elision changed the typed cycle, memo-child effects or ownership")
	}
	// После прогрева ровно четыре raw: root, два разных AST-use x и cycle
	// второго use. Три interior miss публикуют три records. У двух разных
	// source разные корзины; candidate visits 0+1+2 становятся 0+0+1.
	// Из прежних exact 14/25 исчезают ровно два чистых visits. Остальные
	// boundary/dependency и ручной dedup шаги остаются: exact 12/23.
	negative, _ := callerExitDedupTwins(t, fast)
	distinct := false
	for record := fast.objectExecutions.traceRecords; record != nil; record = record.next {
		if record.source != negative.source {
			if record.source%16 == negative.source%16 {
				t.Fatal("typed two-source work witness has an unexpected real bucket collision")
			}
			distinct = true
		}
	}
	if !distinct {
		t.Fatal("typed work witness lost its other actual source")
	}
	if fast.work.ObjectRawEvaluations-fw.ObjectRawEvaluations != 4 || manual.work.ObjectRawEvaluations-mw.ObjectRawEvaluations != 4 || fast.work.ObjectTraceQueries-fw.ObjectTraceQueries != 3 || fast.work.ObjectTraceStores-fw.ObjectTraceStores != 3 || manual.work.ObjectTraceStores-mw.ObjectTraceStores != 3 || fast.work.ObjectTraceValidationSteps-fw.ObjectTraceValidationSteps != 12 || manual.work.ObjectTraceValidationSteps-mw.ObjectTraceValidationSteps != 23 {
		t.Fatalf("typed exit work bound: owned=%d manual=%d raw=%d/%d stores=%d/%d", fast.work.ObjectTraceValidationSteps-fw.ObjectTraceValidationSteps, manual.work.ObjectTraceValidationSteps-mw.ObjectTraceValidationSteps, fast.work.ObjectRawEvaluations-fw.ObjectRawEvaluations, manual.work.ObjectRawEvaluations-mw.ObjectRawEvaluations, fast.work.ObjectTraceStores-fw.ObjectTraceStores, manual.work.ObjectTraceStores-mw.ObjectTraceStores)
	}
	callerExitDedupTwins(t, fast)
	callerExitDedupTwins(t, manual)
	for _, g := range []*callerGraph{fast, manual} {
		if g.objectExecutions.active != 0 || g.objectExecutions.traceChains != nil || g.objectExecutions.traceFrames != nil {
			t.Fatal("completed typed span retained a live owner")
		}
		callerAssertExecutionRetention(t, g.objectExecutions, nil)
	}
}

func TestCallerIdentityExitDedupCycleUnknownAndReadonly(t *testing.T) {
	for _, name := range []string{"hollow", "anchored"} {
		t.Run(name, func(t *testing.T) {
			initial := "var found []Box;"
			if name == "anchored" {
				initial = "found:=[]Box{};"
			}
			fast, manual, root := callerExitDedupPair(t, initial+"found=append(found,Box{});found=append(found,Box{});alias:=found;_=alias;", "alias")
			type escaped struct{ answer, before map[callerObjectKey]bool }
			var old []escaped
			for repeat := range 3 {
				fm, mm := callerReuseMarks(fast), callerReuseMarks(manual)
				got, unknown, owned := fast.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
				want, otherUnknown, otherOwned := callerExitDedupManual(manual, root)
				if unknown != (name == "hollow") || unknown != otherUnknown || owned != otherOwned || !maps.Equal(got, want) || callerReuseDelta(fast, fm) != callerReuseDelta(manual, mm) || callerReuseDelta(fast, fm)[3] == 0 {
					t.Fatal("self-append changed UNKNOWN, aliases, ownership or cycle multiplicity")
				}
				if repeat == 0 {
					for record := fast.objectExecutions.traceRecords; record != nil; record = record.next {
						old = append(old, escaped{record.objects, maps.Clone(record.objects)})
					}
				}
				for _, saved := range old {
					if !maps.Equal(saved.answer, saved.before) {
						t.Fatal("a later duplicate or borrowed result mutated an escaped certificate map")
					}
				}
				callerAssertExecutionRetention(t, fast.objectExecutions, nil)
				callerAssertExecutionRetention(t, manual.objectExecutions, nil)
			}
			if len(old) == 0 || fast.work.ObjectTraceHits == 0 || manual.work.ObjectTraceHits == 0 {
				t.Fatal("typed cycle fixture never retained and reused a real certificate")
			}
		})
	}
}

func TestCallerIdentityExitDedupManualDuplicateLookup(t *testing.T) {
	g, foreign, root := callerExitDedupPair(t, "var x *Box;x=x;x=&Box{};root:=x;_=root;", "root")
	callerExitDedupManual(g, root)
	callerExitDedupManual(foreign, root)
	negative, positive := callerExitDedupTwins(t, g)
	foreignNegative, _ := callerExitDedupTwins(t, foreign)
	c := g.objectExecutions
	before := g.work.ObjectTraceValidationSteps
	marks := callerReuseMarks(g)
	if !c.callerTraceDuplicate(g, negative, map[callerObjectSourceID]bool{}) || !c.callerTraceDuplicate(g, positive, map[callerObjectSourceID]bool{positive.source: true}) || c.callerTraceDuplicate(g, foreignNegative, map[callerObjectSourceID]bool{}) || g.work.ObjectTraceValidationSteps <= before || callerReuseMarks(g) != marks {
		t.Fatal("manual duplicate lookup lost exact scope, seen variants or its original validation work")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.ctx = ctx
	if c.callerTraceDuplicate(g, negative, map[callerObjectSourceID]bool{}) {
		t.Fatal("manual duplicate lookup accepted another exact context")
	}
	callerAssertExecutionRetention(t, c, nil)
}

func TestCallerIdentityExitDedupContextBoundary(t *testing.T) {
	for _, mode := range []string{"nil", "opaque", "opaque_cancel", "standard_cancel"} {
		t.Run(mode, func(t *testing.T) {
			fast, manual, root := callerExitDedupPair(t, "var x *Box;x=x;x=&Box{};root:=x;_=root;", "root")
			calls := [2]int{}
			for i, g := range []*callerGraph{fast, manual} {
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
			fm, mm := callerReuseMarks(fast), callerReuseMarks(manual)
			got, unknown, owned := fast.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
			want, otherUnknown, otherOwned := callerExitDedupManual(manual, root)
			if !maps.Equal(got, want) || unknown != otherUnknown || owned != otherOwned || callerReuseDelta(fast, fm) != callerReuseDelta(manual, mm) || calls[0] != calls[1] || fast.work.ObjectTraceStores != 0 || manual.work.ObjectTraceStores != 0 {
				t.Fatal("non-admitted context changed original checkpoints, answer or ownership")
			}
			if mode == "opaque" && calls[0] == 0 || mode == "opaque_cancel" && (calls[0] != 1 || !unknown) || mode == "standard_cancel" && !unknown {
				t.Fatal("context/cancellation preservation case was vacuous")
			}
			callerAssertExecutionRetention(t, fast.objectExecutions, nil)
			callerAssertExecutionRetention(t, manual.objectExecutions, nil)
		})
	}
}

func TestCallerIdentityExitDedupOpenOwnerBoundary(t *testing.T) {
	for _, mode := range []string{"reentry", "reset"} {
		t.Run(mode, func(t *testing.T) {
			g, original, root := callerExitDedupPair(t, "var x *Box;x=x;x=&Box{};root:=x;_=root;", "root")
			original.objectExecutions = nil
			chain := g.beginCallerTrace(map[callerObjectSourceID]bool{})
			if chain == nil || chain.executing || !g.callerTraceValid(chain) {
				t.Fatal("real manual owner unexpectedly acquired a closed-span proof")
			}
			c := g.objectExecutions
			if mode == "reset" {
				g.resetCallerObjectExecutions()
			}
			entries, units := c.entries, c.weight
			gm, om := callerReuseMarks(g), callerReuseMarks(original)
			got, unknown, _ := g.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
			want, otherUnknown, _ := original.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
			if unknown != otherUnknown || !maps.Equal(got, want) || callerReuseDelta(g, gm) != callerReuseDelta(original, om) || !chain.bad || g.callerTraceValid(chain) {
				t.Fatal("fresh owned entry hid suspended-chain taint or changed raw effects")
			}
			g.endCallerTrace(chain)
			if c.active != 0 || chain.live {
				t.Fatal("manual owner failed to drain")
			}
			if mode == "reset" && (c.graph != nil || c.entries != entries || c.weight != units || g.work.ObjectTraceStores != 0) {
				t.Fatal("disabled B1 owner admitted dedup/publication or prematurely uncharged storage")
			}
			callerAssertExecutionRetention(t, c, nil)
			if mode == "reset" {
				g.resetCallerObjectExecutions()
				if g.objectExecutions == c || g.objectExecutions.entries != 0 || g.objectExecutions.weight != 0 {
					t.Fatal("idle reset kept the disabled account")
				}
			}
		})
	}
}
