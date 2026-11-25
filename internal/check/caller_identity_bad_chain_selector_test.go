// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"maps"
	"testing"
)

// Оба ребра принадлежат настоящему typed RPC. Первое проходит общий call,
// второе читает уже активный запрос поля; ответы, bad, seen и work не внедряются.
func callerBadSelectorProgram(t *testing.T) *surfaceProgram {
	t.Helper()
	p := callerSoundnessProgram(t,
		"type Holder struct{items []Box};func identity(items []Box)[]Box{return items}",
		"holder:=&Holder{items:[]Box{}};top:=identity(nil);top=holder.items;_=append(top,Box{});",
		"&Handler{}")
	t.Cleanup(func() { callerGraphs.Delete(p) })
	return p
}

func callerBadSelectorGraph(t *testing.T, p *surfaceProgram) (*callerGraph, valueSrc, valueSrc, valueSrc) {
	t.Helper()
	g, root, _ := callerTraceTypedGraph(t, p, "top")
	refs := g.sources(callerVariable(root.pkg, root.expr))
	if len(refs) != 2 {
		t.Fatal("typed root потерял два последовательных ребра")
	}
	if _, ok := ast.Unparen(refs[0].expr).(*ast.CallExpr); !ok {
		t.Fatal("первое ребро больше не обычный вызов")
	}
	if _, ok := ast.Unparen(refs[1].expr).(*ast.SelectorExpr); !ok {
		t.Fatal("второе ребро больше не selector")
	}
	g.ctx = context.Background()
	g.objectMemo, g.initialObjectMemo = nil, nil
	g.resetCallerObjectExecutions()
	if len(g.fieldQueries) == 0 || !g.callerExecutionScopeTracked() {
		t.Fatal("нет настоящего активного scope")
	}
	return g, root, refs[0], refs[1]
}

func callerBadSelectorRaw(g *callerGraph, src valueSrc, seen map[callerObjectSourceID]bool, chain *callerTraceChain) callerOwnedChainResult {
	marks := callerReuseMarks(g)
	var out callerOwnedChainResult
	out.objects, out.unknown, out.owned = g.callerObjectsRaw(src, seen, g.internObjectSource(src), chain)
	out.marks = callerReuseDelta(g, marks)
	return out
}

func TestCallerTraceBadChainSelectorsWork(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		name := "known"
		if unknown {
			name = "unknown"
		}
		t.Run(name, func(t *testing.T) {
			p := callerBadSelectorProgram(t)
			g, _, call, selector := callerBadSelectorGraph(t, p)
			original, _, otherCall, otherSelector := callerBadSelectorGraph(t, p)
			g.fieldQueries[0].unknown, original.fieldQueries[0].unknown = unknown, unknown
			seen, otherSeen := map[callerObjectSourceID]bool{}, map[callerObjectSourceID]bool{}
			chain := g.beginCallerTrace(seen)
			if chain == nil || chain.bad || chain.executing {
				t.Fatal("нет свежей ручной цепочки")
			}
			defer func() {
				g.endCallerTrace(chain)
				if g.objectExecutions.active != 0 || g.objectExecutions.traceChains != nil || g.objectExecutions.traceFrames != nil {
					t.Fatal("завершённая цепочка сохранила ticket или frame")
				}
				callerAssertExecutionRetention(t, g.objectExecutions, nil)
			}()
			beforeResolve := g.work.ResolveQueries
			a := callerBadSelectorRaw(g, call, seen, chain)
			b := callerBadSelectorRaw(original, otherCall, otherSeen, nil)
			if !maps.Equal(a.objects, b.objects) || a.unknown != b.unknown || a.owned != b.owned || a.marks != b.marks {
				t.Fatal("raw traversal изменил objects, UNKNOWN, владение или semantic marks")
			}
			if !chain.bad || g.work.ResolveQueries == beforeResolve || len(seen) != 0 {
				t.Fatal("обычный typed call не закрыл цепочку естественным путём")
			}
			// Положительный контроль старой цены: неизменённый helper действительно
			// прочитывает весь scope даже после bad; сам traversal ниже его не вызывает.
			x := ast.Unparen(selector.expr).(*ast.SelectorExpr)
			visits := g.work.ObjectScopeTrackedFrameVisits
			if !g.callerTraceSelector(selector, selector.pkg.info.Selections[x]) || g.work.ObjectScopeTrackedFrameVisits-visits != len(g.fieldQueries) {
				t.Fatal("положительный контроль полного structural proof пуст")
			}
			before, marks := g.work, callerReuseMarks(g)
			a = callerBadSelectorRaw(g, selector, seen, chain)
			b = callerBadSelectorRaw(original, otherSelector, otherSeen, nil)
			if !maps.Equal(a.objects, b.objects) || a.unknown != b.unknown || a.owned != b.owned || a.marks != b.marks {
				t.Fatal("raw traversal изменил objects, UNKNOWN, владение или semantic marks")
			}
			if len(a.objects) == 0 || a.unknown != unknown || !chain.bad || len(seen) != 0 || len(otherSeen) != 0 {
				t.Fatal("selector изменил objects, UNKNOWN или восстановление seen")
			}
			if g.work.ObjectScopeTrackedFrameVisits != before.ObjectScopeTrackedFrameVisits {
				t.Fatalf("уже закрытая цепочка повторила structural proof: visits=%d", g.work.ObjectScopeTrackedFrameVisits-before.ObjectScopeTrackedFrameVisits)
			}
			if g.work.ObjectTraceHits != before.ObjectTraceHits || g.work.ObjectTraceStores != before.ObjectTraceStores || callerReuseDelta(g, marks) != b.marks {
				t.Fatal("bad selector получил replay/publication либо изменил semantic marks")
			}
			escaped := maps.Clone(a.objects)
			again := callerBadSelectorRaw(g, selector, seen, chain)
			if !maps.Equal(a.objects, escaped) || !maps.Equal(again.objects, escaped) || again.unknown != unknown || again.owned != a.owned {
				t.Fatal("повтор изменил ранее выданную карту или владение")
			}
			if g.objectExecutions.active != 1 || chain.head != nil || g.objectExecutions.traceFrames != nil {
				t.Fatal("selector оставил лишний ticket или frame")
			}
			callerAssertExecutionRetention(t, g.objectExecutions, nil)
		})
	}
}

func TestCallerTraceBadChainSelectorsOwnedTraversal(t *testing.T) {
	p := callerBadSelectorProgram(t)
	g, root, _, _ := callerBadSelectorGraph(t, p)
	original, other, _, _ := callerBadSelectorGraph(t, p)
	original.objectExecutions = nil
	// Здесь единое production Owned-тело само проходит call → selector.
	// Ручная граница предыдущего теста нужна только для точного счётчика suffix.
	a := callerOwnedChainRun(t, g, root, false)
	b := callerOwnedChainRun(t, original, other, false)
	if len(a.objects) == 0 || !maps.Equal(a.objects, b.objects) || a.unknown != b.unknown || a.owned != b.owned || a.marks != b.marks {
		t.Fatal("production Owned traversal изменил ответ или semantic marks")
	}
}

func TestCallerTraceBadChainSelectorsLiveProof(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		name := "live"
		if malformed {
			name = "malformed"
		}
		t.Run(name, func(t *testing.T) {
			g, _, _, selector := callerBadSelectorGraph(t, callerBadSelectorProgram(t))
			seen := map[callerObjectSourceID]bool{}
			chain := g.beginCallerTrace(seen)
			if chain == nil || chain.bad {
				t.Fatal("нет живой цепочки")
			}
			defer func() {
				g.endCallerTrace(chain)
				if g.objectExecutions.active != 0 || g.objectExecutions.traceChains != nil || g.objectExecutions.traceFrames != nil {
					t.Fatal("завершённая цепочка сохранила ticket или frame")
				}
				callerAssertExecutionRetention(t, g.objectExecutions, nil)
			}()
			if malformed {
				g.fieldQueryIndexedDepth = -1
			}
			before := g.work
			out := callerBadSelectorRaw(g, selector, seen, chain)
			if len(out.objects) == 0 || len(seen) != 0 {
				t.Fatal("живой selector не прошёл реальный raw")
			}
			if malformed {
				if !chain.bad || g.work.ObjectTraceStores != before.ObjectTraceStores {
					t.Fatal("повреждённый scope получил trace publication")
				}
			} else if chain.bad || g.work.ObjectScopeTrackedFrameVisits <= before.ObjectScopeTrackedFrameVisits {
				t.Fatal("живой selector потерял полный structural proof")
			}
		})
	}
}
