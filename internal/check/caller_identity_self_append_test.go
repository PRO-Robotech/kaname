// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"fmt"
	"go/ast"
	"maps"
	"testing"
)

func TestCallerIdentitySelfAppendPermutationEffects(t *testing.T) {
	for _, anchored := range []bool{false, true} {
		init := "var items []any"
		if anchored {
			init = "items:=[]any{}"
		}
		p := callerSoundnessProgram(t, "", init+`;items=append(items,1);items=append(items,2);items=append(items,3);items=append(items,4);_=items`, "&Handler{}")
		for _, initial := range []bool{false, true} {
			for _, external := range []bool{false, true} {
				for _, liveTrace := range []bool{false, true} {
					name := fmt.Sprintf("literal_%t/initial_%t/seen_%t/trace_%t", anchored, initial, external, liveTrace)
					t.Run(name, func(t *testing.T) {
						type result struct {
							objects map[callerObjectKey]bool
							marks   [4]uint64
							unknown bool
							raw     int
						}
						var runs [2]result
						for i := range runs {
							g := newCallerGraph(p)
							g.lifetimeScanning = initial
							g.ctx = context.Background()
							if liveTrace {
								g.resetCallerObjectExecutions()
							}
							src := callerOwnershipSources(p)["items"]
							v := callerVariable(src.pkg, src.expr)
							refs := g.sources(v)
							src.fk = refs[0].fk
							if i == 0 {
								// В старой ветке запроса этих чистых идентификаторов
								// addrTaken не участвует. Отключаем лишь новую свёртку.
								g.index.addrTaken[v] = true
							}
							seen := map[callerObjectSourceID]bool{}
							if external {
								a, b := refs[len(refs)-2], refs[len(refs)-1]
								seen[g.internObjectSource(a)] = true
								b.expr = b.expr.(*ast.CallExpr).Args[0]
								seen[g.internObjectSource(b)] = true
							}
							before := maps.Clone(seen)
							marks := callerReuseMarks(g)
							objects, unknown := g.callerObjects(src, seen)
							if !maps.Equal(before, seen) {
								t.Fatal("изменён внешний стек источников")
							}
							runs[i] = result{objects, callerReuseDelta(g, marks), unknown, g.work.ObjectRawEvaluations}
						}
						old, fast := runs[0], runs[1]
						if old.unknown != fast.unknown || !maps.Equal(old.objects, fast.objects) || old.marks != fast.marks {
							t.Fatalf("изменены объекты/UNKNOWN/семантические отметки: old=%+v fast=%+v", old, fast)
						}
						if fast.unknown != (!anchored && !external) || fast.marks[3] == 0 || fast.raw >= old.raw {
							t.Fatalf("не подтверждён исходный цикл и выигрыш по реальным raw: old=%+v fast=%+v", old, fast)
						}
					})
				}
			}
		}
	}
}

func TestCallerIdentitySelfAppendPreservesAlternatives(t *testing.T) {
	const appends = `;items=append(items,anchor);items=append(items,nil);items=append(items,nil);items=append(items,nil)`
	for _, extra := range []struct{ name, stmt string }{
		{"contents", ""},
		{"opaque_rebind", ";items=source.Value().([]any)"},
		{"captured_rebind", ";func(){items=source.Value().([]any)}()"},
		{"element_write", ";items[0]=source.Value()"},
		{"address_escape", ";source.Mutate(&items)"},
	} {
		t.Run(extra.name, func(t *testing.T) {
			p := callerSoundnessProgram(t, "", "anchor:=&Box{};var items []any"+appends+extra.stmt+";_=items", "&Handler{}")
			g := newCallerGraph(p)
			g.safeExternal = map[string]bool{"fixture/source": true}
			named := callerOwnershipSources(p)
			src := named["items"]
			v := callerVariable(src.pkg, src.expr)
			refs := g.sources(v)
			src.fk = refs[0].fk
			anchor := named["anchor"]
			allocation := g.sources(callerVariable(anchor.pkg, anchor.expr))[0].expr.(*ast.UnaryExpr).X
			target := callerObjectKey{pkg: p.root, expr: allocation}
			storage := callerObjectKey{pkg: p.root, zero: v}
			_, eligible := g.callerSelfAppendObjects(src, v, refs, storage, map[callerObjectSourceID]bool{}, nil)
			if eligible != (extra.name == "contents") {
				t.Fatalf("допуск свёртки=%t", eligible)
			}
			probe := callerLifetimeProbe{g: g, want: target, seen: map[callerResolveKey]bool{}, objects: map[callerObjectKey]bool{}}
			if !probe.contains(src) {
				t.Fatal("из обычной достижимости пропал добавленный объект")
			}
		})
	}
}

func TestCallerIdentitySelfAppendOverflowAndCancellation(t *testing.T) {
	p := callerSoundnessProgram(t, "", `var items []any;items=append(items,1);items=append(items,2);items=append(items,3);items=append(items,4);_=items`, "&Handler{}")
	for _, canceled := range []bool{false, true} {
		var reference [4]uint64
		for i := range 2 {
			g := newCallerGraph(p)
			src := callerOwnershipSources(p)["items"]
			v := callerVariable(src.pkg, src.expr)
			src.fk = g.sources(v)[0].fk
			if i == 0 {
				g.index.addrTaken[v] = true
			}
			g.resolveCuts = ^uint64(0) - 3
			if canceled {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				g.ctx = ctx
			}
			objects, unknown := g.callerObjects(src, map[callerObjectSourceID]bool{})
			if !unknown || len(objects) != 0 || g.semanticOverflow == canceled {
				t.Fatalf("не сохранён отказ: отмена=%t overflow=%t unknown=%t", canceled, g.semanticOverflow, unknown)
			}
			if i == 0 {
				reference = callerReuseMarks(g)
			} else if reference != callerReuseMarks(g) {
				t.Fatalf("изменился момент переполнения: %v / %v", reference, callerReuseMarks(g))
			}
		}
	}
}
