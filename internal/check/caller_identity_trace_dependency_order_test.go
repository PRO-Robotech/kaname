// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"maps"
	"slices"
	"testing"
)

func TestCallerIdentityTraceDependencyOrderedBoundary(t *testing.T) {
	for _, mode := range []string{"contradiction", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			g, _, roots, _ := callerTraceIndexPair(t, false)
			ids := make([]callerObjectSourceID, 65)
			for i := range ids {
				ids[i] = g.objectSourceIDs[callerResolveKeyFor(roots[i], true)]
				if ids[i] == 0 {
					t.Fatal("typed источник не получил настоящий стабильный ID")
				}
			}
			slices.Sort(ids)
			for i := 1; i < len(ids); i++ {
				if ids[i-1] == ids[i] {
					t.Fatal("typed источники не различаются")
				}
			}

			// Локальный record проверяет только операцию накопления predicates.
			// Он не выдаётся за опубликованный или оплаченный cache-ticket.
			record := &callerTraceRecord{dependencies: make([]callerTraceDependency, 64)}
			chain := &callerTraceChain{record: record}
			c := g.objectExecutions
			entries, units, active := c.entries, c.weight, c.active
			beforeSteps, marks := g.work.ObjectTraceDependencySteps, callerReuseMarks(g)
			expected := map[callerObjectSourceID]bool{}
			low, middle, high := false, false, false
			for i := 0; i < 64; i++ {
				id := ids[(i*17+31)%64]
				below, above := false, false
				for previous := range expected {
					below = below || previous < id
					above = above || previous > id
				}
				low = low || !below && above
				middle = middle || below && above
				high = high || below && !above
				g.callerTraceDependency(chain, callerTraceDependency{source: id})
				expected[id] = false
				// Повтор включает последний, уже полностью заполненный record.
				g.callerTraceDependency(chain, callerTraceDependency{source: id})
				if record.bad || int(record.count) != len(expected) {
					t.Fatal("повтор потерял predicate или занял дополнительный slot")
				}
			}
			got := map[callerObjectSourceID]bool{}
			for i := 0; i < int(record.count); i++ {
				dependency := record.dependencies[i]
				if dependency.want != 0 || i > 0 && record.dependencies[i-1].source >= dependency.source {
					t.Fatal("точный набор не сохранил значения или строгий порядок")
				}
				got[dependency.source] = dependency.want == 1
			}
			if !low || !middle || !high || !maps.Equal(got, expected) || len(got) != 64 {
				t.Fatal("перестановка не покрыла low/mid/high или изменила независимый набор")
			}
			// При 64 slots один точный поиск посещает не более семи slots.
			// Прежние 64 новых + 64 повторных линейных поиска требуют 4096 visits.
			if steps := g.work.ObjectTraceDependencySteps - beforeSteps; steps <= 0 || steps > 2*64*7 {
				t.Fatalf("поиск сохранил линейный объём: visits=%d", steps)
			}
			unchanged := slices.Clone(record.dependencies)
			if mode == "contradiction" {
				// Изолированная проба задаёт owner с внешней для record глубиной.
				// Меняется требуемое значение того же ID: false обязано дать bad.
				owner := &callerTraceFrame{chain: chain, source: ids[31], depth: 1, live: true}
				chain.head, record.entry = owner, owner
				g.callerTraceDependency(chain, callerTraceDependency{source: ids[31], want: 1})
			} else {
				g.callerTraceDependency(chain, callerTraceDependency{source: ids[64]})
			}
			if !record.bad || record.count != 64 || !slices.Equal(record.dependencies, unchanged) || chain.bad {
				t.Fatal("противоречие или 65-й predicate изменил принятый набор вместо отказа")
			}
			if c.entries != entries || c.weight != units || c.active != active || callerReuseMarks(g) != marks {
				t.Fatal("чистое накопление predicates изменило учёт владения или семантику")
			}
		})
	}
}

func TestCallerIdentityTraceDependencyOrderTypedReplay(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		name := "known"
		if unknown {
			name = "unknown"
		}
		t.Run(name, func(t *testing.T) {
			p := callerTraceTypedProgram(t, callerTraceDiamondBody(6))
			fast, root, _ := callerTraceTypedGraph(t, p, "x6")
			manual, _, _ := callerTraceTypedGraph(t, p, "x6")
			original, _, _ := callerTraceTypedGraph(t, p, "x6")
			fast.ctx, manual.ctx = context.Background(), context.Background()
			original.objectExecutions = nil
			for _, g := range []*callerGraph{fast, manual, original} {
				g.fieldQueries[0].unknown = unknown
			}
			var escaped, previous map[callerObjectKey]bool
			nontrivial := false
			for range 2 {
				got := callerOwnedChainRun(t, fast, root, false)
				full := callerOwnedChainRun(t, manual, root, true)
				want := callerOwnedChainRun(t, original, root, false)
				callerOwnedChainEqual(t, got, full)
				if got.unknown != unknown || got.unknown != want.unknown || len(got.objects) == 0 || !maps.Equal(got.objects, want.objects) || got.marks != want.marks {
					t.Fatal("новый порядок изменил typed objects, UNKNOWN или semantic effects")
				}
				if previous != nil && !maps.Equal(previous, escaped) {
					t.Fatal("повторный replay изменил ранее выданный readonly ответ")
				}
				previous, escaped = got.objects, maps.Clone(got.objects)
				for record := fast.objectExecutions.traceRecords; record != nil; record = record.next {
					nontrivial = nontrivial || record.count > 1
					for i := 1; i < int(record.count); i++ {
						if record.dependencies[i-1].source >= record.dependencies[i].source {
							t.Fatal("production writer оставил неупорядоченные или повторные predicates")
						}
					}
				}
			}
			if !nontrivial || fast.work.ObjectTraceHits == 0 || fast.work.ObjectTraceStores == 0 {
				t.Fatal("typed replay не использовал непустые реальные сертификаты")
			}
			callerAssertExecutionRetention(t, fast.objectExecutions, nil)
			callerAssertExecutionRetention(t, manual.objectExecutions, nil)
		})
	}
}
