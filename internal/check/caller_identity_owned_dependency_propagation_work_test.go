// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"testing"
)

// Старый callerOwnedChainEqual намеренно не меняется: он ещё требует равных
// dependency steps. Здесь сравниваем все остальные его поля, а dependency work
// проверяем отдельным заключительным oracle после всех semantic assertions.
func TestCallerIdentityOwnedDependencyPropagationWork(t *testing.T) {
	for _, depth := range []int{4, 6, 8} {
		for _, unknown := range []bool{false, true} {
			t.Run(fmt.Sprintf("depth_%d_unknown_%t", depth, unknown), func(t *testing.T) {
				p := callerTraceTypedProgram(t, callerTraceDiamondBody(depth))
				name := fmt.Sprintf("x%d", depth)
				owned, root, _ := callerTraceTypedGraph(t, p, name)
				manual, manualRoot, _ := callerTraceTypedGraph(t, p, name)
				reference, referenceRoot, _ := callerTraceTypedGraph(t, p, name)
				if owned == manual || owned == reference || manual == reference {
					t.Fatal("typed runs share mutable graph state")
				}
				reference.objectExecutions = nil
				for _, g := range []*callerGraph{owned, manual, reference} {
					g.ctx = context.Background()
					if len(g.fieldQueries) != 1 {
						t.Fatal("typed diamond lacks its real field scope")
					}
					g.fieldQueries[0].unknown = unknown
				}
				ownedScope, manualScope, referenceScope := owned.callerExecutionSnapshot(), manual.callerExecutionSnapshot(), reference.callerExecutionSnapshot()
				var escaped, immutable [3]map[callerObjectKey]bool
				ownedDeps, manualDeps, hits, stores := 0, 0, 0, 0
				for run := 0; run < 2; run++ {
					a := callerOwnedChainRun(t, owned, root, false)
					b := callerOwnedChainRun(t, manual, manualRoot, true)
					want := callerOwnedChainRun(t, reference, referenceRoot, false)
					// helper также проверяет пустой seen, drain chains/frames и
					// независимый physical retention oracle для каждого cache.
					if len(a.objects) == 0 || a.unknown != unknown || b.unknown != unknown || want.unknown != unknown || !maps.Equal(a.objects, b.objects) || !maps.Equal(a.objects, want.objects) || a.marks != b.marks || a.marks != want.marks || a.owned != b.owned {
						t.Fatal("owned/manual/reference changed typed objects, UNKNOWN, ownership or four marks")
					}
					if a.raw != b.raw || a.queries != b.queries || a.reads != b.reads || a.hits != b.hits || a.stores != b.stores || a.evictions != b.evictions || a.capacity != b.capacity {
						t.Fatal("work outside dependency propagation and stack validation changed")
					}
					if a.raw == 0 || want.raw == 0 || a.queries == 0 || a.reads == 0 || a.hits == 0 {
						t.Fatal("typed run lacks real raw, trace hit/read or dependency work")
					}
					if want.hits != 0 || want.stores != 0 || reference.objectExecutions != nil {
						t.Fatal("reference unexpectedly acquired a trace cache")
					}
					if owned.objectExecutions.entries != manual.objectExecutions.entries || owned.objectExecutions.weight != manual.objectExecutions.weight || owned.objectExecutions.active != 0 || manual.objectExecutions.active != 0 {
						t.Fatal("equal typed runs changed physical retention accounting or pins")
					}
					if !ownedScope.matches(owned) || !manualScope.matches(manual) || !referenceScope.matches(reference) {
						t.Fatal("dependency propagation changed full mutable scope contents")
					}
					results := [3]map[callerObjectKey]bool{a.objects, b.objects, want.objects}
					for i, result := range results {
						if run == 0 {
							escaped[i], immutable[i] = result, maps.Clone(result)
						} else if !maps.Equal(escaped[i], immutable[i]) || !maps.Equal(result, immutable[i]) {
							t.Fatal("later run mutated an escaped readonly map or its result")
						}
					}
					ownedDeps += a.deps
					manualDeps += b.deps
					hits += a.hits
					stores += a.stores
					t.Logf("semantic run passed: depth=%d unknown=%t run=%d ownedDeps=%d manualDeps=%d raw=%d referenceRaw=%d hits=%d stores=%d marks=%v", depth, unknown, run, a.deps, b.deps, a.raw, want.raw, a.hits, a.stores, a.marks)
				}
				if hits == 0 || stores == 0 || ownedDeps == 0 || manualDeps == 0 {
					t.Fatal("case lacks real trace hit, publication or dependency work")
				}
				t.Logf("semantic case passed: depth=%d unknown=%t ownedDeps=%d manualDeps=%d hits=%d stores=%d", depth, unknown, ownedDeps, manualDeps, hits, stores)
				// Единственный ожидаемый RED: прежний алгоритм повторяет поиск
				// одинакового predicate во всех предках и здесь даёт равные steps.
				if ownedDeps >= manualDeps {
					t.Fatalf("repeated owned dependency propagation: ownedDeps=%d manualDeps=%d; want ownedDeps < manualDeps", ownedDeps, manualDeps)
				}
			})
		}
	}
}

// Открытая цепь не доказывает, что predicate child ранее прошёл всех предков.
// Blanket return при exact duplicate потеряет отсутствующий predicate parent.
func TestCallerIdentityManualDependencyDuplicateStillPropagates(t *testing.T) {
	p := callerTraceTypedProgram(t, callerTraceDiamondBody(4))
	g, root, _ := callerTraceTypedGraph(t, p, "x4")
	id := g.objectSourceIDs[callerResolveKeyFor(root, true)]
	if id == 0 {
		t.Fatal("manual negative lacks a real typed source identity")
	}
	dependency := callerTraceDependency{source: id}
	// Это локальная проба операции, не опубликованные cache records: backing
	// обоих records действительно выделен, fixture не меняет cache accounting.
	parent := &callerTraceRecord{dependencies: make([]callerTraceDependency, callerTraceDependencies)}
	child := &callerTraceRecord{dependencies: make([]callerTraceDependency, callerTraceDependencies), count: 1, parent: parent}
	child.dependencies[0] = dependency
	chain := &callerTraceChain{record: child}
	before := slices.Clone(child.dependencies)
	c := g.objectExecutions
	entries, weight, active, marks := c.entries, c.weight, c.active, callerReuseMarks(g)
	g.callerTraceDependency(chain, dependency)
	if chain.executing || chain.bad || child.bad || parent.bad || child.count != 1 || parent.count != 1 || parent.dependencies[0] != dependency || !slices.Equal(child.dependencies, before) {
		t.Fatal("manual duplicate failed to reach the missing parent predicate")
	}
	if c.entries != entries || c.weight != weight || c.active != active || callerReuseMarks(g) != marks {
		t.Fatal("pure manual propagation changed accounting or semantic marks")
	}
	callerAssertExecutionRetention(t, c, nil)
}
