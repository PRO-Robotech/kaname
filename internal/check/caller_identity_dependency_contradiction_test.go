// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"fmt"
	"slices"
	"testing"
)

// Равный predicate может завершать owned-передачу, противоречащий — никогда.
// Уже bad промежуточный record тоже не должен скрыть обязательство предка.
func TestCallerIdentityDependencyContradictionPropagatesPastBadParent(t *testing.T) {
	for _, executing := range []bool{false, true} {
		for _, badParent := range []bool{false, true} {
			t.Run(fmt.Sprintf("owned_%t_bad_parent_%t", executing, badParent), func(t *testing.T) {
				p := callerTraceTypedProgram(t, callerTraceDiamondBody(4))
				g, root, _ := callerTraceTypedGraph(t, p, "x4")
				id := g.objectSourceIDs[callerResolveKeyFor(root, true)]
				if id == 0 {
					t.Fatal("contradiction fixture lacks the warmed exact typed source")
				}
				// Изолированные локальные records не публикуются в cache. Backing
				// реально выделен; проверяем чистую операцию и неизменность account.
				chain := &callerTraceChain{executing: executing, live: true}
				owner := &callerTraceFrame{source: id, depth: 1, live: true, chain: chain}
				chain.head = owner
				var records [3]*callerTraceRecord
				var before [3][]callerTraceDependency
				for i := range records {
					records[i] = &callerTraceRecord{dependencies: make([]callerTraceDependency, callerTraceDependencies), count: 1, phase: callerTraceLive, chain: chain, entry: owner, ticket: true, holdsScope: true}
					records[i].dependencies[0] = callerTraceDependency{source: id}
					before[i] = slices.Clone(records[i].dependencies)
					if i > 0 {
						records[i-1].parent = records[i]
					}
				}
				records[1].bad = badParent
				chain.record = records[0]
				c := g.objectExecutions
				entries, weight, active, marks := c.entries, c.weight, c.active, callerReuseMarks(g)
				g.callerTraceDependency(chain, callerTraceDependency{source: id, want: 1})
				for i, record := range records {
					if !record.bad || record.count != 1 || !slices.Equal(record.dependencies, before[i]) {
						t.Fatalf("contradiction did not invalidate ancestor %d or changed its predicates", i)
					}
				}
				if chain.bad || c.entries != entries || c.weight != weight || c.active != active || callerReuseMarks(g) != marks {
					t.Fatal("contradiction changed chain, retention accounting or semantic marks")
				}
				callerAssertExecutionRetention(t, c, nil)
			})
		}
	}
}
