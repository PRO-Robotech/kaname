// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"maps"
	"slices"
	"strings"
	"testing"
)

// Только испытательная коллизия индекса: узел уже создан настоящим acquire.
// Не создаются ответы, снимки, tickets или единицы учёта. Исходный индекс
// восстанавливается до проверки семантического replay; естественная коллизия
// производственного хеша здесь не предполагается.
func callerTrackedProofMoveBucket(t *testing.T, c *callerObjectExecutions, node *callerObjectExecutionScope, hash uint64) {
	t.Helper()
	old := c.scopes[node.hash]
	if old == node {
		if node.next == nil {
			delete(c.scopes, node.hash)
		} else {
			c.scopes[node.hash] = node.next
		}
	} else {
		for old != nil && old.next != node {
			old = old.next
		}
		if old == nil {
			t.Fatal("real acquired scope missing from its bucket")
		}
		old.next = node.next
	}
	node.hash = hash
	node.next = c.scopes[hash]
	c.scopes[hash] = node
}

func TestCallerIdentityTrackedProofExactScopeDecoy(t *testing.T) {
	for _, name := range []string{"container", "mutation"} {
		t.Run(name, func(t *testing.T) {
			p := callerCanonicalScopeProgram(t)
			g, root, base, fields := callerCanonicalScopeGraph(t, p)
			slow, slowRoot, slowBase, slowFields := callerCanonicalScopeGraph(t, p)
			slow.objectExecutions = nil
			set := func(graph *callerGraph, source valueSrc, value bool) {
				if name == "container" {
					graph.containerScanning = map[callerResolveKey]bool{callerResolveKeyFor(source, true): value}
				} else {
					graph.mutationScanning = map[callerFieldKey]bool{{callerResolveKeyFor(source, true), fields[0]}: value}
				}
			}
			if fields[0] != slowFields[0] {
				t.Fatal("typed twins do not share the actual field identity")
			}
			set(g, base, true)
			set(slow, slowBase, true)
			c := g.objectExecutions
			first := c.scope(g)
			if first == nil {
				t.Fatal("real first scope missing")
			}
			defer c.releaseTicket(g, first)
			originalHash := first.hash
			set(g, base, false)
			if !g.callerExecutionScopeTracked() || first.snapshot.matches(g) {
				t.Fatal("exact guard value did not distinguish the typed scopes")
			}
			// Переносим настоящий pinned decoy, а не подставляем готовый ответ.
			callerTrackedProofMoveBucket(t, c, first, c.scopeHash(g))
			entries, units := c.entries, c.weight
			second := c.scope(g)
			if second == nil {
				t.Fatal("real second scope missing")
			}
			secondLive := true
			defer func() {
				if secondLive {
					c.releaseTicket(g, second)
				}
			}()
			if second == first || !second.snapshot.matches(g) || first.snapshot.matches(g) || c.entries != entries+1 || c.weight != units+second.weight || first.references != 1 || second.references != 1 || c.active != 2 {
				t.Fatal("bucket decoy bypassed exact content or changed real ownership")
			}
			callerTrackedProofMoveBucket(t, c, first, originalHash)
			set(g, base, true)
			restored := c.scope(g)
			if restored != nil {
				c.releaseTicket(g, restored)
			}
			if restored != first {
				t.Fatal("restored exact content lost the original real scope identity")
			}
			c.releaseTicket(g, second)
			secondLive = false
			callerAssertExecutionRetention(t, c, first)
			escaped := callerPrimeObjectExecution(t, g, root)
			immutable := maps.Clone(escaped)
			for range 3 {
				slow.callerObjects(slowRoot, map[callerObjectSourceID]bool{})
			}
			gm, sm := callerReuseMarks(g), callerReuseMarks(slow)
			gr, sr, hits := g.work.ObjectRawEvaluations, slow.work.ObjectRawEvaluations, g.work.ObjectExecutionHits
			got, unknown := g.callerObjects(root, map[callerObjectSourceID]bool{})
			want, otherUnknown := slow.callerObjects(slowRoot, map[callerObjectSourceID]bool{})
			if len(got) == 0 || !maps.Equal(got, want) || unknown != otherUnknown || callerReuseDelta(g, gm) != callerReuseDelta(slow, sm) || !maps.Equal(escaped, immutable) {
				t.Fatal("exact scope replay changed typed objects, UNKNOWN, four marks or borrowed map")
			}
			if g.work.ObjectExecutionHits != hits+1 || g.work.ObjectRawEvaluations != gr || slow.work.ObjectRawEvaluations <= sr || callerReuseDelta(g, gm)[2] != 0 {
				t.Fatal("real replay lacks a positive original-body witness or invented completion")
			}
			callerAssertExecutionRetention(t, c, first)
		})
	}
}

func TestCallerIdentityTrackedProofInvalidEntry(t *testing.T) {
	for _, name := range []string{"latest", "missing", "previous_cycle"} {
		t.Run(name, func(t *testing.T) {
			g, _, _, _ := callerCanonicalScopeGraph(t, callerCanonicalScopeProgram(t))
			c := g.objectExecutions
			pin := c.scope(g)
			if pin == nil {
				t.Fatal("real canonical scope missing")
			}
			defer c.releaseTicket(g, pin)
			heads, queries := maps.Clone(g.fieldQueryHeads), slices.Clone(g.fieldQueries)
			defer func() { g.fieldQueryHeads, g.fieldQueries = heads, queries }()
			switch name {
			case "latest":
				g.fieldQueryHeads[queries[0].source] = 1
			case "missing":
				delete(g.fieldQueryHeads, queries[1].source)
			case "previous_cycle":
				g.fieldQueries[2].previousSourceQuery = 3
			}
			entries, units, active := c.entries, c.weight, c.active
			if pin.snapshot.matches(g) {
				t.Fatal("standalone matcher lost its canonical proof")
			}
			if acquired := c.scope(g); acquired != nil {
				c.releaseTicket(g, acquired)
				t.Fatal("real acquire used content without its entry proof")
			}
			if c.entries != entries || c.weight != units || c.active != active {
				t.Fatal("invalid entry changed cache ownership")
			}
			callerAssertExecutionRetention(t, c, pin)
		})
	}
}

func TestCallerIdentityTrackedProofCheckpoint(t *testing.T) {
	for _, name := range []string{"before_copy/heads", "before_copy/refs", "before_copy/container", "before_copy/mutation", "after_copy/heads", "after_copy/refs", "after_copy/container", "after_copy/mutation"} {
		t.Run(name, func(t *testing.T) {
			p := callerCanonicalScopeProgram(t)
			g, root, base, fields := callerCanonicalScopeGraph(t, p)
			slow, slowRoot, slowBase, _ := callerCanonicalScopeGraph(t, p)
			slow.objectExecutions = nil
			c := g.objectExecutions
			for _, head := range c.scopes {
				for node := head; node != nil; node = node.next {
					if node.snapshot.matches(g) {
						t.Fatal("checkpoint fixture unexpectedly already has this exact scope")
					}
				}
			}
			trigger := 1
			phase, change, _ := strings.Cut(name, "/")
			if phase == "after_copy" {
				trigger = 2
			}
			mutate := func(graph *callerGraph, source valueSrc) {
				switch change {
				case "heads":
					graph.fieldQueryHeads[graph.fieldQueries[0].source] = 1
				case "refs":
					if graph.fieldQueries[0].refs[0] == graph.fieldQueries[2].refs[0] {
						t.Fatal("typed refs mutation is vacuous")
					}
					graph.fieldQueries[0].refs = []valueSrc{graph.fieldQueries[2].refs[0]}
				case "container":
					graph.containerScanning = map[callerResolveKey]bool{callerResolveKeyFor(source, true): false}
				case "mutation":
					graph.mutationScanning = map[callerFieldKey]bool{{callerResolveKeyFor(source, true), fields[0]}: false}
				}
			}
			heads := maps.Clone(g.fieldQueryHeads)
			defer func() { g.fieldQueryHeads = heads }()
			full := g.captureCallerContainerObjectScope()
			entries, units, epoch, marks := c.entries, c.weight, g.bindingEpoch, callerReuseMarks(g)
			checks := 0
			g.ctx = &callerExecutionResetContext{Context: context.Background(), checkpoint: func() {
				checks++
				if checks != trigger {
					return
				}
				if trigger == 1 {
					if c.active != 0 {
						t.Fatal("before-copy callback already owns a new ticket")
					}
					callerAssertExecutionRetention(t, c, nil)
				} else {
					var pending *callerObjectExecutionScope
					for _, head := range c.scopes {
						for node := head; node != nil; node = node.next {
							if node.snapshot.matches(g) {
								pending = node
							}
						}
					}
					if pending == nil || c.active != 1 {
						t.Fatal("after-copy callback lacks a real accounted ticket")
					}
					callerAssertExecutionRetention(t, c, pending)
				}
				mutate(g, base)
			}}
			// Opaque контекст проверяет настоящий lifecycle-примитив напрямую;
			// end-to-end replay с таким контекстом остаётся запрещённым.
			if acquired := c.scope(g); acquired != nil {
				c.releaseTicket(g, acquired)
				t.Fatal("checkpoint mutation crossed the complete fresh proof")
			}
			g.ctx = nil
			if checks != trigger || c.active != 0 || c.entries != entries || c.weight != units || g.bindingEpoch != epoch || callerReuseMarks(g) != marks || full.matches(g) {
				t.Fatal("checkpoint was vacuous, changed semantic state or leaked ownership")
			}
			callerAssertExecutionRetention(t, c, nil)
			// Неканонический стек нельзя отдавать raw evaluator. Для heads
			// восстанавливаем индекс; для остальных изменений сравниваем именно
			// изменённое содержимое с отдельным настоящим original-графом.
			if change == "heads" {
				g.fieldQueryHeads = maps.Clone(heads)
			} else {
				mutate(slow, slowBase)
			}
			fastChecks, slowChecks := 0, 0
			g.ctx = &callerExecutionResetContext{Context: context.Background(), checkpoint: func() { fastChecks++ }}
			slow.ctx = &callerExecutionResetContext{Context: context.Background(), checkpoint: func() { slowChecks++ }}
			gm, sm := callerReuseMarks(g), callerReuseMarks(slow)
			gr, sr, hits, stores := g.work.ObjectRawEvaluations, slow.work.ObjectRawEvaluations, g.work.ObjectExecutionHits, g.work.ObjectExecutionStores
			got, unknown := g.callerObjects(root, map[callerObjectSourceID]bool{})
			want, otherUnknown := slow.callerObjects(slowRoot, map[callerObjectSourceID]bool{})
			g.ctx, slow.ctx = nil, nil
			if len(got) == 0 || !maps.Equal(got, want) || unknown != otherUnknown || callerReuseDelta(g, gm) != callerReuseDelta(slow, sm) || fastChecks == 0 || fastChecks != slowChecks {
				t.Fatal("opaque original twins changed objects, UNKNOWN, four marks or actual Err trace")
			}
			if g.work.ObjectRawEvaluations <= gr || g.work.ObjectRawEvaluations-gr != slow.work.ObjectRawEvaluations-sr || g.work.ObjectExecutionHits != hits || g.work.ObjectExecutionStores != stores {
				t.Fatal("opaque twin did not execute equal real raw work without replay")
			}
			callerAssertExecutionRetention(t, c, nil)
		})
	}
}
