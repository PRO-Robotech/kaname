// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"testing"
)

func callerFrozenScopeStack(t *testing.T) (*callerGraph, func(int)) {
	t.Helper()
	p := callerCanonicalScopeProgram(t)
	reference, _, _, _ := callerCanonicalScopeGraph(t, p)
	g := callerGraphFor(p, nil)
	g.ctx = context.Background()
	g.claimCallerFieldQueryIndex()
	g.fieldQueryHashOwner = g
	push := func(index int) {
		t.Helper()
		frame := reference.fieldQueries[index]
		got, entered := g.enterCallerFieldQuery(frame.source.source, frame.fields)
		if !entered || got != index {
			t.Fatalf("не вошли в кадр %d", index)
		}
		g.fieldQueries[got].refs = frame.refs
	}
	return g, push
}

func TestCallerIdentityScopeHashSuspendedFrames(t *testing.T) {
	g, push := callerFrozenScopeStack(t)
	c := g.objectExecutions
	uncached := &callerObjectExecutions{seed: c.seed}
	check := func(wantSaved int) {
		t.Helper()
		before := g.work.ObjectScopePrefixFrames
		if got, want := c.scopeHash(g), uncached.scopeHash(g); got != want {
			t.Fatalf("корзина %x вместо полной %x", got, want)
		}
		if saved := g.work.ObjectScopePrefixFrames - before; saved != wantSaved {
			t.Fatalf("повторно использовано %d кадров вместо %d", saved, wantSaved)
		}
	}
	push(0)
	push(1)
	push(2)
	check(0)
	check(2)
	g.fieldQueries[2].unknown = true
	g.fieldQueries[2].refs = nil
	key := g.fieldQueries[1].source
	g.containerScanning = map[callerResolveKey]bool{key: false}
	g.mutationScanning = map[callerFieldKey]bool{{key, g.fieldQueries[1].fields[0]}: true}
	check(2)
	g.containerScanning[key] = true
	check(2)
	g.leaveCallerFieldQuery(2)
	g.fieldQueries[1].unknown = true
	g.fieldQueries[1].refs = nil
	push(2)
	check(1)
	check(2)

	// Внешний Err, копия графа и только структурное владение
	// не дают права доверять содержимому приостановленных кадров.
	g.ctx = &callerExecutionResetContext{Context: context.Background(), checkpoint: func() {}}
	g.fieldQueries[0].unknown = true
	check(0)
	g.ctx = context.Background()
	check(0)
	check(2)
	clone := *g
	clone.fieldQueries = callerExecutionSlice(g.fieldQueries)
	clone.fieldQueries[0].refs = nil
	if c.scopeHash(&clone) != uncached.scopeHash(&clone) {
		t.Fatal("копия графа получила префикс владельца")
	}
	g.fieldQueryHashOwner = nil
	g.fieldQueries[0].refs = nil
	check(0)
	g.leaveCallerFieldQuery(2)
	g.leaveCallerFieldQuery(1)
	g.leaveCallerFieldQuery(0)
	if c.prefixDepth != 0 {
		t.Fatal("пустой стек сохранил префикс")
	}
}

func TestCallerIdentityLastFrozenScope(t *testing.T) {
	for _, change := range []string{"active_refs", "active_field", "active_unknown", "container_value", "mutation_value", "thawed_parent"} {
		t.Run(change, func(t *testing.T) {
			g, push := callerFrozenScopeStack(t)
			push(0)
			push(1)
			push(2)
			c := g.objectExecutions
			key := g.fieldQueries[0].source
			fieldKey := callerFieldKey{key, g.fieldQueries[0].fields[0]}
			g.containerScanning = map[callerResolveKey]bool{key: false}
			g.mutationScanning = map[callerFieldKey]bool{fieldKey: false}
			first := c.scope(g)
			if first == nil || c.lastScope != first || c.lastFrozen != 2 {
				t.Fatal("closed acquisition did not certify the two suspended frames")
			}
			before := g.work.ObjectScopePrefixFrames
			again := c.scope(g)
			if again != first || g.work.ObjectScopePrefixFrames != before || c.active != 2 || first.references != 2 {
				t.Fatal("consecutive acquisition did not obtain the exact live ticket without rehashing")
			}
			c.releaseTicket(g, again)

			switch change {
			case "active_refs":
				g.fieldQueries[2].refs = nil
			case "active_field":
				g.fieldQueries[2].fields = g.fieldQueries[0].fields
			case "active_unknown":
				g.fieldQueries[2].unknown = true
			case "container_value":
				g.containerScanning[key] = true
			case "mutation_value":
				g.mutationScanning[fieldKey] = true
			case "thawed_parent":
				g.leaveCallerFieldQuery(2)
				if c.lastFrozen != 1 {
					t.Fatal("parent was still certified after child returned")
				}
				g.fieldQueries[1].refs = nil
				push(2)
			}
			if first.snapshot.matches(g) {
				t.Fatal("changed scope unexpectedly passed full comparison")
			}
			// Тот же live node и та же корзина не должны скрыть изменение.
			oldHash := first.hash
			callerTrackedProofMoveBucket(t, c, first, c.scopeHash(g))
			changed := c.scope(g)
			if changed == nil || changed == first || !changed.snapshot.matches(g) || c.lastScope != changed || c.lastFrozen != 2 {
				t.Fatal("scope equality survived a real content change and a forced bucket collision")
			}
			callerTrackedProofMoveBucket(t, c, first, oldHash)
			c.releaseTicket(g, changed)
			if c.lastScope != nil || c.lastFrozen != 0 || changed.references != 0 {
				t.Fatal("released scope left a lookup hint")
			}
			c.releaseTicket(g, first)
			if c.active != 0 || c.entries != 0 || c.weight != 0 {
				t.Fatal("scope lookup changed ownership accounting")
			}
		})
	}
}

func TestCallerIdentityLastFrozenScopeOpaqueCheckpoint(t *testing.T) {
	g, push := callerFrozenScopeStack(t)
	push(0)
	push(1)
	push(2)
	c := g.objectExecutions
	first := c.scope(g)
	if first == nil || c.lastScope != first {
		t.Fatal("missing live scope in closed graph")
	}
	defer c.releaseTicket(g, first)
	g.fieldQueries[2].unknown = true // Реальный miss до первого Err.
	calls := 0
	g.ctx = &callerExecutionResetContext{Context: context.Background(), checkpoint: func() {
		calls++
		if calls == 2 {
			g.fieldQueries[0].refs = nil
		}
	}}
	if node := c.scope(g); node != nil || calls != 2 || c.lastScope != nil || c.lastFrozen != 0 {
		t.Fatal("opaque Err mutation escaped the full post-copy check")
	}
	g.ctx = context.Background()
	g.fieldQueries[2].unknown = false
	node := c.scope(g)
	if node == nil || node == first || !node.snapshot.matches(g) {
		t.Fatal("closed lookup reused the prefix from before the opaque callback")
	}
	c.releaseTicket(g, node)
}

func TestCallerIdentityLastFrozenScopeAliasedAppend(t *testing.T) {
	g, push := callerFrozenScopeStack(t)
	push(0)
	push(1)
	c := g.objectExecutions
	left, right := g.fieldQueries[0].refs[0], g.fieldQueries[1].refs[0]
	if left == right {
		t.Fatal("typed reference sources must differ")
	}
	shared := []valueSrc{left, left}
	g.fieldQueries[0].refs = shared[:1]
	g.fieldQueries[1].refs = shared
	push(2)
	first := c.scope(g)
	if first == nil || c.lastFrozen != 2 {
		t.Fatal("missing closed scope for suspended refs")
	}
	defer c.releaseTicket(g, first)
	// Настоящий duplicate возвращает более короткий refs приостановленного предка.
	q := g.fieldQueries[0]
	short, _ := g.embeddedCallerSources(q.source.source, q.fields, map[callerFieldKey]bool{})
	updated := g.appendCallerFieldRefs(short, []valueSrc{right})
	if len(updated) != 2 || g.fieldQueries[1].refs[1] != right || first.snapshot.matches(g) || c.prefixDepth != 0 || c.lastFrozen != 0 {
		t.Fatal("alias write to the second suspended frame preserved a prefix certificate")
	}
	second := c.scope(g)
	if second == nil || second == first || !second.snapshot.matches(g) {
		t.Fatal("an aliased append produced a false lookup hit")
	}
	c.releaseTicket(g, second)
}

func TestCallerIdentityScopeRefSamplingKeepsExactInterior(t *testing.T) {
	for _, opaque := range []bool{false, true} {
		name := "retained_bucket"
		if opaque {
			name = "opaque_checkpoint"
		}
		t.Run(name, func(t *testing.T) {
			g, push := callerFrozenScopeStack(t)
			push(0)
			defer g.leaveCallerFieldQuery(0)
			frame := &g.fieldQueries[0]
			if len(frame.refs) == 0 {
				t.Fatal("expected concrete refs")
			}
			a := frame.refs[0]
			frame.refs = []valueSrc{a, a, a}
			c := g.objectExecutions
			bucket := c.scopeHash(g)
			changeInterior := func() { frame.refs[1].tuple = a.tuple + 1 }

			if opaque {
				g.ctx = &callerExecutionResetContext{Context: context.Background(), checkpoint: changeInterior}
				if scope := c.scope(g); scope != nil {
					t.Fatal("a callback changed the exact input before publication")
				}
				if got := c.scopeHash(g); got != bucket || c.active != 0 || c.entries != 0 {
					t.Fatal("the rejected collision changed bucket or retained tickets")
				}
				return
			}

			first := c.scope(g)
			if first == nil {
				t.Fatal("initial scope unavailable")
			}
			defer c.releaseTicket(g, first)
			changeInterior()
			if got := c.scopeHash(g); got != bucket {
				t.Fatal("the control did not produce an identical bucket")
			}
			second := c.scope(g)
			if second == nil || second == first || !second.snapshot.matches(g) || first.snapshot.matches(g) {
				t.Fatal("a matching bucket erased the interior ref change")
			}
			c.releaseTicket(g, second)
		})
	}
}
