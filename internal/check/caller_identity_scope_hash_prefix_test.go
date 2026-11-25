// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"testing"
)

func TestCallerIdentityScopeHashSuspendedFrames(t *testing.T) {
	p := callerCanonicalScopeProgram(t)
	reference, _, _, _ := callerCanonicalScopeGraph(t, p)
	g := callerGraphFor(p, nil)
	g.ctx = context.Background()
	g.claimCallerFieldQueryIndex()
	g.fieldQueryHashOwner = g
	c := g.objectExecutions
	uncached := &callerObjectExecutions{seed: c.seed}
	push := func(index int) {
		t.Helper()
		frame := reference.fieldQueries[index]
		got, entered := g.enterCallerFieldQuery(frame.source.source, frame.fields)
		if !entered || got != index {
			t.Fatalf("не вошли в кадр %d", index)
		}
		g.fieldQueries[got].refs = frame.refs
	}
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
