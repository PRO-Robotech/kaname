// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/types"
	"maps"
	"slices"
	"testing"
)

func callerCanonicalScopeProgram(t *testing.T) *surfaceProgram {
	t.Helper()
	p := callerSoundnessProgram(t, "type Pair struct{left Box;right Box}", "a:=&Pair{left:Box{},right:Box{}};b:=&Pair{left:Box{}};_=a.left;_=b.left;_=a.right;", "&Handler{}")
	t.Cleanup(func() { callerGraphs.Delete(p) })
	return p
}

// Все источники и оба поля взяты из typed RPC. Повторный source использует
// тот же настоящий AST use a, но другой путь поля; enter создаёт цепочку 3→1.
func callerCanonicalScopeGraph(t *testing.T, p *surfaceProgram) (*callerGraph, valueSrc, valueSrc, []*types.Var) {
	t.Helper()
	g := callerGraphFor(p, nil)
	g.lifetimeScanning = true
	selected := map[string]valueSrc{}
	var literals []valueSrc
	for node, body := range g.bodies {
		if body.sp != p.root || node.fn == nil || node.fn.Name() != "RPC" {
			continue
		}
		g.markCallerCalled(node)
		ast.Inspect(body.node, func(n ast.Node) bool {
			src := valueSrc{pkg: body.sp, fk: callerKey(node), tuple: -1}
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if base, ok := x.X.(*ast.Ident); ok && body.sp.info.Selections[x] != nil {
					src.expr = x
					selected[base.Name+"."+x.Sel.Name] = src
				}
			case *ast.CompositeLit:
				src.expr = x
				literals = append(literals, src)
			}
			return true
		})
	}
	a, b, right := selected["a.left"], selected["b.left"], selected["a.right"]
	if a.expr == nil || b.expr == nil || right.expr == nil {
		t.Fatal("typed field sources missing")
	}
	abase, bbase := a, b
	abase.expr = a.expr.(*ast.SelectorExpr).X
	bbase.expr = b.expr.(*ast.SelectorExpr).X
	leftPath := fieldPath(a.pkg.info.Selections[a.expr.(*ast.SelectorExpr)])
	rightPath := fieldPath(right.pkg.info.Selections[right.expr.(*ast.SelectorExpr)])
	if len(leftPath) != 1 || len(rightPath) != 1 || leftPath[0] == rightPath[0] {
		t.Fatal("typed paths are not distinct fields")
	}
	for _, src := range append(literals, abase, bbase) {
		g.callerObjects(src, map[callerObjectSourceID]bool{})
	}
	indices := []int{}
	t.Cleanup(func() {
		for i := len(indices) - 1; i >= 0; i-- {
			g.leaveCallerFieldQuery(indices[i])
		}
	})
	for _, frame := range []struct {
		source valueSrc
		fields []*types.Var
	}{{abase, leftPath}, {bbase, leftPath}, {abase, rightPath}} {
		refs, unknown := g.embeddedCallerSourcesRaw(frame.source, frame.fields, map[callerFieldKey]bool{})
		if unknown || len(refs) == 0 {
			t.Fatal("typed field did not supply concrete raw provenance")
		}
		index, entered := g.enterCallerFieldQuery(frame.source, frame.fields)
		if !entered {
			t.Fatal("real distinct field frame was rejected")
		}
		indices = append(indices, index)
		g.fieldQueries[index].refs, g.fieldQueries[index].unknown = refs, unknown
	}
	if len(g.fieldQueryHeads) != 2 || len(g.fieldQueries) != 3 || g.fieldQueryHeads[callerResolveKeyFor(abase, true)] != 3 || g.fieldQueries[2].previousSourceQuery != 1 || !g.callerExecutionScopeTracked() {
		t.Fatal("actual multi-source stack did not establish the repeated-source chain")
	}
	return g, a, bbase, rightPath
}

func TestCallerIdentityCanonicalExecutionScopeReplayAndPayload(t *testing.T) {
	p := callerCanonicalScopeProgram(t)
	fast, root, _, _ := callerCanonicalScopeGraph(t, p)
	slow, otherRoot, _, _ := callerCanonicalScopeGraph(t, p)
	slow.objectExecutions = nil
	for range 2 {
		fast.callerObjects(root, map[callerObjectSourceID]bool{})
		slow.callerObjects(otherRoot, map[callerObjectSourceID]bool{})
	}
	c := fast.objectExecutions
	pin := c.freshScope(fast)
	if pin == nil {
		t.Fatal("real execution scope acquisition failed")
	}
	defer c.releaseTicket(fast, pin)
	// Старый полный снимок — независимый положительный свидетель реально
	// копируемых heads. Он сохранён в продукте для локального container reuse.
	full := fast.captureCallerContainerObjectScope()
	if len(full.heads) != 2 || !maps.Equal(full.heads, fast.fieldQueryHeads) || !full.matches(fast) || pin.snapshot.heads != nil || !pin.snapshot.matches(fast) {
		t.Fatal("canonical snapshot did not remove the duplicate full-reference heads payload")
	}
	units := 1 + len(full.queries) + len(full.containers) + len(full.mutations)
	for _, q := range full.queries {
		units += len(q.fields) + len(q.refs)
	}
	if pin.weight != units || 1+fast.callerContainerObjectScopeWeight()-pin.weight != len(full.heads) {
		t.Fatal("physical retained payload does not differ by the exact omitted heads map")
	}
	state, epoch := fast.callerObjectExecutionState(), fast.bindingEpoch
	var escaped map[callerObjectKey]bool
	for range 8 {
		fm, sm := callerReuseMarks(fast), callerReuseMarks(slow)
		fr, sr, hits := fast.work.ObjectRawEvaluations, slow.work.ObjectRawEvaluations, fast.work.ObjectExecutionHits
		got, unknown := fast.callerObjects(root, map[callerObjectSourceID]bool{})
		want, otherUnknown := slow.callerObjects(otherRoot, map[callerObjectSourceID]bool{})
		if unknown || otherUnknown || len(got) == 0 || !maps.Equal(got, want) || callerReuseDelta(fast, fm) != callerReuseDelta(slow, sm) || callerReuseDelta(fast, fm)[0] <= callerReuseDelta(fast, fm)[1] || callerReuseDelta(fast, fm)[2] != 0 {
			t.Fatal("canonical execution changed objects, UNKNOWN or four semantic marks")
		}
		if fast.work.ObjectExecutionHits != hits+1 || fast.work.ObjectRawEvaluations != fr || slow.work.ObjectRawEvaluations <= sr || fast.callerObjectExecutionState() != state || fast.bindingEpoch != epoch {
			t.Fatal("real replay lacked a positive original-body witness or changed durable state")
		}
		if escaped == nil {
			escaped = maps.Clone(got)
		} else if !maps.Equal(got, escaped) {
			t.Fatal("borrowed answer changed")
		}
		callerAssertExecutionRetention(t, c, pin)
	}
}

func TestCallerIdentityCanonicalExecutionScopeInvalidHeads(t *testing.T) {
	for _, name := range []string{"latest", "zero", "extra", "missing", "wrong_source", "previous_cycle", "previous_skip", "overlap", "indexed_depth"} {
		t.Run(name, func(t *testing.T) {
			g, root, _, _ := callerCanonicalScopeGraph(t, callerCanonicalScopeProgram(t))
			callerPrimeObjectExecution(t, g, root)
			c := g.objectExecutions
			pin := c.freshScope(g)
			if pin == nil {
				t.Fatal("real canonical pin missing")
			}
			defer c.releaseTicket(g, pin)
			heads, queries, depth := maps.Clone(g.fieldQueryHeads), slices.Clone(g.fieldQueries), g.fieldQueryIndexedDepth
			defer func() { g.fieldQueryHeads, g.fieldQueries, g.fieldQueryIndexedDepth = heads, queries, depth }()
			a, b := queries[0].source, queries[1].source
			switch name {
			case "latest":
				g.fieldQueryHeads[a] = 1
			case "zero":
				g.fieldQueryHeads[a] = 0
			case "extra":
				g.fieldQueryHeads[callerResolveKeyFor(root, true)] = 3
			case "missing":
				delete(g.fieldQueryHeads, b)
			case "wrong_source":
				g.fieldQueryHeads[a] = 2
			case "previous_cycle":
				g.fieldQueries[2].previousSourceQuery = 3
			case "previous_skip":
				g.fieldQueries[2].previousSourceQuery = 0
			case "overlap":
				g.fieldQueryHeads[b] = 3
			case "indexed_depth":
				g.fieldQueryIndexedDepth--
			}
			entries, units, active, hits := c.entries, c.weight, c.active, g.work.ObjectExecutionHits
			// malformed previous нельзя отдавать raw traversal, который ожидает
			// штатный стек. Проверяем настоящий admission и post-Err matches отдельно.
			if pin.snapshot.matches(g) || g.callerExecutionScopeTracked() {
				t.Fatal("noncanonical heads accepted at exact snapshot boundary")
			}
			if acquired := c.freshScope(g); acquired != nil {
				c.releaseTicket(g, acquired)
				t.Fatal("noncanonical heads acquired a real ticket")
			}
			if c.entries != entries || c.weight != units || c.active != active || g.work.ObjectExecutionHits != hits {
				t.Fatal("rejected structure changed retained ownership or replay")
			}
		})
	}
}

func TestCallerIdentityCanonicalExecutionScopeContentAndPop(t *testing.T) {
	for _, name := range []string{"refs_order", "refs_content", "unknown", "field_identity", "container_false_extra", "mutation_false_extra", "pop_restore"} {
		t.Run(name, func(t *testing.T) {
			g, _, bbase, right := callerCanonicalScopeGraph(t, callerCanonicalScopeProgram(t))
			leftRef, rightRef := g.fieldQueries[0].refs[0], g.fieldQueries[2].refs[0]
			if leftRef == rightRef {
				t.Fatal("typed fields did not give distinct provenance")
			}
			g.fieldQueries[0].refs = []valueSrc{leftRef, rightRef}
			c := g.objectExecutions
			pin := c.freshScope(g)
			if pin == nil {
				t.Fatal("real canonical scope missing")
			}
			defer c.releaseTicket(g, pin)
			full := g.captureCallerContainerObjectScope()
			epoch := g.bindingEpoch
			if !pin.snapshot.matches(g) || !full.matches(g) {
				t.Fatal("baseline exact scopes differ")
			}
			switch name {
			case "refs_order":
				g.fieldQueries[0].refs = []valueSrc{rightRef, leftRef}
			case "refs_content":
				g.fieldQueries[0].refs = []valueSrc{rightRef, rightRef}
			case "unknown":
				g.fieldQueries[0].unknown = true
			case "field_identity":
				g.fieldQueries[0].fields = right
			case "container_false_extra":
				g.containerScanning = map[callerResolveKey]bool{callerResolveKeyFor(bbase, true): false}
			case "mutation_false_extra":
				g.mutationScanning = map[callerFieldKey]bool{{callerResolveKeyFor(bbase, true), right[0]}: false}
			case "pop_restore":
				index, entered := g.enterCallerFieldQuery(bbase, right)
				if !entered {
					t.Fatal("distinct real nested frame missing")
				}
				if pin.snapshot.matches(g) || full.matches(g) {
					g.leaveCallerFieldQuery(index)
					t.Fatal("push reused the older full context")
				}
				g.leaveCallerFieldQuery(index)
			}
			if name != "pop_restore" {
				if !g.callerExecutionScopeTracked() || pin.snapshot.matches(g) || full.matches(g) || g.bindingEpoch != epoch {
					t.Fatal("same-epoch exact payload change did not invalidate both representations")
				}
				g.fieldQueries[0].refs = callerExecutionSlice(full.queries[0].refs)
				g.fieldQueries[0].fields = callerExecutionSlice(full.queries[0].fields)
				g.fieldQueries[0].unknown = full.queries[0].unknown
				g.containerScanning, g.mutationScanning = maps.Clone(full.containers), maps.Clone(full.mutations)
			}
			if !pin.snapshot.matches(g) || !full.matches(g) {
				t.Fatal("restored exact content lost equality")
			}
			again := c.freshScope(g)
			if again == nil {
				t.Fatal("restored scope could not acquire a real ticket")
			}
			if again != pin {
				c.releaseTicket(g, again)
				t.Fatal("restoration did not recover the pinned content identity")
			}
			c.releaseTicket(g, again)
			callerAssertExecutionRetention(t, c, pin)
		})
	}
}
