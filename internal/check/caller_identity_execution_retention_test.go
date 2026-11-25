// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"maps"
	"strings"
	"testing"
)

// Все источники снимка — реальные typed присваивания одного поля. Каждый tick
// связывает новый реальный аргумент, но возвращает постоянный объект; это меняет
// долговечную эпоху, не раздувая результат проверяемого field query.
func callerExecutionRetentionFixture(t *testing.T) (*surfaceProgram, valueSrc, valueSrc, []valueSrc, []valueSrc) {
	t.Helper()
	const assignments = 64
	const calls = callerObjectExecutionValues/(assignments+4) + 2
	body := "box:=&Box{reader:Benign{}};" + strings.Repeat("box.reader=Benign{};", assignments) + strings.Repeat("_ = tick(&Box{});", calls) + "_ = box.reader"
	p := callerSoundnessProgram(t, "func tick(value *Box)*Box{return &Box{}}", body, `&Handler{}`)
	t.Cleanup(func() { callerGraphs.Delete(p) })
	g := callerGraphFor(p, nil)
	var field valueSrc
	var refs, ticks []valueSrc
	for node, body := range g.bodies {
		if body.sp != p.root || node.fn == nil || node.fn.Name() != "RPC" {
			continue
		}
		ast.Inspect(body.node, func(n ast.Node) bool {
			src := valueSrc{pkg: body.sp, fk: callerKey(node), tuple: -1}
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if x.Sel.Name == "reader" {
					src.expr = x
					field = src
				}
			case *ast.CompositeLit:
				if typ := namedOf(body.sp.info.TypeOf(x)); typ != nil && typ.Obj().Name() == "Benign" {
					src.expr = x
					refs = append(refs, src)
				}
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "tick" {
					src.expr = x
					ticks = append(ticks, src)
				}
			}
			return true
		})
	}
	if field.expr == nil || len(refs) != assignments+1 || len(ticks) != calls {
		t.Fatal("typed retention fixture lost its field values or real binding calls")
	}
	base := field
	base.expr = field.expr.(*ast.SelectorExpr).X
	return p, field, base, refs, ticks
}

// Независимый пересчёт включает каждый полный snapshot, owned result и ссылки
// на scopes. Дубликаты immutable данных не исключаются из прежнего бюджета.
func callerAssertExecutionRetention(t *testing.T, c *callerObjectExecutions, pinned *callerObjectExecutionScope) {
	t.Helper()
	entries, weight := len(c.answers), 0
	answerRefs := map[*callerObjectExecutionScope]int{}
	for key, answer := range c.answers {
		weight += 1 + len(answer.answer.objects)
		answerRefs[key.scope]++
	}
	traceEntries, traceWeight, traceRefs := callerTraceAccount(t, c)
	entries += traceEntries
	weight += traceWeight
	for scope, count := range traceRefs {
		answerRefs[scope] += count
	}
	found := pinned == nil
	for _, head := range c.scopes {
		for node := head; node != nil; node = node.next {
			entries++
			s := node.snapshot
			units := 1 + len(s.queries) + len(s.heads) + len(s.containers) + len(s.mutations)
			for _, query := range s.queries {
				units += len(query.fields) + len(query.refs)
			}
			weight += units
			wantRefs := answerRefs[node]
			if node == pinned {
				found = true
				wantRefs++
			}
			if node.weight != units || node.references != wantRefs {
				t.Fatal("retained scope weight/pins differ from real answers and live outer ticket")
			}
			delete(answerRefs, node)
		}
	}
	if !found || len(answerRefs) != 0 || entries != c.entries || weight != c.weight || entries > callerObjectExecutionEntries || weight > callerObjectExecutionValues {
		t.Fatal("retention lost a live scope or stopped counting an owned node/result")
	}
}

func TestCallerIdentityExecutionRetentionAcrossLiveGenerations(t *testing.T) {
	p, field, base, refs, ticks := callerExecutionRetentionFixture(t)
	type observation struct {
		objects           map[callerObjectKey]bool
		unknown           bool
		marks             [4]uint64
		tailRaw, tailHits int
	}
	run := func(reference bool) observation {
		g := callerGraphFor(p, nil)
		g.markCallerCalled(callerNode{fn: field.fk.fn, lit: field.fk.lit})
		g.lifetimeScanning = true
		if reference {
			g.objectExecutions = nil
		}
		selector := field.expr.(*ast.SelectorExpr)
		index, entered := g.enterCallerFieldQuery(base, fieldPath(field.pkg.info.Selections[selector]))
		if !entered {
			t.Fatal("typed field owner did not enter its real indexed scope")
		}
		defer g.leaveCallerFieldQuery(index)
		g.fieldQueries[index].refs = refs
		var warm map[callerObjectKey]bool
		for range 3 {
			var unknown bool
			warm, unknown = g.callerObjects(field, map[callerObjectSourceID]bool{})
			if unknown {
				t.Fatal("lawful typed field snapshot became unknown during warmup")
			}
		}
		immutable := maps.Clone(warm)
		answerUnits := 1 + len(warm)
		if len(warm) != len(refs)+2 || len(ticks)*answerUnits <= callerObjectExecutionValues {
			t.Fatal("typed obsolete answers do not exceed the unchanged value budget")
		}
		// Другой exact snapshot гарантирует реальный outer miss после warmup.
		g.fieldQueries[index].unknown = true
		// Отдельный lifecycle primitive удерживает scope через реальные поколения.
		var outerScope *callerObjectExecutionScope
		if !reference {
			outerScope = g.objectExecutions.scope(g)
			if outerScope == nil {
				t.Fatal("real outer scope acquisition failed")
			}
		}
		outerRaw := g.work.ObjectRawEvaluations
		marks := callerReuseMarks(g)
		triggered := false
		var got observation
		g.ctx = &callerExecutionResetContext{Context: context.Background(), checkpoint: func() {
			if triggered {
				return
			}
			if g.work.ObjectRawEvaluations == outerRaw {
				return
			}
			triggered = true
			// Cache-positive вложенные queries используют настоящий nil context;
			// оба эталона выполняют ровно такую же смену и восстановление.
			outerContext := g.ctx
			g.ctx = nil
			defer func() { g.ctx = outerContext }()
			var pinned *callerObjectExecutionScope
			if !reference {
				c := g.objectExecutions
				if c.active != 1 {
					t.Fatal("pressure did not start inside one real outer ticket")
				}
				for _, head := range c.scopes {
					for node := head; node != nil; node = node.next {
						if node.snapshot.matches(g) {
							pinned = node
						}
					}
				}
				if pinned == nil || pinned.references != 1 {
					t.Fatal("outer context was not pinned before its reentrant checkpoint")
				}
			}
			for _, tick := range ticks {
				epoch := g.bindingEpoch
				objects, unknown := g.callerObjects(tick, map[callerObjectSourceID]bool{})
				if unknown || len(objects) == 0 || g.bindingEpoch <= epoch {
					t.Fatal("typed call did not create a real new live binding")
				}
				// Первый обход греет ordinary memo, следующий публикует stable
				// execution; прогрев не входит в измеряемый повтор текущей эпохи.
				for range 3 {
					objects, unknown = g.callerObjects(field, map[callerObjectSourceID]bool{})
					if !unknown || !maps.Equal(objects, immutable) {
						t.Fatal("generation pressure changed field aliases or snapshot UNKNOWN")
					}
				}
				raw, hits := g.work.ObjectRawEvaluations, g.work.ObjectExecutionHits
				for range 4 {
					objects, unknown = g.callerObjects(field, map[callerObjectSourceID]bool{})
					if !unknown || !maps.Equal(objects, immutable) {
						t.Fatal("current exact generation replay changed its original answer")
					}
				}
				got.tailRaw += g.work.ObjectRawEvaluations - raw
				got.tailHits += g.work.ObjectExecutionHits - hits
				if !reference {
					c := g.objectExecutions
					if c.active != 1 || g.work.ObjectExecutionCapacityFallbacks != 0 {
						t.Fatal("dead generations exhausted capacity while the current working set fits")
					}
					callerAssertExecutionRetention(t, c, pinned)
				}
			}
		}}
		got.objects, got.unknown = g.callerObjects(field, map[callerObjectSourceID]bool{})
		if outerScope != nil {
			g.objectExecutions.releaseTicket(g, outerScope)
		}
		g.ctx = nil
		got.marks = callerReuseDelta(g, marks)
		if !triggered || !got.unknown || !maps.Equal(got.objects, immutable) || !maps.Equal(warm, immutable) || got.marks[2] != 0 {
			t.Fatal("real outer traversal lost its original answer, immutable map, or uncovered marks")
		}
		if !reference {
			if g.objectExecutions.active != 0 || g.work.ObjectExecutionRetiredAnswers < len(ticks)-1 || g.work.ObjectExecutionReleasedScopes == 0 {
				t.Fatal("obsolete retained generations or unowned scopes survived the completed pressure run")
			}
		}
		return got
	}
	actual, fallback := run(false), run(true)
	if actual.unknown != fallback.unknown || !maps.Equal(actual.objects, fallback.objects) || actual.marks != fallback.marks {
		t.Fatal("retention correction changed original provenance or semantic cut/skip/cycle effects")
	}
	// При старом active==0-only eviction сумма реальных old answer units выше
	// бюджета; без слоя тот же fallback обязательно нарушает нулевой raw bound.
	if actual.tailRaw != 0 || actual.tailHits != 4*len(ticks) || fallback.tailRaw < 4*len(ticks) || fallback.tailHits != 0 {
		t.Fatalf("generation work bound: actual raw=%d hits=%d; fallback raw=%d hits=%d", actual.tailRaw, actual.tailHits, fallback.tailRaw, fallback.tailHits)
	}
}

func TestCallerIdentityExecutionRetentionScopeCheckpoint(t *testing.T) {
	p, field, base, refs, ticks := callerExecutionRetentionFixture(t)
	for _, phase := range []string{"before_copy", "after_copy"} {
		t.Run(phase, func(t *testing.T) {
			g := callerGraphFor(p, nil)
			g.markCallerCalled(callerNode{fn: field.fk.fn, lit: field.fk.lit})
			g.lifetimeScanning = true
			selector := field.expr.(*ast.SelectorExpr)
			index, entered := g.enterCallerFieldQuery(base, fieldPath(field.pkg.info.Selections[selector]))
			if !entered {
				t.Fatal("checkpoint fixture did not enter its tracked typed scope")
			}
			defer g.leaveCallerFieldQuery(index)
			g.fieldQueries[index].refs = refs
			warm := maps.Clone(callerPrimeObjectExecution(t, g, field))
			g.fieldQueries[index].unknown = true
			checkpoints, trigger := 0, 1
			if phase == "after_copy" {
				trigger = 2
			}
			triggered := false
			var marks [4]uint64
			stores, hits := 0, 0
			g.ctx = &callerExecutionResetContext{Context: context.Background(), checkpoint: func() {
				if triggered {
					return
				}
				checkpoints++
				if checkpoints != trigger {
					return
				}
				triggered = true
				probeContext := g.ctx
				g.ctx = nil
				defer func() { g.ctx = probeContext }()
				var pending *callerObjectExecutionScope
				if phase == "after_copy" {
					if g.objectExecutions.active != 1 {
						t.Fatal("pending captured scope was not accounted and pinned before callback")
					}
					for _, head := range g.objectExecutions.scopes {
						for node := head; node != nil; node = node.next {
							if node.snapshot.matches(g) {
								pending = node
							}
						}
					}
					if pending == nil {
						t.Fatal("pending scope copy was absent from shared retention accounting")
					}
				}
				// Контент и его вес действительно изменяются. Затем реальный call
				// меняет binding и вложенные field queries удаляют obsolete answers.
				g.fieldQueries[index].refs = append(callerExecutionSlice(refs), refs...)
				epoch := g.bindingEpoch
				objects, unknown := g.callerObjects(ticks[0], map[callerObjectSourceID]bool{})
				if unknown || len(objects) == 0 || g.bindingEpoch <= epoch {
					t.Fatal("checkpoint did not execute its real typed binding")
				}
				for range 3 {
					objects, unknown = g.callerObjects(field, map[callerObjectSourceID]bool{})
					if !unknown || !maps.Equal(objects, warm) {
						t.Fatal("nested checkpoint traversal changed exact aliases")
					}
				}
				callerAssertExecutionRetention(t, g.objectExecutions, pending)
				marks = callerReuseMarks(g)
				stores, hits = g.work.ObjectExecutionStores, g.work.ObjectExecutionHits
			}}
			// Проверяем acquire/copy primitive напрямую: opaque end-to-end вход
			// обязан миновать его полностью и идти исходным обходом.
			if scope := g.objectExecutions.scope(g); scope != nil {
				g.objectExecutions.releaseTicket(g, scope)
				t.Fatal("mutated scope primitive accepted a stale capture")
			}
			objects, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
			g.ctx = nil
			delta := callerReuseDelta(g, marks)
			if !triggered || !unknown || !maps.Equal(objects, warm) || g.work.ObjectExecutionStores != stores || g.work.ObjectExecutionHits != hits || g.objectExecutions.active != 0 {
				t.Fatal("stale capture crossed a reentrant checkpoint as a hit or publication")
			}
			callerAssertExecutionRetention(t, g.objectExecutions, nil)
			marks = callerReuseMarks(g)
			want, otherUnknown, _ := g.callerObjectsOwned(field, map[callerObjectSourceID]bool{})
			if otherUnknown != unknown || !maps.Equal(want, objects) || callerReuseDelta(g, marks) != delta {
				t.Fatal("stale capture fallback changed original semantic effects")
			}
		})
	}
}

func TestCallerIdentityExecutionRetentionHitCheckpoint(t *testing.T) {
	for _, change := range []string{"refs", "unknown"} {
		g, field, base, literals := callerExecutionSnapshotFixture(t)
		old := callerPrimeObjectExecution(t, g, field)
		before := maps.Clone(old)
		// Настоящий ticket переживает opaque raw checkpoint; replay запрещён.
		pinned := g.objectExecutions.scope(g)
		if pinned == nil {
			t.Fatal("real hit-scope acquisition failed")
		}
		checks, hits, stores := 0, g.work.ObjectExecutionHits, g.work.ObjectExecutionStores
		epoch := g.bindingEpoch
		marks := callerReuseMarks(g)
		g.ctx = &callerExecutionResetContext{Context: context.Background(), checkpoint: func() {
			checks++
			if checks != 2 {
				return
			}
			if g.objectExecutions.active != 1 {
				t.Fatal("hit context was not pinned across its context checkpoint")
			}
			if change == "refs" {
				g.fieldQueries[0].refs[0] = literals["Concrete"]
			} else {
				g.fieldQueries[0].unknown = true
			}
		}}
		objects, unknown := g.callerObjects(field, map[callerObjectSourceID]bool{})
		g.objectExecutions.releaseTicket(g, pinned)
		g.ctx = nil
		delta := callerReuseDelta(g, marks)
		wantName := "Benign"
		if change == "refs" {
			wantName = "Concrete"
		}
		want := callerEffectCertificateObjects(t, field, base, literals, wantName)
		if checks < 2 || unknown != (change == "unknown") || !maps.Equal(objects, want) || !maps.Equal(old, before) || g.bindingEpoch != epoch || g.work.ObjectExecutionHits != hits || g.work.ObjectExecutionStores != stores || g.objectExecutions.active != 0 {
			t.Fatal("same-epoch callback mutation replayed or published a stale scope answer")
		}
		callerAssertExecutionRetention(t, g.objectExecutions, nil)
		marks = callerReuseMarks(g)
		original, originalUnknown, _ := g.callerObjectsOwned(field, map[callerObjectSourceID]bool{})
		if originalUnknown != unknown || !maps.Equal(original, objects) || callerReuseDelta(g, marks) != delta {
			t.Fatal("invalidated hit changed the original fallback semantic effects")
		}
	}
}
