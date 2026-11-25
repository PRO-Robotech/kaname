// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"maps"
	"testing"
)

// Это малый предметный reproducer, не эквивалент full202. Twin вводит временную
// переменную, сохраняя значение x; её дополнительное место хранения законно
// меняет provenance. Между разными AST ключи и множества не сравниваются.
func callerValueReceiverProgram(t *testing.T, twin bool) *surfaceProgram {
	t.Helper()
	assignment := "x=x.Project();"
	if twin {
		assignment = "tmp:=x.Project();x=tmp;"
	}
	p := callerSoundnessProgram(t,
		`type Projection struct{Field Reader;Removed Reader}
func(value Projection)Project()Projection{value.Removed=nil;return value}`,
		`x:=Projection{Field:Benign{},Removed:Concrete{}};`+assignment+
			`x.Field=Concrete{};_=x.Field;extra:=Projection{Field:Concrete{}};_=extra;`, "&Handler{}")
	t.Cleanup(func() { callerGraphs.Delete(p) })
	return p
}

// Источник — настоящий AST owner записи x.Field, как ID254 нового witness.
// Стек поля создаётся штатным enter, а не поддельным hash/depth свидетельством.
func callerValueReceiverGraph(t *testing.T, p *surfaceProgram, reference bool) (*callerGraph, valueSrc, valueSrc, map[string]valueSrc, context.CancelFunc) {
	t.Helper()
	g := callerGraphFor(p, nil)
	ctx, cancel := context.WithCancel(context.Background())
	g.ctx = ctx
	t.Cleanup(cancel)
	g.lifetimeScanning = true
	var root, field valueSrc
	literals := map[string]valueSrc{}
	for node, body := range g.bodies {
		if body.sp != p.root || node.fn == nil || node.fn.Name() != "RPC" {
			continue
		}
		g.markCallerCalled(node)
		ast.Inspect(body.node, func(n ast.Node) bool {
			src := valueSrc{pkg: body.sp, fk: callerKey(node), tuple: -1}
			switch x := n.(type) {
			case *ast.AssignStmt:
				if len(x.Lhs) == 1 && len(x.Rhs) == 1 {
					if id, ok := x.Lhs[0].(*ast.Ident); ok && id.Name == "x" {
						if literal, ok := x.Rhs[0].(*ast.CompositeLit); ok {
							src.expr = literal
							literals["anchor"] = src
						}
					}
				}
				for _, lhs := range x.Lhs {
					selector, ok := lhs.(*ast.SelectorExpr)
					if !ok || selector.Sel.Name != "Field" {
						continue
					}
					if id, ok := selector.X.(*ast.Ident); ok && id.Name == "x" {
						root, field = src, src
						root.expr, field.expr = selector.X, selector
					}
				}
			case *ast.CompositeLit:
				if id, ok := x.Type.(*ast.Ident); ok {
					src.expr = x
					literals[id.Name] = src
				}
			}
			return true
		})
	}
	if root.expr == nil || field.expr == nil || literals["anchor"].expr == nil || literals["Benign"].expr == nil || literals["Concrete"].expr == nil {
		t.Fatal("нет настоящего owner записи или типизированных значений")
	}
	selector := field.expr.(*ast.SelectorExpr)
	index, entered := g.enterCallerFieldQuery(root, fieldPath(p.root.info.Selections[selector]))
	if !entered {
		t.Fatal("не создан настоящий активный запрос поля")
	}
	g.fieldQueries[index].refs = []valueSrc{literals["Benign"]}
	t.Cleanup(func() { g.leaveCallerFieldQuery(index) })
	if reference {
		// Существующий штатный fallback; ни ответ, ни cuts, ни memo не подменяем.
		g.objectExecutions = nil
	}
	return g, root, field, literals, cancel
}

func TestCallerIdentityValueReceiverExactStateReproducer(t *testing.T) {
	for _, twin := range []bool{false, true} {
		name := "self_assignment"
		if twin {
			name = "temporary_twin"
		}
		t.Run(name, func(t *testing.T) {
			p := callerValueReceiverProgram(t, twin)
			g, root, _, literals, _ := callerValueReceiverGraph(t, p, false)
			reference, otherRoot, _, _, _ := callerValueReceiverGraph(t, p, true)
			if callerResolveKeyFor(root, true) != callerResolveKeyFor(otherRoot, true) {
				t.Fatal("reference использует другой source")
			}
			var previousState callerObjectExecutionState
			var previousScope callerContainerObjectScope
			var previousContext context.Context
			var previousObjects map[callerObjectKey]bool
			var previousUnknown bool
			var previousMarks [4]uint64
			var previousRaw int
			var escaped []map[callerObjectKey]bool
			var saved []map[callerObjectKey]bool
			equalPairs, repeatedPairs := 0, 0
			// Конечное наблюдение, не performance budget и не прогрев до успеха.
			for iteration := 0; iteration < 6; iteration++ {
				state := g.callerObjectExecutionState()
				scope := g.captureCallerContainerObjectScope()
				same := iteration > 0 && previousState == state && previousScope.matches(g) && previousContext == g.ctx
				if !g.callerExecutionScopeTracked() || !scope.matches(g) {
					t.Fatal("нет полного structural/content свидетельства текущего scope")
				}
				ctx := g.ctx
				marks, referenceMarks := callerReuseMarks(g), callerReuseMarks(reference)
				raw := g.work.ObjectRawEvaluations
				seen, referenceSeen := map[callerObjectSourceID]bool{}, map[callerObjectSourceID]bool{}
				got, unknown := g.callerObjects(root, seen)
				want, otherUnknown := reference.callerObjects(otherRoot, referenceSeen)
				delta, referenceDelta := callerReuseDelta(g, marks), callerReuseDelta(reference, referenceMarks)
				rawDelta := g.work.ObjectRawEvaluations - raw
				if len(seen) != 0 || len(referenceSeen) != 0 || !maps.Equal(got, want) || unknown != otherUnknown || delta != referenceDelta {
					t.Fatalf("production/fallback различаются: objects=%d/%d unknown=%v/%v marks=%v/%v", len(got), len(want), unknown, otherUnknown, delta, referenceDelta)
				}
				if len(got) == 0 || !got[callerOwnershipZero(root)] || !got[callerObjectKey{pkg: p.root, expr: literals["anchor"].expr}] {
					t.Fatal("reproducer потерял место хранения x или конкретное основание Projection")
				}
				if same {
					equalPairs++
					if !maps.Equal(got, previousObjects) || unknown != previousUnknown || delta != previousMarks {
						t.Fatal("равный полный вход изменил объекты, UNKNOWN или semantic marks")
					}
					if previousRaw > 0 && rawDelta > 0 {
						repeatedPairs++
					}
				}
				for i := range escaped {
					if !maps.Equal(escaped[i], saved[i]) {
						t.Fatal("следующий обход изменил ранее возвращённую read-only карту")
					}
				}
				escaped, saved = append(escaped, got), append(saved, maps.Clone(got))
				t.Logf("iteration=%d exact_previous_input=%v raw=%d objects=%d unknown=%v marks=%v input_state=%+v", iteration, same, rawDelta, len(got), unknown, delta, state)
				previousState, previousScope, previousContext = state, scope, ctx
				previousObjects, previousUnknown, previousMarks, previousRaw = maps.Clone(got), unknown, delta, rawDelta
			}
			classification := "UNCONFIRMED_STATE_CHANGED"
			if equalPairs > 0 {
				classification = "NO_REPEAT_IN_EQUAL_INPUT_PAIRS"
			}
			if repeatedPairs > 0 {
				classification = "VERIFIED_RAW_REPEAT_IN_EQUAL_INPUT_PAIRS"
			}
			t.Logf("DIAGNOSTIC_NOT_PERFORMANCE_ACCEPTANCE classification=%s equal_pairs=%d repeated_pairs=%d full202_equivalence=false runtime_allocation=UNMEASURED", classification, equalPairs, repeatedPairs)
		})
	}
}

func TestCallerIdentityValueReceiverNegativeKeysAndOwnership(t *testing.T) {
	for _, kind := range []string{"binding", "refs", "unknown", "nonempty_seen", "context_cancel", "ownership"} {
		t.Run(kind, func(t *testing.T) {
			p := callerValueReceiverProgram(t, false)
			g, root, field, literals, cancel := callerValueReceiverGraph(t, p, false)
			reference, otherRoot, otherField, otherLiterals, referenceCancel := callerValueReceiverGraph(t, p, true)
			for range 3 {
				g.callerObjects(root, map[callerObjectSourceID]bool{})
				reference.callerObjects(otherRoot, map[callerObjectSourceID]bool{})
				g.callerObjects(field, map[callerObjectSourceID]bool{})
				reference.callerObjects(otherField, map[callerObjectSourceID]bool{})
			}
			state, scope := g.callerObjectExecutionState(), g.captureCallerContainerObjectScope()
			seen, otherSeen := map[callerObjectSourceID]bool{}, map[callerObjectSourceID]bool{}
			switch kind {
			case "binding":
				extra := callerOwnershipSources(p)["extra"]
				g.addCallerLive(callerVariable(root.pkg, root.expr), extra)
				reference.addCallerLive(callerVariable(otherRoot.pkg, otherRoot.expr), extra)
				if g.callerObjectExecutionState() == state {
					t.Fatal("новый binding не изменил полный state")
				}
			case "refs":
				g.fieldQueries[0].refs = []valueSrc{literals["Concrete"]}
				reference.fieldQueries[0].refs = []valueSrc{otherLiterals["Concrete"]}
				if scope.matches(g) {
					t.Fatal("равная длина refs скрыла другой полный scope")
				}
				root, otherRoot = field, otherField
			case "unknown":
				g.fieldQueries[0].unknown, reference.fieldQueries[0].unknown = true, true
				if scope.matches(g) {
					t.Fatal("UNKNOWN скрыт равной формой scope")
				}
				root, otherRoot = field, otherField
			case "nonempty_seen":
				seen[g.internObjectSource(root)] = true
				otherSeen[reference.internObjectSource(otherRoot)] = true
			case "context_cancel":
				cancel()
				referenceCancel()
			case "ownership":
				objects, _, owned := g.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
				before := maps.Clone(objects)
				probe := callerObjectKey{pkg: p.root, expr: ast.NewIdent("owned_probe")}
				if owned {
					if len(objects) == 0 {
						t.Fatal("пустой ответ заявил owned")
					}
					objects[probe] = true
				}
				again, _, _ := g.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
				if again[probe] || !owned && !maps.Equal(objects, before) {
					t.Fatal("owned ответ разделяет карту с replay либо borrowed карта изменена")
				}
				// Симметрично продвигаем reference через те же настоящие Owned-входы.
				reference.callerObjectsOwned(otherRoot, map[callerObjectSourceID]bool{})
				reference.callerObjectsOwned(otherRoot, map[callerObjectSourceID]bool{})
				t.Logf("owned=%v objects=%d", owned, len(before))
			}
			marks, otherMarks := callerReuseMarks(g), callerReuseMarks(reference)
			got, unknown := g.callerObjects(root, seen)
			want, otherUnknown := reference.callerObjects(otherRoot, otherSeen)
			if !maps.Equal(got, want) || unknown != otherUnknown || callerReuseDelta(g, marks) != callerReuseDelta(reference, otherMarks) {
				t.Fatal("негативный вход разошёлся со штатным fallback")
			}
			if kind == "binding" && !got[callerOwnershipZero(callerOwnershipSources(p)["extra"])] {
				t.Fatal("новое binding потеряло дополнительное место хранения")
			}
			if kind == "refs" && !got[callerObjectKey{pkg: p.root, expr: literals["Concrete"].expr}] {
				t.Fatal("новое содержимое refs не появилось в provenance")
			}
			if kind == "unknown" && !unknown {
				t.Fatal("активный UNKNOWN потерян")
			}
			if kind == "context_cancel" && (!unknown || len(got) != 0) {
				t.Fatal("отменённый контекст вернул прежнее доказательство")
			}
			if kind == "nonempty_seen" && (len(seen) != 1 || !seen[g.internObjectSource(root)] || len(otherSeen) != 1) {
				t.Fatal("вход изменил чужую историю seen")
			}
		})
	}
}
