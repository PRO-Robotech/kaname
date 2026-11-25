// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"fmt"
	"go/ast"
	"go/types"
	"maps"
	"slices"
	"strings"
	"testing"
)

// Это свидетель исходного обхода, а не проверка нового ускорителя. Большое
// число путей должно реально раскрыться при малом числе typed источников.
func TestCallerIdentityExpansionDAGBaselineWitness(t *testing.T) {
	for _, depth := range []int{4, 6, 8} {
		t.Run(fmt.Sprintf("depth_%d", depth), func(t *testing.T) {
			var body strings.Builder
			body.WriteString("holder:=&Holder{items:[]Box{}};x0:=holder.items;")
			for level := 1; level <= depth; level++ {
				fmt.Fprintf(&body, "l%d:=x%d;r%d:=x%d;x%d:=l%d;x%d=r%d;", level, level-1, level, level-1, level, level, level, level)
			}
			fmt.Fprintf(&body, "_=append(x%d,Box{});", depth)
			p := callerSoundnessProgram(t, "type Holder struct{items []Box}", body.String(), "&Handler{}")
			t.Cleanup(func() { callerGraphs.Delete(p) })
			g := callerGraphFor(p, nil)
			// Отсутствующий namespace уже имеет штатный полный fallback. Ни memo,
			// ни результаты, ни счётчики исходного обхода не подменяются.
			g.objectExecutions = nil
			g.lifetimeScanning = true
			aliases := map[string]valueSrc{}
			var leaf, appended valueSrc
			for node, function := range g.bodies {
				if function.sp != p.root || node.fn == nil || node.fn.Name() != "RPC" {
					continue
				}
				g.markCallerCalled(node)
				ast.Inspect(function.node, func(n ast.Node) bool {
					src := valueSrc{pkg: function.sp, fk: callerKey(node), tuple: -1}
					switch x := n.(type) {
					case *ast.Ident:
						if v, ok := function.sp.info.Defs[x].(*types.Var); ok && !v.IsField() && (strings.HasPrefix(x.Name, "x") || strings.HasPrefix(x.Name, "l") || strings.HasPrefix(x.Name, "r")) {
							src.expr = x
							aliases[x.Name] = src
						}
					case *ast.SelectorExpr:
						if x.Sel.Name == "items" {
							if leaf.expr != nil {
								t.Fatal("fixture has more than one terminal field read")
							}
							src.expr = x
							leaf = src
						}
					case *ast.CallExpr:
						if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "append" && len(x.Args) == 2 {
							src.expr = x.Args[1]
							appended = src
						}
					}
					return true
				})
			}
			root := aliases[fmt.Sprintf("x%d", depth)]
			if len(aliases) != 3*depth+1 || root.expr == nil || leaf.expr == nil || appended.expr == nil {
				t.Fatal("typed diamond lost its aliases, terminal field, or append")
			}
			selector := leaf.expr.(*ast.SelectorExpr)
			base := leaf
			base.expr = selector.X
			fields := fieldPath(leaf.pkg.info.Selections[selector])
			if len(fields) != 1 {
				t.Fatal("terminal must select one exact typed field")
			}
			ownerObjects, ownerUnknown := g.callerObjects(base, map[callerObjectSourceID]bool{})
			index, entered := g.enterCallerFieldQuery(base, fields)
			if !entered || ownerUnknown || len(ownerObjects) != 2 {
				t.Fatal("real field owner did not establish allocation and storage")
			}
			t.Cleanup(func() { g.leaveCallerFieldQuery(index) })
			// Срез получается настоящим обходом литерала. Устанавливаем ровно
			// checkpoint remember после raw-фазы, до container/mutation/lifetime.
			// Здесь нет выдуманных refs или готового object answer.
			snapshot, snapshotUnknown := g.embeddedCallerSourcesRaw(base, fields, map[callerFieldKey]bool{})
			if snapshotUnknown || len(snapshot) != 1 {
				t.Fatal("typed holder literal did not produce one concrete slice source")
			}
			g.fieldQueries[index].refs, g.fieldQueries[index].unknown = snapshot, snapshotUnknown
			if len(g.fieldQueries) != 1 || !g.callerExecutionScopeTracked() {
				t.Fatal("real field checkpoint lost its exact tracked frame")
			}
			terminalObjects, terminalUnknown := g.callerObjects(snapshot[0], map[callerObjectSourceID]bool{})
			if terminalUnknown || len(terminalObjects) != 1 {
				t.Fatal("terminal slice allocation is not exact")
			}
			wantLeaf := maps.Clone(terminalObjects)
			for object := range ownerObjects {
				object.field = fields[0].Origin()
				wantLeaf[object] = true
			}
			if len(wantLeaf) != 3 {
				t.Fatal("terminal oracle lost allocation or field-qualified storage")
			}

			// Перепись рёбер берёт настоящие typed assignment sources; она не
			// исполняет новый evaluator и не считает повторные пути отдельными V.
			vertices := map[callerResolveKey]valueSrc{callerResolveKeyFor(root, true): root}
			for _, alias := range aliases {
				for _, ref := range g.sources(callerVariable(alias.pkg, alias.expr)) {
					vertices[callerResolveKeyFor(ref, true)] = ref
				}
			}
			vertices[callerResolveKeyFor(base, true)] = base
			vertices[callerResolveKeyFor(snapshot[0], true)] = snapshot[0]
			edges := 2 // Две точные границы leaf: owner memo и slice memo.
			for key, src := range vertices {
				if key == callerResolveKeyFor(base, true) {
					continue // Уже завершённый owner — терминальная граница.
				}
				if _, alias := src.expr.(*ast.Ident); alias {
					edges += len(g.sources(callerVariable(src.pkg, src.expr)))
				}
			}
			if len(vertices) != 4*depth+4 || edges != 6*depth+2 {
				t.Fatalf("typed region census differs: V=%d E=%d depth=%d", len(vertices), edges, depth)
			}

			// Полный прогрев отделён от измерения. Cut обязан пережить прогрев:
			// иначе ordinary memo скрыл бы именно исследуемый повтор.
			g.callerObjects(root, map[callerObjectSourceID]bool{})
			leafMarks, leafRaw := callerReuseMarks(g), g.work.ObjectRawEvaluations
			leafObjects, leafUnknown := g.callerObjects(leaf, map[callerObjectSourceID]bool{})
			unitMarks := callerReuseDelta(g, leafMarks)
			if leafUnknown || !maps.Equal(leafObjects, wantLeaf) || unitMarks != [4]uint64{3, 2, 0, 0} || g.work.ObjectRawEvaluations-leafRaw != 1 {
				t.Fatalf("active field is not a stable cut terminal: unknown=%v marks=%v raw=%d", leafUnknown, unitMarks, g.work.ObjectRawEvaluations-leafRaw)
			}
			want := maps.Clone(wantLeaf)
			for _, alias := range aliases {
				want[callerOwnershipZero(alias)] = true
			}
			if len(want) != 3*depth+4 {
				t.Fatal("typed storage oracle collapsed distinct alias variables")
			}
			paths := 1 << depth
			wantRaw := 5*paths - 3 // R0=2; R(d)=2*R(d-1)+3.
			var wantMarks [4]uint64
			for i, mark := range unitMarks {
				wantMarks[i] = uint64(paths) * mark
			}
			for repeat := 0; repeat < 2; repeat++ {
				state := g.callerObjectExecutionState()
				scope := g.captureCallerContainerObjectScope()
				marks, raw := callerReuseMarks(g), g.work.ObjectRawEvaluations
				seen := map[callerObjectSourceID]bool{}
				got, unknown := g.callerObjects(root, seen)
				actualRaw, actualMarks := g.work.ObjectRawEvaluations-raw, callerReuseDelta(g, marks)
				if unknown || !maps.Equal(got, want) || actualMarks != wantMarks || actualRaw != wantRaw {
					t.Fatalf("baseline witness differs: depth=%d repeat=%d unknown=%v objects=%d raw=%d/%d marks=%v/%v", depth, repeat, unknown, len(got), actualRaw, wantRaw, actualMarks, wantMarks)
				}
				if len(seen) != 0 || state != g.callerObjectExecutionState() || !scope.matches(g) || g.semanticOverflow || g.work.ObjectExecutionHits != 0 || g.work.ObjectExecutionStores != 0 {
					t.Fatal("measured region changed its durable state, active scope, or fallback mode")
				}
				if actualRaw <= len(vertices)+edges {
					t.Fatal("reference does not violate the proposed one-expansion-per-vertex/edge bound")
				}
				for key := range vertices {
					if key == callerResolveKeyFor(base, true) || key == callerResolveKeyFor(snapshot[0], true) {
						continue
					}
					id := g.objectSourceIDs[key]
					_, initialComplete := g.initialObjectMemo[id]
					_, fullComplete := g.objectMemo[id]
					if id == 0 || initialComplete || fullComplete {
						t.Fatal("cut-bearing alias/field region entered a completed object memo")
					}
				}
				t.Logf("BASELINE depth=%d repeat=%d V=%d E=%d paths=%d raw=%d objects=%d unknown=%v marks=%v", depth, repeat, len(vertices), edges, paths, actualRaw, len(got), unknown, actualMarks)
			}

			// Настоящий append связывает тот же diamond с container owner lookup.
			// Это отдельный контроль пути, не часть измеренной прозрачной области.
			marks, raw := callerReuseMarks(g), g.work.ObjectRawEvaluations
			matched := g.work.ContainerMatchedWrites
			values, unknown := g.callerContainerSources(root, nil, map[callerFieldKey]bool{})
			containerMarks := wantMarks
			for i := range containerMarks {
				containerMarks[i] *= 2
			}
			if unknown || !slices.Equal(values, []valueSrc{appended}) || g.work.ContainerMatchedWrites-matched != 1 || g.work.ObjectRawEvaluations-raw != 2*wantRaw || callerReuseDelta(g, marks) != containerMarks {
				t.Fatalf("real container edge differs: unknown=%v values=%d matched=%d raw=%d marks=%v", unknown, len(values), g.work.ContainerMatchedWrites-matched, g.work.ObjectRawEvaluations-raw, callerReuseDelta(g, marks))
			}
		})
	}
}
