// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"sync"
	"testing"
)

func TestCallerIdentityContainerCandidatesPreserveStaticScan(t *testing.T) {
	param := types.NewTypeParam(types.NewTypeName(token.NoPos, nil, "T", nil), types.NewInterfaceType(nil, nil).Complete())
	ints := types.NewSlice(types.Typ[types.Int])
	named := types.NewNamed(types.NewTypeName(token.NoPos, nil, "Numbers", nil), ints, nil)
	generic := types.NewSlice(param)
	mapping := types.NewMap(types.Typ[types.String], types.Typ[types.Int])
	array := types.NewArray(types.Typ[types.Int], 2)
	structural := types.NewSlice(types.NewStruct([]*types.Var{types.NewField(token.NoPos, nil, "X", types.Typ[types.Int], false)}, nil))
	structuralNamed := types.NewNamed(types.NewTypeName(token.NoPos, nil, "Rows", nil), structural, nil)
	owners := []types.Type{ints, named, types.NewSlice(types.Typ[types.String]), generic, nil, ints, mapping, array, structural, structuralNamed}
	sp := &surfaceSrcPkg{info: &types.Info{Types: map[ast.Expr]types.TypeAndValue{}}}
	g := &callerGraph{}
	for i, typ := range owners {
		expr := &ast.Ident{Name: "owner"}
		if typ != nil {
			sp.info.Types[expr] = types.TypeAndValue{Type: typ}
		}
		g.lifetimeWrites = append(g.lifetimeWrites, callerLifetimeWrite{owner: valueSrc{pkg: sp, expr: expr}, whole: i == 5})
	}
	g.indexCallerLifetimeWrites()
	for _, tc := range []struct {
		name string
		typ  types.Type
		want []int
	}{
		{"concrete", ints, []int{0, 1, 3, 4}},
		{"named_underlying", named, []int{0, 1, 3, 4}},
		{"structural_underlying", structural, []int{3, 4, 8, 9}},
		{"generic_query", generic, []int{0, 1, 2, 3, 4, 6, 7, 8, 9}},
		{"map", mapping, []int{3, 4, 6}},
		{"array", array, []int{3, 4, 7}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Независимый прежний предикат по исходным записям, включая порядок исходников.
			var old []int
			for ordinal, write := range g.lifetimeWrites {
				if write.whole {
					continue
				}
				owner := callerContainerType(write.owner.pkg.info.TypeOf(write.owner.expr))
				if owner != nil && !types.Identical(owner.Underlying(), tc.typ.Underlying()) && !g.hasCallerTypeParam(owner) && !g.hasCallerTypeParam(tc.typ) {
					continue
				}
				old = append(old, ordinal)
			}
			if !reflect.DeepEqual(old, tc.want) {
				t.Fatalf("old predicate fixture=%v want=%v", old, tc.want)
			}
			for range 2 {
				got, ok := g.callerContainerWriteCandidates(tc.typ)
				if !ok || !reflect.DeepEqual(got, old) {
					t.Fatalf("indexed=%v retained=%v old=%v", got, ok, old)
				}
			}
		})
	}
	if g.work.ContainerCandidateBuilds != 6 || g.work.ContainerCandidateHits != 6 {
		t.Fatalf("unexpected cache work: %+v", g.work)
	}
}

func TestCallerIdentityContainerCandidatesFallbackIsComplete(t *testing.T) {
	typ := types.NewSlice(types.Typ[types.Int])
	g := &callerGraph{}
	if _, ok := g.callerContainerWriteCandidates(typ); ok {
		t.Fatal("nil index retained a result")
	}
	g.indexCallerLifetimeWrites()
	for _, key := range []types.Type{nil, types.Typ[types.Int]} {
		if _, ok := g.callerContainerWriteCandidates(key); ok {
			t.Fatal("unknown key must fall back")
		}
	}
	// Кешированное пустое множество — полный ответ, отличный от запасного полного обхода.
	if result, ok := g.callerContainerWriteCandidates(typ); !ok || len(result) != 0 {
		t.Fatal("empty answer was lost")
	}
	for len(g.lifetimeWriteIndex.queries) < callerContainerCandidateEntries {
		g.lifetimeWriteIndex.queries[types.NewSlice(types.Typ[types.String])] = nil
	}
	if _, ok := g.callerContainerWriteCandidates(types.NewSlice(types.Typ[types.Int])); ok {
		t.Fatal("entry limit did not select full scan")
	}
	if _, ok := g.callerContainerWriteCandidates(typ); !ok {
		t.Fatal("entry limit disabled existing entries")
	}
	sp := &surfaceSrcPkg{info: &types.Info{Types: map[ast.Expr]types.TypeAndValue{}}}
	g.lifetimeWrites = []callerLifetimeWrite{{owner: valueSrc{pkg: sp, expr: &ast.Ident{Name: "unknown"}}}}
	g.indexCallerLifetimeWrites()
	g.lifetimeWriteIndex.weight = callerContainerCandidateValues
	if _, ok := g.callerContainerWriteCandidates(typ); ok {
		t.Fatal("ordinal limit retained an incomplete answer")
	}
	if len(g.lifetimeWriteIndex.queries) != 0 {
		t.Fatal("partial candidate list published")
	}
}

func TestCallerIdentityContainerIndexMatchesFullScanAcrossLiveState(t *testing.T) {
	for _, tc := range []struct {
		name, setup string
		unknown     bool
	}{
		{"alias", `var shelf=[]Box{{reader:Benign{}}};func mutate(){alias:=shelf;alias[0]=Box{reader:Concrete{}}}`, false},
		{"opaque_owner", `var shelf=[]Box{{reader:Benign{}}};func mutate(){alias:=source.Value().([]Box);alias[0]=Box{reader:Concrete{}}}`, true},
		{"whole_and_unrelated", `var shelf=[]Box{{reader:Benign{}}};func mutate(){alias:=shelf;alias[0]=Box{reader:Concrete{}};other:=[]int{0};other[0]=1;*(&other)=[]int{2}}`, false},
		{"outer_closure", `var shelf=[]Box{{reader:Benign{}}};func mutate(){_ = func(){_ = func(){alias:=shelf;alias[0]=Box{reader:Concrete{}}}}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := callerSoundnessProgram(t, tc.setup, `_=shelf[0]`, `&Handler{}`)
			defer callerGraphs.Delete(p)
			indexed := callerGraphFor(p, nil)
			full := callerGraphFor(p, nil)
			full.lifetimeWriteIndex = nil // Исходный полный обход остаётся исполняемым эталоном.
			var src valueSrc
			ast.Inspect(p.root.files[0], func(n ast.Node) bool {
				if spec, ok := n.(*ast.ValueSpec); ok {
					for _, id := range spec.Names {
						if id.Name == "shelf" {
							src = valueSrc{pkg: p.root, expr: id, tuple: -1}
						}
					}
				}
				return true
			})
			if src.expr == nil {
				t.Fatal("missing container query")
			}
			var mutate callerNode
			for node := range indexed.bodies {
				if node.fn != nil && node.fn.Name() == "mutate" {
					mutate = node
				}
			}
			if mutate.fn == nil {
				t.Fatal("missing mutation body")
			}
			query := func(g *callerGraph) ([]valueSrc, bool) {
				g.safeExternal = map[string]bool{"fixture/source": true}
				return g.callerContainerSources(src, nil, map[callerFieldKey]bool{})
			}
			check := func(stage string) ([]valueSrc, bool) {
				t.Helper()
				got, u := query(indexed)
				old, oldU := query(full)
				if u != oldU || !reflect.DeepEqual(got, old) {
					t.Fatalf("%s indexed=(%v,%v) full=(%v,%v)", stage, got, u, old, oldU)
				}
				return got, u
			}
			if refs, u := check("inactive warmup"); len(refs) != 0 || u {
				t.Fatalf("inactive writes returned refs=%v unknown=%v", refs, u)
			}
			indexed.markCallerCalled(mutate)
			full.markCallerCalled(mutate)
			refs, u := check("active after warmup")
			if u != tc.unknown || (!tc.unknown && len(refs) == 0) {
				t.Fatalf("active fixture refs=%v unknown=%v", refs, u)
			}
			check("active warm repeat")
			if indexed.work.ContainerOriginalWrites != indexed.work.ContainerScannedWrites+indexed.work.ContainerExcludedWrites+indexed.work.ContainerInactiveSkippedWrites {
				t.Fatal("source/visited/excluded diagnostic counts disagree")
			}
			// GraphFor сбрасывает состояние решения, разделяя лишь неизменяемые метаданные
			// и синхронизированный статический кеш. Ответ об эффекте не переживает этот сброс.
			reset := callerGraphFor(p, nil)
			if reset.lifetimeWriteIndex != indexed.lifetimeWriteIndex {
				t.Fatal("static index not shared")
			}
			if got, u := query(reset); len(got) != 0 || u {
				t.Fatalf("reset retained live answer: %v %v", got, u)
			}
			// Также проверяем обычную поверхностную копию с независимой картой called.
			copyGraph := *reset
			copyGraph.called = map[callerNode]bool{}
			copyGraph.markCallerCalled(mutate)
			if got, v := query(&copyGraph); v != u || !reflect.DeepEqual(got, refs) {
				t.Fatalf("copy lost fresh answer: %v %v", got, v)
			}
			if got, u := query(reset); len(got) != 0 || u {
				t.Fatalf("copy leaked live state: %v %v", got, u)
			}
			// Исчерпание записей и порядковых номеров должно выполнять полный исходный обход,
			// включая случаи алиасов и UNKNOWN выше, без изменения вычисленного ответа.
			for _, mode := range []string{"entries", "ordinals"} {
				fallback := callerGraphFor(p, nil)
				fallback.indexCallerLifetimeWrites()
				if mode == "entries" {
					for i := 0; i < callerContainerCandidateEntries; i++ {
						fallback.lifetimeWriteIndex.queries[types.NewSlice(types.Typ[types.Int])] = nil
					}
				} else {
					fallback.lifetimeWriteIndex.weight = callerContainerCandidateValues
				}
				fallback.markCallerCalled(mutate)
				got, v := query(fallback)
				if v != u || !reflect.DeepEqual(got, refs) || fallback.work.ContainerIndexFallbacks == 0 {
					t.Fatalf("%s fallback lost answer: %v %v", mode, got, v)
				}
			}
		})
	}
}

// Настоящий кеш графов использует поверхностные копии. Параллельно проверяем только
// общий статический кеш; каждая копия владеет своими диагностическими счётчиками.
func TestCallerIdentityContainerCandidateMemoSharesSafely(t *testing.T) {
	typ := types.NewSlice(types.Typ[types.Int])
	sp := &surfaceSrcPkg{info: &types.Info{Types: map[ast.Expr]types.TypeAndValue{}}}
	expr := &ast.Ident{Name: "owner"}
	sp.info.Types[expr] = types.TypeAndValue{Type: typ}
	g := &callerGraph{lifetimeWrites: []callerLifetimeWrite{{owner: valueSrc{pkg: sp, expr: expr}}}}
	g.indexCallerLifetimeWrites()
	var workers sync.WaitGroup
	for range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			clone := *g
			clone.work = CallerIdentityWork{}
			for range 8 {
				result, ok := clone.callerContainerWriteCandidates(typ)
				if !ok || len(result) != 1 || result[0] != 0 {
					t.Error("shared memo lost immutable candidate")
				}
			}
		}()
	}
	workers.Wait()
	if len(g.lifetimeWriteIndex.queries) != 1 || g.lifetimeWriteIndex.weight != 1 {
		t.Fatal("concurrent cache publication repeated retention")
	}
}

func TestCallerIdentityContainerIndexPreservesRecursiveFieldAnswers(t *testing.T) {
	for _, value := range []string{`Concrete{}`, `source.Value().(Reader)`} {
		t.Run(value, func(t *testing.T) {
			p := callerSoundnessProgram(t, `var shelf=[]Box{{reader:Benign{}}};func mutate(){alias:=shelf;alias[0]=Box{reader:`+value+`}}`, `_=shelf[0]`, `&Handler{}`)
			defer callerGraphs.Delete(p)
			indexed := callerGraphFor(p, nil)
			full := callerGraphFor(p, nil)
			full.lifetimeWriteIndex = nil
			indexed.safeExternal = map[string]bool{"fixture/source": true}
			full.safeExternal = map[string]bool{"fixture/source": true}
			var src valueSrc
			ast.Inspect(p.root.files[0], func(n ast.Node) bool {
				if spec, ok := n.(*ast.ValueSpec); ok {
					for _, id := range spec.Names {
						if id.Name == "shelf" {
							src = valueSrc{pkg: p.root, expr: id, tuple: -1}
						}
					}
				}
				return true
			})
			field := p.root.types.Scope().Lookup("Box").Type().Underlying().(*types.Struct).Field(0)
			for _, active := range []bool{false, true, true} {
				if active {
					for node := range indexed.bodies {
						if node.fn != nil && node.fn.Name() == "mutate" {
							indexed.markCallerCalled(node)
							full.markCallerCalled(node)
						}
					}
				}
				got, u := indexed.callerContainerSources(src, []*types.Var{field}, map[callerFieldKey]bool{})
				old, v := full.callerContainerSources(src, []*types.Var{field}, map[callerFieldKey]bool{})
				if u != v || !reflect.DeepEqual(got, old) {
					t.Fatalf("active=%v recursive field indexed=(%v,%v) full=(%v,%v)", active, got, u, old, v)
				}
			}
		})
	}
}
