// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestCallerIdentityLifetimeWritesCanonicalSourceOrder(t *testing.T) {
	const source = `package fixture
//line shared.go:10
func pair() (int, int) { return 1, 2 }
func writes(xs []int, p *int) {
 xs[0], xs[1] = pair()
 xs = append(xs, 3, 4)
 *p = 5
}
`
	type row struct {
		pkg, file           string
		owner, value, tuple int
		whole               bool
	}
	// Independent expected offsets come from the fixture text, not a sorting helper.
	var want []row
	for _, pkg := range []string{"fixture/a", "fixture/z"} {
		want = append(want,
			row{pkg, "/" + pkg + "/writes.go", strings.Index(source, "xs[0]"), strings.LastIndex(source, "pair()"), 0, false},
			row{pkg, "/" + pkg + "/writes.go", strings.Index(source, "xs[1]"), strings.LastIndex(source, "pair()"), 1, false},
			row{pkg, "/" + pkg + "/writes.go", strings.Index(source, "xs, 3"), strings.Index(source, "3, 4"), -1, false},
			row{pkg, "/" + pkg + "/writes.go", strings.Index(source, "xs, 3"), strings.Index(source, "4)"), -1, false},
			row{pkg, "/" + pkg + "/writes.go", strings.Index(source, "p = 5"), strings.Index(source, "5\n"), -1, true},
		)
	}
	for _, reverseFiles := range []bool{false, true} {
		p := &surfaceProgram{fset: token.NewFileSet()}
		g := &callerGraph{p: p, bodies: map[callerNode]callerBody{}}
		packages := []string{"fixture/a", "fixture/z"}
		if reverseFiles {
			slices.Reverse(packages)
		}
		for _, path := range packages {
			file, err := parser.ParseFile(p.fset, "/"+path+"/writes.go", source, 0)
			if err != nil {
				t.Fatal(err)
			}
			info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
			pkg, err := (&types.Config{}).Check(path, p.fset, []*ast.File{file}, info)
			if err != nil {
				t.Fatal(err)
			}
			sp := &surfaceSrcPkg{path: path, types: pkg, files: []*ast.File{file}, info: info}
			p.pkgs = append(p.pkgs, sp)
			for _, decl := range file.Decls {
				fn := decl.(*ast.FuncDecl)
				g.bodies[callerNode{fn: info.Defs[fn.Name].(*types.Func)}] = callerBody{sp: sp, node: fn.Body}
			}
		}
		coordinates := func(writes []callerLifetimeWrite) []row {
			var out []row
			for _, write := range writes {
				op := p.fset.PositionFor(write.owner.expr.Pos(), false)
				vp := p.fset.PositionFor(write.value.expr.Pos(), false)
				out = append(out, row{write.owner.pkg.path, op.Filename, op.Offset, vp.Offset, write.value.tuple, write.whole})
			}
			return out
		}
		inventory := func(writes []callerLifetimeWrite) map[callerLifetimeWrite]int {
			out := map[callerLifetimeWrite]int{}
			for _, write := range writes {
				out[write]++
			}
			return out
		}
		// Ordinary production entry must order before the ordinal index is built.
		g.collectCallerLifetime()
		if !slices.Equal(coordinates(g.lifetimeWrites), want) {
			t.Fatalf("production order=%+v want=%+v", coordinates(g.lifetimeWrites), want)
		}
		forward := slices.Clone(g.lifetimeWrites)
		// Include an exact duplicate: ordering must not deduplicate source records.
		forward = append([]callerLifetimeWrite{forward[0]}, forward...)
		duplicateWant := append([]row{want[0]}, want...)
		for _, reverse := range []bool{false, true} {
			g.lifetimeWrites = slices.Clone(forward)
			if reverse {
				slices.Reverse(g.lifetimeWrites)
			}
			before := inventory(g.lifetimeWrites)
			g.orderCallerLifetimeWrites()
			if !maps.Equal(before, inventory(g.lifetimeWrites)) || !slices.Equal(coordinates(g.lifetimeWrites), duplicateWant) {
				t.Fatal("explicit permutation changed source identity, multiplicity, or canonical order")
			}
			g.indexCallerLifetimeWrites()
			got, ok := g.callerContainerWriteCandidates(types.NewSlice(types.Typ[types.Int]))
			if !ok || !slices.Equal(got, []int{0, 1, 2, 3, 4, 6, 7, 8, 9}) {
				t.Fatalf("container ordinals=%v retained=%v", got, ok)
			}
		}
	}
}

func TestCallerIdentityLifetimeWriteOrderKeepsCallbackContract(t *testing.T) {
	for _, escape := range []bool{false, true} {
		p, base := callerLifetimeOrderProgram(t, escape)
		graph := callerGraphFor(p, nil)
		original, _ := callerGraphs.Load(p)
		if len(graph.lifetimeWrites) < 2 {
			t.Fatal("fixture must exercise multiple lifetime writes")
		}
		observe := func(reverse, canonical bool) callerLifetimeOrderObservation {
			isolated := *original.(*callerGraphMemo).graph
			isolated.lifetimeWrites = slices.Clone(graph.lifetimeWrites)
			if reverse {
				slices.Reverse(isolated.lifetimeWrites)
			}
			if canonical {
				isolated.orderCallerLifetimeWrites()
			}
			isolated.indexCallerLifetimeWrites()
			memo := &callerGraphMemo{}
			memo.once.Do(func() { memo.graph = &isolated })
			var after callerLifetimeOrderObservation
			func() {
				callerGraphs.Store(p, memo)
				defer callerGraphs.Store(p, original)
				after = callerLifetimeOrderObserve(t, p, base, graph.lifetimeCalls, escape)
			}()
			return after
		}
		// The raw reverse control deliberately permutes the full write sequence.
		// It is a semantic oracle, not a claim about any historical map order.
		before := observe(true, false)
		for _, reverse := range []bool{false, true} {
			after := observe(reverse, true)
			if !slices.Equal(before.origins, after.origins) || before.unknown != after.unknown || before.lifetimeUnknown != after.lifetimeUnknown || !slices.Equal(before.negative.Findings, after.negative.Findings) || !slices.Equal(before.declared.Findings, after.declared.Findings) || !reflect.DeepEqual(before.negative.Reads, after.negative.Reads) || !reflect.DeepEqual(before.declared.Reads, after.declared.Reads) {
				t.Fatal("write ordering changed origins, unknown, Reads or Findings")
			}
			t.Logf("escape=%v reverse=%v objectRaw=%d->%d resolveRaw=%d->%d", escape, reverse, before.objectRaw, after.objectRaw, before.resolveRaw, after.resolveRaw)
		}
	}
}
