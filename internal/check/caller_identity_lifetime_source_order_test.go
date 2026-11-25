// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"slices"
	"strings"
	"testing"
)

func TestCallerIdentityLifetimeCallsCanonicalSourceOrder(t *testing.T) {
	const aSource = `package fixture
//line shared.go:10
var initA = factory()()
func factory() func() int { return leaf }
func leaf() int { return 1 }
func bodyA() { _ = leaf(); _ = leaf() }
`
	const zSource = `package fixture
//line shared.go:10
var initZ = leaf()
func bodyZ() { _ = factory()() }
`
	type row struct {
		pkg, file      string
		offset, length int
	}
	// Ожидаемые интервалы заданы исходным текстом, без сортировки и FileSet.
	// Оба вложенных вызова имеют один старт; вызовы leaf остаются отдельными.
	var want []row
	for _, pkg := range []string{"fixture/a", "fixture/b"} {
		a, z := "/"+pkg+"/a.go", "/"+pkg+"/z.go"
		aFactory := strings.Index(aSource, "factory()()")
		zFactory := strings.Index(zSource, "factory()()")
		want = append(want,
			row{pkg, a, aFactory, len("factory()")},
			row{pkg, a, aFactory, len("factory()()")},
			row{pkg, a, strings.Index(aSource, "leaf();"), len("leaf()")},
			row{pkg, a, strings.LastIndex(aSource, "leaf()"), len("leaf()")},
			row{pkg, z, strings.Index(zSource, "leaf()"), len("leaf()")},
			row{pkg, z, zFactory, len("factory()")},
			row{pkg, z, zFactory, len("factory()()")},
		)
	}
	for _, scene := range []struct {
		name    string
		reverse bool
	}{{"forward", false}, {"reverse", true}} {
		t.Run(scene.name, func(t *testing.T) {
			p := &surfaceProgram{fset: token.NewFileSet()}
			g := &callerGraph{p: p, bodies: map[callerNode]callerBody{}}
			expected := map[callSrc]int{}
			packages, files := []string{"fixture/a", "fixture/b"}, []string{"a.go", "z.go"}
			if scene.reverse {
				slices.Reverse(packages)
				slices.Reverse(files)
			}
			for _, pkgPath := range packages {
				info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
				sp := &surfaceSrcPkg{path: pkgPath, info: info}
				for _, name := range files {
					text := aSource
					if name == "z.go" {
						text = zSource
					}
					file, err := parser.ParseFile(p.fset, "/"+pkgPath+"/"+name, text, 0)
					if err != nil {
						t.Fatal(err)
					}
					sp.files = append(sp.files, file)
				}
				pkg, err := (&types.Config{}).Check(pkgPath, p.fset, sp.files, info)
				if err != nil {
					t.Fatal(err)
				}
				sp.types = pkg
				p.pkgs = append(p.pkgs, sp)
				if pkgPath == "fixture/a" {
					p.root = sp
				}
				for _, file := range sp.files {
					for _, decl := range file.Decls {
						owner := fkey{}
						if fn, ok := decl.(*ast.FuncDecl); ok {
							owner.fn = info.Defs[fn.Name].(*types.Func)
							g.bodies[callerNode{fn: owner.fn}] = callerBody{sp: sp, node: fn.Body, name: owner.fn.FullName()}
						}
						// Фикстура без литералов функций: каждая декларация задаёт
						// точного владельца всех своих вызовов, включая инициализаторы пакета.
						ast.Inspect(decl, func(node ast.Node) bool {
							if call, ok := node.(*ast.CallExpr); ok {
								if info.Types[call.Fun].IsType() {
									t.Fatal("в фикстуре неожиданно встретилось преобразование типа")
								}
								expected[callSrc{pkg: sp, fk: owner, call: call}]++
							}
							return true
						})
					}
				}
			}
			// Собираем вызовы тем же методом, что и при обычном анализе.
			g.collectCallerLifetime()
			actual := map[callSrc]int{}
			var got []row
			for _, site := range g.lifetimeCalls {
				actual[site]++
				position := p.fset.PositionFor(site.call.Pos(), false)
				got = append(got, row{site.pkg.path, position.Filename, position.Offset, int(site.call.End() - site.call.Pos())})
			}
			if len(want) != 14 || len(got) != len(want) || !maps.Equal(expected, actual) {
				t.Fatalf("изменились пакет, владелец, AST или число вызовов: got=%d want=%d, multiset=%v", len(got), len(want), maps.Equal(expected, actual))
			}
			if !slices.Equal(got, want) {
				t.Fatalf("порядок зависит от map/FileSet/директивы line: got=%+v want=%+v", got, want)
			}
		})
	}
}
