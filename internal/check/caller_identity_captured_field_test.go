// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package check

import (
	"context"
	"go/ast"
	"slices"
	"testing"
)

const callerCapturedFieldSetup = `
type Runner interface{run(Reader)}
type Worker struct{reader Reader}
func(w *Worker)run(arg Reader){w.reader.read();arg.read()}
type Holder struct{F func(Reader)}
`

func TestCallerIdentityCapturedFieldBinding(t *testing.T) {
	for _, tc := range []struct {
		name, extra string
		direct      bool
	}{
		{"interface_only", "", false},
		{"also_direct_value", "func observe(w *Worker){_=w.run}", true},
		{"also_method_expression", "var _=(*Worker).run", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const body = "var r Runner=&Worker{reader:Concrete{}}; hld:=Holder{F:r.run};hld.F(Benign{})"
			pg := callerSoundnessProgram(t, callerCapturedFieldSetup+tc.extra, body, "&Handler{}")
			g := newCallerGraph(pg)
			g.ctx = context.Background()
			g.lifetimeScanning = true
			var call *ast.CallExpr
			var owner, worker callerNode
			for n, b := range g.bodies {
				if b.sp != pg.root || n.fn == nil {
					continue
				}
				switch n.fn.Name() {
				case "run":
					worker = n
				case "RPC":
					owner = n
					ast.Inspect(b.node, func(node ast.Node) bool {
						c, ok := node.(*ast.CallExpr)
						if ok {
							if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "F" {
								call = c
							}
						}
						return true
					})
				}
			}
			if call == nil || owner.fn == nil || worker.fn == nil {
				t.Fatal("нет вызываемой функции или её источника")
			}
			sel := call.Fun.(*ast.SelectorExpr)
			selection := pg.root.info.Selections[sel]
			sig := worker.fn.Signature()
			recv := sig.Recv().Origin()
			if g.capturedCallerField(pg.root, sel, selection, worker.fn, sig) {
				t.Fatal("получатель ещё не связан")
			}
			targets, unknown := g.resolve(valueSrc{pkg: pg.root, fk: callerKey(owner), expr: sel, tuple: -1}, false, map[callerResolveKey]bool{})
			if unknown || len(targets) != 1 || targets[0].node != worker {
				t.Fatalf("неожиданные цели: %d, unknown=%v", len(targets), unknown)
			}
			before := slices.Clone(g.live[recv])
			if len(before) == 0 {
				t.Fatal("потерян захваченный интерфейсом получатель")
			}
			if g.directMethodRefs[worker.fn] != tc.direct || g.capturedCallerField(pg.root, sel, selection, worker.fn, sig) == tc.direct {
				t.Fatal("прямое или диспетчеризованное происхождение не распознано")
			}
			g.bindCaller(pg.root, owner, call, worker)
			holder := valueSrc{pkg: pg.root, fk: callerKey(owner), expr: sel.X, tuple: -1}
			if slices.Contains(g.live[recv], holder) != tc.direct || !tc.direct && !slices.Equal(g.live[recv], before) {
				t.Fatal("нарушена привязка захваченного получателя")
			}
			arg := valueSrc{pkg: pg.root, fk: callerKey(owner), expr: call.Args[0], tuple: -1}
			if !slices.Contains(g.live[sig.Params().At(0).Origin()], arg) {
				t.Fatal("потерян обычный аргумент вызова")
			}
		})
	}
}
