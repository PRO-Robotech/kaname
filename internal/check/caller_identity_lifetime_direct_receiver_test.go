// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"testing"
)

func TestCallerIdentityLifetimeDirectReceiverCopy(t *testing.T) {
	const setup = `
type Inner struct{ Ref *Box }
type Receiver struct{ Inner Inner; Refs []*Box }
func (Receiver) Value()
func (*Receiver) Pointer()
type Promoted struct{ Receiver }
`
	for _, tc := range []struct {
		name, body string
		want       bool
	}{
		{"fresh_outer_and_nested", `Receiver{Inner:Inner{}}.Value()`, false},
		{"fresh_positional", `Receiver{Inner{},nil}.Value()`, false},
		{"retains_direct_reference", `Receiver{Inner:Inner{Ref:anchor}}.Value()`, true},
		{"retains_slice_alias", `shared:=make([]*Box,1);copied:=shared;shared[0]=anchor;Receiver{Refs:copied}.Value()`, true},
		{"addressable_copy", `receiver:=Receiver{};source.Mutate(&receiver);receiver.Value()`, true},
		{"pointer_receiver", `(&Receiver{Inner:Inner{Ref:anchor}}).Pointer()`, true},
		{"promoted_receiver", `Promoted{Receiver:Receiver{Inner:Inner{Ref:anchor}}}.Value()`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program := callerSoundnessProgram(t, setup,
				`anchor:=&Box{};other:=source.Value().([]*Box);other[0]=anchor;`+tc.body, `&Handler{}`)
			g := newCallerGraph(program)
			g.safeExternal = map[string]bool{"fixture/source": true}
			g.lifetimeScanning = true
			var site callSrc
			var wanted callerObjectKey
			for node, body := range g.bodies {
				if body.sp != program.root || node.fn == nil || node.fn.Name() != "RPC" {
					continue
				}
				g.markCallerCalled(node)
				ast.Inspect(body.node, func(n ast.Node) bool {
					switch expr := n.(type) {
					case *ast.UnaryExpr:
						if lit, ok := expr.X.(*ast.CompositeLit); ok && wanted.expr == nil {
							wanted = callerObjectKey{pkg: body.sp, expr: lit}
						}
					case *ast.CallExpr:
						if sel, ok := expr.Fun.(*ast.SelectorExpr); ok &&
							(sel.Sel.Name == "Value" || sel.Sel.Name == "Pointer") && body.sp.info.Selections[sel] != nil {
							site = callSrc{pkg: body.sp, fk: callerKey(node), call: expr}
						}
					}
					return true
				})
			}
			if wanted.expr == nil || site.call == nil || g.callerLifetimeLocal(site) {
				t.Fatal("фикстура не дошла до непрозрачного получателя")
			}
			probe := func() callerLifetimeProbe {
				return callerLifetimeProbe{g: g, want: wanted, seen: map[callerResolveKey]bool{}, objects: map[callerObjectKey]bool{}}
			}
			p := probe()
			if got := p.opaqueCalleeContains(site); got != tc.want {
				t.Fatalf("связь с получателем=%t, ожидается %t", got, tc.want)
			}
			if tc.want {
				return
			}
			p = probe()
			if !p.contains(valueSrc{pkg: site.pkg, fk: site.fk, expr: site.call.Fun, tuple: -1}) {
				t.Fatal("обычный обход не воспроизвёл связь с посторонним владельцем")
			}
			p = probe()
			p.steps = callerLifetimeStepLimit
			if !p.opaqueCalleeContains(site) {
				t.Fatal("лимит превратился в доказательство отсутствия связи")
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			g.ctx = ctx
			p = probe()
			if !p.opaqueCalleeContains(site) {
				t.Fatal("отмена превратилась в доказательство отсутствия связи")
			}
		})
	}
}
