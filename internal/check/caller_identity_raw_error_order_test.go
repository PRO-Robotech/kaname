// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"maps"
	"testing"
)

func callerRawErrorOrderFixture(t *testing.T) (*callerGraph, valueSrc) {
	t.Helper()
	p := callerTraceTypedProgram(t, `leaf:=func(){};_=leaf`)
	g := callerGraphFor(p, nil)
	g.ctx = context.Background()
	var literal valueSrc
	for node, body := range g.bodies {
		if body.sp != p.root || node.fn == nil || node.fn.Name() != "RPC" {
			continue
		}
		ast.Inspect(body.node, func(n ast.Node) bool {
			if f, ok := n.(*ast.FuncLit); ok {
				literal = valueSrc{pkg: body.sp, fk: callerKey(node), tuple: -1, expr: f}
			}
			return true
		})
	}
	if literal.expr == nil {
		t.Fatal("не найдена типизированная функция")
	}
	return g, literal
}

func TestCallerIdentityRawBranchesPreserveErrorOrder(t *testing.T) {
	g, src := callerRawErrorOrderFixture(t)
	id := g.internObjectSource(src)
	invalidID := g.internObjectSource(valueSrc{})
	for _, tc := range []struct {
		name                               string
		invalid, cancelled, overflow, seen bool
		wantErr                            int
		wantUnknown                        bool
	}{
		{"cancel_before_invalid_and_seen", true, true, false, true, 1, true},
		{"overflow_before_err_and_seen", false, false, true, true, 0, true},
		{"invalid_before_seen", true, false, false, true, 1, true},
		{"terminal_seen", false, false, false, true, 2, false},
		{"entered_unseen", false, false, false, false, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input, key := src, id
			if tc.invalid {
				input, key = valueSrc{}, invalidID
			}
			seen := map[callerObjectSourceID]bool{}
			if tc.seen {
				seen[key] = true
			}
			calls := 0
			g.ctx = &callerTraceDelayedContext{Context: context.Background(), step: func() error {
				calls++
				if tc.cancelled {
					return context.Canceled
				}
				return nil
			}}
			g.semanticOverflow = tc.overflow
			before := maps.Clone(seen)
			objects, unknown, owned := g.callerObjectsRaw(input, seen, key, nil)
			if calls != tc.wantErr || unknown != tc.wantUnknown || owned || len(objects) != 0 || !maps.Equal(seen, before) {
				t.Fatalf("изменился исход обхода: вызовов Err() = %d, unknown = %v, owned = %v", calls, unknown, owned)
			}
		})
	}
}
