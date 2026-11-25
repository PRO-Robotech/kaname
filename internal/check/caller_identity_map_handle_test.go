// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"go/types"
	"maps"
	"testing"
)

func TestCallerIdentityClosedMapHandleDisjoint(t *testing.T) {
	for _, initializer := range []string{`map[int]any{}`, `make(map[int]any)`} {
		t.Run(initializer, func(t *testing.T) {
			program := callerSoundnessProgram(t, `type Carrier struct{Value any};var m=`+initializer+`;func build(){m[0]=source.Value()}`, `anchor:=&Box{};candidate:=Carrier{};_=anchor;_=candidate;build()`, `&Handler{}`)
			var marks [2][4]uint64
			for mode := range 2 {
				g, query, wanted, allocation, write := callerMapHandleFixture(t, program)
				g.ctx = context.Background()
				if mode == 0 {
					g.resetCallerObjectExecutions()
				}
				owners, unknown := g.callerObjects(write.owner, map[callerObjectSourceID]bool{})
				if !unknown || owners[allocation] {
					t.Fatal("фикстура потеряла UNKNOWN payload в происхождении владельца")
				}
				before := maps.Clone(owners)
				probe := callerLifetimeProbe{g: g, want: wanted, seen: map[callerResolveKey]bool{}, objects: map[callerObjectKey]bool{}}
				if !probe.separateClosedMapHandle(write, allocation) || probe.contains(query) {
					t.Fatal("payload чужой карты загрязнил конкретный literal")
				}
				marks[mode] = callerReuseMarks(g)
				if !maps.Equal(owners, before) {
					t.Fatal("source proof изменил borrowed owner provenance")
				}
				if mode == 0 {
					if g.objectExecutions == nil || g.objectExecutions.graph != g || g.work.ObjectExecutionQueries+g.work.ObjectExecutionFallbacks == 0 {
						t.Fatal("не выполнен реальный execution dispatch")
					}
				} else if g.work.ObjectExecutionQueries != 0 || g.work.ObjectExecutionFallbacks != 0 || g.work.ObjectRawEvaluations == 0 {
					t.Fatal("raw контроль не остался исходным resolver")
				}
				variable := callerVariable(write.owner.pkg, write.owner.expr)
				own := g.closedMapHandles[variable]
				if own.expr == nil || probe.separateClosedMapHandle(write, own) || !probe.objectWrites(own) {
					t.Fatal("положительная запись в саму карту исчезла")
				}
				g.closedMapHandles[variable] = callerObjectKey{}
				control := callerLifetimeProbe{g: g, want: wanted, seen: map[callerResolveKey]bool{}, objects: map[callerObjectKey]bool{}}
				if !control.contains(query) {
					t.Fatal("без леммы не воспроизвёлся прежний false alias")
				}
				g.closedMapHandles[variable] = own
				payloadRetained := false
				for _, ref := range g.sources(variable) {
					payloadRetained = payloadRetained || ref.elem
				}
				if !payloadRetained {
					t.Fatal("элемент удалён из общего source inventory")
				}
				g.semanticOverflow = true
				if probe.separateClosedMapHandle(write, allocation) {
					t.Fatal("overflow стал отдельностью")
				}
				g.semanticOverflow = false
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				g.ctx = ctx
				if probe.separateClosedMapHandle(write, allocation) {
					t.Fatal("cancel стал отдельностью")
				}
				g.ctx = &callerExecutionResetContext{Context: context.Background(), checkpoint: func() {}}
				if probe.separateClosedMapHandle(write, allocation) {
					t.Fatal("непрозрачный context получил source certificate")
				}
				g.ctx = context.Background()
				probe.steps = callerLifetimeStepLimit + 1
				if probe.separateClosedMapHandle(write, allocation) {
					t.Fatal("лимит стал отдельностью")
				}
				probe.steps = 0
				g.addCallerLive(variable, query)
				if probe.separateClosedMapHandle(write, allocation) {
					t.Fatal("неучтённый live handle получил source certificate")
				}
				matched := callerLifetimeProbe{g: g, want: wanted, seen: map[callerResolveKey]bool{}, objects: map[callerObjectKey]bool{}}
				if !matched.objectWrites(allocation) {
					t.Fatal("положительное пересечение owners подавлено")
				}
			}
			if marks[0] != marks[1] {
				t.Fatal("raw/execution изменили semantic marks")
			}
		})
	}
}

func TestCallerIdentityClosedMapHandleBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, setup string
		want        bool
	}{
		{"package_literal", `var m=map[int]any{};func build(){m[0]=source.Value()}`, true},
		{"local_literal", `func build(){m:=map[int]any{};m[0]=source.Value()}`, true},
		{"local_var_make", `func build(){var m=make(map[int]any);m[0]=source.Value()}`, true},
		{"read_index", `var m=map[int]any{};func build(){m[0]=source.Value();_,_=m[0]}`, true},
		{"closure_index", `var m=map[int]any{};func build(){m[0]=source.Value();_=func(){_=m[0]}}`, true},
		{"rebind", `var m=map[int]any{};func build(){m=source.Value().(map[int]any);m[0]=source.Value()}`, false},
		{"alias", `var m=map[int]any{};func build(){m[0]=source.Value();alias:=m;_=alias}`, false},
		{"return_handle", `var m=map[int]any{};func build()map[int]any{m[0]=source.Value();return m}`, false},
		{"opaque_escape", `var m=map[int]any{};func build(){m[0]=source.Value();source.Mutate(m)}`, false},
		{"address_escape", `var m=map[int]any{};func build(){m[0]=source.Value();source.Mutate(&m)}`, false},
		{"capture_handle", `var m=map[int]any{};func build(){m[0]=source.Value();_=func(){source.Mutate(m)}}`, false},
		{"method", `type table map[int]any;func(*table)Touch(){};var m=table{};func build(){m[0]=source.Value();m.Touch()}`, false},
		{"exported", `var M=map[int]any{};func build(){M[0]=source.Value()}`, false},
		{"parameter", `func build(m map[int]any){m[0]=source.Value()}`, false},
		{"late_initializer", `var m map[int]any;func build(){m=map[int]any{};m[0]=source.Value()}`, false},
		{"shadowed_make", `func make()map[int]any{return nil};var m=make();func build(){m[0]=source.Value()}`, false},
		{"range_handle", `var m=map[int]any{};func build(){m[0]=source.Value();for range m{}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program := callerSoundnessProgram(t, tc.setup, `anchor:=&Box{};candidate:=[]any{};_=anchor;_=candidate`, `&Handler{}`)
			g, _, wanted, allocation, write := callerMapHandleFixture(t, program)
			probe := callerLifetimeProbe{g: g, want: wanted}
			if got := probe.separateClosedMapHandle(write, allocation); got != tc.want {
				t.Fatalf("map handle proof=%t want=%t", got, tc.want)
			}
			write.whole = true
			if probe.separateClosedMapHandle(write, allocation) {
				t.Fatal("whole write принята за запись элемента карты")
			}
		})
	}
}

func TestCallerIdentityClosedMapPayloadRemainsVisible(t *testing.T) {
	for _, tc := range []struct{ name, store, read string }{
		{"direct", `m[0]=anchor`, `m[0]`},
		{"map_value", `m[0]=anchor`, `m`},
		{"callback", `m[0]=func(){_=anchor}`, `m[0]`},
		{"shared_backing", `shared:=[]*Box{anchor};m[0]=shared`, `m[0]`},
		{"copied_alias", `alias:=m;alias[0]=anchor`, `m[0]`},
		{"opaque", `m[0]=source.Value()`, `m[0]`},
		{"unsafe_integer", `m[0]=source.Value().(uintptr)`, `m[0]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program := callerSoundnessProgram(t, `var m=map[int]any{}`, `anchor:=&Box{};`+tc.store+`;candidate:=`+tc.read+`;_=anchor;_=candidate`, `&Handler{}`)
			g, query, wanted, _, _ := callerMapHandleFixture(t, program)
			probe := callerLifetimeProbe{g: g, want: wanted, seen: map[callerResolveKey]bool{}, objects: map[callerObjectKey]bool{}}
			if !probe.contains(query) {
				t.Fatal("payload или UNKNOWN исчез из общего contains")
			}
		})
	}
}

func callerMapHandleFixture(t *testing.T, program *surfaceProgram) (*callerGraph, valueSrc, callerObjectKey, callerObjectKey, callerLifetimeWrite) {
	t.Helper()
	g := newCallerGraph(program)
	g.safeExternal = map[string]bool{"fixture/source": true}
	g.lifetimeScanning = true
	var query valueSrc
	var wanted, allocation callerObjectKey
	for node, body := range g.bodies {
		if body.sp != program.root || node.fn == nil || node.fn.Name() != "RPC" && node.fn.Name() != "build" && node.fn.Name() != "init" {
			continue
		}
		g.markCallerCalled(node)
		ast.Inspect(body.node, func(n ast.Node) bool {
			assignment, ok := n.(*ast.AssignStmt)
			if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
				return true
			}
			id, ok := assignment.Lhs[0].(*ast.Ident)
			if !ok {
				return true
			}
			if id.Name == "anchor" {
				address, ok := assignment.Rhs[0].(*ast.UnaryExpr)
				if !ok {
					t.Fatal("нет адреса anchor")
				}
				wanted = callerObjectKey{pkg: body.sp, expr: address.X}
			}
			if id.Name == "candidate" {
				query = valueSrc{pkg: body.sp, fk: callerKey(node), expr: assignment.Rhs[0], tuple: -1}
				allocation = callerObjectKey{pkg: body.sp, expr: assignment.Rhs[0]}
			}
			return true
		})
	}
	for _, write := range g.lifetimeWrites {
		if write.owner.pkg != program.root || write.owner.expr == nil || !g.callerLifetimeEffectPossible(write.owner) {
			continue
		}
		if _, isMap := write.owner.pkg.info.TypeOf(write.owner.expr).Underlying().(*types.Map); isMap {
			if query.expr == nil || wanted.expr == nil {
				t.Fatal("неполная fixture")
			}
			return g, query, wanted, allocation, write
		}
	}
	t.Fatal("нет активной записи в карту")
	return nil, valueSrc{}, callerObjectKey{}, callerObjectKey{}, callerLifetimeWrite{}
}
