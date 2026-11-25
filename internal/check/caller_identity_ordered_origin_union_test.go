// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"slices"
	"testing"
)

func TestCallerIdentityShortOriginUnionAllocations(t *testing.T) {
	items := make([]callerOrigin, callerOriginLinearLimit+1)
	expr := ast.NewIdent("same")
	for i := range items {
		items[i].source = valueSrc{expr: expr, tuple: i}
	}
	var got []callerOrigin
	for n := 0; n <= callerOriginLinearLimit; n++ {
		allocs := testing.AllocsPerRun(20, func() {
			var union callerOriginUnion
			union.addAll(items[:n])
			union.addAll(items[:n])
			got = union.values
		})
		want := 1.0 // Только собственный срез результата.
		if n == 0 {
			want = 0
		}
		if allocs > want || !slices.Equal(got, items[:n]) || n == 0 && got != nil {
			t.Fatalf("короткое объединение %d: выделений %v, значений %v", n, allocs, got)
		}
	}
	// У первого заимствованного ответа есть свободная ёмкость. Следующее
	// значение и запись в выходной срез должны сохранить весь исходный массив.
	before := slices.Clone(items)
	var borrowed callerOriginUnion
	borrowed.addAll(items[:2])
	borrowed.add(items[len(items)-1])
	borrowed.values[0] = callerOrigin{}
	if !slices.Equal(items, before) {
		t.Fatal("объединение изменило подложку заимствованного среза")
	}

	var union callerOriginUnion
	union.addAll(items[:callerOriginLinearLimit])
	union.addAll(items[:callerOriginLinearLimit])
	if union.seen != nil {
		t.Fatal("повтор на границе короткого списка создал карту")
	}
	union.addAll(items)
	union.addAll(items)
	if len(union.seen) != len(items) || !slices.Equal(union.values, items) {
		t.Fatal("переход к карте потерял точное происхождение или порядок")
	}
}

func TestCallerIdentityCallReturnOrderedOriginUnion(t *testing.T) {
	p := callerSoundnessProgram(t, `func unionResult() func() {
		if true { return func(){} }; return func(){}
	}`, `_ = unionResult()`, "&Handler{}")
	t.Cleanup(func() { callerGraphs.Delete(p) })
	g := callerGraphFor(p, nil)
	var call, callee valueSrc
	for node, body := range g.bodies {
		if node.fn == nil || node.fn.Name() != "RPC" || body.sp != p.root {
			continue
		}
		ast.Inspect(body.node, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "unionResult" {
					call = valueSrc{pkg: body.sp, fk: callerKey(node), expr: c, tuple: -1}
					callee = call
					callee.expr = id
				}
			}
			return true
		})
	}
	if call.expr == nil {
		t.Fatal("вызов unionResult отсутствует")
	}
	fn := callerFunction(callee.pkg, callee.expr).Origin()
	target := callerOrigin{node: callerNode{fn: fn}}
	g.markCallerCalled(target.node)
	g.resolve(callee, false, map[callerResolveKey]bool{})
	refs := g.index.returns[callerKey(target.node)][0]
	if len(refs) != 2 {
		t.Fatalf("ожидались два независимых источника возврата, получено %d", len(refs))
	}

	// У целей и возвратов общий foreign. Вторая ветвь с UNKNOWN повторяет
	// значения первой и добавляет новое, в том числе после перехода к карте.
	foreign, nilOrigin := callerOrigin{foreign: true}, callerOrigin{nilValue: true}
	a := callerOrigin{source: refs[0]}
	b, c, d := a, a, a
	b.source.tuple, c.source.elem, d.source.rangeVal = 0, true, true
	first := []callerOrigin{a, b, c, d}
	second := []callerOrigin{b, nilOrigin, a, foreign}
	g.resolveMemo[callerResolveKeyFor(callee, false)] = callerResolveAnswer{values: []callerOrigin{foreign, nilOrigin, target}}
	g.resolveMemo[callerResolveKeyFor(refs[0], false)] = callerResolveAnswer{values: first}
	g.resolveMemo[callerResolveKeyFor(refs[1], false)] = callerResolveAnswer{values: second, unknown: true}
	raw, unknown := g.resolveRaw(call, false, map[callerResolveKey]bool{})
	wantRaw := []callerOrigin{foreign, a, b, c, d, b, nilOrigin, a, foreign}
	if !unknown || !slices.Equal(raw, wantRaw) {
		t.Fatalf("прямой raw потерял повторы или UNKNOWN: %+v %t", raw, unknown)
	}

	// Отмена после первого дочернего возврата отбрасывает накопленные значения.
	hits := g.work.ResolveHits
	g.ctx = &callerTraceDelayedContext{Context: context.Background(), step: func() error {
		if g.work.ResolveHits == hits+2 {
			return context.Canceled
		}
		return nil
	}}
	seen := map[callerResolveKey]bool{}
	stopped, unknown := g.resolve(call, false, seen)
	if !unknown || stopped != nil || len(seen) != 0 || g.work.ResolveHits != hits+2 {
		t.Fatal("прерванный вызов вернул частичные значения или продолжил обход")
	}
	g.ctx = nil

	before := g.work
	got, unknown := g.resolve(call, false, seen)
	want := []callerOrigin{foreign, a, b, c, d, nilOrigin}
	if !unknown || !slices.Equal(got, want) || g.work.ResolveRawValues-before.ResolveRawValues != len(raw) ||
		g.work.ResolveDistinctValues-before.ResolveDistinctValues != len(want) || g.work.ResolveHits-before.ResolveHits != 3 {
		t.Fatalf("исказились порядок, число вхождений, обход источников или UNKNOWN: %+v %t", got, unknown)
	}
	got[1] = nilOrigin
	if !slices.Equal(first, []callerOrigin{a, b, c, d}) || !slices.Equal(second, []callerOrigin{b, nilOrigin, a, foreign}) {
		t.Fatal("выходная последовательность изменила заимствованные ответы")
	}
}
