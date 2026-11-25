// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/types"
	"slices"
	"testing"
)

// Статическое ребро указывает на адрес назначения и на ту позицию range,
// которая присваивает значение. Наличие цикла не означает его достижимости.
func TestCallerIdentityRangeWholeStoreInventory(t *testing.T) {
	const setup = `
type out[T comparable] struct{ dst *T }
func ranges(a,b *out[int], values map[out[int]]out[int], ch chan out[int], yield func(func(out[int]) bool)) {
	for *a,*b = range values {}
	for *a = range ch {}
	for *b = range yield {}
	for v := range ch { _ = v }
	for range ch {}
}
`
	p := callerSoundnessProgram(t, setup, "", "&Handler{}")
	g := newCallerGraph(p)
	type edge struct {
		owner, rhs string
		key        bool
	}
	var got []edge
	for _, w := range g.lifetimeWrites {
		if w.owner.fk.fn == nil || w.owner.fk.fn.Name() != "ranges" {
			continue
		}
		oid, oidOK := w.owner.expr.(*ast.Ident)
		rid, ridOK := w.value.expr.(*ast.Ident)
		if !oidOK || !ridOK || !w.whole || w.owner.fk != w.value.fk || w.owner.pkg != p.root || w.value.pkg != p.root ||
			w.value.tuple != -1 || w.value.rangeKey == w.value.rangeVal {
			t.Fatalf("неверный источник полной записи range: %+v", w)
		}
		got = append(got, edge{oid.Name, rid.Name, w.value.rangeKey})
	}
	want := []edge{{"a", "values", true}, {"b", "values", false}, {"a", "ch", true}, {"b", "yield", true}}
	if !slices.Equal(got, want) {
		t.Fatalf("перепись полных записей range: получено %v, ожидалось %v", got, want)
	}

	// Проверяем эффект именно совпавшей ячейки. Если принять сам идентификатор
	// функции yield за присвоенное значение, внешнее значение может потеряться.
	for _, w := range g.lifetimeWrites {
		id, ok := w.value.expr.(*ast.Ident)
		if !ok || id.Name != "yield" || !w.value.rangeKey {
			continue
		}
		v := callerVariable(w.owner.pkg, w.owner.expr)
		if v == nil {
			t.Fatal("не найден владелец ячейки итератора")
		}
		g.called = map[callerNode]bool{{fn: w.owner.fk.fn}: true}
		g.lifetimeWrites = []callerLifetimeWrite{w}
		g.lifetimeWriteIndex = nil
		probe := callerLifetimeProbe{g: g, seen: map[callerResolveKey]bool{}, objects: map[callerObjectKey]bool{}}
		if !probe.objectWrites(callerObjectKey{pkg: p.root, zero: v.Origin()}) {
			t.Fatal("значение, переданное через yield, принято за доказанно отдельное")
		}
		return
	}
	t.Fatal("нет записи через итератор")
}

func TestCallerIdentityRangeWholeStoreAtRead(t *testing.T) {
	const rpc = "fixture/service/FixtureService/RPC"
	for _, tc := range []struct {
		name, extra, write string
		unknown            bool
	}{
		{"generic_carrier_value", "", `var local Reader; o:=makeOutput(&local); alias:=o; for _,*alias = range []output[Reader]{{dst:&tracked.reader}} {}; o.Store()`, true},
		{"concrete_owner_key", "", `alias:=tracked; for *alias = range map[Handler]bool{{reader:Concrete{}}:true} {}`, true},
		{"unreachable", `func dormant(){alias:=tracked; for *alias = range map[Handler]bool{{reader:Concrete{}}:true} {}}`, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := callerSoundnessProgram(t, `type output[T any] struct{dst *T}; func makeOutput[T any](v *T)*output[T]{return &output[T]{dst:v}}; func(o *output[T])Store(){*o.dst=source.Value().(T)}; var tracked=&Handler{reader:Benign{}}`+"\n"+tc.extra, `h.reader.read()`, `tracked`, tc.write)
			for sel, s := range p.root.info.Selections {
				if s.Kind() == types.MethodVal && sel.Sel.Name == "read" {
					site := p.fset.PositionFor(sel.Pos(), false).String()
					scope := callerRegisteredWalk{rpc: rpc}
					report := scope.collect(t.Context(), p, map[string]bool{"fixture/source": true}, nil)
					if report.Invalid != "" || slices.Contains(report.Findings, rpc+": неразрешённый вызов "+site) != tc.unknown || !tc.unknown && len(report.Findings) != 0 {
						t.Fatalf("неверный результат в точке %s: %s %v", site, report.Invalid, report.Findings)
					}
					return
				}
			}
			t.Fatal("нет контрольного чтения")
		})
	}
}
