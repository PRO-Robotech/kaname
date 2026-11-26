// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"strings"
	"testing"
)

// Вызов из замыкания получает адрес внешней локальной ячейки, как у записи
// диагностического поля из RPC. Отдельная запись в карту нужна общему fixture.
func TestCallerIdentityScalarSliceStoreBeforeOwner(t *testing.T) {
	const setup = "type Name string;type Row struct{name Name};type Recorder struct{};func(Recorder)save(out *Name){*out=source.Value().(*Row).name}"
	const prefix = "anchor:=&Box{};candidate:=[]any{};_=anchor;_=candidate;tab:=map[string]string{};tab[\"k\"]=\"v\";var result Name;_=string(result);"
	for _, tc := range []struct {
		name, body string
		closed     bool
	}{
		{"sole_address", "func(){Recorder{}.save(&result)}();_=string(result)", true},
		{"second_call", "Recorder{}.save(&result);Recorder{}.save(source.Value().(*Name))", false},
		{"method_value", "Recorder{}.save(&result);f:=Recorder{}.save;f(&result)", false},
		{"address_escapes", "Recorder{}.save(&result);source.Mutate(&result)", false},
		{"actual_slice_element", "Recorder{}.save(&candidate[0])", false},
		{"nonlocal_destination", "Recorder{}.save(source.Value().(*Name))", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := prefix + tc.body
			if tc.name == "actual_slice_element" {
				body = strings.Replace(body, "candidate:=[]any{}", "candidate:=[]Name{\"item\"}", 1)
			}
			pg := callerSoundnessProgram(t, setup, body, "&Handler{}")
			g, query, want, allocation, _ := callerMapHandleFixture(t, pg)
			g.ctx = context.Background()
			var write callerLifetimeWrite
			for _, w := range g.lifetimeWrites {
				if w.whole && w.owner.pkg == pg.root && w.owner.fk.fn != nil && w.owner.fk.fn.Name() == "save" {
					write = w
					break
				}
			}
			if write.owner.expr == nil {
				t.Fatal("нет записи через параметр")
			}
			fn := write.owner.fk.fn
			for _, site := range g.index.calls[fn] {
				g.bindCaller(site.pkg, callerNode{fn: site.fk.fn, lit: site.fk.lit}, site.call, callerNode{fn: fn})
			}
			probe := callerLifetimeProbe{g: g, want: want, seen: map[callerResolveKey]bool{}, objects: map[callerObjectKey]bool{}}
			if got := probe.separateClosedScalarSliceStore(write); got != tc.closed {
				t.Fatalf("сертификат отдельной ячейки = %v", got)
			}
			if tc.name == "actual_slice_element" {
				objs, _ := g.callerObjects(write.owner, map[callerObjectSourceID]bool{})
				if !objs[allocation] {
					t.Fatal("потерян адрес элемента проверяемого среза")
				}
			}
			if !tc.closed {
				return
			}
			g.lifetimeWrites = []callerLifetimeWrite{write}
			queries := g.work.ObjectQueries
			if probe.objectWrites(allocation) || g.work.ObjectQueries != queries {
				t.Fatal("доказанная отдельная ячейка дошла до поиска владельца")
			}
			v := callerVariable(pg.root, write.owner.expr)
			cell := g.scalarSliceStores[v].cell
			for _, change := range []struct {
				name string
				set  func() func()
			}{
				{"range", func() func() { write.value.rangeVal = true; return func() { write.value.rangeVal = false } }},
				{"element", func() func() { write.whole = false; return func() { write.whole = true } }},
				{"native", func() func() { g.scalarStoreNative = true; return func() { g.scalarStoreNative = false } }},
				{"overflow", func() func() { g.semanticOverflow = true; return func() { g.semanticOverflow = false } }},
				{"budget", func() func() { probe.steps = callerLifetimeStepLimit + 1; return func() { probe.steps = 0 } }},
				{"opaque", func() func() {
					g.ctx = &callerTraceOpaqueContext{Context: context.Background()}
					return func() { g.ctx = context.Background() }
				}},
				{"cancelled", func() func() {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					g.ctx = ctx
					return func() { g.ctx = context.Background() }
				}},
				{"changed_local", func() func() { g.addCallerLive(cell, query); return func() { delete(g.live, cell) } }},
			} {
				undo := change.set()
				if probe.separateClosedScalarSliceStore(write) {
					t.Fatalf("принято изменение %s", change.name)
				}
				undo()
			}
			g.addCallerLive(v, query)
			if probe.separateClosedScalarSliceStore(write) {
				t.Fatal("добавленная привязка скрыта")
			}
			probe.objectWrites(allocation)
			if g.work.ObjectQueries <= queries {
				t.Fatal("запасной путь не вычислил владельца")
			}
		})
	}
}
