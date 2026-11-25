// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"testing"
)

func TestCallerIdentityUnpublishedMapWriteBeforeOwner(t *testing.T) {
	setup := `func build(s string){m:=map[string]string{};if s!=""{m["s"]=s};if s==""{m["t"]=s};source.Mutate(m)}`
	program := callerSoundnessProgram(t, setup, `anchor:=&Box{};candidate:=[]any{};_=anchor;_=candidate;build("arg")`, `&Handler{}`)
	g, query, want, allocation, write := callerMapHandleFixture(t, program)
	p := callerLifetimeProbe{g: g, want: want, seen: map[callerResolveKey]bool{}, objects: map[callerObjectKey]bool{}}
	variable := g.unpublishedMapWrites[write]
	if variable == nil || len(g.unpublishedMapWrites) != 2 {
		t.Fatal("префикс двух записей до публикации не найден")
	}
	g.lifetimeWrites = []callerLifetimeWrite{write}
	queries := g.work.ObjectQueries
	if p.objectWrites(allocation) || g.work.ObjectQueries != queries || g.work.UnpublishedMapWriteSkips != 1 {
		t.Fatal("отдельный срез потребовал поиска владельца карты")
	}
	var own callerObjectKey
	for _, ref := range g.index.varWrites[variable] {
		if !ref.elem {
			own = callerObjectKey{pkg: ref.pkg, expr: ref.expr}
		}
	}
	p.objectWrites(own)
	if own.expr == nil || g.work.ObjectQueries <= queries || g.work.UnpublishedMapWriteSkips != 1 {
		t.Fatal("запись в своё выделение не прошла обычный поиск")
	}
	delete(g.unpublishedMapWrites, write)
	queries = g.work.ObjectQueries
	p.objectWrites(allocation)
	if g.work.ObjectQueries <= queries {
		t.Fatal("контроль не вызвал поиск владельца")
	}
	g.unpublishedMapWrites[write] = variable
	synthetic := write
	synthetic.whole = true
	if p.separateUnpublishedMapWrite(synthetic) {
		t.Fatal("принята whole запись")
	}
	g.ctx = &callerTraceOpaqueContext{Context: context.Background()}
	if p.separateUnpublishedMapWrite(write) {
		t.Fatal("принят непрозрачный контекст")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	g.ctx = ctx
	if p.separateUnpublishedMapWrite(write) {
		t.Fatal("принята отмена")
	}
	g.ctx = context.Background()
	g.semanticOverflow = true
	if p.separateUnpublishedMapWrite(write) {
		t.Fatal("принят переполненный граф")
	}
	g.semanticOverflow = false
	p.steps = callerLifetimeStepLimit + 1
	if p.separateUnpublishedMapWrite(write) {
		t.Fatal("превышен бюджет шага")
	}
	p.steps = 0
	g.addCallerLive(variable, query)
	if p.separateUnpublishedMapWrite(write) {
		t.Fatal("принято изменение live handle")
	}
}

func TestCallerIdentityUnpublishedMapWriteBoundaries(t *testing.T) {
	for _, tc := range []struct{ name, prefix, store, tail string }{
		{"early_alias", `alias:=m;_=alias;`, `m["k"]=s`, ""},
		{"early_address", `source.Mutate(&m);`, `m["k"]=s`, ""},
		{"early_rebind", `m=map[string]string{};`, `m["k"]=s`, ""},
		{"earlier_call", `source.Mutate(m);`, `m["k"]=s`, ""},
		{"closure", `f:=func(){_=m};_=f;`, `m["k"]=s`, ""},
		{"call_in_guard", "", `if source.Value()!=nil {m["k"]=s}`, ""},
		{"call_in_value", "", `m["k"]=source.Value().(string)`, ""},
		{"nonconstant_key", "", `m[s]=s`, ""},
		{"loop", "", `for s!=""{m["k"]=s;break}`, ""},
		{"label", `if s==""{goto store};`, `store:m["k"]=s`, ""},
		{"later_rebind", "", `m["k"]=s`, `;m=map[string]string{};_=m`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setup := `func build(s string){m:=map[string]string{};` + tc.prefix + tc.store + tc.tail + `}`
			program := callerSoundnessProgram(t, setup, `anchor:=&Box{};candidate:=[]any{};_=anchor;_=candidate;build("arg")`, `&Handler{}`)
			g, _, _, _, write := callerMapHandleFixture(t, program)
			if g.unpublishedMapWrites[write] != nil {
				t.Fatal("запись вне доказанного префикса")
			}
		})
	}
}
