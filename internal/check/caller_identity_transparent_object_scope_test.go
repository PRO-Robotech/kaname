// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"maps"
	"testing"
	"unsafe"
)

type callerTransparentFixture struct {
	g                            *callerGraph
	target, child, anchor, other valueSrc
	alternate                    []valueSrc
}

// Один typed self-append имеет конкретное основание. В отрицательном twin
// основание читается через настоящий active field checkpoint того же Holder.
func callerTransparentPair(t *testing.T, selector bool) (callerTransparentFixture, callerTransparentFixture) {
	t.Helper()
	initial := "found:=[]Box{};"
	if selector {
		initial = "found:=holder.items;"
	}
	return callerTransparentPairWithInitial(t, initial, 2)
}

// Три self-append повторяют форму retention, не добавляя большой production graph.
// Общий call в отрицательном twin обязан закрыть trace даже с тем же результатом.
func callerTransparentPairWithInitial(t *testing.T, initial string, appendCount int) (callerTransparentFixture, callerTransparentFixture) {
	t.Helper()
	body := "holder:=&Holder{items:[]Box{}};other:=&Holder{items:[]Box{{}}};_=other;_=holder.items;" + initial
	for range appendCount {
		body += "found=append(found,Box{});"
	}
	p := callerTraceTypedProgram(t, body+"child:=found;parent:=child;top:=parent;_=top;")
	makeGraph := func() callerTransparentFixture {
		g, _, refs := callerTraceTypedGraph(t, p, "top")
		g.ctx = context.Background()
		target := g.sources(callerVariable(refs["top"].pkg, refs["top"].expr))
		child := g.sources(callerVariable(refs["parent"].pkg, refs["parent"].expr))
		if len(target) != 1 || len(child) != 1 || target[0].expr == nil || child[0].expr == nil || len(g.fieldQueries) != 1 {
			t.Fatal("typed RHS uses or real field frame missing")
		}
		g.callerObjects(refs["other"], map[callerObjectSourceID]bool{})
		alternate, u := g.embeddedCallerSourcesRaw(refs["other"], g.fieldQueries[0].fields, map[callerFieldKey]bool{})
		if u || len(alternate) != 1 || alternate[0] == g.fieldQueries[0].refs[0] {
			t.Fatal("alternate field provenance is not a distinct concrete typed slice")
		}
		for _, src := range alternate {
			g.callerObjects(src, map[callerObjectSourceID]bool{})
		}
		g.callerObjectsOwned(refs["top"], map[callerObjectSourceID]bool{})
		g.resetCallerObjectExecutions()
		return callerTransparentFixture{g, target[0], child[0], refs["top"], refs["other"], alternate}
	}
	return makeGraph(), makeGraph()
}

type callerTransparentResult struct {
	objects   map[callerObjectKey]bool
	unknown   bool
	marks     [4]uint64
	raw, hits int
}

// Это тот же owned push/pop, который исполняет raw-родитель top перед своим
// RHS. Источник родителя настоящий и прогрет; answers/seen/counters не сеются.
// Reference выключает namespace только на время тела после реального push:
// nested queries идут через неизменённый original fallback.
func callerTransparentRun(t *testing.T, f callerTransparentFixture, target valueSrc, reference bool) callerTransparentResult {
	t.Helper()
	return callerTransparentRunUnder(t, f, target, f.anchor, reference)
}

func callerTransparentRunUnder(t *testing.T, f callerTransparentFixture, target, ancestor valueSrc, reference bool) callerTransparentResult {
	t.Helper()
	g := f.g
	c := g.objectExecutions
	seen := map[callerObjectSourceID]bool{}
	chain := g.beginCallerTrace(seen)
	if chain == nil {
		t.Fatal("real owned chain refused")
	}
	defer g.endCallerTrace(chain)
	key := g.objectSourceIDs[callerResolveKeyFor(ancestor, true)]
	if key == 0 {
		t.Fatal("real parent source was not traversed during warmup")
	}
	frame := g.callerTracePush(chain, key)
	if frame == nil {
		t.Fatal("real parent push refused")
	}
	seen[key] = true
	defer func() { delete(seen, key); g.callerTracePop(chain, frame) }()
	if !g.callerTraceValid(chain) {
		t.Fatal("owned parent protocol invalid")
	}
	if reference {
		g.objectExecutions = nil
		defer func() { g.objectExecutions = c }()
	}
	marks, raw, hits := callerReuseMarks(g), g.work.ObjectRawEvaluations, g.work.ObjectTraceHits
	objects, unknown, _ := g.callerObjectsTracked(target, seen, chain)
	return callerTransparentResult{objects, unknown, callerReuseDelta(g, marks), g.work.ObjectRawEvaluations - raw, g.work.ObjectTraceHits - hits}
}

func callerTransparentEqual(t *testing.T, a, b callerTransparentResult) {
	t.Helper()
	if a.unknown != b.unknown || !maps.Equal(a.objects, b.objects) || a.marks != b.marks {
		t.Fatalf("objects/UNKNOWN/four marks differ: fast=%+v original=%+v", a, b)
	}
}

func callerTransparentRecords(t *testing.T, f callerTransparentFixture, target valueSrc, proof bool) []*callerTraceRecord {
	t.Helper()
	source := f.g.objectSourceIDs[callerResolveKeyFor(target, true)]
	if source == 0 {
		t.Fatal("target RHS never traversed")
	}
	var out []*callerTraceRecord
	for r := f.g.objectExecutions.traceRecords; r != nil; r = r.next {
		if r.phase == callerTraceRetained && r.source == source && r.scopeIndependent == proof {
			out = append(out, r)
		}
	}
	return out
}

func callerTransparentPrime(t *testing.T, a, b callerTransparentFixture, target valueSrc) {
	t.Helper()
	for range 2 {
		callerTransparentEqual(t, callerTransparentRun(t, a, target, false), callerTransparentRun(t, b, target, true))
	}
	callerAssertExecutionRetention(t, a.g.objectExecutions, nil)
	callerAssertExecutionRetention(t, b.g.objectExecutions, nil)
}

func TestCallerIdentityTransparentObjectScopeTransfer(t *testing.T) {
	for _, name := range []string{"refs", "unknown", "container_false_extra", "mutation_false_extra"} {
		t.Run(name, func(t *testing.T) {
			a, b := callerTransparentPair(t, false)
			callerTransparentPrime(t, a, b, a.target)
			records := callerTransparentRecords(t, a, a.target, true)
			if len(records) == 0 {
				t.Fatal("actual self-append did not publish proven target")
			}
			escaped := records[0].objects
			saved := maps.Clone(escaped)
			oldScope := records[0].scope
			state := a.g.callerObjectExecutionState()
			for _, f := range []callerTransparentFixture{a, b} {
				switch name {
				case "refs":
					f.g.fieldQueries[0].refs = f.alternate
				case "unknown":
					f.g.fieldQueries[0].unknown = true
				case "container_false_extra":
					f.g.containerScanning = map[callerResolveKey]bool{callerResolveKeyFor(f.other, true): false}
				case "mutation_false_extra":
					f.g.mutationScanning = map[callerFieldKey]bool{{callerResolveKeyFor(f.other, true), f.g.fieldQueries[0].fields[0]}: false}
				}
			}
			if a.g.callerObjectExecutionState() != state || oldScope.snapshot.matches(a.g) || !a.g.callerExecutionScopeTracked() || len(oldScope.snapshot.queries) != len(a.g.fieldQueries) {
				t.Fatal("distinct same-depth scopes/state precondition is vacuous")
			}
			got, want := callerTransparentRun(t, a, a.target, false), callerTransparentRun(t, b, b.target, true)
			callerTransparentEqual(t, got, want)
			if got.raw != 0 || got.hits != 1 || want.raw <= 0 || len(got.objects) == 0 || got.unknown || got.marks[0] == 0 || got.marks[2] != 0 || got.marks[3] == 0 {
				t.Fatal("cross-scope hit has no exact raw-work/cycle witness")
			}
			if !maps.Equal(escaped, saved) {
				t.Fatal("escaped readonly result mutated")
			}
			callerAssertExecutionRetention(t, a.g.objectExecutions, nil)
		})
	}
}

func TestCallerIdentityTransparentObjectScopeSelectorBoundary(t *testing.T) {
	for _, name := range []string{"refs", "unknown"} {
		t.Run(name, func(t *testing.T) {
			a, b := callerTransparentPair(t, true)
			callerTransparentPrime(t, a, b, a.target)
			old := callerTransparentRecords(t, a, a.target, false)
			if len(old) == 0 || len(callerTransparentRecords(t, a, a.target, true)) != 0 {
				t.Fatal("selector failed to remove proof from every live ancestor")
			}
			baseline := callerTransparentRun(t, b, b.target, true)
			for _, f := range []callerTransparentFixture{a, b} {
				if name == "refs" {
					f.g.fieldQueries[0].refs = f.alternate
				} else {
					f.g.fieldQueries[0].unknown = true
				}
			}
			got, want := callerTransparentRun(t, a, a.target, false), callerTransparentRun(t, b, b.target, true)
			callerTransparentEqual(t, got, want)
			if got.raw <= 0 || want.raw <= 0 || maps.Equal(want.objects, baseline.objects) && want.unknown == baseline.unknown {
				t.Fatal("negative selector twin did not change answer/UNKNOWN or force original body")
			}
			if len(callerTransparentRecords(t, a, a.target, true)) != 0 {
				t.Fatal("field-dependent target gained scope-free certificate")
			}
			for _, r := range old {
				if r.phase == callerTraceRetained && r.scopeIndependent {
					t.Fatal("old unproven record was upgraded")
				}
			}
			callerAssertExecutionRetention(t, a.g.objectExecutions, nil)
		})
	}
}

func TestCallerIdentityTransparentObjectScopeChildComposition(t *testing.T) {
	for _, name := range []string{"proven", "unproven"} {
		t.Run(name, func(t *testing.T) {
			proven := name == "proven"
			a, b := callerTransparentPair(t, !proven)
			callerTransparentPrime(t, a, b, a.child)
			child := callerTransparentRecords(t, a, a.child, proven)
			if len(child) == 0 {
				t.Fatal("real child certificate missing")
			}
			// Родитель ещё не был запросом после reset; warmup был до reset.
			if len(callerTransparentRecords(t, a, a.target, true))+len(callerTransparentRecords(t, a, a.target, false)) != 0 {
				t.Fatal("parent cache makes composition witness vacuous")
			}
			hits := a.g.work.ObjectTraceHits
			got, want := callerTransparentRun(t, a, a.target, false), callerTransparentRun(t, b, b.target, true)
			callerTransparentEqual(t, got, want)
			if a.g.work.ObjectTraceHits <= hits || got.raw <= 0 || got.raw >= want.raw {
				t.Fatal("parent did not execute a real cached-child path")
			}
			parent := callerTransparentRecords(t, a, a.target, proven)
			if len(parent) == 0 || len(callerTransparentRecords(t, a, a.target, !proven)) != 0 {
				t.Fatal("actual child hit proof did not compose conservatively")
			}
			for _, r := range child {
				if r.phase == callerTraceRetained && r.scopeIndependent != proven {
					t.Fatal("duplicate/replay changed old child proof")
				}
			}
			for _, f := range []callerTransparentFixture{a, b} {
				f.g.fieldQueries[0].unknown = true
			}
			got, want = callerTransparentRun(t, a, a.target, false), callerTransparentRun(t, b, b.target, true)
			callerTransparentEqual(t, got, want)
			if proven && (got.raw != 0 || got.hits != 1 || want.raw <= 0) {
				t.Fatal("proven child did not permit parent transfer")
			}
			if !proven && got.raw == 0 {
				t.Fatal("unproven exact child certified parent across scopes")
			}
			callerAssertExecutionRetention(t, a.g.objectExecutions, nil)
		})
	}
}

func TestCallerIdentityTransparentObjectScopeDepthAndRestore(t *testing.T) {
	for _, mode := range []string{"pure", "selector", "general_call"} {
		t.Run(mode, func(t *testing.T) {
			initial := "found:=[]Box{};"
			if mode == "selector" {
				initial = "found:=holder.items;"
			}
			if mode == "general_call" {
				initial = "found:=[]Box{};found=func()[]Box{return found}();"
			}
			a, b := callerTransparentPairWithInitial(t, initial, 3)
			callerTransparentPrime(t, a, b, a.target)
			proven := mode == "pure"
			old := callerTransparentRecords(t, a, a.target, proven)
			if mode != "general_call" && len(old) == 0 {
				t.Fatal("нет настоящего исходного certificate")
			}
			if !proven && len(callerTransparentRecords(t, a, a.target, true)) != 0 {
				t.Fatal("непрозрачный twin получил доказательство независимости")
			}
			state := a.g.callerObjectExecutionState()
			ai, ae := a.g.enterCallerFieldQuery(a.other, a.g.fieldQueries[0].fields)
			bi, be := b.g.enterCallerFieldQuery(b.other, b.g.fieldQueries[0].fields)
			if !ae || !be {
				t.Fatal("не создан настоящий дополнительный field frame")
			}
			defer func() {
				if ae {
					a.g.leaveCallerFieldQuery(ai)
				}
				if be {
					b.g.leaveCallerFieldQuery(bi)
				}
			}()
			if a.g.callerObjectExecutionState() != state || !a.g.callerExecutionScopeTracked() || len(a.g.fieldQueries) != 2 {
				t.Fatal("не получены равный state и допустимый scope другой глубины")
			}
			if len(old) > 0 && (len(old[0].scope.snapshot.queries) != 1 || old[0].scope.snapshot.matches(a.g)) {
				t.Fatal("старый scope не отличается от нового")
			}
			stores := a.g.work.ObjectTraceStores
			got, want := callerTransparentRun(t, a, a.target, false), callerTransparentRun(t, b, b.target, true)
			callerTransparentEqual(t, got, want)
			if want.raw <= 0 {
				t.Fatal("fallback не исполнил исходное тело")
			}
			if proven {
				if got.raw != 0 || got.hits != 1 || a.g.work.ObjectTraceStores != stores || old[0].phase != callerTraceRetained || len(old[0].scope.snapshot.queries) != 1 {
					t.Fatal("старый прозрачный certificate не переиспользован через другой depth")
				}
			} else if got.raw <= 0 || len(callerTransparentRecords(t, a, a.target, true)) != 0 {
				t.Fatal("selector/general call получил небезопасный перенос")
			}
			a.g.leaveCallerFieldQuery(ai)
			ae = false
			b.g.leaveCallerFieldQuery(bi)
			be = false
			got, want = callerTransparentRun(t, a, a.target, false), callerTransparentRun(t, b, b.target, true)
			callerTransparentEqual(t, got, want)
			if mode != "general_call" && (got.raw != 0 || got.hits != 1 || want.raw <= 0) {
				t.Fatal("pop не восстановил исходный exact certificate")
			}
			if mode == "general_call" && (got.raw <= 0 || len(callerTransparentRecords(t, a, a.target, true)) != 0) {
				t.Fatal("pop сделал общий call прозрачным")
			}
			callerAssertExecutionRetention(t, a.g.objectExecutions, nil)
		})
	}
}

// Другой depth не отменяет dependency/state/current-scope границы. Для refs и
// UNKNOWN проверяется зависимый selector twin: чистый путь законно их не читает.
func TestCallerIdentityTransparentObjectScopeDepthGuards(t *testing.T) {
	for _, mode := range []string{"binding", "seen", "head", "refs", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			selector := mode == "refs" || mode == "unknown"
			initial := "found:=[]Box{};"
			if selector {
				initial = "found:=holder.items;"
			}
			a, b := callerTransparentPairWithInitial(t, initial, 3)
			callerTransparentPrime(t, a, b, a.target)
			if len(callerTransparentRecords(t, a, a.target, !selector)) == 0 {
				t.Fatal("негативный контроль не имеет исходного certificate")
			}
			baseline := callerTransparentRun(t, b, b.target, true)
			state := a.g.callerObjectExecutionState()
			for _, f := range []callerTransparentFixture{a, b} {
				index, entered := f.g.enterCallerFieldQuery(f.other, f.g.fieldQueries[0].fields)
				if !entered {
					t.Fatal("нет дополнительного настоящего field frame")
				}
				t.Cleanup(func() { f.g.leaveCallerFieldQuery(index) })
				switch mode {
				case "binding":
					f.g.addCallerLive(callerVariable(f.child.pkg, f.child.expr), f.alternate[0])
				case "refs":
					f.g.fieldQueries[0].refs = f.alternate
				case "unknown":
					f.g.fieldQueries[0].unknown = true
				case "head":
					key := f.g.fieldQueries[index].source
					old := f.g.fieldQueryHeads[key]
					f.g.fieldQueryHeads[key] = 0
					t.Cleanup(func() { f.g.fieldQueryHeads[key] = old })
				}
			}
			if mode == "binding" && a.g.callerObjectExecutionState() == state {
				t.Fatal("новый binding не изменил state")
			}
			if mode == "head" && a.g.callerExecutionScopeTracked() {
				t.Fatal("повреждённый CURRENT scope остался допустимым")
			}
			var got, want callerTransparentResult
			if mode == "seen" {
				got = callerTransparentRunUnder(t, a, a.target, a.target, false)
				want = callerTransparentRunUnder(t, b, b.target, b.target, true)
				if got.marks[0] != 1 || got.marks[3] != 1 || len(got.objects) != 0 {
					t.Fatal("другой seen потерял терминальный цикл")
				}
			} else {
				got, want = callerTransparentRun(t, a, a.target, false), callerTransparentRun(t, b, b.target, true)
			}
			callerTransparentEqual(t, got, want)
			if got.raw <= 0 || want.raw <= 0 {
				t.Fatal("изменённая обязательная зависимость скрыта старым certificate")
			}
			if selector && (len(callerTransparentRecords(t, a, a.target, true)) != 0 || maps.Equal(want.objects, baseline.objects) && want.unknown == baseline.unknown) {
				t.Fatal("зависимый selector не изменил ответ либо стал прозрачным")
			}
			callerAssertExecutionRetention(t, a.g.objectExecutions, nil)
		})
	}
}

func TestCallerIdentityTransparentObjectScopeContextAndOverflow(t *testing.T) {
	for _, name := range []string{"opaque", "canceled", "overflow", "namespace"} {
		t.Run(name, func(t *testing.T) {
			a, b := callerTransparentPair(t, false)
			callerTransparentPrime(t, a, b, a.target)
			if len(callerTransparentRecords(t, a, a.target, true)) == 0 {
				t.Fatal("guard witness has no proven retained record")
			}
			// Контекст, namespace и overflow проверяются уже при другом depth.
			for _, f := range []callerTransparentFixture{a, b} {
				index, entered := f.g.enterCallerFieldQuery(f.other, f.g.fieldQueries[0].fields)
				if !entered {
					t.Fatal("нет дополнительного field frame перед guard")
				}
				t.Cleanup(func() { f.g.leaveCallerFieldQuery(index) })
			}
			a.g.fieldQueries[0].unknown = true
			b.g.fieldQueries[0].unknown = true
			hits := a.g.work.ObjectTraceHits
			switch name {
			case "overflow":
				warm := callerTransparentRun(t, b, b.target, true)
				if warm.marks[0] == 0 {
					t.Fatal("overflow witness has no actual cuts")
				}
				a.g.resolveCuts = ^uint64(0) - warm.marks[0] + 1
				b.g.resolveCuts = a.g.resolveCuts
				x, y := callerTransparentRun(t, a, a.target, false), callerTransparentRun(t, b, b.target, true)
				if !a.g.semanticOverflow || !b.g.semanticOverflow || !x.unknown || !y.unknown {
					t.Fatal("transfer/raw checked overflow did not fail closed")
				}
				a.g.resetCallerObjectExecutions()
				if !a.g.semanticOverflow {
					t.Fatal("reset erased whole-run overflow")
				}
			case "namespace":
				a.g.resetCallerObjectExecutions()
				b.g.resetCallerObjectExecutions()
				got, want := callerTransparentRun(t, a, a.target, false), callerTransparentRun(t, b, b.target, true)
				callerTransparentEqual(t, got, want)
				if got.raw <= 0 {
					t.Fatal("new namespace reused old proof")
				}
			default:
				if name == "opaque" {
					a.g.ctx = &callerOriginOpaqueContext{Context: context.Background(), at: 17}
					b.g.ctx = &callerOriginOpaqueContext{Context: context.Background(), at: 17}
				} else {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					a.g.ctx, b.g.ctx = ctx, ctx
				}
				b.g.objectExecutions = nil
				am, bm := callerReuseMarks(a.g), callerReuseMarks(b.g)
				ar, br := a.g.work.ObjectRawEvaluations, b.g.work.ObjectRawEvaluations
				ao, au, _ := a.g.callerObjectsOwned(a.target, map[callerObjectSourceID]bool{})
				bo, bu, _ := b.g.callerObjectsOwned(b.target, map[callerObjectSourceID]bool{})
				if au != bu || !maps.Equal(ao, bo) || callerReuseDelta(a.g, am) != callerReuseDelta(b.g, bm) || a.g.work.ObjectRawEvaluations-ar != b.g.work.ObjectRawEvaluations-br || a.g.work.ObjectTraceHits != hits {
					t.Fatal("opaque/canceled original execution diverged")
				}
				if name == "opaque" && a.g.ctx.(*callerOriginOpaqueContext).calls != b.g.ctx.(*callerOriginOpaqueContext).calls {
					t.Fatal("opaque Err trace changed")
				}
			}
			callerAssertExecutionRetention(t, a.g.objectExecutions, nil)
		})
	}
}

func TestCallerIdentityTransparentObjectScopeLiveResetAndLayout(t *testing.T) {
	a, b := callerTransparentPair(t, false)
	callerTransparentPrime(t, a, b, a.target)
	c := a.g.objectExecutions
	if unsafe.Sizeof(callerTraceRecord{}) > 146*8 || unsafe.Sizeof(callerTraceGuard{}) > 24*8 {
		t.Fatal("proof flag exceeds existing physical reservation")
	}
	seen := map[callerObjectSourceID]bool{}
	chain := a.g.beginCallerTrace(seen)
	if chain == nil {
		t.Fatal("real live owner missing")
	}
	defer func() {
		if chain.live {
			a.g.endCallerTrace(chain)
		}
	}()
	key := a.g.objectSourceIDs[callerResolveKeyFor(a.anchor, true)]
	frame := a.g.callerTracePush(chain, key)
	if frame == nil || key == 0 {
		t.Fatal("real live push missing")
	}
	seen[key] = true
	defer func() {
		if frame.live {
			delete(seen, key)
			a.g.callerTracePop(chain, frame)
		}
	}()
	callerAssertExecutionRetention(t, c, nil)
	entries, units, active := c.entries, c.weight, c.active
	a.g.resetCallerObjectExecutions()
	a.g.resetCallerObjectExecutions()
	if a.g.objectExecutions != c || c.graph != nil || c.entries != entries || c.weight != units || c.active != active {
		t.Fatal("B1 created second store or uncharged live/pinned payload")
	}
	marks, raw, hits := callerReuseMarks(a.g), a.g.work.ObjectRawEvaluations, a.g.work.ObjectTraceHits
	got, u, _ := a.g.callerObjectsTracked(a.target, seen, chain)
	want := callerTransparentRun(t, b, b.target, true)
	if !maps.Equal(got, want.objects) || u != want.unknown || callerReuseDelta(a.g, marks) != want.marks || a.g.work.ObjectRawEvaluations <= raw || a.g.work.ObjectTraceHits != hits {
		t.Fatal("disabled live owner changed original body/marks")
	}
	delete(seen, key)
	a.g.callerTracePop(chain, frame)
	a.g.endCallerTrace(chain)
	if c.active != 0 || c.entries != entries || c.weight != units {
		t.Fatal("disabled B1 account failed to drain without early uncharge")
	}
	callerAssertExecutionRetention(t, c, nil)
	a.g.resetCallerObjectExecutions()
	if a.g.objectExecutions == c || a.g.objectExecutions.entries != 0 || a.g.objectExecutions.weight != 0 {
		t.Fatal("idle reset failed")
	}
	// Повторный внешний вход выполняет существующий taint, не выдавая proof.
	seen = map[callerObjectSourceID]bool{}
	chain = a.g.beginCallerTrace(seen)
	if chain == nil {
		t.Fatal("fresh live owner missing")
	}
	a.g.callerObjectsOwned(a.target, map[callerObjectSourceID]bool{})
	if !chain.bad {
		t.Fatal("fresh reentry concealed existing taint")
	}
	a.g.endCallerTrace(chain)
	callerAssertExecutionRetention(t, a.g.objectExecutions, nil)
}

// Полный hostile-head contract проверяется и новой entry-веткой: никакой
// scope-free certificate не делает malformed текущий scope допустимым.
func TestCallerIdentityTransparentObjectScopeHostileEntry(t *testing.T) {
	a, _ := callerTransparentPair(t, false)
	key := a.g.fieldQueries[0].source
	old := a.g.fieldQueryHeads[key]
	a.g.fieldQueryHeads[key] = 0
	defer func() { a.g.fieldQueryHeads[key] = old }()
	if a.g.callerExecutionScopeTracked() {
		t.Fatal("malformed head unexpectedly tracked")
	}
	c := a.g.objectExecutions
	entries, units := c.entries, c.weight
	if scope := c.scope(a.g); scope != nil {
		c.releaseTicket(a.g, scope)
		t.Fatal("new path acquired malformed current scope")
	}
	if c.entries != entries || c.weight != units {
		t.Fatal("hostile rejection changed ownership")
	}
	// Остальные latest/previous/extra/depth и content/pop пары — неизменённые
	// старые canonical tests; этот тест не заменяет и не ослабляет их.
}

// Один реальный source получает две разные seen-зависимости. Новая запись
// с доказательством не меняет старую непокрытую запись и её readonly ответ.
func TestCallerIdentityTransparentObjectScopeNoProofUpgrade(t *testing.T) {
	a, b := callerTransparentPair(t, true)
	callerTransparentPrime(t, a, b, a.target)
	old := callerTransparentRecords(t, a, a.target, false)
	if len(old) == 0 {
		t.Fatal("no actual unproven selector record")
	}
	saved := maps.Clone(old[0].objects)
	scope, state := old[0].scope, old[0].guard.state
	// Настоящий push того же typed source представляет замыкающий цикл.
	// Это unit owned-протокола; он не выдаётся за полный RPC traversal.
	got := callerTransparentRunUnder(t, a, a.target, a.target, false)
	want := callerTransparentRunUnder(t, b, b.target, b.target, true)
	callerTransparentEqual(t, got, want)
	proven := callerTransparentRecords(t, a, a.target, true)
	if got.raw <= 0 || got.marks[0] != 1 || got.marks[3] != 1 || len(proven) == 0 {
		t.Fatal("actual positive-ancestor cut did not produce a separate proven record")
	}
	if old[0].phase != callerTraceRetained || old[0].scopeIndependent || !maps.Equal(old[0].objects, saved) || proven[0] == old[0] || proven[0].scope != scope || proven[0].guard.state != state {
		t.Fatal("new proof upgraded/overwrote old record or changed exact context")
	}
	source := a.g.objectSourceIDs[callerResolveKeyFor(a.target, true)]
	oldFalse, newTrue := false, false
	for i := 0; i < int(old[0].count); i++ {
		d := old[0].dependencies[i]
		oldFalse = oldFalse || d.source == source && d.want == 0
	}
	for i := 0; i < int(proven[0].count); i++ {
		d := proven[0].dependencies[i]
		newTrue = newTrue || d.source == source && d.want == 1
	}
	if !oldFalse || !newTrue {
		t.Fatal("records did not preserve their distinct entry predicates")
	}
	again := callerTransparentRunUnder(t, a, a.target, a.target, false)
	callerTransparentEqual(t, again, callerTransparentRunUnder(t, b, b.target, b.target, true))
	if again.raw != 0 || again.hits != 1 {
		t.Fatal("proven positive-ancestor record was not actually replayed")
	}
	got, want = callerTransparentRun(t, a, a.target, false), callerTransparentRun(t, b, b.target, true)
	callerTransparentEqual(t, got, want)
	if got.raw != 0 || got.hits != 1 || old[0].scopeIndependent {
		t.Fatal("negative-ancestor entry lost its original exact record/proof")
	}
	callerAssertExecutionRetention(t, a.g.objectExecutions, nil)
}
