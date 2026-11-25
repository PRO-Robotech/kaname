// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"fmt"
	"go/ast"
	"go/types"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// Новый constructor возвращает concrete pointer; метод возвращает интерфейсное
// поле. Поэтому путь не сводится к чистому alias diamond: он проходит через
// embedded fresh resolver, собственный query/remember/pop и call-return cycle.
func callerOriginTransferProgram(t *testing.T, depth int) (*surfaceProgram, valueSrc, valueSrc, valueSrc) {
	t.Helper()
	setup := `type TransferHolder struct{ value Reader }
 func transferNew(value Reader)*TransferHolder{return &TransferHolder{value:value}}
 func(h *TransferHolder) choose()Reader{return h.value}
 func transferCycle(value Reader)Reader{return value}
 type TransferBuilder func(Reader)*TransferHolder
 func transferFactory(value TransferBuilder)TransferBuilder{return value}`
	body := "var loop Reader;loop=transferCycle(loop);loop=Concrete{};loop=Benign{};var makeHolder TransferBuilder;makeHolder=transferFactory(makeHolder);makeHolder=transferNew;holder:=makeHolder(loop);x0:=holder.choose();"
	for i := 1; i <= depth; i++ {
		body += fmt.Sprintf("var x%d Reader;x%d=x%d;x%d=x%d;", i, i, i-1, i, i-1)
	}
	body += fmt.Sprintf("x%d.read()", depth)
	p := callerSoundnessProgram(t, setup, body, "&Handler{}")
	t.Cleanup(func() { callerGraphs.Delete(p) })
	g := callerGraphFor(p, nil)
	var root, cycle, field valueSrc
	for node, body := range g.bodies {
		if body.sp != p.root {
			continue
		}
		ast.Inspect(body.node, func(n ast.Node) bool {
			src := valueSrc{pkg: body.sp, fk: callerKey(node), tuple: -1}
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "read" {
					src.expr = sel
					root = src
				}
				if sel.Sel.Name == "value" {
					src.expr = sel
					field = src
				}
			}
			if call, ok := n.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "transferCycle" {
					src.expr = call
					cycle = src
				}
			}
			return true
		})
	}
	if root.expr == nil || cycle.expr == nil || field.expr == nil {
		t.Fatal("typed constructor/field/call-return boundary missing")
	}
	return p, root, cycle, field
}

func callerOriginTransferPair(t *testing.T, p *surfaceProgram, root valueSrc) (*callerGraph, *callerGraph) {
	t.Helper()
	fast, original := callerGraphFor(p, nil), callerGraphFor(p, nil)
	for _, g := range []*callerGraph{fast, original} {
		g.lifetimeScanning = true
		// Прогрев обычных bindings/memo выполняет настоящий исходный resolver.
		g.objectExecutions = nil
		for range 4 {
			g.resolve(root, false, map[callerResolveKey]bool{})
		}
	}
	fast.resetCallerObjectExecutions()
	original.resetCallerObjectExecutions()
	original.objectExecutions = nil
	return fast, original
}

type callerOriginObservation struct {
	values  []callerOrigin
	unknown bool
	marks   [4]uint64
	raw     int
}

func callerOriginObserve(g *callerGraph, src valueSrc, seen map[callerResolveKey]bool) callerOriginObservation {
	marks, raw := callerReuseMarks(g), g.work.ResolveEvaluations
	values, u := g.resolve(src, false, seen)
	return callerOriginObservation{slices.Clone(values), u, callerReuseDelta(g, marks), g.work.ResolveEvaluations - raw}
}
func callerOriginSame(t *testing.T, a, b callerOriginObservation) {
	t.Helper()
	if !slices.Equal(a.values, b.values) || a.unknown != b.unknown || a.marks != b.marks {
		t.Fatalf("origin/order/UNKNOWN/four marks differ: %+v / %+v", a, b)
	}
}

func TestCallerIdentityOriginTransferVariableUnionKeepsRawAndOrder(t *testing.T) {
	p := callerSoundnessProgram(t, "func unionFirst() {}\nfunc unionSecond() {}",
		"var callback func(); callback = unionFirst; callback = unionSecond; callback = unionFirst; callback()", "&Handler{}")
	t.Cleanup(func() { callerGraphs.Delete(p) })
	var variable valueSrc
	for node, body := range callerGraphFor(p, nil).bodies {
		ast.Inspect(body.node, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "callback" {
					variable = valueSrc{pkg: body.sp, fk: callerKey(node), expr: id, tuple: -1}
				}
			}
			return true
		})
	}
	if variable.expr == nil {
		t.Fatal("вызов переменной из фикстуры не найден")
	}
	for _, tc := range []struct {
		name       string
		middleCold bool
	}{{"warm", false}, {"middle-cold", true}} {
		t.Run(tc.name, func(t *testing.T) {
			run := func(rawCount *int) (callerOriginObservation, [4]int) {
				g := callerGraphFor(p, nil)
				g.lifetimeScanning = true
				refs := g.sources(callerVariable(variable.pkg, variable.expr))
				if len(refs) != 3 {
					t.Fatalf("источники callback: получили %d, ожидали 3", len(refs))
				}
				for i, ref := range refs {
					if i != 1 || !tc.middleCold {
						g.resolve(ref, false, map[callerResolveKey]bool{})
					}
				}
				for i, ref := range refs {
					_, warm := g.initialResolveMemo[callerResolveKeyFor(ref, false)]
					if warm != (i != 1 || !tc.middleCold) {
						t.Fatalf("источник %d: initial memo hit=%t перед обходом", i, warm)
					}
				}

				// Живой frame допускается обычным путём. push и выбор prefix
				// выполняет сам resolveRawOwned при обходе sources(v).
				guard := callerResolveKeyFor(refs[0], true)
				seen := map[callerResolveKey]bool{guard: true}
				owner := g.beginCallerOrigin(seen)
				if owner == nil {
					t.Fatal("владелец обхода не допущен")
				}
				defer g.endCallerOrigin(owner)
				key := callerResolveKeyFor(variable, false)
				frame := g.beginCallerOriginFrame(owner, key)
				if frame == nil {
					t.Fatal("кадр объявления не допущен")
				}

				before, marks := g.work, callerReuseMarks(g)
				values, unknown := g.resolveRawOwned(variable, false, seen, owner, frame, false, rawCount)
				defer g.endCallerOriginFrame(owner, frame, values, unknown)
				if !maps.Equal(seen, map[callerResolveKey]bool{guard: true}) {
					t.Fatalf("обход изменил seen: %v", seen)
				}
				dep := frame.dependencies
				for i := len(refs) - 1; i >= 0; i-- {
					if dep == nil || dep.key != callerResolveKeyFor(refs[i], false) || dep.want || !dep.propagated {
						t.Fatalf("источник %d: не передано точное отрицательное чтение", i)
					}
					dep = dep.next
				}
				if frame.bad || dep != &frame.seed || dep.key != key || dep.want || !dep.propagated || dep.next != nil {
					t.Fatal("кадр потерял исходное чтение переменной")
				}
				w := g.work
				return callerOriginObservation{values, unknown, callerReuseDelta(g, marks), w.ResolveEvaluations - before.ResolveEvaluations},
					[4]int{w.ResolveQueries - before.ResolveQueries, w.ResolveInitialHits - before.ResolveInitialHits,
						w.ResolveCycleCuts - before.ResolveCycleCuts, w.OriginTransferReads - before.OriginTransferReads}
			}

			rawCount := -1
			fast, fastWork := run(&rawCount)
			// Без счётчика объединения тот же raw-обход сохраняет повторы
			// и проверяет полный список зависимостей каждого источника.
			ordinary, ordinaryWork := run(nil)
			expected := callerDistinctOrigins(ordinary.values)
			if rawCount != 3 || rawCount != len(ordinary.values) || len(expected) != 2 || ordinary.unknown {
				t.Fatalf("объединение: raw=%d, обычный raw=%d, distinct=%d, unknown=%t", rawCount, len(ordinary.values), len(expected), ordinary.unknown)
			}
			ordinary.values = expected
			callerOriginSame(t, fast, ordinary)
			runs := 0
			if tc.middleCold {
				runs = 1
			}
			wantWork := [4]int{3, 3 - runs, 0, 4 + runs}
			if fast.raw != runs || ordinary.raw != runs || fastWork != wantWork || ordinaryWork != wantWork {
				t.Fatalf("работа обхода: raw=%d/%d, [запросы, initial hits, cycle cuts, чтения]=%v/%v, ожидали %d и %v",
					fast.raw, ordinary.raw, fastWork, ordinaryWork, runs, wantWork)
			}
		})
	}
}

// Пересчёт не использует units/count записи как ожидаемые величины. Общий
// бюджет включает старые owners и новый физический header/deps/result capacity.
func callerOriginAccount(t *testing.T, c *callerObjectExecutions) {
	t.Helper()
	entries, units, refs := callerTraceAccount(t, c)
	active := 0
	for chain := c.traceChains; chain != nil; chain = chain.next {
		if chain.live {
			active++
		}
	}
	for record := c.traceRecords; record != nil; record = record.next {
		if record.ticket {
			active++
		}
	}
	for key, answer := range c.answers {
		entries++
		units += 1 + len(answer.answer.objects)
		refs[key.scope]++
	}
	indexed := map[*callerOriginRecord]bool{}
	if c.originAccount {
		if c.originIndex == nil {
			t.Fatal("paid origin index missing")
		}
		entries++
		units += 4 + int((unsafe.Sizeof(*c.originIndex)+7)/8)
		for bucket, head := range c.originIndex.buckets {
			for record := head; record != nil; record = record.bucketNext {
				if indexed[record] || !record.retained || int(record.bucket) != bucket {
					t.Fatal("origin index has duplicate/live/foreign bucket")
				}
				indexed[record] = true
			}
		}
	} else if c.originIndex != nil {
		t.Fatal("unpaid origin index")
	}
	for owner := c.originOwners; owner != nil; owner = owner.next {
		entries++
		units += int((unsafe.Sizeof(*owner) + 7) / 8)
		if owner.live {
			active++
			if owner.scope != nil {
				refs[owner.scope]++
				active++
			}
		}
		if owner.cache != c {
			t.Fatal("foreign origin owner")
		}
		if owner.capacityBoundary != nil {
			found := false
			for frame := owner.top; frame != nil; frame = frame.parent {
				found = found || frame == owner.capacityBoundary
				if found && !frame.bad {
					t.Fatal("capacity boundary skipped a publishable ancestor")
				}
			}
			if !found {
				t.Fatal("capacity boundary retained an unwound frame")
			}
		}
	}
	// Каждая обратная ссылка должна вести к предыдущему узлу прямого обхода.
	var previous *callerOriginRecord
	for record := c.originRecords; record != nil; record = record.next {
		if record.previous != previous {
			t.Fatal("origin forward chain has a cycle or broken reverse link")
		}
		previous = record
		entries++
		own := int((unsafe.Sizeof(*record) + 7) / 8)
		count, seeds := 0, 0
		var dependencyMask uint
		if record.callerOriginProof != nil {
			own += int((unsafe.Sizeof(*record.callerOriginProof) + 7) / 8)
		} else if !record.bad || record.retained || record.dependencies != nil {
			t.Fatal("guard без proof сохранил сертификат или зависимости")
		}
		for dep := record.dependencies; dep != nil; dep = dep.next {
			slot := c.originDependencySlot(dep.key)
			if dep.slot != slot {
				t.Fatal("origin dependency fingerprint differs from its exact source")
			}
			dependencyMask |= slot.mask()
			entries++
			count++
			if record.callerOriginProof != nil && dep == &record.seed {
				seeds++ // Встроенный seed уже оплачен полным sizeof proof.
			} else {
				own += int((unsafe.Sizeof(*dep) + 7) / 8)
			}
		}
		if record.dependencyMask != dependencyMask {
			t.Fatal("origin dependency mask differs from its actual list")
		}
		if record.callerOriginProof != nil && seeds != 1 {
			t.Fatal("proof потерял единственную встроенную seed dependency")
		}
		own += cap(record.values) * int((unsafe.Sizeof(callerOrigin{})+7)/8)
		if count != record.count || own != record.units || cap(record.values) != len(record.values) || count > callerOriginDependencyLimit {
			t.Fatal("unpaid origin payload/capacity")
		}
		units += own
		if record.live {
			active++
			if record.owner == nil {
				t.Fatal("live record without owner")
			}
		}
		if record.holdsScope {
			refs[record.scope]++
		}
		if indexed[record] != record.retained {
			t.Fatal("retained origin record absent from exact index")
		}
		delete(indexed, record)
		if record.retained && (record.owner != nil || record.parent != nil || record.live || !record.holdsScope) {
			t.Fatal("retained record borrows live state")
		}
	}
	if c.originIndex != nil {
		if c.originIndex.oldest != previous {
			t.Fatal("origin tail differs from forward chain")
		}
	} else if previous != nil {
		t.Fatal("origin physical chain has no paid tail")
	}
	for _, head := range c.scopes {
		for scope := head; scope != nil; scope = scope.next {
			entries++
			s := scope.snapshot
			weight := 1 + len(s.queries) + len(s.containers) + len(s.mutations)
			for _, q := range s.queries {
				weight += len(q.fields) + len(q.refs)
			}
			units += weight
			if scope.references != refs[scope] || scope.weight != weight {
				t.Fatal("origin scope holds/account mismatch")
			}
			delete(refs, scope)
		}
	}
	if len(indexed) != 0 || len(refs) != 0 || entries != c.entries || units != c.weight || active != c.active || entries > 4096 || units > 16384 {
		t.Fatalf("shared account mismatch %d/%d %d/%d active %d/%d", entries, c.entries, units, c.weight, active, c.active)
	}
}

func TestCallerIdentityOriginTransferConstructorDiamond(t *testing.T) {
	previousFast, previousOriginal := 0, 0
	for _, depth := range []int{4, 6, 8} {
		t.Run(fmt.Sprintf("depth_%d", depth), func(t *testing.T) {
			p, root, _, field := callerOriginTransferProgram(t, depth)
			fast, original := callerOriginTransferPair(t, p, root)
			state, scope := fast.callerObjectExecutionState(), fast.captureCallerContainerObjectScope()
			a := callerOriginObserve(fast, root, map[callerResolveKey]bool{})
			b := callerOriginObserve(original, root, map[callerResolveKey]bool{})
			callerOriginSame(t, a, b)
			if a.unknown || len(a.values) != 2 || a.marks[0] <= a.marks[1] || a.marks[2] != 0 || a.marks[3] != 0 || a.raw <= 0 || a.raw >= b.raw || fast.work.OriginTransferOwners < 2 || fast.work.OriginTransferFieldRestores == 0 || fast.work.OriginTransferHits == 0 || fast.work.OriginTransferStores == 0 {
				t.Fatalf("real boundary transfer did not reduce original expansion: %+v/%+v", a, b)
			}
			if depth > 4 && (a.raw >= 3*previousFast || b.raw <= 3*previousOriginal) {
				t.Fatal("cold projected-state work still follows the original doubling paths")
			}
			if depth == 8 && a.raw*4 >= b.raw {
				t.Fatal("first traversal did not remove material repeated original work")
			}
			previousFast, previousOriginal = a.raw, b.raw
			if !strings.Contains(a.values[0].node.fn.FullName(), "Concrete") || !strings.Contains(a.values[1].node.fn.FullName(), "Benign") {
				t.Fatal("ordered concrete anchors lost")
			}
			if state != fast.callerObjectExecutionState() || !scope.matches(fast) {
				t.Fatal("stable entry had durable or escaped field writes")
			}
			if _, ok := fast.initialResolveMemo[callerResolveKeyFor(root, false)]; ok {
				t.Fatal("partial answer was published as complete")
			}
			// Сохранённый outer certificate должен реально включать field boundary.
			found := false
			for record := fast.objectExecutions.originRecords; record != nil; record = record.next {
				if record.retained && record.key == callerResolveKeyFor(root, false) {
					found = true
				}
			}
			if !found || field.pkg.info.Selections[field.expr.(*ast.SelectorExpr)] == nil {
				t.Fatal("outer constructor-field certificate not retained")
			}
			again := callerOriginObserve(fast, root, map[callerResolveKey]bool{})
			callerOriginSame(t, again, b)
			if again.raw != 0 || b.raw < 1<<depth {
				t.Fatal("retained replay or original repeated-work witness missing")
			}
			callerOriginAccount(t, fast.objectExecutions)
			if depth == 4 {
				callerOriginCrossLayer(t, fast, original, root)
			}
		})
	}
}

func TestCallerIdentityOriginTransferSeenAndField(t *testing.T) {
	for _, name := range []string{"positive_ancestor", "negative_cleanup", "active_field", "false_extra_guard"} {
		t.Run(name, func(t *testing.T) {
			p, root, cycle, field := callerOriginTransferProgram(t, 4)
			fast, original := callerOriginTransferPair(t, p, root)
			base := callerOriginObserve(fast, root, map[callerResolveKey]bool{})
			callerOriginSame(t, base, callerOriginObserve(original, root, map[callerResolveKey]bool{}))
			key := callerResolveKeyFor(cycle, true)
			seenFast, seenOriginal := map[callerResolveKey]bool{}, map[callerResolveKey]bool{}
			if name == "positive_ancestor" {
				seenFast[key] = true
				seenOriginal[key] = true
			}
			if name == "negative_cleanup" {
				seenFast[key] = false
				seenOriginal[key] = false
			}
			var leaves []func()
			defer func() {
				for _, leave := range leaves {
					leave()
				}
			}()
			for _, g := range []*callerGraph{fast, original} {
				if name == "active_field" {
					sel := field.expr.(*ast.SelectorExpr)
					src := field
					src.expr = sel.X
					index, entered := g.enterCallerFieldQuery(src, fieldPath(field.pkg.info.Selections[sel]))
					if !entered {
						t.Fatal("real field owner missing")
					}
					leaves = append(leaves, func() { g.leaveCallerFieldQuery(index) })
				}
				if name == "false_extra_guard" {
					g.containerScanning = map[callerResolveKey]bool{key: false}
				}
			}
			a, b := callerOriginObserve(fast, root, seenFast), callerOriginObserve(original, root, seenOriginal)
			callerOriginSame(t, a, b)
			if !maps.Equal(seenFast, seenOriginal) {
				t.Fatal("seen cleanup differs")
			}
			if name == "negative_cleanup" && len(seenFast) != 0 {
				t.Fatal("false external key was not deleted by original push/pop")
			}
			if (name == "positive_ancestor" || name == "active_field") && a.marks == base.marks {
				t.Fatal("changed entry obligations were vacuous")
			}
			callerOriginAccount(t, fast.objectExecutions)
		})
	}
}

// Эти contexts непрозрачны по настоящему типу; trace фиксирует реальные Err
// checkpoints исходного пути. Никаких вызовов Err ради имитации тела нет.
type callerOriginOpaqueContext struct {
	context.Context
	calls int
	at    int
}

func (c *callerOriginOpaqueContext) Err() error {
	c.calls++
	if c.calls >= c.at {
		return context.Canceled
	}
	return nil
}

// Сравниваем допуск реального чтения с полной проверкой прежнего пути,
// в том числе после подмены контекста живого owner и после его закрытия.
func TestCallerIdentityOriginOwnerAdmittedContext(t *testing.T) {
	p, root, _, _ := callerOriginTransferProgram(t, 2)
	g := callerGraphFor(p, nil)
	g.lifetimeScanning = true
	g.resetCallerObjectExecutions()
	key := callerResolveKeyFor(root, false)
	cancelContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	otherCancelContext, otherCancel := context.WithCancel(context.Background())
	defer otherCancel()
	timerContext, stop := context.WithTimeout(context.Background(), time.Hour)
	defer stop()
	admitted := []context.Context{nil, context.Background(), context.TODO(), cancelContext, otherCancelContext, timerContext}
	var typedNil *callerTraceOpaqueContext
	replacements := append(slices.Clone(admitted), typedNil, callerTraceNoncomparableContext{context.Background(), []int{1}})
	for _, entry := range admitted {
		g.ctx = entry
		owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
		if owner == nil {
			t.Fatalf("owner was not admitted for %T", entry)
		}
		for _, replacement := range replacements {
			g.ctx = replacement
			reads := g.work.OriginTransferReads
			want := callerFreshSameContext(entry, replacement)
			if got := g.callerOriginRead(owner, key, false); got != want {
				t.Fatalf("entry %T, current %T: read %t, want %t", entry, replacement, got, want)
			}
			if want {
				reads++
			}
			if g.work.OriginTransferReads != reads {
				t.Fatal("context mismatch changed logical read count")
			}
		}
		g.ctx = entry
		g.endCallerOrigin(owner)
		if g.callerOriginRead(owner, key, false) {
			t.Fatal("closed owner accepted a read")
		}
	}
}

func TestCallerIdentityOriginTransferContextAndOverflow(t *testing.T) {
	for _, name := range []string{"opaque", "canceled", "overflow", "namespace"} {
		t.Run(name, func(t *testing.T) {
			p, root, _, _ := callerOriginTransferProgram(t, 4)
			fast, original := callerOriginTransferPair(t, p, root)
			warm := callerOriginObserve(fast, root, map[callerResolveKey]bool{})
			callerOriginSame(t, warm, callerOriginObserve(original, root, map[callerResolveKey]bool{}))
			hits := fast.work.OriginTransferHits
			if name == "opaque" {
				fast.ctx = &callerOriginOpaqueContext{Context: context.Background(), at: 17}
				original.ctx = &callerOriginOpaqueContext{Context: context.Background(), at: 17}
			}
			if name == "canceled" {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				fast.ctx, original.ctx = ctx, ctx
			}
			if name == "overflow" {
				if warm.marks[0] == 0 {
					t.Fatal("no real cuts")
				}
				fast.resolveCuts = ^uint64(0) - warm.marks[0] + 1
				original.resolveCuts = fast.resolveCuts
			}
			if name == "namespace" {
				fast.resetCallerObjectExecutions()
				original.resetCallerObjectExecutions()
				original.objectExecutions = nil
			}
			a, b := callerOriginObserve(fast, root, map[callerResolveKey]bool{}), callerOriginObserve(original, root, map[callerResolveKey]bool{})
			if name != "overflow" {
				callerOriginSame(t, a, b)
			} else {
				if !fast.semanticOverflow || !original.semanticOverflow || !a.unknown || !b.unknown {
					t.Fatal("checked replay/raw overflow did not refuse")
				}
				fast.resetCallerObjectExecutions()
				if !fast.semanticOverflow {
					t.Fatal("reset erased sticky overflow")
				}
			}
			if name == "opaque" {
				if fast.ctx.(*callerOriginOpaqueContext).calls != original.ctx.(*callerOriginOpaqueContext).calls || a.raw != b.raw || fast.work.OriginTransferHits != hits {
					t.Fatal("opaque fallback changed real Err/raw trace")
				}
			}
			if name == "canceled" && (a.raw != 0 || fast.work.OriginTransferHits != hits) {
				t.Fatal("canceled replay passed entry gate")
			}
			callerOriginAccount(t, fast.objectExecutions)
		})
	}
}

func TestCallerIdentityOriginTransferFirstLive(t *testing.T) {
	p := callerSoundnessProgram(t, "func transferFirst(value Reader)Reader{_=transferFirst(value);return value}", "_=transferFirst(Concrete{});_=transferFirst(Benign{})", "&Handler{}")
	t.Cleanup(func() { callerGraphs.Delete(p) })
	fast, original := callerGraphFor(p, nil), callerGraphFor(p, nil)
	original.objectExecutions = nil
	var ref valueSrc
	var parameter *types.Var
	var call *ast.CallExpr
	var owner callerNode
	for node, body := range fast.bodies {
		if node.fn == nil || body.sp != p.root {
			continue
		}
		if node.fn.Name() == "transferFirst" {
			parameter = node.fn.Type().(*types.Signature).Params().At(0)
			ast.Inspect(body.node, func(n ast.Node) bool {
				if r, ok := n.(*ast.ReturnStmt); ok {
					ref = valueSrc{pkg: body.sp, fk: callerKey(node), expr: r.Results[0], tuple: -1}
				}
				return true
			})
		}
		if node.fn.Name() == "RPC" {
			owner = node
			ast.Inspect(body.node, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok {
					if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "transferFirst" && call == nil {
						call = c
					}
				}
				return true
			})
		}
	}
	if parameter == nil || call == nil || ref.expr == nil {
		t.Fatal("real first-live inputs missing")
	}
	var before, after [][]callerOrigin
	var beforeMarks, afterMarks [][4]uint64
	for _, g := range []*callerGraph{fast, original} {
		g.lifetimeScanning = true
		for range 3 {
			g.resolve(ref, true, map[callerResolveKey]bool{})
		}
		hits := g.work.OriginTransferHits
		marks := callerReuseMarks(g)
		values, u := g.resolve(ref, true, map[callerResolveKey]bool{})
		beforeMarks = append(beforeMarks, callerReuseDelta(g, marks))
		if u {
			t.Fatal("unbound union unresolved")
		}
		before = append(before, values)
		if g == fast && (g.work.OriginTransferStores == 0 || g.work.OriginTransferHits <= hits) {
			t.Fatal("first-live test did not hold and replay a partial transfer")
		}
		raw := g.work.ResolveEvaluations
		hits = g.work.OriginTransferHits
		epoch := g.bindingEpoch
		g.bindCaller(p.root, owner, call, callerNode{fn: ref.fk.fn})
		marks = callerReuseMarks(g)
		values, u = g.resolve(ref, true, map[callerResolveKey]bool{})
		afterMarks = append(afterMarks, callerReuseDelta(g, marks))
		if u || g.bindingEpoch <= epoch || len(g.sources(parameter)) != 1 {
			t.Fatal("first-live did not replace fallback")
		}
		after = append(after, values)
		if g.work.ResolveEvaluations <= raw || g.work.OriginTransferHits != hits {
			t.Fatal("first-live reused the old partial transfer")
		}
	}
	if len(before[0]) != 2 || len(after[0]) != 1 || !slices.Equal(before[0], before[1]) || !slices.Equal(after[0], after[1]) || beforeMarks[0] != beforeMarks[1] || afterMarks[0] != afterMarks[1] {
		t.Fatal("first-live origin shrink differs")
	}
	callerOriginAccount(t, fast.objectExecutions)
}

func TestCallerIdentityOriginTransferOwnedBudgetAndReset(t *testing.T) {
	p, root, _, _ := callerOriginTransferProgram(t, 4)
	g, original := callerOriginTransferPair(t, p, root)
	callerOriginSame(t, callerOriginObserve(g, root, map[callerResolveKey]bool{}), callerOriginObserve(original, root, map[callerResolveKey]bool{}))
	c := g.objectExecutions
	var owners []*callerOriginOwner
	// Настоящие owner/scope acquisitions до настоящего отказа общей ёмкости.
	defer func() {
		for i := len(owners) - 1; i >= 0; i-- {
			if owners[i].live {
				g.endCallerOrigin(owners[i])
			}
		}
	}()
	for {
		owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
		if owner == nil {
			break
		}
		owners = append(owners, owner)
	}
	if len(owners) == 0 || g.work.OriginTransferCapacityFallbacks == 0 {
		t.Fatal("live owner pressure missing")
	}
	callerOriginAccount(t, c)
	a, b := callerOriginObserve(g, root, map[callerResolveKey]bool{}), callerOriginObserve(original, root, map[callerResolveKey]bool{})
	callerOriginSame(t, a, b)
	entries, units := c.entries, c.weight
	g.resetCallerObjectExecutions()
	g.resetCallerObjectExecutions()
	if g.objectExecutions != c || c.graph != nil || c.entries != entries || c.weight != units {
		t.Fatal("B1 allocated a second origin pool")
	}
	for i := len(owners) - 1; i >= 0; i-- {
		g.endCallerOrigin(owners[i])
	}
	if c.active != 0 || c.entries != entries || c.weight != units {
		t.Fatal("disabled owner drain changed physical account")
	}
	callerOriginAccount(t, c)
	g.resetCallerObjectExecutions()
	if g.objectExecutions == c || g.objectExecutions.entries != 0 || g.objectExecutions.weight != 0 {
		t.Fatal("idle reset did not create an empty namespace")
	}
}

func TestCallerIdentityOriginTransferLiveFrameRefusal(t *testing.T) {
	p, root, _, _ := callerOriginTransferProgram(t, 4)
	g, original := callerOriginTransferPair(t, p, root)
	c := g.objectExecutions
	owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
	if owner == nil {
		t.Fatal("real owner admission failed")
	}
	frame := g.beginCallerOriginFrame(owner, callerResolveKeyFor(root, false))
	if frame == nil || frame.dependencies == nil {
		t.Fatal("live frame/dependency reservation missing")
	}
	var extra []*callerOriginOwner
	defer func() {
		for i := len(extra) - 1; i >= 0; i-- {
			if extra[i].live {
				g.endCallerOrigin(extra[i])
			}
		}
		if frame.live {
			frame.bad = true
			g.endCallerOriginFrame(owner, frame, nil, true)
		}
		if owner.live {
			g.endCallerOrigin(owner)
		}
	}()
	// Unit настоящего lifecycle: push в seen не подставляется. Родительский
	// ticket жив; дочерний resolve обязан получить отказ именно frame admission.
	for {
		next := g.beginCallerOrigin(map[callerResolveKey]bool{})
		if next == nil {
			break
		}
		extra = append(extra, next)
	}
	if c.traceRoom(1, callerOriginRecordUnits) {
		t.Fatal("real owner reservations left room for a frame")
	}
	before, raw := callerReuseMarks(g), g.work.ResolveEvaluations
	values, u := g.resolveOwned(root, false, owner.seen, owner)
	a := callerOriginObservation{slices.Clone(values), u, callerReuseDelta(g, before), g.work.ResolveEvaluations - raw}
	b := callerOriginObserve(original, root, map[callerResolveKey]bool{})
	callerOriginSame(t, a, b)
	if owner.bad || !frame.bad || frame.dependencies != nil || frame.count != 0 || frame.pushed || a.raw != b.raw || a.raw == 0 {
		t.Fatal("refused child attributed push to parent or skipped raw work")
	}
	callerOriginAccount(t, c)
	entries, units := c.entries, c.weight
	g.resetCallerObjectExecutions()
	g.resetCallerObjectExecutions()
	if g.objectExecutions != c || c.graph != nil || c.entries != entries || c.weight != units || !frame.live {
		t.Fatal("B1 lost live origin frame")
	}
	for i := len(extra) - 1; i >= 0; i-- {
		g.endCallerOrigin(extra[i])
	}
	g.endCallerOriginFrame(owner, frame, nil, true)
	g.endCallerOrigin(owner)
	if c.active != 0 || c.entries != entries || c.weight != units || frame.owner != nil || frame.parent != nil {
		t.Fatal("B1 frame/dependency drain changed retained physical account")
	}
	callerOriginAccount(t, c)
	g.resetCallerObjectExecutions()
	if g.objectExecutions == c || g.objectExecutions.entries != 0 {
		t.Fatal("idle frame namespace survived reset")
	}
}

func TestCallerIdentityOriginTransferIndexDecoys(t *testing.T) {
	for _, name := range []string{"source", "scope", "context"} {
		t.Run(name, func(t *testing.T) {
			p, root, _, field := callerOriginTransferProgram(t, 4)
			g, original := callerOriginTransferPair(t, p, root)
			// Все три контекста прогреваются исходным evaluator до retention, чтобы
			// коллизия проверяла ключ, а не попутную обычную memo publication.
			g.objectExecutions = nil
			for range 3 {
				g.resolve(root, false, map[callerResolveKey]bool{})
				sel := field.expr.(*ast.SelectorExpr)
				src := field
				src.expr = sel.X
				index, entered := g.enterCallerFieldQuery(src, fieldPath(field.pkg.info.Selections[sel]))
				if !entered {
					t.Fatal("warm field owner missing")
				}
				g.resolve(root, false, map[callerResolveKey]bool{})
				g.leaveCallerFieldQuery(index)
				g.ctx = context.Background()
				g.resolve(root, false, map[callerResolveKey]bool{})
				g.ctx = nil
			}
			g.resetCallerObjectExecutions()
			base := callerOriginObserve(g, root, map[callerResolveKey]bool{})
			callerOriginSame(t, base, callerOriginObserve(original, root, map[callerResolveKey]bool{}))
			if name == "scope" {
				sel := field.expr.(*ast.SelectorExpr)
				src := field
				src.expr = sel.X
				index, entered := g.enterCallerFieldQuery(src, fieldPath(field.pkg.info.Selections[sel]))
				if !entered {
					t.Fatal("decoy field owner missing")
				}
				g.resolve(root, false, map[callerResolveKey]bool{})
				g.leaveCallerFieldQuery(index)
			}
			if name == "context" {
				g.ctx = context.Background()
				g.resolve(root, false, map[callerResolveKey]bool{})
				g.ctx = nil
			}
			owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
			if owner == nil {
				t.Fatal("lookup owner missing")
			}
			defer g.endCallerOrigin(owner)
			c, key, state := g.objectExecutions, callerResolveKeyFor(root, false), g.callerObjectExecutionState()
			bucket := c.callerOriginBucket(key, owner.scope, state, g.ctx)
			var decoy *callerOriginRecord
			for record := c.originRecords; record != nil; record = record.next {
				if !record.retained {
					continue
				}
				if name == "source" && record.key != key {
					decoy = record
					break
				}
				if name == "scope" && record.key == key && record.scope != owner.scope {
					decoy = record
					break
				}
				if name == "context" && record.key == key && record.scope == owner.scope && record.ctx != nil {
					decoy = record
					break
				}
			}
			if decoy == nil {
				t.Fatal("actual retained decoy was not produced by typed traversal")
			}
			// Только детерминированная инъекция коллизии в тесте: перемещается настоящий
			// retained узел с настоящими answer/dependencies/pins. Хеш-коллизия не заявлена
			// естественной; account, seen и семантические ответы не подставляются.
			oldBucket := decoy.bucket
			link := &c.originIndex.buckets[oldBucket]
			for *link != decoy {
				link = &(*link).bucketNext
			}
			*link = decoy.bucketNext
			decoy.bucket = bucket
			decoy.bucketNext = c.originIndex.buckets[bucket]
			c.originIndex.buckets[bucket] = decoy
			restore := func() {
				slot := &c.originIndex.buckets[bucket]
				for *slot != decoy {
					slot = &(*slot).bucketNext
				}
				*slot = decoy.bucketNext
				decoy.bucket = oldBucket
				decoy.bucketNext = c.originIndex.buckets[oldBucket]
				c.originIndex.buckets[oldBucket] = decoy
			}
			restored := false
			defer func() {
				if !restored {
					restore()
				}
			}()
			marks, raw, candidates := callerReuseMarks(g), g.work.ResolveEvaluations, g.work.OriginTransferCandidates
			values, u := g.resolveOwned(root, false, owner.seen, owner)
			got := callerOriginObservation{slices.Clone(values), u, callerReuseDelta(g, marks), g.work.ResolveEvaluations - raw}
			restore()
			restored = true
			callerOriginSame(t, got, base)
			if got.raw != 0 || g.work.OriginTransferCandidates-candidates < 2 {
				t.Fatal("decoy bypassed exact comparison or real cached root disappeared")
			}
			callerOriginAccount(t, c)
		})
	}
}

// Проверка композиции использует настоящий протокол старого владельца:
// begin, Push, запись seen, delete, Pop, end. Готовые ответы и bad не задаются.
// Отдельный исходный general-call body показывает событие, которое нельзя
// считать закодированным четырьмя числовыми semantic marks.
func callerOriginCrossLayer(t *testing.T, fast, original *callerGraph, root valueSrc) {
	t.Helper()
	var call valueSrc
	for node, body := range fast.bodies {
		if body.sp == root.pkg {
			ast.Inspect(body.node, func(n ast.Node) bool {
				if x, ok := n.(*ast.CallExpr); ok {
					if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "makeHolder" {
						call = valueSrc{pkg: body.sp, fk: callerKey(node), expr: x, tuple: -1}
					}
				}
				return true
			})
		}
	}
	if call.expr == nil {
		t.Fatal("real constructor call missing")
	}
	fast.ctx, original.ctx = context.Background(), context.Background()
	ancestor := fast.internObjectSource(root)
	if ancestor == 0 {
		t.Fatal("real ancestor source missing")
	}
	// Все identity/warmup изменения предшествуют измеряемому живому frame.
	for range 3 {
		callerOriginSame(t, callerOriginObserve(fast, root, map[callerResolveKey]bool{}), callerOriginObserve(original, root, map[callerResolveKey]bool{}))
	}
	seen := map[callerObjectSourceID]bool{}
	chain := fast.beginCallerTrace(seen)
	if chain == nil {
		t.Fatal("clean old trace owner refused")
	}
	frame := fast.callerTracePush(chain, ancestor)
	if frame == nil {
		fast.endCallerTrace(chain)
		t.Fatal("clean old frame refused")
	}
	seen[ancestor] = true
	defer func() {
		delete(seen, ancestor)
		fast.callerTracePop(chain, frame)
		fast.endCallerTrace(chain)
		callerOriginAccount(t, fast.objectExecutions)
	}()
	if !fast.callerTraceValid(chain) {
		t.Fatal("old chain was not clean before origin hit")
	}
	hits := fast.work.OriginTransferHits
	a, b := callerOriginObserve(fast, root, map[callerResolveKey]bool{}), callerOriginObserve(original, root, map[callerResolveKey]bool{})
	callerOriginSame(t, a, b)
	if a.raw != 0 || fast.work.OriginTransferHits != hits+1 || !chain.bad || fast.callerTraceValid(chain) {
		t.Fatal("real origin hit hid old trace publication barrier")
	}
	callerOriginAccount(t, fast.objectExecutions)
	// Здесь включается только настоящий владелец старой цепочки. Исходный call
	// body вызывается напрямую, до него нет сохранённого origin-сертификата.
	original.resetCallerObjectExecutions()
	callKey := original.internObjectSource(call)
	baseSeen := map[callerObjectSourceID]bool{}
	baseChain := original.beginCallerTrace(baseSeen)
	if baseChain == nil || !original.callerTraceValid(baseChain) {
		t.Fatal("original call owner refused")
	}
	defer func() { original.endCallerTrace(baseChain); callerOriginAccount(t, original.objectExecutions) }()
	raw := original.work.ResolveEvaluations
	original.callerObjectsRaw(call, baseSeen, callKey, baseChain)
	if original.work.ResolveEvaluations <= raw || !baseChain.bad || original.callerTraceValid(baseChain) || len(baseSeen) != 0 {
		t.Fatal("original constructor body did not expose old trace barrier")
	}
}

// Настоящий constructor diamond создаёт записи с исходными dependencies и scope.
// Ожидаемая жертва выбирается прежним прямым обходом, независимо от нового tail.
func TestCallerIdentityOriginTransferEvictsOldestEligibleWithPinnedTail(t *testing.T) {
	p, root, _, _ := callerOriginTransferProgram(t, 4)
	g, original := callerOriginTransferPair(t, p, root)
	callerOriginSame(t, callerOriginObserve(g, root, map[callerResolveKey]bool{}),
		callerOriginObserve(original, root, map[callerResolveKey]bool{}))
	c := g.objectExecutions
	callerOriginAccount(t, c)
	eligible := func(record *callerOriginRecord) bool {
		return record.retained && !record.live && record.pins == 0 && record.owner == nil && record.parent == nil
	}
	before := map[*callerOriginRecord]bool{}
	var oldest *callerOriginRecord
	for record := c.originRecords; record != nil; record = record.next {
		before[record] = true
		oldest = record
	}
	if oldest == nil || !eligible(oldest) {
		t.Fatal("constructor diamond did not retain an eligible oldest record")
	}
	// Имитируется только удержание готового сертификата; ответ и account настоящие.
	oldest.pins++
	defer func() { oldest.pins-- }()
	var victim *callerOriginRecord
	for record := c.originRecords; record != nil; record = record.next {
		if eligible(record) {
			victim = record
		}
	}
	if victim == nil || victim == oldest {
		t.Fatal("constructor diamond did not retain another eviction candidate")
	}
	evictions := g.work.OriginTransferEvictions
	if !c.evictCallerOrigin(g) || g.work.OriginTransferEvictions != evictions+1 {
		t.Fatal("origin eviction did not remove exactly one eligible record")
	}
	delete(before, victim)
	for record := c.originRecords; record != nil; record = record.next {
		if !before[record] {
			t.Fatal("origin eviction removed the wrong record or inserted a record")
		}
		delete(before, record)
	}
	if len(before) != 0 || c.originIndex == nil || c.originIndex.oldest != oldest || oldest.pins != 1 {
		t.Fatal("origin eviction changed the pinned oldest record or another survivor")
	}
	callerOriginAccount(t, c)
}

func TestCallerIdentityOriginTransferDistinctSiblingPrefix(t *testing.T) {
	p, root, cycle, _ := callerOriginTransferProgram(t, 2)
	type dependency struct {
		key              callerResolveKey
		want, propagated bool
	}
	read := func(frame *callerOriginRecord) (out []dependency) {
		for d := frame.dependencies; d != nil; d = d.next {
			out = append(out, dependency{d.key, d.want, d.propagated})
		}
		return out
	}
	for _, stop := range []string{"paren", "cycle", "raw", "capacity"} {
		t.Run(stop, func(t *testing.T) {
			fast, ordinary := callerOriginTransferPair(t, p, root)
			ordinary.resetCallerObjectExecutions()
			graphs := []*callerGraph{fast, ordinary}
			var owners [2]*callerOriginOwner
			var parents, frames [2]*callerOriginRecord
			var marks [2][4]uint64
			var counts [2]CallerIdentityWork
			var prefix = true
			child := root
			child.tuple = 1000
			for side, g := range graphs {
				owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
				if owner == nil {
					t.Fatal("owner admission")
				}
				defer g.endCallerOrigin(owner)
				owners[side] = owner
				parent := g.beginCallerOriginFrame(owner, callerResolveKeyFor(cycle, false))
				if parent == nil {
					t.Fatal("parent admission")
				}
				defer g.endCallerOriginFrame(owner, parent, nil, true)
				parents[side] = parent
				// Уже существующий конфликт у предка должен остаться видимым.
				g.callerOriginRead(owner, callerResolveKeyFor(child, false), true)
				frame := g.beginCallerOriginFrame(owner, callerResolveKeyFor(root, false))
				if frame == nil {
					t.Fatal("leaf admission")
				}
				defer g.endCallerOriginFrame(owner, frame, nil, true)
				frames[side] = frame
				frame.pushed, owner.seen[frame.key] = true, true
				defer delete(owner.seen, frame.key)
				marks[side], counts[side] = callerReuseMarks(g), g.work
			}
			n := 4
			if stop == "capacity" {
				n = callerOriginDependencyLimit
			}
			for i := range n {
				ref := child
				ref.tuple += i
				last := i == n-1
				if last && stop == "paren" {
					ref = child
					ref.expr = &ast.ParenExpr{X: child.expr}
				}
				if last && stop == "raw" {
					ref.expr = &ast.BasicLit{Value: "1"}
				}
				key := callerResolveKeyFor(ref, false)
				var answers [2]callerResolveAnswer
				for side, g := range graphs {
					owner := owners[side]
					if last && stop == "cycle" {
						owner.seen[key] = true
						defer delete(owner.seen, key)
					}
					if !(last && stop == "raw") {
						if _, exists := g.initialResolveMemo[key]; !exists {
							g.retainCallerAnswer(key, callerResolveAnswer{values: []callerOrigin{{nilValue: true}}}, true)
						}
					}
					if side == 0 {
						answers[side].values, answers[side].unknown = g.resolveOwnedSibling(ref, false, owner.seen, owner, &prefix)
					} else {
						answers[side].values, answers[side].unknown = g.resolveOwned(ref, false, owner.seen, owner)
					}
					callerOriginAccount(t, g.objectExecutions)
				}
				if prefix == last || !parents[0].bad || !parents[1].bad ||
					frames[0].bad != (last && stop == "capacity") || frames[1].bad != frames[0].bad ||
					!slices.Equal(read(frames[0]), read(frames[1])) || !maps.Equal(owners[0].seen, owners[1].seen) ||
					!slices.Equal(answers[0].values, answers[1].values) || answers[0].unknown != answers[1].unknown {
					t.Fatalf("sibling %d: prefix=%t, bad=%t/%t, count=%d/%d", i, prefix, frames[0].bad, frames[1].bad, frames[0].count, frames[1].count)
				}
			}
			f, o := fast.work, ordinary.work
			if callerReuseDelta(fast, marks[0]) != callerReuseDelta(ordinary, marks[1]) ||
				f.OriginTransferReads-counts[0].OriginTransferReads != o.OriginTransferReads-counts[1].OriginTransferReads ||
				f.ResolveInitialHits-counts[0].ResolveInitialHits != o.ResolveInitialHits-counts[1].ResolveInitialHits ||
				f.ResolveCycleCuts-counts[0].ResolveCycleCuts != o.ResolveCycleCuts-counts[1].ResolveCycleCuts ||
				f.ResolveEvaluations-counts[0].ResolveEvaluations != o.ResolveEvaluations-counts[1].ResolveEvaluations {
				t.Fatal("semantic effects or observed work differ")
			}
		})
	}
}
