// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	contextspoof "github.com/PRO-Robotech/kaname/internal/check/caller_identity/testdata/context"
)

// Физическая стоимость выводится из реальных Go-типов и capacity, а не из
// production constants или c.weight. Прежний guard сохраняет reservation24
// с отдельной проверкой sizeof <= 192; это верхняя граница, не exact sizeof.
// Prefix обязан иметь собственный backing;
// отдельный storage test проверяет отсутствие alias с live-буфером.
func callerTraceRecordPhysicalUnits(t *testing.T, record *callerTraceRecord) int {
	t.Helper()
	if record.guard == nil || unsafe.Sizeof(callerTraceGuard{}) > 24*8 || int(record.count) > 64 || int(record.count) > len(record.dependencies) {
		t.Fatal("trace lost its guard or exceeded the exact predicate limit")
	}
	// Форма следует независимому контракту постепенного роста; физические единицы
	// ниже по-прежнему считаются по sizeof/cap, независимо от production-учёта.
	capacity := 0
	if record.count != 0 {
		capacity = 1
		for capacity < int(record.count) {
			capacity *= 2
		}
	}
	liveStorage := len(record.dependencies) == cap(record.dependencies) && cap(record.dependencies) <= capacity && (record.count != 0 || record.dependencies == nil)
	switch record.phase {
	case callerTraceLive:
		if !liveStorage {
			t.Fatal("live trace does not own bounded geometric predicate storage")
		}
	case callerTraceRetained:
		if len(record.dependencies) != int(record.count) || cap(record.dependencies) != int(record.count) {
			t.Fatal("retained trace still reserves unused dependency slots")
		}
	case callerTraceDead:
		// Quarantine leaves the old fully charged allocation in its owner until
		// idle reset. Both live and already compacted backing remain possible.
		if !liveStorage && (len(record.dependencies) != int(record.count) || cap(record.dependencies) != int(record.count)) {
			t.Fatal("quarantined trace lost its original dependency allocation")
		}
	default:
		t.Fatal("account contains a trace without a live/retained/dead phase")
	}
	return int((unsafe.Sizeof(*record)+7)/8) + 24 + cap(record.dependencies)*int((unsafe.Sizeof(callerTraceDependency{})+7)/8)
}

// Даже без prefix/result/scopes столько различных сертификатов не помещается
// в прежний бюджет. Это физический lower bound, не старый fixed-slot floor.
func callerTracePressureSources() int {
	header := int((unsafe.Sizeof(callerTraceRecord{})+7)/8) + int((unsafe.Sizeof(callerTraceGuard{})+7)/8)
	return callerObjectExecutionValues/header + 1
}

// Пересчёт не читает entries/weight как ожидаемые величины. Каждый header,
// backing, guard, chain/frame и pending result перечисляется независимо.
func callerTraceAccount(t *testing.T, c *callerObjectExecutions) (int, int, map[*callerObjectExecutionScope]int) {
	t.Helper()
	entries, units := 0, 0
	refs := map[*callerObjectExecutionScope]int{}
	var buckets [16][]*callerTraceRecord
	if c.traceAccount {
		entries++
		units += 5 + 16
		if c.traceBuckets == nil || unsafe.Sizeof(*c.traceBuckets) != 128 {
			t.Fatal("paid fixed trace index is missing or exceeds its physical reservation")
		}
	} else if c.traceBuckets != nil {
		t.Fatal("trace index exists without its full header reservation")
	}
	for chain := c.traceChains; chain != nil; chain = chain.next {
		entries++
		units += 9
		if chain.owner != c || unsafe.Sizeof(*chain) > 72 {
			t.Fatal("chain owner/layout is outside its reservation")
		}
		if scope := chain.entryScope; scope != nil {
			found := false
			for node := c.scopes[scope.hash]; node != nil; node = node.next {
				found = found || node == scope
			}
			if !chain.executing || scope.references <= 0 || !found {
				t.Fatal("borrowed entry scope has no real retained owner")
			}
			// Borrow не добавляется к refs: настоящий ticket считает его caller.
		}
	}
	for frame := c.traceFrames; frame != nil; frame = frame.next {
		entries++
		units += 8
		if frame.chain == nil || frame.chain.owner != c || unsafe.Sizeof(*frame) > 64 {
			t.Fatal("push frame has no real charged owner")
		}
	}
	for record := c.traceRecords; record != nil; record = record.next {
		buckets[record.source%16] = append(buckets[record.source%16], record)
		entries++
		units += callerTraceRecordPhysicalUnits(t, record)
		if record.holdsScope {
			refs[record.scope]++
		}
		if record.ticket {
			refs[record.scope]++
		}
		if record.resultReserved {
			result := record.objects
			if record.pending != nil {
				result = record.pending
			}
			units += 1 + len(result)
		} else if record.objects != nil || record.pending != nil {
			t.Fatal("result map exists without its reservation")
		}
		if record.phase == callerTraceRetained && (record.chain != nil || record.parent != nil || record.entry != nil || !record.holdsScope) {
			t.Fatal("retained certificate still borrows a live stack")
		}
	}
	if entries > 0 && !c.traceAccount {
		t.Fatal("trace metadata lost its shared header reservation")
	}
	// Ожидаемая последовательность получена из независимого global next,
	// поэтому проверяются все live/retained/dead записи, порядок и обе ссылки.
	for bucket, want := range buckets {
		if c.traceBuckets == nil {
			if len(want) != 0 {
				t.Fatal("global record has no paid lookup index")
			}
			continue
		}
		index := 0
		var previous *callerTraceRecord
		for record := c.traceBuckets[bucket]; record != nil; record = record.bucketNext {
			if index >= len(want) || record != want[index] || record.bucketPrevious != previous {
				t.Fatal("trace bucket differs from exact global order or owns a foreign/cyclic link")
			}
			previous = record
			index++
		}
		if index != len(want) {
			t.Fatal("trace bucket omitted an owned global record")
		}
	}
	return entries, units, refs
}

func callerTraceTypedProgram(t *testing.T, body string) *surfaceProgram {
	t.Helper()
	p := callerSoundnessProgram(t, "type Holder struct{items []Box}", body, "&Handler{}")
	t.Cleanup(func() { callerGraphs.Delete(p) })
	return p
}

func callerTraceDiamondBody(depth int) string {
	var body strings.Builder
	body.WriteString("holder:=&Holder{items:[]Box{}};x0:=holder.items;")
	for i := 1; i <= depth; i++ {
		fmt.Fprintf(&body, "l%d:=x%d;r%d:=x%d;x%d:=l%d;x%d=r%d;", i, i-1, i, i-1, i, i, i, i)
	}
	fmt.Fprintf(&body, "_=append(x%d,Box{});", depth)
	return body.String()
}

// Все ссылки принадлежат typed RPC. Snapshot взят из реальной raw-фазы
// поля; ни object answers, ни seen, ни work counters не внедряются.
func callerTraceTypedGraph(t *testing.T, p *surfaceProgram, rootName string) (*callerGraph, valueSrc, map[string]valueSrc) {
	t.Helper()
	g := callerGraphFor(p, nil)
	g.lifetimeScanning = true
	refs := map[string]valueSrc{}
	var field valueSrc
	for node, body := range g.bodies {
		if body.sp != p.root || node.fn == nil || node.fn.Name() != "RPC" {
			continue
		}
		g.markCallerCalled(node)
		ast.Inspect(body.node, func(n ast.Node) bool {
			src := valueSrc{pkg: body.sp, fk: callerKey(node), tuple: -1}
			switch x := n.(type) {
			case *ast.Ident:
				if v, ok := body.sp.info.Defs[x].(*types.Var); ok && !v.IsField() {
					src.expr = x
					refs[x.Name] = src
				}
			case *ast.SelectorExpr:
				if x.Sel.Name == "items" {
					src.expr = x
					field = src
				}
			}
			return true
		})
	}
	if field.expr != nil {
		selector := field.expr.(*ast.SelectorExpr)
		base := field
		base.expr = selector.X
		fields := fieldPath(field.pkg.info.Selections[selector])
		g.callerObjects(base, map[callerObjectSourceID]bool{})
		index, entered := g.enterCallerFieldQuery(base, fields)
		if !entered {
			t.Fatal("typed field frame was not entered")
		}
		t.Cleanup(func() { g.leaveCallerFieldQuery(index) })
		g.fieldQueries[index].refs, g.fieldQueries[index].unknown = g.embeddedCallerSourcesRaw(base, fields, map[callerFieldKey]bool{})
		if g.fieldQueries[index].unknown || len(g.fieldQueries[index].refs) != 1 {
			t.Fatal("typed field snapshot was not concrete")
		}
	}
	root := refs[rootName]
	if root.expr == nil {
		t.Fatal("typed root is missing")
	}
	g.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	g.resetCallerObjectExecutions()
	return g, root, refs
}

type callerTraceOpaqueContext struct {
	context.Context
	onErr func()
}

func (c *callerTraceOpaqueContext) Err() error {
	if c.onErr != nil {
		c.onErr()
	}
	return c.Context.Err()
}

type callerTraceNoncomparableContext struct {
	context.Context
	values []int
}

func TestCallerIdentityInteriorContextAdmission(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	defer cancel()
	timed, stop := context.WithTimeout(context.Background(), time.Minute)
	defer stop()
	calls := 0
	spoof := contextspoof.New(func() { calls++ })
	if reflect.TypeOf(spoof).String() != reflect.TypeOf(context.Background()).String() || reflect.TypeOf(spoof).PkgPath() == "context" {
		t.Fatal("typed spoof did not reproduce the stdlib type string with a different import path")
	}
	spy := &callerTraceOpaqueContext{Context: context.Background(), onErr: func() { calls++ }}
	var typedNil *callerTraceOpaqueContext
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want bool
	}{
		{"background", context.Background(), true}, {"todo", context.TODO(), true},
		{"cancel", cancelled, true}, {"timer", timed, true},
		{"nil", nil, false}, {"typed_nil", typedNil, false},
		{"opaque", spy, false}, {"name_spoof", spoof, false},
		{"value", context.WithValue(context.Background(), "trace", 1), false},
		{"without_cancel", context.WithoutCancel(spy), false},
		{"noncomparable", callerTraceNoncomparableContext{context.Background(), []int{1}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, version := range []string{"go1.26.10", "go1.26.11"} {
				if callerTraceContextVersion(tc.ctx, version) != tc.want {
					t.Fatalf("concrete context admission differs for %s", version)
				}
			}
			for _, version := range []string{"unknown", "go1.26.9", "go1.26.12", "go1.26.11-custom", "devel go1.26.11"} {
				if callerTraceContextVersion(tc.ctx, version) {
					t.Fatalf("unreviewed toolchain %s entered context admission", version)
				}
			}
			if callerTraceSameContext(context.Background(), tc.ctx) && tc.name != "background" {
				t.Fatal("identity guard accepted a different context")
			}
			admitted := callerTraceContext(tc.ctx)
			if callerTraceSameContext(tc.ctx, tc.ctx) != admitted ||
				callerFreshSameContext(tc.ctx, tc.ctx) != (admitted || tc.ctx == nil) {
				t.Fatal("сравнение контекста с собой изменило допуск")
			}
		})
	}
	other, otherCancel := context.WithCancel(context.Background())
	defer otherCancel()
	if calls != 0 || callerTraceSameContext(cancelled, other) {
		t.Fatal("classifier invoked opaque methods or merged different pointer identities")
	}
}

// Старый metadata-предикат остаётся независимым oracle только в этой пробе.
// Особые формы отражением проверяют границы exact type и typed nil, которые
// обычные constructors не возвращают; методы непрозрачного Context не зовутся.
func TestCallerIdentityInteriorContextTypeIdentityEquivalence(t *testing.T) {
	oldAdmission := func(ctx context.Context, version string) bool {
		if (version != "go1.26.10" && version != "go1.26.11") || ctx == nil {
			return false
		}
		typ := reflect.TypeOf(ctx)
		if typ.Kind() == reflect.Struct {
			return typ.PkgPath() == "context" && (typ.Name() == "backgroundCtx" || typ.Name() == "todoCtx")
		}
		if typ.Kind() != reflect.Pointer || reflect.ValueOf(ctx).IsNil() {
			return false
		}
		typ = typ.Elem()
		return typ.Kind() == reflect.Struct && typ.PkgPath() == "context" && (typ.Name() == "cancelCtx" || typ.Name() == "timerCtx")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	defer cancel()
	timed, stop := context.WithTimeout(context.Background(), time.Minute)
	defer stop()
	calls := 0
	spy := &callerTraceOpaqueContext{Context: context.Background(), onErr: func() { calls++ }}
	contexts := []context.Context{
		nil, context.Background(), context.TODO(), cancelled, timed,
		spy, contextspoof.New(func() { calls++ }),
		context.WithValue(spy, "type-identity", 1), context.WithoutCancel(spy),
		callerTraceNoncomparableContext{context.Background(), []int{1}},
	}
	for _, ctx := range []context.Context{context.Background(), context.TODO()} {
		contexts = append(contexts, reflect.New(reflect.TypeOf(ctx)).Interface().(context.Context))
	}
	for _, ctx := range []context.Context{cancelled, timed} {
		typ := reflect.TypeOf(ctx)
		contexts = append(contexts, reflect.Zero(typ).Interface().(context.Context))
		contexts = append(contexts, reflect.New(typ.Elem()).Interface().(context.Context))
	}
	for phase := 0; phase < 2; phase++ {
		for _, version := range []string{"go1.26.10", "go1.26.11", "unknown", "go1.26.12", "go1.26.11-custom"} {
			for i, ctx := range contexts {
				if got, want := callerTraceContextVersion(ctx, version), oldAdmission(ctx, version); got != want {
					t.Fatalf("context %d phase %d version %s: exact-type=%v metadata=%v", i, phase, version, got, want)
				}
			}
		}
		cancel()
		stop()
	}
	if calls != 0 {
		t.Fatal("context classification invoked an opaque method")
	}
}

// Эта проверка подтверждает source в выбранном GOROOT, а не происхождение
// исполняемого файла: привязка бинарника к проверенному toolchain остаётся
// обязанностью build provenance. Неизвестный toolchain не пропускается.
func TestCallerIdentityInteriorContextSourcePin(t *testing.T) {
	if runtime.Version() != "go1.26.10" && runtime.Version() != "go1.26.11" {
		t.Fatal("context source pin requires a reviewed toolchain")
	}
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "context", "context.go"))
	if err != nil {
		t.Fatal(err)
	}
	const want = "765f99f7cc0710b0117ffa183e432524f429c21496fcbad9b63fb9886fdbaac7"
	if got := fmt.Sprintf("%x", sha256.Sum256(source)); got != want {
		t.Fatalf("reviewed context source changed: got %s, want %s", got, want)
	}
}

func TestCallerIdentityInteriorDiamondWork(t *testing.T) {
	if runtime.Version() != "go1.26.10" && runtime.Version() != "go1.26.11" {
		t.Fatal("this source-pinned admission test requires the reviewed toolchain")
	}
	p := callerTraceTypedProgram(t, callerTraceDiamondBody(6))
	fast, root, _ := callerTraceTypedGraph(t, p, "x6")
	slow, _, _ := callerTraceTypedGraph(t, p, "x6")
	fast.ctx = context.Background()
	slow.objectExecutions = nil
	fastState, slowState := fast.callerObjectExecutionState(), slow.callerObjectExecutionState()
	fastScope := fast.callerExecutionSnapshot()
	fastMarks, slowMarks := callerReuseMarks(fast), callerReuseMarks(slow)
	fastRaw, slowRaw := fast.work.ObjectRawEvaluations, slow.work.ObjectRawEvaluations
	got, unknown, _ := fast.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	want, otherUnknown, _ := slow.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	actual, baseline := fast.work.ObjectRawEvaluations-fastRaw, slow.work.ObjectRawEvaluations-slowRaw
	if unknown != otherUnknown || !maps.Equal(got, want) || len(got) != 22 || callerReuseDelta(fast, fastMarks) != callerReuseDelta(slow, slowMarks) {
		t.Fatal("interior diamond changed exact objects/unknown/four semantic marks")
	}
	if baseline != 317 || actual >= baseline || fast.work.ObjectTraceHits == 0 || fast.work.ObjectTraceStores == 0 || fast.work.ObjectTraceSeenReads == 0 || fast.work.ObjectTraceDependencySteps == 0 || fast.work.ObjectTraceValidationSteps == 0 {
		t.Fatalf("nonvacuous interior work witness failed: raw=%d reference=%d work=%+v", actual, baseline, fast.work)
	}
	if fast.callerObjectExecutionState() != fastState || slow.callerObjectExecutionState() != slowState || !fastScope.matches(fast) {
		t.Fatal("measured typed region changed durable state or exact scope")
	}
	immutable := maps.Clone(got)
	retainedCopies := map[*callerTraceRecord]map[callerObjectKey]bool{}
	for record := fast.objectExecutions.traceRecords; record != nil; record = record.next {
		retainedCopies[record] = maps.Clone(record.objects)
	}
	fm, sm := callerReuseMarks(fast), callerReuseMarks(slow)
	gotAgain, u, _ := fast.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	wantAgain, other, _ := slow.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	if u != other || !maps.Equal(gotAgain, wantAgain) || !maps.Equal(got, immutable) || callerReuseDelta(fast, fm) != callerReuseDelta(slow, sm) {
		t.Fatal("reused child answer changed copy-on-write provenance")
	}
	for record, copy := range retainedCopies {
		if !maps.Equal(record.objects, copy) {
			t.Fatal("borrowed trace answer was mutated by parent union")
		}
	}
	callerAssertExecutionRetention(t, fast.objectExecutions, nil)
	t.Logf("INTERIOR raw=%d reference=%d seen=%d dependency=%d validation=%d hits=%d stores=%d", actual, baseline, fast.work.ObjectTraceSeenReads, fast.work.ObjectTraceDependencySteps, fast.work.ObjectTraceValidationSteps, fast.work.ObjectTraceHits, fast.work.ObjectTraceStores)
}

func TestCallerIdentityInteriorSelfAppend(t *testing.T) {
	for _, anchored := range []bool{false, true} {
		name, initial := "hollow", "var found []Box;"
		if anchored {
			name, initial = "anchored", "found:=[]Box{};"
		}
		t.Run(name, func(t *testing.T) {
			p := callerTraceTypedProgram(t, initial+"found=append(found,Box{});found=append(found,Box{});alias:=found;_=alias;_=found[0]")
			fast, root, _ := callerTraceTypedGraph(t, p, "alias")
			slow, _, _ := callerTraceTypedGraph(t, p, "alias")
			fast.ctx = context.Background()
			slow.objectExecutions = nil
			positive, negative := false, false
			for repeat := 0; repeat < 3; repeat++ {
				fm, sm := callerReuseMarks(fast), callerReuseMarks(slow)
				got, unknown, _ := fast.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
				want, u, _ := slow.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
				if unknown != !anchored || unknown != u || !maps.Equal(got, want) || callerReuseDelta(fast, fm) != callerReuseDelta(slow, sm) || callerReuseDelta(fast, fm)[3] == 0 {
					t.Fatal("self-append changed an actual cycle, outer hollow barrier, or semantic multiplicity")
				}
			}
			for record := fast.objectExecutions.traceRecords; record != nil; record = record.next {
				for i := 0; i < int(record.count); i++ {
					positive = positive || record.dependencies[i].want == 1
					negative = negative || record.dependencies[i].want == 0
				}
			}
			if fast.work.ObjectTraceHits == 0 || !positive || !negative {
				t.Fatal("cyclic fixture did not exercise real positive and negative entry predicates")
			}
			callerAssertExecutionRetention(t, fast.objectExecutions, nil)
		})
	}
}

func TestCallerIdentityInteriorAncestorTranslation(t *testing.T) {
	p := callerTraceTypedProgram(t, "holder:=&Holder{items:[]Box{}};x:=holder.items;left:=x;right:=x;x=left;root:=left;root=right;outer:=root;_=outer")
	fast, _, refs := callerTraceTypedGraph(t, p, "outer")
	slow, _, _ := callerTraceTypedGraph(t, p, "outer")
	fast.ctx = context.Background()
	slow.objectExecutions = nil
	for _, name := range []string{"left", "right", "outer", "left", "right", "outer"} {
		fm, sm := callerReuseMarks(fast), callerReuseMarks(slow)
		got, unknown, _ := fast.callerObjectsOwned(refs[name], map[callerObjectSourceID]bool{})
		want, u, _ := slow.callerObjectsOwned(refs[name], map[callerObjectSourceID]bool{})
		if unknown != u || !maps.Equal(got, want) || len(got) == 0 || callerReuseDelta(fast, fm) != callerReuseDelta(slow, sm) {
			t.Fatalf("ancestor %s changed objects, UNKNOWN or cut multiplicity", name)
		}
	}
	// Предикаты keyed по точному AST use, не по имени переменной/Defs.
	xUse := fast.sources(callerVariable(refs["left"].pkg, refs["left"].expr))[0]
	var leftUse valueSrc
	for _, ref := range fast.sources(callerVariable(refs["x"].pkg, refs["x"].expr)) {
		if id, ok := ref.expr.(*ast.Ident); ok && id.Name == "left" {
			leftUse = ref
		}
	}
	rootUse := fast.sources(callerVariable(refs["outer"].pkg, refs["outer"].expr))[0]
	x := fast.objectSourceIDs[callerResolveKeyFor(xUse, true)]
	left := fast.objectSourceIDs[callerResolveKeyFor(leftUse, true)]
	root := fast.objectSourceIDs[callerResolveKeyFor(rootUse, true)]
	if x == 0 || left == 0 || root == 0 {
		t.Fatal("typed ancestor use was not interned")
	}
	positive, negative, translated := false, false, false
	for record := fast.objectExecutions.traceRecords; record != nil; record = record.next {
		if record.phase != callerTraceRetained {
			continue
		}
		for i := 0; i < int(record.count); i++ {
			dep := record.dependencies[i]
			if dep.source == left && record.source == x {
				positive = positive || dep.want == 1
				negative = negative || dep.want == 0
			}
			if record.source == root && dep.source == left {
				if dep.want != 0 {
					t.Fatal("child hit leaked its locally pushed ancestor into parent entry predicates")
				}
				translated = true
			}
		}
	}
	if !positive || !negative || !translated || fast.work.ObjectTraceHits == 0 {
		t.Fatal("typed cyclic twins did not retain conflicting ancestor variants and a translated live parent")
	}
	callerAssertExecutionRetention(t, fast.objectExecutions, nil)
}

// Непрозрачный контекст меняется на N-м действительно исполненном Err.
// Никаких вызовов Err из самого теста или подставных cache answers нет.
type callerTraceDelayedContext struct {
	context.Context
	step func() error
}

func (c *callerTraceDelayedContext) Err() error { return c.step() }

func TestCallerIdentityInteriorOpaqueFallbackTrace(t *testing.T) {
	for _, change := range []string{"unknown", "identity", "noncomparable", "cancel", "reentry"} {
		for _, delayed := range []bool{false, true} {
			name := change + "_immediate"
			at := 1
			if delayed {
				name, at = change+"_delayed", 7
			}
			t.Run(name, func(t *testing.T) {
				p := callerTraceTypedProgram(t, callerTraceDiamondBody(4))
				type point struct {
					raw   int
					marks [4]uint64
				}
				type observation struct {
					answer  map[callerObjectKey]bool
					unknown bool
					marks   [4]uint64
					trace   []point
					raw     int
				}
				run := func(reference bool) observation {
					g, field, _ := callerTraceTypedGraph(t, p, "x4")
					base, index := g.fieldQueries[0].source.source, 0
					g.ctx = context.Background()
					for range 3 {
						g.callerObjects(field, map[callerObjectSourceID]bool{})
					}
					if g.work.ObjectTraceStores == 0 || len(g.objectExecutions.answers) == 0 {
						t.Fatal("admitted typed diamond did not warm both real replay layers")
					}
					traceHits, traceStores := g.work.ObjectTraceHits, g.work.ObjectTraceStores
					if reference {
						g.objectExecutions = nil
					}
					marks, raw := callerReuseMarks(g), g.work.ObjectRawEvaluations
					queries, hits, stores := g.work.ObjectExecutionQueries, g.work.ObjectExecutionHits, g.work.ObjectExecutionStores
					var result observation
					calls, cancelled := 0, false
					g.ctx = &callerTraceDelayedContext{Context: context.Background(), step: func() error {
						calls++
						result.trace = append(result.trace, point{g.work.ObjectRawEvaluations - raw, callerReuseDelta(g, marks)})
						if calls == at {
							switch change {
							case "unknown":
								g.fieldQueries[index].unknown = true
							case "identity":
								g.ctx = context.Background()
							case "noncomparable":
								g.ctx = callerTraceNoncomparableContext{context.Background(), []int{1}}
							case "cancel":
								cancelled = true
							case "reentry":
								outer := g.ctx
								g.ctx = nil
								g.callerObjectsOwned(base, map[callerObjectSourceID]bool{})
								g.ctx = outer
							}
						}
						if cancelled {
							return context.Canceled
						}
						return nil
					}}
					result.answer, result.unknown = g.callerObjects(field, map[callerObjectSourceID]bool{})
					result.marks, result.raw = callerReuseDelta(g, marks), g.work.ObjectRawEvaluations-raw
					if calls < at || g.work.ObjectExecutionQueries != queries || g.work.ObjectExecutionHits != hits || g.work.ObjectExecutionStores != stores || g.work.ObjectTraceHits != traceHits || g.work.ObjectTraceStores != traceStores {
						t.Fatal("opaque path missed its actual delayed checkpoint or entered either replay layer")
					}
					return result
				}
				got, want := run(false), run(true)
				if got.unknown != want.unknown || !maps.Equal(got.answer, want.answer) || got.marks != want.marks || got.raw != want.raw || len(got.trace) != len(want.trace) {
					t.Fatal("opaque enabled path differs from genuine original fallback")
				}
				for i := range got.trace {
					if got.trace[i] != want.trace[i] {
						t.Fatalf("Err checkpoint %d moved to another raw/semantic point", i+1)
					}
				}
			})
		}
	}
}

func TestCallerIdentityInteriorCapacityAndK(t *testing.T) {
	for _, name := range []string{"dependency_bound", "shared_value_bound"} {
		t.Run(name, func(t *testing.T) {
			depths := []int{62, 63}
			if name == "shared_value_bound" {
				depths = []int{130}
			}
			for _, depth := range depths {
				var body strings.Builder
				body.WriteString("holder:=&Holder{items:[]Box{}};x0:=holder.items;")
				for i := 1; i <= depth; i++ {
					fmt.Fprintf(&body, "x%d:=x%d;", i, i-1)
				}
				fmt.Fprintf(&body, "left:=x%d;right:=x%d;root:=left;root=right;_=root", depth, depth)
				p := callerTraceTypedProgram(t, body.String())
				fast, root, refs := callerTraceTypedGraph(t, p, "root")
				slow, _, _ := callerTraceTypedGraph(t, p, "root")
				fast.ctx = context.Background()
				slow.objectExecutions = nil

				// refs содержит Defs; кандидат приходит из реального RHS left.
				// Нулевой ID или совпадение Def/use здесь были бы вакуозным oracle.
				leftSources := fast.sources(callerVariable(refs["left"].pkg, refs["left"].expr))
				rightSources := fast.sources(callerVariable(refs["right"].pkg, refs["right"].expr))
				rootSources := fast.sources(callerVariable(root.pkg, root.expr))
				if len(leftSources) != 1 || len(rightSources) != 1 || len(rootSources) != 2 {
					t.Fatal("typed chain lost its actual single-source branches")
				}
				target, rightTarget := leftSources[0], rightSources[0]
				definition := refs[fmt.Sprintf("x%d", depth)]
				variable := callerVariable(definition.pkg, definition.expr)
				firstBranch := callerVariable(rootSources[0].pkg, rootSources[0].expr)
				if variable == nil || callerVariable(target.pkg, target.expr) != variable || callerVariable(rightTarget.pkg, rightTarget.expr) != variable || target.expr == definition.expr || target.expr == rightTarget.expr || firstBranch != callerVariable(refs["left"].pkg, refs["left"].expr) {
					t.Fatal("candidate is not the first actually traversed typed RHS use")
				}
				topID := fast.objectSourceIDs[callerResolveKeyFor(target, true)]
				rightID := fast.objectSourceIDs[callerResolveKeyFor(rightTarget, true)]
				rootID := fast.objectSourceIDs[callerResolveKeyFor(root, true)]
				branchID := fast.objectSourceIDs[callerResolveKeyFor(rootSources[0], true)]
				if topID == 0 || rightID == 0 || rightID == topID || rootID == 0 || branchID == 0 {
					t.Fatal("actual warm traversal did not intern the distinct candidate and entry ancestors")
				}

				// Перепись исходных typed рёбер, не содержимого проверяемого record.
				// У xN..x0 ровно один RHS, затем active field terminal; owner/slice
				// уже в ordinary memo и не выполняют raw seen-read. Все эти N+2
				// разных reads отсутствуют среди двух entry ancestors, поэтому
				// являются внешними отрицательными predicates для кандидата.
				required := map[callerObjectSourceID]bool{}
				var path []valueSrc
				for current := target; ; {
					id := fast.objectSourceIDs[callerResolveKeyFor(current, true)]
					_, initialMemo := fast.initialObjectMemo[id]
					_, fullMemo := fast.objectMemo[id]
					if id == 0 || required[id] || id == rootID || id == branchID || initialMemo || fullMemo {
						t.Fatal("predicate census is not an actual acyclic raw path external to entry ancestors")
					}
					required[id] = true
					path = append(path, current)
					if selector, terminal := current.expr.(*ast.SelectorExpr); terminal {
						base := current
						base.expr = selector.X
						if len(fast.fieldQueries) != 1 || fast.fieldQueries[0].source != callerResolveKeyFor(base, true) || len(fast.fieldQueries[0].fields) != 1 || len(fast.fieldQueries[0].refs) != 1 || fast.fieldQueries[0].unknown || !fast.callerExecutionScopeTracked() {
							t.Fatal("predicate census did not end at its exact concrete active field")
						}
						for _, boundary := range []valueSrc{base, fast.fieldQueries[0].refs[0]} {
							boundaryID := fast.objectSourceIDs[callerResolveKeyFor(boundary, true)]
							answer, complete := fast.initialObjectMemo[boundaryID]
							if boundaryID == 0 || !complete || answer.unknown {
								t.Fatal("terminal ordinary-memo boundary was not really warmed")
							}
						}
						break
					}
					v := callerVariable(current.pkg, current.expr)
					if v == nil {
						t.Fatal("predicate census escaped the typed readonly alias chain")
					}
					next := fast.sources(v)
					if len(next) != 1 {
						t.Fatal("predicate census encountered an unaccounted branch")
					}
					current = next[0]
				}
				if len(required) != depth+2 {
					t.Fatal("typed external-predicate count differs from the actual linear source path")
				}
				withinK := len(required) <= callerTraceDependencies
				if name == "dependency_bound" && len(required) != 64 && len(required) != 65 {
					t.Fatal("K-only twins do not straddle the exact fixed limit")
				}

				state := fast.callerObjectExecutionState()
				scope := fast.callerExecutionSnapshot()
				// Даже mutant, публикующий все усечённые записи, укладывается в
				// этот верхний предел: N+5 records, N+4 live frames, один scope;
				// суммы размеров результатов учитывают каждую добавленную storage.
				maxEntries := (depth + 5) + (depth + 4) + 3
				maxResultUnits := depth*(depth-1)/2 + 9*depth + 26
				// Все records считаем по большему live backing; один дополнительный
				// prefix64 одновременно существует только при текущем completion.
				pairUnits := int((unsafe.Sizeof(callerTraceDependency{}) + 7) / 8)
				liveUnits := int((unsafe.Sizeof(callerTraceRecord{})+7)/8) + 24 + 64*pairUnits
				maxUnits := 21 + 9 + (depth+4)*8 + (depth+5)*liveUnits + 64*pairUnits + maxResultUnits + 1 + fast.callerContainerObjectScopeWeight()
				if name == "dependency_bound" && (maxEntries >= callerObjectExecutionEntries || maxUnits >= callerObjectExecutionValues) {
					t.Fatal("K-only fixture cannot exclude shared capacity as a refusal cause")
				}
				if len(fast.objectExecutions.answers) != 0 || fast.objectExecutions.traceRecords != nil {
					t.Fatal("measured candidate already has an execution summary")
				}
				if depth == 130 {
					// Холодный длинный спуск может исчерпать budget живыми frames
					// до leaf и законно не сохранить ничего. Для отдельного capacity
					// case реально греем его же суффикс; это не store от измеряемого130.
					warmQuery, warmCandidate := path[len(path)-65], path[len(path)-64]
					warmID := fast.objectSourceIDs[callerResolveKeyFor(warmCandidate, true)]
					if warmID == 0 {
						t.Fatal("capacity warmup candidate was not visited by the typed baseline")
					}
					warmFast, warmSlow, stores := callerReuseMarks(fast), callerReuseMarks(slow), fast.work.ObjectTraceStores
					warmAnswer, warmUnknown, _ := fast.callerObjectsOwned(warmQuery, map[callerObjectSourceID]bool{})
					warmWant, warmOther, _ := slow.callerObjectsOwned(warmQuery, map[callerObjectSourceID]bool{})
					if warmUnknown != warmOther || !maps.Equal(warmAnswer, warmWant) || len(warmAnswer) == 0 || callerReuseDelta(fast, warmFast) != callerReuseDelta(slow, warmSlow) || fast.work.ObjectTraceStores <= stores {
						t.Fatal("real capacity warmup changed original semantics or stored no certificate")
					}
					warmed := false
					for record := fast.objectExecutions.traceRecords; record != nil; record = record.next {
						if record.source == warmID && record.phase == callerTraceRetained && record.count == 64 {
							warmed = true
						}
					}
					if !warmed {
						t.Fatal("capacity case did not really retain its matched within-K typed source")
					}
					callerAssertExecutionRetention(t, fast.objectExecutions, nil)
				}
				capacityBefore := fast.work.ObjectTraceCapacityFallbacks
				evictionsBefore := fast.work.ObjectTraceEvictions
				fm, sm := callerReuseMarks(fast), callerReuseMarks(slow)
				got, unknown, _ := fast.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
				want, u, _ := slow.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
				if unknown != u || !maps.Equal(got, want) || len(got) <= depth || callerReuseDelta(fast, fm) != callerReuseDelta(slow, sm) {
					t.Fatal("fixed capacity introduced a semantic cutoff or lost typed aliases")
				}
				delta := callerReuseDelta(fast, fm)
				if fast.callerObjectExecutionState() != state || !scope.matches(fast) || delta[0] <= delta[1] || delta[2] != 0 || delta[3] != 0 || unknown {
					t.Fatal("typed K witness changed durable/scope state or lost its uncovered acyclic cut")
				}
				if name == "dependency_bound" && (fast.work.ObjectTraceCapacityFallbacks != 0 || fast.work.ObjectExecutionCapacityFallbacks != 0 || fast.work.ObjectExecutionPeakEntries > maxEntries || fast.work.ObjectExecutionPeakValues > maxUnits) {
					t.Fatal("K-only refusal is confounded by shared capacity or unaccounted retention")
				}
				retained, matched := 0, 0
				for record := fast.objectExecutions.traceRecords; record != nil; record = record.next {
					retained++
					if record.count > 64 {
						t.Fatal("overflowed entry dependency set was published")
					}
					if record.source != topID {
						continue
					}
					if !withinK {
						t.Fatal("actually visited >K candidate was retained, including a silently truncated certificate")
					}
					matched++
					if record.phase != callerTraceRetained || record.count == 0 || int(record.count) != len(required) || record.guard.state != state || !record.scope.snapshot.matches(fast) {
						t.Fatal("matched within-K typed candidate was not completely retained")
					}
					remaining := maps.Clone(required)
					for i := 0; i < int(record.count); i++ {
						dependency := record.dependencies[i]
						if dependency.want != 0 || !remaining[dependency.source] {
							t.Fatal("positive certificate does not retain the exact independently enumerated predicates")
						}
						delete(remaining, dependency.source)
					}
					if len(remaining) != 0 {
						t.Fatal("positive certificate omitted an external predicate")
					}
				}
				if withinK && matched != 1 {
					t.Fatal("matched within-K candidate was not admitted exactly once")
				}
				// Прогрев выше уже доказал удержание настоящего сертификата. При
				// depth130 вытеснение может удалить его до исчерпания живых кадров;
				// отсутствие записей после этого требует фактического eviction.
				if depth == 130 {
					if fast.work.ObjectTraceCapacityFallbacks <= capacityBefore || retained == 0 && fast.work.ObjectTraceEvictions <= evictionsBefore {
						t.Fatal("typed capacity pressure lacked real refusal or lost its warm certificate without eviction")
					}
				} else if retained == 0 {
					t.Fatal("typed K-only chain did not retain certificates")
				}
				callerAssertExecutionRetention(t, fast.objectExecutions, nil)
			}
		})
	}
}

func TestCallerIdentityInteriorSemanticOverflow(t *testing.T) {
	p := callerTraceTypedProgram(t, callerTraceDiamondBody(6))
	g, root, _ := callerTraceTypedGraph(t, p, "x6")
	g.ctx = context.Background()
	g.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	if g.work.ObjectTraceStores == 0 {
		t.Fatal("real trace warmup did not publish any execution")
	}
	// Это отдельный arithmetic-тест, не seeded performance witness.
	g.resolveCuts = ^uint64(0) - 1
	marks, raw := callerReuseMarks(g), g.work.ObjectRawEvaluations
	_, unknown, _ := g.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	if !unknown || !g.semanticOverflow || g.resolveCuts != marks[0] || g.work.ObjectRawEvaluations-raw != 1 || g.completedInitialSkips != marks[2] {
		t.Fatal("interior replay wrapped semantic cuts or manufactured completion before refusal")
	}
	callerAssertExecutionRetention(t, g.objectExecutions, nil)
	g.resetCallerObjectExecutions()
	_, unknown, _ = g.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	if !unknown || !g.semanticOverflow {
		t.Fatal("RPC namespace reset erased whole-run arithmetic refusal")
	}
	report := CallerIdentityReport{}
	g.refuseCallerSemanticOverflow(&report)
	if report.Invalid == "" {
		t.Fatal("semantic overflow was admitted as a successful report")
	}
}

func TestCallerIdentityInteriorMeasuredWork(t *testing.T) {
	const depth = 16
	p := callerTraceTypedProgram(t, callerTraceDiamondBody(depth))
	fast, root, refs := callerTraceTypedGraph(t, p, "x16")
	slow, _, _ := callerTraceTypedGraph(t, p, "x16")
	fast.ctx = context.Background()
	slow.objectExecutions = nil
	// V/E считаются по точным typed source keys, включая разные AST uses.
	base := fast.fieldQueries[0].source.source
	leaf := fast.fieldQueries[0].refs[0]
	vertices := map[callerResolveKey]valueSrc{callerResolveKeyFor(root, true): root, callerResolveKeyFor(base, true): base, callerResolveKeyFor(leaf, true): leaf}
	for name, alias := range refs {
		if name == "holder" {
			continue
		}
		for _, ref := range fast.sources(callerVariable(alias.pkg, alias.expr)) {
			vertices[callerResolveKeyFor(ref, true)] = ref
		}
	}
	edges := 2
	for key, src := range vertices {
		if key == callerResolveKeyFor(base, true) {
			continue
		}
		if _, alias := src.expr.(*ast.Ident); alias {
			edges += len(fast.sources(callerVariable(src.pkg, src.expr)))
		}
	}
	if len(vertices) != 4*depth+4 || edges != 6*depth+2 {
		t.Fatal("typed V/E census lost a source identity")
	}
	fm, sm := callerReuseMarks(fast), callerReuseMarks(slow)
	before, baselineBefore := fast.work, slow.work.ObjectRawEvaluations
	got, unknown, _ := fast.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	want, u, _ := slow.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
	raw := fast.work.ObjectRawEvaluations - before.ObjectRawEvaluations
	// Здесь суммируются исполненные операции; replay cuts не считаются работой.
	measured := raw + fast.work.ObjectUnionWrites - before.ObjectUnionWrites + fast.work.ObjectTraceSeenReads - before.ObjectTraceSeenReads + fast.work.ObjectTraceDependencySteps - before.ObjectTraceDependencySteps + fast.work.ObjectTraceValidationSteps - before.ObjectTraceValidationSteps
	baseline := slow.work.ObjectRawEvaluations - baselineBefore
	if unknown != u || !maps.Equal(got, want) || callerReuseDelta(fast, fm) != callerReuseDelta(slow, sm) {
		t.Fatal("measured trace work changed exact semantics")
	}
	if baseline != 5*(1<<depth)-3 || baseline <= 4*(len(vertices)+edges) || raw > 4*(len(vertices)+edges) || measured >= baseline || fast.work.ObjectTraceHits == 0 {
		t.Fatalf("nonvacuous work bound: raw=%d measured=%d reference=%d V=%d E=%d", raw, measured, baseline, len(vertices), edges)
	}
	callerAssertExecutionRetention(t, fast.objectExecutions, nil)
}

// Эти проверки исполняют настоящие lifecycle primitives на typed графе.
// Они не изображают callbacks внутри допущенного stdlib Err: таких callbacks нет.
func TestCallerIdentityInteriorLifecycleGuards(t *testing.T) {
	for _, mode := range []string{"false_extra", "context_identity", "noncomparable", "reentry", "same_epoch_scope", "repeated_reset", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			p := callerTraceTypedProgram(t, callerTraceDiamondBody(4))
			g, root, refs := callerTraceTypedGraph(t, p, "x4")
			g.ctx = context.Background()
			if mode == "context_identity" {
				first, cancel := context.WithCancel(context.Background())
				defer cancel()
				g.ctx = first
			}
			g.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
			if g.work.ObjectTraceStores == 0 {
				t.Fatal("typed lifecycle warmup retained no real trace")
			}
			if mode == "reentry" {
				for range 3 {
					g.callerObjects(root, map[callerObjectSourceID]bool{})
				}
			}
			c := g.objectExecutions
			seen := map[callerObjectSourceID]bool{}
			entryContext := g.ctx
			chain := g.beginCallerTrace(seen)
			if chain == nil || !g.callerTraceValid(chain) {
				t.Fatal("real empty-chain admission failed")
			}
			callerAssertExecutionRetention(t, c, nil)
			// Прямой unit исполняет ровно production push/delete/pop protocol.
			// Счётчики и кеши не заполняются вручную; key реально интернирован.
			var liveFrame *callerTraceFrame
			var liveID callerObjectSourceID
			if mode == "repeated_reset" {
				liveID = g.internObjectSource(root)
				liveFrame = g.callerTracePush(chain, liveID)
				if liveFrame == nil {
					t.Fatal("real owned push reservation failed")
				}
				seen[liveID] = true
				if !g.callerTraceValid(chain) || liveFrame.chain != chain || !liveFrame.live {
					t.Fatal("real push lost its owned map/frame")
				}
				callerAssertExecutionRetention(t, c, nil)
			}
			epoch := g.bindingEpoch
			switch mode {
			case "false_extra":
				// Это враждебный входной map, а не имитация owned push.
				id := g.objectSourceIDs[callerResolveKeyFor(refs["x0"], true)]
				seen[id] = false
				if g.callerTraceValid(chain) {
					t.Fatal("false-valued extra key entered a proven stack")
				}
				delete(seen, id)
				if g.callerTraceValid(chain) {
					t.Fatal("restored map erased sticky chain taint")
				}
			case "context_identity", "noncomparable":
				if mode == "context_identity" {
					other, cancel := context.WithCancel(context.Background())
					defer cancel()
					g.ctx = other
				} else {
					g.ctx = callerTraceNoncomparableContext{context.Background(), []int{1}}
				}
				if g.callerTraceValid(chain) {
					t.Fatal("changed context identity entered old live chain")
				}
				g.ctx = entryContext
				if g.callerTraceValid(chain) {
					t.Fatal("restored identity erased sticky chain taint")
				}
			case "reentry":
				hits := g.work.ObjectExecutionHits
				g.callerObjects(root, map[callerObjectSourceID]bool{})
				if g.callerTraceValid(chain) || g.work.ObjectExecutionHits != hits+1 {
					t.Fatal("public fresh hit did not taint suspended chain")
				}
			case "same_epoch_scope":
				old := c.scope(g)
				if old == nil {
					t.Fatal("real scope acquire failed")
				}
				g.fieldQueries[0].unknown = true
				fresh := c.scope(g)
				if fresh == nil || fresh == old || old.snapshot.matches(g) || g.bindingEpoch != epoch {
					t.Fatal("same-epoch scope mutation reused old identity")
				}
				c.releaseTicket(g, fresh)
				g.fieldQueries[0].unknown = false
				restored := c.scope(g)
				if restored != old {
					t.Fatal("restored exact content lost its pinned identity")
				}
				c.releaseTicket(g, restored)
				c.releaseTicket(g, old)
			case "repeated_reset":
				entries, units := c.entries, c.weight
				for range 2 {
					g.resetCallerObjectExecutions()
					if g.objectExecutions != c || c.graph != nil || c.entries != entries || c.weight != units || c.active != 1 {
						t.Fatal("live metadata allocated a second namespace or lost B1 account")
					}
					callerAssertExecutionRetention(t, c, nil)
				}
				if g.callerTraceValid(chain) {
					t.Fatal("reset chain remained eligible")
				}
			case "cancel":
				cancelled, cancel := context.WithCancel(context.Background())
				cancel()
				g.ctx = cancelled
				hits, stores := g.work.ObjectTraceHits, g.work.ObjectTraceStores
				answer, unknown, _ := g.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
				if !unknown || len(answer) != 0 || g.work.ObjectTraceHits != hits || g.work.ObjectTraceStores != stores {
					t.Fatal("admitted cancellation replayed or published an answer")
				}
			}
			disabledEntries, disabledUnits := c.entries, c.weight
			if liveFrame != nil {
				delete(seen, liveID)
				g.callerTracePop(chain, liveFrame)
			}
			g.endCallerTrace(chain)
			if c.graph == nil && (c.entries != disabledEntries || c.weight != disabledUnits) {
				t.Fatal("B1 drain uncharged still-retained metadata")
			}
			callerAssertExecutionRetention(t, c, nil)
			if c.active != 0 {
				t.Fatal("real chain did not drain")
			}
			if mode == "repeated_reset" {
				g.resetCallerObjectExecutions()
				if g.objectExecutions == c || g.objectExecutions.entries != 0 || g.objectExecutions.weight != 0 {
					t.Fatal("idle reset failed to replace the single disabled account")
				}
			}
		})
	}
}

func TestCallerIdentityInteriorEffectfulAndFullBoundary(t *testing.T) {
	for _, full := range []bool{false, true} {
		name := "effectful_binding"
		if full {
			name = "full_mode"
		}
		t.Run(name, func(t *testing.T) {
			body := callerTraceDiamondBody(4) + "id:=func(v []Box)[]Box{return v};result:=id(x4);_=result"
			p := callerTraceTypedProgram(t, body)
			fast, _, refs := callerTraceTypedGraph(t, p, "x4")
			slow, _, _ := callerTraceTypedGraph(t, p, "x4")
			root := refs["result"]
			fast.ctx, slow.ctx = context.Background(), context.Background()
			slow.objectExecutions = nil
			fast.lifetimeScanning, slow.lifetimeScanning = !full, !full
			callRefs := fast.assignments[callerVariable(root.pkg, root.expr).Origin()]
			if len(callRefs) != 1 {
				t.Fatal("у результата вызова должен быть один источник")
			}
			if _, ok := callRefs[0].expr.(*ast.CallExpr); !ok {
				t.Fatal("источник результата должен быть вызовом")
			}
			fm, sm, epoch := callerReuseMarks(fast), callerReuseMarks(slow), fast.bindingEpoch
			got, unknown, _ := fast.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
			want, u, _ := slow.callerObjectsOwned(root, map[callerObjectSourceID]bool{})
			if unknown != u || !maps.Equal(got, want) || len(got) == 0 || callerReuseDelta(fast, fm) != callerReuseDelta(slow, sm) {
				t.Fatal("обход через границу изменил результат или логические счётчики")
			}
			if full {
				if fast.work.ObjectTraceHits != 0 || fast.work.ObjectTraceStores != 0 {
					t.Fatal("в полном режиме переиспользование трасс запрещено")
				}
			} else {
				if fast.bindingEpoch <= epoch {
					t.Fatal("не выполнено штатное связывание аргументов вызова")
				}
				rootID := fast.objectSourceIDs[callerResolveKeyFor(root, true)]
				callID := fast.objectSourceIDs[callerResolveKeyFor(callRefs[0], true)]
				if rootID == 0 || callID == 0 {
					t.Fatal("обход не дошёл до корня или вызова")
				}
				// Разрешены только дочерние трассы после связывания. Весь
				// effectful вызов и исходный запрос не могут стать записями кэша.
				for _, record := range callerUnlinkRecords(t, fast.objectExecutions) {
					if record.source == rootID || record.source == callID || record.guard.state.bindingEpoch != fast.bindingEpoch {
						t.Fatal("кэш захватил вызов или состояние из прежней эпохи")
					}
				}
			}
			callerAssertExecutionRetention(t, fast.objectExecutions, nil)
		})
	}
}
