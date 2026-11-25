// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"strings"
	"testing"
)

// Наблюдаемый self-cycle не получает искусственного allocation anchor.
// Отдельность проверяется только для чужого конкретного места выделения.
func TestCallerIdentityLocalAppendBackingDisjoint(t *testing.T) {
	for _, tc := range []struct {
		name, allocation string
	}{
		{"struct", `Carrier{}`},
		{"nested_struct", `Carrier{Nested:Nested{Values:[]any{}}}`},
		{"slice", `[]any{}`},
		{"array", `[1]any{}`},
		{"map", `map[string]any{}`},
		{"make_slice", `make([]any,0)`},
		{"make_map", `make(map[string]any)`},
		{"make_chan", `make(chan any)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program := callerSoundnessProgram(t, `type Nested struct{Values []any};type Carrier struct{Value any;Nested Nested}
type path []any
func build()path{var out path;out=append(out,source.Value());return out}`, `anchor:=&Box{};candidate:=`+tc.allocation+`;_=anchor;_=candidate;_=build()`, `&Handler{}`)
			var marks [2][4]uint64
			for mode := range 2 {
				g, query, wanted, allocation, write := callerLocalAppendFixture(t, program)
				g.ctx = context.Background()
				if mode == 0 {
					g.resetCallerObjectExecutions()
					if g.objectExecutions == nil || g.objectExecutions.graph != g || !callerFreshReplayContext(g.ctx) || !g.lifetimeScanning {
						t.Fatal("не подготовлен реальный execution namespace")
					}
				} else if g.objectExecutions != nil {
					t.Fatal("raw контроль неожиданно получил execution namespace")
				}
				owners, unknown := g.callerObjects(write.owner, map[callerObjectSourceID]bool{})
				if !unknown || owners[allocation] {
					t.Fatal("фикстура потеряла исходный неразрешённый self-cycle")
				}
				before := maps.Clone(owners)
				g.callerObjects(write.owner, map[callerObjectSourceID]bool{})
				hits, queries, raw := g.work.ObjectExecutionHits, g.work.ObjectExecutionQueries, g.work.ObjectRawEvaluations
				repeated, repeatedUnknown := g.callerObjects(write.owner, map[callerObjectSourceID]bool{})
				if repeatedUnknown != unknown || !maps.Equal(repeated, before) || !maps.Equal(owners, before) {
					t.Fatal("повтор изменил UNKNOWN или immutable provenance")
				}
				if mode == 0 {
					if g.work.ObjectExecutionHits != hits+1 || g.work.ObjectExecutionQueries <= queries || g.work.ObjectRawEvaluations != raw {
						t.Fatal("reuse режим не исполнил настоящий fresh replay")
					}
				} else if g.work.ObjectExecutionQueries != 0 || g.work.ObjectExecutionHits != 0 || g.work.ObjectRawEvaluations <= raw {
					t.Fatal("raw контроль не исполнил исходный resolver")
				}
				probe := callerLifetimeProbe{g: g, want: wanted, seen: map[callerResolveKey]bool{}, objects: map[callerObjectKey]bool{}}
				if !probe.separateLocalAppendBacking(write, allocation) || probe.contains(query) {
					t.Fatal("self-append чужого nil builder загрязнил отдельное выделение")
				}
				marks[mode] = callerReuseMarks(g)
				// Выключаем только новую лемму: та же фикстура обязана воспроизвести
				// baseline false alias, а не пройти из-за отсутствующего пути.
				variable := callerVariable(write.owner.pkg, write.owner.expr)
				g.localAppendBuilders[variable] = false
				if !probe.contains(query) {
					t.Fatal("контроль без леммы не воспроизвёл исходный ложный alias")
				}
				g.localAppendBuilders[variable] = true
				probe.want = allocation
				if !probe.contains(query) {
					t.Fatal("потеряна собственная identity выделения")
				}
				probe.want = wanted
				g.semanticOverflow = true
				if probe.separateLocalAppendBacking(write, allocation) || !probe.contains(query) {
					t.Fatal("переполнение стало доказательством отдельности")
				}
				g.semanticOverflow = false
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				g.ctx = ctx
				if probe.separateLocalAppendBacking(write, allocation) || !probe.contains(query) {
					t.Fatal("отмена стала доказательством отдельности")
				}
				g.ctx = context.Background()
				probe.steps = callerLifetimeStepLimit + 1
				if probe.separateLocalAppendBacking(write, allocation) || !probe.contains(query) {
					t.Fatal("лимит стал доказательством отдельности")
				}
				// Даже при наличии source certificate положительный ответ owners
				// имеет приоритет. Вводим оба ответа через штатные live bindings.
				g.addCallerLive(variable, query)
				g.addCallerLive(variable, write.value)
				owners, unknown = g.callerObjects(write.owner, map[callerObjectSourceID]bool{})
				if !unknown || !owners[allocation] {
					t.Fatal("контроль не создал одновременно known owner и unknown")
				}
				matched := callerLifetimeProbe{g: g, want: wanted, seen: map[callerResolveKey]bool{}, objects: map[callerObjectKey]bool{}}
				if !matched.objectWrites(allocation) {
					t.Fatal("лемма подавила положительное совпадение owners")
				}
			}
			if marks[0] != marks[1] {
				t.Fatal("raw/reuse изменил четыре semantic marks")
			}
		})
	}
}

func TestCallerIdentityLocalAppendBuilderBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, setup string
		want        bool
	}{
		{"nil_self", `func build()[]any{var out []any;out=append(out,source.Value());return out}`, true},
		{"loop", `func build()[]any{var out []any;for i:=0;i<3;i++{out=append(out,source.Value())};return out}`, true},
		{"spread_other", `func build()[]any{var out []any;out=append(out,source.Value().([]any)...);return out}`, true},
		{"return_variadic_value", `func collect(xs ...any)[]any{return xs};func build()[]any{var out []any;out=append(out,source.Value());return collect(out...)}`, true},
		{"fixed_and_spread", `func collect(label string,xs ...any)[]any{return xs};func build()[]any{var out []any;out=append(out,source.Value());kept:=collect("x",out...);return kept}`, true},
		{"fixed_slice", `func bind(xs []any)[]any{return xs};func build()[]any{var out []any;out=append(out,source.Value());kept:=bind(out);return kept}`, true},
		{"conditional_len_join", `func join(xs []string,sep string)string{return sep};func build()string{var out []string;out=append(out,source.Value().(string));if len(out)==0 || cap(out)==0{return ""};return join(out,",")}`, true},
		{"typed_call_rebind", `func replace(xs []any)[]any{return source.Value().([]any)};func build()[]any{var out []any;out=append(out,source.Value());out=replace(out);return out}`, false},
		{"typed_call_capture", `func build()[]any{var out []any;out=append(out,source.Value());return (func(xs []any)[]any{out=source.Value().([]any);return xs})(out)}`, false},
		{"variadic_boxing", `func collect(xs ...any){};func build()[]any{var out []any;out=append(out,source.Value());collect(out);return out}`, false},
		{"return_variadic_capture", `func build()[]any{var out []any;out=append(out,source.Value());return (func(xs ...any)[]any{out=source.Value().([]any);return xs})(out...)}`, false},
		{"initial_backing", `func build()[]any{out:=make([]any,0,4);out=append(out,source.Value());return out}`, false},
		{"rebind", `func build()[]any{var out []any;out=source.Value().([]any);out=append(out,source.Value());return out}`, false},
		{"copied_alias", `func build()[]any{var out []any;out=append(out,source.Value());alias:=out;_=alias;return out}`, false},
		{"shared_alias", `var shared []any;func build()[]any{var out []any;out=append(out,source.Value());shared=out;return out}`, false},
		{"capture", `func build()[]any{var out []any;out=append(out,source.Value());_=func(){_=out};return out}`, false},
		{"capture_self_append", `func build()[]any{var out []any;out=append(out,source.Value());_=func(){out=append(out,source.Value())};return out}`, false},
		{"address_escape", `func build()[]any{var out []any;out=append(out,source.Value());source.Mutate(&out);return out}`, false},
		{"opaque_escape", `func build()[]any{var out []any;out=append(out,source.Value());source.Mutate(out);return out}`, false},
		{"pointer_method", `type path []any;func(p *path)touch(){};func build()path{var out path;out=append(out,source.Value());out.touch();return out}`, false},
		{"range", `func build()[]any{var out []any;out=append(out,source.Value());for range out{};return out}`, false},
		{"projection", `func build()[]any{var out []any;out=append(out,source.Value());_=out[0];return out}`, false},
		{"copy", `func build()[]any{var out []any;out=append(out,source.Value());copy(out,[]any{source.Value()});return out}`, false},
		{"self_spread", `func build()[]any{var out []any;out=append(out,source.Value());out=append(out,out...);return out}`, false},
		{"shadowed_builtin", `func build()[]any{var out []any;append:=func(s []any,v any)[]any{return s};out=append(out,source.Value());return out}`, false},
		{"parameter", `func build(out []any)[]any{out=append(out,source.Value());return out}`, false},
		{"package_variable", `var out []any;func build()[]any{out=append(out,source.Value());return out}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program := callerSoundnessProgram(t, tc.setup, `anchor:=&Box{};candidate:=[]any{};_=anchor;_=candidate`, `&Handler{}`)
			g, _, wanted, allocation, write := callerLocalAppendFixture(t, program)
			probe := callerLifetimeProbe{g: g, want: wanted}
			if got := probe.separateLocalAppendBacking(write, allocation); got != tc.want {
				t.Fatalf("доказательство=%t want=%t", got, tc.want)
			}
			if tc.want {
				for _, key := range []callerObjectKey{{pkg: allocation.pkg, zero: callerVariable(write.owner.pkg, write.owner.expr)}, {pkg: allocation.pkg, expr: write.value.expr}} {
					if probe.separateLocalAppendBacking(write, key) {
						t.Fatal("неизвестный/zero ключ принят как конкретное выделение")
					}
				}
			}
		})
	}
}

// Чужие объявления не расходуют лимит доказательства локального среза.
func TestCallerIdentityLocalAppendLargePackage(t *testing.T) {
	unrelated := "func unrelated(x int) {\n" + strings.Repeat("_ = x\n", callerLifetimeStepLimit+1) + "}"
	for _, tc := range []struct {
		name, extra string
		want        bool
	}{
		{"local", "", true},
		{"closure_capture", "_ = func() { out = source.Value().([]any) };", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setup := unrelated + `
func collect(xs ...any) []any { return xs }
func build() []any {
	var out []any
	for i := 0; i < 2; i++ { out = append(out, source.Value()) }
	` + tc.extra + ` return collect(out...)
}
`
			program := callerSoundnessProgram(t, setup, `anchor:=&Box{};candidate:=[]any{};_=anchor;_=candidate`, `&Handler{}`)
			if len(program.root.info.Uses) <= callerLifetimeStepLimit {
				t.Fatal("фикстура не превысила размер пакета")
			}
			g, _, wanted, allocation, write := callerLocalAppendFixture(t, program)
			probe := callerLifetimeProbe{g: g, want: wanted}
			if got := probe.separateLocalAppendBacking(write, allocation); got != tc.want {
				t.Fatalf("доказательство=%t want=%t", got, tc.want)
			}
		})
	}
}

// Содержимое builder и алиасы по-прежнему доступны обычному contains.
func TestCallerIdentityLocalAppendContentsRemainVisible(t *testing.T) {
	for _, tc := range []struct{ name, expression, prefix string }{
		{"returned_builder", `build(anchor)`, ``},
		{"returned_variadic_builder", `buildVariadic(anchor)`, ``},
		{"fixed_argument_alias", `buildFixed(anchor)`, ``},
		{"direct_nil", `append([]*Box(nil),anchor)`, ``},
		{"base_alias", `append([]*Box{anchor},nil)`, ``},
		{"spread", `append([]*Box(nil),[]*Box{anchor}...)`, ``},
		{"spread_alias", `append([]*Box(nil),copied...)`, `shared:=[]*Box{anchor};copied:=shared;`},
		{"shared_write", `shared`, `shared:=make([]*Box,1);alias:=shared;alias[0]=anchor;`},
		{"copied_alias", `copied`, `shared:=[]*Box{anchor};copied:=shared;`},
		{"opaque_owner", `opaque`, `opaque:=source.Value().([]*Box);opaque[0]=anchor;`},
		{"direct_field", `Carrier{Value:anchor}`, ``},
		{"backing_field", `Carrier{Value:[]*Box{anchor}}`, ``},
		{"opaque_field", `Carrier{Value:source.Value()}`, ``},
		{"unsafe_integer", `Carrier{Value:source.Value().(uintptr)}`, ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program := callerSoundnessProgram(t, `type Carrier struct{Value any};func build(v *Box)[]*Box{var out []*Box;out=append(out,v);return out};func bind(xs []*Box)[]*Box{return xs};func buildFixed(v *Box)[]*Box{var out []*Box;out=append(out,v);held:=bind(out);return held};func pass(xs ...*Box)[]*Box{return xs};func buildVariadic(v *Box)[]*Box{var out []*Box;out=append(out,v);return pass(out...)}`, `anchor:=&Box{};`+tc.prefix+`candidate:=`+tc.expression+`;_=anchor;_=candidate`, `&Handler{}`)
			g, query, wanted, _, _ := callerLocalAppendFixture(t, program)
			probe := callerLifetimeProbe{g: g, want: wanted, seen: map[callerResolveKey]bool{}, objects: map[callerObjectKey]bool{}}
			if !probe.contains(query) {
				t.Fatal("содержимое/alias исчезло после доказательства отдельности чужой памяти")
			}
		})
	}
}

func TestCallerIdentityLocalAppendAllocationBoundary(t *testing.T) {
	for _, tc := range []struct{ name, setup, expression string }{
		{"append_result", ``, `append([]any(nil),source.Value())`},
		{"conversion", ``, `[]any(nil)`},
		{"returned_alias", `func same(v []any)[]any{return v}`, `same([]any{})`},
		{"opaque", ``, `source.Value()`},
		{"new", ``, `new(Box)`},
		{"shadowed_make", `func make()[]any{return nil}`, `make()`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program := callerSoundnessProgram(t, tc.setup+`
func build()[]any{var out []any;out=append(out,source.Value());return out}`, `anchor:=&Box{};candidate:=`+tc.expression+`;_=anchor;_=candidate`, `&Handler{}`)
			g, _, wanted, key, write := callerLocalAppendFixture(t, program)
			probe := callerLifetimeProbe{g: g, want: wanted}
			if probe.separateLocalAppendBacking(write, key) {
				t.Fatal("неподтверждённый ключ принят как отдельное выделение")
			}
			field := wanted.pkg.info.TypeOf(wanted.expr).Underlying().(*types.Struct).Field(0)
			withField := wanted
			withField.field = field
			if probe.separateLocalAppendBacking(write, withField) {
				t.Fatal("проекция поля принята как целое выделение")
			}
			whole := write
			whole.whole = true
			if probe.separateLocalAppendBacking(whole, wanted) {
				t.Fatal("whole store потерял прежний барьер")
			}
		})
	}
}

func TestCallerIdentityLocalAppendCopyAndUnsafe(t *testing.T) {
	program := callerSoundnessProgram(t, `func build()[]any{var out []any;out=append(out,source.Value());return out}`, `anchor:=&Box{};candidate:=make([]*Box,1);copy(candidate,[]*Box{anchor});_=anchor;_=candidate`, `&Handler{}`)
	g, _, wanted, _, _ := callerLocalAppendFixture(t, program)
	found := false
	for _, site := range g.lifetimeCalls {
		id, ok := site.call.Fun.(*ast.Ident)
		if !ok || id.Name != "copy" || site.pkg != program.root {
			continue
		}
		found = true
		if g.callerLifetimeLocal(site) {
			t.Fatal("copy потерял прежний непрозрачный lifetime barrier")
		}
		probe := callerLifetimeProbe{g: g, want: wanted, seen: map[callerResolveKey]bool{}, objects: map[callerObjectKey]bool{}}
		if !probe.contains(valueSrc{pkg: site.pkg, fk: site.fk, expr: site.call.Args[1], tuple: -1}) {
			t.Fatal("opaque copy больше не видит переданный alias")
		}
	}
	if !found {
		t.Fatal("не найден реальный copy")
	}
	for _, tc := range []struct {
		name, extra string
		closed      bool
	}{
		{"unsafe_content", ``, true},
		{"unsafe_owner_escape", `_=unsafe.Pointer(&out);`, false},
		{"unsafe_slice_data", `_=unsafe.SliceData(out);`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "fixture.go", `package fixture
import "unsafe"
type Box struct{Value any}
func build()[]any{var out []any;out=append(out,nil);`+tc.extra+`return out}
func RPC(){anchor:=&Box{};candidate:=unsafe.Pointer(anchor);_=candidate;_=build()}`, 0)
			if err != nil {
				t.Fatal(err)
			}
			info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}, Implicits: map[ast.Node]types.Object{}, Instances: map[*ast.Ident]types.Instance{}}
			pkg, err := (&types.Config{Importer: callerFixtureImporter{"unsafe": types.Unsafe}}).Check("fixture", fset, []*ast.File{file}, info)
			if err != nil {
				t.Fatal(err)
			}
			sp := &surfaceSrcPkg{path: "fixture", types: pkg, files: []*ast.File{file}, info: info, own: true, root: true}
			program := &surfaceProgram{fset: fset, root: sp, pkgs: []*surfaceSrcPkg{sp}, byPath: map[string]*surfaceSrcPkg{"fixture": sp}}
			g, query, wanted, unknown, write := callerLocalAppendFixture(t, program)
			probe := callerLifetimeProbe{g: g, want: wanted, seen: map[callerResolveKey]bool{}, objects: map[callerObjectKey]bool{}}
			if probe.separateLocalAppendBacking(write, unknown) {
				t.Fatal("unsafe conversion принята за выделение")
			}
			if got := probe.separateLocalAppendBacking(write, wanted); got != tc.closed {
				t.Fatalf("закрытость unsafe owner=%t want=%t", got, tc.closed)
			}
			if !probe.contains(query) {
				t.Fatal("unsafe alias исчез из обычного contains")
			}
		})
	}
}

func callerLocalAppendFixture(t *testing.T, program *surfaceProgram) (*callerGraph, valueSrc, callerObjectKey, callerObjectKey, callerLifetimeWrite) {
	t.Helper()
	g := newCallerGraph(program)
	g.safeExternal = map[string]bool{"fixture/source": true}
	g.lifetimeScanning = true
	var query valueSrc
	var wanted, allocation callerObjectKey
	var write callerLifetimeWrite
	for node, body := range g.bodies {
		if body.sp != program.root || node.fn == nil || node.fn.Name() != "RPC" && node.fn.Name() != "build" {
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
			if node.fn.Name() == "build" && id.Name == "out" {
				if call, ok := assignment.Rhs[0].(*ast.CallExpr); ok && len(call.Args) > 1 {
					// Shadowed append тоже получает точный owner для проверки отказа;
					// это не подмена production inventory в тестах contains.
					write = callerLifetimeWrite{owner: valueSrc{pkg: body.sp, fk: callerKey(node), expr: call.Args[0], tuple: -1}, value: valueSrc{pkg: body.sp, fk: callerKey(node), expr: call.Args[1], tuple: -1}}
				}
			}
			return true
		})
	}
	if query.expr == nil || wanted.expr == nil || write.owner.expr == nil {
		t.Fatal("неполная типизированная фикстура")
	}
	return g, query, wanted, allocation, write
}
