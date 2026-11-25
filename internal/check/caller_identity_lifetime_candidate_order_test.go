// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Это малый свидетель порядка, а не воспроизведение стоимости full202.
// Оба тела горячего пути берутся из продукта без переписывания: callback с
// tuple-return в ruleVerbSet и range результата в expandedVerbSet. Только
// носители Rule/Role сокращены до читаемых этими телами полей; чтение личности
// находится в настоящем типизированном callback, замкнувшем Box.
func callerLifetimeOrderDeclarations(t *testing.T, file string, names ...string) string {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	fs := token.NewFileSet()
	parsed, err := parser.ParseFile(fs, file, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, decl := range parsed.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && slices.Contains(names, fn.Name.Name) {
			if _, duplicate := found[fn.Name.Name]; duplicate {
				t.Fatalf("неоднозначное тело %s", fn.Name.Name)
			}
			found[fn.Name.Name] = string(data[fs.Position(fn.Pos()).Offset:fs.Position(fn.End()).Offset])
		}
	}
	var out []string
	for _, name := range names {
		body, exists := found[name]
		if !exists {
			t.Fatalf("исчезло продуктовое тело %s", name)
		}
		out = append(out, body)
	}
	return strings.Join(out, "\n")
}

type callerLifetimeOrderImporter struct {
	local    callerFixtureImporter
	standard types.Importer
}

func (i callerLifetimeOrderImporter) Import(path string) (*types.Package, error) {
	if p := i.local[path]; p != nil {
		return p, nil
	}
	return i.standard.Import(path)
}

func callerLifetimeOrderProgram(t *testing.T, escape bool) (*surfaceProgram, valueSrc) {
	t.Helper()
	// Берём проверенные сервис/producer/external типы прежней typed-фикстуры.
	// Корень затем целиком перепроверяется с настоящим импортом strings.
	p := callerSoundnessProgram(t, "", "", "&Handler{}")
	imports := callerFixtureImporter{}
	for _, sp := range p.pkgs {
		imports[sp.path] = sp.types
	}
	mutation := "source.Mutate(other)"
	if escape {
		mutation = "source.Mutate(alias)"
	}
	source := `package main
import("strings";"fixture/service";"fixture/source";"github.com/PRO-Robotech/corelib/operations")
type Reader interface{read()}
type Concrete struct{}
func(Concrete)read(){operations.PrincipalFromContext()}
type Box struct{reader Reader}
type Handler struct{}
type Rule struct{Module string;Resources,Verbs []string}
type Role struct{Rules []Rule}
type TypeVerbLookup func(module,resource string)(verbs []string,ok bool)
func anchor(){operations.PrincipalFromContext()}
func lookupFor(box *Box)TypeVerbLookup{
 return func(module,resource string)([]string,bool){box.reader.read();return []string{module,resource},true}
}
func(h *Handler)RPC(){
 anchor()
 box:=&Box{reader:Concrete{}}
 other:=&Box{reader:Concrete{}}
 _=other
 alias:=box
 _=alias
 ` + mutation + `
 lookup:=lookupFor(box)
 role:=Role{Rules:[]Rule{{Module:"fixture",Resources:[]string{"one","two"},Verbs:[]string{"*"}}}}
 verbs,_:=role.expandedVerbSet(lookup)
 _=verbs
}
func main(){service.RegisterFixtureServiceServer(nil,&Handler{})}
` + callerLifetimeOrderDeclarations(t, "../domain/role_effective_verbs.go", "ruleVerbSet", "expandedVerbSet") + "\n" +
		callerLifetimeOrderDeclarations(t, "../domain/rule_verbs.go", "NormalizeVerb")
	file, err := parser.ParseFile(p.fset, "fixture/app/lifetime_order.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}, Implicits: map[ast.Node]types.Object{}, Instances: map[*ast.Ident]types.Instance{}}
	pkg, err := (&types.Config{Importer: callerLifetimeOrderImporter{imports, importer.Default()}}).Check("fixture/app", p.fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatal(err)
	}
	old := p.root
	p.root = &surfaceSrcPkg{path: "fixture/app", types: pkg, files: []*ast.File{file}, info: info, own: true, root: true}
	p.byPath[p.root.path] = p.root
	for i, sp := range p.pkgs {
		if sp == old {
			p.pkgs[i] = p.root
		}
	}
	// Проба базового allocation не подменяет lifetimeScanning или Err.
	var base valueSrc
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "RPC" {
			continue
		}
		var allocation *types.Var
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "box" {
				if declared, ok := info.Defs[id].(*types.Var); ok {
					allocation = declared
				}
			}
			return true
		})
		// Берём существующее чтение именно объявленного box на настоящем
		// ребре lookupFor(box), а не AST объявления и не одноимённый параметр.
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			target := callerFunction(p.root, call.Fun)
			if target == nil || target.Name() != "lookupFor" {
				return true
			}
			use, ok := call.Args[0].(*ast.Ident)
			if ok && allocation != nil && info.Uses[use] == allocation {
				base = valueSrc{pkg: p.root, fk: fkey{fn: info.Defs[fn.Name].(*types.Func)}, expr: use, tuple: -1}
			}
			return true
		})
	}
	if base.expr == nil {
		t.Fatal("нет настоящего allocation box")
	}
	t.Cleanup(func() { callerGraphs.Delete(p) })
	return p, base
}

type callerLifetimeOrderObservation struct {
	origins                                              []callerOrigin
	unknown, lifetimeUnknown                             bool
	marks                                                [4]uint64
	negative, declared                                   CallerIdentityReport
	objectRaw, resolveRaw, lifetimeSteps, traceEvictions int
}

// Новый mutable view строит штатный callerGraphFor. Два списка отличаются
// только порядком; тело кандидата, его fk/pkg/AST и кратность не меняются.
func callerLifetimeOrderObserve(t *testing.T, p *surfaceProgram, base valueSrc, candidates []callSrc, escape bool) callerLifetimeOrderObservation {
	t.Helper()
	original, exists := callerGraphs.Load(p)
	if !exists {
		t.Fatal("нет собственного базового графа")
	}
	// Копируем один уже собранный граф: порядок остальных индексов одинаков.
	// Обнуляются только вычисляемые pure/MAY memo, чтобы первый порядок не
	// прогрел второй. Никаких готовых ответов или ложных proof сюда не кладём.
	isolated := *original.(*callerGraphMemo).graph
	isolated.pure = &callerPureMemo{potential: map[callerPotentialKey][]callerNode{}, signatures: map[callerSignaturePair]bool{}}
	isolated.mayMemo = &callerMayMemo{}
	memo := &callerGraphMemo{}
	memo.once.Do(func() { memo.graph = &isolated })
	callerGraphs.Store(p, memo)
	defer callerGraphs.Store(p, original)
	g := callerGraphFor(p, nil)
	g.ctx = context.Background()
	g.safeExternal = map[string]bool{"fixture/source": true, "strings": true}
	g.lifetimeCalls = slices.Clone(candidates)
	g.markCallerCalled(callerNode{fn: base.fk.fn})
	g.closeCallerEffects()
	if g.effectIncomplete || g.analysisErr != nil || g.semanticOverflow {
		t.Fatal("эффекты типизированной фикстуры не замкнулись")
	}
	for _, name := range []string{"lookupFor", "ruleVerbSet", "expandedVerbSet"} {
		reached := false
		for node := range g.called {
			reached = reached || node.fn != nil && node.fn.Name() == name
		}
		if !reached {
			t.Fatalf("не достигнут настоящий callback/return путь %s", name)
		}
	}
	before, marks := g.work, callerReuseMarks(g)
	lifetimeUnknown := g.callerLifetimeUnknown(base)
	// Oracle ниже проверяет сам Box как receiver, а не раскрытие его полей.
	values, unknown := g.resolve(base, true, map[callerResolveKey]bool{})
	if lifetimeUnknown != escape || g.lifetimeScanning || g.effectScanning || len(g.fieldQueries) != 0 {
		t.Fatalf("lifetime: unknown=%v, escape=%v; незакрытые границы", lifetimeUnknown, escape)
	}
	if len(values) != 1 || unknown || values[0].foreign || values[0].nilValue || namedOf(values[0].typ) == nil || namedOf(values[0].typ).Obj().Name() != "Box" {
		t.Fatal("потеряно единственное явное происхождение allocation Box")
	}
	if g.work.LifetimeProofs <= before.LifetimeProofs || g.work.LifetimeProbeSteps <= before.LifetimeProbeSteps || g.work.ObjectRawEvaluations <= before.ObjectRawEvaluations {
		t.Fatal("наблюдение не исполнило настоящий lifetime/raw путь")
	}
	observation := callerLifetimeOrderObservation{origins: slices.Clone(values), unknown: unknown, lifetimeUnknown: lifetimeUnknown, marks: callerReuseDelta(g, marks),
		objectRaw: g.work.ObjectRawEvaluations - before.ObjectRawEvaluations, resolveRaw: g.work.ResolveEvaluations - before.ResolveEvaluations,
		lifetimeSteps: g.work.LifetimeProbeSteps - before.LifetimeProbeSteps, traceEvictions: g.work.ObjectTraceEvictions - before.ObjectTraceEvictions}
	// Только базовый граф ЭТОЙ пробы получает перестановку. Judge сам создаёт
	// свой mutable view; callbacks, допуск, бюджет и proof не переопределяются.
	cached, exists := callerGraphs.Load(p)
	if !exists {
		t.Fatal("исчез собственный разобранный граф")
	}
	entry := cached.(*callerGraphMemo)
	previous := entry.graph.lifetimeCalls
	entry.graph.lifetimeCalls = slices.Clone(candidates)
	defer func() { entry.graph.lifetimeCalls = previous }()
	const rpc = "fixture/service/FixtureService/RPC"
	const producer = "github.com/PRO-Robotech/corelib/operations.PrincipalFromContext"
	declarations := []CallerReadDeclaration{{RPC: rpc, Producer: producer, Site: "fixture/app.anchor", Kind: CallerObservation, Reason: "Непустой реальный корень фикстуры."}}
	observation.negative = judgeCallerIdentity(p, declarations, g.safeExternal)
	declarations = append(declarations, CallerReadDeclaration{RPC: rpc, Producer: producer, Site: "(fixture/app.Concrete).read", Kind: CallerObservation, Reason: "То же callback-чтение; изменено только объявление."})
	observation.declared = judgeCallerIdentity(p, declarations, g.safeExternal)
	for _, report := range []CallerIdentityReport{observation.negative, observation.declared} {
		if report.Invalid != "" || report.RPCs != 1 {
			t.Fatalf("judge не исполнился над одним настоящим RPC: %+v", report)
		}
	}
	if !escape {
		var coordinate string
		for _, read := range observation.negative.Reads {
			if read.Site == "(fixture/app.Concrete).read" {
				coordinate = read.Coordinate
			}
		}
		if coordinate == "" || len(observation.negative.Findings) != 1 || !strings.Contains(observation.negative.Findings[0], "чтение личности без объявления") || !strings.Contains(observation.negative.Findings[0], coordinate) {
			t.Fatalf("нет точного undeclared callback-reader отказа: %+v", observation.negative)
		}
		if len(observation.declared.Findings) != 0 || !reflect.DeepEqual(observation.negative.Reads, observation.declared.Reads) {
			t.Fatalf("lawful declaration twin не молчит: %+v", observation.declared)
		}
	} else {
		refused := false
		for _, finding := range observation.declared.Findings {
			refused = refused || strings.Contains(finding, "неразрешённый")
		}
		if !refused {
			t.Fatalf("объявление reader скрыло настоящий alias escape: %+v", observation.declared)
		}
	}
	t.Logf("кандидатов=%d lifetimeSteps=%d objectRaw=%d resolveRaw=%d traceEvictions=%d marks=%v", len(candidates), g.work.LifetimeProbeSteps-before.LifetimeProbeSteps, g.work.ObjectRawEvaluations-before.ObjectRawEvaluations, g.work.ResolveEvaluations-before.ResolveEvaluations, g.work.ObjectTraceEvictions-before.ObjectTraceEvictions, observation.marks)
	return observation
}

func TestCallerIdentityLifetimeCandidateOrderKeepsCallbackContract(t *testing.T) {
	for _, scene := range []struct {
		name   string
		escape bool
	}{{"lawful", false}, {"alias_escape", true}} {
		t.Run(scene.name, func(t *testing.T) {
			p, base := callerLifetimeOrderProgram(t, scene.escape)
			graph := callerGraphFor(p, nil)
			forward := slices.Clone(graph.lifetimeCalls)
			// Канонические координаты задают обе перестановки независимо от map order.
			slices.SortFunc(forward, func(a, b callSrc) int {
				if cmp := strings.Compare(a.pkg.path, b.pkg.path); cmp != 0 {
					return cmp
				}
				if a.call.Pos() < b.call.Pos() {
					return -1
				}
				if a.call.Pos() > b.call.Pos() {
					return 1
				}
				return 0
			})
			reverse := slices.Clone(forward)
			slices.Reverse(reverse)
			inventory := func(calls []callSrc) map[callSrc]int {
				out := map[callSrc]int{}
				for _, call := range calls {
					out[call]++
				}
				return out
			}
			if len(forward) < 2 || slices.Equal(forward, reverse) || !maps.Equal(inventory(graph.lifetimeCalls), inventory(forward)) || !maps.Equal(inventory(forward), inventory(reverse)) {
				t.Fatal("не две перестановки полного исходного набора кандидатов")
			}
			var observations []callerLifetimeOrderObservation
			for _, order := range []struct {
				name  string
				calls []callSrc
			}{{"forward", forward}, {"reverse", reverse}} {
				t.Run(order.name, func(t *testing.T) {
					observations = append(observations, callerLifetimeOrderObserve(t, p, base, order.calls, scene.escape))
				})
			}
			if len(observations) != 2 {
				t.Fatal("оба порядка должны реально завершить наблюдение")
			}
			a, b := observations[0], observations[1]
			// Ранний escape меняет префикс обхода; счётчики остаются диагностикой и предметом отдельных reuse-controls.
			if !slices.Equal(a.origins, b.origins) || a.unknown != b.unknown || a.lifetimeUnknown != b.lifetimeUnknown || !slices.Equal(a.negative.Findings, b.negative.Findings) || !slices.Equal(a.declared.Findings, b.declared.Findings) || !reflect.DeepEqual(a.negative.Reads, b.negative.Reads) || !reflect.DeepEqual(a.declared.Reads, b.declared.Reads) {
				t.Fatal("перестановка кандидатов изменила origins/unknown/отказы/популяцию reader")
			}
			// Разницу работы измеряем, не выдаём любое отличие или его отсутствие
			// за доказанную причину full202 и не выбираем более удобный порядок.
			t.Logf("порядки: forward objectRaw=%d resolveRaw=%d; reverse objectRaw=%d resolveRaw=%d", a.objectRaw, a.resolveRaw, b.objectRaw, b.resolveRaw)
		})
	}
}
