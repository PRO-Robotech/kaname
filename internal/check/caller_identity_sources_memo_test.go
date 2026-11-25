// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestCallerIdentitySourcesMemoOrderAndLiveEpoch(t *testing.T) {
	p := callerSoundnessProgram(t, "", `child:=&Box{};other:=&Box{};alias:=child;alias=child;_=alias;_=other`, `&Handler{}`)
	g, refs := newCallerGraph(p), callerOwnershipSources(p)
	v := callerVariable(p.root, refs["alias"].expr)
	want := g.sourcesRaw(v)
	cold := g.sources(v)
	before := slices.Clone(cold)
	work := g.work
	warm := g.sources(v)
	if len(warm) == 0 || !reflect.DeepEqual(cold, want) || !reflect.DeepEqual(warm, want) || &warm[0] != &cold[0] || g.work != work {
		t.Fatal("полный упорядоченный синтаксический ответ не переиспользован без изменения WORK")
	}
	// Компактный снимок не предоставляет вызывающему запас backing array.
	if cap(warm) != len(warm) {
		t.Fatal("memo удерживает лишнюю ёмкость синтаксического списка")
	}
	appended := append(warm, refs["other"])
	if &appended[0] == &warm[0] {
		t.Fatal("append не отделил принадлежащий вызывающему срез")
	}
	appended[0] = refs["other"]
	if !reflect.DeepEqual(warm, before) || !reflect.DeepEqual(g.sources(v), before) {
		t.Fatal("запись в append-результат изменила заимствованный ответ")
	}
	epoch := g.bindingEpoch
	g.addCallerLive(v, refs["other"])
	changed := g.sources(v)
	if g.bindingEpoch == epoch || !reflect.DeepEqual(changed, g.sourcesRaw(v)) || !slices.Contains(changed, refs["other"]) || !reflect.DeepEqual(cold, before) {
		t.Fatal("live alias не инвалидировал ответ либо изменил старый снимок")
	}
	g.addCallerLive(v, refs["other"])
	if &g.sources(v)[0] != &changed[0] {
		t.Fatal("дублирующий live источник создал новую эпоху")
	}
}

func TestCallerIdentitySourcesMemoFallbackAndVariadicBindings(t *testing.T) {
	p := callerSoundnessProgram(t, `func relay(input *Box,items ...*Box){_=input;_=items}`, `child:=&Box{};other:=&Box{};relay(child,other);relay(child)`, `&Handler{}`)
	g, refs := newCallerGraph(p), callerOwnershipSources(p)
	input, items := callerVariable(p.root, refs["input"].expr), callerVariable(p.root, refs["items"].expr)
	for _, v := range []*types.Var{input, items} {
		want := g.sourcesRaw(v)
		if len(want) == 0 || !reflect.DeepEqual(g.sources(v), want) || !reflect.DeepEqual(g.sources(v), want) {
			t.Fatal("static call-argument fallback потерян до live binding")
		}
	}
	var emptyCall, fullCall *ast.CallExpr
	fn := p.root.types.Scope().Lookup("relay").(*types.Func)
	for _, body := range g.bodies {
		ast.Inspect(body.node, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && callerFunction(body.sp, call.Fun) == fn {
				if len(call.Args) == 1 {
					emptyCall = call
				} else {
					fullCall = call
				}
			}
			return true
		})
	}
	if emptyCall == nil || fullCall == nil {
		t.Fatal("не найдены реальные вызовы variadic")
	}
	g.bindCaller(p.root, callerNode{}, emptyCall, callerNode{fn: fn})
	if !g.emptyVariadic[items.Origin()] || g.sources(items) != nil || g.sourcesRaw(items) != nil {
		t.Fatal("пустой variadic binding не убрал static fallback либо nil превратился в пустой non-nil")
	}
	g.bindCaller(p.root, callerNode{}, fullCall, callerNode{fn: fn})
	got := g.sources(items)
	if len(got) != 1 || !reflect.DeepEqual(got, g.sourcesRaw(items)) || got[0].expr != fullCall.Args[1] {
		t.Fatal("новый live variadic источник скрыт ранее закэшированным пустым ответом")
	}
}

func TestCallerIdentitySourcesMemoCapacityReturnsCompleteRaw(t *testing.T) {
	for _, bound := range []string{"entries", "values"} {
		t.Run(bound, func(t *testing.T) {
			p := callerSoundnessProgram(t, "", `child:=&Box{};alias:=child;_=alias`, `&Handler{}`)
			g, refs := newCallerGraph(p), callerOwnershipSources(p)
			if bound == "entries" {
				for i := 0; i < callerSourceMemoEntryLimit; i++ {
					v := types.NewVar(token.NoPos, nil, "empty", types.Typ[types.Int])
					if g.sources(v) != nil {
						t.Fatal("пустой синтаксический источник изменился")
					}
				}
			} else {
				v := types.NewVar(token.NoPos, nil, "many", types.Typ[types.Int])
				for i := 0; i < callerSourceMemoValueLimit; i++ {
					ref := refs["child"]
					ref.tuple = i
					g.assignments[v] = append(g.assignments[v], ref)
				}
				if len(g.sources(v)) != callerSourceMemoValueLimit {
					t.Fatal("не создано насыщение веса")
				}
			}
			v := callerVariable(p.root, refs["alias"].expr)
			want, count, weight := g.sourcesRaw(v), len(g.sourceMemo), g.sourceMemoWeight
			for i := 0; i < 2; i++ {
				if !reflect.DeepEqual(g.sources(v), want) {
					t.Fatal("capacity превратила полный ответ в частичный")
				}
			}
			if _, retained := g.sourceMemo[v.Origin()]; retained || len(g.sourceMemo) != count || g.sourceMemoWeight != weight {
				t.Fatal("превышен предел удерживаемых синтаксических источников")
			}
		})
	}
}

func TestCallerIdentitySourcesMemoWarmObjectCutsUnchanged(t *testing.T) {
	for _, mode := range []bool{false, true} {
		for _, name := range []string{"cycle", "hollow", "opaque"} {
			p := callerSoundnessProgram(t, "", `anchor:=&Box{};var cycle *Box;cycle=anchor;cycle=cycle;var hollow *Box;hollow=hollow;opaque:=source.Value();_=cycle;_=hollow;_=opaque`, `&Handler{}`)
			cold, warm := newCallerGraph(p), newCallerGraph(p)
			refs := callerOwnershipSources(p)
			for _, ref := range refs {
				v := callerVariable(p.root, ref.expr)
				warm.sources(v)
				warm.sources(v)
			}
			cold.safeExternal, warm.safeExternal = map[string]bool{"fixture/source": true}, map[string]bool{"fixture/source": true}
			cold.lifetimeScanning, warm.lifetimeScanning = mode, mode
			cold.work, warm.work = CallerIdentityWork{}, CallerIdentityWork{}
			a, au, ao := cold.callerObjectsOwned(refs[name], map[callerObjectSourceID]bool{})
			b, bu, bo := warm.callerObjectsOwned(refs[name], map[callerObjectSourceID]bool{})
			// Времена и отсортированный по времени ResolveSlowest не сравниваем.
			cw, ww := reflect.ValueOf(cold.work), reflect.ValueOf(warm.work)
			for i := 0; i < cw.NumField(); i++ {
				if cw.Field(i).Kind() == reflect.Int && cw.Field(i).Int() != ww.Field(i).Int() {
					t.Fatalf("%s initial=%v: изменён WORK %s", name, mode, cw.Type().Field(i).Name)
				}
			}
			if !maps.Equal(a, b) || au != bu || ao != bo || cold.resolveCuts != warm.resolveCuts || cold.objectCuts != warm.objectCuts || cold.initialSkips != warm.initialSkips || cold.completedInitialSkips != warm.completedInitialSkips {
				t.Fatalf("%s initial=%v: синтаксический memo изменил provenance, cuts либо WORK", name, mode)
			}
			if name == "hollow" && !au || name == "cycle" && au || name == "opaque" && !au {
				t.Fatal("контроль не различает anchored cycle и неизвестный источник")
			}
		}
	}
}

func TestCallerIdentitySourcesMemoFactoryReset(t *testing.T) {
	p := callerSoundnessProgram(t, "", `child:=&Box{};_=child`, `&Handler{}`)
	g := callerGraphFor(p, nil)
	defer callerGraphs.Delete(p)
	ref := callerOwnershipSources(p)["child"]
	v := callerVariable(p.root, ref.expr)
	want := g.sourcesRaw(v)
	entry, _ := callerGraphs.Load(p)
	base := entry.(*callerGraphMemo).graph
	base.sourceMemo = map[*types.Var][]valueSrc{v: nil}
	base.sourceMemoEpoch, base.sourceMemoWeight = 0, 123
	fresh := callerGraphFor(p, nil)
	if fresh.sourceMemo != nil || fresh.sourceMemoWeight != 0 || !reflect.DeepEqual(fresh.sources(v), want) {
		t.Fatal("factory перенёс синтаксический memo предыдущего graph state с совпавшей нулевой эпохой")
	}
}

// Общий helper не импортирует grpc в fixture/app. Добавляем настоящий импорт
// и тип registrar, затем заново проверяем весь пакет; готовые types.Object
// и найденные production roots не подменяются.
func callerSourcesMemoTypedRegistrar(t *testing.T, p *surfaceProgram) {
	t.Helper()
	file := p.root.files[0]
	imports, ok := file.Decls[0].(*ast.GenDecl)
	if !ok || imports.Tok != token.IMPORT {
		t.Fatal("fixture/app потерял исходный блок импортов")
	}
	added := &ast.ImportSpec{Path: &ast.BasicLit{Kind: token.STRING, Value: `"google.golang.org/grpc"`}}
	imports.Specs = append(imports.Specs, added)
	file.Imports = append(file.Imports, added)
	var registration *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "RegisterTwinServiceServer" {
			registration = fn
		}
	}
	if registration == nil || len(registration.Type.Params.List) != 2 {
		t.Fatal("fixture потерял функцию регистрации с двумя параметрами")
	}
	registration.Type.Params.List[0].Type = &ast.SelectorExpr{X: ast.NewIdent("grpc"), Sel: ast.NewIdent("ServiceRegistrar")}
	fixtureImports := callerFixtureImporter{}
	for _, sp := range p.pkgs {
		if sp != p.root {
			fixtureImports[sp.path] = sp.types
		}
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}, Implicits: map[ast.Node]types.Object{}, Instances: map[*ast.Ident]types.Instance{}}
	pkg, err := (&types.Config{Importer: fixtureImports}).Check(p.root.path, p.fset, p.root.files, info)
	if err != nil {
		t.Fatal(err)
	}
	p.root.types, p.root.info = pkg, info
	// Предусловие совпадает с grammar discovery: вызывается метод из grpc,
	// а не одноимённый метод anonymous interface, объявленный в fixture/app.
	call := registration.Body.List[0].(*ast.ExprStmt).X.(*ast.CallExpr)
	target := callerFunction(p.root, call.Fun)
	if target == nil || target.Pkg() == nil || target.Pkg().Path() != "google.golang.org/grpc" || target.Name() != "RegisterService" {
		t.Fatal("fixture не содержит типизированный grpc.RegisterService")
	}
}

func TestCallerIdentitySourcesMemoRootAndDeclarationTwins(t *testing.T) {
	const producer = "github.com/PRO-Robotech/corelib/operations.PrincipalFromContext"
	p := callerSoundnessProgram(t, `type TwinServiceServer interface{First();Second()}
func RegisterTwinServiceServer(s interface{RegisterService(any,any)},h TwinServiceServer){s.RegisterService(nil,h)}
type Pair struct{}
func(*Pair)First(){relay(Benign{})}
func(*Pair)Second(){relay(Concrete{})}
func relay(reader Reader){reader.read()}`, "", `&Handler{}`, `RegisterTwinServiceServer(nil,&Pair{})`)
	callerSourcesMemoTypedRegistrar(t, p)
	base := []CallerReadDeclaration{{RPC: "fixture/service/FixtureService/RPC", Producer: producer, Site: "fixture/app.anchor", Kind: CallerObservation, Reason: "Непустой baseline fixture."}}
	negative := judgeCallerIdentity(p, base, map[string]bool{"fixture/source": true})
	declared := append(slices.Clone(base), CallerReadDeclaration{RPC: "fixture/app/TwinService/Second", Producer: producer, Site: "(fixture/app.Concrete).read", Kind: CallerObservation, Reason: "То же чтение, добавлено только объявление."})
	lawful := judgeCallerIdentity(p, declared, map[string]bool{"fixture/source": true})
	wantRoots := []string{"fixture/app/TwinService/First", "fixture/app/TwinService/Second", "fixture/service/FixtureService/RPC"}
	if negative.Invalid != "" || lawful.Invalid != "" || negative.RPCs != 3 || lawful.RPCs != 3 || !slices.Equal(negative.Roots, wantRoots) || !slices.Equal(lawful.Roots, wantRoots) || !reflect.DeepEqual(negative.Reads, lawful.Reads) || len(lawful.Findings) != 0 {
		t.Fatalf("корни или lawful twin изменены: negative=%+v lawful=%+v", negative, lawful)
	}
	second, undeclared := false, false
	for _, read := range negative.Reads {
		if read.Site == "(fixture/app.Concrete).read" {
			if read.RPC != "fixture/app/TwinService/Second" {
				t.Fatal("memo перенёс reader между корнями")
			}
			second = true
		}
	}
	for _, finding := range negative.Findings {
		undeclared = undeclared || strings.Contains(finding, "чтение личности без объявления")
	}
	if !second || !undeclared {
		t.Fatal("необъявленное чтение Second потеряно после Benign First")
	}
}

func TestCallerIdentitySourcesMemoReceiverFallback(t *testing.T) {
	p := callerSoundnessProgram(t, `type Carrier struct{};func(receiver *Carrier)take(argument *Box){_=argument}`, `left:=&Carrier{};right:=&Carrier{};child:=&Box{};left.take(child);right.take(child)`, `&Handler{}`)
	g, refs := newCallerGraph(p), callerOwnershipSources(p)
	v := callerVariable(p.root, refs["receiver"].expr)
	want := g.sourcesRaw(v)
	if len(want) != 2 || !reflect.DeepEqual(g.sources(v), want) || !reflect.DeepEqual(g.sources(v), want) {
		t.Fatal("static receiver fallback потерял точных владельцев")
	}
	var site callSrc
	var target *types.Func
	for _, candidate := range g.lifetimeCalls {
		if fn := callerFunction(candidate.pkg, candidate.call.Fun); fn != nil && fn.Name() == "take" {
			site, target = candidate, fn
			break
		}
	}
	if target == nil {
		t.Fatal("отсутствует typed method call")
	}
	g.bindCaller(site.pkg, callerNode{fn: site.fk.fn, lit: site.fk.lit}, site.call, callerNode{fn: target})
	got := g.sources(v)
	if len(got) != 1 || !reflect.DeepEqual(got, g.sourcesRaw(v)) || got[0].expr != site.call.Fun.(*ast.SelectorExpr).X {
		t.Fatal("live receiver не вытеснил static fallback после смены эпохи")
	}
}

func TestCallerIdentitySourcesMemoLifetimeAliasTwins(t *testing.T) {
	const producer = "github.com/PRO-Robotech/corelib/operations.PrincipalFromContext"
	base := []CallerReadDeclaration{{RPC: "fixture/service/FixtureService/RPC", Producer: producer, Site: "fixture/app.anchor", Kind: CallerObservation, Reason: "Непустой baseline fixture."}}
	for _, effect := range []string{"", "source.Mutate(alias);"} {
		p := callerSoundnessProgram(t, "", `box:=&Box{reader:Concrete{}};alias:=box;`+effect+`alias.reader.read();alias.reader.read()`, `&Handler{}`)
		negative := judgeCallerIdentity(p, base, map[string]bool{"fixture/source": true})
		declared := append(slices.Clone(base), CallerReadDeclaration{RPC: base[0].RPC, Producer: producer, Site: "(fixture/app.Concrete).read", Kind: CallerObservation, Reason: "То же чтение, добавлено только объявление."})
		lawful := judgeCallerIdentity(p, declared, map[string]bool{"fixture/source": true})
		if negative.Invalid != "" || lawful.Invalid != "" || len(negative.Reads) < 2 || !reflect.DeepEqual(negative.Reads, lawful.Reads) {
			t.Fatal("alias/lifetime twin потерял реальные чтения")
		}
		undeclared, unresolved := false, false
		for _, finding := range negative.Findings {
			undeclared = undeclared || strings.Contains(finding, "чтение личности без объявления")
		}
		for _, finding := range lawful.Findings {
			if strings.Contains(finding, "чтение личности без объявления") {
				t.Fatal("объявление не закрыло своё чтение")
			}
			unresolved = unresolved || strings.Contains(finding, "неразрешённый вызов")
		}
		if !undeclared || effect == "" && len(lawful.Findings) != 0 || effect != "" && !unresolved {
			t.Fatal("синтаксический memo ослабил объявления либо lifetime escape")
		}
	}
}
