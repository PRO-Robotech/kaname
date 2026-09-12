// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// frontparity_test.go — четыре гейта дерева о собственном REST-фронте.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Перечень служб фронта и перечень служб слушателя — ДВА объявления одного
// предмета. Разошедшись, они дают либо маршрут, которого нет, либо маршрут не на
// том фронте; второе необратимо — поверхность, побывавшая публичной, считается
// раскрытой. Молча разойтись им нечем только тогда, когда равенство требуется в
// ОБЕ стороны и проверяется машиной.
//
// Судится РАЗОБРАННОЕ дерево, а не текст: имена служб стоят в этом дереве и в
// прозе (шапки объясняют, почему служба здесь и почему не там), и предикат по
// подстроке краснел бы на собственном объяснении проверяемого.
//
// Все четыре печатают объём осмотренного и падают на пустом обходе: «ноль
// расхождений» обязано быть отличимо от «ноль прочитанного».
//
// Способность упасть и смолчать доказана инъекцией — frontparity_injection_test.go.

package restfront

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	// Дескрипторы служб, которые служба поднимает на своих слушателях. Пустой
	// импорт — единственный способ влинковать их в бинарь гейта; перечень обязан
	// покрывать все три пакета, иначе маршруты непокрытого не найдутся вовсе и
	// «объявлено ноль» прочтётся как «поднято всё».
	_ "github.com/PRO-Robotech/corelib/api/kacho/cloud/operation"
	_ "github.com/PRO-Robotech/corelib/api/kacho/cloud/quota/v1"
	_ "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// ownDoorProtoPackages — пакеты контракта, чьи службы служба поднимает.
//
// Выписан здесь, а не взят у двери решения, НАМЕРЕННО: гейт обязан судить
// маршруты независимо от того, что о них думает дверь. Совпадение перечней —
// предмет отдельной проверки ниже, а не посылка этой.
var ownDoorProtoPackages = map[string]bool{
	"kaname.cloud.iam.v1":   true,
	"kacho.cloud.operation": true,
	"kacho.cloud.quota.v1":  true,
}

// route — пара «метод + путь», то есть ровно то, что различает маршрут снаружи.
type route struct {
	method string
	path   string
}

func (r route) String() string { return r.method + " " + r.path }

// ─────────────────────────────────────────────────────────────────────────────
// РАЗБОР ДЕРЕВА
//
// Обе функции принимают КАТАЛОГ, а не путь дерева: тем же вызовом инъекция
// подаёт синтетический вход, меняя ровно один факт.

// registrationsIn читает тело названной функции и возвращает имена служб,
// подключённых названной формой регистрации, — по ОБЕИМ законным записям.
//
// # Форм записи ДВЕ, и распознаватель обязан знать обе
//
// Первая — прямой вызов `pkg.RegisterXHandlerFromEndpoint(ctx, mux, ...)`.
// Вторая — та же функция ЗНАЧЕНИЕМ в таблице, которую обходит общий цикл: имя
// службы тогда стоит рядом с ней, а довод-адрес приходит один на всех. Обе
// законны и обе распространены; предикат, знающий одну, не даёт ни красного, ни
// зелёного — он МОЛЧИТ, и всё записанное другой формой оказывается вне
// наблюдения.
//
// Это не домысел: первая редакция гейта знала только вызов и насчитала ноль
// служб на фронте, где их пятнадцать. Перепись печатает обе оси отдельно —
// иначе прибавка распознавателя неотличима от прибавки в дереве.
//
// Каталог принимается доводом, а не берётся из рабочего: тем же вызовом
// инъекция подаёт синтетический вход, меняя ровно один факт.
func registrationsIn(dir, funcName, suffix string) (svcs map[string]string, found bool, err error) {
	fset := token.NewFileSet()
	names, rerr := goFilesIn(dir)
	if rerr != nil {
		return nil, false, rerr
	}
	svcs = map[string]string{}
	for _, name := range names {
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			return nil, false, fmt.Errorf("%s не разбирается: %w", name, perr)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != funcName || fn.Body == nil {
				continue
			}
			found = true
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				// Форма записи — ось переписи, а не вердикт: обе законны.
				// Вызов опознаётся вторым проходом и перекрывает пометку.
				if sel, isSel := n.(*ast.SelectorExpr); isSel {
					if svc, okName := serviceFromRegistration(sel.Sel.Name, suffix); okName {
						svcs[svc] = "значением"
					}
				}
				return true
			})
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall {
					return true
				}
				if sel, isSel := call.Fun.(*ast.SelectorExpr); isSel {
					if svc, okName := serviceFromRegistration(sel.Sel.Name, suffix); okName {
						svcs[svc] = "вызовом"
					}
				}
				return true
			})
		}
	}
	return svcs, found, nil
}

// serviceFromRegistration превращает Register<X>Service<суффикс> → XService.
func serviceFromRegistration(name, suffix string) (string, bool) {
	if !strings.HasPrefix(name, "Register") || !strings.HasSuffix(name, suffix) {
		return "", false
	}
	mid := strings.TrimSuffix(strings.TrimPrefix(name, "Register"), suffix)
	if mid == "" {
		return "", false
	}
	return mid + "Service", true
}

// goFilesIn — не-тестовые файлы Go каталога, в устойчивом порядке.
func goFilesIn(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// endpointArgsIn возвращает имена выражений, которыми в теле названной функции
// названа точка подключения.
//
// Судится КАЖДОЕ подключение, независимо от того, названа функция регистрации
// прямо или взята из таблицы: предмет здесь — адрес, а не форма записи.
// Признак подключения — вызов вида (ctx, mux, endpoint, opts), второй довод
// которого есть мультиплексор самой функции.
func endpointArgsIn(dir, funcName string) ([]string, error) {
	const bindArity = 4
	const muxArgIndex, endpointArgIndex = 1, 2
	fset := token.NewFileSet()
	names, err := goFilesIn(dir)
	if err != nil {
		return nil, err
	}
	var args []string
	for _, name := range names {
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			return nil, perr
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != funcName || fn.Body == nil {
				continue
			}
			muxParam := muxParamName(fn)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall || len(call.Args) != bindArity || muxParam == "" {
					return true
				}
				mux, isIdent := call.Args[muxArgIndex].(*ast.Ident)
				if !isIdent || mux.Name != muxParam {
					return true
				}
				if id, okID := call.Args[endpointArgIndex].(*ast.Ident); okID {
					args = append(args, id.Name)
				} else {
					args = append(args, "")
				}
				return true
			})
		}
	}
	return args, nil
}

// muxParamName — имя довода-мультиплексора у функции регистрации.
func muxParamName(fn *ast.FuncDecl) string {
	if fn.Type.Params == nil {
		return ""
	}
	for _, p := range fn.Type.Params.List {
		star, isStar := p.Type.(*ast.StarExpr)
		if !isStar {
			continue
		}
		sel, isSel := star.X.(*ast.SelectorExpr)
		if !isSel || sel.Sel.Name != "ServeMux" {
			continue
		}
		for _, nm := range p.Names {
			return nm.Name
		}
	}
	return ""
}

// funcParamNames возвращает имена доводов названной функции.
func funcParamNames(dir, funcName string) (map[string]bool, error) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			return nil, perr
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != funcName || fn.Type.Params == nil {
				continue
			}
			for _, p := range fn.Type.Params.List {
				for _, nm := range p.Names {
					out[nm.Name] = true
				}
			}
		}
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// МАРШРУТЫ КОНТРАКТА — выводятся из влинкованных дескрипторов

// contractRoutes возвращает маршруты, объявленные контрактом, по службам.
func contractRoutes() (byService map[string][]route, internalService map[string]bool) {
	byService = map[string][]route{}
	internalService = map[string]bool{}
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if !ownDoorProtoPackages[string(fd.Package())] {
			return true
		}
		for i := 0; i < fd.Services().Len(); i++ {
			svc := fd.Services().Get(i)
			name := string(svc.Name())
			if _, seen := byService[name]; !seen {
				byService[name] = nil
			}
			internalService[name] = strings.HasPrefix(name, "Internal")
			for j := 0; j < svc.Methods().Len(); j++ {
				m := svc.Methods().Get(j)
				rule, _ := proto.GetExtension(m.Options(), annotations.E_Http).(*annotations.HttpRule)
				if rule == nil {
					continue
				}
				for _, r := range append([]*annotations.HttpRule{rule}, rule.GetAdditionalBindings()...) {
					if rt, ok := routeOf(r); ok {
						byService[name] = append(byService[name], rt)
					}
				}
			}
		}
		return true
	})
	return byService, internalService
}

func routeOf(r *annotations.HttpRule) (route, bool) {
	switch p := r.GetPattern().(type) {
	case *annotations.HttpRule_Get:
		return route{"GET", p.Get}, true
	case *annotations.HttpRule_Post:
		return route{"POST", p.Post}, true
	case *annotations.HttpRule_Put:
		return route{"PUT", p.Put}, true
	case *annotations.HttpRule_Patch:
		return route{"PATCH", p.Patch}, true
	case *annotations.HttpRule_Delete:
		return route{"DELETE", p.Delete}, true
	default:
		return route{}, false
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// КООРДИНАТЫ ДЕРЕВА

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("рабочий каталог не читается: %v", err)
	}
	// Самый ВНЕШНИЙ go.mod: у службы свой модуль, поэтому первый встречный
	// остановил бы обход на её границе, а координаты гейта лежат выше.
	root := ""
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			root = dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	if root == "" {
		t.Fatal("go.mod не найден ни на одном уровне — дерево не опознано, вердикт беспредметен")
	}
	return root
}

func grpcRegisterDir(t *testing.T) string {
	t.Helper()
	return platformtree.RequirePath(t, "services/iam/cmd/kaname")
}

func restFrontDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("рабочий каталог не читается: %v", err)
	}
	return dir
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// ГЕЙТ 1 (KAN-REST-04). Публичный фронт не несёт НИ ОДНОЙ службы `Internal*`.

func TestPublicRESTFrontCarriesNoInternalService(t *testing.T) {
	pub, foundPub, err := registrationsIn(restFrontDir(t), "registerPublicRESTServices", "ServiceHandlerFromEndpoint")
	if err != nil {
		t.Fatalf("разбор публичной регистрации не состоялся: %v", err)
	}
	if !foundPub {
		t.Fatal("функция registerPublicRESTServices в пакете не найдена: " +
			"публичного REST-фронта нет, и утверждать о его составе нечего")
	}
	internal, foundInt, err := registrationsIn(restFrontDir(t), "registerInternalRESTServices", "ServiceHandlerFromEndpoint")
	if err != nil {
		t.Fatalf("разбор внутренней регистрации не состоялся: %v", err)
	}
	if !foundInt {
		t.Fatal("функция registerInternalRESTServices в пакете не найдена: " +
			"внутреннего REST-фронта нет — тогда «на публичном нет внутренних служб» " +
			"верно тривиально, потому что их нет нигде")
	}

	var leaked []string
	for _, svc := range sortedKeys(pub) {
		if strings.HasPrefix(svc, "Internal") {
			leaked = append(leaked, svc)
		}
	}

	t.Logf("осмотрено: служб на публичном REST-фронте %d, на внутреннем %d, "+
		"из публичных с именем Internal* %d", len(pub), len(internal), len(leaked))

	if len(pub) == 0 {
		t.Fatal("на публичном фронте не зарегистрировано ни одной службы — обход пуст, " +
			"вердикт беспредметен: отсутствие внутренних служб здесь ничего не доказывает")
	}
	if len(internal) == 0 {
		t.Fatal("на внутреннем фронте не зарегистрировано ни одной службы — обход пуст, " +
			"вердикт беспредметен")
	}
	if len(leaked) > 0 {
		t.Errorf("на ПУБЛИЧНОМ REST-фронте зарегистрированы служебные поверхности: %s.\n"+
			"Поверхность, побывавшая публичной, считается раскрытой — отката у этой "+
			"ошибки нет. Место такой службы — внутренний фронт (registerInternalRESTServices)",
			strings.Join(leaked, ", "))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ГЕЙТ 2 (KAN-REST-05). Перечни gRPC и REST совпадают в ОБЕ стороны.

func TestRESTAndGRPCServiceSetsMatchBothWays(t *testing.T) {
	cmdDir := grpcRegisterDir(t)
	frontDir := restFrontDir(t)

	type pair struct {
		title    string
		grpcFunc string
		restFunc string
	}
	pairs := []pair{
		{"публичный", "registerPublicServices", "registerPublicRESTServices"},
		{"внутренний", "registerInternalServices", "registerInternalRESTServices"},
	}

	inspected := 0
	for _, p := range pairs {
		grpcSvcs, foundGRPC, err := registrationsIn(cmdDir, p.grpcFunc, "ServiceServer")
		if err != nil {
			t.Fatalf("%s слушатель: разбор не состоялся: %v", p.title, err)
		}
		if !foundGRPC {
			t.Fatalf("%s слушатель: функция %s не найдена — сверять не с чем",
				p.title, p.grpcFunc)
		}
		restSvcs, foundREST, err := registrationsIn(frontDir, p.restFunc, "ServiceHandlerFromEndpoint")
		if err != nil {
			t.Fatalf("%s фронт: разбор не состоялся: %v", p.title, err)
		}
		if !foundREST {
			t.Errorf("%s REST-фронт: функция %s не найдена. Службы на слушателе есть (%d), "+
				"а REST-фронта у них нет: каждый их маршрут недосягаем",
				p.title, p.restFunc, len(grpcSvcs))
			continue
		}

		var onlyGRPC, onlyREST []string
		for _, svc := range sortedKeys(grpcSvcs) {
			if _, ok := restSvcs[svc]; !ok {
				onlyGRPC = append(onlyGRPC, svc)
			}
		}
		for _, svc := range sortedKeys(restSvcs) {
			if _, ok := grpcSvcs[svc]; !ok {
				onlyREST = append(onlyREST, svc)
			}
		}
		inspected += len(grpcSvcs) + len(restSvcs)

		t.Logf("осмотрено: %s слушатель — служб %d, его REST-фронт — служб %d, "+
			"только на слушателе %d, только на фронте %d",
			p.title, len(grpcSvcs), len(restSvcs), len(onlyGRPC), len(onlyREST))

		if len(grpcSvcs) == 0 {
			t.Fatalf("%s слушатель: служб ноль — обход пуст, вердикт беспредметен", p.title)
		}
		if len(onlyGRPC) > 0 {
			t.Errorf("%s: служба поднята на слушателе и НЕ зарегистрирована на его REST-фронте: %s.\n"+
				"Её маршруты объявлены контрактом и недосягаемы по HTTP",
				p.title, strings.Join(onlyGRPC, ", "))
		}
		if len(onlyREST) > 0 {
			t.Errorf("%s: служба зарегистрирована на REST-фронте и НЕ поднята на его слушателе: %s.\n"+
				"Каждый её маршрут отвечал бы отказом соединения, а не отказом по существу",
				p.title, strings.Join(onlyREST, ", "))
		}
	}
	if inspected == 0 {
		t.Fatal("осмотрено ноль регистраций — обход пуст, вердикт беспредметен")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ГЕЙТ 3 (KAN-REST-08). Регистрация — только через СОБСТВЕННЫЙ адрес.

func TestRESTFrontRegistersOnlyThroughItsOwnEndpoint(t *testing.T) {
	frontDir := restFrontDir(t)
	fronts := []string{"registerPublicRESTServices", "registerInternalRESTServices"}

	byValue, byCall, bindings, viaParam := 0, 0, 0, 0
	for _, fn := range fronts {
		// Внутрипроцессная форма минует КАЖДОЕ звено слушателя: решение о
		// вызывающем, пообъектный вопрос, анти-аноним. Её присутствие означает
		// два пути к одному обработчику с разными решениями по дороге.
		inProcess, found, err := registrationsIn(frontDir, fn, "ServiceHandlerServer")
		if err != nil {
			t.Fatalf("%s: разбор не состоялся: %v", fn, err)
		}
		if !found {
			t.Errorf("%s: функция не найдена — REST-фронта нет", fn)
			continue
		}
		if len(inProcess) > 0 {
			t.Errorf("%s: службы подключены ВНУТРИПРОЦЕССНОЙ формой: %s.\n"+
				"Она зовёт реализацию напрямую, минуя перехватчики слушателя, — "+
				"тогда запрос по HTTP обслуживается иначе, чем тот же запрос по gRPC",
				fn, strings.Join(sortedKeys(inProcess), ", "))
		}

		byEndpoint, _, err := registrationsIn(frontDir, fn, "ServiceHandlerFromEndpoint")
		if err != nil {
			t.Fatalf("%s: разбор не состоялся: %v", fn, err)
		}
		for _, svc := range sortedKeys(byEndpoint) {
			if byEndpoint[svc] == "вызовом" {
				byCall++
			} else {
				byValue++
			}
		}

		params, err := funcParamNames(frontDir, fn)
		if err != nil {
			t.Fatalf("%s: доводы функции не читаются: %v", fn, err)
		}
		args, err := endpointArgsIn(frontDir, fn)
		if err != nil {
			t.Fatalf("%s: подключения не читаются: %v", fn, err)
		}
		for _, arg := range args {
			bindings++
			if arg == "" {
				t.Errorf("%s: подключение к точке, названной не идентификатором.\n"+
					"Адрес, выбранный не вызывающим, есть адрес СОСЕДА, а не собственного "+
					"слушателя, и никакое звено этой службы такой запрос не проходит", fn)
				continue
			}
			if !params[arg] {
				t.Errorf("%s: подключение к %q, которого нет среди доводов функции.\n"+
					"Собственный адрес обязан приходить доводом: иначе он берётся из "+
					"объявления рядом и молча разойдётся с тем, на чём поднят слушатель",
					fn, arg)
				continue
			}
			viaParam++
		}
		if len(byEndpoint) > 0 && bindings == 0 {
			t.Errorf("%s: службы названы (%d), а подключения не выполнено ни одного.\n"+
				"Перечень, который никто не обходит, поднимает ноль маршрутов",
				fn, len(byEndpoint))
		}
	}

	t.Logf("осмотрено: служб подключено на обоих фронтах %d (записаны вызовом %d, "+
		"значением в таблице %d); подключений выполнено %d, из них через довод-адрес %d",
		byValue+byCall, byCall, byValue, bindings, viaParam)

	if byValue+byCall == 0 {
		t.Fatal("регистраций не найдено ни одной — обход пуст, вердикт беспредметен")
	}
	if bindings == 0 {
		t.Fatal("подключений не найдено ни одного — обход пуст, вердикт беспредметен")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ГЕЙТ 4 (KAN-REST-29 и KAN-REST-30). Маршруты контракта ↔ маршруты фронта.

func TestEveryContractRouteResolvesOnItsOwnFront(t *testing.T) {
	frontDir := restFrontDir(t)
	byService, isInternal := contractRoutes()
	if len(byService) == 0 {
		t.Fatal("из дескрипторов не выведено ни одной службы — обход пуст, вердикт беспредметен")
	}

	pub, foundPub, err := registrationsIn(frontDir, "registerPublicRESTServices", "ServiceHandlerFromEndpoint")
	if err != nil {
		t.Fatalf("разбор публичной регистрации не состоялся: %v", err)
	}
	internal, foundInt, err := registrationsIn(frontDir, "registerInternalRESTServices", "ServiceHandlerFromEndpoint")
	if err != nil {
		t.Fatalf("разбор внутренней регистрации не состоялся: %v", err)
	}
	if !foundPub || !foundInt {
		t.Fatal("одной из функций регистрации фронта нет: множество маршрутов фронта пусто, " +
			"и равенство его с контрактом было бы утверждением о несуществующем")
	}

	// Маршруты, которые РАЗРЕШАЕТ каждый фронт: объединение привязок его служб.
	// Порождённая форма регистрации поднимает привязки службы ЦЕЛИКОМ — части у
	// неё нет, — поэтому множество выводится по службам, а не по методам.
	allowed := func(svcs map[string]string) map[route]string {
		out := map[route]string{}
		for svc := range svcs {
			for _, r := range byService[svc] {
				out[r] = svc
			}
		}
		return out
	}
	pubRoutes, internalRoutes := allowed(pub), allowed(internal)

	// Маршруты, ОБЪЯВЛЕННЫЕ контрактом, по сторонам.
	declaredPublic, declaredInternal := map[route]string{}, map[route]string{}
	for svc, rs := range byService {
		for _, r := range rs {
			if isInternal[svc] {
				declaredInternal[r] = svc
			} else {
				declaredPublic[r] = svc
			}
		}
	}

	var missingPublic, missingInternal, leaked []string
	for r, svc := range declaredPublic {
		if _, ok := pubRoutes[r]; !ok {
			missingPublic = append(missingPublic, r.String()+" ("+svc+")")
		}
	}
	for r, svc := range declaredInternal {
		if _, ok := internalRoutes[r]; !ok {
			missingInternal = append(missingInternal, r.String()+" ("+svc+")")
		}
		// Внутренний путь на ПУБЛИЧНОМ фронте — то же утверждение, что KAN-REST-02,
		// и здесь оно проверяется ПО ПЕРЕЧНЮ, а не по одному пути.
		if _, ok := pubRoutes[r]; ok {
			leaked = append(leaked, r.String()+" ("+svc+")")
		}
	}
	sort.Strings(missingPublic)
	sort.Strings(missingInternal)
	sort.Strings(leaked)

	// Число публичных маршрутов, разрешаемых ВНУТРЕННИМ фронтом, — следствие
	// того, что служба ответа о доступе стоит на ОБОИХ слушателях, а привязки
	// поднимаются целиком. Расширением внутренней поверхности это не является,
	// поэтому считается и печатается отдельно, а не объявляется нарушением.
	publicOnInternal := 0
	for r := range internalRoutes {
		if _, ok := declaredPublic[r]; ok {
			publicOnInternal++
		}
	}

	t.Logf("осмотрено: маршрутов контракта объявлено %d (публичных %d, внутренних %d); "+
		"публичный фронт разрешает %d, внутренний %d (из них публичных путей %d — "+
		"служба стоит на обоих слушателях)",
		len(declaredPublic)+len(declaredInternal), len(declaredPublic), len(declaredInternal),
		len(pubRoutes), len(internalRoutes), publicOnInternal)

	if len(declaredPublic) == 0 || len(declaredInternal) == 0 {
		t.Fatal("контракт не объявил маршрутов одной из сторон — обход пуст, вердикт беспредметен")
	}
	if len(missingPublic) > 0 {
		t.Errorf("публичных маршрутов объявлено контрактом и НЕ поднято публичным фронтом: %d\n  %s",
			len(missingPublic), strings.Join(missingPublic, "\n  "))
	}
	if len(missingInternal) > 0 {
		t.Errorf("внутренних маршрутов объявлено контрактом и НЕ поднято внутренним фронтом: %d\n  %s",
			len(missingInternal), strings.Join(missingInternal, "\n  "))
	}
	if len(leaked) > 0 {
		t.Errorf("ВНУТРЕННИЕ маршруты разрешаются ПУБЛИЧНЫМ фронтом: %d\n  %s\n"+
			"Раздельность фронтов есть свойство сокета: внутреннее обязано быть "+
			"недосягаемо снаружи, а не отклоняемо по дороге",
			len(leaked), strings.Join(leaked, "\n  "))
	}
}
