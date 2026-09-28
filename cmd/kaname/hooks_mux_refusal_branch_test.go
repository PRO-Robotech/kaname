// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// hooks_mux_refusal_branch_test.go — отказ сборки полос выдачи в `buildHooksMux`
// значит ОТСУТСТВИЕ обработчика (kaname#436, находка 2).
//
// # Признак
//
// `TestIssuanceLanesAssemblyRefusalStopsTheStart` держит половину: «обработчика нет —
// поверхность отказывает, корень не стартует». Вторую половину — «отказ сборки —
// обработчика нет» — не держало ничего: мутант, где ветвь отказа `buildHooksMux`
// возвращает обработчик, оставлял пакет корня зелёным, и полоса без хуков выдачи
// поднималась бы под внешним поставщиком.
//
// # Почему чтение кода, а не вызов
//
// Ветвь сегодня НЕДОСТИЖИМА входом: предел на вызов — константа
// (`credentialLanePeerTimeout`), а приёмник потерь журнала реестр отдаёт всегда.
// Вызвать `buildHooksMux` так, чтобы сборка отказала, нечем без шва в корне, а шов
// ради пробы — правка продукта. Поэтому ветвь судится по разбору файла: за вызовом
// `buildIssuanceHooks` стоит проверка его отказа, и КАЖДЫЙ выход из неё возвращает
// `nil` обработчиком и отказ, в который входит отказ сборки, а последний оператор
// ветви — возврат (ветвь, которая пишет строку журнала и идёт дальше, собрала бы
// мультиплексор с пустыми обработчиками выдачи).
//
// Отказ вторым значением — форма kaname#440: причина доходит до старта значением.
// Поэтому находка и `return nil, nil` (корень откажет словами «обслуживать нечем», а
// не тем, что сломалось), и отказ, не несущий отказа сборки (причина потеряна).
// Отказ корня с причиной на шве держит `TestIssuanceLanesAssemblyRefusalReachesTheStartWithItsCause`.
//
// Законные формы записи, которые разбор знает: присваивание и следом `if <err> !=
// nil`; то же с присваиванием в заголовке `if`. Любая другая форма — находка с
// именем формы, а не молчание.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// refusalBranchVerdict — сколько вызовов сборки полос найдено в функции и что с
// их ветвями отказа не так.
type refusalBranchVerdict struct {
	calls  int
	faults []string
}

// judgeRefusalBranches разбирает src и судит в функции fn ветвь отказа каждого
// вызова `buildIssuanceHooks`.
func judgeRefusalBranches(src, fn string) (refusalBranchVerdict, error) {
	var v refusalBranchVerdict
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "hooks_mux.go", src, 0)
	if err != nil {
		return v, fmt.Errorf("разбор: %w", err)
	}
	var body *ast.BlockStmt
	for _, d := range file.Decls {
		if f, ok := d.(*ast.FuncDecl); ok && f.Recv == nil && f.Name.Name == fn {
			body = f.Body
		}
	}
	if body == nil {
		return v, fmt.Errorf("функции %s в файле нет", fn)
	}
	var walk func(list []ast.Stmt)
	walk = func(list []ast.Stmt) {
		for i, st := range list {
			if ifs, ok := st.(*ast.IfStmt); ok {
				if as, ok := ifs.Init.(*ast.AssignStmt); ok && callsAssembly(as) {
					v.calls++
					v.faults = append(v.faults, judgeOneBranch(fset, as, ifs)...)
					walk(ifs.Body.List)
					continue
				}
			}
			if as, ok := st.(*ast.AssignStmt); ok && callsAssembly(as) {
				v.calls++
				var next *ast.IfStmt
				if i+1 < len(list) {
					next, _ = list[i+1].(*ast.IfStmt)
				}
				if next == nil {
					v.faults = append(v.faults, fmt.Sprintf("%s: за вызовом buildIssuanceHooks нет проверки "+
						"его отказа — отказ сборки проходит мимо", fset.Position(as.Pos())))
					continue
				}
				v.faults = append(v.faults, judgeOneBranch(fset, as, next)...)
			}
			if b, ok := st.(*ast.BlockStmt); ok {
				walk(b.List)
			}
		}
	}
	walk(body.List)
	return v, nil
}

// callsAssembly — присваивание результатов вызова `buildIssuanceHooks`.
func callsAssembly(as *ast.AssignStmt) bool {
	if len(as.Rhs) != 1 {
		return false
	}
	call, ok := as.Rhs[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	return ok && id.Name == "buildIssuanceHooks"
}

// judgeOneBranch — ветвь отказа одного вызова: проверка ошибки ИМЕННО этого
// вызова, каждый возврат — `nil` и отказ с причиной (`judgeRefusalReturn`),
// последний оператор — возврат.
func judgeOneBranch(fset *token.FileSet, as *ast.AssignStmt, ifs *ast.IfStmt) []string {
	at := fset.Position(ifs.Pos())
	errVar, ok := as.Lhs[len(as.Lhs)-1].(*ast.Ident)
	if !ok {
		return []string{fmt.Sprintf("%s: отказ сборки не присвоен переменной — судить нечего", at)}
	}
	notCheck := []string{fmt.Sprintf("%s: следом за сборкой стоит не проверка «%s != nil» её отказа", at, errVar.Name)}
	cond, ok := ifs.Cond.(*ast.BinaryExpr)
	if !ok || cond.Op != token.NEQ {
		return notCheck
	}
	x, xok := cond.X.(*ast.Ident)
	y, yok := cond.Y.(*ast.Ident)
	if !xok || !yok || x.Name != errVar.Name || y.Name != "nil" {
		return notCheck
	}
	var out []string
	ast.Inspect(ifs.Body, func(n ast.Node) bool {
		if _, lit := n.(*ast.FuncLit); lit {
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		out = append(out, judgeRefusalReturn(fset, ret, errVar.Name)...)
		return true
	})
	list := ifs.Body.List
	if len(list) == 0 {
		out = append(out, fmt.Sprintf("%s: ветвь отказа пуста — сборка продолжается с пустыми обработчиками", at))
	} else if _, ok := list[len(list)-1].(*ast.ReturnStmt); !ok {
		out = append(out, fmt.Sprintf("%s: ветвь отказа кончается не возвратом — корень идёт дальше и собирает "+
			"мультиплексор с пустыми обработчиками выдачи", at))
	}
	return out
}

// judgeRefusalReturn — один возврат из ветви отказа: ровно два значения, первое —
// `nil` (обработчика нет), второе — отказ, в который входит отказ сборки errName
// (причина доходит до старта, kaname#440).
func judgeRefusalReturn(fset *token.FileSet, ret *ast.ReturnStmt, errName string) []string {
	at := fset.Position(ret.Pos())
	if len(ret.Results) != 2 {
		return []string{fmt.Sprintf("%s: возврат из ветви отказа несёт %d значений вместо двух — "+
			"nil обработчиком и отказа сборки", at, len(ret.Results))}
	}
	var out []string
	if id, ok := ret.Results[0].(*ast.Ident); !ok || id.Name != "nil" {
		out = append(out, fmt.Sprintf("%s: ветвь отказа сборки полос возвращает ОБРАБОТЧИК, а не nil — "+
			"поверхность с объявленным адресом поднимется без хуков выдачи", at))
	}
	refusal := ret.Results[1]
	if id, ok := refusal.(*ast.Ident); ok && id.Name == "nil" {
		return append(out, fmt.Sprintf("%s: ветвь отказа возвращает nil вместо отказа — корень откажет старту "+
			"словами «обслуживать нечем», а не тем, что не собралось", at))
	}
	carries := false
	ast.Inspect(refusal, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == errName {
			carries = true
		}
		return !carries
	})
	if !carries {
		out = append(out, fmt.Sprintf("%s: отказ из ветви не несёт отказа сборки «%s» — причина сборки "+
			"теряется до старта", at, errName))
	}
	return out
}

// TestHooksMuxAssemblyRefusalYieldsNoHandler — в `buildHooksMux` ветвь отказа
// сборки полос выдачи возвращает nil обработчиком и отказ, несущий причину сборки.
func TestHooksMuxAssemblyRefusalYieldsNoHandler(t *testing.T) {
	src, err := os.ReadFile("hooks_mux.go")
	if err != nil {
		t.Fatalf("чтение hooks_mux.go: %v", err)
	}
	v, err := judgeRefusalBranches(string(src), "buildHooksMux")
	if err != nil {
		t.Fatalf("предпосылка: %v", err)
	}
	t.Logf("перепись: вызовов buildIssuanceHooks в buildHooksMux %d · находок %d", v.calls, len(v.faults))
	if v.calls == 0 {
		t.Fatal("в buildHooksMux нет ни одного вызова buildIssuanceHooks — проба беспредметна: она молчала бы " +
			"и тогда, когда полосы выдачи собираются мимо неё")
	}
	for _, f := range v.faults {
		t.Error(f)
	}
}

// TestHooksMuxRefusalBranchJudgeRedsOnTheMutantsItIsFor — судья ветви краснеет на
// каждом мутанте ветви и молчит на законных близнецах обеих форм записи. Синтетика
// несёт ту же сигнатуру, что настоящая сборка: обработчик и отказ (kaname#440).
func TestHooksMuxRefusalBranchJudgeRedsOnTheMutantsItIsFor(t *testing.T) {
	wrap := func(body string) string {
		return "package main\n\nfunc buildHooksMux() (http.Handler, error) {\n" + body + "\n\treturn mux, nil\n}\n"
	}
	const call = "\ttokenHook, refreshHook, err := buildIssuanceHooks(cfg, ports, drops, logger)\n"
	cases := []struct {
		name      string
		src       string
		calls     int
		wantFault string // пусто — молчание
	}{
		{"ЗАКОННЫЙ БЛИЗНЕЦ: присваивание, затем if err != nil { return nil, fmt.Errorf(…%w, err) }",
			wrap(call + "\tif err != nil {\n\t\tlogger.Error(\"x\", \"err\", err)\n\t\treturn nil, fmt.Errorf(\"обработчики хуков выдачи: %w\", err)\n\t}"), 1, ""},
		{"ЗАКОННЫЙ БЛИЗНЕЦ: присваивание в заголовке if, отказ возвращается как есть",
			wrap("\tif _, _, berr := buildIssuanceHooks(cfg, ports, drops, logger); berr != nil {\n\t\treturn nil, berr\n\t}"), 1, ""},
		{"мутант B1: ветвь отказа возвращает обработчик",
			wrap(call + "\tif err != nil {\n\t\treturn http.NotFoundHandler(), fmt.Errorf(\"x: %w\", err)\n\t}"), 1, "ОБРАБОТЧИК"},
		{"мутант B1 без отказа: ветвь отказа возвращает обработчик и nil",
			wrap(call + "\tif err != nil {\n\t\treturn http.NotFoundHandler(), nil\n\t}"), 1, "ОБРАБОТЧИК"},
		{"мутант: ветвь отказа возвращает nil вместо отказа",
			wrap(call + "\tif err != nil {\n\t\treturn nil, nil\n\t}"), 1, "вместо отказа"},
		{"мутант: отказ из ветви не несёт причины сборки",
			wrap(call + "\tif err != nil {\n\t\treturn nil, errors.New(\"полоса не собрана\")\n\t}"), 1, "причина"},
		{"мутант: возврат прежней формы — одно значение",
			wrap(call + "\tif err != nil {\n\t\treturn nil\n\t}"), 1, "вместо двух"},
		{"мутант: ветвь отказа пишет журнал и идёт дальше",
			wrap(call + "\tif err != nil {\n\t\tlogger.Error(\"x\", \"err\", err)\n\t}"), 1, "не возвратом"},
		{"мутант: отказ сборки не проверен",
			wrap(call + "\t_ = tokenHook"), 1, "нет проверки"},
		{"мутант: проверяется чужая ошибка",
			wrap(call + "\tif other != nil {\n\t\treturn nil, other\n\t}"), 1, "не проверка"},
		{"беспредметно: вызова сборки нет", wrap("\t_ = cfg"), 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, err := judgeRefusalBranches(c.src, "buildHooksMux")
			if err != nil {
				t.Fatalf("разбор синтетики: %v", err)
			}
			if v.calls != c.calls {
				t.Fatalf("вызовов найдено %d, ожидалось %d", v.calls, c.calls)
			}
			joined := strings.Join(v.faults, "\n")
			if c.wantFault == "" && len(v.faults) != 0 {
				t.Fatalf("законная форма названа находкой: %v", v.faults)
			}
			if c.wantFault != "" && !strings.Contains(joined, c.wantFault) {
				t.Fatalf("мутант не назван причиной %q: %v", c.wantFault, v.faults)
			}
		})
	}
}
