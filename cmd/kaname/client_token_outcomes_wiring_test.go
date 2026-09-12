// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// client_token_outcomes_wiring_test.go — перепись исходов токен-эндпоинта
// ЧИТАЕТСЯ корнем, а не только собирается обработчиком (задача продукта #2501).
//
// # Почему это отдельная проба
//
// Обработчик несёт карту счётчиков с пред-засевом по каждому объявленному исходу
// и экспортированный аксессор: работа сделана на девять десятых. Корень
// монтировал эндпоинт и не читал перепись, поэтому разбивка отказов жила только
// в памяти процесса — и «ноль отказов за всю жизнь полосы» было неотличимо от
// «полоса не исполнялась ни разу».
//
// Контраст стоял В ТОМ ЖЕ файле корня: у двух соседних поверхностей выдачи
// коллектор провязан вплотную к построению. Расхождение никем не решалось.
//
// # Что здесь считается провязкой
//
// Тот же идентификатор, который связан `buildClientTokenEndpoint`, упомянут
// ВНУТРИ вызова читателя переписи. Не «слово встречается в файле»: имя читателя
// стоит и в комментарии рядом.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestTheClientTokenCensusHasAReaderInTheRoot(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("чтение каталога корня: %v", err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, name)
	}
	sort.Strings(files)

	var (
		parsed   int
		bound    []string            // идентификаторы, связанные построением эндпоинта
		readers  int                 // вызовов читателя переписи всего
		observed = map[string]bool{} // из них — назвавшие связанный идентификатор
	)
	fset := token.NewFileSet()
	for _, name := range files {
		src, rerr := os.ReadFile(filepath.Clean(name))
		if rerr != nil {
			t.Fatalf("чтение %s: %v", name, rerr)
		}
		file, perr := parser.ParseFile(fset, name, src, 0)
		if perr != nil {
			t.Fatalf("разбор %s: %v", name, perr)
		}
		parsed++
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				if len(x.Rhs) != 1 || len(x.Lhs) == 0 {
					return true
				}
				call, ok := x.Rhs[0].(*ast.CallExpr)
				if !ok {
					return true
				}
				fn, ok := call.Fun.(*ast.Ident)
				if !ok || fn.Name != "buildClientTokenEndpoint" {
					return true
				}
				if id, ok := x.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
					bound = append(bound, id.Name)
				}
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "NewClientTokenOutcomeCollector" {
					return true
				}
				readers++
				for _, arg := range x.Args {
					ast.Inspect(arg, func(inner ast.Node) bool {
						if id, ok := inner.(*ast.Ident); ok {
							observed[id.Name] = true
						}
						return true
					})
				}
			}
			return true
		})
	}

	t.Logf("перепись: не-тестовых файлов корня разобрано %d, построений эндпоинта %v, "+
		"вызовов читателя %d, названных им идентификаторов %d", parsed, bound, readers, len(observed))

	if parsed == 0 {
		t.Fatalf("разобрано ноль файлов корня — обход беспредметен")
	}
	if len(bound) == 0 {
		t.Fatalf("построений токен-эндпоинта в корне НОЛЬ — гейт беспредметен: он молчал бы и " +
			"тогда, когда эндпоинта не стало вовсе")
	}
	var mute []string
	for _, name := range bound {
		if !observed[name] {
			mute = append(mute, name)
		}
	}
	if len(mute) > 0 {
		t.Fatalf("эндпоинт(ы) %v построены, а перепись их исходов НЕ ЧИТАЕТСЯ (вызовов читателя %d).\n\n"+
			"Через эту полосу в отдельной установке выдаётся ВСЯКОЕ арендаторское удостоверение. "+
			"Разбивка отказов по исходам остаётся в памяти процесса, и «ноль отказов за всю жизнь "+
			"полосы» неотличимо от «полоса не исполнялась ни разу». У двух соседних поверхностей "+
			"выдачи коллектор провязан вплотную к построению — в том же файле корня.\n"+
			"Снятие: `metricsReg.NewClientTokenOutcomeCollector(clienttokenhttp.DeclaredOutcomes(), "+
			"clientTokenOutcomeReader(%s))` рядом с монтированием.", mute, readers, mute[0])
	}
}
