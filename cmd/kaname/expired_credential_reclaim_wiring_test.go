// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// expired_credential_reclaim_wiring_test.go — второй уборщик ДОКЛАДЫВАЕТ
// величинам, а не только журналу (задача продукта #2499).
//
// # Почему это отдельная проба
//
// Уборщиков одного вида два, и полосы наблюдения у них разошлись: у первого три
// семейства величин, у второго — строка на прогон. Различие никем не решалось.
// Приёмник, объявленный и не провязанный, при этом выглядит работающим: его
// пробы зелены, а наружу «рядов нет» читается так же, как «уборщик крутится и
// ничего не находит».
//
// # Что здесь считается провязкой
//
// Вызов `WithObserver` НА ТОМ ЖЕ идентификаторе, который связан
// `expiredcredsweep.New`. Не «слово встречается в файле».

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

// expiredCredSweepPath — путь пакета второго уборщика.
const expiredCredSweepPath = "github.com/PRO-Robotech/kaname/internal/apps/kaname/expiredcredsweep"

func TestTheExpiredCredentialSweeperReportsToValues(t *testing.T) {
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
		bound    []string
		observed = map[string]string{}
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
		local := localName(file, expiredCredSweepPath)
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				if local == "" || len(x.Rhs) != 1 || len(x.Lhs) == 0 {
					return true
				}
				call, ok := x.Rhs[0].(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "New" {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != local {
					return true
				}
				if id, ok := x.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
					bound = append(bound, id.Name)
				}
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "WithObserver" {
					return true
				}
				if recv, ok := sel.X.(*ast.Ident); ok {
					observed[recv.Name] = name
				}
			}
			return true
		})
	}

	t.Logf("перепись: не-тестовых файлов корня разобрано %d, связываний уборщика %v, "+
		"провязок приёмника %v", parsed, bound, observed)

	if parsed == 0 {
		t.Fatalf("разобрано ноль файлов корня — обход беспредметен")
	}
	if len(bound) == 0 {
		t.Fatalf("связываний второго уборщика в корне НОЛЬ — гейт беспредметен: он молчал бы " +
			"и тогда, когда уборщика не стало вовсе")
	}
	var mute []string
	for _, name := range bound {
		if _, ok := observed[name]; !ok {
			mute = append(mute, name)
		}
	}
	if len(mute) > 0 {
		t.Fatalf("уборщик(и) %v связаны и НЕ докладывают величинам.\n\n"+
			"Три состояния — «выключен оператором», «включён и отказывает каждый прогон», "+
			"«включён и находит ноль» — не различает ни одна величина. Первое объявляется "+
			"единожды при старте и уходит вместе со сроком хранения журнала.\n"+
			"Снятие: `%s.WithObserver(reg.ExpiredCredentialSweepRecorder(expiredcredsweep.Outcomes()))`.",
			mute, mute[0])
	}
}
