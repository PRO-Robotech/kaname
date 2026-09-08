// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// module_catalog_observer_wiring_test.go — применитель, которого зовёт корень,
// НЕСЁТ наблюдателя (задача продукта #1963).
//
// # Почему это отдельная проба, а не строка в шапке
//
// Счётчик, объявленный и не провязанный, отличается от отсутствующего ровно
// одним: он покрыт пробой пакета и потому выглядит работающим. Наружу это видно
// как «серии нет» — то же самое, что видно при исправном применителе, ни разу
// ничего не снявшем. То есть неотличимость ровно та, ради устранения которой
// метрика и заводится.
//
// Соседний гейт (`module_catalog_apply_wiring_test.go`) утверждает, что
// применителя ЗОВУТ. О том, докладывает ли он, он не говорит ничего и говорить
// не обязан: предметы разные, и слив их в одну пробу, мы получили бы зелёное на
// половине свойства.
//
// # Что здесь считается провязкой
//
// Вызов `WithObserver` НА ТОМ ЖЕ идентификаторе, который связан
// `modulecatalog.NewApplier`. Не «слово встречается в файле»: имя метода стоит и
// в комментарии рядом, и гейт по подстроке зеленел бы на собственном
// объяснении.

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

// TestTheAppliedCatalogIsObserved — сам гейт.
func TestTheAppliedCatalogIsObserved(t *testing.T) {
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
		bound    []string // идентификаторы, связанные конструктором применителя
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
		local := localName(file, "github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog")
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
				if !ok || sel.Sel.Name != "NewApplier" {
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

	t.Logf("перепись: не-тестовых файлов корня разобрано %d, связываний применителя %v, "+
		"провязок наблюдателя %v", parsed, bound, observed)

	if parsed == 0 {
		t.Fatalf("разобрано ноль файлов корня — обход беспредметен, и его молчание " +
			"сказано ни о чём")
	}
	if len(bound) == 0 {
		t.Fatalf("связываний применителя каталога в корне НОЛЬ — гейт беспредметен: он " +
			"молчал бы и тогда, когда применителя не стало вовсе")
	}
	var mute []string
	for _, name := range bound {
		if _, ok := observed[name]; !ok {
			mute = append(mute, name)
		}
	}
	if len(mute) > 0 {
		t.Fatalf("применитель(и) %v связаны и НЕ докладывают наблюдателю.\n\n"+
			"Счётчик, объявленный и не провязанный, снаружи выглядит как исправный "+
			"применитель, ни разу ничего не снявший: серии нет в обоих случаях. Оператор "+
			"в три часа ночи не отличит «каталог не менялся» от «применитель не ходил».\n"+
			"Снятие: `%s = %s.WithObserver(metricsReg.NewModuleCatalogRecorder())`.",
			mute, mute[0], mute[0])
	}
}

// localName — имя, под которым файл импортировал названный путь; пусто, когда не
// импортировал. Псевдоним задаёт вызывающий, поэтому сравнение идёт с путём, а
// не с последним сегментом.
func localName(file *ast.File, path string) string {
	for _, imp := range file.Imports {
		if imp.Path == nil || strings.Trim(imp.Path.Value, `"`) != path {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}
		seg := path[strings.LastIndexByte(path, '/')+1:]
		return seg
	}
	return ""
}
