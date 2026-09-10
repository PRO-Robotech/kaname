// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// module_seed_apply_wiring_test.go — гейт «применитель ПОСЕВА, построенный
// композиционным корнем, им же и позван, и позван ПОСЛЕ применения ролей»
// (задача продукта #2452).
//
// # Предмет
//
// Применитель посева — единственный производитель служебных учёток модулей
// платформы после того, как их сняла миграция
// `20260909202745_module_identities_leave_the_baseline.sql`. Применитель,
// которого не позвали, молчит ровно так же уверенно, как записавший все строки:
// установка платформы поднялась бы БЕЗ личностей своих модулей, а снаружи это
// выглядит как «сосед недоступен».
//
// Это тот же класс мёртвого стража (`00-kacho-core` ban #16), из-за которого
// заведены гейты провязки каталога и ролей. Отличать надо не «применитель есть»
// от «применителя нет», а «вызов меняет состояние платформы» от «не меняет».
//
// # Гейт судит ДВА факта, и ни один не выводится из другого
//
//	A. СВЯЗЫВАНИЕ → ВЫЗОВ. Идентификатор, связанный `moduleseed.NewApplier`,
//	   обязан быть доводом вызова применения в прод-коде корня.
//
//	B. ПОРЯДОК на пути старта: доставка → применение ролей → применение посева.
//
// # Почему посев — ПОСЛЕ ролей
//
// Выдача формой РОЛИ ссылается на строку роли ключом (`access_bindings_role_fk`)
// и на её живость триггером. Посев, применённый раньше, отказывал бы отказом
// чужого ограничения, называя не тот предмет. Сегодня такой выдачи не объявляет
// ни один манифест — и порядок всё равно принадлежит ФОРМЕ, а не сегодняшнему
// содержимому: первый же такой манифест иначе упал бы на старте, и упал бы там,
// где причину не ищут.
//
// # Разбор идёт по УЗЛУ вызова, а не по подстроке
//
// Имена всех трёх шагов встречаются в комментариях этого же файла и соседних:
// проверка по тексту краснела бы на собственном объяснении (`testing.md`
// §«Гейт на класс», п. 4).
//
// # Границы названы вслух
//
// Судится связывание и вызов в пределах прод-файлов композиционного корня.
// Применитель, переданный чужому пакету, который зовёт применение у себя, этим
// гейтом не виден; такой формы в дереве сегодня нет. Об ИСХОДЕ применения гейт
// не судит вовсе — это предмет проб применителя против живой базы.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedWiringCensus — объём осмотренного вместе с находками: «вызова нет»
// обязано быть отличимо от «прочитано ноль».
type seedWiringCensus struct {
	filesRead int
	callsSeen int
	// bound — идентификаторы, связанные `moduleseed.NewApplier`, с координатой.
	bound map[string]string
	// called — идентификаторы, поданные доводом в `applyDeliveredModuleSeed`.
	called map[string]string
}

// rootProdFiles — не-тестовые файлы Go композиционного корня.
func rootProdFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("каталог корня не прочитан: %v — вердикт беспредметен", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		out = append(out, e.Name())
	}
	return out
}

// seedApplierWiring — где применитель посева СВЯЗАН и где он ПОЗВАН.
func seedApplierWiring(t *testing.T) seedWiringCensus {
	t.Helper()
	census := seedWiringCensus{bound: map[string]string{}, called: map[string]string{}}
	fset := token.NewFileSet()

	for _, name := range rootProdFiles(t) {
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			// Неразобранный файл — НАХОДКА, а не молчание: вердикт по нему не
			// выносится, и сказать это надо отказом, а не строкой журнала.
			t.Fatalf("%s не разобран: %v — непрочитанное есть находка", name, err)
		}
		census.filesRead++

		ast.Inspect(file, func(n ast.Node) bool {
			// Связывание: `x := moduleseed.NewApplier(...)`.
			if assign, ok := n.(*ast.AssignStmt); ok {
				for i, rhs := range assign.Rhs {
					call, isCall := rhs.(*ast.CallExpr)
					if !isCall || i >= len(assign.Lhs) {
						continue
					}
					sel, isSel := call.Fun.(*ast.SelectorExpr)
					if !isSel || sel.Sel.Name != "NewApplier" {
						continue
					}
					pkg, isIdent := sel.X.(*ast.Ident)
					if !isIdent || pkg.Name != "moduleseed" {
						continue
					}
					if lhs, isIdent := assign.Lhs[i].(*ast.Ident); isIdent {
						census.bound[lhs.Name] = fset.Position(call.Pos()).String()
					}
				}
			}
			// Вызов: `applyDeliveredModuleSeed(..., x, ...)`.
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			census.callsSeen++
			fn, isIdent := call.Fun.(*ast.Ident)
			if !isIdent || fn.Name != "applyDeliveredModuleSeed" {
				return true
			}
			for _, arg := range call.Args {
				if id, isIdent := arg.(*ast.Ident); isIdent {
					census.called[id.Name] = fset.Position(call.Pos()).String()
				}
			}
			return true
		})
	}
	return census
}

// TestIAM2452_SeedApplierBuiltByTheRootIsAlsoCalledByIt — часть A.
func TestIAM2452_SeedApplierBuiltByTheRootIsAlsoCalledByIt(t *testing.T) {
	c := seedApplierWiring(t)
	t.Logf("перепись: прод-файлов корня прочитано %d · вызовов осмотрено %d · "+
		"связываний применителя посева %d · вызовов применения %d",
		c.filesRead, c.callsSeen, len(c.bound), len(c.called))

	if c.filesRead == 0 || c.callsSeen == 0 {
		t.Fatal("обход не прочитал ни одного файла либо не нашёл ни одного вызова — " +
			"вердикт беспредметен")
	}
	if len(c.bound) == 0 {
		t.Fatal("композиционный корень НЕ СТРОИТ применитель посева: служебные учётки модулей " +
			"платформы сняты миграцией, и производителя у них не осталось ни одного (kacho#2452)")
	}
	for name, at := range c.bound {
		if _, called := c.called[name]; !called {
			t.Errorf("применитель посева связан в %s (%s) и НЕ ПОЗВАН: он написан, доказан "+
				"пробами против живой базы — и не производит ничего. Установка платформы "+
				"поднимется без личностей своих модулей, а снаружи это неотличимо от "+
				"«сосед недоступен» (kacho#2452)", name, at)
		}
	}
}

// seedOrderAnchors — где на пути старта стоят доставка, применение ролей и
// применение посева.
type seedOrderAnchors struct {
	callsSeen                   int
	delivery, roles, seed       token.Pos
	deliveryAt, rolesAt, seedAt string
}

func bootSeedOrderAnchors(fset *token.FileSet, file *ast.File) seedOrderAnchors {
	var a seedOrderAnchors
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		a.callsSeen++
		fn, isIdent := call.Fun.(*ast.Ident)
		if !isIdent {
			return true
		}
		switch fn.Name {
		case "loadDeliveredManifests":
			if !a.delivery.IsValid() {
				a.delivery, a.deliveryAt = call.Pos(), fset.Position(call.Pos()).String()
			}
		case "applyDeliveredModuleRoles":
			if !a.roles.IsValid() {
				a.roles, a.rolesAt = call.Pos(), fset.Position(call.Pos()).String()
			}
		case "applyDeliveredModuleSeed":
			if !a.seed.IsValid() {
				a.seed, a.seedAt = call.Pos(), fset.Position(call.Pos()).String()
			}
		}
		return true
	})
	return a
}

// TestIAM2452_ServeAppliesModuleSeedAfterModuleRoles — часть B.
func TestIAM2452_ServeAppliesModuleSeedAfterModuleRoles(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(".", "serve.go"), nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("serve.go не разобран: %v — непрочитанное есть находка", err)
	}
	a := bootSeedOrderAnchors(fset, file)
	t.Logf("осмотрено вызовов в serve.go: %d · доставка %q · роли %q · посев %q",
		a.callsSeen, a.deliveryAt, a.rolesAt, a.seedAt)

	if a.callsSeen == 0 {
		t.Fatal("обход не нашёл ни одного вызова — вердикт беспредметен")
	}
	if !a.delivery.IsValid() {
		t.Fatal("serve.go не зовёт loadDeliveredManifests — предпосылка проверки о порядке " +
			"исчезла, и порядок больше нечем судить")
	}
	if !a.roles.IsValid() {
		t.Fatal("serve.go не зовёт applyDeliveredModuleRoles — предпосылка проверки о порядке " +
			"исчезла, и порядок больше нечем судить")
	}
	if !a.seed.IsValid() {
		t.Fatal("serve.go НЕ ПРИМЕНЯЕТ посев доставленных манифестов: служебные учётки модулей " +
			"платформы сняты миграцией, и заводить их стало некому (kacho#2452)")
	}
	if a.seed < a.delivery {
		t.Errorf("применение посева стоит ПЕРЕД чтением доставки (%s против %s) — применять "+
			"нечего: манифесты ещё не прочитаны", a.seedAt, a.deliveryAt)
	}
	if a.seed < a.roles {
		t.Errorf("применение посева стоит ПЕРЕД применением ролей (%s против %s) — выдача "+
			"формой роли сослалась бы на строку, которой ещё нет, и отказ пришёл бы от "+
			"чужого ограничения, называя не тот предмет (kacho#2452)", a.seedAt, a.rolesAt)
	}
}
