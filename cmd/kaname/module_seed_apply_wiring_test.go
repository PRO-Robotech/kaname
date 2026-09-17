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
// # Гейт судит ТРИ факта, и ни один не выводится из другого
//
//	A. СВЯЗЫВАНИЕ → ВЫЗОВ. Идентификатор, связанный `moduleseed.NewApplier`,
//	   обязан быть доводом вызова применения в прод-коде корня.
//
//	B. ПОРЯДОК на пути старта: доставка → применение ролей → применение посева.
//
//	C. СВОЙ МАНИФЕСТ — ОТДЕЛЬНЫМ ДОВОДОМ (приёмка MRW-1, Р3). Довод своего
//	   манифеста связан `loadOwnManifest`, довод доставки — `loadDeliveredManifests`,
//	   и это РАЗНЫЕ идентификаторы: подмешанный в перечень доставки манифест
//	   службы достался бы всем пяти потребителям перечня разом, а проба на
//	   исходе применения о радиусе не утверждает ничего — она зелена и тогда.
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
//
// Часть C судит ДОВОДЫ вызова, а не содержимое перечня: свой манифест, дописанный
// в перечень доставки отдельным присваиванием ДО вызова, гейту не виден — так
// проверено инъекцией (`deliveredManifests = append(deliveredManifests,
// ownManifest)` → зелёный), тогда как та же примесь выражением на месте вызова
// краснеет. Слепая зона названа, а не умолчана; форма в дереве не встречается.

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
	// called — идентификаторы, поданные доводом в `applyModuleSeed`.
	called map[string]string
	// callArgs — доводы вызова применения по позициям (идентификаторы либо "").
	callArgs []string
	// ownBound — идентификаторы, связанные `loadOwnManifest`.
	ownBound map[string]string
	// deliveredBound — идентификаторы, связанные `loadDeliveredManifests`.
	deliveredBound map[string]string
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
	census := seedWiringCensus{
		bound: map[string]string{}, called: map[string]string{},
		ownBound: map[string]string{}, deliveredBound: map[string]string{},
	}
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
			// Связывание: `x := moduleseed.NewApplier(...)`, `own, err :=
			// loadOwnManifest(...)`, `delivered, err := loadDeliveredManifests(...)`.
			if assign, ok := n.(*ast.AssignStmt); ok {
				for i, rhs := range assign.Rhs {
					call, isCall := rhs.(*ast.CallExpr)
					if !isCall || i >= len(assign.Lhs) {
						continue
					}
					lhs, isIdent := assign.Lhs[i].(*ast.Ident)
					if !isIdent {
						continue
					}
					at := fset.Position(call.Pos()).String()
					switch fn := call.Fun.(type) {
					case *ast.SelectorExpr:
						if pkg, ok := fn.X.(*ast.Ident); ok && pkg.Name == "moduleseed" && fn.Sel.Name == "NewApplier" {
							census.bound[lhs.Name] = at
						}
					case *ast.Ident:
						switch fn.Name {
						case "loadOwnManifest":
							census.ownBound[lhs.Name] = at
						case "loadDeliveredManifests":
							census.deliveredBound[lhs.Name] = at
						}
					}
				}
			}
			// Вызов: `applyModuleSeed(..., x, own, delivered)`.
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			census.callsSeen++
			fn, isIdent := call.Fun.(*ast.Ident)
			if !isIdent || fn.Name != "applyModuleSeed" {
				return true
			}
			census.callArgs = census.callArgs[:0]
			for _, arg := range call.Args {
				name := ""
				if id, isIdent := arg.(*ast.Ident); isIdent {
					name = id.Name
					census.called[id.Name] = fset.Position(call.Pos()).String()
				}
				census.callArgs = append(census.callArgs, name)
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

// Позиции доводов вызова применения посева: `applyModuleSeed(ctx, logger,
// applier, own, delivered)`. Названы числом здесь, а не выведены из сигнатуры:
// гейт читает узел вызова, и сигнатуры у него нет.
const (
	seedCallArgOwn       = 3
	seedCallArgDelivered = 4
)

// TestMRW1_OwnManifestReachesTheSeedApplierAsItsOwnArgument — часть C.
func TestMRW1_OwnManifestReachesTheSeedApplierAsItsOwnArgument(t *testing.T) {
	c := seedApplierWiring(t)
	t.Logf("перепись: прод-файлов корня прочитано %d · связываний своего манифеста %d · "+
		"связываний доставки %d · доводов вызова применения %d",
		c.filesRead, len(c.ownBound), len(c.deliveredBound), len(c.callArgs))

	if c.filesRead == 0 || c.callsSeen == 0 {
		t.Fatal("обход не прочитал ни одного файла либо не нашёл ни одного вызова — вердикт беспредметен")
	}
	if len(c.callArgs) == 0 {
		t.Fatal("композиционный корень НЕ ЗОВЁТ applyModuleSeed: свой манифест службы до применителя " +
			"посева не доезжает, и группа пишущих кортежи остаётся объявлением без производителя (kaname#106)")
	}
	if len(c.callArgs) <= seedCallArgDelivered {
		t.Fatalf("вызов applyModuleSeed несёт %d довод(ов), а свой манифест и доставка — позиции %d и %d",
			len(c.callArgs), seedCallArgOwn, seedCallArgDelivered)
	}
	own, delivered := c.callArgs[seedCallArgOwn], c.callArgs[seedCallArgDelivered]
	if own == "" || delivered == "" {
		t.Fatalf("доводы своего манифеста (%q) и доставки (%q) обязаны быть идентификаторами, "+
			"связанными загрузчиками корня, а не выражениями на месте", own, delivered)
	}
	if own == delivered {
		t.Fatalf("свой манифест и доставка поданы ОДНИМ доводом %q: манифест службы подмешан в перечень, "+
			"который читают пятеро потребителей старта (Р3)", own)
	}
	if _, ok := c.ownBound[own]; !ok {
		t.Errorf("довод своего манифеста %q не связан loadOwnManifest (связаны: %v)", own, keysOf(c.ownBound))
	}
	if _, ok := c.deliveredBound[own]; ok {
		t.Errorf("довод своего манифеста %q связан loadDeliveredManifests — доставка подана вместо своего", own)
	}
	if _, ok := c.deliveredBound[delivered]; !ok {
		t.Errorf("довод доставки %q не связан loadDeliveredManifests (связаны: %v)", delivered, keysOf(c.deliveredBound))
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
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
		case "applyModuleSeed":
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
		t.Fatal("serve.go НЕ ПРИМЕНЯЕТ посев (applyModuleSeed): служебные учётки модулей " +
			"платформы сняты миграцией, и заводить их стало некому (kacho#2452); группу службы " +
			"объявляет свой манифест, и производителя у неё тоже нет (kaname#106)")
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
