// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// module_roles_apply_wiring_test.go — гейт «применитель РОЛЕЙ, построенный
// композиционным корнем, им же и позван, и позван ПОСЛЕ стража паритета
// каталога» (задача продукта #2010).
//
// # Предмет
//
// Применитель ролей модуля написан, покрыт пробами против живой Postgres и
// прогоняется по всем шести манифестам сверкой `moduleroleparity` — а вызова на
// пути старта у него НЕТ. Замер на день заведения гейта:
// `git grep -rn 'moduleroles\.NewApplier' -- '*.go'` → пять вхождений, и все
// пять в `_test.go`. То есть раздел `roles:` манифеста в работающем процессе не
// применяет никто, и объявление роли до базы не доезжает.
//
// Это ровно класс мёртвого стража (`00-kacho-core` ban #16): применитель,
// которого не позвали, молчит так же уверенно, как записавший все строки, и
// отличить одно от другого нечем. Отличать надо не «применитель есть» от
// «применителя нет», а «вызов меняет состояние платформы» от «не меняет».
//
// # Гейт судит ДВА РАЗНЫХ факта, и ни один не выводится из другого
//
//	A. СВЯЗЫВАНИЕ → ВЫЗОВ. Идентификатор, связанный `moduleroles.NewApplier`,
//	   обязан быть получателем вызова применения где-то в прод-коде корня.
//
//	B. ПОРЯДОК на пути старта. Применение ролей в `serve.go` обязано стоять ПОСЛЕ
//	   стража паритета каталога — а значит и после применения каталога, которое
//	   страж собой замыкает.
//
// # Почему роли — ПОСЛЕ каталога, а не рядом с ним
//
// Правило роли ссылается на строки каталога КЛЮЧАМИ: `role_rule_ref_res_fk` на
// `(module, resource, live)` и `role_rule_ref_verb_fk`. Роль, применённая до
// каталога, писала бы проекцию сегментов на референт, которого ещё нет, — и
// падала бы отказом оператора базы, называющим чужое ограничение.
//
// Порядок сильнее: ПОСЛЕ СТРАЖА. Страж фейл-клоузед — он роняет пуск, когда
// каталог разошёлся с образом. Применить роли раньше него значило бы записать
// строки, ссылающиеся на каталог, который через строку будет отвергнут. Плюс
// каталожный факт для производителя правил берётся из ЖИВЫХ строк, прочитанных
// стражем: третьего чтения каталога на старте не заводится.
//
// # Границы, названные вслух
//
// Судится СВЯЗЫВАНИЕ и ВЫЗОВ в пределах прод-файлов композиционного корня.
// Применитель, переданный чужому пакету, который зовёт применение у себя, этим
// гейтом не виден; такой формы в дереве сегодня нет, а появившись, она обязана
// быть учтена своим изменением — как это уже произошло с глагольным
// применителем каталога (`module_catalog_verb_wiring_test.go`).
//
// О ЧИСЛЕ применённых манифестов и об исходе применения гейт не судит вовсе —
// это предмет проб применителя против живой базы, а не дерева.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// moduleRolesPkgPath — пакет применителя ролей.
const moduleRolesPkgPath = "github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"

// moduleRolesApplierCtor — конструктор применителя ролей.
const moduleRolesApplierCtor = "NewApplier"

// rolesApplierTypeName — тип применителя. Функция корня считается применяющей,
// только если она зовёт применение на параметре ИМЕННО этого типа: иначе за неё
// сошла бы всякая, у чьего аргумента нашёлся метод с подходящим именем.
const rolesApplierTypeName = "Applier"

// rolesApplyMethods — методы, которыми применитель ролей ПРИМЕНЯЕТ.
//
// Сегодня он несёт одно применение — `Apply` на одном манифесте; `ApplyAll` у
// него нет, и цикл по доставленным пишет корень. Набор объявлен здесь один раз и
// НЕ выведен из сегодняшней раскладки корня: появится `ApplyAll` — он законен, и
// гейт, знающий одно написание, молчал бы на форме столь же законной.
var rolesApplyMethods = map[string]bool{"Apply": true, "ApplyAll": true}

// rolesApplierBinding — идентификатор, связанный конструктором применителя.
type rolesApplierBinding struct {
	Name string
	File string
	Line int
}

// rolesWiringCensus — объём осмотренного; печатается ВСЕГДА, на всяком исходе.
type rolesWiringCensus struct {
	Files     int
	Parsed    int
	Built     int
	ApplyRcv  int
	ApplyFns  int
	HandedOff int
}

func (c rolesWiringCensus) Summary() string {
	return fmt.Sprintf("прод-файлов корня %d · разобрано %d · применителей ролей построено %d · "+
		"получателей вызова применения %d · функций-применителей %d · передач применителя %d",
		c.Files, c.Parsed, c.Built, c.ApplyRcv, c.ApplyFns, c.HandedOff)
}

// rolesApplierWiring разбирает перечень файлов корня и отвечает, у каких
// построенных применителей ролей применение действительно позвано.
//
// Два хопа — по той же причине, что у гейта каталога: корень строит применитель
// и ПЕРЕДАЁТ его функции провязки, которая зовёт применение. Гейт, сверяющий имя
// связанного идентификатора с именем получателя вызова, покраснел бы на этой
// законной раскладке, а починка свелась бы к переименованию переменной, — то
// есть он судил бы СОВПАДЕНИЕ ИМЁН, а не свойство.
func rolesApplierWiring(root string, files []string) (
	built []rolesApplierBinding, used map[string]bool, c rolesWiringCensus, err error,
) {
	type parsedFile struct {
		rel   string
		file  *ast.File
		local string
	}
	var parsed []parsedFile
	fset := token.NewFileSet()
	for _, path := range files {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		c.Files++
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil, nil, c, fmt.Errorf("разобрать %s: %w", path, perr)
		}
		c.Parsed++
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		parsed = append(parsed, parsedFile{
			rel:   filepath.ToSlash(rel),
			file:  file,
			local: localNameOfImport(file, moduleRolesPkgPath, "moduleroles"),
		})
	}

	// Шаг 1: функции корня, ЗОВУЩИЕ применение на своём параметре-применителе.
	applyingFuncs := make(map[string]bool)
	for _, pf := range parsed {
		if pf.local == "" {
			continue
		}
		for _, decl := range pf.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Type.Params == nil {
				continue
			}
			applierParams := make(map[string]bool)
			for _, field := range fn.Type.Params.List {
				star, ok := field.Type.(*ast.StarExpr)
				if !ok || !isSelector(star.X, pf.local, rolesApplierTypeName) {
					continue
				}
				for _, name := range field.Names {
					applierParams[name.Name] = true
				}
			}
			if len(applierParams) == 0 {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !rolesApplyMethods[sel.Sel.Name] {
					return true
				}
				recv, ok := sel.X.(*ast.Ident)
				if !ok || !applierParams[recv.Name] {
					return true
				}
				applyingFuncs[fn.Name.Name] = true
				return true
			})
		}
	}
	c.ApplyFns = len(applyingFuncs)

	// Шаг 2: связывания и то, чем они используются.
	used = make(map[string]bool)
	for _, pf := range parsed {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				// Связывание: `rolesApplier := moduleroles.NewApplier(…)`.
				if pf.local == "" || len(x.Rhs) != 1 || len(x.Lhs) == 0 {
					return true
				}
				call, ok := x.Rhs[0].(*ast.CallExpr)
				if !ok || !isSelector(call.Fun, pf.local, moduleRolesApplierCtor) {
					return true
				}
				id, ok := x.Lhs[0].(*ast.Ident)
				if !ok || id.Name == "_" {
					return true
				}
				c.Built++
				built = append(built, rolesApplierBinding{
					Name: id.Name, File: pf.rel, Line: fset.Position(id.Pos()).Line,
				})
			case *ast.CallExpr:
				// (i) применение на самом идентификаторе.
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok && rolesApplyMethods[sel.Sel.Name] {
					if recv, ok := sel.X.(*ast.Ident); ok {
						c.ApplyRcv++
						used[recv.Name] = true
					}
				}
				// (ii) передача в функцию корня, которая применяет.
				callee, ok := x.Fun.(*ast.Ident)
				if !ok || !applyingFuncs[callee.Name] {
					return true
				}
				for _, arg := range x.Args {
					id, ok := arg.(*ast.Ident)
					if !ok {
						continue
					}
					c.HandedOff++
					used[id.Name] = true
				}
			}
			return true
		})
	}

	sort.Slice(built, func(i, j int) bool {
		if built[i].File != built[j].File {
			return built[i].File < built[j].File
		}
		return built[i].Line < built[j].Line
	})
	return built, used, c, nil
}

// TestIAM2010_RolesApplierBuiltByTheRootIsAlsoCalledByIt — часть A гейта.
func TestIAM2010_RolesApplierBuiltByTheRootIsAlsoCalledByIt(t *testing.T) {
	root := iamServiceRoot(t)

	files, err := treecorpus.UnderWithSuffix(filepath.Join(root, "cmd"), ".go")
	if err != nil {
		t.Fatalf("перечень файлов композиционного корня: %v", err)
	}
	built, used, census, err := rolesApplierWiring(root, files)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("%s", census.Summary())

	if census.Parsed == 0 {
		t.Fatalf("обход не разобрал НИ ОДНОГО прод-файла композиционного корня — "+
			"вердикт беспредметен: «ноль находок» неотличимо от «ноль прочитанного» (корень %s)", root)
	}
	if census.Built == 0 {
		t.Fatalf("композиционный корень НЕ СТРОИТ применителя ролей вовсе "+
			"(разобрано %d файлов) — раздел `roles:` манифеста в работающем процессе не "+
			"применяет никто: объявление роли до базы не доезжает, и роли остаются тем, "+
			"что записала миграция (kacho#2010)", census.Parsed)
	}

	for _, b := range built {
		if used[b.Name] {
			continue
		}
		t.Errorf("%s:%d — применитель ролей `%s` построен и НЕ позван: без вызова "+
			"`%s.Apply(ctx, манифест)` объявленная манифестом роль остаётся объявлением "+
			"без производителя (kacho#2010)", b.File, b.Line, b.Name, b.Name)
	}
}

// rolesOrderAnchors — позиции опорных вызовов пути старта. Ноль означает
// «вызова нет».
type rolesOrderAnchors struct {
	Delivery  token.Pos // loadDeliveredManifests
	Parity    token.Pos // …AssertCatalogParity
	Roles     token.Pos // applyDeliveredModuleRoles
	CallsSeen int

	DeliveryAt string
	ParityAt   string
	RolesAt    string
}

// bootRolesOrderAnchors — где на пути старта стоят доставка, страж каталога и
// применение ролей.
//
// Разбор идёт по УЗЛУ ВЫЗОВА, а не по подстроке: имена всех трёх встречаются в
// комментариях этого же файла, и проверка по тексту краснела бы на собственном
// объяснении.
func bootRolesOrderAnchors(fset *token.FileSet, file *ast.File) rolesOrderAnchors {
	var a rolesOrderAnchors
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		a.CallsSeen++
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			switch fn.Name {
			case "loadDeliveredManifests":
				if !a.Delivery.IsValid() {
					a.Delivery = call.Pos()
					a.DeliveryAt = fset.Position(call.Pos()).String()
				}
			case "applyDeliveredModuleRoles":
				if !a.Roles.IsValid() {
					a.Roles = call.Pos()
					a.RolesAt = fset.Position(call.Pos()).String()
				}
			}
		case *ast.SelectorExpr:
			if fn.Sel.Name == "AssertCatalogParity" && !a.Parity.IsValid() {
				a.Parity = call.Pos()
				a.ParityAt = fset.Position(call.Pos()).String()
			}
		}
		return true
	})
	return a
}

// TestIAM2010_ServeAppliesModuleRolesAfterTheCatalogParityGuard — часть B.
//
// Порядок есть часть решения, а не оформление: правило роли ссылается на строки
// каталога ключами, а каталожный факт производителя правил берётся из ЖИВЫХ
// строк, прочитанных стражем. Применение ролей до стража записало бы проекцию
// сегментов на каталог, который через строку может быть отвергнут.
func TestIAM2010_ServeAppliesModuleRolesAfterTheCatalogParityGuard(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "serve.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("serve.go не разобран: %v — непрочитанное есть НАХОДКА", err)
	}
	a := bootRolesOrderAnchors(fset, file)
	t.Logf("осмотрено вызовов в serve.go: %d · доставка %q · страж каталога %q · роли %q",
		a.CallsSeen, a.DeliveryAt, a.ParityAt, a.RolesAt)

	if a.CallsSeen == 0 {
		t.Fatal("обход не нашёл ни одного вызова — вердикт беспредметен")
	}
	if !a.Delivery.IsValid() {
		t.Fatal("serve.go не зовёт loadDeliveredManifests — предпосылка проверки о порядке " +
			"исчезла, и порядок больше нечем судить")
	}
	if !a.Parity.IsValid() {
		t.Fatal("serve.go не зовёт AssertCatalogParity — предпосылка проверки о порядке " +
			"исчезла, и порядок больше нечем судить")
	}
	if !a.Roles.IsValid() {
		t.Fatal("serve.go НЕ ПРИМЕНЯЕТ роли доставленных манифестов: применитель ролей " +
			"написан, доказан пробами против живой базы и сверкой по всем манифестам — и не " +
			"позван ни разу. Роли остаются тем, что записала миграция, а раздел `roles:` " +
			"манифеста остаётся объявлением без производителя (kacho#2010)")
	}
	if a.Roles < a.Delivery {
		t.Errorf("применение ролей стоит ПЕРЕД чтением доставки (%s против %s) — применять "+
			"нечего: манифесты ещё не прочитаны", a.RolesAt, a.DeliveryAt)
	}
	if a.Roles < a.Parity {
		t.Errorf("применение ролей стоит ПЕРЕД стражем паритета каталога (%s против %s) — "+
			"проекция сегментов правила легла бы на строки каталога, которые страж ещё не "+
			"признал, а каталожный факт производителя правил брался бы из непроверенных "+
			"строк (kacho#2010)", a.RolesAt, a.ParityAt)
	}
}
