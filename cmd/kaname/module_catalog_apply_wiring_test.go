// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// module_catalog_apply_wiring_test.go — гейт «применитель каталога, ПОСТРОЕННЫЙ
// композиционным корнем, им же и ПОЗВАН, и позван МЕЖДУ доставкой и стражем
// паритета» (задача продукта #1034).
//
// # Предмет
//
// Применитель каталога — единственный писатель строк `kaname.catalog_*` в
// прод-коде. Пока его никто не зовёт, каталог наполняет ПОСЕВ МИГРАЦИИ, то есть
// объявленное манифестом состояние доезжает до базы только пересборкой образа
// (`//go:embed *.sql`). Замер на день заведения гейта: прод-файлов
// композиционного корня, знающих применитель, — НОЛЬ.
//
// Глагол, написанный и не позванный, отличается от отсутствующего одним: он
// покрыт пробами и потому выглядит работающим. Это ровно класс мёртвого стража
// (`00-kacho-core` ban #16): «поле есть» против «значение меняет исход старта».
//
// # Гейт судит ДВА РАЗНЫХ факта, и ни один не выводится из другого
//
//	A. СВЯЗЫВАНИЕ → ВЫЗОВ. Идентификатор, связанный `modulecatalog.NewApplier`,
//	   обязан быть получателем вызова применения где-то в прод-коде корня.
//	   Построенный и неиспользованный применитель — тот же мёртвый глагол, только
//	   с конструктором.
//
//	B. ПОРЯДОК на пути старта. Вызов применения в `serve.go` обязан стоять ПОСЛЕ
//	   чтения доставки и ПЕРЕД стражем паритета.
//
// Почему порядок — часть свойства, а не вкус, сказано в
// `services/iam/docs/engineering/architecture/module-catalog-applier-runs-at-boot.md`:
// страж, стоящий ПОСЛЕ применителя, судит то, что применитель ТОЛЬКО ЧТО
// записал, и потому ConfigMap в одиночку не вправе расширить каталог за пределы
// того, что знает образ. Переставь их — и страж будет судить посев, а продукт
// применителя не проверит никто.
//
// # Границы, названные вслух
//
// Судится СВЯЗЫВАНИЕ и ВЫЗОВ в пределах прод-файлов композиционного корня, и
// предмет здесь ОДИН — применитель ПУТИ СТАРТА (`modulecatalog.NewApplier`).
//
// Применитель, переданный чужому пакету, который зовёт применение у себя, этим
// гейтом не виден. Прежняя редакция добавляла «такой формы в дереве нет» — с
// 2026-09-03 это неверно: композиционный корень строит ГЛАГОЛЬНЫЙ применитель
// (`modulecatalog.NewVerbApplier`) и передаёт его use-case службы
// `InternalModuleService`. Обещание «а появившись, она обязана быть учтена своим
// изменением» исполнено: форму судит `module_catalog_verb_wiring_test.go`,
// заведённый тем же изменением, что и провязка. Гейта ДВА, и требуются оба —
// снятие любого из двух вызовов есть находка.
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
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// moduleCatalogPkgPath — пакет применителя каталога.
const moduleCatalogPkgPath = "github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"

// moduleCatalogApplierCtor — конструктор применителя.
const moduleCatalogApplierCtor = "NewApplier"

// applierTypeName — тип применителя. Функция корня считается применяющей, только
// если она зовёт применение на параметре ИМЕННО этого типа: иначе за неё сошла бы
// всякая, у чьего аргумента нашёлся метод с подходящим именем.
const applierTypeName = "Applier"

// applierApplyMethods — методы, которыми применитель ПРИМЕНЯЕТ.
//
// Их два, и оба законны: `ApplyAll` — то, чем корень применяет доставленное
// целиком, `Apply` — применение одного манифеста. Гейт, знающий одно написание,
// молчал бы на форме столь же законной; поэтому набор объявлен здесь один раз, а
// не выведен из сегодняшней раскладки корня.
var applierApplyMethods = map[string]bool{"ApplyAll": true, "Apply": true}

// applierBinding — идентификатор, связанный конструктором применителя.
type applierBinding struct {
	Name string
	File string
	Line int
}

// applierWiringCensus — объём осмотренного; печатается ВСЕГДА, на всяком исходе.
type applierWiringCensus struct {
	Files     int
	Parsed    int
	Built     int
	ApplyRcv  int
	ApplyFns  int
	HandedOff int
}

func (c applierWiringCensus) Summary() string {
	return fmt.Sprintf("прод-файлов корня %d · разобрано %d · применителей построено %d · "+
		"получателей вызова применения %d · функций-применителей %d · передач применителя %d",
		c.Files, c.Parsed, c.Built, c.ApplyRcv, c.ApplyFns, c.HandedOff)
}

// applierWiring разбирает ПЕРЕЧЕНЬ файлов композиционного корня и отвечает, у
// каких построенных применителей применение действительно позвано.
//
// # Почему двух шагов мало и зачем второй хоп
//
// Корень строит применитель и ПЕРЕДАЁТ его функции провязки, которая и зовёт
// применение. Гейт, сверяющий имя связанного идентификатора с именем получателя
// вызова, покраснел бы на этой — совершенно законной — раскладке, а починка
// свелась бы к переименованию переменной. Тогда он судил бы СОВПАДЕНИЕ ИМЁН, а не
// свойство.
//
// Поэтому применитель считается позванным, если он либо (i) сам получатель
// вызова применения, либо (ii) передан аргументом в функцию корня, которая зовёт
// применение НА СВОЁМ ПАРАМЕТРЕ типа `*<пакет>.Applier`. Требование к ТИПУ
// параметра — не педантизм: без него за функцию-применитель сошла бы всякая, у
// чьего аргумента нашёлся метод с таким именем, и посредник-пустышка прошёл бы.
//
// Состав приходит ПАРАМЕТРОМ: в живом дереве его даёт индекс git, а инъекция
// подаёт синтетический — доказательство, требующее испортить рабочую копию, в
// конвейере не исполняется никогда.
func applierWiring(root string, files []string) (
	built []applierBinding, used map[string]bool, c applierWiringCensus, err error,
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
			local: localNameOfImport(file, moduleCatalogPkgPath, "modulecatalog"),
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
				if !ok || !isSelector(star.X, pf.local, applierTypeName) {
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
				if !ok || !applierApplyMethods[sel.Sel.Name] {
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
				// Связывание: `catalogApplier := modulecatalog.NewApplier(…)`.
				if pf.local == "" || len(x.Rhs) != 1 || len(x.Lhs) == 0 {
					return true
				}
				call, ok := x.Rhs[0].(*ast.CallExpr)
				if !ok || !isSelector(call.Fun, pf.local, moduleCatalogApplierCtor) {
					return true
				}
				id, ok := x.Lhs[0].(*ast.Ident)
				if !ok || id.Name == "_" {
					return true
				}
				c.Built++
				built = append(built, applierBinding{
					Name: id.Name, File: pf.rel, Line: fset.Position(id.Pos()).Line,
				})
			case *ast.CallExpr:
				// (i) применение на самом идентификаторе.
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok && applierApplyMethods[sel.Sel.Name] {
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

// localNameOfImport — ЛОКАЛЬНОЕ имя пакета в этом файле; псевдоним учитывается,
// иначе форма `mc "…/modulecatalog"` осталась бы вне наблюдения.
func localNameOfImport(file *ast.File, pkgPath, defaultName string) string {
	for _, imp := range file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != pkgPath {
			continue
		}
		if imp.Name != nil {
			if imp.Name.Name == "_" || imp.Name.Name == "." {
				return ""
			}
			return imp.Name.Name
		}
		return defaultName
	}
	return ""
}

// TestIAM1034_CatalogApplierBuiltByTheRootIsAlsoCalledByIt — часть A гейта.
func TestIAM1034_CatalogApplierBuiltByTheRootIsAlsoCalledByIt(t *testing.T) {
	root := iamServiceRoot(t)

	files, err := treecorpus.UnderWithSuffix(filepath.Join(root, "cmd"), ".go")
	if err != nil {
		t.Fatalf("перечень файлов композиционного корня: %v", err)
	}
	built, used, census, err := applierWiring(root, files)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("%s", census.Summary())

	if census.Parsed == 0 {
		t.Fatalf("обход не разобрал НИ ОДНОГО прод-файла композиционного корня — "+
			"вердикт беспредметен: «ноль находок» неотличимо от «ноль прочитанного» (корень %s)", root)
	}
	if census.Built == 0 {
		t.Fatalf("композиционный корень НЕ СТРОИТ применителя каталога вовсе "+
			"(разобрано %d файлов) — строки `kaname.catalog_*` наполняет посев миграции, "+
			"то есть объявленное манифестом состояние доезжает до базы только пересборкой "+
			"образа; глагол написан и не позван (kacho#1034)", census.Parsed)
	}

	for _, b := range built {
		if used[b.Name] {
			continue
		}
		t.Errorf("%s:%d — применитель каталога `%s` построен и НЕ позван: без вызова "+
			"`%s.ApplyAll(ctx, манифесты)` каталог остаётся тем, что посеяла миграция, "+
			"а манифест — объявлением без производителя (kacho#1034)",
			b.File, b.Line, b.Name, b.Name)
	}
}

// applyOrderAnchors — позиции трёх опорных вызовов пути старта в разобранном
// файле. Ноль означает «вызова нет».
type applyOrderAnchors struct {
	Delivery   token.Pos // loadDeliveredManifests
	Apply      token.Pos // applyDeliveredManifests
	Parity     token.Pos // …AssertCatalogParity
	CallsSeen  int
	DeliveryAt string
	ApplyAt    string
	ParityAt   string
}

// bootOrderAnchors — где на пути старта стоят доставка, применение и страж.
//
// Разбор идёт по УЗЛУ ВЫЗОВА, а не по подстроке: имена всех трёх встречаются в
// комментариях этого же файла, и проверка по тексту краснела бы на собственном
// объяснении.
func bootOrderAnchors(fset *token.FileSet, file *ast.File) applyOrderAnchors {
	var a applyOrderAnchors
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
			case "applyDeliveredManifests":
				if !a.Apply.IsValid() {
					a.Apply = call.Pos()
					a.ApplyAt = fset.Position(call.Pos()).String()
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

// TestIAM1034_ServeAppliesManifestsBetweenDeliveryAndTheParityGuard — часть B.
//
// Порядок есть часть решения, а не оформление: страж, стоящий ПОСЛЕ применителя,
// судит то, что применитель только что записал, — значит ConfigMap в одиночку не
// вправе расширить каталог за пределы того, что знает образ. Переставленный, он
// судил бы посев, а продукт применителя не проверил бы никто.
func TestIAM1034_ServeAppliesManifestsBetweenDeliveryAndTheParityGuard(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "serve.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("serve.go не разобран: %v — непрочитанное есть НАХОДКА", err)
	}
	a := bootOrderAnchors(fset, file)
	t.Logf("осмотрено вызовов в serve.go: %d · доставка %q · применение %q · страж %q",
		a.CallsSeen, a.DeliveryAt, a.ApplyAt, a.ParityAt)

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
	if !a.Apply.IsValid() {
		t.Fatal("serve.go НЕ ПРИМЕНЯЕТ доставленные манифесты: применитель каталога " +
			"написан, доказан пробами против живой базы и не позван ни разу — каталог " +
			"наполняет посев миграции, а манифест остаётся объявлением без производителя " +
			"(kacho#1034)")
	}
	if a.Apply < a.Delivery {
		t.Errorf("применение стоит ПЕРЕД чтением доставки (%s против %s) — применять "+
			"нечего: манифесты ещё не прочитаны", a.ApplyAt, a.DeliveryAt)
	}
	if a.Apply > a.Parity {
		t.Errorf("применение стоит ПОСЛЕ стража паритета (%s против %s) — страж судил бы "+
			"ПОСЕВ, а строки, записанные применителем, не проверил бы никто; и ConfigMap "+
			"в одиночку получил бы право расширить каталог за пределы того, что знает образ",
			a.ApplyAt, a.ParityAt)
	}
}
