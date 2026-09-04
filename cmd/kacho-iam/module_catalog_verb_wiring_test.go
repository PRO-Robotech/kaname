// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

// module_catalog_verb_wiring_test.go — гейт провязки ВТОРОГО вызывающего
// применителя каталога (задача продукта #1034, О10).
//
// # Почему он заведён отдельно, а не дописан в соседний
//
// Соседний гейт (`module_catalog_apply_wiring_test.go`) судит применитель ПУТИ
// СТАРТА и называет свою границу дословно: применитель, переданный ЧУЖОМУ
// пакету, который позвал бы применение у себя, им не виден, «а появившись, она
// обязана быть учтена своим изменением». Ровно эта форма и появилась:
// композиционный корень строит ГЛАГОЛЬНЫЙ применитель и передаёт его use-case
// службы `InternalModuleService`, который зовёт применение у себя.
//
// Гейты требуются ОБА, а не один вместо другого: путь старта и глагол — разные
// вызывающие одного механизма, и снятие любого из двух обязано быть находкой.
//
// # Что судится, и почему двух шагов мало
//
// Гейт, довольствующийся «применитель кому-то передан», молчал бы на
// посреднике-пустышке — то есть на глаголе, который по-прежнему не позван.
// Поэтому свойство состоит из ДВУХ половин, и обе измеряются, а не
// подразумеваются:
//
//	A. КОРЕНЬ передаёт связанный `NewVerbApplier` в вызов ПАКЕТА-ПОТРЕБИТЕЛЯ;
//	B. ПАКЕТ-ПОТРЕБИТЕЛЬ действительно применяет — зовёт `Apply` на значении,
//	   объявленном ПОРТОМ применителя, а не на чём попало с подходящим именем
//	   метода.
//
// Требование к ТИПУ во второй половине — не педантизм: без него за применение
// сошёл бы всякий вызов `Apply` в пакете-потребителе, в том числе на репозитории,
// на клиенте соседа и на собственном use-case.
//
// # Перепись печатается ВСЕГДА
//
// «Ноль находок» обязано быть отличимо от «ноль прочитанного»: обход, не
// разобравший ни одного файла корня либо ни одного файла потребителя, есть
// ОТКАЗ, а не молчаливый успех.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/internal/treecorpus"
)

// moduleVerbApplierCtor — конструктор ГЛАГОЛЬНОГО применителя. Отличается от
// стартового ТИПОМ, а не флагом: он сверяет опору безусловно и требует
// подтверждения с потолками, поэтому подать один вместо другого невозможно.
const moduleVerbApplierCtor = "NewVerbApplier"

// moduleVerbConsumerPkg — пакет-потребитель: use-case четырёх глаголов.
const moduleVerbConsumerPkg = "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/module"

// moduleVerbApplierPort — имя ПОРТА применителя в пакете-потребителе. Именно на
// значении этого типа обязан быть позван `Apply`.
const moduleVerbApplierPort = "CatalogApplier"

// moduleVerbApplyMethod — метод, которым глагол применяет.
const moduleVerbApplyMethod = "Apply"

// verbWiringCensus — объём осмотренного; печатается на всяком исходе.
type verbWiringCensus struct {
	RootFiles      int
	RootParsed     int
	ConsumerFiles  int
	ConsumerParsed int
	PortNames      int
	ConsumerApply  int
	Built          int
	HandedOff      int
}

func (c verbWiringCensus) Summary() string {
	return fmt.Sprintf("прод-файлов корня %d (разобрано %d) · файлов потребителя %d "+
		"(разобрано %d) · имён порта %d · вызовов применения у потребителя %d · "+
		"глагольных применителей построено %d · передач потребителю %d",
		c.RootFiles, c.RootParsed, c.ConsumerFiles, c.ConsumerParsed,
		c.PortNames, c.ConsumerApply, c.Built, c.HandedOff)
}

// consumerApplies — половина B: пакет-потребитель зовёт применение на значении
// ПОРТА применителя.
//
// Возвращает число таких вызовов и число имён, объявленных портом: обе величины
// входят в перепись, потому что ноль у каждой означает РАЗНОЕ — «порт исчез» и
// «порт есть, применения нет».
func consumerApplies(files []string) (portNames map[string]bool, applyCalls, parsedN int, err error) {
	portNames = make(map[string]bool)
	fset := token.NewFileSet()
	var parsed []*ast.File
	for _, path := range files {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil, 0, 0, fmt.Errorf("разобрать %s: %w", path, perr)
		}
		parsed = append(parsed, file)
	}

	// Шаг 1: имена, ОБЪЯВЛЕННЫЕ портом применителя — поля структур и параметры.
	for _, file := range parsed {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.StructType:
				for _, field := range x.Fields.List {
					if id, ok := field.Type.(*ast.Ident); ok && id.Name == moduleVerbApplierPort {
						for _, name := range field.Names {
							portNames[name.Name] = true
						}
					}
				}
			case *ast.FuncDecl:
				if x.Type.Params == nil {
					return true
				}
				for _, field := range x.Type.Params.List {
					if id, ok := field.Type.(*ast.Ident); ok && id.Name == moduleVerbApplierPort {
						for _, name := range field.Names {
							portNames[name.Name] = true
						}
					}
				}
			}
			return true
		})
	}

	// Шаг 2: вызовы применения НА ЭТИХ именах.
	for _, file := range parsed {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != moduleVerbApplyMethod {
				return true
			}
			switch recv := sel.X.(type) {
			case *ast.Ident:
				// `applier.Apply(…)` — применение на параметре.
				if portNames[recv.Name] {
					applyCalls++
				}
			case *ast.SelectorExpr:
				// `uc.applier.Apply(…)` — применение на поле.
				if portNames[recv.Sel.Name] {
					applyCalls++
				}
			}
			return true
		})
	}
	return portNames, applyCalls, len(parsed), nil
}

// verbApplierWiring — половина A: связывания глагольного применителя в корне и
// то, переданы ли они пакету-потребителю.
func verbApplierWiring(root string, rootFiles []string) (
	built []applierBinding, handed map[string]bool, files, parsedN int, handedN int, err error,
) {
	handed = make(map[string]bool)
	fset := token.NewFileSet()
	for _, path := range rootFiles {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		files++
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil, nil, files, parsedN, handedN, fmt.Errorf("разобрать %s: %w", path, perr)
		}
		parsedN++
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)

		// Псевдоним импорта учитывается у ОБОИХ пакетов: гейт, знающий одно
		// написание, молчал бы на форме столь же законной.
		catalogLocal := localNameOfImport(file, moduleCatalogPkgPath, "modulecatalog")
		consumerLocal := localNameOfImport(file, moduleVerbConsumerPkg, "module")

		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				if catalogLocal == "" || len(x.Rhs) != 1 || len(x.Lhs) == 0 {
					return true
				}
				call, ok := x.Rhs[0].(*ast.CallExpr)
				if !ok || !isSelector(call.Fun, catalogLocal, moduleVerbApplierCtor) {
					return true
				}
				id, ok := x.Lhs[0].(*ast.Ident)
				if !ok || id.Name == "_" {
					return true
				}
				built = append(built, applierBinding{
					Name: id.Name, File: rel, Line: fset.Position(id.Pos()).Line,
				})
			case *ast.CallExpr:
				if consumerLocal == "" {
					return true
				}
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != consumerLocal {
					return true
				}
				for _, arg := range x.Args {
					id, ok := arg.(*ast.Ident)
					if !ok {
						continue
					}
					handedN++
					handed[id.Name] = true
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
	return built, handed, files, parsedN, handedN, nil
}

// TestIAM1034_VerbApplierBuiltByTheRootIsHandedToAConsumerThatApplies — гейт О10.
func TestIAM1034_VerbApplierBuiltByTheRootIsHandedToAConsumerThatApplies(t *testing.T) {
	root := iamServiceRoot(t)

	rootFiles, err := treecorpus.UnderWithSuffix(filepath.Join(root, "cmd"), ".go")
	if err != nil {
		t.Fatalf("перечень файлов композиционного корня: %v", err)
	}
	consumerFiles, err := treecorpus.UnderWithSuffix(
		filepath.Join(root, "internal", "apps", "kacho", "api", "module"), ".go")
	if err != nil {
		t.Fatalf("перечень файлов пакета-потребителя: %v", err)
	}

	built, handed, files, parsedN, handedN, err := verbApplierWiring(root, rootFiles)
	if err != nil {
		t.Fatalf("%v", err)
	}
	portNames, applyCalls, consumerParsed, cerr := consumerApplies(consumerFiles)
	if cerr != nil {
		t.Fatalf("%v", cerr)
	}
	census := verbWiringCensus{
		RootFiles: files, RootParsed: parsedN,
		ConsumerFiles: len(consumerFiles), ConsumerParsed: consumerParsed,
		PortNames: len(portNames), ConsumerApply: applyCalls,
		Built: len(built), HandedOff: handedN,
	}
	t.Logf("%s", census.Summary())

	if parsedN == 0 {
		t.Fatalf("обход не разобрал НИ ОДНОГО прод-файла корня — вердикт беспредметен "+
			"(корень %s)", root)
	}
	if consumerParsed == 0 {
		t.Fatalf("обход не разобрал НИ ОДНОГО прод-файла пакета-потребителя %s "+
			"(файлов найдено %d) — вердикт беспредметен: половина B гейта ни о чём "+
			"не утверждала бы", moduleVerbConsumerPkg, len(consumerFiles))
	}
	if len(built) == 0 {
		t.Fatalf("композиционный корень НЕ СТРОИТ глагольного применителя вовсе "+
			"(разобрано %d файлов) — служба `InternalModuleService` смонтирована, а "+
			"применять ей нечем (kacho#1034, О10)", parsedN)
	}
	if applyCalls == 0 {
		t.Fatalf("пакет-потребитель НЕ ЗОВЁТ применение на значении порта `%s` "+
			"(имён порта %d) — применитель передан посреднику-пустышке: он построен, "+
			"передан и по-прежнему не позван", moduleVerbApplierPort, len(portNames))
	}

	for _, b := range built {
		if handed[b.Name] {
			continue
		}
		t.Errorf("%s:%d — глагольный применитель `%s` построен и НЕ передан пакету "+
			"`%s`: глагол службы применять нечем, и это тот же мёртвый глагол, только "+
			"с конструктором (kacho#1034, О10)",
			b.File, b.Line, b.Name, moduleVerbConsumerPkg)
	}
}
