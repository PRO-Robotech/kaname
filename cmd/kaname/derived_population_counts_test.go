// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// derived_population_counts_test.go — ЧИСЛА О ПОПУЛЯЦИЯХ КОРНЯ ВЫВОДЯТСЯ, а не
// выписываются (kacho#2480, предикат 2).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// У числа в комментарии НЕТ ВЛАДЕЛЬЦА: оно стареет молча вместе с тем, из чего
// выведено, а следующий читатель чинит код под неверный текст. За один раунд
// класс воспроизвёлся семь раз; поверхностей было названо четыре при шести,
// очередей три при четырёх сканерах, и один из названных поимённо сканера не
// имел вовсе.
//
// Эта проба даёт читателю то, чего комментарий дать не может: ЖИВОЕ число,
// выведенное из дерева в момент чтения. Комментарии, которые называли числа,
// переписаны на ссылку сюда.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ЕЩЁ УТВЕРЖДАЕТСЯ, КРОМЕ ПЕРЕПИСИ
//
// Согласие двух объявлений поверхности: построенная обязана быть ОБСЛУЖЕННОЙ, и
// обслуживаемая — ПОСТРОЕННОЙ. Поверхность, собранная и не попавшая в срез
// подъёма, не поднимается вовсе — а посадка снаружи выглядит исправной: порт
// просто никто не слушает, и узнать об этом неоткуда, пока клиент не придёт.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТО НЕ СКАНЕР ПРОЗЫ, И ЭТО ИЗМЕРЕНО
//
// Соблазн — искать в комментариях числительное рядом со словом популяции и
// требовать совпадения. Подход ПРОВЕРЕН И ОТВЕРГНУТ: предикат «числительное +
// (поверхност|очеред|сканер|чекер) в пределах двух слов» по этому дереву даёт
// 76 попаданий, и подавляющее большинство — законная проза о ДРУГИХ популяциях
// («две поверхности об одном предмете расходятся молча», «три поверхности дерева
// требуют»). Прибор, у которого почти все находки ложные, перестают читать, а
// перестав читать — перестают видеть и настоящую.
//
// Поэтому судится ДЕРЕВО, а не проза: числа выводятся разбором узлов, и читатель
// получает их прогоном, а не чтением комментария.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

// populationCensus — объём осмотренного и три выведенных числа.
type populationCensus struct {
	Files             int
	Parsed            int
	SurfacesBuilt     int
	SurfacesServed    int
	GRPCListeners     int
	QueueScanners     int
	ReadinessCheckers int
}

func (c populationCensus) Summary() string {
	return fmt.Sprintf(
		"прод-файлов корня %d · разобрано %d · поверхностей построено %d · "+
			"обслуживается %d · gRPC-слушателей %d · сканеров очередей %d · "+
			"чекеров готовности %d",
		c.Files, c.Parsed, c.SurfacesBuilt, c.SurfacesServed, c.GRPCListeners,
		c.QueueScanners, c.ReadinessCheckers)
}

// countRootPopulations разбирает перечень файлов корня и выводит числа.
//
// Состав приходит ПАРАМЕТРОМ: в живом дереве его даёт обход корня, а инъекция
// подаёт синтетический.
func countRootPopulations(files []string) (c populationCensus, err error) {
	fset := token.NewFileSet()
	for _, path := range files {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		c.Files++
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return c, fmt.Errorf("разобрать %s: %w", path, perr)
		}
		c.Parsed++
		ast.Inspect(file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.CallExpr:
				switch fn := v.Fun.(type) {
				case *ast.Ident:
					if fn.Name == "iamHTTPSurface" {
						c.SurfacesBuilt++
					}
				case *ast.SelectorExpr:
					// Сканер состояния очереди: конструктор общего коллектора
					// фундамента. Пакет сверяется по ИМЕНИ ПСЕВДОНИМА, потому
					// что корень импортирует его под своим.
					if fn.Sel.Name == "NewCollector" {
						if id, ok := fn.X.(*ast.Ident); ok && id.Name == "outboxmetrics" {
							c.QueueScanners++
						}
					}
					// gRPC-слушатель: привязка сокета корнем. Число их тоже
					// НЕ выписывается — на нём стоит сверка перечня адресов,
					// который подаёт стражу проба боевого профиля.
					if fn.Sel.Name == "Listen" {
						if id, ok := fn.X.(*ast.Ident); ok && id.Name == "net" {
							c.GRPCListeners++
						}
					}
				}
			case *ast.AssignStmt:
				c.SurfacesServed += servedSurfacesIn(v)
				c.ReadinessCheckers += readinessCheckersIn(v)
			}
			return true
		})
	}
	return c, nil
}

// servedSurfacesIn — число элементов среза, который корень отдаёт петле подъёма
// поверхностей.
func servedSurfacesIn(assign *ast.AssignStmt) int {
	return litElementsOf(assign, "httpSurfaces")
}

// readinessCheckersIn — число объявленных зависимостей готовности.
func readinessCheckersIn(assign *ast.AssignStmt) int {
	return litElementsOf(assign, "readinessCheckers")
}

// litElementsOf — сколько элементов в составном литерале, связанном с именем.
func litElementsOf(assign *ast.AssignStmt, name string) int {
	if len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return 0
	}
	id, ok := assign.Lhs[0].(*ast.Ident)
	if !ok || id.Name != name {
		return 0
	}
	lit, ok := assign.Rhs[0].(*ast.CompositeLit)
	if !ok {
		return 0
	}
	return len(lit.Elts)
}

// TestIAM2480_DerivedPopulationCounts — перепись популяций корня и согласие двух
// объявлений поверхности.
func TestIAM2480_DerivedPopulationCounts(t *testing.T) {
	root := iamServiceRoot(t)
	files, err := treecorpus.UnderWithSuffix(filepath.Join(root, "cmd"), ".go")
	if err != nil {
		t.Fatalf("перечень файлов композиционного корня: %v", err)
	}
	census, err := countRootPopulations(files)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("%s", census.Summary())

	if census.Parsed == 0 {
		t.Fatalf("обход не разобрал НИ ОДНОГО прод-файла корня — вердикт беспредметен: "+
			"«ноль находок» неотличимо от «ноль прочитанного» (корень %s)", root)
	}
	for _, p := range []struct {
		name string
		got  int
		why  string
	}{
		{"поверхностей построено", census.SurfacesBuilt,
			"распознаватель построения поверхностей мёртв: он ищет вызовы `iamHTTPSurface`"},
		{"поверхностей обслуживается", census.SurfacesServed,
			"распознаватель среза подъёма мёртв: он ищет связывание `httpSurfaces`"},
		{"сканеров очередей", census.QueueScanners,
			"распознаватель сканеров мёртв: он ищет вызовы конструктора коллектора очередей"},
		{"чекеров готовности", census.ReadinessCheckers,
			"распознаватель чекеров мёртв: он ищет связывание `readinessCheckers`"},
		{"gRPC-слушателей", census.GRPCListeners,
			"распознаватель слушателей мёртв: он ищет вызовы `net.Listen`"},
	} {
		if p.got == 0 {
			t.Fatalf("популяция %q выведена НУЛЁМ — %s. Ноль здесь означает отказ "+
				"РАЗБОРА, а не пустую популяцию: корень без поверхностей не поднимается",
				p.name, p.why)
		}
	}
	if census.SurfacesBuilt != census.SurfacesServed {
		t.Errorf("построено поверхностей %d, обслуживается %d — согласие двух объявлений "+
			"нарушено. Построенная и не попавшая в срез подъёма поверхность НЕ ПОДНИМАЕТСЯ "+
			"вовсе, а посадка снаружи выглядит исправной: порт просто никто не слушает, и "+
			"узнать об этом неоткуда, пока не придёт клиент.",
			census.SurfacesBuilt, census.SurfacesServed)
	}
}
