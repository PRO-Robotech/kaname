// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// producer_has_a_caller_test.go — ПРОБА ПАКЕТА: у производителя величины есть
// вызывающий (kacho#2638).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Сосед (`closed_label_sets_test.go`) держит обратную сторону одного предмета:
// семейство с закрытым набором заводит свои клетки нулём, чтобы «механизм не
// провязан» было отличимо от «провязан и не сработал». Здесь — та же пара, с
// другого конца: провязать нечего, если РЯДА НЕТ ВОВСЕ, потому что метод,
// которым семейство наполняется, не зовёт никто.
//
// Такое семейство хуже отсутствующего. Оно зарегистрировано, оно есть в выдаче
// реестра, его текст помощи перечисляет исходы — и не получит ни одной строки
// ни при каком поведении продукта. Читатель панели прочтёт пустоту как «сюда не
// обращались», а руководство по разбору отправит дежурного смотреть ряд,
// которого не бывает.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОПУЛЯЦИЯ — МЕТОДЫ ФАСАДА, И ГРАНИЦА НАЗВАНА ВСЛУХ
//
// Судятся методы `*Registry` — фасада величин, который этот модуль зовёт САМ:
// пакет внутренний, снаружи модуля держать фасад некому by construction,
// поэтому «ноль вызывающих в дереве» здесь означает «ноль вызывающих вообще».
//
// Методы типов-ДОКЛАДЧИКОВ (`*OutboxRecorder`, `*LRORecorder` и прочие) из
// популяции исключены, и это не послабление, а предпосылка: докладчик отдаётся
// фундаменту интерфейсом, и зовут его ИЗ ДРУГОГО МОДУЛЯ — обход этого дерева
// такого вызова не видит. Замер 2026-09-13: без исключения находок 14, из них
// 13 — ровно такие докладчики (`SetBacklogDepth`, `IncOrphansRecovered`, …),
// то есть прибор, у которого почти все находки ложные.
//
// ─────────────────────────────────────────────────────────────────────────────
// ССЫЛКА СЧИТАЕТСЯ ПО УЗЛУ, А НЕ ПО ПОДСТРОКЕ
//
// Имя метода встречается в прозе шапок этого пакета десятками раз — предикат по
// тексту краснел бы на собственном объяснении проверяемого. Поэтому считаются
// узлы-идентификаторы разобранного дерева, а объявления вычитаются: вызов
// `r.ObserveX(…)` и значение метода `reg.ObserveX`, переданное дальше, оба дают
// идентификатор, а комментарий не даёт ни одного.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// metricProducer — метод фасада, ТРОГАЮЩИЙ величину.
type metricProducer struct {
	File string
	Line int
	Name string
}

// producerVerbs — обращения к величине. Набор закрыт и перечислен здесь, потому
// что распознаватель обязан говорить о том, чего он не знает: форма, которой
// здесь нет, делает метод не-производителем, и он выпадает из наблюдения.
var producerVerbs = map[string]bool{
	"WithLabelValues": true,
	"Observe":         true,
	"Inc":             true,
	"Dec":             true,
	"Set":             true,
	"Add":             true,
}

// producerCensus — объём осмотренного; печатается ВСЕГДА.
type producerCensus struct {
	PkgFiles    int
	Parsed      int
	Methods     int // объявлений с получателем вообще
	Producers   int // из них методы фасада, трогающие величину
	OffFacade   int // методы-докладчики, исключённые предпосылкой
	ModuleFiles int
	Findings    int
}

func (c producerCensus) Summary() string {
	return fmt.Sprintf(
		"прод-файлов пакета %d · разобрано %d · методов %d · из них производителей фасада %d · "+
			"методов докладчиков вне популяции %d · прод-файлов модуля %d · находок %d",
		c.PkgFiles, c.Parsed, c.Methods, c.Producers, c.OffFacade, c.ModuleFiles, c.Findings)
}

// facadeType — тип, чьи методы судятся. Имя одно и стоит здесь, а не у каждого
// сравнения: два места об одном предмете разошлись бы при переименовании.
const facadeType = "Registry"

// scanRegistryProducers разбирает перечень файлов и отдаёт методы фасада,
// трогающие величину.
//
// Состав приходит ПАРАМЕТРОМ: в живом дереве его даёт каталог пакета, а инъекция
// подаёт синтетический — доказательство, требующее испортить рабочую копию, в
// конвейере не исполняется никогда.
func scanRegistryProducers(files []string) (prods []metricProducer, c producerCensus, err error) {
	fset := token.NewFileSet()
	for _, path := range files {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		c.PkgFiles++
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil, c, fmt.Errorf("разобрать %s: %w", path, perr)
		}
		c.Parsed++
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil || fd.Recv == nil {
				continue
			}
			c.Methods++
			if !touchesAMetric(fd.Body) {
				continue
			}
			if receiverTypeName(fd) != facadeType {
				c.OffFacade++
				continue
			}
			c.Producers++
			prods = append(prods, metricProducer{
				File: filepath.Base(path),
				Line: fset.Position(fd.Pos()).Line,
				Name: fd.Name.Name,
			})
		}
	}
	sort.Slice(prods, func(i, j int) bool { return prods[i].Name < prods[j].Name })
	return prods, c, nil
}

// touchesAMetric — есть ли в теле обращение к величине.
func touchesAMetric(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && producerVerbs[sel.Sel.Name] {
			found = true
		}
		return true
	})
	return found
}

// receiverTypeName — имя типа получателя, со звездой и без.
func receiverTypeName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	t := fd.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// referencesByName считает УПОМИНАНИЯ имён узлами разобранного дерева и
// отдельно — объявления функций с этими именами.
//
// Вычитание одного из другого и есть число вызывающих: объявление метода даёт
// свой идентификатор ровно один раз, а всякое иное упоминание имени — это либо
// вызов, либо значение метода, переданное дальше. Оба нас устраивают: и то и
// другое означает, что производителя кто-то держит.
func referencesByName(files []string) (refs, decls map[string]int, err error) {
	refs, decls = map[string]int{}, map[string]int{}
	fset := token.NewFileSet()
	for _, path := range files {
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil, nil, fmt.Errorf("разобрать %s: %w", path, perr)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.FuncDecl:
				decls[v.Name.Name]++
			case *ast.Ident:
				refs[v.Name]++
			}
			return true
		})
	}
	return refs, decls, nil
}

// TestIAM2638_EveryDeclaredMetricProducerHasACaller — гейт задачи #2638.
func TestIAM2638_EveryDeclaredMetricProducerHasACaller(t *testing.T) {
	pkgFiles, err := packageGoFiles(".")
	if err != nil {
		t.Fatalf("перечень файлов пакета: %v", err)
	}
	prods, census, err := scanRegistryProducers(pkgFiles)
	if err != nil {
		t.Fatalf("%v", err)
	}
	root := moduleRootFromMetrics(t)
	moduleFiles, err := moduleProductionGoFiles(root)
	if err != nil {
		t.Fatalf("перечень прод-файлов модуля: %v", err)
	}
	census.ModuleFiles = len(moduleFiles)
	refs, decls, err := referencesByName(moduleFiles)
	if err != nil {
		t.Fatalf("%v", err)
	}

	var dead []metricProducer
	for _, p := range prods {
		if refs[p.Name]-decls[p.Name] == 0 {
			dead = append(dead, p)
		}
	}
	census.Findings = len(dead)
	defer func() { t.Logf("%s", census.Summary()) }()

	if census.Parsed == 0 {
		t.Fatalf("обход не разобрал НИ ОДНОГО прод-файла пакета величин — вердикт " +
			"беспредметен: «ноль находок» неотличимо от «ноль прочитанного»")
	}
	if census.ModuleFiles == 0 {
		t.Fatalf("обход модуля не дал НИ ОДНОГО прод-файла (корень %s) — считать "+
			"вызывающих не по чему, и каждый производитель выглядел бы мёртвым", root)
	}
	if census.Producers == 0 {
		t.Fatalf("в пакете не найдено НИ ОДНОГО производителя фасада (методов осмотрено "+
			"%d) — это отказ РАЗБОРА, а не пакет без производителей: фасад величин без "+
			"единого обращения к величине не поднимается", census.Methods)
	}

	for _, p := range dead {
		t.Errorf("%s:%d — `%s.%s` не зовёт НИ ОДНО место модуля. Семейство, которое он "+
			"наполняет, зарегистрировано и не получит ни одной строки ни при каком "+
			"поведении продукта: читатель панели прочтёт пустоту как «сюда не "+
			"обращались», а руководство по разбору отправит дежурного смотреть ряд, "+
			"которого не бывает. Исходов ДВА: провязать производителя к тому, что он "+
			"измеряет, либо снять семейство ВМЕСТЕ с методом, его текстом помощи и "+
			"строками документации, которые на него ссылаются.",
			p.File, p.Line, facadeType, p.Name)
	}
}
