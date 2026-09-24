// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// envelope_composition_root.go — страж корня композиции: в не-тестовом дереве
// службы огибающую по потолку строит ОДНО место — композиционный корень, — и
// мера прогона в нём — мера настенных часов (приёмка Ф3, Р17 «Мера прогона»,
// Ф3-53 строка стража; заказ kaname#295).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Мера прогона — вход огибающей (`passwordverify.CostMeter`). В боевом корне её
// мерят настенные часы вокруг самого прогона (`WallClockCostMeter`); стоимость,
// назначенная числом, живёт только в пробах выбора потолка. Назначенная мера в
// не-тестовом файле довела бы число пробы туда, где платит вход, и исход входа
// снова стал бы отличим по времени; второе построение — вторая огибающая со
// своим потолком, которого полоса входа не читает. Оба пути компилируются, и
// ни одна проба огибающей их не видит: у проб своя огибающая.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЕДИНИЦА СЧЁТА — МЕСТО ПОСТРОЕНИЯ, УЗНАННОЕ РАЗБОРОМ
//
// Местом построения считается КАЖДАЯ форма, в которой огибающая появляется:
//
//	вызов конструктора        `pv.NewEnvelope` (…) под любым именем импорта
//	                          дома, при импорте с точкой и без квалификатора в
//	                          самом доме; в скобках — то же;
//	конструктор значением     `f := pv.NewEnvelope` — мера у места не видна;
//	значение мимо конструктора `pv.Envelope{…}`, `&pv.Envelope{…}`,
//	                          `new(pv.Envelope)`, `var e pv.Envelope`, поле и
//	                          элемент значения, приведение — огибающая без меры
//	                          либо с мерой, которой страж не видит; в доме — всякое
//	                          такое место вне тела конструктора.
//
// Тип огибающей за указателем (`*pv.Envelope`), в доводах и результатах функций и
// в получателе метода — не построение: значения он не заводит.
//
// Дом узнаётся по ПУТИ ИМПОРТА в каждом файле, а не по имени: пакет того же
// имени из другого пути — чужой, его конструктор построением не считается, а
// его мера на месте меры дома — иная мера.
//
// Мера судится у места вызова: довод конструктора, чья позиция ВЫВЕДЕНА из
// объявления (единственный параметр типа меры), обязан быть мерой настенных
// часов дома — селектором, в скобках либо приведением к типу меры. Всё иное —
// литерал функции, метод меры пробы, переменная, довод обёртки — иная мера.
// Обёртка, принимающая меру доводом и строящая огибающую внутри, краснеет
// консервативно: у места построения мера — идентификатор, и что в него
// положили, страж не прослеживает.
//
// ─────────────────────────────────────────────────────────────────────────────
// РЕАЛИЗАЦИЯ ПОРТА ВНЕ ДОМА
//
// Полоса входа принимает огибающую портом. Тип с методом `Admit`, отдающим
// `Admission` дома, — огибающая, которую страж не строит и чью меру не видит;
// вне типа огибающей дома это красное с координатой.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОСЫЛКА — ОТКАЗ, А НЕ МОЛЧАНИЕ
//
// Конструктор объявлен в доме ровно раз и несёт ровно один довод типа меры;
// мера настенных часов, тип огибающей и тип меры объявлены в доме; `go.mod`
// корня дерева называет модуль; корень композиции несёт не-тестовые файлы.
// Не держится — ErrEnvelopeRootPremise с тем, что не нашлось. Пустой обход —
// ErrEmptyTraversal. «Построений 0» — находка о дереве, а не отказ посылки.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦЫ, НАЗВАННЫЕ ВСЛУХ
//
//  1. Граница — РОД ФАЙЛА, суффикс `_test.go` (`ProductionGoFile`). Тег сборки
//     не читается: не-тестовый файл под `//go:build ignore` судится, помощник
//     пробы в не-тестовом файле краснеет по замыслу — Р17 проводит границу по
//     роду файла, а не по имени меры.
//  2. Единица — синтаксическое место. Второе построение во время работы через
//     то же место (цикл, двойной вызов сборщика корня) статически не видно.
//  3. Судится ИМЯ меры, а не её тело; тело меры корня держит проба огибающей
//     TestWallClockCostMeter_MeasuresTheWholeRunItCalls.
//  4. Не узнаются: огибающая, пронесённая копией значения (`*e` новой меры не
//     заводит), и порт, собранный встраиванием настоящей огибающей с подменой
//     одного метода, — второе требует вывода типов.
//  5. Область обхода — `OutsideTraversal`: не-тестовые файлы под её сегментами
//     не судятся, и перепись печатает их числом.
//  6. Состав — индекс git: файл, не внесённый в индекс, стражу невидим.
package check

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

// ErrEnvelopeRootPremise — посылка стража корня не держится: объявления, по
// которым он узнаёт построение и меру, не найдены либо неоднозначны.
var ErrEnvelopeRootPremise = errors.New("посылка стража корня композиции не держится")

// EnvelopeRootSpec — объявление предмета стража: где дом огибающей, где корень
// композиции и какими именами дом объявляет узнаваемое.
type EnvelopeRootSpec struct {
	// HomeDir — каталог дома огибающей от корня модуля; RootDir — каталог
	// композиционного корня службы.
	HomeDir, RootDir string
	// Constructor, EnvelopeType, MeterType, WallClock — конструктор, тип
	// огибающей, тип меры и мера настенных часов, объявленные домом.
	Constructor, EnvelopeType, MeterType, WallClock string
	// AdmitMethod, AdmissionType — метод допуска порта и тип его исхода.
	AdmitMethod, AdmissionType string
}

// EnvelopeCompositionRootSpec — предмет стража в этом дереве.
func EnvelopeCompositionRootSpec() EnvelopeRootSpec {
	return EnvelopeRootSpec{
		HomeDir: "internal/passwordverify", RootDir: "cmd/kaname",
		Constructor: "NewEnvelope", EnvelopeType: "Envelope", MeterType: "CostMeter",
		WallClock: "WallClockCostMeter", AdmitMethod: "Admit", AdmissionType: "Admission",
	}
}

// EnvelopeSiteForm — форма места построения огибающей.
type EnvelopeSiteForm string

const (
	// EnvelopeSiteCall — вызов конструктора: мера судится доводом.
	EnvelopeSiteCall EnvelopeSiteForm = "вызов конструктора"
	// EnvelopeSiteConstructorValue — конструктор взят значением: мера у места не видна.
	EnvelopeSiteConstructorValue EnvelopeSiteForm = "конструктор взят значением"
	// EnvelopeSiteBypass — значение типа огибающей мимо конструктора.
	EnvelopeSiteBypass EnvelopeSiteForm = "значение огибающей мимо конструктора"
)

// EnvelopeSite — место построения огибающей с координатой.
type EnvelopeSite struct {
	Rel  string
	Line int
	Form EnvelopeSiteForm
	// Expr — выражение места; Meter — довод меры (только у вызова).
	Expr, Meter string
	// WallClock — довод меры вызова есть мера настенных часов дома.
	WallClock bool
}

func (s EnvelopeSite) String() string {
	if s.Form == EnvelopeSiteCall {
		return fmt.Sprintf("%s:%d %s `%s`, мера `%s`", s.Rel, s.Line, s.Form, s.Expr, s.Meter)
	}
	return fmt.Sprintf("%s:%d %s `%s`", s.Rel, s.Line, s.Form, s.Expr)
}

// EnvelopePortImpl — тип, реализующий порт огибающей мимо её дома.
type EnvelopePortImpl struct {
	Rel      string
	Line     int
	Receiver string
}

// EnvelopeRootCensus — объём осмотренного и посылка, на которой стоит вердикт.
type EnvelopeRootCensus struct {
	// TreeFiles — файлов в составе дерева; ProductionGo — не-тестовых `.go` по
	// суффиксу; OutsideTraversal — из них вне области обхода; Examined — разобрано.
	TreeFiles, ProductionGo, OutsideTraversal, Examined int
	// ReferringHome — файлов дома и файлов, импортирующих дом.
	ReferringHome int
	// MeterParam — позиция довода меры у конструктора, с единицы.
	MeterParam int
	// ConstructorAt, WallClockAt — координаты объявлений в доме.
	ConstructorAt, WallClockAt string
}

func (c EnvelopeRootCensus) String() string {
	return fmt.Sprintf("файлов дерева %d · не-тестовых .go %d, из них вне области обхода %d · разобрано %d · "+
		"обращаются к дому %d · посылка: мера — довод №%d конструктора %s, мера настенных часов %s",
		c.TreeFiles, c.ProductionGo, c.OutsideTraversal, c.Examined, c.ReferringHome,
		c.MeterParam, c.ConstructorAt, c.WallClockAt)
}

// EnvelopeRootVerdict — исход стража: перепись, найденное и находки.
type EnvelopeRootVerdict struct {
	Census    EnvelopeRootCensus
	Sites     []EnvelopeSite
	PortImpls []EnvelopePortImpl
	Findings  []string
}

// Summary — перепись и найденное одной строкой вывода.
func (v EnvelopeRootVerdict) Summary() string {
	sites := make([]string, 0, len(v.Sites))
	for _, s := range v.Sites {
		sites = append(sites, s.String())
	}
	return fmt.Sprintf("%s · построений %d [%s] · реализаций порта вне дома %d · находок %d",
		v.Census, len(v.Sites), strings.Join(sites, "; "), len(v.PortImpls), len(v.Findings))
}

// JudgeEnvelopeCompositionRoot — вердикт стража по дереву.
func JudgeEnvelopeCompositionRoot(tree *treecorpus.Tree, spec EnvelopeRootSpec) (EnvelopeRootVerdict, error) {
	var v EnvelopeRootVerdict
	if tree == nil {
		return v, errors.New("дерево не передано: обход не с чего начинать")
	}
	v.Census.TreeFiles = tree.Count()
	for _, rel := range tree.SortedFiles() {
		if strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, "_test.go") {
			v.Census.ProductionGo++
			if OutsideTraversal(rel) {
				v.Census.OutsideTraversal++
			}
		}
	}
	corpus, err := CorpusFrom(tree, ProductionGoFile)
	if err != nil {
		return v, fmt.Errorf("не-тестовых файлов Go в области обхода 0 (по суффиксу %d, вне области %d): %w",
			v.Census.ProductionGo, v.Census.OutsideTraversal, err)
	}
	homeImport, err := envRootHomeImport(tree, spec)
	if err != nil {
		return v, err
	}

	fset := token.NewFileSet()
	files := make(map[string]*ast.File, len(corpus))
	rels := corpus.Rels()
	for _, rel := range rels {
		f, err := parser.ParseFile(fset, rel, corpus[rel], parser.SkipObjectResolution)
		if err != nil {
			return v, fmt.Errorf("разбор %s: %w — страж не вправе судить файл, которого не разобрал", rel, err)
		}
		files[rel] = f
		v.Census.Examined++
	}

	premise, err := envRootPremise(fset, files, rels, spec)
	if err != nil {
		return v, err
	}
	v.Census.MeterParam = premise.meterIndex + 1
	v.Census.ConstructorAt, v.Census.WallClockAt = premise.constructorAt, premise.wallClockAt

	for _, rel := range rels {
		f := files[rel]
		inHome := path.Dir(rel) == spec.HomeDir
		names, dot := envRootHomeNames(f, homeImport, premise.homePkg)
		if !inHome && len(names) == 0 && !dot {
			continue
		}
		v.Census.ReferringHome++
		r := &envRootResolver{spec: spec, names: names, unqualified: inHome || dot}
		v.Sites = append(v.Sites, r.sites(fset, rel, f, inHome, premise.meterIndex)...)
		v.PortImpls = append(v.PortImpls, r.portImpls(fset, rel, f, inHome)...)
	}
	v.Findings = envRootFindings(v, spec, premise.homePkg)
	return v, nil
}

// envRootHomeImport — путь импорта дома: модуль из `go.mod` корня дерева и
// каталог дома.
func envRootHomeImport(tree *treecorpus.Tree, spec EnvelopeRootSpec) (string, error) {
	if !tree.HasFile("go.mod") {
		return "", fmt.Errorf("%w: go.mod в составе дерева нет — путь импорта дома выводить не из чего", ErrEnvelopeRootPremise)
	}
	body, err := os.ReadFile(filepath.Join(tree.Root(), "go.mod")) // #nosec G304 -- путь от корня этого дерева
	if err != nil {
		return "", fmt.Errorf("%w: чтение go.mod: %v", ErrEnvelopeRootPremise, err)
	}
	module := modfile.ModulePath(body)
	if module == "" {
		return "", fmt.Errorf("%w: go.mod модуля не называет", ErrEnvelopeRootPremise)
	}
	return module + "/" + spec.HomeDir, nil
}

// envRootPremiseFacts — то, что посылка установила в доме.
type envRootPremiseFacts struct {
	homePkg                    string
	meterIndex                 int
	constructorAt, wallClockAt string
}

// envRootPremise — посылка стража по объявлениям дома и составу корня.
func envRootPremise(fset *token.FileSet, files map[string]*ast.File, rels []string, spec EnvelopeRootSpec) (envRootPremiseFacts, error) {
	var (
		p                              envRootPremiseFacts
		homeFiles, rootFiles           int
		constructors, wallClocks       []string
		meterParams                    int
		envelopeDeclared, meterDeclare bool
	)
	p.meterIndex = -1
	for _, rel := range rels {
		switch path.Dir(rel) {
		case spec.RootDir:
			rootFiles++
			continue
		case spec.HomeDir:
		default:
			continue
		}
		f := files[rel]
		homeFiles++
		if p.homePkg == "" {
			p.homePkg = f.Name.Name
		} else if f.Name.Name != p.homePkg {
			return p, fmt.Errorf("%w: в доме %s два имени пакета (%s, %s)", ErrEnvelopeRootPremise, spec.HomeDir, p.homePkg, f.Name.Name)
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv != nil {
					continue
				}
				at := fmt.Sprintf("%s:%d", rel, fset.Position(d.Pos()).Line)
				switch d.Name.Name {
				case spec.Constructor:
					constructors = append(constructors, at)
					index := 0
					for _, field := range d.Type.Params.List {
						width := max(len(field.Names), 1)
						if id, ok := field.Type.(*ast.Ident); ok && id.Name == spec.MeterType {
							meterParams += width
							p.meterIndex = index
						}
						index += width
					}
				case spec.WallClock:
					wallClocks = append(wallClocks, at)
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					ts, ok := s.(*ast.TypeSpec)
					if !ok {
						continue
					}
					switch ts.Name.Name {
					case spec.EnvelopeType:
						envelopeDeclared = true
					case spec.MeterType:
						meterDeclare = true
					}
				}
			}
		}
	}
	var missing []string
	if homeFiles == 0 {
		missing = append(missing, fmt.Sprintf("дом %s не-тестовых файлов не несёт", spec.HomeDir))
	}
	if len(constructors) != 1 {
		missing = append(missing, fmt.Sprintf("конструктор %s объявлен в доме %d раз(а) [%s], а не ровно один",
			spec.Constructor, len(constructors), strings.Join(constructors, ", ")))
	}
	if len(constructors) == 1 && meterParams != 1 {
		missing = append(missing, fmt.Sprintf("у конструктора %s доводов типа %s %d, а не ровно один — позицию меры выводить не из чего",
			spec.Constructor, spec.MeterType, meterParams))
	}
	if len(wallClocks) != 1 {
		missing = append(missing, fmt.Sprintf("мера настенных часов %s объявлена в доме %d раз(а), а не ровно один",
			spec.WallClock, len(wallClocks)))
	}
	if !envelopeDeclared {
		missing = append(missing, fmt.Sprintf("тип огибающей %s в доме не объявлен", spec.EnvelopeType))
	}
	if !meterDeclare {
		missing = append(missing, fmt.Sprintf("тип меры %s в доме не объявлен", spec.MeterType))
	}
	if rootFiles == 0 {
		missing = append(missing, fmt.Sprintf("корень композиции %s не-тестовых файлов не несёт", spec.RootDir))
	}
	if len(missing) > 0 {
		return p, fmt.Errorf("%w: %s", ErrEnvelopeRootPremise, strings.Join(missing, "; "))
	}
	p.constructorAt, p.wallClockAt = constructors[0], wallClocks[0]
	return p, nil
}

// envRootHomeNames — местные имена дома в файле (по пути импорта) и импорт с
// точкой. Импорт `_` имени не заводит.
func envRootHomeNames(f *ast.File, homeImport, homePkg string) (map[string]bool, bool) {
	names := map[string]bool{}
	dot := false
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != homeImport {
			continue
		}
		switch {
		case imp.Name == nil:
			names[homePkg] = true
		case imp.Name.Name == ".":
			dot = true
		case imp.Name.Name != "_":
			names[imp.Name.Name] = true
		}
	}
	return names, dot
}

// envRootResolver — узнавание имён дома в одном файле.
type envRootResolver struct {
	spec  EnvelopeRootSpec
	names map[string]bool
	// unqualified — имена дома пишутся без квалификатора: файл дома либо
	// импорт с точкой.
	unqualified bool
}

// homeName — имя дома, которое называет выражение (скобки сняты).
func (r *envRootResolver) homeName(e ast.Expr) (string, bool) {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			break
		}
		e = p.X
	}
	switch x := e.(type) {
	case *ast.SelectorExpr:
		if id, ok := x.X.(*ast.Ident); ok && r.names[id.Name] {
			return x.Sel.Name, true
		}
	case *ast.Ident:
		if r.unqualified {
			return x.Name, true
		}
	}
	return "", false
}

// isWallClock — довод меры есть мера настенных часов дома: селектор, в скобках
// либо приведённый к типу меры дома.
func (r *envRootResolver) isWallClock(e ast.Expr) bool {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
			continue
		case *ast.CallExpr:
			if name, ok := r.homeName(x.Fun); ok && name == r.spec.MeterType && len(x.Args) == 1 && !x.Ellipsis.IsValid() {
				e = x.Args[0]
				continue
			}
			return false
		}
		name, ok := r.homeName(e)
		return ok && name == r.spec.WallClock
	}
}

// sites — места построения огибающей в файле.
func (r *envRootResolver) sites(fset *token.FileSet, rel string, f *ast.File, inHome bool, meterIndex int) []EnvelopeSite {
	var out []EnvelopeSite
	at := func(n ast.Node) int { return fset.Position(n.Pos()).Line }
	w := &parentWalker{}
	w.visit = func(n ast.Node, parents []ast.Node) {
		var name string
		switch x := n.(type) {
		case *ast.SelectorExpr:
			id, ok := x.X.(*ast.Ident)
			if !ok || !r.names[id.Name] {
				return
			}
			name = x.Sel.Name
		case *ast.Ident:
			if !r.unqualified || envRootDeclaresOrSelects(x, parents) {
				return
			}
			name = x.Name
		default:
			return
		}
		expr := n.(ast.Expr)
		switch name {
		case r.spec.Constructor:
			child, parent := envRootUnparen(expr, parents)
			if call, ok := parent.(*ast.CallExpr); ok && call.Fun == child {
				site := EnvelopeSite{Rel: rel, Line: at(call), Form: EnvelopeSiteCall, Expr: types.ExprString(call.Fun), Meter: "<довода меры нет>"}
				if meterIndex < len(call.Args) && !call.Ellipsis.IsValid() {
					site.Meter = types.ExprString(call.Args[meterIndex])
					site.WallClock = r.isWallClock(call.Args[meterIndex])
				}
				out = append(out, site)
				return
			}
			out = append(out, EnvelopeSite{Rel: rel, Line: at(n), Form: EnvelopeSiteConstructorValue, Expr: types.ExprString(expr)})
		case r.spec.EnvelopeType:
			if inHome && envRootInsideConstructor(parents, r.spec.Constructor) {
				return
			}
			if !envRootMakesAValue(expr, parents) {
				return
			}
			text := types.ExprString(expr)
			child, parent := envRootUnparen(expr, parents)
			switch p := parent.(type) {
			case *ast.CompositeLit:
				if p.Type == child {
					text += "{…}"
				}
			case *ast.CallExpr:
				if id, ok := p.Fun.(*ast.Ident); ok && id.Name == "new" {
					text = "new(" + text + ")"
				}
			}
			out = append(out, EnvelopeSite{Rel: rel, Line: at(n), Form: EnvelopeSiteBypass, Expr: text})
		}
	}
	ast.Walk(w, f)
	return out
}

// portImpls — типы файла с методом допуска, отдающим исход допуска дома, кроме
// типа огибающей в самом доме.
func (r *envRootResolver) portImpls(fset *token.FileSet, rel string, f *ast.File, inHome bool) []EnvelopePortImpl {
	var out []EnvelopePortImpl
	for _, decl := range f.Decls {
		d, ok := decl.(*ast.FuncDecl)
		if !ok || d.Recv == nil || len(d.Recv.List) == 0 || d.Name.Name != r.spec.AdmitMethod || d.Type.Results == nil {
			continue
		}
		yields := false
		for _, res := range d.Type.Results.List {
			if name, ok := r.homeName(res.Type); ok && name == r.spec.AdmissionType {
				yields = true
			}
		}
		if !yields {
			continue
		}
		recv := envRootReceiverName(d.Recv.List[0].Type)
		if inHome && recv == r.spec.EnvelopeType {
			continue
		}
		out = append(out, EnvelopePortImpl{Rel: rel, Line: fset.Position(d.Pos()).Line, Receiver: recv})
	}
	return out
}

// envRootFindings — находки по найденному.
func envRootFindings(v EnvelopeRootVerdict, spec EnvelopeRootSpec, homePkg string) []string {
	var out []string
	switch n := len(v.Sites); {
	case n == 0:
		out = append(out, fmt.Sprintf("построений 0: в не-тестовом дереве огибающую не строит никто — ни корень %s, ни иное место "+
			"(разобрано %d, обращаются к дому %d); вызов конструктора снят либо спрятан формой, которой страж не знает",
			spec.RootDir, v.Census.Examined, v.Census.ReferringHome))
	case n > 1:
		sites := make([]string, 0, n)
		for _, s := range v.Sites {
			sites = append(sites, fmt.Sprintf("%s:%d", s.Rel, s.Line))
		}
		out = append(out, fmt.Sprintf("построений %d [%s]: огибающую строит одно место — композиционный корень %s; "+
			"вторая огибающая несёт свой потолок, которого полоса входа не читает", n, strings.Join(sites, ", "), spec.RootDir))
	}
	for _, s := range v.Sites {
		if path.Dir(s.Rel) != spec.RootDir {
			out = append(out, fmt.Sprintf("%s:%d — построение вне композиционного корня %s (%s `%s`)", s.Rel, s.Line, spec.RootDir, s.Form, s.Expr))
		}
		switch s.Form {
		case EnvelopeSiteCall:
			if !s.WallClock {
				out = append(out, fmt.Sprintf("%s:%d — мера огибающей `%s`, а не %s.%s: в не-тестовом файле огибающую меряют только "+
					"настенные часы, назначенная стоимость живёт в файлах проб", s.Rel, s.Line, s.Meter, homePkg, spec.WallClock))
			}
		case EnvelopeSiteConstructorValue:
			out = append(out, fmt.Sprintf("%s:%d — конструктор огибающей взят значением `%s`: мера у места построения не видна", s.Rel, s.Line, s.Expr))
		case EnvelopeSiteBypass:
			out = append(out, fmt.Sprintf("%s:%d — значение огибающей мимо конструктора `%s`: огибающая без меры либо с мерой, которой страж не видит",
				s.Rel, s.Line, s.Expr))
		}
	}
	for _, p := range v.PortImpls {
		out = append(out, fmt.Sprintf("%s:%d — реализация порта огибающей вне её дома: метод %s типа %s отдаёт %s.%s — "+
			"ни построения, ни меры страж у неё не видит", p.Rel, p.Line, spec.AdmitMethod, p.Receiver, homePkg, spec.AdmissionType))
	}
	return out
}

// envRootUnparen — выражение и его родитель над слоями скобок.
func envRootUnparen(e ast.Expr, parents []ast.Node) (ast.Expr, ast.Node) {
	child := e
	for i := len(parents) - 1; i >= 0; i-- {
		p, ok := parents[i].(*ast.ParenExpr)
		if !ok {
			return child, parents[i]
		}
		child = p
	}
	return child, nil
}

// envRootDeclaresOrSelects — идентификатор стоит не обращением, а именем
// объявления либо частью селектора (селектор судится целиком).
func envRootDeclaresOrSelects(id *ast.Ident, parents []ast.Node) bool {
	if len(parents) == 0 {
		return true
	}
	switch p := parents[len(parents)-1].(type) {
	case *ast.SelectorExpr, *ast.LabeledStmt, *ast.BranchStmt, *ast.ImportSpec, *ast.File:
		return true
	case *ast.FuncDecl:
		return p.Name == id
	case *ast.TypeSpec:
		return p.Name == id
	case *ast.KeyValueExpr:
		return p.Key == id && len(parents) > 1 && isCompositeLit(parents[len(parents)-2])
	case *ast.ValueSpec:
		return envRootIn(id, p.Names)
	case *ast.Field:
		return envRootIn(id, p.Names)
	case *ast.AssignStmt:
		if p.Tok != token.DEFINE {
			return false
		}
		for _, l := range p.Lhs {
			if l == id {
				return true
			}
		}
	}
	return false
}

func isCompositeLit(n ast.Node) bool {
	_, ok := n.(*ast.CompositeLit)
	return ok
}

func envRootIn(id *ast.Ident, names []*ast.Ident) bool {
	for _, n := range names {
		if n == id {
			return true
		}
	}
	return false
}

// envRootInsideConstructor — узел внутри объявления конструктора дома.
func envRootInsideConstructor(parents []ast.Node, constructor string) bool {
	for _, p := range parents {
		if d, ok := p.(*ast.FuncDecl); ok && d.Recv == nil && d.Name.Name == constructor {
			return true
		}
	}
	return false
}

// envRootMakesAValue — обращение к типу огибающей заводит значение: не за
// указателем, не в доводах и результатах функции и не в получателе метода.
func envRootMakesAValue(e ast.Expr, parents []ast.Node) bool {
	child, parent := envRootUnparen(e, parents)
	if star, ok := parent.(*ast.StarExpr); ok && star.X == child {
		return false
	}
	for i := len(parents) - 1; i >= 1; i-- {
		switch parents[i].(type) {
		case *ast.ArrayType, *ast.MapType, *ast.ChanType, *ast.Ellipsis, *ast.ParenExpr, *ast.IndexExpr, *ast.IndexListExpr, *ast.SelectorExpr:
			continue
		case *ast.Field:
			list, ok := parents[i-1].(*ast.FieldList)
			if !ok || i < 2 {
				return true
			}
			switch owner := parents[i-2].(type) {
			case *ast.FuncType:
				return false
			case *ast.FuncDecl:
				return owner.Recv != list
			}
			return true
		}
		return true
	}
	return true
}

// envRootReceiverName — имя типа получателя (указатель и параметры типа сняты).
func envRootReceiverName(e ast.Expr) string {
	for {
		switch x := e.(type) {
		case *ast.StarExpr:
			e = x.X
		case *ast.ParenExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.IndexListExpr:
			e = x.X
		case *ast.Ident:
			return x.Name
		default:
			return types.ExprString(e)
		}
	}
}
