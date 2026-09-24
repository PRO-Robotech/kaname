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
//	                          такое место вне тела конструктора (литерал функции
//	                          в нём — вне тела: исполняется после построения).
//
// Тип огибающей за указателем (`*pv.Envelope`), в доводах и результатах функций, в
// именованном поле и в получателе метода — не построение: значения он не
// заводит. Встраивание огибающей — не построение, а подставной тип (ниже).
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
// ЗАПИСЬ ПОЛЯ МЕРЫ — ТОЛЬКО ДОВОДОМ КОНСТРУКТОРА
//
// Мера у места построения — мера огибающей, лишь пока в поле меры ложится довод
// меры конструктора и ничто иное. Поле ВЫВЕДЕНО из объявления огибающей
// (единственное поле типа меры). Законная запись одна: довод меры — тем же
// именем, без переписывания — в теле самого конструктора, не в литерале функции.
// Всякая иная запись поля в доме — присваивание (и кортежем), взятие адреса,
// поле или позиция в составном литерале, цикл по диапазону — красное с
// координатой и выражением: сеттер, позванный корнем после построения, меняет
// меру мимо довода, который страж судит. Переписанный или затенённый в теле
// конструктора довод меры — тоже красное; конструктор, не кладущий довода в
// поле, — красное с координатой конструктора.
//
// Носитель меры в доме один — поле меры, и вход в него один — довод
// конструктора. Всякое иное обращение к типу меры в доме — переменная пакета,
// которую корень пишет после построения, довод сеттера, исход геттера, поле иной
// структуры, приведение — и всякий функциональный тип подписи меры, записанный
// без её имени, кроме объявления функции и литерала, — красное с координатой:
// второй носитель доводит до прогона меру мимо судимого довода. Геттер
// краснеет консервативно.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОДСТАВНОЙ ТИП НА МЕСТЕ ПОРТА
//
// Полоса входа принимает огибающую портом; методы порта ВЫВЕДЕНЫ из его
// объявления (`PortDir`, `PortInterface`). Не-тестовый метод с именем и
// арностью метода порта на типе помимо огибающей дома — реализация порта вне
// дома: целиком (исход допуска под псевдонимом ли, из третьего пакета ли — тип
// исхода не читается) или частью, подменой одного метода поверх встроенного
// порта либо встроенной огибающей. Встраивание огибающей дома в структуру — по
// значению и по указателю, вне дома и в нём — красное само: встроивший
// исполняет порт методами огибающей и подменяет любой из них.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОБХОД СИСТЕМЫ ТИПОВ
//
// Неэкспортированное поле меры пишется мимо дома только мимо системы типов:
// импорт `unsafe` в файле, обращающемся к дому, и директива `//go:linkname`,
// называющая символ дома, в любом не-тестовом файле — красное с координатой.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОСЫЛКА — ОТКАЗ, А НЕ МОЛЧАНИЕ
//
// Конструктор объявлен в доме ровно раз и несёт ровно один довод типа меры, и
// у довода есть имя; мера настенных часов, тип огибающей и тип меры объявлены в
// доме, тип меры — функциональный; у огибающей ровно одно поле типа меры, оно неэкспортировано, и его имя
// в доме несёт одно поле — тогда запись вне дома не компилируется, а в доме
// узнаётся по имени однозначно; порт объявлен ровно раз, методы перечислены без
// встраивания, и каждый объявлен у огибающей дома с той же арностью; `go.mod`
// корня дерева называет модуль; корень композиции несёт не-тестовые файлы. Не
// держится — ErrEnvelopeRootPremise с тем, что не нашлось. Пустой обход —
// ErrEmptyTraversal. «Построений 0» — находка о дереве, а не отказ посылки.
//
// Положительный контроль того же прогона: законная запись поля меры и методы
// порта у огибающей дома узнаются теми же распознавателями, что ищут нарушение;
// перепись печатает их координаты.
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
//  3. Судится ИМЯ меры, путь довода в поле меры и носители меры в доме; что
//     прогон делает с мерой поля дальше, — нет. Тело меры корня держит проба
//     TestWallClockCostMeter_MeasuresTheWholeRunItCalls; то, что стоимость класса
//     берётся мерой поля, — TestEnvelope_ADearerClassRaisesTheFloorACheaperOneDoesNot
//     (назначенная пробой стоимость доходит до потолка).
//  4. Тип довода и исхода не выводится: подставной метод узнаётся по имени и
//     арности метода порта, и метод с тем же именем и арностью, порта не
//     исполняющий, краснеет консервативно. Порт — объявленный
//     спекой: иной порт над огибающей стражу неизвестен. Подпись меры сличается
//     текстом типов: носитель под псевдонимом типа довода не узнаётся. Копия
//     значения огибающей (`c := *e`) новой меры не заводит и не судится.
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
	"sort"
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
	// PortDir, PortInterface — каталог и имя порта, которым полоса входа
	// принимает огибающую; его методы выводятся из объявления.
	PortDir, PortInterface string
}

// EnvelopeCompositionRootSpec — предмет стража в этом дереве.
func EnvelopeCompositionRootSpec() EnvelopeRootSpec {
	return EnvelopeRootSpec{
		HomeDir: "internal/passwordverify", RootDir: "cmd/kaname",
		Constructor: "NewEnvelope", EnvelopeType: "Envelope", MeterType: "CostMeter",
		WallClock: "WallClockCostMeter",
		PortDir:   "internal/apps/kaname/api/humansession", PortInterface: "TimingEnvelope",
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
	// MeterFrom — путь импорта пакета, которым квалифицирован довод меры
	// (пусто — довод не селектор импортированного пакета).
	MeterFrom string
	// WallClock — довод меры вызова есть мера настенных часов дома.
	WallClock bool
}

func (s EnvelopeSite) String() string {
	if s.Form == EnvelopeSiteCall {
		return fmt.Sprintf("%s:%d %s `%s`, мера `%s`", s.Rel, s.Line, s.Form, s.Expr, s.Meter)
	}
	return fmt.Sprintf("%s:%d %s `%s`", s.Rel, s.Line, s.Form, s.Expr)
}

// EnvelopePortImpl — метод порта огибающей на типе помимо огибающей дома.
type EnvelopePortImpl struct {
	Rel              string
	Line             int
	Receiver, Method string
}

// EnvelopeEmbedding — структура, встроившая огибающую дома.
type EnvelopeEmbedding struct {
	Rel         string
	Line        int
	Owner, Expr string
}

// EnvelopeMeterWrite — запись поля меры либо довода меры конструктора, кроме
// законной.
type EnvelopeMeterWrite struct {
	Rel  string
	Line int
	// Param — переписан довод меры конструктора, а не поле меры.
	Param bool
	// Where — где запись и почему она не законная; Form и Expr — вид и
	// выражение записи.
	Where, Form, Expr string
}

// EnvelopeMeterCarrier — обращение к типу меры в доме помимо поля меры
// огибающей и довода меры конструктора.
type EnvelopeMeterCarrier struct {
	Rel  string
	Line int
	// Context — объявление, в котором стоит обращение; Shape — подпись меры,
	// записанная без имени типа меры (пусто — обращение к типу по имени).
	Context, Shape string
}

// EnvelopeTypeBypass — обход системы типов рядом с домом огибающей.
type EnvelopeTypeBypass struct {
	Rel  string
	Line int
	// Directive — текст директивы связывания; пусто — импорт unsafe.
	Directive string
}

// EnvelopeRootCensus — объём осмотренного и посылка, на которой стоит вердикт.
type EnvelopeRootCensus struct {
	// TreeFiles — файлов в составе дерева; ProductionGo — не-тестовых `.go` по
	// суффиксу; OutsideTraversal — из них вне области обхода; Examined — разобрано.
	TreeFiles, ProductionGo, OutsideTraversal, Examined int
	// ReferringHome — файлов дома и файлов, импортирующих дом.
	ReferringHome int
	// HomeImport — путь импорта дома, выведенный из go.mod корня дерева.
	HomeImport string
	// MeterParam, MeterParamName — позиция довода меры у конструктора, с
	// единицы, и его имя.
	MeterParam     int
	MeterParamName string
	// ConstructorAt, WallClockAt — координаты объявлений в доме.
	ConstructorAt, WallClockAt string
	// MeterField, MeterFieldAt — поле меры огибающей, выведенное из её объявления.
	MeterField, MeterFieldAt string
	// Port, PortAt — порт полосы входа; PortMethods — его методов.
	Port, PortAt string
	PortMethods  int
	// LawfulMeterWrites — законные записи поля меры; PortMethodsAtHome — методы
	// порта, узнанные у огибающей дома тем же распознавателем, что ищет
	// подставной тип. Положительный контроль того же прогона.
	LawfulMeterWrites []string
	PortMethodsAtHome int
}

func (c EnvelopeRootCensus) String() string {
	return fmt.Sprintf("файлов дерева %d · не-тестовых .go %d, из них вне области обхода %d · разобрано %d · "+
		"обращаются к дому %s %d · посылка: мера — довод №%d `%s` конструктора %s, мера настенных часов %s, "+
		"поле меры `%s` %s, порт %s %s (методов %d) · законных записей поля меры %d [%s] · методов порта у огибающей дома %d",
		c.TreeFiles, c.ProductionGo, c.OutsideTraversal, c.Examined, c.HomeImport, c.ReferringHome,
		c.MeterParam, c.MeterParamName, c.ConstructorAt, c.WallClockAt, c.MeterField, c.MeterFieldAt,
		c.Port, c.PortAt, c.PortMethods, len(c.LawfulMeterWrites), strings.Join(c.LawfulMeterWrites, ", "), c.PortMethodsAtHome)
}

// EnvelopeRootVerdict — исход стража: перепись, найденное и находки.
type EnvelopeRootVerdict struct {
	Census        EnvelopeRootCensus
	Sites         []EnvelopeSite
	PortImpls     []EnvelopePortImpl
	Embeddings    []EnvelopeEmbedding
	MeterWrites   []EnvelopeMeterWrite
	MeterCarriers []EnvelopeMeterCarrier
	Bypasses      []EnvelopeTypeBypass
	Findings      []string
}

// Summary — перепись и найденное одной строкой вывода.
func (v EnvelopeRootVerdict) Summary() string {
	sites := make([]string, 0, len(v.Sites))
	for _, s := range v.Sites {
		sites = append(sites, s.String())
	}
	return fmt.Sprintf("%s · построений %d [%s] · реализаций порта вне дома %d · встраиваний огибающей %d · "+
		"записей меры помимо довода конструктора %d · носителей типа меры помимо поля и довода %d · обходов системы типов %d · находок %d",
		v.Census, len(v.Sites), strings.Join(sites, "; "), len(v.PortImpls), len(v.Embeddings),
		len(v.MeterWrites), len(v.MeterCarriers), len(v.Bypasses), len(v.Findings))
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
	v.Census.HomeImport = homeImport

	fset := token.NewFileSet()
	files := make(map[string]*ast.File, len(corpus))
	rels := corpus.Rels()
	for _, rel := range rels {
		f, err := parser.ParseFile(fset, rel, corpus[rel], parser.SkipObjectResolution|parser.ParseComments)
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
	v.Census.MeterParam, v.Census.MeterParamName = premise.meterIndex+1, premise.meterParam
	v.Census.ConstructorAt, v.Census.WallClockAt = premise.constructorAt, premise.wallClockAt
	v.Census.MeterField, v.Census.MeterFieldAt = premise.meterField, premise.meterFieldAt
	v.Census.Port, v.Census.PortAt, v.Census.PortMethods = premise.portPkg+"."+spec.PortInterface, premise.portAt, len(premise.portMethods)

	for _, rel := range rels {
		f := files[rel]
		inHome := path.Dir(rel) == spec.HomeDir
		// Подставной тип и директива связывания узнаются в КАЖДОМ файле: псевдоним
		// исхода из третьего пакета и встраивание порта обходятся без импорта дома.
		impls, atHome := envRootPortImpls(fset, rel, f, inHome, spec, premise.portMethods)
		v.PortImpls = append(v.PortImpls, impls...)
		v.Census.PortMethodsAtHome += atHome
		v.Bypasses = append(v.Bypasses, envRootLinknames(fset, rel, f, homeImport)...)

		names, dot := envRootHomeNames(f, homeImport, premise.homePkg)
		if !inHome && len(names) == 0 && !dot {
			continue
		}
		v.Census.ReferringHome++
		r := &envRootResolver{spec: spec, names: names, unqualified: inHome || dot, imports: envRootImports(f)}
		sites, embeddings := r.sites(fset, rel, f, inHome, premise.meterIndex)
		v.Sites = append(v.Sites, sites...)
		v.Embeddings = append(v.Embeddings, embeddings...)
		v.Bypasses = append(v.Bypasses, envRootUnsafeImports(fset, rel, f)...)
		if inHome {
			lawful, writes, carriers := r.meterWrites(fset, rel, f, premise)
			v.Census.LawfulMeterWrites = append(v.Census.LawfulMeterWrites, lawful...)
			v.MeterWrites = append(v.MeterWrites, writes...)
			v.MeterCarriers = append(v.MeterCarriers, carriers...)
		}
	}
	v.Findings = envRootFindings(v, spec, premise)
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

// envRootPremiseFacts — то, что посылка установила в доме и в порте.
type envRootPremiseFacts struct {
	homePkg                    string
	meterIndex                 int
	meterParam                 string
	constructorAt, wallClockAt string
	// meterField — поле меры огибающей; meterFieldIndex — его позиция среди
	// полей объявления (для позиционного литерала).
	meterField, meterFieldAt string
	meterFieldIndex          int
	// meterShape — подпись типа меры без имён доводов.
	meterShape string
	// portPkg, portAt, portMethods — пакет, координата и методы порта.
	portPkg, portAt string
	portMethods     map[string]envRootArity
}

// envRootArity — арность метода: доводов, исходов и признак переменного числа
// доводов. Сличается она, а не типы: вывода типов у стража нет.
type envRootArity struct {
	params, results int
	variadic        bool
}

func (a envRootArity) String() string {
	if a.variadic {
		return fmt.Sprintf("доводов %d с переменным числом, исходов %d", a.params, a.results)
	}
	return fmt.Sprintf("доводов %d, исходов %d", a.params, a.results)
}

func envRootArityOf(ft *ast.FuncType) envRootArity {
	var a envRootArity
	if ft.Params != nil {
		for _, field := range ft.Params.List {
			a.params += max(len(field.Names), 1)
			if _, ok := field.Type.(*ast.Ellipsis); ok {
				a.variadic = true
			}
		}
	}
	if ft.Results != nil {
		for _, field := range ft.Results.List {
			a.results += max(len(field.Names), 1)
		}
	}
	return a
}

// envRootPremise — посылка стража по объявлениям дома, порта и составу корня.
func envRootPremise(fset *token.FileSet, files map[string]*ast.File, rels []string, spec EnvelopeRootSpec) (envRootPremiseFacts, error) {
	var (
		p                              envRootPremiseFacts
		homeFiles, rootFiles           int
		constructors, wallClocks       []string
		meterParams                    int
		envelopeDeclared, meterDeclare bool
		envelope                       *ast.StructType
		envelopeRel                    string
		envelopeMethods                = map[string]envRootArity{}
		ports                          []string
		port                           *ast.InterfaceType
	)
	p.meterIndex = -1
	for _, rel := range rels {
		f := files[rel]
		dir := path.Dir(rel)
		if dir == spec.PortDir {
			for _, decl := range f.Decls {
				d, ok := decl.(*ast.GenDecl)
				if !ok {
					continue
				}
				for _, s := range d.Specs {
					if ts, ok := s.(*ast.TypeSpec); ok && ts.Name.Name == spec.PortInterface {
						ports = append(ports, fmt.Sprintf("%s:%d", rel, fset.Position(ts.Pos()).Line))
						port, _ = ts.Type.(*ast.InterfaceType)
						p.portPkg = f.Name.Name
					}
				}
			}
		}
		switch dir {
		case spec.RootDir:
			rootFiles++
			continue
		case spec.HomeDir:
		default:
			continue
		}
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
					if len(d.Recv.List) > 0 && envRootReceiverName(d.Recv.List[0].Type) == spec.EnvelopeType {
						envelopeMethods[d.Name.Name] = envRootArityOf(d.Type)
					}
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
							p.meterParam = ""
							if len(field.Names) > 0 {
								p.meterParam = field.Names[0].Name
							}
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
						envelope, _ = ts.Type.(*ast.StructType)
						envelopeRel = rel
					case spec.MeterType:
						meterDeclare = true
						if ft, ok := ts.Type.(*ast.FuncType); ok {
							p.meterShape = envRootShape(ft)
						}
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
	if len(constructors) == 1 && meterParams == 1 && (p.meterParam == "" || p.meterParam == "_") {
		missing = append(missing, fmt.Sprintf("довод меры конструктора %s без имени — положить его в поле меры нечем, и законную запись поля узнавать не по чему",
			spec.Constructor))
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
	if meterDeclare && p.meterShape == "" {
		missing = append(missing, fmt.Sprintf("тип меры %s — не функциональный: подпись меры выводить не из чего", spec.MeterType))
	}
	if envelopeDeclared {
		missing = append(missing, envRootMeterField(fset, files, rels, spec, envelope, envelopeRel, &p)...)
	}
	missing = append(missing, envRootPort(spec, ports, port, envelopeMethods, &p)...)
	if rootFiles == 0 {
		missing = append(missing, fmt.Sprintf("корень композиции %s не-тестовых файлов не несёт", spec.RootDir))
	}
	if len(missing) > 0 {
		return p, fmt.Errorf("%w: %s", ErrEnvelopeRootPremise, strings.Join(missing, "; "))
	}
	p.constructorAt, p.wallClockAt = constructors[0], wallClocks[0]
	return p, nil
}

// envRootMeterField — поле меры из объявления огибающей: ровно одно поле типа
// меры, неэкспортированное, и его имя в доме несёт одно поле. Иначе — чего не
// хватает посылке.
func envRootMeterField(fset *token.FileSet, files map[string]*ast.File, rels []string, spec EnvelopeRootSpec,
	envelope *ast.StructType, envelopeRel string, p *envRootPremiseFacts) []string {
	meterFields := 0
	if envelope != nil {
		index := 0
		for _, field := range envelope.Fields.List {
			width := max(len(field.Names), 1)
			if id, ok := field.Type.(*ast.Ident); ok && id.Name == spec.MeterType {
				meterFields += width
				p.meterField = id.Name
				if len(field.Names) > 0 {
					p.meterField = field.Names[0].Name
				}
				p.meterFieldIndex = index
				p.meterFieldAt = fmt.Sprintf("%s:%d", envelopeRel, fset.Position(field.Pos()).Line)
			}
			index += width
		}
	}
	if meterFields != 1 {
		return []string{fmt.Sprintf("полей типа %s у огибающей %s %d, а не ровно одно — поле меры выводить не из чего",
			spec.MeterType, spec.EnvelopeType, meterFields)}
	}
	if ast.IsExported(p.meterField) {
		return []string{fmt.Sprintf("поле меры %s экспортировано — писать его можно вне дома, и разбор записей одного дома неполон", p.meterField)}
	}
	var named []string
	for _, rel := range rels {
		if path.Dir(rel) != spec.HomeDir {
			continue
		}
		ast.Inspect(files[rel], func(n ast.Node) bool {
			st, ok := n.(*ast.StructType)
			if !ok {
				return true
			}
			for _, field := range st.Fields.List {
				for _, name := range field.Names {
					if name.Name == p.meterField {
						named = append(named, fmt.Sprintf("%s:%d", rel, fset.Position(name.Pos()).Line))
					}
				}
			}
			return true
		})
	}
	if len(named) != 1 {
		return []string{fmt.Sprintf("имя поля меры %s несут в доме %d поля [%s], а не одно — запись по имени поля неоднозначна",
			p.meterField, len(named), strings.Join(named, ", "))}
	}
	return nil
}

// envRootPort — методы порта из его объявления; каждый объявлен у огибающей дома
// с той же арностью. Иначе — чего не хватает посылке.
func envRootPort(spec EnvelopeRootSpec, ports []string, port *ast.InterfaceType, envelopeMethods map[string]envRootArity,
	p *envRootPremiseFacts) []string {
	if len(ports) != 1 {
		return []string{fmt.Sprintf("порт %s в %s объявлен %d раз(а) [%s], а не ровно один — подставной тип узнавать не по чему",
			spec.PortInterface, spec.PortDir, len(ports), strings.Join(ports, ", "))}
	}
	p.portAt = ports[0]
	if port == nil {
		return []string{fmt.Sprintf("порт %s (%s) — не интерфейс", spec.PortInterface, p.portAt)}
	}
	p.portMethods = map[string]envRootArity{}
	var missing []string
	for _, field := range port.Methods.List {
		ft, ok := field.Type.(*ast.FuncType)
		if len(field.Names) == 0 || !ok {
			missing = append(missing, fmt.Sprintf("порт %s встраивает интерфейс `%s` — перечень методов выводить не из чего",
				spec.PortInterface, types.ExprString(field.Type)))
			continue
		}
		for _, name := range field.Names {
			p.portMethods[name.Name] = envRootArityOf(ft)
		}
	}
	if len(missing) > 0 {
		return missing
	}
	if len(p.portMethods) == 0 {
		return []string{fmt.Sprintf("у порта %s методов нет", spec.PortInterface)}
	}
	methods := make([]string, 0, len(p.portMethods))
	for name := range p.portMethods {
		methods = append(methods, name)
	}
	sort.Strings(methods)
	for _, name := range methods {
		have, ok := envelopeMethods[name]
		switch {
		case !ok:
			missing = append(missing, fmt.Sprintf("метод %s порта %s у огибающей дома не объявлен — огибающая порт не исполняет, и подставной тип узнавать не по чему",
				name, spec.PortInterface))
		case have != p.portMethods[name]:
			missing = append(missing, fmt.Sprintf("метод %s порта %s у огибающей дома иной арности (порт: %s; огибающая: %s)",
				name, spec.PortInterface, p.portMethods[name], have))
		}
	}
	return missing
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
	// imports — местное имя импорта → путь: только для текста находки о мере.
	imports map[string]string
}

// envRootImports — местные имена импортов файла. Имя без псевдонима — последний
// сегмент пути: оно служит тексту находки, узнавание дома идёт по пути.
func envRootImports(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := path.Base(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		out[name] = p
	}
	return out
}

// meterFrom — путь импорта, которым квалифицирован довод меры.
func (r *envRootResolver) meterFrom(e ast.Expr) string {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			break
		}
		e = p.X
	}
	if sel, ok := e.(*ast.SelectorExpr); ok {
		if id, ok := sel.X.(*ast.Ident); ok {
			return r.imports[id.Name]
		}
	}
	return ""
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

// sites — места построения огибающей в файле и встраивания её типа в структуры.
func (r *envRootResolver) sites(fset *token.FileSet, rel string, f *ast.File, inHome bool, meterIndex int) ([]EnvelopeSite, []EnvelopeEmbedding) {
	var (
		out        []EnvelopeSite
		embeddings []EnvelopeEmbedding
	)
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
					site.MeterFrom = r.meterFrom(call.Args[meterIndex])
					site.WallClock = r.isWallClock(call.Args[meterIndex])
				}
				out = append(out, site)
				return
			}
			out = append(out, EnvelopeSite{Rel: rel, Line: at(n), Form: EnvelopeSiteConstructorValue, Expr: types.ExprString(expr)})
		case r.spec.EnvelopeType:
			if owner, field, ok := envRootEmbedded(expr, parents); ok {
				embeddings = append(embeddings, EnvelopeEmbedding{Rel: rel, Line: at(field), Owner: owner, Expr: types.ExprString(field.Type)})
				return
			}
			if inCtor, inLit := envRootConstructorScope(parents, r.spec.Constructor); inHome && inCtor && !inLit {
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
	return out, embeddings
}

// envRootEmbedded — обращение к типу огибающей стоит типом ВСТРОЕННОГО поля
// структуры — по значению либо за указателем; владелец — имя объявленного типа
// структуры. Безымянный довод функции (`func(*pv.Envelope)`) — не встраивание.
func envRootEmbedded(e ast.Expr, parents []ast.Node) (string, *ast.Field, bool) {
	var node ast.Node = e
	for i := len(parents) - 1; i >= 0; i-- {
		switch p := parents[i].(type) {
		case *ast.ParenExpr:
			node = p
			continue
		case *ast.StarExpr:
			if p.X != node {
				return "", nil, false
			}
			node = p
			continue
		case *ast.Field:
			if len(p.Names) != 0 || p.Type != node || i < 2 {
				return "", nil, false
			}
			if _, ok := parents[i-2].(*ast.StructType); !ok {
				return "", nil, false
			}
			owner := "<безымянная структура>"
			if i >= 3 {
				if ts, ok := parents[i-3].(*ast.TypeSpec); ok {
					owner = ts.Name.Name
				}
			}
			return owner, p, true
		}
		return "", nil, false
	}
	return "", nil, false
}

// envRootPortImpls — методы файла с именем и арностью метода порта на типе
// помимо огибающей дома; второе значение — сколько таких методов у самой
// огибающей дома (положительный контроль распознавателя).
func envRootPortImpls(fset *token.FileSet, rel string, f *ast.File, inHome bool, spec EnvelopeRootSpec,
	methods map[string]envRootArity) ([]EnvelopePortImpl, int) {
	var (
		out    []EnvelopePortImpl
		atHome int
	)
	for _, decl := range f.Decls {
		d, ok := decl.(*ast.FuncDecl)
		if !ok || d.Recv == nil || len(d.Recv.List) == 0 {
			continue
		}
		want, ok := methods[d.Name.Name]
		if !ok || envRootArityOf(d.Type) != want {
			continue
		}
		recv := envRootReceiverName(d.Recv.List[0].Type)
		if inHome && recv == spec.EnvelopeType {
			atHome++
			continue
		}
		out = append(out, EnvelopePortImpl{Rel: rel, Line: fset.Position(d.Pos()).Line, Receiver: recv, Method: d.Name.Name})
	}
	return out, atHome
}

// meterWrites — записи поля меры в файле дома: законные (довод меры в теле
// конструктора) координатами и все прочие — находками; туда же — переписанный
// в теле конструктора довод меры и обращения к типу меры помимо поля меры и
// довода конструктора.
func (r *envRootResolver) meterWrites(fset *token.FileSet, rel string, f *ast.File,
	p envRootPremiseFacts) ([]string, []EnvelopeMeterWrite, []EnvelopeMeterCarrier) {
	var (
		lawful   []string
		writes   []EnvelopeMeterWrite
		carriers []EnvelopeMeterCarrier
	)
	at := func(n ast.Node) int { return fset.Position(n.Pos()).Line }
	isField := func(e ast.Expr) bool {
		sel, ok := envRootUnparenExpr(e).(*ast.SelectorExpr)
		return ok && sel.Sel.Name == p.meterField
	}
	isParam := func(e ast.Expr) bool {
		id, ok := envRootUnparenExpr(e).(*ast.Ident)
		return ok && id.Name == p.meterParam
	}
	w := &parentWalker{}
	w.visit = func(n ast.Node, parents []ast.Node) {
		inCtor, inLit := envRootConstructorScope(parents, r.spec.Constructor)
		field := func(node ast.Node, form, expr string, value ast.Expr) {
			var where string
			switch {
			case inCtor && !inLit && value != nil && isParam(value):
				lawful = append(lawful, fmt.Sprintf("%s:%d", rel, at(node)))
				return
			case inCtor && !inLit && value != nil:
				where = fmt.Sprintf("в конструкторе %s значением `%s`, а не довода меры `%s`", r.spec.Constructor, types.ExprString(value), p.meterParam)
			case inCtor && !inLit:
				where = fmt.Sprintf("в конструкторе %s мимо довода меры `%s`", r.spec.Constructor, p.meterParam)
			case inCtor:
				where = fmt.Sprintf("в литерале функции внутри конструктора %s", r.spec.Constructor)
			default:
				where = fmt.Sprintf("вне конструктора %s", r.spec.Constructor)
			}
			writes = append(writes, EnvelopeMeterWrite{Rel: rel, Line: at(node), Where: where, Form: form, Expr: expr})
		}
		param := func(node ast.Node, form, expr string) {
			writes = append(writes, EnvelopeMeterWrite{Rel: rel, Line: at(node), Param: true, Form: form, Expr: expr})
		}
		switch x := n.(type) {
		case *ast.Ident:
			if x.Name == r.spec.MeterType && !envRootMeterTypeAllowed(x, parents, r.spec) {
				carriers = append(carriers, EnvelopeMeterCarrier{Rel: rel, Line: at(x), Context: envRootEnclosingDecl(parents)})
			}
		case *ast.FuncType:
			if shape := envRootShape(x); shape == p.meterShape && !envRootMeterShapeAllowed(x, parents, r.spec) {
				carriers = append(carriers, EnvelopeMeterCarrier{Rel: rel, Line: at(x), Context: envRootEnclosingDecl(parents), Shape: shape})
			}
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				if isField(lhs) {
					var value ast.Expr
					if x.Tok == token.ASSIGN && len(x.Lhs) == len(x.Rhs) {
						value = x.Rhs[i]
					}
					field(x, "присваивание", envRootAssignText(x), value)
				}
				if inCtor && isParam(lhs) {
					if x.Tok == token.DEFINE {
						param(x, "объявление", p.meterParam)
					} else {
						param(x, "присваивание", envRootAssignText(x))
					}
				}
			}
		case *ast.UnaryExpr:
			if x.Op == token.AND && isField(x.X) {
				field(x, "взятие адреса", types.ExprString(x), nil)
			}
			if x.Op == token.AND && inCtor && isParam(x.X) {
				param(x, "взятие адреса", types.ExprString(x))
			}
		case *ast.IncDecStmt:
			if isField(x.X) {
				field(x, "приращение", types.ExprString(x.X)+x.Tok.String(), nil)
			}
		case *ast.RangeStmt:
			for _, e := range []ast.Expr{x.Key, x.Value} {
				if e == nil {
					continue
				}
				if x.Tok == token.ASSIGN && isField(e) {
					field(x, "цикл по диапазону", types.ExprString(e)+" = range "+types.ExprString(x.X), nil)
				}
				if inCtor && isParam(e) {
					param(x, "цикл по диапазону", types.ExprString(e)+" "+x.Tok.String()+" range "+types.ExprString(x.X))
				}
			}
		case *ast.ValueSpec:
			for _, name := range x.Names {
				if inCtor && name.Name == p.meterParam {
					param(x, "объявление", name.Name)
				}
			}
		case *ast.CompositeLit:
			// Ключ литерала отображения — значение, а не поле.
			envelope := false
			if x.Type != nil {
				if _, ok := envRootUnparenExpr(x.Type).(*ast.MapType); ok {
					return
				}
				name, ok := r.homeName(x.Type)
				envelope = ok && name == r.spec.EnvelopeType
			}
			for i, el := range x.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					if id, ok := kv.Key.(*ast.Ident); ok && id.Name == p.meterField {
						field(kv, "поле литерала", types.ExprString(kv), kv.Value)
					}
					continue
				}
				if envelope && i == p.meterFieldIndex {
					field(el, "позиция поля в литерале", types.ExprString(el), el)
				}
			}
		}
	}
	ast.Walk(w, f)
	return lawful, writes, carriers
}

// envRootMeterTypeAllowed — обращение к типу меры в доме законно: имя его
// объявления, тип поля меры огибающей либо тип довода конструктора. Селектор
// `x.CostMeter` типом дома не является.
func envRootMeterTypeAllowed(id *ast.Ident, parents []ast.Node, spec EnvelopeRootSpec) bool {
	n := len(parents)
	if n == 0 {
		return true
	}
	switch p := parents[n-1].(type) {
	case *ast.TypeSpec:
		return p.Name == id
	case *ast.SelectorExpr:
		return p.Sel == id
	case *ast.Field:
		if p.Type != id || n < 4 {
			return false
		}
		list, _ := parents[n-2].(*ast.FieldList)
		switch owner := parents[n-3].(type) {
		case *ast.StructType:
			ts, ok := parents[n-4].(*ast.TypeSpec)
			return ok && ts.Name.Name == spec.EnvelopeType
		case *ast.FuncType:
			d, ok := parents[n-4].(*ast.FuncDecl)
			return ok && d.Recv == nil && d.Name.Name == spec.Constructor && owner.Params == list
		}
	}
	return false
}

// envRootMeterShapeAllowed — функциональный тип подписи меры стоит законно:
// объявлением самого типа меры, подписью объявленной функции (мера настенных
// часов — такая) либо литерала функции. Функция и литерал — значения, а не
// носители: чтобы стать мерой огибающей, значение проходит через довод
// конструктора, поле меры либо носитель, которые судятся сами.
func envRootMeterShapeAllowed(ft *ast.FuncType, parents []ast.Node, spec EnvelopeRootSpec) bool {
	if len(parents) == 0 {
		return false
	}
	switch p := parents[len(parents)-1].(type) {
	case *ast.TypeSpec:
		return p.Name.Name == spec.MeterType
	case *ast.FuncDecl:
		return p.Type == ft
	case *ast.FuncLit:
		return p.Type == ft
	}
	return false
}

// envRootShape — подпись функционального типа без имён доводов:
// `func(T1, T2) R`.
func envRootShape(ft *ast.FuncType) string {
	list := func(fl *ast.FieldList) []string {
		if fl == nil {
			return nil
		}
		var out []string
		for _, field := range fl.List {
			t := types.ExprString(field.Type)
			for range max(len(field.Names), 1) {
				out = append(out, t)
			}
		}
		return out
	}
	shape := "func(" + strings.Join(list(ft.Params), ", ") + ")"
	switch results := list(ft.Results); len(results) {
	case 0:
	case 1:
		shape += " " + results[0]
	default:
		shape += " (" + strings.Join(results, ", ") + ")"
	}
	return shape
}

// envRootEnclosingDecl — объявление, в котором стоит узел: функция или метод по
// имени, иначе объявление пакета.
func envRootEnclosingDecl(parents []ast.Node) string {
	for _, p := range parents {
		if d, ok := p.(*ast.FuncDecl); ok {
			return "функция " + d.Name.Name
		}
	}
	return "объявление пакета"
}

// envRootConstructorScope — узел в теле конструктора дома и, если так, внутри ли
// литерала функции: литерал исполняется после построения.
func envRootConstructorScope(parents []ast.Node, constructor string) (bool, bool) {
	inCtor, inLit := false, false
	for _, p := range parents {
		switch d := p.(type) {
		case *ast.FuncDecl:
			inCtor = d.Recv == nil && d.Name.Name == constructor
		case *ast.FuncLit:
			inLit = inLit || inCtor
		}
	}
	return inCtor, inLit
}

// envRootAssignText — присваивание одной строкой: `a, b.c = x, y`.
func envRootAssignText(x *ast.AssignStmt) string {
	side := func(list []ast.Expr) string {
		parts := make([]string, 0, len(list))
		for _, e := range list {
			parts = append(parts, types.ExprString(e))
		}
		return strings.Join(parts, ", ")
	}
	return side(x.Lhs) + " " + x.Tok.String() + " " + side(x.Rhs)
}

// envRootUnparenExpr — выражение без слоёв скобок.
func envRootUnparenExpr(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// envRootUnsafeImports — импорт unsafe в файле, обращающемся к дому.
func envRootUnsafeImports(fset *token.FileSet, rel string, f *ast.File) []EnvelopeTypeBypass {
	var out []EnvelopeTypeBypass
	for _, imp := range f.Imports {
		if p, err := strconv.Unquote(imp.Path.Value); err == nil && p == "unsafe" {
			out = append(out, EnvelopeTypeBypass{Rel: rel, Line: fset.Position(imp.Pos()).Line})
		}
	}
	return out
}

// envRootLinknames — директивы связывания, называющие символ дома по пути
// импорта. Директива — комментарий, начатый ровно с `//go:linkname `; проза о
// ней директивой не является.
func envRootLinknames(fset *token.FileSet, rel string, f *ast.File, homeImport string) []EnvelopeTypeBypass {
	var out []EnvelopeTypeBypass
	for _, group := range f.Comments {
		for _, c := range group.List {
			if strings.HasPrefix(c.Text, "//go:linkname ") && strings.Contains(c.Text, homeImport+".") {
				out = append(out, EnvelopeTypeBypass{Rel: rel, Line: fset.Position(c.Pos()).Line, Directive: c.Text})
			}
		}
	}
	return out
}

// envRootFindings — находки по найденному.
func envRootFindings(v EnvelopeRootVerdict, spec EnvelopeRootSpec, premise envRootPremiseFacts) []string {
	homePkg := premise.homePkg
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
				from := ""
				if s.MeterFrom != "" && s.MeterFrom != v.Census.HomeImport {
					from = " из " + s.MeterFrom
				}
				out = append(out, fmt.Sprintf("%s:%d — мера огибающей `%s`%s, а не %s.%s дома %s: в не-тестовом файле огибающую "+
					"меряют только настенные часы, назначенная стоимость живёт в файлах проб",
					s.Rel, s.Line, s.Meter, from, homePkg, spec.WallClock, v.Census.HomeImport))
			}
		case EnvelopeSiteConstructorValue:
			out = append(out, fmt.Sprintf("%s:%d — конструктор огибающей взят значением `%s`: мера у места построения не видна", s.Rel, s.Line, s.Expr))
		case EnvelopeSiteBypass:
			out = append(out, fmt.Sprintf("%s:%d — значение огибающей мимо конструктора `%s`: огибающая без меры либо с мерой, которой страж не видит",
				s.Rel, s.Line, s.Expr))
		}
	}
	for _, p := range v.PortImpls {
		out = append(out, fmt.Sprintf("%s:%d — реализация порта огибающей вне её дома: метод %s типа %s — имя и арность метода порта %s (%s); "+
			"подставной тип на месте порта несёт свой потолок либо свой допуск, и ни построения, ни меры страж у него не видит",
			p.Rel, p.Line, p.Method, p.Receiver, v.Census.Port, premise.portMethods[p.Method]))
	}
	for _, e := range v.Embeddings {
		out = append(out, fmt.Sprintf("%s:%d — встраивание огибающей `%s` в тип %s: встроивший исполняет порт методами огибающей и подменяет "+
			"любой из них своим — потолок либо допуск идут не от огибающей корня", e.Rel, e.Line, e.Expr, e.Owner))
	}
	if len(v.Census.LawfulMeterWrites) == 0 {
		out = append(out, fmt.Sprintf("%s — конструктор %s не кладёт свой довод меры `%s` в поле меры `%s`: мера у места построения "+
			"до огибающей не доходит", premise.constructorAt, spec.Constructor, premise.meterParam, premise.meterField))
	}
	for _, w := range v.MeterWrites {
		if w.Param {
			out = append(out, fmt.Sprintf("%s:%d — довод меры `%s` конструктора %s переписан в его теле (%s `%s`): в поле меры ложится "+
				"не то, что передал вызывающий, и страж, судящий довод у места построения, судил бы не ту меру",
				w.Rel, w.Line, premise.meterParam, spec.Constructor, w.Form, w.Expr))
			continue
		}
		out = append(out, fmt.Sprintf("%s:%d — запись в поле меры `%s` огибающей %s (%s `%s`): мерой огибающей становится не довод меры "+
			"у места построения, который судит страж", w.Rel, w.Line, premise.meterField, w.Where, w.Form, w.Expr))
	}
	for _, c := range v.MeterCarriers {
		what := fmt.Sprintf("тип меры `%s`", spec.MeterType)
		if c.Shape != "" {
			what = fmt.Sprintf("подпись меры `%s`", c.Shape)
		}
		out = append(out, fmt.Sprintf("%s:%d — %s в доме помимо поля меры огибающей и довода конструктора (%s): второй носитель "+
			"меры доводит до прогона меру мимо довода, который судит страж", c.Rel, c.Line, what, c.Context))
	}
	for _, b := range v.Bypasses {
		if b.Directive != "" {
			out = append(out, fmt.Sprintf("%s:%d — директива `%s` называет символ дома огибающей %s: связывание мимо импорта стражу не видно",
				b.Rel, b.Line, b.Directive, v.Census.HomeImport))
			continue
		}
		out = append(out, fmt.Sprintf("%s:%d — импорт unsafe в файле, обращающемся к дому огибающей %s: запись поля меры мимо системы "+
			"типов стражу не видна", b.Rel, b.Line, v.Census.HomeImport))
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
