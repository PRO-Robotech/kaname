// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// platform_edge_absent_test.go — ГЕЙТ G2: ребра `kaname → kacho` НЕТ НИ ОДНОГО.
//
// # ПРЕДМЕТ — ЦЕЛЬ ВЛАДЕЛЬЦА, А НЕ ВКУС
//
// Разрешённых рёбер между тремя модулями ровно три: `kacho → corelib`,
// `kaname → corelib`, `kacho → kaname`. Запрещённых — тоже три, и они выписаны
// ниже таблицей `forbiddenDirections`. Ребро `kaname → kacho` вместе с
// `kacho → kaname` образует КОЛЬЦО МОДУЛЕЙ: опубликовать нельзя ни один, потому
// что каждый ждёт версию другого.
//
// # ЭТО ВТОРАЯ ПОЛОВИНА ОДНОГО ПРАВИЛА, А НЕ ВТОРОЕ ПРАВИЛО
//
// Первая половина живёт в дереве ПЛАТФОРМЫ: `internal/repohygiene/`
// `foundationboundary.go`, таблица `forbiddenDirections` (шесть осей, перепись
// объёма, отказ на пустом обходе, инъекция в обе стороны). Те же три пары
// направлений, тот же корпус приёмки K3-1 — и запись правила ОДНА, повторённая
// здесь ДОСЛОВНО, чтобы два места не разъехались молча.
//
// РАЗДЕЛЕНИЕ ПОЛОВИН УСТАНОВЛЕНО ЗАМЕРОМ, а не согласовано на словах. Судья
// платформы переводит путь импорта в координату дерева функцией
// `treePathOfImport`, и она отдаёт `true` РОВНО для приставки
// `github.com/PRO-Robotech/kacho`; всякий иной путь — не её предмет. Корень
// обхода у неё — дерево платформы (`repoRoot`). Значит:
//
//	что судит половина платформы   классы каталогов `pkg/*` ВНУТРИ одного модуля:
//	                               раскол ещё не произошёл, и Go отвергнуть ребро
//	                               не может — отказ пришёл бы только в день раскола
//	что судит эта половина         НАСТОЯЩЕЕ межмодульное ребро из дерева службы,
//	                               где раскол уже произошёл: узел импорта,
//	                               `require`, `go.sum`, граф сборки
//
// Ни одного файла этого репозитория половина платформы не видит by construction,
// и ни одного каталога `pkg/*` платформы не видит эта. Дубля нет; есть одно
// правило на двух сторонах раскола.
//
// # ЭТА ПОЛОВИНА НАБЛЮДАЕТ ОДНУ ПАРУ ИЗ ТРЁХ, И ЭТО СКАЗАНО ПРЯМО
//
// Наблюдаемо отсюда ребро, ИСХОДЯЩЕЕ из модуля этого дерева, — то есть
// `kaname → kacho`. Пары `corelib → kacho` и `corelib → kaname` исходят из
// модуля фундамента: их не видит ни это дерево, ни дерево платформы, и держателя
// у них сегодня НЕТ НИ ОДНОГО (в `corelib` гейтов на зависимости ноль — решение
// kacho#2617, гейт G1, заводится своей работой). Таблица ниже несёт все три пары
// именно затем, чтобы это отсутствие было НАЗВАНО, а не умолчано: пара без
// держателя обязана читаться как остаток, а не как «проверено».
//
// # ПОЧЕМУ ПЕРЕЧНЯ ОСТАТКА БОЛЬШЕ НЕТ
//
// Прежняя редакция этого гейта вела ВЕДОМОСТЬ ОСТАТКА — три записи, у каждой
// основание и предикат снятия: контракты самой службы, `pkg/ownerregister`,
// `pkg/subjectchange`. Ведомость сошлась к пустоте своей работой (ступень S0a
// решения kacho#2617, исход C): 251 узел импорта переключён на заглушки службы,
// оба пакета перенесены в её дерево. Послабление, которому нечего послаблять,
// разрешает вперёд то, чего никто не решал, — поэтому перечня здесь нет, и
// законного входа в платформенный модуль у службы не осталось НИ ОДНОГО.
//
// # РЕБРО ПРИХОДИТ ЧЕТЫРЬМЯ НЕЗАВИСИМЫМИ СПОСОБАМИ — СУДЯТСЯ ВСЕ ЧЕТЫРЕ
//
//	узел импорта в дереве службы   прямое ребро, видно разбором
//	require / replace в go.mod     объявленное ребро, даже без единого импорта
//	строка в go.sum                ребро, переживающее снятие require
//	граф сборки (go list -test)    ТРАНЗИТИВНОЕ ребро — через фундамент либо
//	                               через любой другой модуль
//
// Четвёртый предикат несущий, и он заменяет собой прежний гейт
// `internal/contracthome` TestBothCopiesOfAContractNeverReachOneBinary. Тот
// искал НОСИТЕЛЯ второй копии дескриптора: платформенный пакет, который тянет
// платформенные заглушки своим не-тестовым кодом, из-за чего двоичное получает
// вторую копию, НЕ НАЗЫВАЯ ни одного её пути, и падает не сборкой, а паникой
// регистрации в инициализации:
//
//	panic: proto: file "kaname/cloud/iam/v1/authorize_service.proto" is already registered
//
// Носитель искался обходом исходников платформы в кэше модулей — то есть
// предикат существовал ровно пока платформенный модуль оставался зависимостью.
// Со снятием ребра носителя не существует BY CONSTRUCTION: пакета, которого нет
// в графе сборки, линковщик не видит. Здесь это и проверяется — прямо, по
// графу, а не обходом чужого дерева. Половина того класса, что живёт у
// ПЛАТФОРМЫ (её двоичное, слинковавшее свою копию и копию службы), судится в её
// дереве и снимается ступенью S0b; это дерево о её двоичных вердикта не даёт и
// не должно.
//
// # ПАРНЫЙ КОНТРОЛЬ: НОЛЬ НЕ ДОЛЖЕН БЫТЬ СЛЕПЫМ
//
// Ноль находок сам по себе неотличим от «разбор перестал видеть путь». Поэтому
// рядом с каждым нулём стоит величина о МОДУЛЕ ФУНДАМЕНТА, ребро к которому
// законно и обязано быть: импорты `corelib` в дереве, его `require`, его строки
// в `go.sum`, его пакеты в графе сборки. Ноль в любой из них — находка о дереве,
// а не тишина.
//
// # ИМПОРТЫ ЧИТАЮТСЯ РАЗБОРОМ, А НЕ ПОИСКОМ ПО ОБРАЗЦУ
//
// Путь `github.com/PRO-Robotech/kacho/...` встречается в этом дереве не только
// импортом: он стоит в комментариях (в том числе в шапке этого файла), в
// строковых литералах синтетических фикстур соседних гейтов и в ведомости
// входных контрактов. Замер на дереве после S0a: поиск по тексту находит путь в
// 49 файлах, узлом импорта он не является НИ В ОДНОМ. Судится узел импорта,
// полученный `parser.ImportsOnly`.
package supplyhygiene

import (
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

// platformModulePath — модуль платформы. Ребра к нему у службы быть не должно.
const platformModulePath = "github.com/PRO-Robotech/kacho"

// foundationModulePath — модуль фундамента, общий для службы и платформы. Ребро
// службы идёт СЮДА, и его наличие — парный контроль каждого нуля ниже.
const foundationModulePath = "github.com/PRO-Robotech/corelib"

// serviceModulePathDeclared — модуль ЭТОГО дерева. Читается из `go.mod` при
// обходе, а здесь объявлен затем, чтобы таблица направлений называла свою
// наблюдаемую пару, не завися от успеха чтения файла.
const serviceModulePathDeclared = "github.com/PRO-Robotech/kaname"

// forbiddenDirection — одна запрещённая пара направления. Форма и состав — те
// же, что у первой половины правила (`kacho:internal/repohygiene/`
// `foundationboundary.go`, `forbiddenDirections`); добавлены два поля, которых у
// той половины быть не может: наблюдаема ли пара ИЗ ЭТОГО дерева и кто её
// держит, если не эта проверка.
type forbiddenDirection struct {
	// From, To — модули пары. Направление читается «From зависит от To».
	From, To string
	// ObservableHere — видна ли пара из дерева службы. Видна ровно та, что
	// исходит из модуля этого дерева: остальные исходят из чужого модуля, и
	// сказать о них отсюда нечего — ни красного, ни зелёного.
	ObservableHere bool
	// Holder — кто судит пару, если не эта проверка. Пустая строка означает
	// ОСТАТОК: держателя нет ни одного, и это названо, а не умолчано.
	Holder string
}

// forbiddenDirections — три пары, запрещённые целевой раскладкой
// `corelib ← kaname ← kacho`. Перечень ЗАКРЫТ: четвёртой пары между тремя
// модулями не бывает, и это проверяется, а не подразумевается.
var forbiddenDirections = []forbiddenDirection{
	{
		From: serviceModulePathDeclared, To: platformModulePath, ObservableHere: true,
		Holder: "",
	},
	{
		From: foundationModulePath, To: platformModulePath, ObservableHere: false,
		Holder: "",
	},
	{
		From: foundationModulePath, To: serviceModulePathDeclared, ObservableHere: false,
		Holder: "",
	},
}

// observableDirection — пара, судимая ЭТОЙ проверкой. Она одна, и её
// единственность судится пробой ниже: появись вторая — вердикт этой проверки
// стал бы шире того, что она обходит.
func observableDirection() (forbiddenDirection, int) {
	var found forbiddenDirection
	count := 0
	for _, d := range forbiddenDirections {
		if d.ObservableHere {
			found = d
			count++
		}
	}
	return found, count
}

// основания находки. Различие несёт исход: элемент пути `internal` закрывает
// компилятор (сборка вне дерева платформы отказывает языком), остальные три —
// решение о составе зависимости (соберётся, но ребро запрещено).
const (
	platformEdgeGroundLanguage = "правило языка: этот путь платформы недостижим извне её дерева"
	platformEdgeGroundImport   = "узел импорта называет модуль платформы: прямое ребро kaname → kacho"
	platformEdgeGroundRequire  = "go.mod объявляет модуль платформы в require: ребро есть даже без единого импорта"
	platformEdgeGroundReplace  = "go.mod подменяет модуль платформы директивой replace: ребро осталось, а его версия перестала быть объявленной"
	platformEdgeGroundSum      = "go.sum несёт отпечаток модуля платформы: ребро переживает снятие require"
	platformEdgeGroundGraph    = "пакет платформы стоит в ГРАФЕ СБОРКИ службы: ребро приехало транзитивно, ни одним узлом импорта не названное"
)

// platformEdgeFinding — одно ребро к платформе.
type platformEdgeFinding struct {
	Where  string // координата: файл:строка либо имя предиката
	What   string // что именно названо
	Ground string
}

func (f platformEdgeFinding) String() string {
	return fmt.Sprintf("%s — %s (%s)", f.Where, f.What, f.Ground)
}

// platformImportCensus — объём осмотренного при обходе дерева.
type platformImportCensus struct {
	Files          int
	Imports        int
	PlatformModule int
	Foundation     int
	Own            int
	FindingFiles   int
	LanguageBound  int
}

func (c platformImportCensus) String() string {
	return fmt.Sprintf("файлов Go %d; узлов импорта %d — платформенного модуля %d, "+
		"модуля фундамента %d, своего модуля %d; находок — файлов %d, рёбер %d "+
		"(из них сборка откажет языком на %d)",
		c.Files, c.Imports, c.PlatformModule, c.Foundation, c.Own,
		c.FindingFiles, c.PlatformModule, c.LanguageBound)
}

// platformEdgeGroundForImport — основание, по которому путь назван находкой.
func platformEdgeGroundForImport(innerPath string) string {
	for _, seg := range strings.Split(innerPath, "/") {
		if seg == "internal" {
			return platformEdgeGroundLanguage
		}
	}
	return platformEdgeGroundImport
}

// scanPlatformImports разбирает импорты файлов службы. Находка — КАЖДЫЙ узел,
// называющий платформенный модуль: законного входа в него не осталось.
//
// СОСТАВ ПРИНОСИТ ВЫЗЫВАЮЩИЙ: у настоящего дерева службы авторитет — ИНДЕКС git,
// у синтетики инъекции — обход диска (`treecorpus.SyntheticTree`). Обход вынесен
// из теста, чтобы способность гейта упасть проверялась подачей настоящего входа,
// а не чтением.
func scanPlatformImports(tree *treecorpus.Tree) ([]platformEdgeFinding, platformImportCensus, error) {
	census := platformImportCensus{}
	root := tree.Root()
	serviceModule := ""
	if raw, err := os.ReadFile(filepath.Join(root, "go.mod")); err == nil {
		serviceModule = modulePathOf(raw)
	}

	var findings []platformEdgeFinding
	seenFiles := map[string]bool{}
	fset := token.NewFileSet()

	for _, rel := range tree.SortedFiles() {
		if !strings.HasSuffix(rel, ".go") {
			continue
		}
		f, err := parser.ParseFile(fset, path.Join(root, rel), nil, parser.ImportsOnly)
		if err != nil {
			return nil, census, fmt.Errorf("%s: разбор импортов: %w", rel, err)
		}
		census.Files++
		for _, spec := range f.Imports {
			census.Imports++
			value, unquoteErr := strconv.Unquote(spec.Path.Value)
			if unquoteErr != nil {
				continue
			}
			switch {
			case value == foundationModulePath || strings.HasPrefix(value, foundationModulePath+"/"):
				census.Foundation++
				continue
			case serviceModule != "" && (value == serviceModule || strings.HasPrefix(value, serviceModule+"/")):
				census.Own++
				continue
			case value != platformModulePath && !strings.HasPrefix(value, platformModulePath+"/"):
				continue // чужой модуль либо stdlib — не предмет
			}
			census.PlatformModule++

			ground := platformEdgeGroundForImport(strings.TrimPrefix(value, platformModulePath+"/"))
			if ground == platformEdgeGroundLanguage {
				census.LanguageBound++
			}
			seenFiles[rel] = true
			findings = append(findings, platformEdgeFinding{
				Where:  fmt.Sprintf("%s:%d", rel, fset.Position(spec.Path.Pos()).Line),
				What:   value,
				Ground: ground,
			})
		}
	}
	census.FindingFiles = len(seenFiles)
	sort.Slice(findings, func(i, j int) bool { return findings[i].Where < findings[j].Where })
	return findings, census, nil
}

// modulePathOf — путь модуля из `go.mod`, без разбора остального. Своя функция
// нужна затем, чтобы обход дерева не зависел от успеха разбора всего файла:
// синтетика инъекции подаёт минимальный `go.mod`.
func modulePathOf(raw []byte) string {
	for _, line := range strings.Split(string(raw), "\n") {
		if fields := strings.Fields(line); len(fields) == 2 && fields[0] == "module" {
			return fields[1]
		}
	}
	return ""
}

// moduleGraphCensus — объём осмотренного при разборе графа модулей.
type moduleGraphCensus struct {
	Require           int
	Replace           int
	SumLines          int
	GraphPackages     int
	FoundationRequire int
	FoundationSum     int
	FoundationGraph   int
}

func (c moduleGraphCensus) String() string {
	return fmt.Sprintf("go.mod: require %d, replace %d; go.sum: строк %d; "+
		"граф сборки (go list -test -deps ./...): пакетов %d. Парный контроль по модулю "+
		"фундамента: require %d, строк go.sum %d, пакетов в графе %d",
		c.Require, c.Replace, c.SumLines, c.GraphPackages,
		c.FoundationRequire, c.FoundationSum, c.FoundationGraph)
}

// goModDeclaration — ровно та часть `go mod edit -json`, которая решает, есть ли
// ребро. Читается РАЗБОРОМ вывода команды, а не текстом файла: `require` бывает
// и одиночной директивой, и блоком, и косвенным, и текстовая форма их различает
// иначе, чем сборка.
type goModDeclaration struct {
	Module  struct{ Path string } `json:"Module"`
	Require []struct {
		Path    string `json:"Path"`
		Version string `json:"Version"`
	} `json:"Require"`
	Replace []struct {
		Old struct{ Path string } `json:"Old"`
		New struct{ Path string } `json:"New"`
	} `json:"Replace"`
}

// judgeModuleDeclaration судит РАЗОБРАННОЕ объявление модуля. Чистая функция:
// вход приносит вызывающий, поэтому инъекция подаёт синтетическое объявление, а
// не правит настоящий `go.mod`.
func judgeModuleDeclaration(decl goModDeclaration) ([]platformEdgeFinding, moduleGraphCensus) {
	var findings []platformEdgeFinding
	var census moduleGraphCensus
	for _, r := range decl.Require {
		switch {
		case r.Path == platformModulePath || strings.HasPrefix(r.Path, platformModulePath+"/"):
			census.Require++
			findings = append(findings, platformEdgeFinding{
				Where: "go.mod require", What: r.Path + " " + r.Version, Ground: platformEdgeGroundRequire,
			})
		case r.Path == foundationModulePath || strings.HasPrefix(r.Path, foundationModulePath+"/"):
			census.FoundationRequire++
		}
	}
	for _, r := range decl.Replace {
		if r.Old.Path == platformModulePath || strings.HasPrefix(r.Old.Path, platformModulePath+"/") {
			census.Replace++
			findings = append(findings, platformEdgeFinding{
				Where: "go.mod replace", What: r.Old.Path + " => " + r.New.Path, Ground: platformEdgeGroundReplace,
			})
		}
	}
	return findings, census
}

// judgeSum судит строки `go.sum`. Единица счёта — СТРОКА, и она названа: у
// одного модуля их две (архив и его `go.mod`), поэтому «2» здесь не значит «два
// модуля».
func judgeSum(raw []byte) ([]platformEdgeFinding, moduleGraphCensus) {
	var findings []platformEdgeFinding
	var census moduleGraphCensus
	for i, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch {
		case fields[0] == platformModulePath || strings.HasPrefix(fields[0], platformModulePath+"/"):
			census.SumLines++
			findings = append(findings, platformEdgeFinding{
				Where: fmt.Sprintf("go.sum:%d", i+1), What: strings.Join(fields[:2], " "), Ground: platformEdgeGroundSum,
			})
		case fields[0] == foundationModulePath || strings.HasPrefix(fields[0], foundationModulePath+"/"):
			census.FoundationSum++
		}
	}
	return findings, census
}

// judgeBuildGraph судит ПЕРЕЧЕНЬ ПАКЕТОВ графа сборки. Чистая функция: перечень
// приносит вызывающий (`go list -test -deps ./...` у настоящего дерева,
// синтетика у инъекции), поэтому её способность найти транзитивное ребро
// проверяется подачей входа, а не запуском команды.
//
// Граф ВКЛЮЧАЕТ тестовые зависимости (`-test`), и это несущее: тестового импорта
// достаточно, чтобы ребро существовало в `go.mod` и в `go.sum`, а второй копии
// дескриптора — приехать в пробное двоичное.
func judgeBuildGraph(packages []string) ([]platformEdgeFinding, moduleGraphCensus) {
	var findings []platformEdgeFinding
	var census moduleGraphCensus
	for _, p := range packages {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		census.GraphPackages++
		switch {
		case p == platformModulePath || strings.HasPrefix(p, platformModulePath+"/"):
			findings = append(findings, platformEdgeFinding{
				Where: "граф сборки", What: p, Ground: platformEdgeGroundGraph,
			})
		case p == foundationModulePath || strings.HasPrefix(p, foundationModulePath+"/"):
			census.FoundationGraph++
		}
	}
	return findings, census
}

// readModuleDeclaration — настоящее объявление модуля службы, разобранное
// `go mod edit -json`.
func readModuleDeclaration(root string) (goModDeclaration, error) {
	var decl goModDeclaration
	cmd := exec.Command("go", "mod", "edit", "-json")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return decl, fmt.Errorf("go mod edit -json в %s: %w", root, err)
	}
	if err := json.Unmarshal(out, &decl); err != nil {
		return decl, fmt.Errorf("разбор вывода go mod edit -json: %w", err)
	}
	return decl, nil
}

// readBuildGraph — настоящий граф сборки службы, ВКЛЮЧАЯ тестовые зависимости.
func readBuildGraph(root string) ([]string, error) {
	cmd := exec.Command("go", "list", "-test", "-deps", "./...")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list -test -deps ./... в %s: %w", root, err)
	}
	return strings.Split(strings.TrimRight(string(out), "\n"), "\n"), nil
}

// TestNoImportNodeNamesThePlatformModule — первый из двух предикатов G2: дерево
// службы не называет модуль платформы НИ ОДНИМ узлом импорта.
func TestNoImportNodeNamesThePlatformModule(t *testing.T) {
	t.Parallel()

	tree, err := treecorpus.NewTree(serviceRoot)
	if err != nil {
		t.Fatalf("состав дерева службы (%s) не прочитан у индекса — вердикт беспредметен: "+
			"обход диска вместо индекса читал бы каталоги, которых в репозитории нет: %v",
			serviceRoot, err)
	}

	findings, census, err := scanPlatformImports(tree)
	if err != nil {
		t.Fatalf("обход дерева службы: %v", err)
	}

	t.Logf("перепись: %s", census)

	if census.Files == 0 {
		t.Fatal("обход пуст: файлов Go не разобрано ни одного — вердикт беспредметен")
	}
	if census.Imports == 0 {
		t.Fatal("обход пуст: узлов импорта не осмотрено ни одного — вердикт беспредметен")
	}
	// ПАРНЫЙ КОНТРОЛЬ. Ноль платформенных находок неотличим от «разбор перестал
	// видеть путь» — ровно поэтому рядом стоят импорты ФУНДАМЕНТА и СВОЕГО
	// модуля. Ноль в любом из двух означает, что обход ослеп либо что зависимость
	// заводят вторым путём.
	if census.Foundation == 0 {
		t.Errorf("импортов модуля фундамента (%s) не найдено ни одного: служба обязана брать "+
			"общий фундамент оттуда. Ноль означает либо что разбор перестал видеть путь, "+
			"либо что фундамент тянут вторым путём", foundationModulePath)
	}
	if census.Own == 0 {
		t.Errorf("импортов СВОЕГО модуля не найдено ни одного — разбор не читает пути " +
			"собственного модуля, и ноль платформенных находок ничего не доказывает")
	}

	for _, f := range findings {
		t.Errorf("%s. Разрешённых рёбер три — kacho → corelib, kaname → corelib, "+
			"kacho → kaname; ребро kaname → kacho запрещено и вместе с kacho → kaname даёт "+
			"КОЛЬЦО МОДУЛЕЙ: опубликовать нельзя ни один. Общий фундамент берётся из %s, "+
			"свои контракты — из своего модуля", f, foundationModulePath)
	}
}

// TestModuleGraphCarriesNoEdgeToThePlatform — второй предикат G2: ребра нет ни в
// объявлении модуля, ни в отпечатках, ни в графе сборки. Три независимых
// источника, потому что ребро приходит тремя разными способами, и снятие одного
// не снимает остальных.
func TestModuleGraphCarriesNoEdgeToThePlatform(t *testing.T) {
	t.Parallel()

	decl, err := readModuleDeclaration(serviceRoot)
	if err != nil {
		t.Fatalf("объявление модуля службы не прочитано — это «НЕ ВЫПОЛНИЛОСЬ», а не "+
			"«ребра нет»: %v", err)
	}
	declFindings, declCensus := judgeModuleDeclaration(decl)

	sumRaw, err := os.ReadFile(filepath.Join(serviceRoot, "go.sum"))
	if err != nil {
		t.Fatalf("go.sum не прочитан — это «НЕ ВЫПОЛНИЛОСЬ», а не «отпечатков платформы "+
			"нет»: %v", err)
	}
	sumFindings, sumCensus := judgeSum(sumRaw)

	packages, err := readBuildGraph(serviceRoot)
	if err != nil {
		t.Fatalf("граф сборки не получен — это «НЕ ВЫПОЛНИЛОСЬ», а не «пакетов платформы "+
			"в графе нет». Нужно: go mod download, и разрешимый набор пакетов. %v", err)
	}
	graphFindings, graphCensus := judgeBuildGraph(packages)

	census := moduleGraphCensus{
		Require: declCensus.Require, Replace: declCensus.Replace,
		SumLines: sumCensus.SumLines, GraphPackages: graphCensus.GraphPackages,
		FoundationRequire: declCensus.FoundationRequire,
		FoundationSum:     sumCensus.FoundationSum,
		FoundationGraph:   graphCensus.FoundationGraph,
	}
	t.Logf("перепись: %s", census)

	if decl.Module.Path == "" {
		t.Fatal("объявление модуля не называет собственного пути — вердикт беспредметен")
	}
	if census.GraphPackages == 0 {
		t.Fatal("граф сборки пуст: пакетов не осмотрено ни одного — вердикт беспредметен")
	}
	// ПАРНЫЙ КОНТРОЛЬ по каждому из трёх источников: ноль обязан быть отличим от
	// «источник перестал читаться». Ребро к фундаменту законно и обязано быть во
	// всех трёх.
	if census.FoundationRequire == 0 {
		t.Errorf("в require нет модуля фундамента (%s): либо объявление читается не то, "+
			"либо фундамент приезжает не объявленным ребром", foundationModulePath)
	}
	if census.FoundationSum == 0 {
		t.Errorf("в go.sum нет ни одной строки модуля фундамента (%s): разбор отпечатков "+
			"ничего не измеряет", foundationModulePath)
	}
	if census.FoundationGraph == 0 {
		t.Errorf("в графе сборки нет ни одного пакета модуля фундамента (%s): граф получен "+
			"не о том дереве", foundationModulePath)
	}

	for _, f := range append(append(declFindings, sumFindings...), graphFindings...) {
		t.Errorf("%s. Подделкой ребро не снимается: `replace` на локальный путь, копия "+
			"пакета и vendor-копия запрещены — предмет снимается переносом владения, а не "+
			"сокрытием координаты", f)
	}
}

// TestForbiddenDirectionsRecordIsWellFormed — таблица направлений судится раньше
// дерева. Она — ВТОРАЯ ЗАПИСЬ одного правила, и расхождение двух записей есть
// ровно тот класс, который весь этот гейт и закрывает.
//
// Судятся четыре вещи, и каждая отвечает на свой способ разъехаться: число пар
// (между тремя модулями их ровно три); отсутствие пары, направленной в себя;
// единственность наблюдаемой отсюда пары; и то, что наблюдаемая пара исходит
// именно из модуля этого дерева. Пара БЕЗ держателя находкой не является — она
// названный остаток, и проба это фиксирует явно, чтобы «держателя нет» не
// читалось как «проверено».
func TestForbiddenDirectionsRecordIsWellFormed(t *testing.T) {
	t.Parallel()

	if len(forbiddenDirections) != 3 {
		t.Fatalf("пар запрещённого направления объявлено %d, а между тремя модулями их "+
			"ровно ТРИ: перечень разошёлся с первой половиной правила "+
			"(kacho:internal/repohygiene/foundationboundary.go, forbiddenDirections)",
			len(forbiddenDirections))
	}
	seen := map[[2]string]bool{}
	for _, d := range forbiddenDirections {
		if d.From == d.To {
			t.Errorf("пара %s → %s направлена в себя: запрещать модулю зависеть от себя нечего",
				d.From, d.To)
		}
		key := [2]string{d.From, d.To}
		if seen[key] {
			t.Errorf("пара %s → %s объявлена дважды: вторая запись не судится ничем",
				d.From, d.To)
		}
		seen[key] = true
	}

	observable, count := observableDirection()
	if count != 1 {
		t.Fatalf("наблюдаемых отсюда пар %d, ожидалась РОВНО одна: дерево службы видит "+
			"ребро, исходящее из своего модуля, и ничего не может сказать о рёбрах чужого",
			count)
	}
	if observable.From != serviceModulePathDeclared || observable.To != platformModulePath {
		t.Errorf("наблюдаемая пара — %s → %s, а из этого дерева наблюдаемо только %s → %s",
			observable.From, observable.To, serviceModulePathDeclared, platformModulePath)
	}

	// ОСТАТОК НАЗЫВАЕТСЯ ЧИСЛОМ. Пара, которую это дерево не наблюдает и у
	// которой нет держателя, не проверена НИЧЕМ; молчание о ней — не зелёное.
	unheld := 0
	for _, d := range forbiddenDirections {
		if !d.ObservableHere && d.Holder == "" {
			unheld++
			t.Logf("ОСТАТОК: пара %s → %s не наблюдаема из этого дерева и держателя не имеет — "+
				"её судит гейт G1 в репозитории фундамента, и он ещё не заведён (kacho#2617)",
				d.From, d.To)
		}
	}
	if unheld != 2 {
		t.Errorf("пар без держателя %d, а на день заведения их ДВЕ (оба ребра из модуля "+
			"фундамента). Изменилось число — значит либо G1 заведён и запись обязана его "+
			"назвать, либо перечень пар разъехался", unheld)
	}
}
