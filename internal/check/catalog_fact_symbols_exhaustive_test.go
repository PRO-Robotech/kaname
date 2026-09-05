// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// catalog_fact_symbols_exhaustive_test.go — РАСПОЗНАВАТЕЛЬ соседнего гейта
// обязан знать ВСЕ экспортированные функции, читающие литерал каталога
// (kacho#1816, приёмка
// `services/iam/docs/engineering/acceptance/catalog-readers-move-to-the-table.md`).
//
// # Предмет: невидимость, а не нарушение
//
// `TestIAMCT2_LiteralIsNotAReadSource` отбирает обращения по РУКОПИСНОМУ перечню
// имён (`catalogFactSymbols`). Перечень — второе место о предмете «что в пакете
// `authzmap` отвечает на каталожный вопрос», и держать его в согласии с самим
// пакетом не поручено ничему: функция, добавленная в `authzmap` и читающая тот же
// словарь, в перечень не попадает, и всё записанное через неё оказывается ВНЕ
// НАБЛЮДЕНИЯ. Это не красное и не зелёное — это молчание, и отличить его от
// чистого дерева нельзя ничем (`testing.md` §«Гейт на класс», п. 7).
//
// Замер, ради которого гейт написан: на ревизии заведения экспортированных
// функций пакета, транзитивно достающих до `objectTypes`/`typeVerbRelations`,
// было БОЛЬШЕ, чем перечислено обоими наборами соседнего гейта. Числа печатает
// перепись ниже — их не надо брать отсюда, они устаревают.
//
// # Что гейт требует и чего НЕ требует
//
// Требует: каждая экспортированная функция-читатель названа ровно одним из трёх
// наборов — запрещённый каталожный факт · переходник имени типа · читатель,
// осознанно оставленный вне предмета с ПРИЧИНОЙ. И: имя, названное набором,
// существует в пакете (иначе запись пережила свой предмет).
//
// НЕ требует, чтобы всякое имя из первых двух наборов было читателем: набор
// каталожного факта перечисляет то, что прод-коду СПРАШИВАТЬ У ЛИТЕРАЛА нельзя,
// и туда законно попадает функция, ставшая чистой. Третий набор — послабление, и
// у него требование обратное: запись без предмета есть находка.
//
// # Почему транзитивно
//
// `GrantedVerbs` литерала не касается сама — она зовёт `VerbsOfType`. Разбор,
// смотрящий только на тело, объявил бы её нечитателем, и перечень запрещённых
// разошёлся бы с разбором в первой же строке.
//
// # Вердикт живёт в ЧИСТОЙ ФУНКЦИИ, и её зовут ОБА
//
// `recognizerVerdictless` · `recognizerFindings` · `reportRecognizerFindings` —
// единственные места, где решается, что делает прогон беспредметным, что
// является находкой и как находка ОБЪЯВЛЯЕТСЯ. Все три зовёт и гейт, и его
// инъекция; своей ветви вердикта у гейта не остаётся ни одной.
//
// Слоёв три, а не один, потому что выпотрошить можно каждый по отдельности, и
// вычислить находку и сказать о ней — разные предметы: красное даёт только
// объявление. Инъекция подаёт объявителю СВОЙ приёмник и сверяет напечатанное.
//
// Иначе доказательство не относится к предмету. Прежняя редакция инъекции звала
// РАЗБОРЩИК (`authzmapLiteralReaders`), а три ветви вердикта переписывала у себя
// — `if !tc.classified[r]`, — то есть утверждала «имя отсутствует в локально
// поданной карте», а не «гейт даёт находку». Выпотрошенный вердикт оставлял её
// ЗЕЛЁНОЙ: способность гейта объявлять находки не была показана ничем.
//
// # Почему находка — ЗНАЧЕНИЕ, а не сразу `t.Errorf`
//
// Инъекция сверяет пару «вид находки · символ» — она стабильна и переживает
// правку прозы. Плюс отдельным утверждением требует, чтобы текст находки НАЗЫВАЛ
// символ: гейт, покрасневший молча, посылает читателя искать не там
// (`testing.md` §«Гейт на класс», п. 8 — инъекция проверяет не только
// «покраснел», но и ЧТО напечатал).
//
// # Почему производная переменная пакета читателем НЕ считается
//
// `expandableRelations` собирается из `typeVerbRelations` в инициализаторе
// переменной пакета. Приёмка (§0.2) называет её ОТДЕЛЬНЫМ литералом —
// поверхностью раскрытия, — и её читатели (`AcceptExpand`,
// `IsExpandableRelation`) предметом `#1816` не являются. Поэтому разбор считает
// чтением обращение к словарю ВНУТРИ ТЕЛА ФУНКЦИИ, а не в инициализаторе
// переменной: иначе гейт задним числом переклассифицировал бы решение, принятое
// приёмкой, и сделал бы это молча.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unicode"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// catalogLiteralNames — словари-литералы каталога. Ровно те два, которые называет
// приёмка (§0.2): других объявлений формы «карта каталога» в пакете нет.
var catalogLiteralNames = map[string]bool{
	"objectTypes":       true,
	"typeVerbRelations": true,
}

// literalReadersOutOfScope — читатели литерала, ОСОЗНАННО оставленные вне
// предмета #1816, с причиной у каждого.
//
// Это послабление, и оно истекает само: запись, чья функция читателем быть
// перестала (или из пакета исчезла), — находка. Иначе слепая зона переживёт свой
// предмет и достанется следующему читателю, который положит в неё что угодно.
var literalReadersOutOfScope = map[string]string{
	"CatalogSeedResources": "ЛЕВАЯ СТОРОНА ПАРИТЕТА: значение, с которым страж старта и гейт " +
		"дерева сверяют живые строки. Читать литерал — её работа by construction, и запретить " +
		"это значило бы потребовать, чтобы паритет сверял строки сами с собой (§2.1, §6.4)",
	"CatalogSeedVerbs": "то же, глагольная половина посева каталога (§6.4)",
	"CatalogSeedModules": "то же, МОДУЛЬНАЯ половина посева каталога (kacho#1927). Заведена " +
		"вместе со снятием литерала `domain.knownModules`: набор модулей стал строками " +
		"`catalog_module`, а левая сторона паритета обязана остаться выводимой ИЗ ДЕРЕВА — " +
		"её спрашивают страж старта, гейт паритета и оснастка, у которой базы нет by construction. " +
		"На пути запроса членство модуля спрашивают у строк (`catalog.Facts.IsKnownModule`)",
}

// readerCensus — объём осмотренного. Печатается всегда и независимо от исхода:
// «ноль находок» обязано быть отличимо от «ноль прочитанного».
type readerCensus struct {
	Files      int
	Funcs      int
	Exported   int
	Readers    int
	Classified int
}

// authzmapLiteralReaders — экспортированные функции пакета, ТРАНЗИТИВНО достающие
// до словаря-литерала каталога, отсортированно.
//
// Состав приходит ПАРАМЕТРОМ по той же причине, что и у соседнего гейта: в живом
// дереве его даёт индекс git, а инъекция подаёт синтетический перечень —
// доказательство, требующее испортить живое дерево, в конвейере не исполняется
// никогда.
func authzmapLiteralReaders(files []string) (readers []string, exported map[string]bool, c readerCensus, err error) {
	type fn struct {
		reads   bool
		callees []string
	}
	funcs := map[string]*fn{}
	exported = map[string]bool{}

	fset := token.NewFileSet()
	for _, path := range files {
		name := filepath.Base(path)
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil, nil, c, fmt.Errorf("разобрать %s: %w", path, perr)
		}
		c.Files++
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Body == nil {
				continue
			}
			c.Funcs++
			f := &fn{}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.Ident:
					if catalogLiteralNames[node.Name] {
						f.reads = true
					}
				case *ast.CallExpr:
					if id, isIdent := node.Fun.(*ast.Ident); isIdent {
						f.callees = append(f.callees, id.Name)
					}
				}
				return true
			})
			funcs[fd.Name.Name] = f
			if isExportedName(fd.Name.Name) {
				c.Exported++
				exported[fd.Name.Name] = true
			}
		}
	}

	// Неподвижная точка: чтение поднимается по вызовам ВНУТРИ пакета.
	for changed := true; changed; {
		changed = false
		for _, f := range funcs {
			if f.reads {
				continue
			}
			for _, callee := range f.callees {
				if target, ok := funcs[callee]; ok && target.reads {
					f.reads = true
					changed = true
					break
				}
			}
		}
	}

	for name, f := range funcs {
		if f.reads && isExportedName(name) {
			readers = append(readers, name)
		}
	}
	sort.Strings(readers)
	c.Readers = len(readers)
	return readers, exported, c, nil
}

// isExportedName — имя, видимое вне пакета.
func isExportedName(name string) bool {
	if name == "" {
		return false
	}
	return unicode.IsUpper([]rune(name)[0])
}

// recognizerFindingKind — вид находки распознавателя. Инъекция сверяет ВИД и
// СИМВОЛ, а не прозу: пара стабильна и переживает правку текста.
type recognizerFindingKind string

const (
	// findingUnnamedReader — читатель литерала не назван ни одним набором.
	findingUnnamedReader recognizerFindingKind = "нераспознанный-читатель"
	// findingStaleClassification — набор называет имя, которого в пакете нет.
	findingStaleClassification recognizerFindingKind = "имя-набора-без-предмета"
	// findingStaleExemption — послаблению больше нечего исключать.
	findingStaleExemption recognizerFindingKind = "послабление-без-предмета"
)

// recognizerFinding — одна находка: вид, символ и текст, который увидит читатель.
type recognizerFinding struct {
	Kind   recognizerFindingKind
	Symbol string
	Detail string
}

// recognizerFindings — ВЕРДИКТ распознавателя целиком, чистой функцией.
//
// Зовётся ИЗ ОБОИХ — из гейта и из инъекции, — и своей ветви вердикта у гейта не
// остаётся. Выпотрошенный вердикт поэтому краснит инъекцию: без этого она
// утверждала бы про собственную локальную карту, а не про то, что гейт способен
// объявить находку.
//
// Три оси, и третья требует ОБРАТНОГО первым двум:
//
//  1. читатель, не названный ни одним набором, — НЕВИДИМОСТЬ;
//  2. имя набора, которого в пакете нет, — запись пережила свой предмет;
//  3. послабление, чья функция читателем быть перестала, — предмета нет.
//
// Ось 2 НЕ требует, чтобы всякое классифицированное имя было читателем: набор
// каталожного факта перечисляет то, что прод-коду спрашивать у литерала нельзя,
// и туда законно попадает функция, ставшая чистой. Ось 3 — про послабление, и у
// него требование именно обратное.
func recognizerFindings(
	readers []string,
	exported map[string]bool,
	classified map[string]bool,
	outOfScope map[string]string,
) []recognizerFinding {
	var out []recognizerFinding

	for _, r := range readers {
		if classified[r] {
			continue
		}
		out = append(out, recognizerFinding{
			Kind:   findingUnnamedReader,
			Symbol: r,
			Detail: fmt.Sprintf("экспортированная функция authzmap.%s читает литерал каталога "+
				"и НЕ НАЗВАНА ни одним набором распознавателя.\n\n"+
				"Прод-файл, позвавший её, гейт TestIAMCT2_LiteralIsNotAReadSource не увидит — "+
				"это не нарушение и не чистота, а НЕВИДИМОСТЬ. Отнесите имя к одному из трёх:\n"+
				"  catalogFactSymbols        — каталожный факт, прод-коду спрашивать у литерала нельзя;\n"+
				"  typeDictionarySymbols     — переходник имени типа, остаётся на литерале (§2.2);\n"+
				"  literalReadersOutOfScope  — вне предмета #1816, с ПРИЧИНОЙ у записи.", r),
		})
	}

	for _, name := range sortedKeys(classified) {
		if exported[name] {
			continue
		}
		out = append(out, recognizerFinding{
			Kind:   findingStaleClassification,
			Symbol: name,
			Detail: fmt.Sprintf("набор распознавателя называет authzmap.%s, а такой "+
				"экспортированной функции в пакете нет — запись пережила свой предмет и молча "+
				"сужает наблюдение", name),
		})
	}

	readerSet := map[string]bool{}
	for _, r := range readers {
		readerSet[r] = true
	}
	for _, name := range sortedKeys(outOfScope) {
		if readerSet[name] {
			continue
		}
		out = append(out, recognizerFinding{
			Kind:   findingStaleExemption,
			Symbol: name,
			Detail: fmt.Sprintf("послабление literalReadersOutOfScope[%q] больше нечего "+
				"исключать: функция литерал не читает. Снимите запись — послабление без "+
				"предмета становится слепой зоной, заведённой вперёд", name),
		})
	}
	return out
}

// recognizerReporter — минимальная поверхность ОБЪЯВЛЕНИЯ находки.
//
// Заведена ради того, чтобы инъекция подавала свой приёмник вместо `*testing.T`
// и убеждалась, что вердикт не только ВЫЧИСЛЯЕТСЯ, но и ОБЪЯВЛЯЕТСЯ. Без этого
// слоя «гейт посчитал находки и не сказал о них» остаётся непоказанным: вычисление
// и объявление — разные предметы, и красное даёт только второе.
type recognizerReporter interface {
	Errorf(format string, args ...any)
}

// reportRecognizerFindings — объявляет находки. Единственное место, где вердикт
// становится КРАСНЫМ; зовётся и гейтом, и инъекцией.
func reportRecognizerFindings(r recognizerReporter, findings []recognizerFinding) {
	for _, f := range findings {
		r.Errorf("[%s] %s", f.Kind, f.Detail)
	}
}

// recognizerVerdictless — прогон БЕЗ ВЕРДИКТА: обход не прочитал предмета, и
// «ноль находок» здесь неотличимо от «ноль прочитанного». Пустая строка означает,
// что предмет прочитан; непустая — текст отказа.
//
// Живёт рядом с вердиктом и по той же причине: инъекция обязана связываться и с
// этой границей, иначе снятый страж пустого обхода останется непоказанным.
func recognizerVerdictless(pkg string, c readerCensus, literals []string) string {
	if c.Files == 0 || c.Funcs == 0 {
		return fmt.Sprintf("в %s прочитано файлов %d, функций %d — вердикт беспредметен",
			pkg, c.Files, c.Funcs)
	}
	if c.Readers == 0 {
		return fmt.Sprintf("читателей литерала распознано НОЛЬ при %d экспортированных "+
			"функциях — это отказ РАЗБОРА, а не пакет без литерала: словари %v объявлены "+
			"в нём и читаются", c.Exported, literals)
	}
	return ""
}

// TestIAMCT2_CatalogFactRecognizerKnowsEveryLiteralReader — распознаватель
// соседнего гейта полон относительно ПАКЕТА, а не относительно памяти автора.
//
// Своей логики вердикта здесь нет ни одной ветви: гейт собирает вход, печатает
// перепись и передаёт решение `recognizerVerdictless`/`recognizerFindings`, тем
// же двум функциям, которые зовёт инъекция.
func TestIAMCT2_CatalogFactRecognizerKnowsEveryLiteralReader(t *testing.T) {
	root := catalogRepoRoot(t)
	files, err := treecorpus.UnderWithSuffix(filepath.Join(root, literalPackageRel), ".go")
	if err != nil {
		t.Fatalf("состав пакета-литерала: %v", err)
	}
	readers, exported, c, err := authzmapLiteralReaders(files)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}

	classified := classifiedLiteralSymbols()
	c.Classified = len(classified)
	t.Logf("осмотрено файлов: %d; функций верхнего уровня: %d (экспортированных %d); "+
		"читателей литерала: %d; классифицировано имён: %d",
		c.Files, c.Funcs, c.Exported, c.Readers, c.Classified)
	// Перечень читателей печатается ПОИМЁННО, а не только числом: таблица §0.2
	// приёмки перечисляет ровно его, и без имён её нечем перемерить. Так она с
	// пакетом и разошлась — в ЧЕТЫРЁХ ячейках при СОШЕДШЕМСЯ счёте (по
	// четырнадцать имён с обеих сторон), то есть расхождение не выдавало себя
	// ничем. Разбор всех четырёх — §И.7 приёмки.
	t.Logf("читатели литерала поимённо: %s", strings.Join(readers, " · "))

	if void := recognizerVerdictless(literalPackageRel, c, sortedKeys(catalogLiteralNames)); void != "" {
		t.Fatalf("%s", void)
	}

	reportRecognizerFindings(t, recognizerFindings(readers, exported, classified, literalReadersOutOfScope))
}

// classifiedLiteralSymbols — объединение трёх наборов распознавателя.
func classifiedLiteralSymbols() map[string]bool {
	out := map[string]bool{}
	for s := range catalogFactSymbols {
		out[s] = true
	}
	for _, s := range typeDictionarySymbols {
		out[s] = true
	}
	for s := range literalReadersOutOfScope {
		out[s] = true
	}
	return out
}

// sortedKeys — детерминированный порядок вывода находок.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestIAMCT2_CatalogFactRecognizerInjection — доказательство способности упасть,
// в ОБЕ стороны и по каждой оси отдельно.
//
// Инъекция подаётся синтетическим пакетом: портить живое дерево ради
// доказательства нельзя, а утверждение, чью способность падать не показали, от
// вакуумного неотличимо.
//
// # Что здесь исправлено по сравнению с первой редакцией
//
// Она звала РАЗБОРЩИК, а вердикт переписывала у себя (`if !tc.classified[r]`), и
// потому доказывала свойство ЛОКАЛЬНОЙ КАРТЫ, а не гейта: выпотрошенный вердикт
// оставлял её зелёной. Теперь зовутся ТЕ ЖЕ `recognizerVerdictless` и
// `recognizerFindings`, что и в гейте, — своей копии решения у инъекции нет.
//
// # Оси, и у каждой законный близнец
//
// Осей ПЯТЬ: разбор (читатель прямой · транзитивный · производная переменная ·
// неэкспортированный), нераспознанный читатель, имя набора без предмета,
// послабление без предмета, беспредметный обход. Первые три ветви вердикта до
// этой правки не проверялись НИ ОДНА: ось послабления не подавалась вовсе, а две
// другие судились локальной копией.
func TestIAMCT2_CatalogFactRecognizerInjection(t *testing.T) {
	cases := []struct {
		name         string
		body         string
		classified   map[string]bool
		exemptions   map[string]string
		wantReaders  []string
		wantFindings []string // «вид:символ», отсортировано
		wantVoid     bool     // обход беспредметен
	}{
		{
			name: "контроль: единственный читатель назван набором",
			body: "package authzmap\n" +
				"var objectTypes = map[string]string{}\n" +
				"func ObjectType(k string) string { return objectTypes[k] }\n",
			classified:  map[string]bool{"ObjectType": true},
			wantReaders: []string{"ObjectType"},
		},
		{
			name: "инъекция: новый экспортированный читатель не назван",
			body: "package authzmap\n" +
				"var typeVerbRelations = map[string][]string{}\n" +
				"func VerbsOfType(k string) []string { return typeVerbRelations[k] }\n" +
				"func VerbRelationsOfType(k string) []string { return typeVerbRelations[k] }\n",
			classified:   map[string]bool{"VerbsOfType": true},
			wantReaders:  []string{"VerbRelationsOfType", "VerbsOfType"},
			wantFindings: []string{"нераспознанный-читатель:VerbRelationsOfType"},
		},
		{
			name: "инъекция: читатель ТРАНЗИТИВНЫЙ — тело литерала не называет",
			body: "package authzmap\n" +
				"var typeVerbRelations = map[string][]string{}\n" +
				"func verbs(k string) []string { return typeVerbRelations[k] }\n" +
				"func GrantedVerbs(k string) []string { return verbs(k) }\n",
			classified:   map[string]bool{},
			wantReaders:  []string{"GrantedVerbs"},
			wantFindings: []string{"нераспознанный-читатель:GrantedVerbs"},
		},
		{
			name: "контроль: производная переменная пакета читателем НЕ делает",
			body: "package authzmap\n" +
				"var typeVerbRelations = map[string][]string{}\n" +
				"var expandableRelations = func() map[string]bool {\n" +
				"  m := map[string]bool{}\n" +
				"  for _, s := range typeVerbRelations { _ = s }\n" +
				"  return m\n" +
				"}()\n" +
				"func IsExpandableRelation(r string) bool { return expandableRelations[r] }\n" +
				"func ObjectType(k string) string { _ = typeVerbRelations; return k }\n",
			classified:  map[string]bool{"ObjectType": true},
			wantReaders: []string{"ObjectType"},
		},
		{
			name: "контроль: неэкспортированный читатель находкой не является",
			body: "package authzmap\n" +
				"var objectTypes = map[string]string{}\n" +
				"func lookup(k string) string { return objectTypes[k] }\n" +
				"func ObjectType(k string) string { return lookup(k) }\n",
			classified:  map[string]bool{"ObjectType": true},
			wantReaders: []string{"ObjectType"},
		},
		{
			name: "инъекция: набор называет имя, которого в пакете НЕТ",
			body: "package authzmap\n" +
				"var objectTypes = map[string]string{}\n" +
				"func ObjectType(k string) string { return objectTypes[k] }\n",
			classified:   map[string]bool{"ObjectType": true, "VerbsOfType": true},
			wantReaders:  []string{"ObjectType"},
			wantFindings: []string{"имя-набора-без-предмета:VerbsOfType"},
		},
		{
			name: "инъекция: послаблению больше нечего исключать",
			body: "package authzmap\n" +
				"var objectTypes = map[string]string{}\n" +
				"func ObjectType(k string) string { return objectTypes[k] }\n" +
				"func CatalogSeedResources() []string { return nil }\n",
			classified:   map[string]bool{"ObjectType": true, "CatalogSeedResources": true},
			exemptions:   map[string]string{"CatalogSeedResources": "левая сторона паритета"},
			wantReaders:  []string{"ObjectType"},
			wantFindings: []string{"послабление-без-предмета:CatalogSeedResources"},
		},
		{
			name: "контроль: послабление С ПРЕДМЕТОМ молчит",
			body: "package authzmap\n" +
				"var objectTypes = map[string]string{}\n" +
				"func ObjectType(k string) string { return objectTypes[k] }\n" +
				"func CatalogSeedResources() []string { return []string{objectTypes[\"\"]} }\n",
			classified:  map[string]bool{"ObjectType": true, "CatalogSeedResources": true},
			exemptions:  map[string]string{"CatalogSeedResources": "левая сторона паритета"},
			wantReaders: []string{"CatalogSeedResources", "ObjectType"},
		},
		{
			name: "инъекция: читателей НОЛЬ — вердикта нет, а не чистое дерево",
			body: "package authzmap\n" +
				"var objectTypes = map[string]string{}\n" +
				"func SplitObjectType(t string) string { return t }\n",
			classified:  map[string]bool{},
			wantReaders: nil,
			wantVoid:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "fga_types.go")
			if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
				t.Fatalf("записать синтетику: %v", err)
			}
			readers, exported, c, err := authzmapLiteralReaders([]string{path})
			if err != nil {
				t.Fatalf("разбор синтетики: %v", err)
			}
			if c.Files == 0 || c.Funcs == 0 {
				t.Fatalf("синтетика не прочитана (файлов %d, функций %d) — инъекция ничего "+
					"не доказывает", c.Files, c.Funcs)
			}
			if strings.Join(readers, ",") != strings.Join(tc.wantReaders, ",") {
				t.Fatalf("читатели: получено %v, ожидалось %v", readers, tc.wantReaders)
			}

			// Граница беспредметного обхода — та же функция, что в гейте.
			void := recognizerVerdictless("синтетика", c, sortedKeys(catalogLiteralNames))
			if (void != "") != tc.wantVoid {
				t.Fatalf("беспредметность обхода: получено %q, ожидалась %v", void, tc.wantVoid)
			}
			if tc.wantVoid {
				return // при беспредметном обходе гейт до вердикта не доходит
			}

			// ВЕРДИКТ — той же функцией, что в гейте. Своей копии решения здесь
			// нет: выпотрошив `recognizerFindings`, эту инъекцию не оставить
			// зелёной, и ровно этого прежней редакции не хватало.
			findings := recognizerFindings(readers, exported, tc.classified, tc.exemptions)
			var got []string
			for _, f := range findings {
				got = append(got, fmt.Sprintf("%s:%s", f.Kind, f.Symbol))
			}
			sort.Strings(got)
			want := append([]string(nil), tc.wantFindings...)
			sort.Strings(want)
			if strings.Join(got, " | ") != strings.Join(want, " | ") {
				t.Fatalf("находки: получено %v, ожидалось %v", got, want)
			}

			// ОБЪЯВЛЕНИЕ — тем же объявителем, что в гейте, и в СВОЙ приёмник.
			// Вычислить находку и не сказать о ней — разные предметы: красное
			// даёт только второе, и без этой проверки «гейт посчитал и смолчал»
			// осталось бы непоказанным.
			var rec recordingReporter
			reportRecognizerFindings(&rec, findings)
			if len(rec.lines) != len(findings) {
				t.Fatalf("объявлено находок %d, а вычислено %d — вердикт вычисляется, "+
					"но не ОБЪЯВЛЯЕТСЯ", len(rec.lines), len(findings))
			}
			for i, f := range findings {
				// Находка обязана НАЗЫВАТЬ символ и свой вид: покрасневший молча
				// гейт посылает читателя искать не там.
				if !strings.Contains(rec.lines[i], f.Symbol) ||
					!strings.Contains(rec.lines[i], string(f.Kind)) {
					t.Errorf("объявленная находка не называет вид %q и символ %q: %q",
						f.Kind, f.Symbol, rec.lines[i])
				}
			}
		})
	}
}

// recordingReporter — приёмник объявлений для инъекции: запоминает то, что гейт
// напечатал бы в прогон. Подаётся вместо `*testing.T`, поэтому инъекция судит
// ОБЪЯВЛЕНИЕ, а не только вычисление.
type recordingReporter struct{ lines []string }

func (r *recordingReporter) Errorf(format string, args ...any) {
	r.lines = append(r.lines, fmt.Sprintf(format, args...))
}
