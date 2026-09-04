// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// seeddeclaration_internal_test.go — раздел `seed` не объявляет себя тем, чего
// у него нет (задача продукта #1948).
//
// # Что здесь было неверно
//
// Проза называла раздел ИМПЕРАТИВОМ — «что заводит УСТАНОВКА модуля», «выдачи,
// которые делает установка модуля», — а применителя у него нет ни одного.
// Единственный прод-читатель всех четырёх подразделов — валидатор связности,
// то есть судья формы, а не производитель строк. Строки заводит применённая
// МИГРАЦИЯ, и раздел с ними лишь сверяется (`internal/moduleseedparity`).
//
// Это не «принято-и-проигнорировано»: значение меняет исход загрузки, несвязный
// `seed` отвергается, и отказ виден. Неверна не обработка, а ОБЕЩАНИЕ — и оно
// дороже обычной устаревшей строки: у разделов `resources` и `roles`
// применитель есть, поэтому читатель вправе достроить его и для третьего.
//
// # Почему гейт, а не правка прозы
//
// Правка прозы закрывает экземпляр; класс закрывает гейт. И у него есть вторая
// половина, ради которой он и написан: он ИСТЕКАЕТ САМ. Появится применитель —
// гейт потребует перечитать прозу, вместо того чтобы позволить ей остаться
// заниженной. Утверждение, пережившее свой предмет, бывает неверно в обе
// стороны, и вторая замечается хуже первой.
//
// # Требование ПОЛОЖИТЕЛЬНОЕ, и это выбор
//
// Гейт требует, чтобы проза НАЗЫВАЛА свой статус, а не чтобы она не содержала
// запретных слов. Перечень запретных слов обходится переформулировкой молча;
// требование назвать статус переформулировкой не обходится — его надо снять,
// а снятие видно.
//
// Литеральный замок на прежнюю ложную фразу здесь СТОЯЛ и снят замером: он
// покраснел на прозе, которая эту фразу ЦИТИРУЕТ, объясняя, почему она снята.
// Это ровно класс «гейт по подстроке краснеет на собственном объяснении»
// (`testing.md` §«Гейт на класс», п. 4), и лечится он не хитрее написанным
// образцом, а отказом от запрета на слово: запрет вынуждал бы не объяснять
// историю, то есть платить прозой за проверку.
//
// Маркеры сверяются БЕЗ УЧЁТА РЕГИСТРА: проза законно выделяет несущее слово
// капителью («СВЕРЯЕТСЯ»), и регистрозависимая сверка объявила бы находкой
// стиль, а не предмет.
//
// # Граница названа честно
//
// Гейт судит доккомментарий типа `Seed` и его полей. НОВАЯ ложная формулировка
// другими словами, приписанная рядом с сохранённым объявлением статуса, им не
// ловится — это остаётся за обзором. Машинного предиката у «проза обещает
// несуществующее» нет, и обещать его здесь значило бы завести ровно тот класс,
// который гейт ловит.
package manifest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// seedSubsectionFields — четыре подраздела посева. Перечень выводится из САМОГО
// типа ниже и сверяется с этим списком: подраздел, добавленный к типу и не
// названный здесь, оказался бы вне наблюдения молча.
var seedSubsectionFields = []string{"AccessBindings", "Groups", "Joins", "ServiceAccounts"}

// manifestPackageDir — каталог самого пакета, исключаемый из поиска
// производителей: судья формы производителем не является, и считать его таковым
// значило бы никогда не увидеть появления настоящего.
const manifestPackageDir = "services/iam/internal/manifest"

// manifestImportPath — импорт, без которого держать `*manifest.Seed` нечем.
const manifestImportPath = "github.com/PRO-Robotech/kacho/services/iam/internal/manifest"

// seedProducerCensus — объём осмотренного вместе с находками: «ноль
// производителей» обязано быть отличимо от «ноль прочитанного».
type seedProducerCensus struct {
	filesRead int
	importers int
	producers []string
}

// findSeedRowProducers — файлы ВНЕ пакета manifest, читающие подразделы посева.
//
// # Почему поиск сужен импортом, а не именем переменной
//
// Прежний предикат задачи искал обращения к полю у переменной, названной
// `seed`. Такой предикат меряет СОГЛАШЕНИЕ ОБ ИМЕНОВАНИИ: переименование
// переменной вывело бы настоящего производителя из наблюдения, ничем этого не
// показав. Держать `*manifest.Seed`, не импортировав пакет, нельзя, поэтому
// импорт есть надёжная нижняя граница.
//
// # Приближение названо, и оно в БЕЗОПАСНУЮ сторону
//
// Селектор судится по имени поля, а не по разрешённому типу: файл, который
// импортирует пакет и зовёт `.Groups` у чего-то другого, будет сосчитан. Это
// ПЕРЕсчёт, и его исход — «производитель появился, перечитайте прозу», то есть
// взгляд человека. Недосчёт был бы опасен, и его здесь нет by construction.
func findSeedRowProducers(t *testing.T) seedProducerCensus {
	t.Helper()
	root := treeRootFromPackage
	var census seedProducerCensus
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(fsPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(fsPath, ".go") || strings.HasSuffix(fsPath, "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, fsPath)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		// Исключается САМ пакет, а не его поддерево: подпакет (`roleexport`) —
		// отдельный пакет, и производитель, заведённый в нём, обязан быть
		// виден. Исключение поддеревом дало бы НЕДОсчёт — единственное
		// направление ошибки, которое здесь опасно.
		if path.Dir(rel) == manifestPackageDir {
			return nil
		}
		census.filesRead++

		src, readErr := os.ReadFile(fsPath)
		if readErr != nil {
			return readErr
		}
		file, parseErr := parser.ParseFile(fset, fsPath, src, parser.SkipObjectResolution)
		if parseErr != nil {
			// Неразбираемый файл — не находка и не молчание: о нём вердикт не
			// выносится, и сказать это надо вслух.
			t.Logf("НЕ РАЗОБРАН (вердикт по нему не выносится): %s: %v", rel, parseErr)
			return nil
		}
		imports := false
		for _, spec := range file.Imports {
			if strings.Trim(spec.Path.Value, `"`) == manifestImportPath {
				imports = true
				break
			}
		}
		if !imports {
			return nil
		}
		census.importers++

		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if !inSet(seedSubsectionFields, sel.Sel.Name) {
				return true
			}
			census.producers = append(census.producers,
				rel+":"+fset.Position(sel.Pos()).String()[len(fset.Position(sel.Pos()).Filename)+1:]+
					" читает "+sel.Sel.Name)
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("обход дерева не состоялся (%s): %v — «ноль производителей» означало бы "+
			"«ноль прочитанного»", root, err)
	}
	sort.Strings(census.producers)
	return census
}

// seedDocBlock — доккомментарий типа Seed вместе с доккомментариями его полей,
// прочитанный РАЗБОРОМ, а не поиском по тексту файла.
//
// Разбор здесь несущий: тот же текст встречается в прозе соседних объявлений и
// в этом самом файле, и гейт по подстроке краснел бы на собственном объяснении.
func seedDocBlock(t *testing.T) (doc string, fields []string) {
	t.Helper()
	const src = "manifest.go"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, src, nil, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("%s не разобран: %v — судить о прозе нечем", src, err)
	}

	var found bool
	var parts []string
	// Обход идёт по GenDecl, а не по TypeSpec, и это НЕ педантизм: у одиночного
	// объявления `type Seed struct` доккомментарий Go привязывает к GenDecl, и
	// TypeSpec.Doc остаётся nil. Первая редакция этого гейта читала только
	// TypeSpec.Doc — она молча судила ОДНИ доккомментарии полей и не видела
	// прозы самого типа вовсе. Поймано тем, что маркеры не нашлись в тексте,
	// который был только что написан; чтением кода это не находится.
	ast.Inspect(file, func(n ast.Node) bool {
		decl, ok := n.(*ast.GenDecl)
		if !ok || decl.Tok != token.TYPE {
			return true
		}
		for _, s := range decl.Specs {
			spec, isType := s.(*ast.TypeSpec)
			if !isType || spec.Name.Name != "Seed" {
				continue
			}
			found = true
			// Обе формы привязки: групповое объявление кладёт доккомментарий на
			// TypeSpec, одиночное — на GenDecl. Форма, о которой обход не знает,
			// не даёт ни красного, ни зелёного — она молчит.
			if spec.Doc != nil {
				parts = append(parts, spec.Doc.Text())
			}
			if decl.Doc != nil {
				parts = append(parts, decl.Doc.Text())
			}
			st, isStruct := spec.Type.(*ast.StructType)
			if !isStruct || st.Fields == nil {
				continue
			}
			for _, f := range st.Fields.List {
				if f.Doc == nil || len(f.Names) == 0 {
					continue
				}
				fields = append(fields, f.Names[0].Name)
				parts = append(parts, f.Doc.Text())
			}
		}
		return true
	})
	if !found {
		t.Fatalf("тип Seed в %s не найден — гейт судит несуществующее, "+
			"и его молчание не является вердиктом", src)
	}
	sort.Strings(fields)
	return strings.Join(parts, "\n"), fields
}

// statusMarkers — чем проза ОБЯЗАНА назвать свой статус, пока производителя нет.
//
// Перечень явный и правится осознанно: требование назвать статус тем и ценно,
// что переформулировкой не обходится — его надо снять, а снятие видно.
var statusMarkers = []struct{ marker, why string }{
	{"ОБЪЯВЛЕНИЕ", "раздел обязан назвать себя объявлением, а не императивом"},
	{"миграц", "проза обязана назвать НАСТОЯЩЕГО производителя строк"},
	{"сверя", "проза обязана назвать, чем объявленное сверяется с живой базой"},
}

// TestSeedSectionProseMatchesItsProducers — проза раздела `seed` отвечает тому,
// что дерево о нём производит; и обязана быть перечитана, когда производитель
// появится.
func TestSeedSectionProseMatchesItsProducers(t *testing.T) {
	census := findSeedRowProducers(t)
	doc, fields := seedDocBlock(t)

	t.Logf("перепись: не-тестовых файлов Go прочитано %d · из них импортируют пакет манифеста %d · "+
		"читателей подразделов посева вне пакета %d · подразделов у типа %d · доккомментарий %d знаков",
		census.filesRead, census.importers, len(census.producers), len(fields), len(doc))

	if census.filesRead == 0 {
		t.Fatalf("обход прочитал ноль файлов — вердикт беспредметен")
	}
	if census.importers == 0 {
		t.Fatalf("пакет манифеста не импортирует ни один файл дерева — обход ищет не там, " +
			"и «ноль производителей» означало бы «ноль прочитанного»")
	}
	if len(fields) != len(seedSubsectionFields) {
		t.Fatalf("подразделов у типа Seed %d (%s), а гейт знает %d (%s) — "+
			"подраздел вне этого перечня оказался бы вне наблюдения",
			len(fields), strings.Join(fields, ", "),
			len(seedSubsectionFields), strings.Join(seedSubsectionFields, ", "))
	}

	if len(census.producers) > 0 {
		t.Fatalf("производитель строк посева ПОЯВИЛСЯ (%d) — проза раздела обязана быть перечитана, "+
			"а этот гейт снят вместе со своим предметом; пока он молчал, проза называла раздел "+
			"объявлением, и теперь это занижение:\n  %s",
			len(census.producers), strings.Join(census.producers, "\n  "))
	}

	// Производителя нет — значит проза обязана называть раздел объявлением.
	for _, m := range statusMarkers {
		if !strings.Contains(strings.ToLower(doc), strings.ToLower(m.marker)) {
			t.Errorf("проза раздела `seed` не несёт %q: %s.\n"+
				"Применителя у раздела нет ни одного, поэтому «что заводит установка» есть обещание "+
				"без исполнителя: строки заводит применённая миграция, а раздел с ними сверяется",
				m.marker, m.why)
		}
	}
}
