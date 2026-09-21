// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iamhooks_test

// route_prose_names_every_route_test.go — ПРОЗА ПАКЕТА, ПЕРЕЧИСЛЯЮЩАЯ МАРШРУТЫ,
// ВЫВОДИТСЯ ИЗ ПРОИЗВОДИТЕЛЯ ПЕРЕЧНЯ, А НЕ ПИШЕТСЯ ПО ПАМЯТИ.
//
// # Предмет
//
// У полосы хуков ЧЕТЫРЕ маршрута, и производитель перечня один — [iamhooks.Routes].
// Шапки пакета называли ТРИ из четырёх: четвёртый (завершение восстановления)
// приехал позже соседей, а шапки остались прежними. Утверждение пережило свой
// предмет молча — прозу никто не сверяет с кодом, и разошлись они в сторону
// «маршрута нет», то есть в сторону, по которой читатель решит, что его и не
// заводили.
//
// # Форма утверждения — БЕЗУСЛОВНАЯ
//
// Не «в doc.go есть recovery» — такая проба истекла бы вместе с именем файла и
// ничего не сказала бы о следующем маршруте. Утверждается свойство КЛАССА:
//
//	всякая шапка пакета, ПЕРЕЧИСЛЯЮЩАЯ маршруты полосы, обязана перечислить
//	их ВСЕ.
//
// Перечень файлов не выписывается: он выводится тем же обходом, что и перепись.
// Перечень маршрутов не выписывается: он берётся у производителя. Выписанная
// копия того или другого разошлась бы молча — ровно тем дефектом, который эта
// проба и закрывает.
//
// # Что такое «перечисляющая» — и почему не «называющая хотя бы один»
//
// Шапка обработчика называет РОВНО СВОЙ маршрут, и это законно: она описывает
// один файл, а не полосу. Предикат «назвал один — назови все» краснел бы на
// трёх таких шапках, то есть ловил бы форму, а не существо, и снять красное
// можно было бы только вписав в шапку каждого обработчика чужие маршруты.
//
// Перечисление узнаётся по числу: шапка, назвавшая БОЛЕЕ ОДНОГО маршрута, есть
// опись полосы, и опись обязана быть полной. Это ровно тот признак, который
// отличает `doc.go` и `http_server.go` от трёх шапок обработчиков, и он
// выводится из самого текста, а не из перечня имён файлов.
//
// # Читается ШАПКА, а не текст файла
//
// `http_server.go` несёт пути маршрутов в ИСПОЛНЯЕМОЙ части (`mux.Handle`).
// Предикат по тексту файла был бы зелен от кода и не сказал бы о прозе ничего.
// Поэтому шапка берётся разбором (`go/parser`, `f.Doc`), а не поиском по
// образцу.
//
// # Предпосылка и перепись
//
// Обход, не нашедший НИ ОДНОГО файла с шапкой, называющей маршрут, — не
// «находок ноль», а «прочитано ноль»: такой исход отказ, а не зелёное. Объём
// осмотренного печатается всегда.

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

	"github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
)

// routeProseCensus — объём осмотренного. Печатается и при нуле находок:
// «находок ноль» обязано быть отличимо от «прочитано ноль».
type routeProseCensus struct {
	FilesWalked  int
	FilesWithDoc int
	// FilesNaming — шапок-ОПИСЕЙ: назвавших более одного маршрута.
	FilesNaming int
	DocLines    int
	Routes      int
}

func (c routeProseCensus) String() string {
	return fmt.Sprintf("файлов обойдено %d · с шапкой %d · шапок-описей %d · "+
		"строк шапок прочитано %d · маршрутов у производителя %d",
		c.FilesWalked, c.FilesWithDoc, c.FilesNaming, c.DocLines, c.Routes)
}

// routeProseFinding — одна шапка, назвавшая часть перечня.
type routeProseFinding struct {
	File    string
	Named   []string
	Missing []string
}

func (f routeProseFinding) String() string {
	return fmt.Sprintf("%s: шапка называет маршруты %v и НЕ называет %v — "+
		"перечень в прозе отстал от производителя [iamhooks.Routes]; читатель шапки "+
		"решит, что неназванного маршрута нет",
		f.File, f.Named, f.Missing)
}

// routeHookPath — путь маршрута по его имени. ОДНО место перевода: имя метки
// величины и путь на мультиплексоре — две стороны одного соответствия.
func routeHookPath(route string) string { return "/iam/v1/hooks/" + route }

// judgeRouteProse судит шапки пакета в каталоге dir против перечня routes.
//
// Отдельной функцией — ради инъекции: доказать способность упасть можно только
// тем же кодом, который исполняется на дереве, поданным синтетикой.
func judgeRouteProse(dir string, routes []string) ([]routeProseFinding, routeProseCensus, error) {
	var census routeProseCensus
	census.Routes = len(routes)
	if len(routes) == 0 {
		return nil, census, fmt.Errorf("производитель перечня маршрутов пуст — судить нечего, " +
			"и «находок ноль» означало бы «предмета нет»")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, census, fmt.Errorf("каталог пакета не прочитан: %w", err)
	}

	fset := token.NewFileSet()
	var findings []routeProseFinding
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		census.FilesWalked++
		f, perr := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.ParseComments)
		if perr != nil {
			return nil, census, fmt.Errorf("файл %s не разобран: %w", e.Name(), perr)
		}
		doc := packageDocOf(f)
		if doc == "" {
			continue
		}
		census.FilesWithDoc++
		census.DocLines += strings.Count(doc, "\n") + 1

		var named, missing []string
		for _, r := range routes {
			if strings.Contains(doc, routeHookPath(r)) {
				named = append(named, r)
			} else {
				missing = append(missing, r)
			}
		}
		// ОПИСЬ ПОЛОСЫ — шапка, назвавшая БОЛЕЕ ОДНОГО маршрута. Шапка
		// обработчика называет ровно свой и описью не является: требовать от неё
		// полноты значило бы вписывать в неё чужие маршруты.
		if len(named) < 2 {
			continue
		}
		census.FilesNaming++
		if len(missing) > 0 {
			sort.Strings(named)
			sort.Strings(missing)
			findings = append(findings, routeProseFinding{File: e.Name(), Named: named, Missing: missing})
		}
	}

	if census.FilesNaming == 0 {
		return nil, census, fmt.Errorf("ни одна шапка пакета не перечисляет маршрутов полосы — " +
			"предпосылка пробы отказала: судить нечего, и это НЕ зелёное")
	}
	return findings, census, nil
}

// packageDocOf — шапка пакета: комментарий, стоящий ПЕРЕД словом package.
// Берётся разбором; текст исполняемой части сюда не попадает by construction.
func packageDocOf(f *ast.File) string {
	if f.Doc == nil {
		return ""
	}
	return f.Doc.Text()
}

// TestPackageProseNamesEveryRouteOfTheProducer — свойство на ДЕРЕВЕ.
func TestPackageProseNamesEveryRouteOfTheProducer(t *testing.T) {
	findings, census, err := judgeRouteProse(".", iamhooks.Routes())
	t.Log(census)
	if err != nil {
		t.Fatalf("прогон недействителен: %v", err)
	}
	if len(findings) == 0 {
		return
	}
	var say []string
	for _, f := range findings {
		say = append(say, f.String())
	}
	t.Fatalf("шапок, отставших от производителя перечня: %d\n  %s",
		len(findings), strings.Join(say, "\n  "))
}
