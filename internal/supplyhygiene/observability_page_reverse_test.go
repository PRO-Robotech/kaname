// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// observability_page_reverse_test.go — ОБРАТНОЕ направление: каждый ряд, который
// служба производит, назван на опубликованной странице.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТО ВТОРАЯ ПРОВЕРКА, А НЕ ВТОРАЯ ПОЛОВИНА ПЕРВОЙ
//
// Соседняя проверка (`TestObservabilityPagePromisesOnlyWhatTheServiceProduces`)
// идёт СТРАНИЦА → ПРОИЗВОДИТЕЛЬ и ловит обещание величины, которой нет.
// Обратного направления у неё нет вовсе, и это её ОБЪЯВЛЕННАЯ граница, а не
// забывчивость: ряд, у которого нет ни строки на странице, для неё невидим.
//
// Величина без читателя — не наблюдаемость, а её вид. Она создаёт уверенность,
// что за предметом следят, и через полгода снимается как мёртвая — вместе с тем
// свойством, ради которого заводилась. Дежурный, не читая кода, о ней не узнает
// НИКОГДА: страница — единственный артефакт, который он получает.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СВОЙ РАЗБОР, А НЕ УКАЗАТЕЛЬ ПРОИЗВОДИТЕЛЕЙ СОСЕДНЕЙ ПРОВЕРКИ
//
// Тот указатель ПЕРМИССИВЕН по построению и объявляет это прямо: он принимает
// имя, объявленное где угодно в ОБОИХ модулях — службы и фундамента. Для прямого
// направления это безопасно (ошибиться он может только в сторону «принял
// существующее»), а для обратного — неверно by construction: он вернул бы ряды
// ФУНДАМЕНТА, за чью страницу эта служба не отвечает, и требовал бы описать
// чужое. Поэтому здесь свой обход, и его корень ОДИН — пакет величин службы.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПЕРЕЧНЯ ПРОЩЁННЫХ ЗДЕСЬ НЕТ, И ЭТО РЕШЕНИЕ
//
// Каждая запись такого перечня — место, куда невидимость вносят незамеченной.
// Ряд, которому читатель не нужен, снимается ВМЕСТЕ С ПРОИЗВОДИТЕЛЕМ, а не
// вносится в список: производитель без читателя и есть предмет этой проверки.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЕДИНИЦА СЧЁТА НАЗВАНА, ПОТОМУ ЧТО ДРУГАЯ ДАЁТ ДРУГОЕ ЧИСЛО
//
// Единица — ИМЯ РЯДА, собранное разбором В ПОЗИЦИИ ИМЕНИ РЯДА: поле `Name:`
// настроек коллектора либо первый довод `prometheus.NewDesc`. Счёт по константам
// вида `*Metric` даёт другое число — часть имён стоит литералом по месту.
//
// ЧЕГО ЭТА ПРОВЕРКА НЕ ЗАКРЫВАЕТ: верность толкования. Страница вправе объяснить
// существующий ряд неправильно, и машинного предиката у этого нет.
package supplyhygiene

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// serviceMetricsPkg — ЕДИНСТВЕННЫЙ корень обхода этой проверки.
const serviceMetricsPkg = "internal/observability/metrics"

// reverseCensus — объём осмотренного. Печатается всегда.
type reverseCensus struct {
	filesRead int // не-тестовых файлов пакета величин прочитано
	declared  int // имён рядов объявлено
	named     int // из них названо на странице
	missing   int // из них НЕ названо
}

// collectServiceSeries — имена рядов, объявленные пакетом величин СЛУЖБЫ.
//
// Разбором, а не поиском слова: имена рядов стоят и в текстах справки, и в
// комментариях, и поиск словом принял бы за объявление собственное объяснение.
func collectServiceSeries(pkgDir string) (map[string]string, reverseCensus, error) {
	var census reverseCensus
	out := map[string]string{} // имя ряда → координата объявления
	fset := token.NewFileSet()

	var files []*ast.File
	where := map[*ast.File]string{}
	err := filepath.WalkDir(pkgDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		files = append(files, f)
		where[f] = path
		census.filesRead++
		return nil
	})
	if err != nil {
		return nil, census, err
	}

	consts := metricNameConsts(files)
	for _, f := range files {
		rel := where[f]
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.KeyValueExpr:
				if k, ok := x.Key.(*ast.Ident); ok && k.Name == "Name" {
					if v, ok := evalString(x.Value, consts); ok && seriesShape.MatchString(v) {
						out[v] = fset.Position(x.Pos()).String()
						_ = rel
					}
				}
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "NewDesc" || len(x.Args) == 0 {
					return true
				}
				if v, ok := evalString(x.Args[0], consts); ok && seriesShape.MatchString(v) {
					out[v] = fset.Position(x.Pos()).String()
				}
			}
			return true
		})
	}
	census.declared = len(out)
	return out, census, nil
}

// TestEveryProducedSeriesIsNamedOnTheObservabilityPage — НЕСУЩЕЕ утверждение.
func TestEveryProducedSeriesIsNamedOnTheObservabilityPage(t *testing.T) {
	declared, census, err := collectServiceSeries(filepath.Join(serviceRoot, serviceMetricsPkg))
	require.NoError(t, err)
	require.NotZerof(t, census.filesRead,
		"обход пакета величин пуст (%s) — вердикта о производимых рядах нет",
		serviceMetricsPkg)
	require.NotZerof(t, census.declared,
		"пакет величин не объявил НИ ОДНОГО ряда — проверка вакуумна: либо пакет "+
			"переехал, либо разбор перестал узнавать позицию имени ряда")

	raw, err := os.ReadFile(filepath.Join(serviceRoot, observabilityPage))
	require.NoError(t, err)
	page := string(raw)

	names := make([]string, 0, len(declared))
	for name := range declared {
		names = append(names, name)
	}
	sort.Strings(names)

	var missing []string
	for _, name := range names {
		if strings.Contains(page, name) {
			census.named++
			continue
		}
		census.missing++
		missing = append(missing, name+" (объявлен "+declared[name]+")")
	}

	t.Logf("перепись: файлов пакета величин прочитано %d · имён рядов объявлено %d · "+
		"названо на странице %d · НЕ названо %d",
		census.filesRead, census.declared, census.named, census.missing)

	require.Emptyf(t, missing,
		"служба производит %d ряд(ов), у которых на опубликованной странице нет ни "+
			"строки. Величина без читателя — не наблюдаемость, а её вид: дежурный, не "+
			"читая кода, о ней не узнает. Ряд, которому читатель не нужен, снимается "+
			"ВМЕСТЕ С ПРОИЗВОДИТЕЛЕМ, а не вносится в перечень прощённых:\n  %s",
		len(missing), strings.Join(missing, "\n  "))
}
