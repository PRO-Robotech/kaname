// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// observability_page_provider_roads_test.go — строка семейства дорог к
// поставщику на опубликованной странице называет РОВНО те дороги и клетки
// исхода, что семейство считает, и значениями метки, а не своими словами.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Соседняя проверка страницы (`observability_page_test.go`) судит СУЩЕСТВОВАНИЕ
// ряда и прямо говорит, что верность его толкования вне её наблюдения. У этого
// семейства толкование и есть запрос: значение метки `road` дежурный берёт со
// страницы и подставляет в выражение. Строка, называющая дорогу, которой
// семейство не считает, отдаёт ему пустой ряд, а пустой ряд читается как
// «событий не было».
//
// Так и было: строка называла три контура (`ADMIN`, `JWKS`, `TOKEN`), а
// семейство считает две дороги — `admin` и `token_exchange`. Дорога набора
// ключей снята вместе с зеркалом этого набора (kaname#361), а написание
// заглавными не совпадало со значением метки ни у одной из трёх.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СУДИТСЯ — три утверждения об ОДНОЙ строке таблицы
//
//  1. строка с именем семейства в первой ячейке есть, и она одна: вторая строка
//     о том же семействе — два места об одном предмете;
//  2. каждое значение обоих закрытых наборов — дорог и клеток исхода — названо в
//     ячейке толкования в обратных кавычках, написанием метки. Требуются ОБА
//     набора: перечень, названный частью, стареет пропуском так же молча, как
//     лишним значением;
//  3. всякое значение в обратных кавычках той же ячейки — из словаря семейства:
//     имя метки (вторая ячейка строки), значение закрытого набора либо имя
//     ряда. Иное — утверждение о клетке, которой семейство не производит.
//
// Набор дорог и набор клеток берутся у ВЛАДЕЛЬЦА (`internal/clients`), а не
// выписываются здесь: выписанная копия разошлась бы с ним так же молча, как
// разошлась страница.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА ПРОВЕРКА НЕ СУДИТ — сказано прямо
//
// Прозу без обратных кавычек: число дорог, названное словом, вне её наблюдения.
// И остальные строки страницы: у их семейств свои закрытые наборы, и сверка
// каждого — отдельный предмет, а не расширение этого.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// backtickedValue — значение в обратных кавычках внутри ячейки таблицы.
var backtickedValue = regexp.MustCompile("`([^`]+)`")

// familyRowCensus — объём осмотренного одним разбором.
type familyRowCensus struct {
	tableRows int // строк таблиц на странице
	rows      int // из них с именем семейства в первой ячейке
	line      int // номер первой такой строки
	labels    int // имён меток во второй ячейке
	values    int // значений в обратных кавычках в ячейке толкования
	required  int // значений закрытых наборов, обязанных быть названными
}

// tableCells режет строку таблицы на ячейки. Не строка таблицы — nil.
func tableCells(line string) []string {
	s := strings.TrimSpace(line)
	if !strings.HasPrefix(s, "|") || !strings.HasSuffix(s, "|") || len(s) < 2 {
		return nil
	}
	parts := strings.Split(s[1:len(s)-1], "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// judgeFamilyRow — разбор над ПРОИЗВОЛЬНОЙ страницей. Вынесен из пробы затем,
// чтобы способность упасть доказывалась подачей входа, а не чтением.
//
// required — значения закрытых наборов семейства: строка обязана назвать каждое
// и не вправе называть иных, кроме имён своих меток и рядов.
func judgeFamilyRow(raw, metric string, required []string) (familyRowCensus, []string) {
	var census familyRowCensus
	census.required = len(required)
	head := "`" + metric + "`"
	var labelsCell, meaningCell string
	for i, line := range strings.Split(raw, "\n") {
		cells := tableCells(line)
		if cells == nil {
			continue
		}
		census.tableRows++
		if len(cells) < 3 || cells[0] != head {
			continue
		}
		census.rows++
		if census.rows == 1 {
			census.line = i + 1
			labelsCell, meaningCell = cells[1], cells[2]
		}
	}

	var findings []string
	switch census.rows {
	case 0:
		return census, []string{"строки семейства " + metric + " на странице нет: запрос по его " +
			"клеткам дежурному строить не по чему"}
	case 1:
	default:
		findings = append(findings, "строк семейства "+metric+" на странице "+
			strconv.Itoa(census.rows)+": два места об одном семействе расходятся молча")
	}

	vocab := map[string]bool{}
	for _, v := range required {
		vocab[v] = true
	}
	for _, m := range backtickedValue.FindAllStringSubmatch(labelsCell, -1) {
		census.labels++
		vocab[m[1]] = true
	}

	named := map[string]bool{}
	for _, m := range backtickedValue.FindAllStringSubmatch(meaningCell, -1) {
		census.values++
		v := m[1]
		named[v] = true
		if vocab[v] || seriesShape.FindString(v) == v {
			continue
		}
		findings = append(findings, "строка "+strconv.Itoa(census.line)+" называет `"+v+
			"`, а семейство "+metric+" такой клетки не производит: запрос по ней вернёт "+
			"пустой ряд, а пустой ряд читается как «событий не было»")
	}
	for _, v := range required {
		if !named[v] {
			findings = append(findings, "строка "+strconv.Itoa(census.line)+" не называет `"+v+
				"`, хотя семейство "+metric+" его считает: запрос о нём по странице не построить")
		}
	}
	return census, findings
}

func TestObservabilityPageNamesEveryCellOfTheProviderRoadFamily(t *testing.T) {
	// ПРЕДПОСЫЛКА: наборы, с которыми сверяется строка, не пусты. Пустой набор
	// сделал бы требование «назвать каждое значение» выполнимым ничем.
	require.NotEmpty(t, clients.ProviderRoads, "закрытый набор дорог пуст — сверять строку не с чем")
	require.NotEmpty(t, clients.ProviderRoadOutcomes, "закрытый набор клеток исхода пуст — сверять строку не с чем")

	path := filepath.Join(serviceRoot, observabilityPage)
	raw, err := os.ReadFile(path)
	require.NoErrorf(t, err, "страница не прочитана: %s", path)

	required := append(append([]string{}, clients.ProviderRoads...), clients.ProviderRoadOutcomes...)
	census, findings := judgeFamilyRow(string(raw), metrics.ProviderRoadOutcomesMetric, required)
	t.Logf("перепись: строк таблиц %d · из них строк семейства %s %d (строка %d) · "+
		"имён меток %d · значений в толковании %d · значений закрытых наборов %d · находок %d",
		census.tableRows, metrics.ProviderRoadOutcomesMetric, census.rows, census.line,
		census.labels, census.values, census.required, len(findings))

	require.NotZero(t, census.tableRows, "обход пуст: ни одной строки таблицы — страница не та либо не прочитана")
	for _, f := range findings {
		t.Errorf("%s: %s", filepath.ToSlash(path), f)
	}
}
