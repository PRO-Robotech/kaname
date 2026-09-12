// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// alert_outcome_values_test.go — ОТБОР ПО ЗНАЧЕНИЮ ИСХОДА на опубликованной
// странице называет значение, которое дерево ПРОИЗВОДИТ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Четыре ряда исходов несут ЗАКРЫТЫЕ словари значений, объявленные в коде.
// Запрос дежурного и правило тревоги повторяют значение строкой PromQL — то есть
// словарь оказывается в двух местах. Переименование в коде тогда не двигает
// правило, и правило перестаёт совпадать с чем-либо: отбор даёт пустой ряд,
// выражение не превышает порога НИ ПРИ КАКОМ состоянии продукта, а «не звонит»
// неотличимо от «всё в порядке».
//
// Соседний гейт (`TestObservabilityPagePromisesOnlyWhatTheServiceProduces`) этого
// класса не видит BY CONSTRUCTION: он судит ИМЯ РЯДА, а имя ряда здесь верное.
// Неверен отбор ВНУТРИ ряда, и он лежит ровно в его слепой зоне.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СУДЯТСЯ И ОТРИЦАТЕЛЬНЫЕ ОТБОРЫ
//
// У отбора по имени контракта отрицание безвредно: не совпавшее ни с чем
// отрицание ничего не исключает. Здесь иначе — значение приходит из ЗАКРЫТОГО
// словаря, и промах отрицания РАСШИРЯЕТ числитель: `outcome!="accepted"` при
// переименовании успеха начинает считать успех отказом. Ошибка при этом громкая,
// а не тихая, — но она всё равно ошибка, и словарь называет её предикатом.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА ПРОВЕРКА НЕ ЗАКРЫВАЕТ — сказано прямо
//
// Она судит СУЩЕСТВОВАНИЕ значения в словаре, а не верность его толкования:
// страница вправе объяснить существующий исход неправильно. Она также не судит
// ряды, чьего словаря в таблице ниже нет, — а таблица перечисляет ровно четыре
// ряда, у которых закрытый словарь объявлен кодом.
package supplyhygiene

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/expiredcredsweep"
	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
	"github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// outcomeDictionaries — ряды с ЗАКРЫТЫМ словарём значений метки `outcome` и сам
// словарь.
//
// Таблица связывает имя ряда с ЖИВЫМ объявлением, а не с копией значений: снятие
// объявления роняет сборку этой пробы, а не оставляет её зелёной на мёртвом
// словаре.
func outcomeDictionaries() map[string][]string {
	return map[string][]string{
		metrics.ReadinessChecksMetric:                metrics.ReadinessOutcomes,
		metrics.AuthnHookRequestsMetric:              iamhooks.LaneOutcomes(),
		metrics.ExpiredCredentialReclaimPassesMetric: expiredcredsweep.Outcomes(),
		metrics.ClientTokenOutcomesMetric:            clienttokenhttp.DeclaredOutcomes(),
	}
}

// seriesSelectorRe — ряд вместе со своим отбором: `имя{...}`.
var seriesSelectorRe = regexp.MustCompile(`\b(kaname_[a-z0-9_]+)\{([^}]*)\}`)

// outcomeMatcherRe — позиция отбора по исходу: метка, оператор и строка.
var outcomeMatcherRe = regexp.MustCompile(`outcome\s*(=~|!~|=|!=)\s*"((?:[^"\\]|\\.)*)"`)

// outcomeCensus — объём осмотренного одним обходом.
type outcomeCensus struct {
	pageLines    int // строк осмотрено
	seriesWithIn int // вхождений ряда с отбором
	matchers     int // отборов по исходу найдено
	valuesNamed  int // названных значений (альтернативы регулярного отбора врозь)
	dictionaries int // словарей в таблице
	declared     int // значений во всех словарях
}

// outcomeFinding — одно названное значение, которого словарь не несёт.
type outcomeFinding struct {
	series string
	value  string
}

func (f outcomeFinding) String() string { return f.series + "{outcome=\"" + f.value + "\"}" }

// scanOutcomeSelectors — разбор над ПРОИЗВОЛЬНЫМ текстом и таблицей словарей.
//
// Вынесено из пробы затем, чтобы способность упасть доказывалась подачей входа, а
// не чтением.
func scanOutcomeSelectors(raw string, dictionaries map[string][]string) (outcomeCensus, []outcomeFinding) {
	census := outcomeCensus{
		pageLines:    len(strings.Split(raw, "\n")),
		dictionaries: len(dictionaries),
	}
	known := map[string]map[string]bool{}
	for series, values := range dictionaries {
		set := make(map[string]bool, len(values))
		for _, v := range values {
			set[v] = true
		}
		known[series] = set
		census.declared += len(values)
	}

	var findings []outcomeFinding
	for _, m := range seriesSelectorRe.FindAllStringSubmatch(raw, -1) {
		series, inside := m[1], m[2]
		census.seriesWithIn++
		set, judged := known[series]
		for _, sm := range outcomeMatcherRe.FindAllStringSubmatch(inside, -1) {
			census.matchers++
			// Регулярный отбор несёт альтернативы через `|`; каждая — своё
			// названное значение. Прочие знаки регулярного выражения делают
			// альтернативу не литералом, и такую судить нечем: она пропускается,
			// а не объявляется находкой.
			for _, value := range strings.Split(sm[2], "|") {
				census.valuesNamed++
				if !judged || regexp.QuoteMeta(value) != value || value == "" {
					continue
				}
				if !set[value] {
					findings = append(findings, outcomeFinding{series: series, value: value})
				}
			}
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].String() < findings[j].String() })
	return census, findings
}

func TestAlertOutcomeSelectorsNameValuesTheTreeProduces(t *testing.T) {
	root, err := iamRootFromHere()
	require.NoError(t, err, "корень дерева службы")

	path := filepath.Join(root, observabilityPage)
	raw, err := os.ReadFile(path) // #nosec G304 -- путь из корня службы
	require.NoErrorf(t, err, "опубликованная страница не читается: %s", path)

	dictionaries := outcomeDictionaries()
	census, findings := scanOutcomeSelectors(string(raw), dictionaries)

	t.Logf("ПЕРЕПИСЬ отборов по исходу:\n"+
		"  строк страницы %d · вхождений ряда с отбором %d · отборов по исходу %d · "+
		"названных значений %d · словарей %d · объявленных значений %d · находок %d",
		census.pageLines, census.seriesWithIn, census.matchers, census.valuesNamed,
		census.dictionaries, census.declared, len(findings))

	// Предпосылки: обход непуст с обеих сторон. Пустая страница и пустая таблица
	// дали бы «находок ноль» там, где судить было нечего.
	require.NotZero(t, census.matchers, "отборов по исходу на странице НОЛЬ — "+
		"проверка стережёт координату, которой больше нет")
	require.NotZero(t, census.declared, "словари пусты — сверять названное не с чем")

	require.Emptyf(t, findings, "отбор называет значение исхода, которого словарь НЕ несёт: %v.\n"+
		"Такой отбор даёт пустой ряд и в числителе, и в знаменателе: выражение не превышает "+
		"порога ни при каком состоянии продукта, а «не звонит» неотличимо от «всё в порядке».",
		findings)
}

// iamRootFromHere — корень дерева службы от каталога пробы.
//
// Своя, а не общая с соседним гейтом: тот берёт корень из вспомогательного
// инструмента, а здесь довольно подъёма до файла модуля — и подъём этот
// ограничен, чтобы в чужом дереве проба не нашла чужой корень.
func iamRootFromHere() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("корень модуля не найден подъёмом от %s", dir)
}
