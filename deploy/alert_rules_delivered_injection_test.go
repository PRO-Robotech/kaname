// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// alert_rules_delivered_injection_test.go — доказательство того, что сверка
// объекта со страницей СПОСОБНА упасть, и того, что она молчит на законных
// близнецах.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВА РОДА ИНЪЕКЦИИ, И ПЕРВЫЙ ВАЖНЕЕ
//
//	СКВОЗНАЯ  — настоящий чарт, настоящая страница, РОВНО ОДИН изменённый факт:
//	            ручка объекта выключена. Она проверяет ВЕСЬ путь (рендер →
//	            разбор → сверка), а не одну функцию, и потому доказывает, что
//	            упадёт именно проба, а не только её арифметика.
//	СИНТЕТИЧЕСКАЯ — расхождения, которых в дереве сегодня нет: лишнее правило,
//	            уехавшее выражение, разошедшийся текст для дежурного. Настоящим
//	            деревом их не подать, не внеся дефект в поставку.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ ЗДЕСЬ БЛИЗНЕЦ ПРО ПРОБЕЛЫ
//
// Сверка нормализует выражение по пробелам: страница несёт его блочным
// скаляром с одним отступом, объект — с другим, и различие отступа различием
// правила НЕ является. Решение это спорное ровно в одну сторону — оно могло бы
// заодно проглотить настоящее расхождение текста. Поэтому доказываются ОБЕ
// стороны: отступ молчит, изменённое слово краснеет.
package deploy_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/tools/surfaceroster"
)

// syntheticRendered — рендер с одним объектом правил и заданным телом.
func syntheticRendered(rules string) string {
	return "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: kaname-config\n" +
		"---\n" +
		"apiVersion: monitoring.coreos.com/v1\nkind: PrometheusRule\n" +
		"metadata:\n  name: kaname\nspec:\n  groups:\n    - name: kaname\n      rules:\n" + rules
}

// syntheticRuleGood — одно правило, повторяющее форму страницы.
const syntheticRuleGood = "        - alert: SampleStuck\n" +
	"          expr: kaname_sample_total > 1\n" +
	"          for: 5m\n" +
	"          annotations:\n" +
	"            summary: \"проба\"\n"

// syntheticPage — страница, обещающая ровно это правило.
func syntheticPage(t *testing.T, body string) []alertRule {
	t.Helper()
	rules, err := parseAlertRules(body)
	require.NoError(t, err)
	return rules
}

const syntheticPageBody = "- alert: SampleStuck\n" +
	"  expr: kaname_sample_total > 1\n" +
	"  for: 5m\n" +
	"  annotations:\n" +
	"    summary: \"проба\"\n"

// TestAlertRulesInjection_ControlIsSilent — КОНТРОЛЬ: объект и страница
// совпадают, расхождений ноль.
func TestAlertRulesInjection_ControlIsSilent(t *testing.T) {
	t.Parallel()
	chart, objects := chartAlertRules(t, syntheticRendered(syntheticRuleGood))
	require.Equal(t, 1, objects, "фикстура беспредметна: объект не распознан")
	require.Len(t, chart, 1, "фикстура беспредметна: правило не разобрано")

	onlyPage, onlyChart := diffRuleSets(syntheticPage(t, syntheticPageBody), chart)
	require.Empty(t, onlyPage, "сверка краснеет на СОВПАДАЮЩИХ наборах — она ловит форму, а не существо")
	require.Empty(t, onlyChart)
}

// TestAlertRulesInjection_TheRealChartStopsCarryingWhatThePagePromises —
// СКВОЗНАЯ инъекция: настоящий чарт, настоящая страница, один изменённый факт.
//
// Ручка объекта выключена — и это ровно то состояние, в котором поставка
// обещает страницей то, чего не везёт. Проба обязана назвать КАЖДОЕ обещанное
// правило, а не молча согласиться.
func TestAlertRulesInjection_TheRealChartStopsCarryingWhatThePagePromises(t *testing.T) {
	root, err := surfaceroster.IAMRoot(".")
	require.NoError(t, err, "корень дерева службы")

	page := pageAlertRules(t, root)
	require.NotEmpty(t, page, "инъекция беспредметна: страница не несёт правил")

	off := renderStandaloneChart(t, chartProfiles, alertRulesToggle+"=false")
	chart, objects := chartAlertRules(t, off)
	require.Zero(t, objects, "инъекция не применилась: объект остался в рендере")

	onlyPage, onlyChart := diffRuleSets(page, chart)
	t.Logf("ПЕРЕПИСЬ сквозной инъекции: правил на странице %d · у объекта %d · "+
		"только на странице %d", len(page), len(chart), len(onlyPage))

	require.Lenf(t, onlyPage, len(page), "сверка НЕ назвала обещанные правила недоставленными — "+
		"она вакуумна: обещание без поставки прошло бы молча")
	require.Empty(t, onlyChart)
	require.Contains(t, strings.Join(onlyPage, ","), "KanameIdentityLedgerUnsampled",
		"среди недоставленных не названо правило, звонящее на ОТСУТСТВИЕ события, — "+
			"именно оно не переносится руками никогда")
}

// TestAlertRulesInjection_ChartCarriesARuleThePageDoesNotExplain — объект везёт
// правило, которого страница не объясняет.
func TestAlertRulesInjection_ChartCarriesARuleThePageDoesNotExplain(t *testing.T) {
	t.Parallel()
	extra := syntheticRuleGood + "        - alert: SampleUndocumented\n" +
		"          expr: kaname_sample_total > 2\n" +
		"          annotations:\n            summary: \"нигде не описано\"\n"
	chart, _ := chartAlertRules(t, syntheticRendered(extra))
	require.Len(t, chart, 2, "инъекция не применилась")

	_, onlyChart := diffRuleSets(syntheticPage(t, syntheticPageBody), chart)
	require.Contains(t, onlyChart, "SampleUndocumented",
		"правило без объяснения на странице прошло молча — дежурному позвонят без порядка разбора")
}

// TestAlertRulesInjection_ExpressionDriftIsAFinding — самое тихое расхождение:
// имена совпадают, выражения разошлись.
//
// Сверка по ОДНОМУ ЛИШЬ ИМЕНИ была бы здесь зелёной, и объект годами вёз бы
// другой порог, чем обещает страница.
func TestAlertRulesInjection_ExpressionDriftIsAFinding(t *testing.T) {
	t.Parallel()
	drifted := strings.Replace(syntheticRuleGood, "> 1", "> 999", 1)
	require.NotEqual(t, syntheticRuleGood, drifted, "инъекция не применилась")

	chart, _ := chartAlertRules(t, syntheticRendered(drifted))
	onlyPage, onlyChart := diffRuleSets(syntheticPage(t, syntheticPageBody), chart)

	require.Contains(t, onlyPage, "SampleStuck", "уехавший порог не назван со стороны страницы")
	require.Contains(t, onlyChart, "SampleStuck", "уехавший порог не назван со стороны объекта")
}

// TestAlertRulesInjection_SummaryDriftIsAFinding — текст, который прочтёт
// дежурный, тоже часть правила.
func TestAlertRulesInjection_SummaryDriftIsAFinding(t *testing.T) {
	t.Parallel()
	drifted := strings.Replace(syntheticRuleGood, "\"проба\"", "\"другой текст\"", 1)
	require.NotEqual(t, syntheticRuleGood, drifted, "инъекция не применилась")

	chart, _ := chartAlertRules(t, syntheticRendered(drifted))
	onlyPage, _ := diffRuleSets(syntheticPage(t, syntheticPageBody), chart)
	require.Contains(t, onlyPage, "SampleStuck",
		"разошедшийся текст для дежурного прошёл молча — страница объясняет одно, звонит другое")
}

// TestAlertRulesInjection_IndentationIsNotDrift — ЗАКОННЫЙ БЛИЗНЕЦ предыдущих
// двух: то же выражение, записанное с другим отступом и переносом.
//
// Страница и объект несут выражение блочным скаляром на РАЗНОЙ глубине —
// различие отступа неизбежно by construction. Проба, краснеющая здесь,
// краснела бы на верной поставке всегда.
func TestAlertRulesInjection_IndentationIsNotDrift(t *testing.T) {
	t.Parallel()
	wrapped := "        - alert: SampleStuck\n" +
		"          expr: |\n" +
		"            kaname_sample_total\n" +
		"              > 1\n" +
		"          for: 5m\n" +
		"          annotations:\n" +
		"            summary: \"проба\"\n"

	chart, _ := chartAlertRules(t, syntheticRendered(wrapped))
	require.Len(t, chart, 1, "близнец беспредметен: правило не разобрано")

	pageWrapped := syntheticPage(t, "- alert: SampleStuck\n"+
		"  expr: kaname_sample_total > 1\n"+
		"  for: 5m\n"+
		"  annotations:\n    summary: \"проба\"\n")

	onlyPage, onlyChart := diffRuleSets(pageWrapped, chart)
	require.Empty(t, onlyPage, "перенос и отступ объявлены расхождением — тогда сверка краснела бы "+
		"на верной поставке всегда, и её отключили бы первой")
	require.Empty(t, onlyChart)
}

// TestAlertRulesInjection_RenderWithoutAnyObjectIsNotSilentlyEqual —
// предпосылка сверки: пустой объект против пустой страницы даёт совпадение, и
// именно поэтому непустоту страницы проба дерева требует ОТДЕЛЬНО.
func TestAlertRulesInjection_RenderWithoutAnyObjectIsNotSilentlyEqual(t *testing.T) {
	t.Parallel()
	chart, objects := chartAlertRules(t, "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n")
	require.Zero(t, objects)
	require.Empty(t, chart)

	onlyPage, onlyChart := diffRuleSets(nil, chart)
	require.Empty(t, onlyPage)
	require.Empty(t, onlyChart, "две пустоты совпали — значит «расхождений ноль» само по себе "+
		"вердиктом не является, и непустоту обеих сторон обязана требовать проба дерева")
}
