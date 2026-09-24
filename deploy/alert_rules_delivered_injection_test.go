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
	"net/http"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
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

	// Обещание берётся для посадки поставляемого профиля: правила чужой полосы
	// установке этой посадки не обещаны и недоставленными не считаются.
	page := pageAlertRules(t, root).forPosture(postureOfProfiles(t, chartProfiles))
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

// TestAlertRulesInjection_PostureMarkerSplitsThePage — пометка посадки перед
// блоком относит его правила к полосе; блок без пометки — общий. Обе стороны:
// правило полосы НЕ обещано установке чужой посадки, общее обещано каждой.
func TestAlertRulesInjection_PostureMarkerSplitsThePage(t *testing.T) {
	t.Parallel()
	text := "текст\n```yaml\n" + syntheticPageBody + "```\n" +
		"<!-- posture: own -->\n```yaml\n- alert: LaneOnly\n  expr: kaname_lane_total > 1\n  annotations:\n    summary: \"полоса\"\n```\n"
	rules := posturedRules{}
	for _, m := range pageAlertBlockRe.FindAllStringSubmatch(text, -1) {
		parsed, err := parseAlertRules(m[2])
		require.NoError(t, err)
		rules[m[1]] = append(rules[m[1]], parsed...)
	}
	require.Len(t, rules[""], 1, "блок без пометки не прочитан общим")
	require.Len(t, rules["own"], 1, "блок с пометкой не отнесён к полосе")

	names := func(rs []alertRule) []string {
		out := []string{}
		for _, r := range rs {
			out = append(out, r.Alert)
		}
		return out
	}
	require.ElementsMatch(t, []string{"SampleStuck", "LaneOnly"}, names(rules.forPosture("own")),
		"установке `own` обещаны общие правила И правила её полосы")
	require.ElementsMatch(t, []string{"SampleStuck"}, names(rules.forPosture("external")),
		"правило полосы `own` уехало в обещание установке `external` — под ней оно звонило бы вечно")
	require.ElementsMatch(t, []string{"SampleStuck"}, names(rules.forPosture("")),
		"профиль без посадки получает только общие правила")
}

// ── Ряд прохода сметателя берётся у производителя (#314) ─────────────────────
//
// Опыт S1: значение клетки прохода переименовано у производителя, и ни одна
// проба не покраснела — правило ждало ряд, которого больше нет, и не зазвонило
// бы никогда. Здесь S1 подаётся в процессе: производитель — дублёр с ОДНИМ
// изменённым фактом, чарт — настоящий.

// fakeSigningKeyProducer — производитель ряда событий ключницы: клетка прохода
// под меткой label со значением passValue несёт pass проходов.
//
// Печатает тем же кодом выдачи, что настоящий (реестр и обработчик клиента
// Prometheus), а не строкой руками: дублёр со своим форматом доказывал бы
// разбор своего формата, а не формата производителя.
func fakeSigningKeyProducer(label, passValue string, pass float64) http.Handler {
	reg := prometheus.NewRegistry()
	events := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: metrics.SigningKeyEventsMetric,
		Help: "проба",
	}, []string{label})
	reg.MustRegister(events)
	events.WithLabelValues(metrics.SigningKeyEventRemoved).Add(0)
	events.WithLabelValues(passValue).Add(pass)
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}

// deliveredRules — правила, которые везёт объект поставляемого профиля.
func deliveredRules(t *testing.T) []alertRule {
	t.Helper()
	rules, objects := chartAlertRules(t, renderStandaloneChart(t, chartProfiles))
	require.Equal(t, 1, objects, "инъекция беспредметна: объект правил не отрендерился")
	return rules
}

// TestSweeperSilenceInjection_ControlProducerIsHeard — КОНТРОЛЬ: производитель
// печатает клетку прохода так, как её читает поставляемое правило.
func TestSweeperSilenceInjection_ControlProducerIsHeard(t *testing.T) {
	series, err := sweepPassSeriesFrom(fakeSigningKeyProducer("event", metrics.SigningKeyEventSwept, 1))
	require.NoError(t, err)
	require.Equal(t, metrics.SigningKeyEventsMetric+`{event="`+metrics.SigningKeyEventSwept+`"}`, series)
	require.Lenf(t, sweeperSilenceAlerts(deliveredRules(t), series), 1,
		"контроль красный: клетку %s поставляемое правило не читает — либо значение "+
			"разошлось у производителя и чарта, либо разбор выдачи ослеп", series)
}

// TestSweeperSilenceInjection_ValueRenamedAtTheProducer — S1: у производителя
// переименовано значение клетки прохода. Проба обязана искать НОВЫЙ ряд и не
// найти его в чарте, а не искать старый и найти.
func TestSweeperSilenceInjection_ValueRenamedAtTheProducer(t *testing.T) {
	series, err := sweepPassSeriesFrom(fakeSigningKeyProducer("event", "sweep_pass", 1))
	require.NoError(t, err)
	require.Equalf(t, metrics.SigningKeyEventsMetric+`{event="sweep_pass"}`, series,
		"проба ищет ряд %s, а производитель печатает клетку прохода как sweep_pass — "+
			"ряд выписан литералом, и переименование у производителя её не роняет", series)
	require.Empty(t, sweeperSilenceAlerts(deliveredRules(t), series),
		"правило, ждущее ряд, которого производитель не печатает, признано звонящим")
}

// TestSweeperSilenceInjection_LabelRenamedAtTheProducer — у производителя
// переименована МЕТКА клетки прохода, значение прежнее.
func TestSweeperSilenceInjection_LabelRenamedAtTheProducer(t *testing.T) {
	series, err := sweepPassSeriesFrom(fakeSigningKeyProducer("kind", metrics.SigningKeyEventSwept, 1))
	require.NoError(t, err)
	require.Equalf(t, metrics.SigningKeyEventsMetric+`{kind="`+metrics.SigningKeyEventSwept+`"}`, series,
		"проба ищет ряд %s, а производитель печатает клетку прохода под меткой kind", series)
	require.Empty(t, sweeperSilenceAlerts(deliveredRules(t), series),
		"правило, ждущее метку, которой производитель не печатает, признано звонящим")
}

// TestSweeperSilenceInjection_ProducerWithoutAPassCellIsRefused — производитель
// не печатает клетки с проходом вовсе: ряда брать неоткуда, и это отказ, а не
// пустая строка, с которой любое выражение «совпадает».
func TestSweeperSilenceInjection_ProducerWithoutAPassCellIsRefused(t *testing.T) {
	series, err := sweepPassSeriesFrom(fakeSigningKeyProducer("event", metrics.SigningKeyEventSwept, 0))
	require.Errorf(t, err, "производитель без клетки прохода дал ряд %q", series)
	require.Contains(t, err.Error(), metrics.SigningKeyEventsMetric)
}
