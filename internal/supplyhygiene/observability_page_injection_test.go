// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// observability_page_injection_test.go — доказательство того, что проверка
// страницы СПОСОБНА упасть, и того, что она молчит на законном близнеце.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОДИН ФАКТ ПРОТИВ БЛИЗНЕЦА
//
// Годная страница и годный корень производителей собраны один раз; каждая проба
// меняет РОВНО ОДНУ вещь. У обеих полос близнец назван явно: назвать
// существующий ряд — молчать; назвать несуществующий — краснеть; обратиться к
// самой службе — молчать; обратиться к чужому компоненту — краснеть.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ СИНТЕТИЧЕСКИЙ КОРЕНЬ ПРОИЗВОДИТЕЛЕЙ
//
// Настоящий корень — тысяча с лишним файлов двух модулей. Инъекция по нему была
// бы не одно-фактной: красное могло бы прийти от чего угодно в этой тысяче.
// Синтетический объявляет ОДИН ряд, и всё, что не он, — заведомо без
// производителя.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// pageProducerGo — синтетический производитель: ОДИН ряд, объявленный в позиции
// имени ряда.
const pageProducerGo = `package sample

import "github.com/prometheus/client_golang/prometheus"

const Namespace = "kaname"

var live = prometheus.NewHistogramVec(prometheus.HistogramOpts{
	Name: Namespace + "_live_series_seconds",
	Help: "проба",
}, []string{"lane"})
`

// pageGood — годная страница: называет существующий ряд и несёт команду,
// обращённую к самой службе.
const pageGood = "# Наблюдаемость\n\n" +
	"Задержка живёт в ряде `kaname_live_series_seconds`.\n\n" +
	"```bash\nkubectl exec deploy/kaname -- wget -qO- http://127.0.0.1:9095/metrics\n```\n"

// syntheticProducerRoot — корень с единственным производителем.
func syntheticProducerRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "pkg", "sample")
	require.NoError(t, os.MkdirAll(dir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sample.go"), []byte(pageProducerGo), 0o600))
	return root
}

// writePage кладёт страницу в свой каталог прогона.
func writePage(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "observability.mdx")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

// requirePageFinding — находка с названной подстрокой есть, и перепись непуста.
func requirePageFinding(t *testing.T, body, want string) {
	t.Helper()
	census, findings, err := scanObservabilityPage(writePage(t, body), []string{syntheticProducerRoot(t)})
	require.NoError(t, err)
	require.NotZero(t, census.pageLines, "инъекция беспредметна: страница не прочитана")
	require.NotZero(t, census.producerSeries, "инъекция беспредметна: производителей не собрано")
	joined := strings.Join(findings, "\n")
	require.Containsf(t, joined, want,
		"проверка НЕ упала на внесённом дефекте — она вакуумна.\nнаходки:\n%s", joined)
}

// TestObservabilityPageInjection_ControlIsSilent — КОНТРОЛЬ: всё цело, находок ноль.
func TestObservabilityPageInjection_ControlIsSilent(t *testing.T) {
	t.Parallel()
	census, findings, err := scanObservabilityPage(
		writePage(t, pageGood), []string{syntheticProducerRoot(t)})
	require.NoError(t, err)
	require.Empty(t, findings, "проверка краснеет на ГОДНОЙ странице — она ловит форму, а не существо")
	require.Equal(t, 1, census.seriesDistinct, "распознан не тот набор названных рядов")
	require.Equal(t, 1, census.commandBlocks, "распознан не тот набор блоков команд")
}

// TestObservabilityPageInjection_SeriesWithoutAProducer — названа величина,
// которой никто не производит. Законный близнец — контроль выше, где назван
// существующий ряд.
func TestObservabilityPageInjection_SeriesWithoutAProducer(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(pageGood, "kaname_live_series_seconds", "kaname_no_such_series_total", 1)
	require.NotEqual(t, pageGood, broken, "инъекция не применилась")

	requirePageFinding(t, broken, "названа величина kaname_no_such_series_total")
}

// TestObservabilityPageInjection_DerivedHistogramSuffixIsNotAFinding — законный
// близнец предыдущей: хвост, который Prometheus дописывает к гистограмме,
// находкой не является.
//
// Проба заведена не «на всякий случай»: первый же прогон проверки над настоящей
// страницей объявил находкой живой счётчик, чьё имя оканчивается так же, как
// производное гистограммы. Порядок «полное имя раньше урезанного» держится
// отсюда.
func TestObservabilityPageInjection_DerivedHistogramSuffixIsNotAFinding(t *testing.T) {
	t.Parallel()
	twin := strings.Replace(pageGood,
		"kaname_live_series_seconds", "kaname_live_series_seconds_bucket", 1)
	require.NotEqual(t, pageGood, twin, "близнец не применился")

	_, findings, err := scanObservabilityPage(writePage(t, twin), []string{syntheticProducerRoot(t)})
	require.NoError(t, err)
	require.Empty(t, findings, "производное гистограммы объявлено находкой — тогда ни один "+
		"запрос по процентилю нельзя написать на странице")
}

// TestObservabilityPageInjection_CommandNeedsAForeignComponent — команда
// обращается к компоненту, которого в отдельной установке нет.
func TestObservabilityPageInjection_CommandNeedsAForeignComponent(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(pageGood, "deploy/kaname", "deploy/api-gateway", 1)
	require.NotEqual(t, pageGood, broken, "инъекция не применилась")

	requirePageFinding(t, broken, "обращается к компоненту api-gateway")
}

// TestObservabilityPageInjection_PageNamesNoSeries — страница перечисляет
// области вместо величин. Ровно так выглядела прежняя редакция.
func TestObservabilityPageInjection_PageNamesNoSeries(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(pageGood,
		"Задержка живёт в ряде `kaname_live_series_seconds`.",
		"Смотреть задержку и долю отказов.", 1)
	require.NotEqual(t, pageGood, broken, "инъекция не применилась")

	requirePageFinding(t, broken, "не называет НИ ОДНОГО ряда")
}

// TestObservabilityPageInjection_PageCarriesNoCommands — на странице нет порядка
// разбора: величины названы, спросить их нечем.
func TestObservabilityPageInjection_PageCarriesNoCommands(t *testing.T) {
	t.Parallel()
	broken := strings.Split(pageGood, "```bash")[0]
	require.NotEqual(t, pageGood, broken, "инъекция не применилась")

	requirePageFinding(t, broken, "нет ни одного блока команд")
}

// TestObservabilityPageInjection_EmptyProducerRootLeavesTheCensusEmpty —
// предпосылка самой проверки: корень без файлов Go даёт ПУСТУЮ перепись
// прочитанного, и проба дерева отказывает по ней, а не молчит «находок ноль».
func TestObservabilityPageInjection_EmptyProducerRootLeavesTheCensusEmpty(t *testing.T) {
	t.Parallel()
	census, _, err := scanObservabilityPage(writePage(t, pageGood), []string{t.TempDir()})
	require.NoError(t, err)
	require.Zero(t, census.producerFiles,
		"пустой корень дал непустую перепись — тогда «производителя нет» неотличимо от «не искали»")
	require.Zero(t, census.producerModules)
}
