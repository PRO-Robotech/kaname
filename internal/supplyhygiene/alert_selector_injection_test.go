// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// alert_selector_injection_test.go — доказательство того, что проверка отбора
// СПОСОБНА упасть, и того, что она молчит на законных близнецах.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОДИН ФАКТ ПРОТИВ БЛИЗНЕЦА
//
// Годная страница и годный корень контрактов собраны один раз; каждая проба
// меняет РОВНО ОДНУ вещь. Близнецы названы явно, и их здесь ТРИ — потому что
// молчать проверка обязана по трём разным причинам, и каждую надо доказать
// отдельно:
//
//	отрицательный отбор       — не совпадает ни с чем и НИЧЕГО НЕ ИСКЛЮЧАЕТ;
//	отбор точным именем       — совпадает как строка, а не как выражение;
//	страница вовсе без отбора — отсутствие отбора находкой не является.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ СИНТЕТИЧЕСКИЙ КОРЕНЬ КОНТРАКТОВ
//
// Настоящий корень — 1104 файла двух модулей и 69 контрактов. Инъекция по нему
// не была бы одно-фактной: красное могло бы прийти от чего угодно из этой
// тысячи, а молчание — от случайного совпадения с чужим контрактом.
// Синтетический объявляет ОДИН контракт, и всё, что не он, — заведомо мимо.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// selectorProducerGo — синтетический источник: ОДИН контракт, объявленный в
// позиции имени контракта — ровно так, как это делает генератор стабов.
const selectorProducerGo = `package sample

import "google.golang.org/grpc"

var SampleServiceDesc = grpc.ServiceDesc{
	ServiceName: "kaname.cloud.sample.v1.WidgetService",
	HandlerType: (*any)(nil),
}
`

// selectorDocGood — годная страница: отбор совпадает с объявленным контрактом.
const selectorDocGood = "# Наблюдаемость\n\n" +
	"```yaml\n" +
	"- alert: SampleRPCErrorRate\n" +
	"  expr: |\n" +
	"    sum(rate(kacho_grpc_server_handled_total{grpc_service=~\"kaname\\\\.cloud\\\\.sample\\\\..*\"}[5m])) > 0.05\n" +
	"```\n"

// syntheticContractRoot — корень с единственным контрактом.
func syntheticContractRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "pkg", "sample")
	require.NoError(t, os.MkdirAll(dir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sample.go"), []byte(selectorProducerGo), 0o600))
	return root
}

// writeSelectorDoc кладёт страницу в свой каталог прогона.
func writeSelectorDoc(t *testing.T, body string) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "observability.md"), []byte(body), 0o600))
	return root
}

// scanSelectorFixture — разбор синтетической пары.
func scanSelectorFixture(t *testing.T, body string) (selectorCensus, []string) {
	t.Helper()
	census, findings, err := scanAlertSelectors(writeSelectorDoc(t, body), []string{syntheticContractRoot(t)})
	require.NoError(t, err)
	return census, findings
}

// requireSelectorFinding — находка с названной подстрокой есть, и перепись непуста.
func requireSelectorFinding(t *testing.T, body, want string) {
	t.Helper()
	census, findings := scanSelectorFixture(t, body)
	require.NotZero(t, census.docFiles, "инъекция беспредметна: страница не прочитана")
	require.NotZero(t, census.contracts, "инъекция беспредметна: контрактов не собрано")
	joined := strings.Join(findings, "\n")
	require.Containsf(t, joined, want,
		"проверка НЕ упала на внесённом дефекте — она вакуумна.\nнаходки:\n%s", joined)
}

// TestAlertSelectorInjection_ControlIsSilent — КОНТРОЛЬ: всё цело, находок ноль.
func TestAlertSelectorInjection_ControlIsSilent(t *testing.T) {
	t.Parallel()
	census, findings := scanSelectorFixture(t, selectorDocGood)
	require.Empty(t, findings, "проверка краснеет на ГОДНОЙ странице — она ловит форму, а не существо")
	require.Equal(t, 1, census.matchersAll, "распознан не тот набор отборов")
	require.Equal(t, 1, census.matchersJudge, "положительный отбор не признан судимым")
	require.Equal(t, 1, census.contracts, "собран не тот набор контрактов")
}

// TestAlertSelectorInjection_SelectorNamesARetiredPackage — ТОТ САМЫЙ дефект:
// отбор называет приставку пакета, снятую переездом контракта. Законный
// близнец — контроль выше, где отбор называет живой пакет; различие ровно в
// одном слове.
//
// Приставка здесь СИНТЕТИЧЕСКАЯ (`former`), а не подлинное имя снятого пакета,
// и это решение, а не небрежность. Держатель остатка имени судит дерево
// механически: подлинная приставка, посеянная фикстурой, прибавилась бы к его
// счёту на ЧУЖОЙ полосе — то есть моя проба назначила бы работу владельцу,
// который о ней не просил. Предмет пробы от подмены не меняется: она требует
// отбора, не совпадающего НИ С ОДНИМ произведённым контрактом, а совпадает он
// или нет — от происхождения слова не зависит.
func TestAlertSelectorInjection_SelectorNamesARetiredPackage(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(selectorDocGood, "kaname\\\\.cloud", "former\\\\.cloud", 1)
	require.NotEqual(t, selectorDocGood, broken, "инъекция не применилась")

	requireSelectorFinding(t, broken, "не совпадает НИ С ОДНИМ из 1 контрактов")
}

// TestAlertSelectorInjection_NegativeMatcherIsNotAFinding — ЗАКОННЫЙ БЛИЗНЕЦ:
// то же самое несовпадающее выражение, но в ОТРИЦАТЕЛЬНОМ отборе.
//
// Отрицание, не совпадающее ни с чем, ничего не исключает и вреда не наносит.
// Проверка, краснеющая здесь, требовала бы от исключения совпадения — то есть
// судила бы предмет, обратный своему.
func TestAlertSelectorInjection_NegativeMatcherIsNotAFinding(t *testing.T) {
	t.Parallel()
	twin := strings.Replace(selectorDocGood,
		"grpc_service=~\"kaname\\\\.cloud", "grpc_service!~\"former\\\\.cloud", 1)
	require.NotEqual(t, selectorDocGood, twin, "близнец не применился")

	census, findings := scanSelectorFixture(t, twin)
	require.Empty(t, findings, "отрицательный отбор объявлен находкой — тогда ни одно исключение "+
		"нельзя написать на странице")
	require.Equal(t, 1, census.matchersAll, "отбор не распознан вовсе — молчание пришло не оттуда")
	require.Zero(t, census.matchersJudge, "отрицательный отбор попал в судимые")
}

// TestAlertSelectorInjection_ExactMatcherOnALiveContract — ЗАКОННЫЙ БЛИЗНЕЦ:
// отбор точным именем, а не выражением. Совпадать он обязан как строка.
func TestAlertSelectorInjection_ExactMatcherOnALiveContract(t *testing.T) {
	t.Parallel()
	twin := strings.Replace(selectorDocGood,
		"grpc_service=~\"kaname\\\\.cloud\\\\.sample\\\\..*\"",
		"grpc_service=\"kaname.cloud.sample.v1.WidgetService\"", 1)
	require.NotEqual(t, selectorDocGood, twin, "близнец не применился")

	census, findings := scanSelectorFixture(t, twin)
	require.Empty(t, findings, "отбор точным именем живого контракта объявлен находкой")
	require.Equal(t, 1, census.matchersJudge, "точный отбор не признан судимым")
}

// TestAlertSelectorInjection_ExactMatcherOnADeadContract — обратная сторона
// предыдущего: точное имя, которого дерево не производит.
func TestAlertSelectorInjection_ExactMatcherOnADeadContract(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(selectorDocGood,
		"grpc_service=~\"kaname\\\\.cloud\\\\.sample\\\\..*\"",
		"grpc_service=\"kaname.cloud.sample.v1.NoSuchService\"", 1)
	require.NotEqual(t, selectorDocGood, broken, "инъекция не применилась")

	requireSelectorFinding(t, broken, "NoSuchService")
}

// TestAlertSelectorInjection_SubstringDoesNotSatisfyAnAnchoredMatcher —
// ПРЕДПОСЫЛКА разбора: Prometheus якорит отбор по метке ЦЕЛИКОМ.
//
// Выражение `cloud\.iam` совпадает с именем контракта КАК ПОДСТРОКА и не
// совпадает как целое. Без якорей проверка молчала бы на отборе, который в
// Prometheus не выберет ни одного ряда, — то есть была бы мягче исполняемого.
func TestAlertSelectorInjection_SubstringDoesNotSatisfyAnAnchoredMatcher(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(selectorDocGood,
		"kaname\\\\.cloud\\\\.sample\\\\..*", "cloud\\\\.sample", 1)
	require.NotEqual(t, selectorDocGood, broken, "инъекция не применилась")

	requireSelectorFinding(t, broken, "не совпадает НИ С ОДНИМ")
}

// TestAlertSelectorInjection_UncompilableExpressionIsAFinding — отбор, который
// не примет и сам Prometheus.
func TestAlertSelectorInjection_UncompilableExpressionIsAFinding(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(selectorDocGood,
		"kaname\\\\.cloud\\\\.sample\\\\..*", "kaname(", 1)
	require.NotEqual(t, selectorDocGood, broken, "инъекция не применилась")

	requireSelectorFinding(t, broken, "не компилируется")
}

// TestAlertSelectorInjection_PageWithoutASelectorIsNotAFinding — ЗАКОННЫЙ
// БЛИЗНЕЦ: страница без отбора вовсе.
//
// Опубликованная страница пишется для того, кто поставил ОДНУ службу: у него
// этот ряд производит только она, и отбирать не от чего. Красное здесь означало
// бы требование «отбор обязан быть», а это другой предмет.
func TestAlertSelectorInjection_PageWithoutASelectorIsNotAFinding(t *testing.T) {
	t.Parallel()
	twin := strings.Replace(selectorDocGood,
		"{grpc_service=~\"kaname\\\\.cloud\\\\.sample\\\\..*\"}", "", 1)
	require.NotEqual(t, selectorDocGood, twin, "близнец не применился")

	census, findings := scanSelectorFixture(t, twin)
	require.Empty(t, findings, "отсутствие отбора объявлено находкой — тогда страница отдельной "+
		"поставки не может быть верной ни при какой редакции")
	require.Zero(t, census.matchersJudge, "отбор распознан там, где его нет")
	require.NotZero(t, census.docFiles, "близнец беспредметен: страница не прочитана")
}

// TestAlertSelectorInjection_EmptyProducerRootLeavesTheCensusEmpty —
// предпосылка самой проверки: корень без файлов Go даёт ПУСТУЮ перепись
// прочитанного, и проба дерева отказывает по ней, а не молчит «находок ноль».
func TestAlertSelectorInjection_EmptyProducerRootLeavesTheCensusEmpty(t *testing.T) {
	t.Parallel()
	census, _, err := scanAlertSelectors(writeSelectorDoc(t, selectorDocGood), []string{t.TempDir()})
	require.NoError(t, err)
	require.Zero(t, census.contracts,
		"пустой корень дал непустой набор контрактов — тогда «контракта нет» неотличимо от «не искали»")
	require.Zero(t, census.producerFiles)
	require.Zero(t, census.producerMods)
}

// TestAlertSelectorInjection_ProseNamingAContractIsNotADeclaration —
// предпосылка РАЗБОРА: имя контракта, стоящее в тексте, объявлением не
// является.
//
// Если бы указатель собирался поиском слова, комментарий, объясняющий этот
// самый класс, стал бы «производителем» — и проверка молчала бы на снятом
// контракте, потому что его имя осталось в прозе.
func TestAlertSelectorInjection_ProseNamingAContractIsNotADeclaration(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dir := filepath.Join(root, "pkg", "sample")
	require.NoError(t, os.MkdirAll(dir, 0o750))
	prose := `package sample

// Здесь когда-то регистрировался kaname.cloud.sample.v1.WidgetService.
const note = "kaname.cloud.sample.v1.WidgetService"
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sample.go"), []byte(prose), 0o600))

	census, findings, err := scanAlertSelectors(writeSelectorDoc(t, selectorDocGood), []string{root})
	require.NoError(t, err)
	require.NotZero(t, census.producerFiles, "проба беспредметна: файл не прочитан")
	require.Zero(t, census.contracts, "имя из комментария и строки принято за объявление контракта — "+
		"указатель ослеп бы ровно на снятом контракте, чьё имя осталось в прозе")
	require.NotEmpty(t, findings, "отбор по контракту, который никто не регистрирует, объявлен годным")
}
