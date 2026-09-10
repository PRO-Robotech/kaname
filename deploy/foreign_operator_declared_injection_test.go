// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// foreign_operator_declared_injection_test.go — доказательство того, что сверка
// страницы установки с чартом СПОСОБНА УПАСТЬ, и того, что она молчит на
// законных близнецах.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВА РОДА ИНЪЕКЦИИ, И ПЕРВЫЙ ВАЖНЕЕ
//
//	СКВОЗНАЯ      — настоящий чарт, настоящая страница, РОВНО ОДИН изменённый
//	                факт: копия чарта начинает везти ещё один чужой вид. Она
//	                проверяет ВЕСЬ путь (рендер → разбор → сверка), а не одну
//	                функцию.
//	СИНТЕТИЧЕСКАЯ — расхождения, которых в дереве сегодня нет: уехавший
//	                apiVersion, разошедшееся умолчание, оператор, не названный
//	                в зависимостях. Настоящим деревом их не подать, не внеся
//	                дефект в поставку.
//
// У КАЖДОЙ оси стоит законный близнец: инъекция, доказывающая только красное,
// доказывает, что гейт ловит форму, а не существо.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАМЕР, КОТОРЫМ ОТВЕРГНУТ ОТКАЗ ПРОДУКТА ВМЕСТО ОТКАЗА СХЕМЫ
//
// `TestCapabilitiesCannotTellAbsenceFromNoCluster` ниже — не украшение шапки
// соседнего файла, а её основание: он подаёт helm пробный чарт и показывает,
// что вне кластера возможности отвечают `false` ВСЕГДА. Значит отказ рендера
// по возможностям сработал бы у арендатора, читающего свой релиз без кластера,
// — то есть мы утверждали бы про ЕГО кластер то, чего не спрашивали.
package deploy_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/tools/surfaceroster"
)

// injectedForeignTemplate — ещё один ЧУЖОЙ вид в копии чарта.
//
// Взят вид другого известного оператора: тем самым инъекция меняет ровно один
// факт — «чарт везёт вид, которого страница не называет», — и не задевает ни
// одной уже действующей проверки.
const injectedForeignTemplate = `apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: injected
spec:
  secretName: injected
`

// injectedForeignRow — та же строка, названная страницей. ЗАКОННЫЙ БЛИЗНЕЦ:
// отличается от инъекции выше РОВНО ОДНИМ фактом — объявлением.
var injectedForeignRow = pageRow{
	Kind:        "Certificate",
	APIVersion:  "cert-manager.io/v1",
	Provider:    "cert-manager",
	Foreign:     true,
	Knob:        "certificate.enabled",
	RemedyValue: "false",
	Default:     "true",
}

// realPageRows — строки настоящей страницы установки.
func realPageRows(t *testing.T) []pageRow {
	t.Helper()
	root, err := surfaceroster.IAMRoot(".")
	require.NoError(t, err, "корень дерева службы")
	rows, findings := installPageRows(installPageText(t, root))
	require.Empty(t, findings, "фикстура беспредметна: настоящая страница не разбирается")
	require.NotEmpty(t, rows, "фикстура беспредметна: у настоящей страницы нет строк")
	return rows
}

// TestForeignOperatorInjection_ControlIsSilent — КОНТРОЛЬ: настоящее дерево,
// расхождений ноль. Без него всё, что ниже, доказывало бы лишь способность
// краснеть — в том числе на верном дереве.
func TestForeignOperatorInjection_ControlIsSilent(t *testing.T) {
	rows := realPageRows(t)
	objects := renderedChartObjects(t, renderStandaloneChart(t, chartProfiles))
	require.NotEmpty(t, objects, "фикстура беспредметна: рендер пуст")
	require.Empty(t, judgeDeclaration(rows, objects),
		"сверка краснеет на СОВПАДАЮЩИХ наборах — она ловит форму, а не существо")
}

// TestForeignOperatorInjection_ChartStartsCarryingAnUndeclaredKind — СКВОЗНАЯ
// инъекция: копия настоящего чарта начинает везти чужой вид, которого страница
// не называет.
//
// Именно это состояние и есть предмет: арендатор не узнает, что вид чужой, —
// и получит отказ схемы, не называющий ни ручки, ни того, что поставить.
func TestForeignOperatorInjection_ChartStartsCarryingAnUndeclaredKind(t *testing.T) {
	rows := realPageRows(t)

	dir := chartCopy(t)
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "templates", "zz-injected.yaml"), []byte(injectedForeignTemplate), 0o600),
		"инъекция чужого вида в копию чарта")

	objects := renderedChartObjects(t, renderChartAt(t, dir, "values.yaml", "values.prod.yaml"))
	var got bool
	for _, o := range objects {
		if o.Kind == "Certificate" {
			got = true
		}
	}
	require.True(t, got, "инъекция не применилась: чужого вида в рендере копии нет")

	findings := judgeDeclaration(rows, objects)
	require.NotEmpty(t, findings, "чарт везёт вид, которого страница НЕ НАЗЫВАЕТ, — и сверка молчит")
	require.Contains(t, strings.Join(findings, "\n"), "Certificate (cert-manager.io/v1)",
		"находка не называет вида и его группы — читатель пойдёт искать не там")

	// ЗАКОННЫЙ БЛИЗНЕЦ: тот же чарт, тот же вид — но страница его называет.
	require.Empty(t, judgeDeclaration(append(rows, injectedForeignRow), objects),
		"объявленный вид всё равно назван находкой — тогда гейт краснел бы на верной "+
			"странице всегда, и его отключили бы первым")
}

// TestForeignOperatorInjection_PageKeepsARowWhoseObjectIsGone — самоистечение:
// строка, которой больше нечего описывать, есть находка.
//
// Без этой оси страница пережила бы снятие объекта и продолжала бы требовать
// оператора, которого продукту уже не нужно.
func TestForeignOperatorInjection_PageKeepsARowWhoseObjectIsGone(t *testing.T) {
	t.Parallel()
	objects := []chartObject{{Kind: "ConfigMap", APIVersion: "v1"}}
	rows := []pageRow{
		{Kind: "ConfigMap", APIVersion: "v1", Provider: clusterServesItself},
		{Kind: "PrometheusRule", APIVersion: "monitoring.coreos.com/v1", Provider: "Prometheus Operator", Foreign: true},
	}
	findings := judgeDeclaration(rows, objects)
	require.NotEmpty(t, findings, "строка без предмета прошла молча")
	require.Contains(t, strings.Join(findings, "\n"), "PrometheusRule",
		"находка не назвала строку, которой нечего описывать")

	// ЗАКОННЫЙ БЛИЗНЕЦ: объект вернулся — молчание.
	require.Empty(t, judgeDeclaration(rows, append(objects,
		chartObject{Kind: "PrometheusRule", APIVersion: "monitoring.coreos.com/v1"})),
		"строка с живым предметом названа находкой")
}

// TestForeignOperatorInjection_APIVersionDriftIsAFinding — самое тихое
// расхождение: вид назван, а группа уехала.
//
// Группа решает, КТО заводит вид: по неверной арендатор поставит не то и
// получит тот же отказ схемы.
func TestForeignOperatorInjection_APIVersionDriftIsAFinding(t *testing.T) {
	t.Parallel()
	objects := []chartObject{{Kind: "PrometheusRule", APIVersion: "monitoring.coreos.com/v1"}}
	drifted := []pageRow{{
		Kind: "PrometheusRule", APIVersion: "monitoring.coreos.com/v1beta1",
		Provider: "Prometheus Operator", Foreign: true,
	}}
	findings := judgeDeclaration(drifted, objects)
	require.NotEmpty(t, findings, "уехавшая группа вида прошла молча")
	require.Contains(t, strings.Join(findings, "\n"), "v1beta1")

	// ЗАКОННЫЙ БЛИЗНЕЦ: та же строка с той же группой.
	same := []pageRow{{
		Kind: "PrometheusRule", APIVersion: "monitoring.coreos.com/v1",
		Provider: "Prometheus Operator", Foreign: true,
	}}
	require.Empty(t, judgeDeclaration(same, objects), "совпадающая группа названа находкой")
}

// TestForeignOperatorInjection_DefaultDriftIsAFinding — страница называет одно
// умолчание, профиль несёт другое.
//
// Два места об одном предмете: разъезжается обычно то, которое читают чаще, —
// и читают чаще страницу.
func TestForeignOperatorInjection_DefaultDriftIsAFinding(t *testing.T) {
	t.Parallel()
	const deps = "… <strong>Prometheus Operator</strong> …"
	const values = "alertRules:\n  enabled: true\n"
	row := pageRow{
		Kind: "PrometheusRule", APIVersion: "monitoring.coreos.com/v1",
		Provider: "Prometheus Operator", Foreign: true,
		Knob: "alertRules.enabled", RemedyValue: "false", Default: "false",
	}
	findings := judgeForeignRow(row, deps, values)
	require.NotEmpty(t, findings, "разошедшееся умолчание прошло молча")
	require.Contains(t, strings.Join(findings, "\n"), "alertRules.enabled")

	// ЗАКОННЫЙ БЛИЗНЕЦ: умолчание страницы совпало с профилем.
	row.Default = "true"
	require.Empty(t, judgeForeignRow(row, deps, values), "совпадающее умолчание названо находкой")
}

// TestForeignOperatorInjection_KnobAbsentFromProfileIsAFinding — страница
// называет ручку, которой в профиле нет: средство есть, и оно не действует.
func TestForeignOperatorInjection_KnobAbsentFromProfileIsAFinding(t *testing.T) {
	t.Parallel()
	const deps = "… <strong>Prometheus Operator</strong> …"
	row := pageRow{
		Kind: "PrometheusRule", Provider: "Prometheus Operator", Foreign: true,
		Knob: "alerts.enabled", RemedyValue: "false", Default: "true",
	}
	findings := judgeForeignRow(row, deps, "alertRules:\n  enabled: true\n")
	require.NotEmpty(t, findings, "ручка, которой нет в профиле, прошла молча")
	require.Contains(t, strings.Join(findings, "\n"), "alerts.enabled")

	// ЗАКОННЫЙ БЛИЗНЕЦ: та же ручка, которая в профиле есть.
	row.Knob = "alertRules.enabled"
	require.Empty(t, judgeForeignRow(row, deps, "alertRules:\n  enabled: true\n"))
}

// TestForeignOperatorInjection_OperatorMissingFromDependenciesIsAFinding —
// оператор назван таблицей объектов и НЕ назван зависимостями рантайма.
//
// Ставящий продукт читает зависимости: требование, названное только ниже, он
// прочтёт уже после отказа установки.
func TestForeignOperatorInjection_OperatorMissingFromDependenciesIsAFinding(t *testing.T) {
	t.Parallel()
	const values = "alertRules:\n  enabled: true\n"
	row := pageRow{
		Kind: "PrometheusRule", Provider: "Prometheus Operator", Foreign: true,
		Knob: "alertRules.enabled", RemedyValue: "false", Default: "true",
	}
	silentDeps := "<strong>PostgreSQL</strong> · <strong>Ory Kratos</strong>"
	findings := judgeForeignRow(row, silentDeps, values)
	require.NotEmpty(t, findings, "оператор, не названный в зависимостях, прошёл молча")
	require.Contains(t, strings.Join(findings, "\n"), "зависимостей рантайма")

	// ЗАКОННЫЙ БЛИЗНЕЦ: тот же оператор, названный в зависимостях.
	require.Empty(t, judgeForeignRow(row, silentDeps+" · <strong>Prometheus Operator</strong>", values))
}

// TestForeignOperatorInjection_RemedyThatDoesNotRemoveIsAFinding — СКВОЗНАЯ
// инъекция второй оси: средство страницы перестало снимать объект.
//
// Копия чарта теряет условие ручки — и объект остаётся при выключенной ручке.
// Арендатор выполнит совет, получит тот же отказ и решит, что дело не в
// операторе.
func TestForeignOperatorInjection_RemedyThatDoesNotRemoveIsAFinding(t *testing.T) {
	rows := realPageRows(t)
	var row pageRow
	for _, r := range rows {
		if r.Foreign {
			row = r
		}
	}
	require.NotEmpty(t, row.Knob, "фикстура беспредметна: у страницы нет строки чужого вида")

	dir := chartCopy(t)
	patchInCopy(t, dir, filepath.Join("templates", "prometheusrule.yaml"),
		"{{- if .Values.alertRules.enabled }}", "{{- if true }}")

	off := renderedChartObjects(t,
		renderChartAt2(t, dir, []string{"values.yaml", "values.prod.yaml"}, row.Knob+"="+row.RemedyValue))
	findings := judgeRemedyWorks(row, off)
	require.NotEmpty(t, findings, "средство, не снимающее объект, прошло молча")
	require.Contains(t, strings.Join(findings, "\n"), row.Kind)

	// ЗАКОННЫЙ БЛИЗНЕЦ: настоящий чарт, то же средство — объект уходит.
	realOff := renderedChartObjects(t, renderStandaloneChart(t, chartProfiles, row.Knob+"="+row.RemedyValue))
	require.Empty(t, judgeRemedyWorks(row, realOff),
		"работающее средство названо находкой — тогда гейт краснел бы на верном чарте всегда")
}

// TestForeignOperatorInjection_RowShapeIsJudged — форма строки таблицы: у
// чужого вида ОБЯЗАНЫ быть ручка, её значение и умолчание; у своего — прочерк.
//
// Без этой оси строка «оператор нужен» без ручки читалась бы как объявление, а
// арендатору было бы нечего сделать, прочитав требование.
func TestForeignOperatorInjection_RowShapeIsJudged(t *testing.T) {
	t.Parallel()
	head := objectsTableHeader + "\n|---|---|---|---|\n"

	cases := []struct {
		name, row, want string
	}{
		{"чужой вид без ручки",
			"| `PrometheusRule` | `monitoring.coreos.com/v1` | **Prometheus Operator** | — |",
			"не называет ручки"},
		{"свой вид с ручкой",
			"| `ConfigMap` | `v1` | кластер сам | `cm.enabled=false` (умолчание — `true`) |",
			"обещает выбор, которого нет"},
		{"ячеек не четыре",
			"| `ConfigMap` | `v1` | кластер сам |",
			"вместо четырёх"},
		{"вид не назван",
			"|  | `v1` | кластер сам | — |",
			"не называет вида"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, findings := installPageRows(head + c.row + "\n")
			require.NotEmptyf(t, findings, "строка %q прошла молча", c.row)
			require.Contains(t, strings.Join(findings, "\n"), c.want)
		})
	}

	// ЗАКОННЫЙ БЛИЗНЕЦ: обе законные формы строк разбираются без находок.
	rows, findings := installPageRows(head +
		"| `ConfigMap` | `v1` | кластер сам | — |\n" +
		"| `PrometheusRule` | `monitoring.coreos.com/v1` | **Prometheus Operator** | `alertRules.enabled=false` (умолчание — `true`) |\n")
	require.Empty(t, findings, "законные строки названы находками")
	require.Len(t, rows, 2)
	require.False(t, rows[0].Foreign)
	require.True(t, rows[1].Foreign)
	require.Equal(t, "alertRules.enabled", rows[1].Knob)
	require.Equal(t, "false", rows[1].RemedyValue)
	require.Equal(t, "true", rows[1].Default)
}

// TestForeignOperatorInjection_EmptyWalkIsNotZeroFindings — «ноль находок»
// обязано быть отличимо от «ноль прочитанного».
func TestForeignOperatorInjection_EmptyWalkIsNotZeroFindings(t *testing.T) {
	t.Parallel()

	_, findings := installPageRows("## Развёртывание\n\nтекст без таблицы\n")
	require.NotEmpty(t, findings, "страница БЕЗ таблицы объектов прошла молча")
	require.Contains(t, strings.Join(findings, "\n"), objectsTableHeader)

	rows, findings := installPageRows(objectsTableHeader + "\n|---|---|---|---|\n\nдальше проза\n")
	require.Empty(t, findings, "пустая таблица разобрана с находкой — предмет у неё другой")
	require.Empty(t, rows, "у пустой таблицы взялись строки — разбор читает не то")

	// Пустой рендер при непустой странице обязан давать находки, а не совпадение.
	require.NotEmpty(t, judgeDeclaration(
		[]pageRow{{Kind: "ConfigMap", APIVersion: "v1", Provider: clusterServesItself}}, nil),
		"пустой рендер совпал с непустой страницей — тогда «расхождений ноль» вердиктом не является")

	// А две пустоты совпадают — и ИМЕННО поэтому непустоту обеих сторон проба
	// дерева требует ОТДЕЛЬНО.
	require.Empty(t, judgeDeclaration(nil, nil))
}

// TestForeignOperatorInjection_SectionTextIsBounded — раздел читается до
// СЛЕДУЮЩЕГО заголовка, а не до конца страницы.
//
// Без этой границы «оператор назван в зависимостях» зеленело бы от упоминания
// где угодно ниже — то есть от того самого раздела, который эта проверка и
// стережёт.
func TestForeignOperatorInjection_SectionTextIsBounded(t *testing.T) {
	t.Parallel()
	page := runtimeDependenciesHeading + "\n\nPostgreSQL\n\n## Что чарт создаёт\n\nPrometheus Operator\n"
	deps := sectionText(page, runtimeDependenciesHeading)
	require.Contains(t, deps, "PostgreSQL", "раздел прочитан пустым")
	require.NotContains(t, deps, "Prometheus Operator",
		"раздел зависимостей вобрал СОСЕДНИЙ раздел — тогда проверка зеленела бы от "+
			"упоминания в той самой таблице, расхождение с которой она и стережёт")
	require.Empty(t, sectionText(page, "## Нет такого раздела"))
}

// TestCapabilitiesCannotTellAbsenceFromNoCluster — ЗАМЕР, которым отвергнут
// отказ продукта вместо отказа схемы.
//
// Единственное, что исполняется РАНЬШЕ отказа схемы, — рендер шаблона: текст
// `unable to build kubernetes objects from release manifest` есть обёртка helm
// вокруг сборки манифеста, а хуки, поды и страж старта живут ПОСЛЕ неё. Значит
// отказ продукта выразим только через `.Capabilities.APIVersions.Has` + `fail`.
//
// Здесь показано, чего этот путь стоит: вне кластера возможности отвечают
// `false` ВСЕГДА, а `KubeVersion` отдаёт вшитое в helm значение, неотличимое от
// настоящего кластера той же версии. Отличить «оператора нет» от «спросить не у
// кого» шаблону НЕЧЕМ — и ложный отказ достался бы каждому, кто рендерит без
// кластера: и нам, и арендатору, читающему свой релиз. Цена названа числом в
// шапке соседнего файла — вместе с предикатом, которым это число перемеряется.
//
// Проба пробным чартом, а не нашим: предмет — поведение helm, и подмешивать к
// нему наш чарт значило бы мерить два предмета одной величиной.
func TestCapabilitiesCannotTellAbsenceFromNoCluster(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		if os.Getenv(renderGuardLaneEnv) != "" {
			t.Fatalf("helm не в PATH, а полоса рендера объявлена (%s задан): замер обещал "+
				"величину и дать её не может", renderGuardLaneEnv)
		}
		t.Skipf("helm не в PATH — вердикта НЕТ: третья категория, не зелёное и не красное")
	}

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "templates"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Chart.yaml"),
		[]byte("apiVersion: v2\nname: probe\nversion: 0.1.0\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "templates", "probe.yaml"),
		[]byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: probe\ndata:\n"+
			"  has: {{ .Capabilities.APIVersions.Has \"monitoring.coreos.com/v1\" | quote }}\n"), 0o600))

	render := func(extra ...string) string {
		args := append([]string{"template", "probe", dir}, extra...)
		out, err := exec.Command("helm", args...).CombinedOutput() // #nosec G204 -- фиксированный бинарь, путь из t.TempDir
		require.NoErrorf(t, err, "пробный чарт не отрендерился — это «не выполнилось», а не замер\n%s", out)
		return string(out)
	}

	offline := render()
	declared := render("--api-versions", "monitoring.coreos.com/v1")

	t.Logf("ЗАМЕР возможностей (helm %s):\n"+
		"  без кластера has=%q · с --api-versions has=%q",
		strings.TrimSpace(helmShortVersion(t)), capValue(offline), capValue(declared))

	require.Equal(t, "false", capValue(offline),
		"вне кластера возможности ответили НЕ false — тогда довод, которым отвергнут отказ "+
			"рендера по возможностям, перестал быть верным, и решение надо пересматривать")
	require.Equal(t, "true", capValue(declared),
		"объявленная группа не дошла до шаблона — замер беспредметен: он не показывает, что "+
			"`false` выше означает «спросить не у кого», а не «вида нет»")
}

// capValue — значение, которое шаблон получил от возможностей.
func capValue(rendered string) string {
	for _, l := range strings.Split(rendered, "\n") {
		if s := strings.TrimSpace(l); strings.HasPrefix(s, "has:") {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(s, "has:")), "\"")
		}
	}
	return ""
}

// helmShortVersion — версия helm, которой снят замер. Величина без посадки
// сказана неизвестно о чём.
func helmShortVersion(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("helm", "version", "--short").CombinedOutput()
	if err != nil {
		return "?"
	}
	return string(out)
}
