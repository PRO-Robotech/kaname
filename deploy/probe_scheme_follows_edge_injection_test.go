// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// probe_scheme_follows_edge_injection_test.go — доказательство того, что гейт
// схемы проб СПОСОБЕН УПАСТЬ и падает ровно на своём предмете.
//
// # Прогонов три, а не два
//
//	контроль          действующий шаблон против обоих профилей — молчание
//	                  (утверждает сам гейт, здесь не повторяется);
//	инъекция          схема снята у пробы на ребре ПОД TLS — красное с именем
//	                  пробы, ручки и обеих схем;
//	законный близнец  та же снятая схема на ребре БЕЗ TLS — молчание.
//
// Близнец здесь несущий: гейт, требующий HTTPS безусловно, покраснел бы на
// стендовом профиле, где слушатель открытым текстом и HTTP верен. Такой гейт
// сняли бы первым же — и вместе с ним предмет.
package deploy_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// probeSchemeLines — то, что инъекция снимает: обе строки схемы.
const (
	probeSchemeReadiness = "              scheme: {{ $hooksScheme }}\n            initialDelaySeconds: 5"
	probeSchemeLiveness  = "              scheme: {{ $hooksScheme }}\n            initialDelaySeconds: 10"
	probeNoSchemeRead    = "            initialDelaySeconds: 5"
	probeNoSchemeLive    = "            initialDelaySeconds: 10"
)

// renderWithoutProbeScheme возвращает чарт в состояние ДО починки: пробы без
// схемы, то есть открытым текстом при любом транспорте ребра.
func renderWithoutProbeScheme(t *testing.T, profile string) string {
	t.Helper()
	dir := chartCopy(t)
	patchInCopy(t, dir, "templates/deployment.yaml", probeSchemeReadiness, probeNoSchemeRead)
	patchInCopy(t, dir, "templates/deployment.yaml", probeSchemeLiveness, probeNoSchemeLive)
	return renderChartAt(t, dir, "values.yaml", profile)
}

func TestProbeSchemeCensusCanFail(t *testing.T) {
	rendered := renderWithoutProbeScheme(t, "values.prod.yaml")

	probes, checked, findings := judgeProbeSchemes(t, rendered)
	require.Equal(t, 2, probes, "проб в шаблоне две")
	require.Equal(t, 2, checked, "обе сверены с ребром")
	require.Len(t, findings, 2,
		"боевой профиль поднимает ребро вебхуков по TLS, а обе пробы идут открытым текстом — "+
			"гейт, здесь промолчавший, не измеряет своего предмета")

	joined := strings.Join(findings, "\n")
	require.Contains(t, joined, "readinessProbe", "находка обязана назвать пробу поимённо")
	require.Contains(t, joined, "livenessProbe", "находка обязана назвать пробу поимённо")
	require.Contains(t, joined, "KANAME_HOOKS_SERVER_MTLS_ENABLE",
		"находка обязана назвать РУЧКУ, по которой вынесен вердикт: без неё читатель не знает, где чинить")
	require.Contains(t, joined, "не станет готовым",
		"находка обязана назвать следствие, а не только расхождение: гейт, чьё сообщение непонятно, снимают")
}

// ЗАКОННЫЙ БЛИЗНЕЦ. Та же снятая схема на ребре БЕЗ TLS — молчание.
func TestProbeSchemeStaysSilentWhenTheEdgeIsPlaintext(t *testing.T) {
	rendered := renderWithoutProbeScheme(t, "values.dev.yaml")

	probes, checked, findings := judgeProbeSchemes(t, rendered)
	require.Equal(t, 2, probes)
	require.Equal(t, 2, checked)
	require.Empty(t, findings,
		"стендовый профиль ребра не шифрует, и проба открытым текстом на нём ВЕРНА: "+
			"гейт, покрасневший здесь, требовал бы HTTPS там, где слушатель его не несёт")
}

// ПУСТОТА. Рендер без единой пробы — отказ, а не «проб 0, все сверены».
func TestProbeSchemeRefusesARenderWithoutProbes(t *testing.T) {
	// Законный близнец: на действующем рендере предпосылка держится.
	live := renderedProbes(t, renderStandaloneChart(t, []string{"values.yaml", "values.prod.yaml"}))
	require.NoError(t, probesPresent(live), "на действующем шаблоне предпосылка обязана держаться")

	err := probesPresent(nil)
	require.Error(t, err,
		"рендер без единой пробы обязан быть ОТКАЗОМ, а не вердиктом «проб 0, расхождений 0»")
	require.Contains(t, err.Error(), "неотличимо",
		"отказ обязан называть, чем пустой обход опасен, иначе гейт снимут как непонятный")
}
