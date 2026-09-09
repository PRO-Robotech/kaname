// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// scrape_declared_injection_test.go — доказательство того, что гейт объявления
// сбора СПОСОБЕН УПАСТЬ и падает ровно на своём предмете.
//
// # Осей четыре, у каждой законный близнец
//
//  1. ОТСУТСТВИЕ   объявление снято целиком → красное: величины производятся,
//     снять их нечем. Действующее объявление → молчание.
//  2. СХЕМА        объявление называет открытый текст на поверхности под TLS →
//     красное с обеими схемами и ручкой. Та же схема на стендовом
//     профиле, где TLS нет, → молчание.
//  3. ПРИЧИНА      сбор выключен без причины → красное; выключен С причиной →
//     молчание («сбора здесь нет» — законный выбор оператора).
//  4. ПУСТОТА      ноль прочитанных серий → отказ, а не «серий 0, всё объявлено».
package deploy_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const metricsPort = "9095"

// ── ось 1: отсутствие объявления ─────────────────────────────────────────────

func TestScrapeDeclarationCensusCanFail(t *testing.T) {
	dir := chartCopy(t)
	for _, prefix := range []string{"prometheus.io/scrape:", "prometheus.io/port:", "prometheus.io/path:", "prometheus.io/scheme:"} {
		dropLineInCopy(t, dir, "templates/deployment.yaml", prefix)
	}
	dropLineInCopy(t, dir, "templates/deployment.yaml", "kaname.cloud/metrics-scrape-disabled-because:")
	rendered := renderChartAt(t, dir, "values.yaml", "values.prod.yaml")

	declared, findings := judgeScrapeDeclaration(t, rendered, metricsPort)
	require.NotEmpty(t, findings,
		"объявление сбора снято целиком, величины производятся — гейт, здесь промолчавший, "+
			"не измеряет своего предмета")
	require.Contains(t, declared, "нет",
		"перепись обязана сказать, что способа снятия НЕТ, а не только перечислить находки")
	require.Contains(t, strings.Join(findings, "\n"), "не снимаются никем",
		"находка обязана назвать следствие: величины есть, и снять их нечем")
}

// ── ось 2: схема ─────────────────────────────────────────────────────────────

func TestScrapeDeclarationCatchesPlaintextSchemeOnATLSSurface(t *testing.T) {
	dir := chartCopy(t)
	patchInCopy(t, dir, "templates/deployment.yaml",
		`prometheus.io/scheme: {{ include "kaname-svc.edgeScheme" (dict "root" $ "edge" "METRICS") | lower | quote }}`,
		`prometheus.io/scheme: "http"`)
	rendered := renderChartAt(t, dir, "values.yaml", "values.prod.yaml")

	_, findings := judgeScrapeDeclaration(t, rendered, metricsPort)
	require.NotEmpty(t, findings,
		"боевой профиль поднимает диагностику по TLS, а объявление зовёт агента открытым текстом")
	joined := strings.Join(findings, "\n")
	require.Contains(t, joined, "KANAME_METRICS_SERVER_MTLS_ENABLE",
		"находка обязана назвать ручку, по которой вынесен вердикт")
	require.Contains(t, joined, "сбора не будет вовсе",
		"находка обязана назвать следствие, а не только расхождение строк")
}

// ЗАКОННЫЙ БЛИЗНЕЦ: та же вписанная схема на профиле БЕЗ TLS — молчание.
func TestScrapeDeclarationStaysSilentWhenTheSurfaceIsPlaintext(t *testing.T) {
	dir := chartCopy(t)
	patchInCopy(t, dir, "templates/deployment.yaml",
		`prometheus.io/scheme: {{ include "kaname-svc.edgeScheme" (dict "root" $ "edge" "METRICS") | lower | quote }}`,
		`prometheus.io/scheme: "http"`)
	rendered := renderChartAt(t, dir, "values.yaml", "values.dev.yaml")

	_, findings := judgeScrapeDeclaration(t, rendered, metricsPort)
	require.Empty(t, findings,
		"стендовый профиль поверхность не шифрует, и открытый текст в объявлении ВЕРЕН: "+
			"гейт, покрасневший здесь, требовал бы https там, где слушатель его не несёт")
}

// ── ось 3: причина выключения ────────────────────────────────────────────────

func TestScrapeDeclarationDemandsAReasonWhenCollectionIsOff(t *testing.T) {
	// ПЕРВЫЙ рубеж — сам рендер: выключение без причины не ставится вовсе.
	dir := chartCopy(t)
	_, err := renderChartAtAllowingFailure(t, dir, []string{"values.yaml", "values.prod.yaml"},
		"metricsScrape.enabled=false")
	require.Error(t, err,
		"выключение сбора без причины обязано ронять УСТАНОВКУ: «сбора нет намеренно» "+
			"неотличимо от «забыли», и отличить их обязан рендер, а не память оператора")

	// ВТОРОЙ рубеж — гейт: если рубеж рендера снимут, находка остаётся за ним.
	bare := chartCopy(t)
	dropLineInCopy(t, bare, "templates/deployment.yaml", "kaname.cloud/metrics-scrape-disabled-because:")
	rendered := renderChartAt2(t, bare, []string{"values.yaml", "values.prod.yaml"},
		"metricsScrape.enabled=false")

	declared, findings := judgeScrapeDeclaration(t, rendered, metricsPort)
	require.NotEmpty(t, findings, "сбор выключен, причина не названа — это находка")
	require.Contains(t, declared, "без причины")
	require.Contains(t, strings.Join(findings, "\n"), "неотличимо от «забыли объявить»")
}

// ЗАКОННЫЙ БЛИЗНЕЦ: выключено С причиной — молчание.
func TestScrapeDeclarationAcceptsCollectionDisabledWithAReason(t *testing.T) {
	rendered := renderChartAt2(t, ".", []string{"values.yaml", "values.prod.yaml"},
		"metricsScrape.enabled=false",
		"metricsScrape.disabledBecause=сбор ведёт агент вне кластера по своей описи")

	declared, findings := judgeScrapeDeclaration(t, rendered, metricsPort)
	require.Empty(t, findings,
		"«сбора в этой установке нет» — законный выбор оператора: объявленный, он обязан молчать")
	require.Contains(t, declared, "нет, объявлено:",
		"перепись обязана назвать выбор оператора, а не выдать его за исполненный сбор")
}

// ── ось 4: пустота ───────────────────────────────────────────────────────────

func TestScrapeGateRefusesAnEmptySeriesCensus(t *testing.T) {
	require.NoError(t, seriesPresent(47), "законный близнец: серии прочитаны — предпосылка держится")

	err := seriesPresent(0)
	require.Error(t, err,
		"ноль прочитанных серий обязан быть ОТКАЗОМ, а не вердиктом «серий 0, всё объявлено»")
	require.Contains(t, err.Error(), "неотличимо",
		"отказ обязан называть, чем пустой обход опасен")
}
