// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// port_knob_moves_its_listener_injection_test.go — доказательство того, что гейт
// ключей посадки СПОСОБЕН УПАСТЬ и падает ровно на своём предмете.
//
// # Почему инъекция чартом, а не подставным рендером
//
// Предмет гейта — ЧТО СДЕЛАЕТ ключ, если его тронуть, и производитель ответа —
// сам helm. Подставной рендер доказывал бы о своей копии; здесь возвращается
// настоящий дефект (состояние чарта ДО починки), и гейт судит его ТЕМ ЖЕ кодом,
// которым судит дерево (`judgePortKnobs`).
//
// # Осей три, у каждой законный близнец
//
//  1. МАРШРУТ БЕЗ СЛУШАТЕЛЯ  дерево до починки → красное с именем ключа;
//     на той же копии `ports.grpc` — молчание (он двигает слушатель).
//  2. КЛЮЧ БЕЗ ЧИТАТЕЛЯ      ключ, которого не читает никто → красное;
//     живые ключи рядом — молчание.
//  3. ПУСТОТА                `ports:` пуст → ОТКАЗ предпосылки, а не «ключей 0».
//
// Третья ось обязательна: без неё «ноль находок» неотличимо от «ноль
// прочитанного».
package deploy_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// portsBlockAfterTheFix — блок `ports:` дерева ПОСЛЕ починки. Предмет замены во
// всех осях один, поэтому объявлен однажды.
const portsBlockAfterTheFix = "ports:\n  grpc: 9090\n  internalGrpc: 9091\n"

// retiredKnobGuardInclude — провязка стража снятых ключей.
const retiredKnobGuardInclude = `{{- include "kaname-svc.requireNoRetiredPortKnobs" . -}}`

// chartCopyBeforeTheFix — копия чарта в состоянии ДО починки #2394: ключ
// `ports.metrics` объявлен профилем, шаблон пода читает ЕГО, стража снятых
// ключей нет. Три правки суть ОДИН факт — «состояние до починки», — и тем же
// способом инъицирует соседний гейт маршрутов.
func chartCopyBeforeTheFix(t *testing.T) string {
	t.Helper()
	dir := chartCopy(t)

	patchInCopy(t, dir, "values.yaml", portsBlockAfterTheFix,
		portsBlockAfterTheFix+"  metrics: 9095\n")

	patchInCopy(t, dir, "templates/deployment.yaml",
		`prometheus.io/port: {{ include "kaname-svc.processDefaultPort" "metrics" | quote }}`,
		`prometheus.io/port: {{ .Values.ports.metrics | quote }}`)
	patchInCopy(t, dir, "templates/deployment.yaml",
		`containerPort: {{ include "kaname-svc.processDefaultPort" "metrics" }}`,
		`containerPort: {{ .Values.ports.metrics }}`)

	dropLineInCopy(t, dir, "templates/deployment.yaml", retiredKnobGuardInclude)
	dropLineInCopy(t, dir, "templates/configmap.yaml", retiredKnobGuardInclude)
	return dir
}

func TestPortKnobGateFallsOnARouteWithoutAListener(t *testing.T) {
	dir := chartCopyBeforeTheFix(t)
	files := []string{"values.yaml", "values.prod.yaml"}

	knobs := portKnobsDeclaredAt(t, dir)
	require.Containsf(t, knobs, "metrics",
		"инъекция не вернула ключ в профиль: гейт судил бы то же дерево, что и без неё")

	base := renderChartAt(t, dir, files...)
	single, _, findings := judgePortKnobsAt(t, dir, files, knobs, listenerPortsOf(t, base))

	require.NotEmpty(t, findings, "гейт промолчал на возвращённом дефекте — он не гейт")
	joined := strings.Join(findings, "\n")
	require.Contains(t, joined, "ports.metrics",
		"находка не называет ключ: оператор пойдёт искать не там")
	require.Contains(t, joined, "остался прежним",
		"находка называет не тот предмет: расхождение маршрута и слушателя обязано быть названо")

	// ЗАКОННЫЙ БЛИЗНЕЦ ТОЙ ЖЕ ФОРМЫ, на той же копии: `ports.grpc` — такой же
	// ключ под `ports:`, и он двигает слушатель. Гейт обязан о нём молчать,
	// иначе он ловит форму («ключ под ports:»), а не существо.
	require.NotContains(t, joined, "ports.grpc",
		"гейт краснеет на ключе, который слушатель двигает: он судит форму, а не существо")
	require.NotContains(t, joined, "ports.internalGrpc",
		"гейт краснеет на ключе, который слушатель двигает: он судит форму, а не существо")
	require.Equalf(t, len(knobs)-1, single,
		"ручкой одной двери обязаны остаться все ключи, кроме возвращённого дефектом")
}

func TestPortKnobGateFallsOnAKnobNobodyReads(t *testing.T) {
	dir := chartCopy(t)
	// ОДИН факт против дерева после починки: ключ, которого не читает никто.
	patchInCopy(t, dir, "values.yaml", portsBlockAfterTheFix,
		portsBlockAfterTheFix+"  orphan: 9099\n")

	files := []string{"values.yaml", "values.prod.yaml"}
	knobs := portKnobsDeclaredAt(t, dir)
	base := renderChartAt(t, dir, files...)
	_, _, findings := judgePortKnobsAt(t, dir, files, knobs, listenerPortsOf(t, base))

	joined := strings.Join(findings, "\n")
	require.Contains(t, joined, "ports.orphan", "ключ без читателя обязан быть находкой")
	require.Contains(t, joined, "не двинул НИЧЕГО",
		"находка называет не тот предмет: ручка без читателя — не расхождение двух ручек")
	require.NotContains(t, joined, "ports.grpc", "законный близнец обязан молчать")
}

func TestPortKnobGateRefusesAnEmptyPortsBlock(t *testing.T) {
	dir := chartCopy(t)
	// ОДИН факт: блок ключей опустошён. Гейт обязан ОТКАЗАТЬ, а не отчитаться
	// «ключей 0, все чисты»: пустой обход — не идеал, а отсутствие предмета.
	patchInCopy(t, dir, "values.yaml", portsBlockAfterTheFix, "ports: {}\n")

	require.Empty(t, portKnobsDeclaredAt(t, dir),
		"инъекция не опустошила блок: ось пустоты доказывала бы о непустом входе")
}

// portKnobsDeclaredAt / judgePortKnobsAt — те же суждения, что судят дерево, но
// над названным каталогом. Копий логики здесь нет намеренно: инъекция,
// пересказавшая гейт, доказывает о пересказе.
func portKnobsDeclaredAt(t *testing.T, dir string) []string {
	t.Helper()
	return portKnobsIn(t, readChartFile(t, dir, "values.yaml"))
}

func judgePortKnobsAt(t *testing.T, dir string, files, knobs []string, baseListeners map[string]bool) (int, []portKnobVerdict, []string) {
	t.Helper()
	return judgePortKnobsIn(t, dir, files, knobs, baseListeners)
}
