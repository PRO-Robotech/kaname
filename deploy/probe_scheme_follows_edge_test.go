// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// probe_scheme_follows_edge_test.go — СХЕМА ПРОБЫ следует за транспортом того
// ребра, на которое проба нацелена.
//
// # Предмет
//
// Пробы шли открытым текстом на слушатель, который тот же профиль поднимает по
// TLS (задача #2336). Под, поднятый боевым профилем, НЕ СТАНОВИЛСЯ ГОТОВЫМ:
// kubelet получал ответ вне полосы успеха, проба готовности отказывала, а проба
// живости перезапускала контейнер по кругу. Профиль при этом рендерился и
// читался настроенным.
//
// # Почему это самоистекшее послабление, а не недосмотр
//
// Комментарий над пробами объявлял причину И ПРЕДИКАТ СВОЕГО СНЯТИЯ: «ручки TLS
// слушателей у этого чарта не существует… появится ручка — проба обязана
// переехать вместе с ней тем же изменением». Ручка появилась, проба не
// переехала. Послабление, чей предикат снятия наступил, само не истекает — его
// истечение обязан держать гейт.
//
// # Что здесь утверждается
//
//	Р1  у каждой пробы, нацеленной на ребро с объявленным TLS, схема HTTPS;
//	Р2  у пробы на ребре БЕЗ TLS схема не навязывается — иначе гейт требовал бы
//	    HTTPS там, где слушатель его не несёт, и ронял бы стендовый профиль;
//	Р3  перепись печатается ДВУМЯ величинами.
//
// # Область
//
// Судится ОБЪЯВЛЕНИЕ чарта. Пода проба не поднимает: свободного кластера нет,
// это третья категория.
package deploy_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// probeEdgeOfPort — какое ребро стоит за именованным портом пода.
//
// Имя ребра — то же, которым названа его ручка транспорта
// (`KANAME_<РЕБРО>_SERVER_MTLS_ENABLE`), поэтому связь порта с ручкой здесь
// одна и второго места об одном предмете не заводится.
var probeEdgeOfPort = map[string]string{
	"http-hooks":     "HOOKS",
	"metrics":        "METRICS",
	"http-jwks":      "JWKSPROXY",
	"registry-token": "REGISTRYTOKEN",
	"http-rest":      "REST",
	"http-rest-int":  "INTERNALREST",
}

func TestProbeSchemeFollowsTheTLSOfItsEdge(t *testing.T) {
	for _, profile := range []string{"values.prod.yaml", "values.dev.yaml"} {
		t.Run(profile, func(t *testing.T) {
			rendered := renderStandaloneChart(t, []string{"values.yaml", profile})
			probes, checked, findings := judgeProbeSchemes(t, rendered)
			require.Emptyf(t, findings,
				"проб %d · сверено с ребром %d; расходится %d:\n  - %s",
				probes, checked, len(findings), strings.Join(findings, "\n  - "))
		})
	}
}

// judgeProbeSchemes — само суждение. Отдельной функцией: доказательство
// способности гейта упасть обязано звать его же.
func judgeProbeSchemes(t *testing.T, rendered string) (int, int, []string) {
	t.Helper()

	envs := renderedContainerEnv(t, rendered)
	probes := renderedProbes(t, rendered)
	require.NoError(t, probesPresent(probes), "предпосылка гейта")

	var total, checked int
	var findings []string
	var lines []string

	for _, p := range probes {
		total++
		edge, known := probeEdgeOfPort[p.port]
		if !known {
			lines = append(lines, fmt.Sprintf("  %-16s → порт %q ребром не опознан", p.kind, p.port))
			findings = append(findings, fmt.Sprintf(
				"%s нацелена на порт %q, за которым гейт не знает ребра: транспорт этого порта "+
					"не сверяется НИ С ЧЕМ, и проба на нём была бы вне наблюдения", p.kind, p.port))
			continue
		}
		checked++
		underTLS := envs[fmt.Sprintf("KANAME_%s_SERVER_MTLS_ENABLE", edge)] == "true"
		want := "HTTP"
		if underTLS {
			want = "HTTPS"
		}
		lines = append(lines, fmt.Sprintf("  %-16s порт %-14s ребро %-14s TLS=%-5v схема %s",
			p.kind, p.port, edge, underTLS, p.scheme))
		if p.scheme != want {
			findings = append(findings, fmt.Sprintf(
				"%s на порт %q: ребро %s поднято %s (ручка KANAME_%s_SERVER_MTLS_ENABLE=%q), "+
					"а проба идёт схемой %q — kubelet получит ответ вне полосы успеха, и под "+
					"не станет готовым",
				p.kind, p.port, edge,
				map[bool]string{true: "по TLS", false: "открытым текстом"}[underTLS],
				edge, envs[fmt.Sprintf("KANAME_%s_SERVER_MTLS_ENABLE", edge)], p.scheme))
		}
	}

	sort.Strings(lines)
	t.Logf("ПЕРЕПИСЬ проб пода:\n%s\n  проб %d · СВЕРЕНО С РЕБРОМ %d", strings.Join(lines, "\n"), total, checked)
	require.NotZero(t, checked,
		"ни одна проба не сверена с ребром — гейт прочитал бы ноль и промолчал")
	return total, checked, findings
}

// probesPresent — ПРЕДПОСЫЛКА гейта: сверять есть что.
//
// Отдельной функцией с возвращаемой ошибкой: доказательство способности гейта
// упасть обязано звать ЕЁ ЖЕ. Рендер без единой пробы дал бы вердикт «проб 0,
// расхождений 0» — вакуумное зелёное ровно там, где пробу и потеряли.
func probesPresent(probes []renderedProbe) error {
	if len(probes) == 0 {
		return fmt.Errorf("в рендере нет ни одной пробы: вердикт был бы о пустоте, " +
			"и «ноль находок» стало бы неотличимо от «ноль прочитанного»")
	}
	return nil
}

type renderedProbe struct {
	kind   string
	port   string
	scheme string
}

// renderedProbes — пробы контейнера. Схема, которую не назвали, читается как
// HTTP: таково умолчание Kubernetes, и именно оно давало дефект молча.
func renderedProbes(t *testing.T, rendered string) []renderedProbe {
	t.Helper()
	var out []renderedProbe
	forEachDoc(t, rendered, func(doc map[string]any) {
		if k, _ := doc["kind"].(string); k != "Deployment" {
			return
		}
		spec, _ := doc["spec"].(map[string]any)
		tmpl, _ := spec["template"].(map[string]any)
		pspec, _ := tmpl["spec"].(map[string]any)
		conts, _ := pspec["containers"].([]any)
		for _, c := range conts {
			cm, _ := c.(map[string]any)
			for _, kind := range []string{"readinessProbe", "livenessProbe", "startupProbe"} {
				pr, ok := cm[kind].(map[string]any)
				if !ok {
					continue
				}
				get, ok := pr["httpGet"].(map[string]any)
				if !ok {
					continue
				}
				scheme, ok := get["scheme"].(string)
				if !ok || scheme == "" {
					scheme = "HTTP"
				}
				out = append(out, renderedProbe{
					kind:   kind,
					port:   fmt.Sprintf("%v", get["port"]),
					scheme: scheme,
				})
			}
		}
	})
	return out
}

// renderedContainerEnv — переменные окружения контейнера.
func renderedContainerEnv(t *testing.T, rendered string) map[string]string {
	t.Helper()
	out := map[string]string{}
	forEachDoc(t, rendered, func(doc map[string]any) {
		if k, _ := doc["kind"].(string); k != "Deployment" {
			return
		}
		spec, _ := doc["spec"].(map[string]any)
		tmpl, _ := spec["template"].(map[string]any)
		pspec, _ := tmpl["spec"].(map[string]any)
		conts, _ := pspec["containers"].([]any)
		for _, c := range conts {
			cm, _ := c.(map[string]any)
			list, _ := cm["env"].([]any)
			for _, e := range list {
				em, _ := e.(map[string]any)
				name, _ := em["name"].(string)
				if v, ok := em["value"].(string); ok {
					out[name] = v
				}
			}
		}
	})
	return out
}
