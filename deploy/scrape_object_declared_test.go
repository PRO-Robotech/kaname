// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// scrape_object_declared_test.go — сбор объявлен ТЕМ ЖЕ механизмом, что и
// правила тревоги (kaname#759).
//
// Правила чарт везёт объектом оператора мониторинга (`PrometheusRule`), а сбор
// объявлял только аннотациями `prometheus.io/*` на поде. Оператор аннотаций не
// читает: его Prometheus собирает то, что названо его же объектами сбора. В
// установке, где правила доехали, цель при этом не собиралась — правила
// стояли, рядов не было, и тревоги о тишине молчали ровно там, где были нужны.
//
// Утверждается:
//
//	Р1  на каждом поставляемом профиле, где рендерится объект правил, рядом
//	    рендерится ровно один объект сбора той же группы оператора;
//	Р2  объект сбора исполним: отбирает поды этого Deployment, ходит на порт
//	    диагностики по имени, схемой и путём того же объявления на поде, а под
//	    TLS доверяет листу из секрета слушателя и сверяет его имя;
//	Р3  выключение снимает объект полностью: без оператора (`alertRules`) его
//	    вид отвергла бы схема кластера, без сбора (`metricsScrape`) он
//	    объявлял бы то, от чего оператор отказался.
package deploy_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	monitoringGroupVersion = "monitoring.coreos.com/v1"
	scrapeObjectKind       = "PodMonitor"
)

// renderedKinds — объекты рендера вида kind.
func renderedKinds(t *testing.T, rendered, kind string) []map[string]any {
	t.Helper()
	var out []map[string]any
	forEachDoc(t, rendered, func(doc map[string]any) {
		if k, _ := doc["kind"].(string); k == kind {
			out = append(out, doc)
		}
	})
	return out
}

// dig — значение по пути ключей карты; нет пути — nil.
func dig(v any, path ...string) any {
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[p]
	}
	return v
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

// judgeScrapeObject — находки Р2 об объекте сбора против Deployment того же рендера.
func judgeScrapeObject(t *testing.T, rendered string, mon map[string]any) []string {
	t.Helper()
	deps := renderedKinds(t, rendered, "Deployment")
	require.Len(t, deps, 1, "в рендере не один Deployment — отбирать нечего либо неясно что")
	dep := deps[0]
	ann := renderedPodAnnotations(t, rendered)
	envs := renderedContainerEnv(t, rendered)

	var findings []string
	if got := str(mon["apiVersion"]); got != monitoringGroupVersion {
		findings = append(findings, fmt.Sprintf("apiVersion объекта сбора %q, а правил — %q: механизм не тот же", got, monitoringGroupVersion))
	}

	podLabels, _ := dig(dep, "spec", "template", "metadata", "labels").(map[string]any)
	sel, _ := dig(mon, "spec", "selector", "matchLabels").(map[string]any)
	if len(sel) == 0 {
		findings = append(findings, "отбор подов пуст: пустой отбор берёт ВСЕ поды пространства, а не эту службу")
	}
	for k, v := range sel {
		if str(podLabels[k]) != str(v) {
			findings = append(findings, fmt.Sprintf("отбор %s=%v не совпадает с меткой пода (%v): цель не найдётся", k, v, podLabels[k]))
		}
	}
	if ns, _ := dig(mon, "metadata", "namespace").(string); ns == "" {
		findings = append(findings, "объект сбора без пространства имён: оператор ищет поды в его пространстве")
	}

	eps, _ := dig(mon, "spec", "podMetricsEndpoints").([]any)
	if len(eps) != 1 {
		return append(findings, fmt.Sprintf("точек сбора %d, а поверхность диагностики одна", len(eps)))
	}
	ep, _ := eps[0].(map[string]any)

	// Порт — по ИМЕНИ контейнерного порта, чей номер объявлен на поде.
	portName := str(ep["port"])
	var portNumber string
	containers, _ := dig(dep, "spec", "template", "spec", "containers").([]any)
	for _, c := range containers {
		ports, _ := dig(c, "ports").([]any)
		for _, p := range ports {
			if str(dig(p, "name")) == portName {
				portNumber = str(dig(p, "containerPort"))
			}
		}
	}
	if portNumber == "" {
		findings = append(findings, fmt.Sprintf("порт %q не назван ни одним контейнером: оператору некуда идти", portName))
	} else if portNumber != ann["prometheus.io/port"] {
		findings = append(findings, fmt.Sprintf("порт %q — это %s, а диагностика объявлена на %s", portName, portNumber, ann["prometheus.io/port"]))
	}
	if got := str(ep["path"]); got != ann["prometheus.io/path"] {
		findings = append(findings, fmt.Sprintf("путь %q, а на поде объявлен %q", got, ann["prometheus.io/path"]))
	}
	wantScheme := "http"
	if envs["KANAME_METRICS_SERVER_MTLS_ENABLE"] == "true" {
		wantScheme = "https"
	}
	if got := str(ep["scheme"]); got != wantScheme {
		findings = append(findings, fmt.Sprintf("схема %q, а транспорт диагностики требует %q: сбора не будет", got, wantScheme))
	}
	if wantScheme == "https" {
		var secretName string
		vols, _ := dig(dep, "spec", "template", "spec", "volumes").([]any)
		for _, v := range vols {
			if str(dig(v, "name")) == "tls-server" {
				secretName = str(dig(v, "secret", "secretName"))
			}
		}
		if got := str(dig(ep, "tlsConfig", "ca", "secret", "name")); got == "" || got != secretName {
			findings = append(findings, fmt.Sprintf("якорь доверия из секрета %q, а лист слушателя — из %q: проверка листа отвергнет сбор", got, secretName))
		}
		if got := str(dig(ep, "tlsConfig", "ca", "secret", "key")); got != "ca.crt" {
			findings = append(findings, fmt.Sprintf("ключ якоря %q, а удостоверяющий центр в секрете лежит под ca.crt", got))
		}
		name := str(dig(dep, "metadata", "name"))
		ns := str(dig(dep, "metadata", "namespace"))
		if got, want := str(dig(ep, "tlsConfig", "serverName")), fmt.Sprintf("%s.%s.svc.cluster.local", name, ns); got != want {
			findings = append(findings, fmt.Sprintf("сверяемое имя листа %q, а лист выписан на %q: сбор по IP пода без имени не пройдёт проверку", got, want))
		}
		if dig(ep, "tlsConfig", "insecureSkipVerify") == true {
			findings = append(findings, "проверка листа выключена: сбор под TLS без проверки — открытый текст по смыслу")
		}
	}
	return findings
}

// TestCollectionIsDeclaredByTheRulesMechanism — Р1, Р2 на каждом профиле.
func TestCollectionIsDeclaredByTheRulesMechanism(t *testing.T) {
	renders := alertRenders(t)
	require.NotEmpty(t, renders, "перепись профилей пуста — проверять нечего, это не зелёное")
	for _, r := range renders {
		t.Run(r.name, func(t *testing.T) {
			rendered := renderStandaloneChart(t, r.chain, r.sets...)
			rulesObjs := renderedKinds(t, rendered, "PrometheusRule")
			mons := renderedKinds(t, rendered, scrapeObjectKind)
			t.Logf("перепись: объектов правил %d · объектов сбора %d", len(rulesObjs), len(mons))
			require.NotEmpty(t, rulesObjs, "объект правил не отрендерился — вердикта о сборе рядом с ним нет")
			require.Lenf(t, mons, len(rulesObjs), "объектов сбора %d при объектах правил %d: правила оператора "+
				"стоят, а цель оператором не собирается — тревоги о тишине молчат", len(mons), len(rulesObjs))
			findings := judgeScrapeObject(t, rendered, mons[0])
			require.Emptyf(t, findings, "объект сбора неисполним:\n  %s", strings.Join(findings, "\n  "))
		})
	}
}

// TestScrapeObjectFollowsBothSwitches — Р3.
func TestScrapeObjectFollowsBothSwitches(t *testing.T) {
	chain := []string{"values.yaml", "values.prod.yaml"}
	for _, c := range []struct {
		name string
		sets []string
	}{
		{"без оператора", []string{alertRulesToggle + "=false"}},
		{"без сбора", []string{"metricsScrape.enabled=false", "metricsScrape.disabledBecause=собирает платформа"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			rendered := renderStandaloneChart(t, chain, c.sets...)
			require.Empty(t, renderedKinds(t, rendered, scrapeObjectKind),
				"выключение не сняло объект сбора: без оператора его вид отвергнет схема кластера, "+
					"без сбора он объявлял бы то, от чего оператор отказался")
		})
	}
}

// Инъекция: проба Р2 краснеет на объекте, который выглядит настроенным и не
// собирает, — схема открытым текстом под TLS и чужое имя листа.
func TestScrapeObjectJudgeInjection_PlaintextAndWrongNameAreFound(t *testing.T) {
	rendered := renderStandaloneChart(t, []string{"values.yaml", "values.prod.yaml"})
	mons := renderedKinds(t, rendered, scrapeObjectKind)
	require.Len(t, mons, 1, "предпосылка инъекции: объект сбора есть")
	require.Empty(t, judgeScrapeObject(t, rendered, mons[0]), "предпосылка инъекции: законный близнец чист")

	ep := dig(mons[0], "spec", "podMetricsEndpoints").([]any)[0].(map[string]any)
	ep["scheme"] = "http"
	ep["tlsConfig"].(map[string]any)["serverName"] = "kaname"
	findings := judgeScrapeObject(t, rendered, mons[0])
	t.Logf("находок на инъекции: %d", len(findings))
	require.Len(t, findings, 2, "инъекция двух дефектов обязана дать ровно две находки:\n  %s", strings.Join(findings, "\n  "))
}
