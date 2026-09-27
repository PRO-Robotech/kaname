// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// hooks_port_follows_posture_test.go — ПОРТ ВЕБХУКОВ ПОСТАВЩИКА ЕСТЬ В ЧАРТЕ
// РОВНО ТАМ, ГДЕ ПРОЦЕСС ПОДНИМАЕТ ИХ СЛУШАТЕЛЬ, А ПРОБЫ ПОДА ИДУТ НА
// ДИАГНОСТИКУ, КОТОРАЯ ЕСТЬ ПРИ ЛЮБОЙ ПОСАДКЕ (kaname#360).
//
// # Предмет
//
// Живость и готовность жили на слушателе вебхуков, и пробы пода шли в его
// порт. С #360 процесс под посадкой `own` этот слушатель не поднимает вовсе
// (`hooksLaneSurface`), а чарт продолжал объявлять порт `http-hooks` у пода и
// у внутреннего Service и слать туда kubelet: под `own` не становился готовым
// никогда, проба живости перезапускала контейнер по кругу, а Service вёл в
// дверь, за которой никого нет. Рендер при этом был зелёным: каждое объявление
// по отдельности верно, неверно только их отношение к процессу.
//
// # Что здесь утверждается
//
//	Р1  ИСТОЧНИК ОЖИДАНИЯ — предикат процесса
//	    (`config.AuthNConfig.HasExternalIdentityProvider`), спрошенный по
//	    каждому значению словаря посадок и по незаявленной, а не выписанный
//	    здесь. Предикат процесса — «не own», а не «== external»: незаявленная
//	    посадка слушатель СОХРАНЯЕТ, и чарт обязан сохранить порт;
//	Р2  где процесс слушатель поднимает — порт `http-hooks` есть у пода и у
//	    внутреннего Service и несёт номер адреса по умолчанию; где не поднимает —
//	    нет ни порта с этим именем, ни порта с этим номером ни на одном объекте;
//	Р3  пробы готовности и живости нацелены на диагностическую поверхность —
//	    порт пода, чей номер есть номер адреса диагностики по умолчанию, — и
//	    путь каждой пробы ОБСЛУЖИВАЕТ мультиплексор диагностики (не 404/405);
//	Р4  там, где слушателя нет, ни одно правило тревоги не читает ряд обращений
//	    к хукам (#210); положительный близнец — под `external` такие правила есть,
//	    иначе «ноль правил о хуках» было бы неотличимо от «правил не прочитано»;
//	Р5  перепись печатается числами, пустой обход роняет прогон; обе стороны
//	    предиката (поднят · не поднят) обязаны встретиться хотя бы раз.
//
// # Область
//
// Судится ОБЪЯВЛЕНИЕ чарта. Пода проба не поднимает — об установке в кластере
// она не утверждает ничего; это третья категория, а не зелёное.
package deploy_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/handler/diagnostics"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	"github.com/PRO-Robotech/kaname/tools/surfaceroster"
)

// Ключи адресов в настройке процесса — те, по которым перечень поверхностей
// называет слушатель. Номера портов берутся у перечня, а не выписываются.
const (
	hooksSettingKey       = "authn.hooks-http-endpoint"
	diagnosticsSettingKey = "api-server.metrics-endpoint"
	hooksPortName         = "http-hooks"
)

// postureRender — вход рендера и посадка, которую он объявляет.
type postureRender struct {
	name    string
	chain   []string
	sets    []string
	posture config.IdentityProvider
}

// postureRenders — каждое значение словаря посадок боевой цепочкой плюс
// незаявленная посадка стендовой цепочкой.
//
// Словарь берётся у общего фундамента: новое значение попадёт сюда само, и
// ожидание для него спросится у того же предиката процесса.
func postureRenders(t *testing.T) []postureRender {
	t.Helper()
	var out []postureRender
	for _, p := range config.IdentityProviderValues() {
		r := postureRender{name: "values.prod.yaml+" + p.String(), chain: chartProfiles, posture: p}
		if p == config.IdentityProviderOwn {
			r.sets = ownPostureOverlay
		} else {
			r.sets = []string{identityProviderKnob + "=" + p.String()}
		}
		out = append(out, r)
	}
	dev := []string{"values.yaml", "values.dev.yaml"}
	out = append(out, postureRender{name: "values.dev.yaml", chain: dev, posture: parsePosture(t, postureOfProfiles(t, dev))})
	return out
}

// parsePosture — значение ручки профиля в посадку; пусто — незаявленная.
func parsePosture(t *testing.T, s string) config.IdentityProvider {
	t.Helper()
	if s == "" {
		return config.IdentityProviderUnset
	}
	p, err := config.ParseIdentityProvider(s)
	require.NoError(t, err, "посадка, объявленная профилем")
	return p
}

// hooksRaisedByProcess — ответ ПРОЦЕССА: поднимет ли он слушатель вебхуков
// при этой посадке. Тот же предикат, что читает `hooksListenAddress`.
func hooksRaisedByProcess(p config.IdentityProvider) bool {
	return config.AuthNConfig{IdentityProvider: p}.HasExternalIdentityProvider()
}

func TestHooksPortFollowsTheProcessPosture(t *testing.T) {
	roster := readSurfaceRoster(t)
	covered := map[config.IdentityProvider]bool{}
	var raised, dropped int

	for _, r := range postureRenders(t) {
		covered[r.posture] = true
		if hooksRaisedByProcess(r.posture) {
			raised++
		} else {
			dropped++
		}
		t.Run(r.name, func(t *testing.T) {
			rendered := renderStandaloneChart(t, r.chain, r.sets...)
			c, findings := judgeHooksPosture(t, roster, rendered, r.posture)
			require.Emptyf(t, findings,
				"посадка %s (процесс слушатель вебхуков %s): находок %d:\n  - %s",
				r.posture, map[bool]string{true: "поднимает", false: "НЕ поднимает"}[c.raised],
				len(findings), strings.Join(findings, "\n  - "))
			if r.posture == config.IdentityProviderExternal {
				require.NotZerof(t, c.hookRules,
					"положительный близнец Р4: под external нет ни одного правила о ряде %s — "+
						"«ноль правил о хуках» под own было бы неотличимо от «правил не прочитано»",
					metrics.AuthnHookRequestsMetric)
			}
		})
	}

	for _, p := range append([]config.IdentityProvider{config.IdentityProviderUnset}, config.IdentityProviderValues()...) {
		require.Truef(t, covered[p], "посадка %s не отрендерена ни одним входом — её сторона предиката вне наблюдения", p)
	}
	t.Logf("входов %d · процесс слушатель поднимает на %d · не поднимает на %d", len(covered), raised, dropped)
	require.NotZero(t, raised, "ни один вход не поднимает слушатель — сторона «порт есть» вне наблюдения")
	require.NotZero(t, dropped, "ни один вход не снимает слушатель — сторона «порта нет» вне наблюдения")
}

// hooksPostureCensus — что прочитано одним рендером.
type hooksPostureCensus struct {
	raised    bool
	services  int
	svcPorts  int
	ctrPorts  int
	probes    int
	rules     int
	hookRules int
}

type namedPort struct {
	name   string
	number string
	target string
}

type probeTarget struct {
	kind string
	path string
	port string
}

// judgeHooksPosture — САМО СУЖДЕНИЕ, отделённое от пробы: доказательство
// способности упасть обязано звать его же.
func judgeHooksPosture(t *testing.T, roster surfaceroster.Roster, rendered string,
	posture config.IdentityProvider,
) (hooksPostureCensus, []string) {
	t.Helper()
	hooksPort := rosterDefaultPort(t, roster, hooksSettingKey)
	diagPort := rosterDefaultPort(t, roster, diagnosticsSettingKey)

	services := renderedNamedServicePorts(t, rendered)
	ctrPorts, probes := renderedServiceContainer(t, rendered)
	rules := renderedAlertExprs(t, rendered)
	require.NoError(t, hooksPostureInputPresent(services, ctrPorts, probes), "предпосылка гейта")

	c := hooksPostureCensus{raised: hooksRaisedByProcess(posture), services: len(services),
		ctrPorts: len(ctrPorts), probes: len(probes), rules: len(rules)}
	var findings []string
	var lines []string

	// ── Р2: порт вебхуков ───────────────────────────────────────────────────
	isHooks := func(p namedPort) bool {
		return p.name == hooksPortName || p.target == hooksPortName || p.number == hooksPort
	}
	svcNames := make([]string, 0, len(services))
	for name := range services {
		svcNames = append(svcNames, name)
	}
	sort.Strings(svcNames)
	for _, name := range svcNames {
		for _, p := range services[name] {
			c.svcPorts++
			if isHooks(p) {
				lines = append(lines, fmt.Sprintf("  Service %-16s порт %s :%s → %s", name, p.name, p.number, p.target))
				if !c.raised {
					findings = append(findings, fmt.Sprintf(
						"Service %q несёт порт вебхуков (%s :%s → %s), а процесс при посадке %s их "+
							"слушатель не поднимает: маршрут ведёт в дверь, за которой никого нет",
						name, p.name, p.number, p.target, posture))
				}
			}
		}
	}
	for _, p := range ctrPorts {
		if isHooks(p) {
			lines = append(lines, fmt.Sprintf("  контейнер        порт %s :%s", p.name, p.number))
			if !c.raised {
				findings = append(findings, fmt.Sprintf(
					"под объявляет порт вебхуков (%s :%s), а процесс при посадке %s их слушатель не "+
						"поднимает: оператор, читающий `ports:`, ищет дверь, которой нет",
					p.name, p.number, posture))
			}
		}
	}
	if c.raised {
		if !hasPort(services[internalServiceName], hooksPortName, hooksPort) {
			findings = append(findings, fmt.Sprintf(
				"процесс при посадке %s поднимает слушатель вебхуков на :%s, а у Service %q порта "+
					"%s с этим номером нет: поставщик личности не доносит вебхуки",
				posture, hooksPort, internalServiceName, hooksPortName))
		}
		if !hasPort(ctrPorts, hooksPortName, hooksPort) {
			findings = append(findings, fmt.Sprintf(
				"процесс при посадке %s поднимает слушатель вебхуков на :%s, а под порта %s с этим "+
					"номером не объявляет", posture, hooksPort, hooksPortName))
		}
	}

	// ── Р3: пробы на диагностике ────────────────────────────────────────────
	kinds := map[string]bool{}
	for _, pr := range probes {
		kinds[pr.kind] = true
		number := resolveContainerPort(ctrPorts, pr.port)
		served := diagnosticsServes(pr.path)
		lines = append(lines, fmt.Sprintf("  %-16s %-9s порт %-10s → :%-5s диагностика обслуживает путь: %v",
			pr.kind, pr.path, pr.port, number, served))
		switch {
		case number == "":
			findings = append(findings, fmt.Sprintf(
				"%s нацелена на порт %q, которого под не объявляет: kubelet не найдёт, куда стучаться, "+
					"и под не станет готовым", pr.kind, pr.port))
		case number != diagPort:
			findings = append(findings, fmt.Sprintf(
				"%s нацелена на :%s (%s), а живость и готовность обслуживает диагностическая "+
					"поверхность :%s — единственная, что есть при любой посадке", pr.kind, number, pr.port, diagPort))
		}
		if !served {
			findings = append(findings, fmt.Sprintf(
				"%s спрашивает путь %q, которого мультиплексор диагностики не обслуживает", pr.kind, pr.path))
		}
	}
	for _, k := range []string{"readinessProbe", "livenessProbe"} {
		if !kinds[k] {
			findings = append(findings, fmt.Sprintf("у контейнера службы нет %s по HTTP: готовность "+
				"и живость не спрашиваются у процесса вовсе", k))
		}
	}

	// ── Р4: правила о хуках ────────────────────────────────────────────────
	for _, r := range rules {
		if strings.Contains(r.expr, metrics.AuthnHookRequestsMetric) {
			c.hookRules++
			lines = append(lines, "  правило "+r.alert+" читает "+metrics.AuthnHookRequestsMetric)
			if !c.raised {
				findings = append(findings, fmt.Sprintf(
					"правило %s читает %s, а процесс при посадке %s слушатель вебхуков не поднимает: "+
						"тишина на нём штатна, и правило звонило бы вечно (#210)",
					r.alert, metrics.AuthnHookRequestsMetric, posture))
			}
		}
	}

	sort.Strings(lines)
	t.Logf("ПЕРЕПИСЬ посадки %s (слушатель вебхуков процессом %s; вебхуки :%s · диагностика :%s):\n%s\n"+
		"  объектов Service %d · портов Service %d · портов пода %d · проб %d · правил %d · о хуках %d",
		posture, map[bool]string{true: "поднят", false: "НЕ поднят"}[c.raised], hooksPort, diagPort,
		strings.Join(lines, "\n"), c.services, c.svcPorts, c.ctrPorts, c.probes, c.rules, c.hookRules)
	return c, findings
}

// hooksPostureInputPresent — ПРЕДПОСЫЛКА гейта: судить есть что. Отдельной
// функцией с возвращаемой ошибкой: доказательство способности упасть обязано
// звать её же. Рендер без Service, без портов пода либо без проб дал бы вердикт
// «находок 0» о пустоте — ровно там, где порт и пробу и потеряли.
func hooksPostureInputPresent(services map[string][]namedPort, ctrPorts []namedPort, probes []probeTarget) error {
	var missing []string
	if len(services) == 0 {
		missing = append(missing, "объектов Service")
	}
	if len(ctrPorts) == 0 {
		missing = append(missing, "портов контейнера службы")
	}
	if len(probes) == 0 {
		missing = append(missing, "HTTP-проб контейнера службы")
	}
	if len(missing) > 0 {
		return fmt.Errorf("в рендере нет %s: «ноль находок» было бы неотличимо от «ноль прочитанного»",
			strings.Join(missing, ", "))
	}
	return nil
}

// rosterDefaultPort — номер адреса по умолчанию у поверхности процесса.
func rosterDefaultPort(t *testing.T, roster surfaceroster.Roster, key string) string {
	t.Helper()
	for _, s := range roster.Surfaces {
		if s.SettingKey == key {
			require.NotEmptyf(t, s.DefaultPort, "у поверхности %s нет адреса по умолчанию — номер порта взять неоткуда", key)
			return s.DefaultPort
		}
	}
	t.Fatalf("перечень поверхностей процесса не знает %s (прочитано поверхностей %d) — судить не с чем",
		key, len(roster.Surfaces))
	return ""
}

func hasPort(ports []namedPort, name, number string) bool {
	for _, p := range ports {
		if p.name == name && p.number == number {
			return true
		}
	}
	return false
}

// resolveContainerPort — номер, на который нацелена проба: числом либо
// именованным портом пода. Пусто — под такого порта не объявляет.
func resolveContainerPort(ctrPorts []namedPort, port string) string {
	if _, err := strconv.Atoi(port); err == nil {
		return port
	}
	for _, p := range ctrPorts {
		if p.name == port {
			return p.number
		}
	}
	return ""
}

// diagnosticsServes — обслуживает ли путь мультиплексор диагностики процесса.
// Спрашивается сам мультиплексор, а не перечень путей рядом: перечень
// разошёлся бы с ним молча.
func diagnosticsServes(path string) bool {
	mux := diagnostics.NewMux(diagnostics.Handlers{})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed
}

// renderedNamedServicePorts — порты каждого объекта Service с именами.
func renderedNamedServicePorts(t *testing.T, rendered string) map[string][]namedPort {
	t.Helper()
	out := map[string][]namedPort{}
	forEachDoc(t, rendered, func(doc map[string]any) {
		if k, _ := doc["kind"].(string); k != "Service" {
			return
		}
		meta, _ := doc["metadata"].(map[string]any)
		name, _ := meta["name"].(string)
		spec, _ := doc["spec"].(map[string]any)
		list, _ := spec["ports"].([]any)
		ports := []namedPort{}
		for _, p := range list {
			pm, _ := p.(map[string]any)
			ports = append(ports, namedPort{
				name:   fmt.Sprintf("%v", pm["name"]),
				number: fmt.Sprintf("%v", pm["port"]),
				target: fmt.Sprintf("%v", pm["targetPort"]),
			})
		}
		out[name] = ports
	})
	return out
}

// renderedServiceContainer — порты и HTTP-пробы контейнера службы.
// Контейнер наката (`initContainers`) пробами не судится и сюда не входит.
func renderedServiceContainer(t *testing.T, rendered string) ([]namedPort, []probeTarget) {
	t.Helper()
	var ports []namedPort
	var probes []probeTarget
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
			list, _ := cm["ports"].([]any)
			for _, p := range list {
				pm, _ := p.(map[string]any)
				ports = append(ports, namedPort{
					name:   fmt.Sprintf("%v", pm["name"]),
					number: fmt.Sprintf("%v", pm["containerPort"]),
				})
			}
			for _, kind := range []string{"readinessProbe", "livenessProbe", "startupProbe"} {
				pr, ok := cm[kind].(map[string]any)
				if !ok {
					continue
				}
				get, ok := pr["httpGet"].(map[string]any)
				if !ok {
					continue
				}
				probes = append(probes, probeTarget{
					kind: kind,
					path: fmt.Sprintf("%v", get["path"]),
					port: fmt.Sprintf("%v", get["port"]),
				})
			}
		}
	})
	return ports, probes
}

type alertExpr struct {
	alert string
	expr  string
}

// renderedAlertExprs — правила объекта тревог рендера: имя и выражение.
func renderedAlertExprs(t *testing.T, rendered string) []alertExpr {
	t.Helper()
	rules, _ := chartAlertRules(t, rendered)
	out := make([]alertExpr, 0, len(rules))
	for _, r := range rules {
		out = append(out, alertExpr{alert: r.Alert, expr: r.Expr})
	}
	return out
}
