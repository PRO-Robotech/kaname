// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// hooks_port_follows_posture_injection_test.go — доказательство того, что гейт
// порта вебхуков СПОСОБЕН УПАСТЬ и падает ровно на своём предмете, по ОБЕ
// стороны предиката процесса.
//
// # Почему инъекция чартом
//
// Предмет гейта — расхождение объявлений чарта с тем, что поднимает процесс.
// Здесь в копию чарта возвращается настоящий дефект и судится тем же
// `judgeHooksPosture`, которым судится дерево.
//
// # Оси, у каждой законный близнец
//
//	И1  ЧАРТ ДО ПОЧИНКИ (#360): условие полосы хуков безусловно → под `own`
//	    красное о порте Service, о порте пода и о каждом правиле о хуках (#427:
//	    условие одно на всех читателей); под `external` та же копия молчит;
//	И2  ОБРАТНАЯ СТОРОНА: условие чарта сужено до «== external» → при
//	    незаявленной посадке процесс слушатель поднимает, а чарт не объявляет
//	    ни порта, ни правил о хуках → красное о каждом из трёх: условие одно на
//	    всех читателей; под `external` та же копия молчит;
//	И3  проба готовности возвращена на порт вебхуков → под `external` (где порт
//	    есть) красное «не диагностика», под `own` (где порта нет) — «порта нет»;
//	И4  проба спрашивает путь, которого диагностика не обслуживает → красное;
//	И5  правило о хуках вынуто из-под выключателя посадки → под `own` красное;
//	И6  ПУСТОТА: вход без Service, портов и проб → отказ предпосылки;
//	И7  выключатель правил о хуках возвращён к «== external» (дефект до #427)
//	    при верном условии порта → при незаявленной посадке красное ровно о
//	    правилах, а не о порте; под `external` и под `own` та же копия молчит.
//
// Неиспорченная копия под теми же входами — близнец всех осей: ноль находок.
package deploy_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// Предмет инъекций — дословные строки шаблонов. Не нашлась строка —
// `patchInCopy` роняет пробу: инъекция, ничего не изменившая, доказывала бы
// собственную безвредность.
const (
	hooksLanePredicateLine = `{{- if ne (toString ($authn.identityProvider | default "")) "own" -}}true{{- end -}}`
	hookRulesSwitchLine    = `{{- if include "kaname-svc.hooksLaneRaised" . }}`
	// hookRulesExternalOnly — выключатель правил о хуках до #427: снимает их
	// при незаявленной посадке, где процесс слушатель поднимает.
	hookRulesExternalOnly = `{{- if eq $authn.identityProvider "external" }}`
)

// injectedRender — рендер копии чарта при посадке p.
func injectedRender(t *testing.T, dir string, p config.IdentityProvider) string {
	t.Helper()
	switch p {
	case config.IdentityProviderOwn:
		return renderChartAt2(t, dir, chartProfiles, ownPostureOverlay...)
	case config.IdentityProviderUnset:
		return renderChartAt2(t, dir, []string{"values.yaml", "values.dev.yaml"})
	default:
		return renderChartAt2(t, dir, chartProfiles, identityProviderKnob+"="+p.String())
	}
}

// findingsAbout — находки, несущие данную подстроку.
func findingsAbout(findings []string, sub string) []string {
	var out []string
	for _, f := range findings {
		if strings.Contains(f, sub) {
			out = append(out, f)
		}
	}
	return out
}

func TestHooksPortGate_TwinCopyIsSilentOnEveryPosture(t *testing.T) {
	roster := readSurfaceRoster(t)
	dir := chartCopy(t)
	// Посадки — незаявленная и словарь; снятую `external` объявить чарту нечем
	// (PRO-Robotech/corelib#30, #424).
	for _, p := range append([]config.IdentityProvider{config.IdentityProviderUnset}, config.IdentityProviderValues()...) {
		_, findings := judgeHooksPosture(t, roster, injectedRender(t, dir, p), p)
		require.Emptyf(t, findings, "неиспорченная копия при посадке %s дала находки — близнец не законен:\n%s",
			p, strings.Join(findings, "\n"))
	}
}

func TestHooksPortGate_FindsTheUnconditionalPortUnderOwn(t *testing.T) {
	roster := readSurfaceRoster(t)
	dir := chartCopy(t)
	patchInCopy(t, dir, "templates/_helpers.tpl", hooksLanePredicateLine, "true")

	c, own := judgeHooksPosture(t, roster, injectedRender(t, dir, config.IdentityProviderOwn), config.IdentityProviderOwn)
	require.Lenf(t, findingsAbout(own, `Service "kaname-internal" несёт порт вебхуков`), 1,
		"безусловный порт под own не назван на Service:\n%s", strings.Join(own, "\n"))
	require.Lenf(t, findingsAbout(own, "под объявляет порт вебхуков"), 1,
		"безусловный порт под own не назван у пода:\n%s", strings.Join(own, "\n"))
	require.NotZero(t, c.hookRules, "безусловное условие не вернуло правил о хуках под own — "+
		"правила стоят не тем условием, что порт")
	require.Lenf(t, findingsAbout(own, "звонило бы вечно"), c.hookRules,
		"не каждое правило о хуках под own названо:\n%s", strings.Join(own, "\n"))
	require.Lenf(t, own, 2+c.hookRules, "находок не о предмете инъекции:\n%s", strings.Join(own, "\n"))

	// Близнец — незаявленная посадка: процесс слушатель там поднимает, и
	// безусловный порт законен. Прежде близнецом стояла посадка `external`;
	// она снята (PRO-Robotech/corelib#30, #424), и объявить её чарту нечем.
	_, unset := judgeHooksPosture(t, roster, injectedRender(t, dir, config.IdentityProviderUnset), config.IdentityProviderUnset)
	require.Emptyf(t, unset, "та же копия при незаявленной посадке обязана молчать — порт там законен:\n%s", strings.Join(unset, "\n"))
}

func TestHooksPortGate_FindsThePortDroppedWhereTheProcessRaisesIt(t *testing.T) {
	roster := readSurfaceRoster(t)
	dir := chartCopy(t)
	patchInCopy(t, dir, "templates/_helpers.tpl", hooksLanePredicateLine,
		`{{- if eq (toString ($authn.identityProvider | default "")) "external" -}}true{{- end -}}`)

	_, unset := judgeHooksPosture(t, roster, injectedRender(t, dir, config.IdentityProviderUnset), config.IdentityProviderUnset)
	require.Lenf(t, findingsAbout(unset, `у Service "kaname-internal" порта`), 1,
		"снятый при незаявленной посадке порт Service не назван:\n%s", strings.Join(unset, "\n"))
	require.Lenf(t, findingsAbout(unset, "а под порта http-hooks"), 1,
		"снятый при незаявленной посадке порт пода не назван:\n%s", strings.Join(unset, "\n"))
	require.Lenf(t, findingsAbout(unset, "тишину работающей двери не видит никто"), 1,
		"снятые при незаявленной посадке правила о хуках не названы — условие у них не то же, "+
			"что у порта:\n%s", strings.Join(unset, "\n"))
	require.Lenf(t, unset, 3, "находок не о предмете инъекции:\n%s", strings.Join(unset, "\n"))

	// Близнец — посадка `own`: процесс слушатель там не поднимает, и суженное
	// условие чарта его тоже снимает — расхождения нет. Прежде близнецом стояла
	// посадка `external`; она снята (PRO-Robotech/corelib#30, #424).
	_, own := judgeHooksPosture(t, roster, injectedRender(t, dir, config.IdentityProviderOwn), config.IdentityProviderOwn)
	require.Emptyf(t, own, "та же копия под own обязана молчать:\n%s", strings.Join(own, "\n"))
}

func TestHooksPortGate_FindsAProbeBackOnTheHooksPort(t *testing.T) {
	roster := readSurfaceRoster(t)
	dir := chartCopy(t)
	// Первое вхождение — проба готовности; живость остаётся на диагностике и
	// служит близнецом внутри того же рендера.
	patchInCopy(t, dir, "templates/deployment.yaml", "port: metrics", "port: http-hooks")

	// Посадка, где порт вебхуков есть, — незаявленная: `external` снята
	// (PRO-Robotech/corelib#30, #424).
	_, unset := judgeHooksPosture(t, roster, injectedRender(t, dir, config.IdentityProviderUnset), config.IdentityProviderUnset)
	require.Lenf(t, findingsAbout(unset, "readinessProbe нацелена на :9092"), 1,
		"проба на порту вебхуков при незаявленной посадке не названа:\n%s", strings.Join(unset, "\n"))
	require.Lenf(t, unset, 1, "живость на диагностике — близнец, о ней находок быть не должно:\n%s", strings.Join(unset, "\n"))

	_, own := judgeHooksPosture(t, roster, injectedRender(t, dir, config.IdentityProviderOwn), config.IdentityProviderOwn)
	require.Lenf(t, findingsAbout(own, `readinessProbe нацелена на порт "http-hooks", которого под не объявляет`), 1,
		"проба на несуществующем под own порту не названа:\n%s", strings.Join(own, "\n"))
	require.Lenf(t, own, 1, "находок не о предмете инъекции:\n%s", strings.Join(own, "\n"))
}

func TestHooksPortGate_FindsAProbePathTheDiagnosticsDoesNotServe(t *testing.T) {
	roster := readSurfaceRoster(t)
	dir := chartCopy(t)
	patchInCopy(t, dir, "templates/deployment.yaml", "path: /readyz", "path: /ready")

	_, own := judgeHooksPosture(t, roster, injectedRender(t, dir, config.IdentityProviderOwn), config.IdentityProviderOwn)
	require.Lenf(t, findingsAbout(own, `readinessProbe спрашивает путь "/ready"`), 1,
		"путь вне диагностики не назван:\n%s", strings.Join(own, "\n"))
	require.Lenf(t, own, 1, "находок не о предмете инъекции:\n%s", strings.Join(own, "\n"))
}

func TestHooksPortGate_FindsAHookRuleOutsideItsPostureSwitch(t *testing.T) {
	roster := readSurfaceRoster(t)
	dir := chartCopy(t)
	patchInCopy(t, dir, "templates/prometheusrule.yaml", hookRulesSwitchLine, "{{- if true }}")

	c, own := judgeHooksPosture(t, roster, injectedRender(t, dir, config.IdentityProviderOwn), config.IdentityProviderOwn)
	require.NotZero(t, c.hookRules, "инъекция не вернула правил о хуках под own — судить нечего")
	require.Lenf(t, findingsAbout(own, "звонило бы вечно"), c.hookRules,
		"не каждое правило о хуках под own названо:\n%s", strings.Join(own, "\n"))
	require.Lenf(t, own, c.hookRules, "находок не о предмете инъекции:\n%s", strings.Join(own, "\n"))
}

func TestHooksPortGate_FindsHookRulesNarrowedToExternal(t *testing.T) {
	roster := readSurfaceRoster(t)
	dir := chartCopy(t)
	patchInCopy(t, dir, "templates/prometheusrule.yaml", hookRulesSwitchLine, hookRulesExternalOnly)

	c, unset := judgeHooksPosture(t, roster, injectedRender(t, dir, config.IdentityProviderUnset), config.IdentityProviderUnset)
	require.True(t, c.raised, "предпосылка: при незаявленной посадке процесс слушатель поднимает")
	require.NotZero(t, c.rules, "инъекция беспредметна: правил тревоги в рендере нет вовсе")
	require.Lenf(t, findingsAbout(unset, "тишину работающей двери не видит никто"), 1,
		"правила о хуках, суженные до external, при незаявленной посадке не названы:\n%s",
		strings.Join(unset, "\n"))
	require.Lenf(t, unset, 1, "находок не о предмете инъекции — порт здесь верен:\n%s", strings.Join(unset, "\n"))

	// Близнец — посадка `own`; `external` снята (PRO-Robotech/corelib#30, #424).
	for _, p := range []config.IdentityProvider{config.IdentityProviderOwn} {
		_, twin := judgeHooksPosture(t, roster, injectedRender(t, dir, p), p)
		require.Emptyf(t, twin, "та же копия при посадке %s обязана молчать:\n%s", p, strings.Join(twin, "\n"))
	}
}

func TestHooksPortGate_RefusesAnEmptyInput(t *testing.T) {
	err := hooksPostureInputPresent(nil, nil, nil)
	require.Error(t, err, "пустой вход прошёл предпосылку — «ноль находок» стало бы неотличимо от «ноль прочитанного»")
	for _, want := range []string{"объектов Service", "портов контейнера службы", "HTTP-проб контейнера службы"} {
		require.Containsf(t, err.Error(), want, "отказ предпосылки не называет %q", want)
	}

	require.NoError(t, hooksPostureInputPresent(
		map[string][]namedPort{"kaname": {{name: "grpc", number: "9090"}}},
		[]namedPort{{name: "grpc", number: "9090"}},
		[]probeTarget{{kind: "readinessProbe", path: "/readyz", port: "metrics"}},
	), "близнец: непустой вход предпосылку проходит")
}
