// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_lane_knobs_declared_injection_test.go — доказательство того, что соседняя
// проба СПОСОБНА упасть, и падает ровно на своём предмете.
//
// Вход берётся НАСТОЯЩИЙ (каталог поставки копируется во временный), каждый
// случай меняет против целой копии РОВНО ОДИН факт. Обе стороны паритета имеют
// свой дефект и свой законный близнец: снятый ключ полосы — находка, а ключ,
// переведённый на подачу секретом, — молчание; лишний ключ в блоке полосы —
// находка, а лишний ключ вне полосы — молчание (его судят другие пробы).
package deploy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dropRenderedLines снимает из шаблона карты настроек строку ключа вместе с её
// ветвью: три строки `{{- with … }}` / `ключ: …` / `{{- end }}`.
func dropRenderedLines(t *testing.T, chartDir string, lines ...string) {
	t.Helper()
	raw := readChartFile(t, chartDir, filepath.Join(templatesDir, configMapTemplate))
	body := raw
	for _, l := range lines {
		body = replaceOnceIn(t, body, l+"\n", "")
	}
	writeChartFile(t, chartDir, filepath.Join(templatesDir, configMapTemplate), body)
}

// appendSecretToProdProfile объявляет переменную приезжающей из объекта Secret в
// боевом профиле — законный второй путь подачи.
func appendSecretToProdProfile(t *testing.T, chartDir, env string) {
	t.Helper()
	path := filepath.Join(chartDir, "values.prod.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("фикстура не собрана, боевой профиль не читается: %v", err)
	}
	const anchor = "secrets:\n"
	text := string(raw)
	if !strings.Contains(text, anchor) {
		t.Fatalf("фикстура не собрана: боевой профиль не несёт карты `secrets`")
	}
	text = strings.Replace(text, anchor,
		anchor+"  "+env+":\n    secretName: injected\n    secretKey: injected\n", 1)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("фикстура не собрана, боевой профиль не пишется: %v", err)
	}
}

func TestOwnLaneKnobsDeclaredInjection(t *testing.T) {
	runChartFixtureCases(t, []chartFixtureCase{
		{
			// Положительный контроль: без него всё ниже зеленело бы на входе,
			// который проба вообще не читает.
			name:   "целая копия — молчание",
			mutate: func(*testing.T, string) {},
		},
		{
			name: "срок кода восстановления снят с шаблона — находка с ключом и переменной",
			mutate: func(t *testing.T, chartDir string) {
				dropRenderedLines(t, chartDir,
					"        {{- with .recoveryCodeTtl }}",
					"        recovery-code-ttl: {{ . | quote }}",
					"        {{- end }}")
			},
			wantSubstring: "authn.login.recovery-code-ttl (KANAME_AUTHN__LOGIN__RECOVERY_CODE_TTL)",
		},
		{
			name: "предел темпа регистрации снят с шаблона — находка",
			mutate: func(t *testing.T, chartDir string) {
				dropRenderedLines(t, chartDir,
					`        {{- if hasKey . "admissionsPerWindow" }}`,
					"        admissions-per-window: {{ int64 .admissionsPerWindow }}",
					"        {{- end }}")
			},
			wantSubstring: "authn.registration.admissions-per-window",
		},
		{
			name: "секрет второго фактора снят с боевого профиля — находка",
			mutate: func(t *testing.T, chartDir string) {
				raw := readChartFile(t, chartDir, "values.prod.yaml")
				body := replaceOnceIn(t, raw, "  KANAME_SECOND_FACTOR_ENC_KEY:", "  KANAME_SECOND_FACTOR_ENC_KEY_RETIRED:")
				writeChartFile(t, chartDir, "values.prod.yaml", body)
			},
			wantSubstring: "authn.second-factor-encryption-key-hex (KANAME_SECOND_FACTOR_ENC_KEY)",
		},
		{
			// Законный близнец первой стороны: величина, снятая с файла настроек,
			// но объявленная секретом, — объявлена, и проба обязана молчать.
			name: "окно свежести переведено с файла на секрет — молчание",
			mutate: func(t *testing.T, chartDir string) {
				dropRenderedLines(t, chartDir,
					"      {{- with $authn.selfServiceFreshness }}",
					"      self-service-freshness: {{ . | quote }}",
					"      {{- end }}")
				appendSecretToProdProfile(t, chartDir, "KANAME_AUTHN__SELF_SERVICE_FRESHNESS")
			},
		},
		{
			name: "в блоке полосы появился ключ без читателя — находка с координатой",
			mutate: func(t *testing.T, chartDir string) {
				raw := readChartFile(t, chartDir, filepath.Join(templatesDir, configMapTemplate))
				body := replaceOnceIn(t, raw,
					"        recovery-code-ttl: {{ . | quote }}\n",
					"        recovery-code-ttl: {{ . | quote }}\n        recovery-code-grace: {{ . | quote }}\n")
				writeChartFile(t, chartDir, filepath.Join(templatesDir, configMapTemplate), body)
			},
			wantSubstring: "authn.login.recovery-code-grace",
		},
		{
			// Законный близнец второй стороны: ключ ВНЕ блоков полосы этой пробе
			// не принадлежит — его судят перепись переложения и проба секций.
			name: "лишний ключ вне блоков полосы — молчание",
			mutate: func(t *testing.T, chartDir string) {
				raw := readChartFile(t, chartDir, filepath.Join(templatesDir, configMapTemplate))
				body := replaceOnceIn(t, raw,
					`      graceful-shutdown: {{ default "10s" .Values.apiServer.gracefulShutdown | quote }}`+"\n",
					`      graceful-shutdown: {{ default "10s" .Values.apiServer.gracefulShutdown | quote }}`+"\n"+
						`      graceful-grace: {{ default "1s" .Values.apiServer.gracefulGrace | quote }}`+"\n")
				writeChartFile(t, chartDir, filepath.Join(templatesDir, configMapTemplate), body)
			},
		},
	}, auditOwnLaneKnobsDeclared, configMapTemplate)
}

// TestOwnLaneKnobsDeclaredEmptyTraversalIsNotGreen — пустой обход даёт ОТКАЗ, а
// не молчание: «ноль находок» обязано быть отличимо от «ноль прочитанного».
func TestOwnLaneKnobsDeclaredEmptyTraversalIsNotGreen(t *testing.T) {
	chartDir := copyChartDeliveryFixture(t)
	replaceInChartFile(t, configMapPath(chartDir), settingsBlockAnchor, "config-yaml-not-here: |")

	_, _, err := auditOwnLaneKnobsDeclared(chartDir)
	if err == nil {
		t.Fatal("обход без единого ключа файла настроек обязан ОТКАЗАТЬ, а не смолчать")
	}
	t.Logf("отказ подтверждён: %v", err)
}
