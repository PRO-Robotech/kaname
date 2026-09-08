// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// boot_guard_defaults_injection_test.go — доказательство того, что соседняя
// проба СПОСОБНА упасть, и падает ровно на своём предмете.
//
// ПОЧЕМУ ЭТО ОТДЕЛЬНАЯ ПРОБА. Зелёное на целом чарте о проверке не говорит
// ничего: проверка, потерявшая способность краснеть, на целом чарте выглядит
// точно так же. Различает их только внесённый дефект.
//
// ФОРМА ДОКАЗАТЕЛЬСТВА. Вход берётся НАСТОЯЩИЙ (каталог поставки копируется во
// временный), и каждый случай меняет против целой копии РОВНО ОДИН факт.
//
// КОНТРОЛЬ В ОБРАТНУЮ СТОРОНУ ОБЯЗАТЕЛЕН, и законных близнецов здесь ТРИ, а не
// один: подстановка у ключа, которого страж НЕ судит; пустой контейнер вместо
// значения; и величина, названная ДРУГИМ доменом. Без них проба ловила бы форму
// (`default`), а не существо (`отменяет ли она стража`) — и первый же ложный
// срабат её отключил бы.
//
// ФОРМЫ ПОДСТАНОВКИ ДОКАЗЫВАЮТСЯ ПО ОДНОЙ. Форма, о которой распознаватель не
// знает, не даёт ни красного, ни зелёного — она молчит; поэтому каждая названная
// в шапке соседки форма имеет здесь свой случай, включая ту, ради которой проба
// и заведена: литерал ЗА `include`, в теле именованного шаблона.
package deploy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// substitutedProbeDomain — величина, которую инъекция подставляет вместо
// оператора. Взята НЕЙТРАЛЬНОЙ намеренно: предмет соседней пробы — сам факт
// подстановки, а не то, чьё имя подставлено. Имя платформы здесь было бы
// вторым предметом — и заодно прибавляло бы к остатку, который эта же линия
// снимает.
const substitutedProbeDomain = `"substituted.example.invalid"`

// renameStandTrustDomain меняет ЗНАЧЕНИЕ домена доверия в стендовой накладке,
// не называя прежнего: величина стенда — предмет накладки, а не пробы.
func renameStandTrustDomain(t *testing.T, chartDir, value string) {
	t.Helper()
	const key = "  trustDomain: "
	path := filepath.Join(chartDir, "values.dev.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("фикстура не собрана, стендовая накладка не читается: %v", err)
	}
	lines := strings.Split(string(raw), "\n")
	changed := false
	for i, line := range lines {
		if strings.HasPrefix(line, key) {
			lines[i], changed = key+value, true
			break
		}
	}
	if !changed {
		t.Fatalf("фикстура не собрана: стендовая накладка не называет домен доверия — " +
			"менять нечего, и молчание случая ничего не доказало бы")
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatalf("фикстура не собрана, стендовая накладка не пишется: %v", err)
	}
}

// helperPath / configMapPath — координаты внутри временной копии поставки.
func helperPath(chartDir string) string {
	return filepath.Join(chartDir, templatesDir, "_helpers.tpl")
}

func configMapPath(chartDir string) string {
	return filepath.Join(chartDir, templatesDir, configMapTemplate)
}

// replaceInChartFile меняет во временной копии ровно один фрагмент. Отсутствие
// фрагмента — ОТКАЗ фикстуры, а не тихий пропуск: инъекция, ничего не
// изменившая, доказывала бы молчание на целом чарте.
func replaceInChartFile(t *testing.T, path, old, new string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("фикстура не собрана, %s не читается: %v", filepath.Base(path), err)
	}
	text := string(raw)
	if !strings.Contains(text, old) {
		t.Fatalf("фикстура не собрана: в %s нет фрагмента, который она меняет:\n%s",
			filepath.Base(path), old)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(text, old, new, 1)), 0o600); err != nil {
		t.Fatalf("фикстура не собрана, %s не пишется: %v", filepath.Base(path), err)
	}
}

// TestBootGuardDefaultsInjection — способность соседки упасть и смолчать.
func TestBootGuardDefaultsInjection(t *testing.T) {
	cases := []chartFixtureCase{
		{
			name: "целая_копия_—_молчание",
		},
		{
			name: "умолчание_домена_доверия_вернули_в_помощника_—_находка",
			mutate: func(t *testing.T, chartDir string) {
				replaceInChartFile(t, helperPath(chartDir),
					"{{- $authn.trustDomain -}}",
					"{{- $authn.trustDomain | default "+substitutedProbeDomain+" -}}")
			},
			wantSubstring: "authn.trust-domain",
		},
		{
			name: "подстановка_записана_приставкой_а_не_трубой_—_находка",
			mutate: func(t *testing.T, chartDir string) {
				replaceInChartFile(t, helperPath(chartDir),
					"{{- $authn.trustDomain -}}",
					"{{- default "+substitutedProbeDomain+" $authn.trustDomain -}}")
			},
			wantSubstring: "authn.trust-domain",
		},
		{
			name: "подстановка_стоит_в_самом_месте_ключа_а_не_за_include_—_находка",
			mutate: func(t *testing.T, chartDir string) {
				replaceInChartFile(t, configMapPath(chartDir),
					`trust-domain: {{ . | quote }}`,
					"trust-domain: {{ .Values.authn.trustDomain | default "+
						substitutedProbeDomain+" | quote }}")
			},
			wantSubstring: "authn.trust-domain",
		},
		{
			name: "подстановка_у_соседнего_судимого_ключа_—_находка",
			mutate: func(t *testing.T, chartDir string) {
				replaceInChartFile(t, configMapPath(chartDir),
					"identity-provider: {{ . | quote }}",
					`identity-provider: {{ default "external" . | quote }}`)
			},
			wantSubstring: "authn.identity-provider",
		},
		{
			name: "подстановка_у_ключа_которого_страж_НЕ_судит_—_молчание",
			mutate: func(t *testing.T, chartDir string) {
				replaceInChartFile(t, configMapPath(chartDir),
					`graceful-shutdown: {{ default "10s" .Values.apiServer.gracefulShutdown | quote }}`,
					`graceful-shutdown: {{ default "30s" .Values.apiServer.gracefulShutdown | quote }}`)
			},
		},
		{
			name: "пустой_контейнер_вместо_значения_—_молчание",
			mutate: func(t *testing.T, chartDir string) {
				replaceInChartFile(t, helperPath(chartDir),
					"{{- $authn.trustDomain -}}",
					"{{- $authn.trustDomain | default list -}}")
			},
		},
		{
			name: "домен_назван_ДРУГИМ_доменом_в_накладке_—_молчание",
			mutate: func(t *testing.T, chartDir string) {
				renameStandTrustDomain(t, chartDir, `"trust.example.invalid"`)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chartDir := copyChartDeliveryFixture(t)
			if tc.mutate != nil {
				tc.mutate(t, chartDir)
			}
			findings, census, err := auditBootGuardDefaults(chartDir)
			if err != nil {
				t.Fatalf("обход отказал там, где обязан был вынести вердикт: %v", err)
			}
			joined := strings.Join(findings, "\n")
			if tc.wantSubstring == "" {
				if len(findings) > 0 {
					t.Fatalf("проба заговорила на законном входе:\n%s\n\n%s", joined, census)
				}
				t.Logf("молчание подтверждено · %s", census)
				return
			}
			if len(findings) == 0 {
				t.Fatalf("проба смолчала на внесённом дефекте — она его НЕ ЛОВИТ\n\n%s", census)
			}
			if !strings.Contains(joined, tc.wantSubstring) {
				t.Fatalf("проба заговорила, но НЕ НАЗВАЛА координату %q:\n%s", tc.wantSubstring, joined)
			}
			t.Logf("находка подтверждена: %s", strings.SplitN(joined, "\n", 2)[0])
		})
	}
}

// TestBootGuardDefaultsEmptyTraversalIsNotGreen — пустой обход даёт ОТКАЗ, а не
// молчание. Без этого «ноль находок» было бы неотличимо от «ноль прочитанного»,
// и проба, потерявшая свой предмет, выглядела бы исправной.
func TestBootGuardDefaultsEmptyTraversalIsNotGreen(t *testing.T) {
	t.Run("шаблоны_без_файла_настроек", func(t *testing.T) {
		chartDir := copyChartDeliveryFixture(t)
		replaceInChartFile(t, configMapPath(chartDir), settingsBlockAnchor, "config-yaml-not-here: |")

		_, _, err := auditBootGuardDefaults(chartDir)
		if err == nil {
			t.Fatal("обход без единого ключа файла настроек обязан ОТКАЗАТЬ, а не смолчать")
		}
		t.Logf("отказ подтверждён: %v", err)
	})

	t.Run("пустой_каталог_шаблонов", func(t *testing.T) {
		chartDir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(chartDir, templatesDir), 0o750); err != nil {
			t.Fatalf("фикстура не собрана: %v", err)
		}
		_, _, err := auditBootGuardDefaults(chartDir)
		if err == nil {
			t.Fatal("обход по пустому каталогу шаблонов обязан ОТКАЗАТЬ, а не смолчать")
		}
		t.Logf("отказ подтверждён: %v", err)
	})
}
