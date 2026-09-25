// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// block_switch_is_boolean_injection_test.go — СПОСОБНОСТЬ суда над
// выключателями упасть, доказанная инъекцией в обе стороны (задача #391).
//
// Каждая законная форма чтения выключателя мимо правила — находка с
// координатой; законный близнец той же формы (комментарий, текст литерала,
// YAML вне действия, соседнее имя поля, чтение внутри самого правила) —
// молчание. Предпосылки судятся отдельно от находок: пустой обход, отсутствие
// правила, правило, не читающее выключатель, — отказ, а не «ноль находок».
//
// Инъекции настоящим входом — на копии дерева: вызов правила, возвращённый к
// чтению поля, и правило, возвращённое к истинности.
package deploy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// syntheticRule — правило в той же форме, что в дереве: читает выключатель
// своими формами, и эти чтения находками не являются.
const syntheticRule = `{{- define "kaname-svc.blockEnabled" -}}
{{- $cur := (index . 0).Values -}}
{{- if and (kindIs "map" $cur) (hasKey $cur "enabled") -}}{{ index $cur "enabled" }}{{- end -}}
{{- end -}}
`

// judgeSynthetic пишет шаблоны в каталог и судит его.
func judgeSynthetic(t *testing.T, files map[string]string) switchCensus {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}
	c, err := judgeBlockSwitchTemplates(dir)
	require.NoError(t, err)
	return c
}

// withRule — синтетический каталог, в котором предпосылки выполнены: правило
// определено и вызвано; проверяемое добавляется отдельным файлом.
func withRule(probe string) map[string]string {
	return map[string]string{
		"_helpers.tpl": syntheticRule,
		"call.yaml":    "{{- if include \"kaname-svc.blockEnabled\" (list $ \"authn.tokenSigning\") }}\nk: v\n{{- end }}\n",
		"probe.yaml":   probe,
	}
}

func TestBlockSwitchInjection_EveryLawfulReadFormIsFound(t *testing.T) {
	cases := []struct {
		name  string
		probe string
		line  int
	}{
		{"поле у переменной", "a: 1\n{{- if $ts.enabled }}\nb: 2\n{{- end }}\n", 2},
		{"поле у .Values", "{{- if .Values.alertRules.enabled }}\n{{- end }}\n", 1},
		{"поле у точки внутри with", "{{- with .Values.metricsScrape }}\n{{- if .enabled }}{{ end }}\n{{- end }}\n", 2},
		{"поле у скобки", "{{- if (.Values.a).enabled }}{{ end }}\n", 1},
		{"поле внутри and/not", "{{- if and $posture (not $ct.enabled) -}}{{ end }}\n", 1},
		{"многострочное действие", "{{- if and\n    $a\n    $x.enabled }}{{ end }}\n", 3},
		{"ключ через index", "{{- if (index $x \"enabled\") }}{{ end }}\n", 1},
		{"ключ через get", "{{- if get $x \"enabled\" }}{{ end }}\n", 1},
		{"ключ через hasKey", "{{- if hasKey $x \"enabled\" }}{{ end }}\n", 1},
		{"ключ через dig", "{{- if dig \"a\" \"enabled\" false .Values }}{{ end }}\n", 1},
		{"ключ через pluck", "{{- $_ := pluck \"enabled\" $x }}\n", 1},
		{"ключ через set", "{{- $_ := set $x \"enabled\" true }}\n", 1},
		{"ключ сырым литералом", "{{- if index $x `enabled` }}{{ end }}\n", 1},
		{"путь-литерал", "{{- if include \"other.path\" (list $ \"a.b.enabled\") }}{{ end }}\n", 1},
		{"с маркерами обрезки", "{{- if $x.enabled -}}{{- end -}}\n", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := judgeSynthetic(t, withRule(c.probe))
			require.Empty(t, got.premise, "предпосылка синтетики не выполнена — инъекция судила бы не то")
			require.Lenf(t, got.findings, 1, "форма %q: ожидалась ровно одна находка:\n%s", c.name, strings.Join(got.findings, "\n"))
			require.Containsf(t, got.findings[0], fmt.Sprintf("probe.yaml:%d:", c.line),
				"находка не называет координату чтения:\n%s", got.findings[0])
			require.Contains(t, got.findings[0], blockSwitchRule, "находка не называет, чем читать")
		})
	}
	t.Logf("перепись: законных форм чтения %d · каждая — ровно одна находка с координатой", len(cases))
}

func TestBlockSwitchInjection_LawfulTwinsAreSilent(t *testing.T) {
	cases := []struct{ name, probe string }{
		{"комментарий", "{{/* $x.enabled и \"enabled\" */}}\n{{- /* .Values.a.enabled */ -}}\n"},
		{"многострочный комментарий с }} внутри", "{{/*\n  {{ $labels.x }} $x.enabled\n*/}}\n"},
		{"текст литерала", "{{- fail \"задайте authn.clientToken.enabled=true и .enabled\" }}\n"},
		{"}} внутри литерала", "{{- $m := \"x }} $y.enabled\" }}\n"},
		{"YAML вне действия", "token-signing:\n  enabled: true\n"},
		{"соседнее имя поля", "{{- if $x.enabledBy }}{{ end }}{{ if $x.enabled_count }}{{ end }}\n"},
		{"экранированный разделитель", "v: {{ \"{{\" }} $labels.enabled {{ \"}}\" }}\n"},
		{"вызов правила", "{{- if not (include \"kaname-svc.blockEnabled\" (list $ \"metricsScrape\")) }}{{ end }}\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := judgeSynthetic(t, withRule(c.probe))
			require.Empty(t, got.premise)
			require.Emptyf(t, got.findings, "законный близнец назван находкой — гейт краснел бы на верном дереве:\n%s",
				strings.Join(got.findings, "\n"))
		})
	}

	got := judgeSynthetic(t, withRule(cases[len(cases)-1].probe))
	var coords []string
	for _, cl := range got.calls {
		coords = append(coords, cl.coord)
	}
	require.ElementsMatch(t, []string{"authn.tokenSigning", "metricsScrape"}, coords,
		"канонические вызовы не дали своих координат — популяция из шаблонов не выводится")
	require.Equal(t, 2, got.ruleReads, "собственные чтения правила не учтены как его чтения")
	t.Logf("перепись: близнецов %d · находок 0", len(cases))
}

func TestBlockSwitchInjection_NonCanonicalCallIsFound(t *testing.T) {
	for _, probe := range []string{
		"{{- if include \"kaname-svc.blockEnabled\" $x }}{{ end }}\n",
		"{{- if include \"kaname-svc.blockEnabled\" (list . \"a\") }}{{ end }}\n",
		"{{- if include \"kaname-svc.blockEnabled\" (list $ $coord) }}{{ end }}\n",
		"{{ template \"kaname-svc.blockEnabled\" (list $ \"a\") }}\n",
	} {
		got := judgeSynthetic(t, withRule(probe))
		require.Lenf(t, got.findings, 1, "вызов %q не назван находкой", probe)
		require.Contains(t, got.findings[0], "probe.yaml:1:")
		require.Contains(t, got.findings[0], "не в канонической форме")
	}

	got := judgeSynthetic(t, withRule("{{- if include \"kaname-svc.blockEnabled\" (list $ \"Not-A.path\") }}{{ end }}\n"))
	require.Len(t, got.findings, 1, "координата не той формы принята")
	require.Contains(t, got.findings[0], "не путь ключей значений")
}

func TestBlockSwitchInjection_PremiseIsJudgedApartFromFindings(t *testing.T) {
	t.Run("пустой обход", func(t *testing.T) {
		got := judgeSynthetic(t, map[string]string{})
		require.NotEmpty(t, got.premise)
		require.Contains(t, strings.Join(got.premise, "\n"), "обход шаблонов")
	})
	t.Run("правила нет", func(t *testing.T) {
		got := judgeSynthetic(t, map[string]string{"x.yaml": "k: v\n{{ .Values.a }}\n"})
		require.Contains(t, strings.Join(got.premise, "\n"), "определено 0 раз")
	})
	t.Run("правило дважды", func(t *testing.T) {
		files := withRule("")
		files["_second.tpl"] = syntheticRule
		got := judgeSynthetic(t, files)
		require.Contains(t, strings.Join(got.premise, "\n"), "определено 2 раз")
	})
	t.Run("правило не читает выключатель", func(t *testing.T) {
		files := withRule("")
		files["_helpers.tpl"] = "{{- define \"kaname-svc.blockEnabled\" -}}true{{- end -}}\n"
		got := judgeSynthetic(t, files)
		require.Contains(t, strings.Join(got.premise, "\n"), "не читает")
	})
	t.Run("ни одного вызова", func(t *testing.T) {
		got := judgeSynthetic(t, map[string]string{"_helpers.tpl": syntheticRule})
		require.Contains(t, strings.Join(got.premise, "\n"), "ни одного вызова")
	})
	t.Run("шаблон не разобран", func(t *testing.T) {
		got := judgeSynthetic(t, withRule("{{ if $x.enabled \n"))
		require.Len(t, got.findings, 1)
		require.Contains(t, got.findings[0], "probe.yaml: шаблон не разобран")
	})
	t.Run("близнец: всё выполнено", func(t *testing.T) {
		got := judgeSynthetic(t, withRule(""))
		require.Empty(t, got.premise)
		require.Empty(t, got.findings)
	})
}

func TestBlockSwitchInjection_ValuesCensusFindsANonBooleanSwitch(t *testing.T) {
	tree := map[string]any{
		"alertRules": map[string]any{"enabled": true},
		"authn": map[string]any{
			"tokenSigning":        map[string]any{"enabled": false, "issuer": ""},
			"presentedCredential": map[string]any{"enabled": "false"},
			"clientToken":         map[string]any{"enabled": 1},
		},
		"list": []any{map[string]any{"enabled": true}},
		"env":  map[string]any{"KANAME_X_ENABLE": "true"},
	}
	coords, findings := switchesInValues("synthetic.yaml", tree)
	require.Equal(t, []string{"alertRules", "authn.tokenSigning"}, coords, "булевы выключатели не выведены")
	joined := strings.Join(findings, "\n")
	require.Len(t, findings, 3, joined)
	require.Contains(t, joined, "authn.presentedCredential.enabled")
	require.Contains(t, joined, "authn.clientToken.enabled")
	require.Contains(t, joined, "list[0].enabled")
}

// realTemplatesCopy — копия настоящего каталога шаблонов, которую инъекция
// вправе портить.
func realTemplatesCopy(t *testing.T) string {
	t.Helper()
	return filepath.Join(chartCopy(t), "templates")
}

// TestBlockSwitchInjection_RealCallRevertedToFieldIsFound — настоящий вход:
// вызов правила в карте настроек возвращён к чтению поля, как было до #391.
func TestBlockSwitchInjection_RealCallRevertedToFieldIsFound(t *testing.T) {
	dir := realTemplatesCopy(t)
	control, err := judgeBlockSwitchTemplates(dir)
	require.NoError(t, err)
	require.Empty(t, control.findings, "контроль: копия настоящего дерева обязана быть чистой")
	require.Empty(t, control.premise)

	patchInCopy(t, filepath.Dir(dir), filepath.Join("templates", "configmap.yaml"),
		`{{- if include "kaname-svc.blockEnabled" (list $ "authn.tokenSigning") }}`, `{{- if $ts.enabled }}`)
	got, err := judgeBlockSwitchTemplates(dir)
	require.NoError(t, err)
	require.Len(t, got.findings, 1, strings.Join(got.findings, "\n"))
	require.Contains(t, got.findings[0], "configmap.yaml:")
	require.Contains(t, got.findings[0], "$ts.enabled")
	require.Len(t, got.calls, len(control.calls)-1, "вызов не выпал из переписи — инъекция ничего не изменила")
}

// TestBlockSwitchInjection_RuleRevertedToTruthinessIsFound — настоящий вход
// рендер-суда: правило в копии чарта судит истинность, как условие до #391.
func TestBlockSwitchInjection_RuleRevertedToTruthinessIsFound(t *testing.T) {
	dir := chartCopy(t)
	control, n := blockSwitchRenderFindings(t, dir, "alertRules")
	require.Emptyf(t, control, "контроль: неиспорченная копия обязана быть чистой:\n%s", strings.Join(control, "\n"))

	patchInCopy(t, dir, filepath.Join("templates", "_helpers.tpl"),
		`{{- if ne $kind "bool" -}}`, `{{- if and false (ne $kind "bool") -}}`)
	patchInCopy(t, dir, filepath.Join("templates", "_helpers.tpl"),
		`{{- if and (eq $kind "bool") $v }}true{{ end -}}`, `{{- if $v }}true{{ end -}}`)
	got, m := blockSwitchRenderFindings(t, dir, "alertRules")
	joined := strings.Join(got, "\n")
	require.NotEmpty(t, got, "правило, судящее истинность, прошло рендер-суд")
	require.Contains(t, joined, `alertRules.enabled [--set-string false]: рендер прошёл`)
	t.Logf("перепись: рендеров контроля %d · инъекции %d · находок инъекции %d", n, m, len(got))
}
