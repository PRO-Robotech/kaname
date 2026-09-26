// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// posture_knob_has_one_address_injection_test.go — СПОСОБНОСТЬ суда над
// тенями ручек стража упасть, доказанная инъекцией в обе стороны (задача #392).
//
// Вывод источников окружения пода: карта, чей ключ становится `name:`
// переменной, — источник в КАЖДОЙ законной форме адреса и ссылки на ключ
// (перечень `lawfulPodEnvSourceForms`); та же карта, чей ключ уходит в другое
// поле, в комментарии либо в перечне портов, — нет; адрес, который
// распознаватель не выводит, — отказ с координатой, а не пропуск. Перечень
// стража: пара литералов словаря внутри стража — строка; тот же литерал вне
// стража — нет.
//
// Настоящий вход — на копии чарта: строка, выпавшая из перечня стража;
// источник, выпавший из обхода стража; новый источник формой `$.Values.` и в
// скобках (опыты 392e и 392f проверяющего) и законный близнец — прежние env и
// secrets формой `$.Values.` (392g).
package deploy_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// envRangeOf — источник окружения в том виде, в каком его пишет шаблон
// развёртывания: заголовок `range` и тело, где ключ становится именем.
func envRangeOf(head, name string) string {
	return "        {{- range " + head + " }}\n" +
		"        " + name + "\n" +
		"          value: {{ $v | quote }}\n" +
		"        {{- end }}\n"
}

// lawfulPodEnvSourceForms — КАЖДАЯ законная форма, которой шаблон даёт
// переменной окружения пода имя из ключа карты значений. Две оси: АДРЕС карты
// в выражении `range` и ССЫЛКА на ключ в теле. Каждая форма — отдельный вход, и
// распознаватель обязан назвать её источник (правило
// recognizer-knows-all-lawful-forms: форма вне наблюдения молчит).
var lawfulPodEnvSourceForms = []struct {
	form string
	src  string
	want []string
}{
	{"адрес: поле от точки корня", envRangeOf(`$k, $v := .Values.extraEnv`, `- name: {{ $k }}`), []string{"extraEnv"}},
	{"адрес: от переменной корня $", envRangeOf(`$k, $v := $.Values.extraEnv`, `- name: {{ $k }}`), []string{"extraEnv"}},
	{"адрес: в скобках", envRangeOf(`$k, $v := (.Values.extraEnv)`, `- name: {{ $k }}`), []string{"extraEnv"}},
	{"адрес: в двойных скобках от $", envRangeOf(`$k, $v := ( ( $.Values.extraEnv ) )`, `- name: {{ $k }}`), []string{"extraEnv"}},
	{"адрес: поле цепочки", envRangeOf(`$k, $v := (.Values).extraEnv`, `- name: {{ $k }}`), []string{"extraEnv"}},
	{"адрес: index от точки", envRangeOf(`$k, $v := index .Values "extraEnv"`, `- name: {{ $k }}`), []string{"extraEnv"}},
	{"адрес: index от $ вглубь", envRangeOf(`$k, $v := index $.Values "pod" "env"`, `- name: {{ $k }}`), []string{"pod.env"}},
	{"адрес: get", envRangeOf(`$k, $v := get $.Values "extraEnv"`, `- name: {{ $k }}`), []string{"extraEnv"}},
	{"адрес: вложенный путь", envRangeOf(`$k, $v := .Values.pod.env`, `- name: {{ $k }}`), []string{"pod.env"}},
	{"адрес: умолчание конвейером", envRangeOf(`$k, $v := .Values.extraEnv | default dict`, `- name: {{ $k }}`), []string{"extraEnv"}},
	{"адрес: умолчание вызовом", envRangeOf(`$k, $v := default (dict) $.Values.extraEnv`, `- name: {{ $k }}`), []string{"extraEnv"}},
	{"адрес: умолчание другой картой", envRangeOf(`$k, $v := default .Values.baseEnv .Values.extraEnv`, `- name: {{ $k }}`),
		[]string{"baseEnv", "extraEnv"}},
	{"адрес: переменная карты",
		"{{- $extra := .Values.extraEnv | default dict }}\n" + envRangeOf(`$k, $v := $extra`, `- name: {{ $k }}`), []string{"extraEnv"}},
	{"адрес: переменная точки корня",
		"{{- $root := . }}\n" + envRangeOf(`$k, $v := $root.Values.extraEnv`, `- name: {{ $k }}`), []string{"extraEnv"}},
	{"адрес: переменная, присвоенная $",
		"{{- $top := $ }}\n" + envRangeOf(`$k, $v := $top.Values.extraEnv`, `- name: {{ $k }}`), []string{"extraEnv"}},
	{"адрес: переприсвоенная переменная — обе карты",
		"{{- $m := .Values.baseEnv }}\n{{- if .Values.flag }}{{- $m = .Values.extraEnv }}{{- end }}\n" +
			envRangeOf(`$k, $v := $m`, `- name: {{ $k }}`), []string{"baseEnv", "extraEnv"}},
	{"адрес: точка внутри with",
		"{{- with .Values.extraEnv }}\n" + envRangeOf(`$k, $v := .`, `- name: {{ $k }}`) + "{{- end }}\n", []string{"extraEnv"}},
	{"адрес: поле точки внутри with",
		"{{- with $.Values }}\n" + envRangeOf(`$k, $v := .extraEnv`, `- name: {{ $k }}`) + "{{- end }}\n", []string{"extraEnv"}},
	{"адрес: переменная with",
		"{{- with $x := .Values.extraEnv }}\n" + envRangeOf(`$k, $v := $x`, `- name: {{ $k }}`) + "{{- end }}\n", []string{"extraEnv"}},
	{"адрес: внутри if и else",
		"{{- if .Values.flag }}\n" + envRangeOf(`$k, $v := .Values.extraEnv`, `- name: {{ $k }}`) +
			"{{- else }}\n" + envRangeOf(`$k, $v := $.Values.otherEnv`, `- name: {{ $k }}`) + "{{- end }}\n",
		[]string{"extraEnv", "otherEnv"}},
	{"ключ: своё имя переменной", envRangeOf(`$envName, $v := .Values.extraEnv`, `- name: {{ $envName }}`), []string{"extraEnv"}},
	{"ключ: конвейером quote", envRangeOf(`$k, $v := .Values.extraEnv`, `- name: {{ $k | quote }}`), []string{"extraEnv"}},
	{"ключ: вызовом quote", envRangeOf(`$k, $v := .Values.extraEnv`, `- name: {{ quote $k }}`), []string{"extraEnv"}},
	{"ключ: через printf", envRangeOf(`$k, $v := .Values.extraEnv`, `- name: {{ printf "%s" $k }}`), []string{"extraEnv"}},
	{"ключ: в кавычках текста", envRangeOf(`$k, $v := .Values.extraEnv`, `- name: "{{ $k }}"`), []string{"extraEnv"}},
	{"ключ: name не первым полем",
		"        {{- range $k, $v := .Values.extraEnv }}\n        - value: {{ $v | quote }}\n          name: {{ $k }}\n        {{- end }}\n",
		[]string{"extraEnv"}},
	{"ключ: под условием в теле",
		"        {{- range $k, $v := .Values.extraEnv }}\n        {{- if $v }}\n        - name: {{ $k }}\n        {{- end }}\n        {{- end }}\n",
		[]string{"extraEnv"}},
}

func TestPostureShadowInjection_PodEnvSourcesKnowEveryLawfulForm(t *testing.T) {
	for _, f := range lawfulPodEnvSourceForms {
		t.Run(f.form, func(t *testing.T) {
			got, err := podEnvSources(f.src)
			require.NoErrorf(t, err, "законная форма отвергнута:\n%s", f.src)
			require.Equalf(t, f.want, got, "законная форма источника окружения не выведена:\n%s", f.src)
		})
	}

	const src = `spec:
  containers:
    - env:
        - name: KANAME_CONFIG_PATH
          value: /etc/kaname/config.yaml
        {{- range $k, $v := .Values.env }}
        - name: {{ $k }}
          value: {{ $v | quote }}
        {{- end }}
        {{- range $k, $v := .Values.secrets }}
        # ссылкой, а не значением
        - name: {{ $k }}
          valueFrom:
            secretKeyRef:
              name: {{ $v.secretName | quote }}
        {{- end }}
        {{- range $name, $v := .Values.extraEnv }}
        - name: {{ $name }}
        {{- end }}
        {{- range $k, $v := $.Values.env }}
        - name: {{ $k }}
        {{- end }}
`
	got, err := podEnvSources(src)
	require.NoError(t, err)
	require.Equal(t, []string{"env", "extraEnv", "secrets"}, got,
		"законные формы источника окружения не выведены, либо один источник назван дважды")
	t.Logf("перепись: законных форм %d, каждая назвала свой источник", len(lawfulPodEnvSourceForms))
}

func TestPostureShadowInjection_PodEnvSourceTwinsAreSilent(t *testing.T) {
	const twins = `{{/* {{- range $k, $v := .Values.commented }}
- name: {{ $k }} */}}
{{- range $k, $v := .Values.labels }}
  {{ $k }}: {{ $v | quote }}
{{- end }}
{{- range $i, $p := .Values.ports }}
- containerPort: {{ $i }}
{{- end }}
{{- range $k, $v := .Values.annotations }}
- name: {{ $v }}
{{- end }}
{{- range $k, $v := .Values.valueOnly }}
- name: FIXED
  value: {{ $k }}
{{- end }}
{{- range $k, $v := dict "KANAME_FIXED" "x" }}
- name: {{ $k }}
{{- end }}
`
	got, err := podEnvSources(twins)
	require.NoError(t, err)
	require.Empty(t, got, "близнец назван источником окружения: ключ карты значений не становится именем переменной")
}

// TestPostureShadowInjection_UnknownSourceAddressIsRefusedNotSkipped — форма,
// чей адрес распознаватель не выводит, — ОТКАЗ с координатой, а не пропуск:
// пропуск и был дефектом (#392, опыты 392e и 392f проверяющего).
func TestPostureShadowInjection_UnknownSourceAddressIsRefusedNotSkipped(t *testing.T) {
	cases := []struct {
		form string
		src  string
	}{
		{"карта из вызова шаблона", envRangeOf(`$k, $v := include "kaname-svc.extraEnv" . | fromYaml`, `- name: {{ $k }}`)},
		{"слияние карт", envRangeOf(`$k, $v := merge (dict) .Values.baseEnv .Values.extraEnv`, `- name: {{ $k }}`)},
		{"весь корень значений", envRangeOf(`$k, $v := .Values`, `- name: {{ $k }}`)},
		{"адрес вне значений", envRangeOf(`$k, $v := .Release`, `- name: {{ $k }}`)},
		{"точка — элемент внешнего range",
			"{{- range .Values.containers }}\n" + envRangeOf(`$k, $v := .Values.extraEnv`, `- name: {{ $k }}`) + "{{- end }}\n"},
		{"$ внутри define", "{{- define \"x\" }}\n" + envRangeOf(`$k, $v := $.Values.extraEnv`, `- name: {{ $k }}`) + "{{- end }}\n"},
		{"переменная элемента", "{{- range $g := .Values.groups }}\n" + envRangeOf(`$k, $v := $g`, `- name: {{ $k }}`) + "{{- end }}\n"},
	}
	for _, c := range cases {
		t.Run(c.form, func(t *testing.T) {
			got, err := podEnvSources("# пролог\n" + c.src)
			require.Errorf(t, err, "незнакомый адрес источника пропущен молча, выведено %v:\n%s", got, c.src)
			require.Contains(t, err.Error(), "адрес карты распознаватель не выводит")
			require.Regexp(t, `:\d+:\d+`, err.Error(), "отказ без координаты")
		})
	}
}

// envRangeInTheTree — карта env в шаблоне развёртывания дерева: за ней в копию
// вставляется новый источник, как его вставлял проверяющий (392e, 392f).
const envRangeInTheTree = `            {{- range $k, $v := .Values.env }}
            - name: {{ $k }}
              value: {{ $v | quote }}
            {{- end }}
`

// TestPostureShadowInjection_NewSourceInEveryLawfulFormIsJudged — настоящий
// вход: новый источник `extraEnv` в копии чарта, записанный формой проверяющего.
// До починки обе формы молчали: перепись 2, находок 0, а рендер с
// `extraEnv.KANAME_AUTHN__CLIENT_TOKEN__ENABLED=false` клал переменную в под.
func TestPostureShadowInjection_NewSourceInEveryLawfulFormIsJudged(t *testing.T) {
	for _, head := range []string{`$k, $v := $.Values.extraEnv`, `$k, $v := (.Values.extraEnv)`} {
		t.Run(head, func(t *testing.T) {
			dir := chartCopy(t)
			patchInCopy(t, dir, filepath.Join("templates", "deployment.yaml"), envRangeInTheTree,
				envRangeInTheTree+"            {{- range "+head+" }}\n            - name: {{ $k }}\n"+
					"              value: {{ $v | quote }}\n            {{- end }}\n")
			drift, sources, _ := judgePostureGuardRoster(t, filepath.Join(dir, "templates"))
			require.Empty(t, drift)
			require.Equal(t, []string{"env", "extraEnv", "secrets"}, sources, "новый источник не выведен обходом")

			got, n := postureShadowFindings(t, dir)
			rows := postureGuardRows(t)
			var own, foreign []string
			for _, f := range got {
				if strings.HasPrefix(f, "extraEnv") {
					own = append(own, f)
					continue
				}
				foreign = append(foreign, f)
			}
			require.Emptyf(t, foreign, "находка пришла и от неиспорченного источника:\n%s", strings.Join(foreign, "\n"))
			require.Lenf(t, own, len(rows)+1, "не каждая ручка в новом источнике найдена:\n%s", strings.Join(got, "\n"))
			for _, r := range rows {
				require.Contains(t, strings.Join(own, "\n"), "extraEnv."+r.env+": рендер прошёл")
			}
			t.Logf("перепись: рендеров %d · находок %d", n, len(got))
		})
	}
}

// TestPostureShadowInjection_ExistingSourcesFromTheRootAreTheSameTwo — законный
// близнец настоящим входом (392g): те же env и secrets формой `$.Values.` —
// перепись 2 и молчание, а не «обход пуст».
func TestPostureShadowInjection_ExistingSourcesFromTheRootAreTheSameTwo(t *testing.T) {
	dir := chartCopy(t)
	rel := filepath.Join("templates", "deployment.yaml")
	patchInCopy(t, dir, rel, `{{- range $k, $v := .Values.env }}`, `{{- range $k, $v := $.Values.env }}`)
	patchInCopy(t, dir, rel, `{{- range $k, $v := .Values.secrets }}`, `{{- range $k, $v := $.Values.secrets }}`)
	drift, sources, _ := judgePostureGuardRoster(t, filepath.Join(dir, "templates"))
	require.Empty(t, drift)
	require.Equal(t, []string{"env", "secrets"}, sources)

	got, n := postureShadowFindings(t, dir)
	require.Emptyf(t, got, "законная перезапись источников дала находки:\n%s", strings.Join(got, "\n"))
	t.Logf("перепись: рендеров %d · находок 0", n)
}

func TestPostureShadowInjection_GuardRosterIsReadInsideTheGuardOnly(t *testing.T) {
	const src = `{{- define "other" -}}
{{- $x := dict "KANAME_OUTSIDE" "a.b" -}}
{{- end -}}
{{- define "kaname-svc.requireClientTokenEndpoint" -}}
{{- $canon := dict
      "KANAME_AUTHN__IDENTITY_PROVIDER" "authn.identityProvider"
      "KANAME_AUTHN__CLIENT_TOKEN__ENABLED" "authn.clientToken.enabled" -}}
{{- if $x }}{{ fail "KANAME_IN_TEXT is not a pair" }}{{ end -}}
{{- end -}}
{{- $y := dict "KANAME_AFTER" "c.d" -}}
`
	got, err := guardEnvRoster(src)
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"KANAME_AUTHN__IDENTITY_PROVIDER":     "authn.identityProvider",
		"KANAME_AUTHN__CLIENT_TOKEN__ENABLED": "authn.clientToken.enabled",
	}, got, "перечень стража прочитан не из стража либо не парами")
}

// TestPostureShadowInjection_RosterRowDroppedIsFound — настоящий вход: из
// перечня стража в копии чарта выпала ручка посадки.
func TestPostureShadowInjection_RosterRowDroppedIsFound(t *testing.T) {
	dir := chartCopy(t)
	control, _, _ := judgePostureGuardRoster(t, filepath.Join(dir, "templates"))
	require.Empty(t, control, "контроль: копия настоящего дерева обязана сходиться с таблицей")

	dropLineInCopy(t, dir, filepath.Join("templates", "_helpers.tpl"), `"KANAME_AUTHN__IDENTITY_PROVIDER" "authn.identityProvider"`)
	got, _, _ := judgePostureGuardRoster(t, filepath.Join(dir, "templates"))
	require.Len(t, got, 1, strings.Join(got, "\n"))
	require.Contains(t, got[0], "KANAME_AUTHN__IDENTITY_PROVIDER")
	require.Contains(t, got[0], identityProviderKnob)
}

// TestPostureShadowInjection_SourceDroppedFromTheGuardIsFound — настоящий
// вход рендер-суда: страж в копии чарта перестал обходить `secrets`.
func TestPostureShadowInjection_SourceDroppedFromTheGuardIsFound(t *testing.T) {
	dir := chartCopy(t)
	patchInCopy(t, dir, filepath.Join("templates", "_helpers.tpl"),
		`{{- range $source := list "env" "secrets" -}}`, `{{- range $source := list "env" -}}`)
	got, n := postureShadowFindings(t, dir)
	joined := strings.Join(got, "\n")
	require.NotEmpty(t, got, "источник окружения, выпавший из стража, прошёл рендер-суд")
	require.Contains(t, joined, "secrets.KANAME_AUTHN__IDENTITY_PROVIDER: рендер прошёл")
	require.NotContains(t, joined, "env.KANAME_AUTHN__IDENTITY_PROVIDER: рендер прошёл",
		"находка пришла и от неиспорченного источника — инъекция уронила не только свой предмет")
	t.Logf("перепись: рендеров инъекции %d · находок %d", n, len(got))
}
