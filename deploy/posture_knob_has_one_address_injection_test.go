// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// posture_knob_has_one_address_injection_test.go — СПОСОБНОСТЬ суда над
// тенями ручек стража упасть, доказанная инъекцией в обе стороны (задача #392).
//
// Ступень разбора: карта, по чьим ключам проходит шаблон, — кандидат в КАЖДОЙ
// законной форме адреса и ссылки на ключ (перечень `lawfulPodEnvSourceForms`),
// в том числе в define, вызванном через include; проход, чьё тело ключа не
// упоминает, комментарий и постоянная — не кандидаты; адрес, который разбор не
// выводит, — отказ с координатой, а не пропуск. Перечень стража: пара литералов
// словаря внутри стража — строка; тот же литерал вне стража — нет.
//
// Ступень рендера и суд — настоящим входом на копии чарта: строка, выпавшая из
// перечня стража; источник, выпавший из обхода стража; новый источник формой
// `$.Values.` и в скобках (опыты 392e и 392f проверяющего) и каждой формой
// ссылки на ключ и дома источника (392h, 392i, 392j, 392m, 392n, `keys`);
// законные близнецы — прежние env и secrets формой `$.Values.` (392g) и ключ,
// дающий имя не переменной пода, а тому (392o), порту, аннотации пода, значению.
// Кандидат, чей пробный ключ не дошёл до имени переменной при условии
// подтверждающего рендера (392p–392s: источник под посадкой own и external, под
// фильтром ключа и выключателем, одна карта двумя проходами, ветвь и
// присваивание в теле прохода), — находка с источником либо «не подтверждён и не
// опровергнут», а не молчание.
package deploy_test

import (
	"os"
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
	{"ключ: через переменную (392h)",
		"        {{- range $k, $v := .Values.extraEnv }}\n        {{- $envName := $k }}\n        - name: {{ $envName }}\n        {{- end }}\n",
		[]string{"extraEnv"}},
	{"ключ: в элементе из dict и toYaml (392i)",
		"        {{- range $k, $v := .Values.extraEnv }}\n        {{- list (dict \"name\" $k \"value\" (toString $v)) | toYaml | nindent 8 }}\n        {{- end }}\n",
		[]string{"extraEnv"}},
	{"ключ: за приставкой текстом (392j)", envRangeOf(`$k, $v := .Values.extraEnv`, `- name: KANAME_{{ $k }}`), []string{"extraEnv"}},
	{"адрес: карта, положенная в dict через set (392m)",
		"{{- $ctx := dict }}\n{{- $_ := set $ctx \"m\" .Values.extraEnv }}\n" + envRangeOf(`$k, $v := $ctx.m`, `- name: {{ $k }}`),
		[]string{"extraEnv"}},
	{"адрес: поле dict с картой",
		"{{- $ctx := dict \"m\" .Values.extraEnv \"c\" 1 }}\n" + envRangeOf(`$k, $v := $ctx.m`, `- name: {{ $k }}`),
		[]string{"extraEnv"}},
	{"адрес: слияние карт", envRangeOf(`$k, $v := merge (dict) .Values.baseEnv .Values.extraEnv`, `- name: {{ $k }}`),
		[]string{"baseEnv", "extraEnv"}},
	{"адрес: слияние в переменную",
		"{{- $m := dict }}\n{{- $_ := mergeOverwrite $m .Values.extraEnv }}\n" + envRangeOf(`$k, $v := $m`, `- name: {{ $k }}`),
		[]string{"extraEnv"}},
	{"адрес: required", envRangeOf(`$k, $v := required "нужен" .Values.extraEnv`, `- name: {{ $k }}`), []string{"extraEnv"}},
	{"адрес: ternary", envRangeOf(`$k, $v := ternary .Values.baseEnv .Values.extraEnv .Values.flag`, `- name: {{ $k }}`),
		[]string{"baseEnv", "extraEnv"}},
	{"перечень ключей keys",
		"        {{- range $name := keys .Values.extraEnv }}\n        - name: {{ $name }}\n        {{- end }}\n", []string{"extraEnv"}},
	{"перечень ключей keys | sortAlpha с умолчанием",
		"        {{- range $name := keys (.Values.extraEnv | default dict) | sortAlpha }}\n        - name: {{ $name }}\n        {{- end }}\n",
		[]string{"extraEnv"}},
	{"перечень ключей с точкой элемента",
		"        {{- range sortAlpha (keys .Values.extraEnv) }}\n        - name: {{ . }}\n        {{- end }}\n", []string{"extraEnv"}},
}

// lawfulPodEnvSourceHomes — источник в define, вызванном из другого шаблона:
// точка define — аргумент места вызова (392n). Форма вызова — каждая, которой
// шаблон её передаёт.
var lawfulPodEnvSourceHomes = []struct {
	form  string
	files map[string]string
	want  []string
}{
	{"include с корнем", map[string]string{
		"deployment.yaml": "        {{- include \"x.env\" . | nindent 8 }}\n",
		"_helpers.tpl":    "{{- define \"x.env\" -}}\n" + envRangeOf(`$k, $v := .Values.extraEnv`, `- name: {{ $k }}`) + "{{- end -}}\n",
	}, []string{"extraEnv"}},
	{"template с корнем и $ внутри", map[string]string{
		"deployment.yaml": "        {{- template \"x.env\" . }}\n",
		"_helpers.tpl":    "{{- define \"x.env\" -}}\n" + envRangeOf(`$k, $v := $.Values.extraEnv`, `- name: {{ $k }}`) + "{{- end -}}\n",
	}, []string{"extraEnv"}},
	{"include с картой аргументом", map[string]string{
		"deployment.yaml": "        {{- include \"x.env\" .Values.pod | nindent 8 }}\n",
		"_helpers.tpl":    "{{- define \"x.env\" -}}\n" + envRangeOf(`$k, $v := .env`, `- name: {{ $k }}`) + "{{- end -}}\n",
	}, []string{"pod.env"}},
	{"include из define, вызванного с dict", map[string]string{
		"deployment.yaml": "        {{- include \"x.outer\" (dict \"root\" $) | nindent 8 }}\n",
		"_helpers.tpl": "{{- define \"x.outer\" -}}\n{{- include \"x.env\" .root -}}\n{{- end -}}\n" +
			"{{- define \"x.env\" -}}\n" + envRangeOf(`$k, $v := .Values.extraEnv`, `- name: {{ $k }}`) + "{{- end -}}\n",
	}, []string{"extraEnv"}},
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

	for _, h := range lawfulPodEnvSourceHomes {
		t.Run(h.form, func(t *testing.T) {
			cands, err := podEnvSourcesIn(h.files)
			require.NoErrorf(t, err, "законный дом источника отвергнут")
			paths := make([]string, 0, len(cands))
			for _, c := range cands {
				paths = append(paths, c.path)
			}
			require.Equalf(t, h.want, paths, "источник в define не выведен с точкой места вызова")
		})
	}
	t.Logf("перепись: законных форм %d и домов %d, каждая назвала свой источник",
		len(lawfulPodEnvSourceForms), len(lawfulPodEnvSourceHomes))
}

// TestPostureShadowInjection_PodEnvSourceNonCandidatesAreSilent — не кандидаты
// на ступени разбора: проход, чьё тело ключа не упоминает (имя из значения),
// ключ, затенённый объявлением, комментарий и постоянная карта. Ключ,
// уходящий в метку, порт или значение, — КАНДИДАТ: решает рендер, и его
// близнецы — настоящим входом ниже (`KeyThatNamesNoPodVariableIsSilent`).
func TestPostureShadowInjection_PodEnvSourceNonCandidatesAreSilent(t *testing.T) {
	const twins = `{{/* {{- range $k, $v := .Values.commented }}
- name: {{ $k }} */}}
{{- range $k, $v := .Values.annotations }}
- name: {{ $v }}
{{- end }}
{{- range $k, $v := .Values.shadowed }}
{{- $k := "KANAME_FIXED" }}
- name: {{ $k }}
{{- end }}
{{- range $k, $v := dict "KANAME_FIXED" "x" }}
- name: {{ $k }}
{{- end }}
{{- range $v := .Values.valuesOnly }}
- name: {{ $v }}
{{- end }}
`
	got, err := podEnvSources(twins)
	require.NoError(t, err)
	require.Empty(t, got, "не кандидат назван кандидатом: по ключам карты значений шаблон здесь не проходит")
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
		{"ключ по вычисляемому полю", envRangeOf(`$k, $v := index .Values (printf "extra%s" "Env")`, `- name: {{ $k }}`)},
		{"define, вызванный по вычисляемому имени", "{{- include (printf \"x.%s\" \"env\") . }}\n{{- define \"x.env\" }}\n" +
			envRangeOf(`$k, $v := .Values.extraEnv`, `- name: {{ $k }}`) + "{{- end }}\n"},
		{"перечень ключей неизвестной карты", "        {{- range $n := keys (include \"x\" . | fromYaml) }}\n        - name: {{ $n }}\n        {{- end }}\n"},
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

// ── Ссылка на ключ и дом источника: опыты 392h–392n проверяющего ──────────────

// extraEnvForms — новый источник `extraEnv` в копии чарта КАЖДОЙ формой, которой
// ключ карты законно становится именем переменной окружения пода, кроме формы
// «range по .Values.карта, name: ключ» (её держит тест выше): ключ через
// переменную (392h), элемент, собранный dict и toYaml (392i), приставка
// текстом (392j), карта, положенная в dict через set (392m), источник в define
// файла _helpers.tpl (392n), перечень ключей `keys`. Каждая обязана дать
// находку по каждой ручке стража: страж обходит только env и secrets.
var extraEnvForms = []struct {
	name    string
	body    string // вставка за картой env шаблона развёртывания
	helpers string // вставка в конец _helpers.tpl
	key     func(env string) string
}{
	{name: "392h ключ через переменную", body: `            {{- range $k, $v := .Values.extraEnv }}
            {{- $envName := $k }}
            - name: {{ $envName }}
              value: {{ $v | quote }}
            {{- end }}
`},
	{name: "392i элемент собран dict и toYaml", body: `            {{- range $k, $v := .Values.extraEnv }}
            {{- list (dict "name" $k "value" (toString $v)) | toYaml | nindent 12 }}
            {{- end }}
`},
	{name: "392j приставка имени текстом", body: `            {{- range $k, $v := .Values.extraEnv }}
            - name: KANAME_{{ $k }}
              value: {{ $v | quote }}
            {{- end }}
`, key: func(env string) string { return strings.TrimPrefix(env, "KANAME_") }},
	{name: "392m карта положена в dict через set", body: `            {{- $ctx := dict }}
            {{- $_ := set $ctx "m" .Values.extraEnv }}
            {{- range $k, $v := $ctx.m }}
            - name: {{ $k }}
              value: {{ $v | quote }}
            {{- end }}
`},
	{name: "392n источник в define файла _helpers.tpl", body: `            {{- include "kaname-svc.cvExtraEnv" . | nindent 12 }}
`, helpers: `
{{- define "kaname-svc.cvExtraEnv" -}}
{{- range $k, $v := .Values.extraEnv }}
- name: {{ $k }}
  value: {{ $v | quote }}
{{- end }}
{{- end -}}
`},
	{name: "перечень ключей keys", body: `            {{- range $name := keys (.Values.extraEnv | default dict) | sortAlpha }}
            - name: {{ $name }}
              value: {{ index $.Values.extraEnv $name | quote }}
            {{- end }}
`},
}

// patchExtraEnvForm кладёт форму в копию чарта.
func patchExtraEnvForm(t *testing.T, dir, body, helpers string) {
	t.Helper()
	patchInCopy(t, dir, filepath.Join("templates", "deployment.yaml"), envRangeInTheTree, envRangeInTheTree+body)
	if helpers == "" {
		return
	}
	path := filepath.Join(dir, "templates", "_helpers.tpl")
	b, err := os.ReadFile(path) // #nosec G304 -- путь из t.TempDir
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, append(b, helpers...), 0o600))
}

func TestPostureShadowInjection_NewSourceInEveryReferenceFormIsJudged(t *testing.T) {
	rows := postureGuardRows(t)
	for _, f := range extraEnvForms {
		t.Run(f.name, func(t *testing.T) {
			dir := chartCopy(t)
			patchExtraEnvForm(t, dir, f.body, f.helpers)

			got, n := postureShadowFindings(t, dir)
			var own, foreign []string
			for _, g := range got {
				if strings.HasPrefix(g, "extraEnv") {
					own = append(own, g)
					continue
				}
				foreign = append(foreign, g)
			}
			require.Emptyf(t, foreign, "находка пришла и от неиспорченного источника:\n%s", strings.Join(foreign, "\n"))
			require.Lenf(t, own, len(rows)+1, "не каждая ручка в новом источнике найдена (рендеров %d):\n%s",
				n, strings.Join(got, "\n"))
			joined := strings.Join(own, "\n")
			for _, r := range rows {
				key := r.env
				if f.key != nil {
					key = f.key(r.env)
				}
				require.Containsf(t, joined, "extraEnv."+key, "ручка %s в новом источнике не названа ключом %s", r.env, key)
				require.Containsf(t, joined, r.env+": рендер прошёл", "ручка %s: находка не называет переменную пода", r.env)
			}
			t.Logf("перепись: рендеров %d · находок %d", n, len(got))
		})
	}
}

// Законные близнецы настоящим входом: ключ карты уходит не в имя переменной
// окружения пода — в имя тома (392o) и в значение переменной (близнец 392h).
// Находок ноль, а не ложная тревога «уехала в окружение пода».
func TestPostureShadowInjection_KeyThatNamesNoPodVariableIsSilent(t *testing.T) {
	for _, twin := range []struct{ name, anchor, insert string }{
		{"392o том назван ключом", "            name: {{ .Values.name }}-config\n", `        {{- range $k, $v := .Values.extraVolumes }}
        - name: {{ $k }}
          configMap:
            name: {{ $v | quote }}
        {{- end }}
`},
		{"порт назван ключом", "              containerPort: {{ .Values.ports.internalGrpc }}\n", `            {{- range $k, $v := .Values.extraPorts }}
            - name: {{ $k }}
              containerPort: {{ $v }}
            {{- end }}
`},
		{"аннотация пода названа ключом", "        app: {{ .Values.name }}\n      annotations:\n", `        {{- range $k, $v := .Values.extraAnnotations }}
        {{ $k }}: {{ $v | quote }}
        {{- end }}
`},
		{"ключ даёт имя строчными — ручку стража (заглавными) не даёт", envRangeInTheTree, `            {{- range $k, $v := .Values.extraEnv }}
            - name: {{ $k | lower }}
              value: {{ $v | quote }}
            {{- end }}
`},
		{"близнец 392h: ключ в значении", envRangeInTheTree, `            {{- range $k, $v := .Values.extraEnv }}
            {{- $envName := $k }}
            - name: KANAME_FIXED_TWIN
              value: {{ $envName | quote }}
            {{- end }}
`},
	} {
		t.Run(twin.name, func(t *testing.T) {
			dir := chartCopy(t)
			patchInCopy(t, dir, filepath.Join("templates", "deployment.yaml"), twin.anchor, twin.anchor+twin.insert)
			got, n := postureShadowFindings(t, dir)
			require.Emptyf(t, got, "ключ, не дающий имени переменной пода, назван источником — ложных находок %d:\n%s",
				len(got), strings.Join(got, "\n"))
			t.Logf("перепись: рендеров %d · находок 0", n)
		})
	}
}

// TestPostureShadowInjection_UnconfirmableCandidateIsNotSilent — кандидат, чей
// пробный ключ рендер не принял (значение обязано быть картой, а разбор этого
// не вывел), — несостоявшееся суждение и находка, а не «не источник»: иначе
// источник, которого рендер не проверил, выпал бы из суда молча.
func TestPostureShadowInjection_UnconfirmableCandidateIsNotSilent(t *testing.T) {
	dir := chartCopy(t)
	patchInCopy(t, dir, filepath.Join("templates", "deployment.yaml"), envRangeInTheTree, envRangeInTheTree+
		`            {{- range $k, $v := .Values.extraEnv }}
            - name: {{ $k }}
              value: {{ required "нужно поле must" (index $v "must") | quote }}
            {{- end }}
`)
	got, _ := postureShadowFindings(t, dir)
	joined := strings.Join(got, "\n")
	require.Containsf(t, joined, "кандидат extraEnv: рендер с пробным ключом",
		"кандидат, которого рендер не подтвердил и не опроверг, выпал из суда молча:\n%s", joined)
	require.Contains(t, joined, "источник не подтверждён и не опровергнут")
}

// ── Пробный ключ, не дошедший до имени переменной: опыты 392p–392s ────────────

// extraEnvRange — новый источник `extraEnv` в том виде, в каком его вставлял
// проверяющий: ключ — имя переменной пода.
const extraEnvRange = `            {{- range $k, $v := .Values.extraEnv }}
            - name: {{ $k }}
              value: {{ $v | quote }}
            {{- end }}
`

// chartPatch — одна вставка в шаблон развёртывания копии чарта: за якорем.
type chartPatch struct{ anchor, insert string }

// Чем находка «не подтверждён и не опровергнут» объясняет себя.
const (
	nowhereWhy  = "не дошёл ни до какого места рендера ни при одном условии суда"
	branchedWhy = "проход по карте стоит под условием либо ключ в его теле под ветвью или уходит из него"
)

// gatedExtraEnvForms — новый источник `extraEnv` в копии чарта, чей ключ доходит
// до имени переменной пода НЕ при всяком условии: под посадкой own (392p), под
// фильтром ключа (392q), под отдельным выключателем (392r), под посадкой
// external; одна карта двумя проходами — в имя тома всегда, в имя переменной
// под выключателем; один проход, где ключ даёт имя под ветвью, а иначе —
// значение; один проход, откуда ключ уходит присваиванием во внешнюю переменную;
// проход под выключателем, когда та же карта целиком выведена в аннотацию;
// законный фильтр, отсекающий ключи вида ручки (392s). До починки каждая форма
// молчала либо судилась не тем: пробный ключ не был похож на ручку,
// подтверждающий рендер шёл одной посадкой, а суд — другой, и кандидат, чей
// пробный ключ не дошёл до имени, выпадал без находки.
//
// Молчания среди исходов нет. judged — условие суда подтвердило источник, и
// находка по каждой ручке называет его ключом; иначе — ровно одна находка
// «не подтверждён и не опровергнут», называющая кандидата. У 392s это ложная
// тревога, и она названа вслух: законный фильтр суд от выключателя не отличает и
// называет себя несостоявшимся, а не молчит.
var gatedExtraEnvForms = []struct {
	name    string
	patches []chartPatch
	judged  bool
	why     string // чем находка «не подтверждён» объясняет себя: каждое правило опровержения держит свой случай
}{
	{name: "392p источник под посадкой own", judged: true, patches: []chartPatch{{envRangeInTheTree,
		"            {{- if eq .Values.authn.identityProvider \"own\" }}\n" + extraEnvRange + "            {{- end }}\n"}}},
	{name: "392q фильтр ключа по приставке ручки", judged: true, patches: []chartPatch{{envRangeInTheTree,
		`            {{- range $k, $v := .Values.extraEnv }}
            {{- if hasPrefix "KANAME_" $k }}
            - name: {{ $k }}
              value: {{ $v | quote }}
            {{- end }}
            {{- end }}
`}}},
	{name: "источник под посадкой external", judged: true, patches: []chartPatch{{envRangeInTheTree,
		"            {{- if eq .Values.authn.identityProvider \"external\" }}\n" + extraEnvRange + "            {{- end }}\n"}}},
	{name: "392r источник под отдельным выключателем", why: nowhereWhy, patches: []chartPatch{{envRangeInTheTree,
		"            {{- if .Values.extraEnvEnabled }}\n" + extraEnvRange + "            {{- end }}\n"}}},
	{name: "одна карта: том всегда, переменная под выключателем", why: branchedWhy, patches: []chartPatch{
		{"            name: {{ .Values.name }}-config\n", `        {{- range $k, $v := .Values.extraEnv }}
        - name: {{ $k }}
          configMap:
            name: {{ $v | quote }}
        {{- end }}
`},
		{envRangeInTheTree, "            {{- if .Values.extraEnvEnabled }}\n" + extraEnvRange + "            {{- end }}\n"}}},
	{name: "один проход: ключ в имени под ветвью, иначе в значении", why: branchedWhy, patches: []chartPatch{{envRangeInTheTree,
		`            {{- range $k, $v := .Values.extraEnv }}
            {{- if $.Values.extraEnvEnabled }}
            - name: {{ $k }}
              value: {{ $v | quote }}
            {{- else }}
            - name: KANAME_EXTRA_ENV_KEY
              value: {{ $k | quote }}
            {{- end }}
            {{- end }}
`}}},
	{name: "один проход: ключ уходит наружу присваиванием", why: branchedWhy, patches: []chartPatch{{envRangeInTheTree,
		`            {{- $extraNames := list }}
            {{- range $k, $v := .Values.extraEnv }}
            {{- $extraNames = append $extraNames $k }}
            - name: KANAME_EXTRA_ENV_KEY
              value: {{ $k | quote }}
            {{- end }}
            {{- if .Values.extraEnvEnabled }}
            {{- range $extraNames }}
            - name: {{ . }}
              value: "1"
            {{- end }}
            {{- end }}
`}}},
	{name: "проход под выключателем, карта целиком в аннотации", why: branchedWhy, patches: []chartPatch{
		{"        app: {{ .Values.name }}\n      annotations:\n", "        kaname.io/extra-env: {{ toJson .Values.extraEnv | quote }}\n"},
		{envRangeInTheTree, "            {{- if .Values.extraEnvEnabled }}\n" + extraEnvRange + "            {{- end }}\n"}}},
	{name: "392s законный фильтр, отсекающий ключи вида ручки", why: nowhereWhy, patches: []chartPatch{{envRangeInTheTree,
		`            {{- range $k, $v := .Values.extraEnv }}
            {{- if not (hasPrefix "KANAME_" $k) }}
            - name: {{ $k }}
              value: {{ $v | quote }}
            {{- end }}
            {{- end }}
`}}},
}

func TestPostureShadowInjection_CandidateWhoseProbeKeyReachesNoNameIsNotSilent(t *testing.T) {
	rows := postureGuardRows(t)
	for _, f := range gatedExtraEnvForms {
		t.Run(f.name, func(t *testing.T) {
			dir := chartCopy(t)
			for _, p := range f.patches {
				patchInCopy(t, dir, filepath.Join("templates", "deployment.yaml"), p.anchor, p.anchor+p.insert)
			}
			got, n := postureShadowFindings(t, dir)
			var own, foreign []string
			for _, g := range got {
				if strings.HasPrefix(g, "extraEnv") || strings.HasPrefix(g, "кандидат extraEnv") {
					own = append(own, g)
					continue
				}
				foreign = append(foreign, g)
			}
			joined := strings.Join(own, "\n")
			require.Emptyf(t, foreign, "находка пришла и от неиспорченного источника:\n%s", strings.Join(foreign, "\n"))
			if f.judged {
				require.Lenf(t, own, len(rows)+1, "источник, подтверждённый условием суда, судим не по каждой ручке (рендеров %d):\n%s",
					n, strings.Join(got, "\n"))
				for _, r := range rows {
					require.Containsf(t, joined, "extraEnv."+r.env+": рендер прошёл — ручка стража посадки уехала в окружение пода",
						"ручка %s в новом источнике не найдена", r.env)
				}
			} else {
				require.Lenf(t, own, 1, "кандидат, чей пробный ключ не дошёл до имени, выпал из суда молча (рендеров %d):\n%s",
					n, strings.Join(got, "\n"))
				require.Contains(t, own[0], "источник не подтверждён и не опровергнут")
				require.Containsf(t, own[0], f.why, "находка объясняет себя не тем правилом — инъекция уронила не свой предмет")
				t.Logf("находка: %s", headOf(own[0]))
			}
			t.Logf("перепись: рендеров %d · находок %d", n, len(got))
		})
	}
}
