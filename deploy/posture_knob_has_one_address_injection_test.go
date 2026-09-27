// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// posture_knob_has_one_address_injection_test.go — СПОСОБНОСТЬ суда над
// тенями ручек стража упасть и смолчать, доказанная настоящим входом на копии
// чарта (задачи #392, #433).
//
// Суд идёт по исполнению (`judgePodEnvByExecution`), и сцены ниже — формы,
// которые прежний держатель по тексту шаблона не видел (круги ревью сборки
// #425), плюс форма, которой нет ни в одном перечне и ни в коде держателя.
// Каждая форма кладётся в копию чарта дважды — карта объявлена в values.yaml
// и не объявлена нигде, — и у каждой есть законный близнец той же формы, где
// ключ карты уходит в значение, а не в имя переменной пода: он молчит.
//
// Перечень стража: пара литералов словаря внутри стража — строка; тот же
// литерал вне стража — нет; строка, выпавшая из перечня, — находка; источник,
// выпавший из обхода стража, — находка по каждой ручке.
package deploy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// envRangeInTheTree — карта env в шаблоне развёртывания дерева: за ней в копию
// вставляется форма.
const envRangeInTheTree = `            {{- range $k, $v := .Values.env }}
            - name: {{ $k }}
              value: {{ $v | quote }}
            {{- end }}
`

// shadowForm — форма, которой ключ карты `extraEnv` становится именем
// переменной окружения пода, и её законный близнец.
type shadowForm struct {
	name          string
	body, helpers string // вставка за картой env и в конец _helpers.tpl
	twin, twinTpl string // близнец той же формы: ключ уходит в значение
	// rangeIn — файл шаблонов, где стоит проход по карте: им называется
	// источник, когда карта не объявлена в дереве значений.
	rangeIn string
}

// shadowForms — формы из «Признака» задачи #433 и прежних кругов, каждая
// настоящим шаблоном.
var shadowForms = []shadowForm{
	{
		name: "C1 выход из итерации под ветвью: ключ в значении, затем в имени",
		body: `            {{- range $k, $v := .Values.extraEnv }}
            - name: KANAME_EXTRA_ENV_KEY
              value: {{ $k | quote }}
            {{- if not $.Values.extraEnvEnabled }}{{ continue }}{{ end }}
            - name: {{ $k }}
              value: {{ $v | quote }}
            {{- end }}
`,
		twin: `            {{- range $k, $v := .Values.extraEnv }}
            - name: KANAME_EXTRA_ENV_KEY
              value: {{ $k | quote }}
            {{- if not $.Values.extraEnvEnabled }}{{ continue }}{{ end }}
            - name: KANAME_EXTRA_ENV_KEY_AGAIN
              value: {{ $k | quote }}
            {{- end }}
`,
	},
	{
		name: "C1 break под ветвью: имя с приставкой, затем голое",
		body: `            {{- range $k, $v := .Values.extraEnv }}
            - name: EXTRA_{{ $k }}
              value: {{ $v | quote }}
            {{- if not $.Values.extraEnvEnabled }}{{ break }}{{ end }}
            - name: {{ $k }}
              value: {{ $v | quote }}
            {{- end }}
`,
		twin: `            {{- range $k, $v := .Values.extraEnv }}
            - name: KANAME_EXTRA_ENV_KEY
              value: {{ $k | quote }}
            {{- if not $.Values.extraEnvEnabled }}{{ break }}{{ end }}
            - name: KANAME_EXTRA_ENV_KEY_AGAIN
              value: {{ $v | quote }}
            {{- end }}
`,
	},
	{
		// Функция, читающая кластер, а не значения: рендер без кластера
		// отдаёт пустое, и имя постоянно; на установке, где объект есть, имя —
		// ключ. Ключ стоит и в значении: пробный ключ доходит до рендера, и
		// прежний держатель, не судивший вызов `lookup` в теле прохода (392-C2),
		// опровергал карту молча.
		name: "C2 ternary по функции, читающей не значения чарта (lookup)",
		body: `            {{- range $k, $v := .Values.extraEnv }}
            - name: {{ ternary "KANAME_EXTRA_FIXED" $k (empty (lookup "v1" "ConfigMap" "kaname" "kaname-extra-env")) }}
              value: {{ $k | quote }}
            {{- end }}
`,
		twin: `            {{- range $k, $v := .Values.extraEnv }}
            - name: {{ ternary "KANAME_EXTRA_FIXED" "KANAME_EXTRA_OTHER" (empty (lookup "v1" "ConfigMap" "kaname" "kaname-extra-env")) }}
              value: {{ $k | quote }}
            {{- end }}
`,
	},
	{
		name: "C2 условие по функции, читающей не значения чарта, конвейером в ternary",
		body: `            {{- range $k, $v := .Values.extraEnv }}
            - name: {{ lookup "v1" "ConfigMap" "kaname" "kaname-extra-env" | empty | ternary "KANAME_EXTRA_FIXED" $k }}
              value: {{ $k | quote }}
            {{- end }}
`,
		twin: `            {{- range $k, $v := .Values.extraEnv }}
            - name: {{ lookup "v1" "ConfigMap" "kaname" "kaname-extra-env" | empty | ternary "KANAME_EXTRA_FIXED" "KANAME_EXTRA_OTHER" }}
              value: {{ $k | quote }}
            {{- end }}
`,
	},
	{
		name: "U1 приставка под ветвью, ключа не упоминающей",
		body: `            {{- range $k, $v := .Values.extraEnv }}
            - name: {{ if not $.Values.extraEnvBare }}EXTRA_{{ end }}{{ $k }}
              value: {{ $v | quote }}
            {{- end }}
`,
		twin: `            {{- range $k, $v := .Values.extraEnv }}
            - name: {{ if not $.Values.extraEnvBare }}EXTRA_{{ end }}KANAME_FIXED
              value: {{ $k | quote }}
            {{- end }}
`,
	},
	{
		name: "U2 запись, которую ветвь без ключа делает комментарием",
		body: `            {{- range $k, $v := .Values.extraEnv }}
            {{ if $.Values.extraEnvOn }}-{{ else }}#{{ end }} name: {{ $k }}
            {{ if $.Values.extraEnvOn }} {{ else }}#{{ end }} value: {{ $v | quote }}
            {{- end }}
`,
		twin: `            {{- range $k, $v := .Values.extraEnv }}
            # name: {{ $k }}
            #  value: {{ $v | quote }}
            {{- end }}
`,
	},
	{
		name: "U3 приставка из переменной, переприсвоенной ветвью вне прохода",
		body: `            {{- $extraPrefix := "EXTRA_" }}
            {{- if .Values.extraEnvBare }}{{- $extraPrefix = "" }}{{- end }}
            {{- range $k, $v := .Values.extraEnv }}
            - name: {{ $extraPrefix }}{{ $k }}
              value: {{ $v | quote }}
            {{- end }}
`,
		twin: `            {{- $extraPrefix := "EXTRA_" }}
            {{- if .Values.extraEnvBare }}{{- $extraPrefix = "" }}{{- end }}
            {{- range $k, $v := .Values.extraEnv }}
            - name: {{ $extraPrefix }}FIXED
              value: {{ $k | quote }}
            {{- end }}
`,
	},
	{
		name: "псевдоним: карта положена в dict через set",
		body: `            {{- $ctx := dict }}
            {{- $_ := set $ctx "m" .Values.extraEnv }}
            {{- range $k, $v := $ctx.m }}
            - name: {{ $k }}
              value: {{ $v | quote }}
            {{- end }}
`,
		twin: `            {{- $ctx := dict }}
            {{- $_ := set $ctx "m" .Values.extraEnv }}
            {{- range $k, $v := $ctx.m }}
            - name: KANAME_EXTRA_FIXED
              value: {{ $k | quote }}
            {{- end }}
`,
	},
	{
		name: "вложенное поле карты шаблона",
		body: `            {{- $ctx := dict "outer" (dict "inner" .Values.extraEnv) }}
            {{- range $k, $v := $ctx.outer.inner }}
            - name: {{ $k }}
              value: {{ $v | quote }}
            {{- end }}
`,
		twin: `            {{- $ctx := dict "outer" (dict "inner" .Values.extraEnv) }}
            {{- range $k, $v := $ctx.outer.inner }}
            - name: KANAME_EXTRA_FIXED
              value: {{ $k | quote }}
            {{- end }}
`,
	},
	{
		name:    "define: проход в define файла _helpers.tpl",
		rangeIn: "_helpers.tpl",
		body: `            {{- include "kaname-svc.cvExtraEnv" . | nindent 12 }}
`,
		helpers: `
{{- define "kaname-svc.cvExtraEnv" -}}
{{- range $k, $v := .Values.extraEnv }}
- name: {{ $k }}
  value: {{ $v | quote }}
{{- end }}
{{- end -}}
`,
		twin: `            {{- include "kaname-svc.cvExtraEnv" . | nindent 12 }}
`,
		twinTpl: `
{{- define "kaname-svc.cvExtraEnv" -}}
{{- range $k, $v := .Values.extraEnv }}
- name: KANAME_EXTRA_FIXED
  value: {{ $k | quote }}
{{- end }}
{{- end -}}
`,
	},
	{
		name:    "define под ветвью внутри define: ключ уходит в define",
		rangeIn: "deployment.yaml",
		body: `            {{- range $k, $v := .Values.extraEnv }}
            {{- include "kaname-svc.cvExtraEnvEntry" (list $k $v $) | nindent 12 }}
            {{- end }}
`,
		helpers: `
{{- define "kaname-svc.cvExtraEnvEntry" -}}
{{- if (index . 2).Values.extraEnvEnabled }}
- name: {{ index . 0 }}
  value: {{ index . 1 | quote }}
{{- end }}
{{- end -}}
`,
		twin: `            {{- range $k, $v := .Values.extraEnv }}
            {{- include "kaname-svc.cvExtraEnvEntry" (list $k $v $) | nindent 12 }}
            {{- end }}
`,
		twinTpl: `
{{- define "kaname-svc.cvExtraEnvEntry" -}}
{{- if (index . 2).Values.extraEnvEnabled }}
- name: KANAME_EXTRA_FIXED
  value: {{ index . 0 | quote }}
{{- end }}
{{- end -}}
`,
	},
	{
		name: "смена регистра приставки",
		body: `            {{- range $k, $v := .Values.extraEnv }}
            - name: {{ printf "kaname_%s" $k | upper }}
              value: {{ $v | quote }}
            {{- end }}
`,
		twin: `            {{- range $k, $v := .Values.extraEnv }}
            - name: {{ printf "kaname_%s" "extra_fixed" | upper }}
              value: {{ $k | quote }}
            {{- end }}
`,
	},
	{
		name: "выбор формы имени по содержимому ключа",
		body: `            {{- range $k, $v := .Values.extraEnv }}
            - name: {{ if hasPrefix "KANAME_" $k }}{{ $k }}{{ else }}KANAME_{{ $k }}{{ end }}
              value: {{ $v | quote }}
            {{- end }}
`,
		twin: `            {{- range $k, $v := .Values.extraEnv }}
            - name: {{ if hasPrefix "KANAME_" $k }}KANAME_EXTRA_A{{ else }}KANAME_EXTRA_B{{ end }}
              value: {{ $k | quote }}
            {{- end }}
`,
	},
	// Прежде законные близнецы, теперь находки — и это решение, а не
	// побочный эффект: постоянная приставка и понижение регистра ручки сами по
	// себе не дают, но что выберет другое исполнение, рендер не называет, и
	// карта вне суда стража не отдаёт ключ именем переменной ни в какой форме.
	{
		name: "ключ за постоянной приставкой без всякого условия",
		body: `            {{- range $k, $v := .Values.extraEnv }}
            - name: EXTRA_{{ $k }}
              value: {{ $v | quote }}
            {{- end }}
`,
		twin: `            {{- range $k, $v := .Values.extraEnv }}
            - name: EXTRA_FIXED
              value: {{ $k | quote }}
            {{- end }}
`,
	},
	{
		name: "ключ строчными без всякого условия",
		body: `            {{- range $k, $v := .Values.extraEnv }}
            - name: {{ $k | lower }}
              value: {{ $v | quote }}
            {{- end }}
`,
		twin: `            {{- range $k, $v := .Values.extraEnv }}
            - name: {{ "KANAME_EXTRA_FIXED" | lower }}
              value: {{ $k | lower | quote }}
            {{- end }}
`,
	},
	{
		name: "392r проход под отдельным выключателем",
		body: `            {{- if .Values.extraEnvEnabled }}
            {{- range $k, $v := .Values.extraEnv }}
            - name: {{ $k }}
              value: {{ $v | quote }}
            {{- end }}
            {{- end }}
`,
		twin: `            {{- if .Values.extraEnvEnabled }}
            {{- range $k, $v := .Values.extraEnv }}
            - name: KANAME_EXTRA_FIXED
              value: {{ $k | quote }}
            {{- end }}
            {{- end }}
`,
	},
	{
		name: "проход под with и в теле внешнего range",
		body: `            {{- with .Values.extraEnvSwitch }}
            {{- range $.Values.extraEnvGroups }}
            {{- range $k, $v := $.Values.extraEnv }}
            - name: {{ $k }}
              value: {{ $v | quote }}
            {{- end }}
            {{- end }}
            {{- end }}
`,
		twin: `            {{- with .Values.extraEnvSwitch }}
            {{- range $.Values.extraEnvGroups }}
            {{- range $k, $v := $.Values.extraEnv }}
            - name: KANAME_EXTRA_FIXED
              value: {{ $k | quote }}
            {{- end }}
            {{- end }}
            {{- end }}
`,
	},
	{
		name: "перечень ключей keys",
		body: `            {{- range $name := keys (.Values.extraEnv | default dict) | sortAlpha }}
            - name: {{ $name }}
              value: "1"
            {{- end }}
`,
		twin: `            {{- range $name := keys (.Values.extraEnv | default dict) | sortAlpha }}
            - name: KANAME_EXTRA_FIXED
              value: {{ $name | quote }}
            {{- end }}
`,
	},
}

// novelShadowForms — формы, которых нет ни в перечне выше, ни в прежних кругах,
// ни в коде держателя: держатель не знает форм шаблона, и они обязаны
// покраснеть тем же исполнением.
var novelShadowForms = []shadowForm{
	{
		name: "перечень, собранный append в проходе и выведенный toYaml вне его",
		body: `            {{- $extra := list }}
            {{- range $k, $v := .Values.extraEnv }}
            {{- $extra = append $extra (dict "name" ($k | b64enc | b64dec) "value" (toString $v)) }}
            {{- end }}
            {{- if $extra }}
            {{- toYaml $extra | nindent 12 }}
            {{- end }}
`,
		twin: `            {{- $extra := list }}
            {{- range $k, $v := .Values.extraEnv }}
            {{- $extra = append $extra (dict "name" "KANAME_EXTRA_FIXED" "value" ($k | b64enc | b64dec)) }}
            {{- end }}
            {{- if $extra }}
            {{- toYaml $extra | nindent 12 }}
            {{- end }}
`,
	},
	{
		name: "карта, вычисленная fromYaml из define",
		body: `            {{- $env := include "kaname-svc.cvEnvYaml" . | fromYaml }}
            {{- range $k, $v := $env }}
            - name: {{ regexReplaceAll "^(.*)$" $k "${1}" }}
              value: {{ $v | quote }}
            {{- end }}
`,
		helpers: `
{{- define "kaname-svc.cvEnvYaml" -}}
{{- toYaml (.Values.extraEnv | default dict) -}}
{{- end -}}
`,
		twin: `            {{- $env := include "kaname-svc.cvEnvYaml" . | fromYaml }}
            {{- range $k, $v := $env }}
            - name: KANAME_EXTRA_FIXED
              value: {{ regexReplaceAll "^(.*)$" $k "${1}" | quote }}
            {{- end }}
`,
		twinTpl: `
{{- define "kaname-svc.cvEnvYaml" -}}
{{- toYaml (.Values.extraEnv | default dict) -}}
{{- end -}}
`,
	},
}

// shadowFormHomes — дом карты `extraEnv`: объявлена в values.yaml пустой либо
// не объявлена нигде.
var shadowFormHomes = []struct {
	name     string
	declared bool
}{
	{"карта объявлена в values.yaml", true},
	{"карта не объявлена ни в одном профиле", false},
}

// chartCopyWith — копия чарта с формой: вставка за картой env шаблона
// развёртывания, define в конце _helpers.tpl и, если declared, пустая карта
// `extraEnv` в values.yaml.
func chartCopyWith(t *testing.T, body, helpers string, declared bool) string {
	t.Helper()
	dir := chartCopy(t)
	patchInCopy(t, dir, filepath.Join("templates", "deployment.yaml"), envRangeInTheTree, envRangeInTheTree+body)
	appendToCopy(t, dir, filepath.Join("templates", "_helpers.tpl"), helpers)
	if declared {
		appendToCopy(t, dir, "values.yaml", "\nextraEnv: {}\n")
	}
	return dir
}

// appendToCopy дописывает текст в конец файла копии чарта.
func appendToCopy(t *testing.T, dir, rel, text string) {
	t.Helper()
	if text == "" {
		return
	}
	path := filepath.Join(dir, rel)
	b, err := os.ReadFile(path) // #nosec G304 -- путь из t.TempDir
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, append(b, text...), 0o600))
}

// requireShadowFormJudged — форма краснеет находкой, называющей источник,
// посадку и контейнер, и только ею; близнец той же формы молчит.
func requireShadowFormJudged(t *testing.T, f shadowForm) {
	t.Helper()
	for _, home := range shadowFormHomes {
		t.Run(home.name, func(t *testing.T) {
			t.Parallel()
			sources := []string{"extraEnv: ", "extraEnv."}
			if !home.declared {
				in := f.rangeIn
				if in == "" {
					in = "deployment.yaml"
				}
				sources = []string{"проход " + in + ":"}
			}
			got, census, err := judgePodEnvByExecution(t, chartCopyWith(t, f.body, f.helpers, home.declared), podEnvConditions)
			require.NoError(t, err)
			t.Logf("перепись: %s · находок %d", census, len(got))
			require.NotEmptyf(t, got, "форма прошла суд молча — ключ карты стал именем переменной пода, а находок 0")
			for _, g := range got {
				require.Truef(t, strings.HasPrefix(g, sources[0]) || strings.HasPrefix(g, sources[len(sources)-1]),
					"находка не называет источник %q либо пришла от неиспорченного:\n%s", sources, g)
				require.Containsf(t, g, "посадка «", "находка без посадки:\n%s", g)
				require.Containsf(t, g, "Deployment/", "находка без документа:\n%s", g)
				require.Containsf(t, g, "containers ", "находка без контейнера:\n%s", g)
			}

			twin, tcensus, err := judgePodEnvByExecution(t, chartCopyWith(t, f.twin, f.twinTpl, home.declared), podEnvConditions)
			require.NoError(t, err)
			t.Logf("близнец: %s", tcensus)
			require.Emptyf(t, twin, "законный близнец формы — ключ ушёл в значение, а не в имя — дал находки:\n%s", strings.Join(twin, "\n"))
		})
	}
}

func TestPostureShadowInjection_EveryFormOfTheSignIsJudged(t *testing.T) {
	for _, f := range shadowForms {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			requireShadowFormJudged(t, f)
		})
	}
}

func TestPostureShadowInjection_NovelFormIsJudgedWithoutBeingKnown(t *testing.T) {
	for _, f := range novelShadowForms {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			requireShadowFormJudged(t, f)
		})
	}
}

// TestPostureShadowInjection_GuardedMapInAnotherNameFormIsFound — карта env,
// которую страж судит, но ключ которой уходит в имя не дословно: страж ключ
// `kaname_authn__identity_provider` не узнаёт, а имя переменной — ручка.
// Близнец: та же карта с `quote` — имя дословно ключ.
func TestPostureShadowInjection_GuardedMapInAnotherNameFormIsFound(t *testing.T) {
	for _, c := range []struct {
		name, form string
		found      bool
	}{
		{"верхний регистр", "{{ $k | upper }}", true},
		{"приставка текстом", "KANAME_{{ $k }}", true},
		{"законный близнец: quote", "{{ $k | quote }}", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			dir := chartCopy(t)
			patchInCopy(t, dir, filepath.Join("templates", "deployment.yaml"), envRangeInTheTree,
				strings.Replace(envRangeInTheTree, "{{ $k }}", c.form, 1))
			got, census, err := judgePodEnvByExecution(t, dir, podEnvConditions)
			require.NoError(t, err)
			t.Logf("перепись: %s · находки: %q", census, got)
			if !c.found {
				require.Empty(t, got)
				return
			}
			require.NotEmpty(t, got, "страж судит ключ дословно, а имя другой формы прошло молча")
			for _, g := range got {
				require.Truef(t, strings.HasPrefix(g, "env: страж судит ключ карты дословно"), "находка не о форме имени:\n%s", g)
				require.Contains(t, g, "посадка «")
				require.Contains(t, g, "containers ")
			}
		})
	}
}

// TestPostureShadowInjection_ProbeTheChartRefusesIsNotSilent — карта, чей
// пробный ключ рендер как есть не принимает (значение обязано нести поле, а
// дерево значений этого не показывает), — «не выполнилось», а не «не
// источник»: иначе карта, которую рендер не проверил, выпала бы из суда молча.
func TestPostureShadowInjection_ProbeTheChartRefusesIsNotSilent(t *testing.T) {
	dir := chartCopyWith(t, `            {{- range $k, $v := .Values.extraEnv }}
            - name: {{ $k }}
              value: {{ required "нужно поле must" (index $v "must") | quote }}
            {{- end }}
`, "", true)
	_, _, err := judgePodEnvByExecution(t, dir, podEnvConditions)
	require.Error(t, err, "карта, чью пробу рендер не принял, выпала из суда молча")
	require.Contains(t, err.Error(), "не рендерится как есть")
}

// TestPostureShadowInjection_ForcingThatBreaksTheRenderIsRepairedAndNamed —
// ветвь, которая при принуждении отказывает (исполнения, где условие ложно,
// дерево не знает), лишается принуждения ОДНА и называется в переписи, а
// форма за выключателем в том же исполнении по-прежнему судится. Две формы
// отказа helm: исполнение шаблона с позицией и разбор YAML без неё.
func TestPostureShadowInjection_ForcingThatBreaksTheRenderIsRepairedAndNamed(t *testing.T) {
	gated := `            {{- if .Values.extraEnvEnabled }}
            {{- range $k, $v := .Values.extraEnv }}
            - name: {{ $k }}
              value: {{ $v | quote }}
            {{- end }}
            {{- end }}
`
	for _, c := range []struct{ name, breaker string }{
		{"отказ исполнения с позицией", "  qzBreaker: {{ if .Values.qzNever }}{{ index (list) 3 }}{{ end }}\n"},
		{"отказ разбора YAML", "{{- if .Values.qzNever }}\n  : : broken: [\n{{- end }}\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			dir := chartCopyWith(t, gated, "", true)
			patchInCopy(t, dir, filepath.Join("templates", "configmap.yaml"), "data:\n", "data:\n"+c.breaker)
			got, census, err := judgePodEnvByExecution(t, dir, podEnvConditions)
			require.NoError(t, err)
			t.Logf("перепись: %s · находок %d", census, len(got))
			require.NotEmpty(t, census.repaired, "принуждение, ломающее рендер, снято молча либо не снято")
			for _, r := range census.repaired {
				require.Containsf(t, r, "configmap.yaml:", "принуждение снято не в файле отказа: %s", r)
			}
			require.NotEmpty(t, got, "форма за выключателем выпала из суда вместе со снятым принуждением")
			for _, g := range got {
				require.Truef(t, strings.HasPrefix(g, "extraEnv: ") || strings.HasPrefix(g, "extraEnv."), "находка не о форме:\n%s", g)
			}
		})
	}
}

// TestPostureShadowInjection_EmptyWalkIsNotClean — ноль посадок и ноль
// контейнеров — «не выполнилось», а не «ни одной тени».
func TestPostureShadowInjection_EmptyWalkIsNotClean(t *testing.T) {
	_, _, err := judgePodEnvByExecution(t, ".", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "посадок ноль")

	dir := chartCopy(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "templates", "deployment.yaml"),
		[]byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Values.name }}-no-pods\n"), 0o600))
	_, _, err = judgePodEnvByExecution(t, dir, podEnvConditions)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ни одного контейнера")
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
	control, _ := judgePostureGuardRoster(t, filepath.Join(dir, "templates"))
	require.Empty(t, control, "контроль: копия настоящего дерева обязана сходиться с таблицей")

	dropLineInCopy(t, dir, filepath.Join("templates", "_helpers.tpl"), `"KANAME_AUTHN__IDENTITY_PROVIDER" "authn.identityProvider"`)
	got, _ := judgePostureGuardRoster(t, filepath.Join(dir, "templates"))
	require.Len(t, got, 1, strings.Join(got, "\n"))
	require.Contains(t, got[0], "KANAME_AUTHN__IDENTITY_PROVIDER")
	require.Contains(t, got[0], identityProviderKnob)
}

// TestPostureShadowInjection_SourceDroppedFromTheGuardIsFound — настоящий
// вход: страж в копии чарта перестал обходить `secrets`. Карта secrets
// по-прежнему даёт имя переменной пода — теперь мимо суда стража.
func TestPostureShadowInjection_SourceDroppedFromTheGuardIsFound(t *testing.T) {
	dir := chartCopy(t)
	patchInCopy(t, dir, filepath.Join("templates", "_helpers.tpl"),
		`{{- range $source := list "env" "secrets" -}}`, `{{- range $source := list "env" -}}`)
	got, census, err := judgePodEnvByExecution(t, dir, podEnvConditions)
	require.NoError(t, err)
	joined := strings.Join(got, "\n")
	t.Logf("перепись: %s · находок %d", census, len(got))
	require.NotEmpty(t, got, "источник окружения, выпавший из стража, прошёл суд")
	require.Contains(t, joined, "secrets.KANAME_AUTHN__IDENTITY_PROVIDER: рендер прошёл — ручка стража посадки уехала в окружение пода")
	require.Contains(t, joined, "secrets: ключ карты стал именем переменной пода")
	for _, g := range got {
		require.Truef(t, strings.HasPrefix(g, "secrets"), "находка пришла и от неиспорченного источника:\n%s", g)
	}
}
