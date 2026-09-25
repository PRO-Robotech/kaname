// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// posture_knob_has_one_address_injection_test.go — СПОСОБНОСТЬ суда над
// тенями ручек стража упасть, доказанная инъекцией в обе стороны (задача #392).
//
// Вывод источников окружения пода: карта, чей ключ становится `- name:`
// переменной, — источник; та же карта, чей ключ уходит в другое поле, в
// комментарии либо в перечне портов, — нет. Перечень стража: пара литералов
// словаря внутри стража — строка; тот же литерал вне стража — нет.
//
// Настоящий вход — на копии чарта: строка, выпавшая из перечня стража, и
// источник, выпавший из обхода стража.
package deploy_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPostureShadowInjection_PodEnvSourcesKnowTheLawfulForm(t *testing.T) {
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
`
	got, err := podEnvSources(src)
	require.NoError(t, err)
	require.Equal(t, []string{"env", "extraEnv", "secrets"}, got, "законные формы источника окружения не выведены")

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
`
	got, err = podEnvSources(twins)
	require.NoError(t, err)
	require.Empty(t, got, "близнец назван источником окружения: ключ карты не становится именем переменной")
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
