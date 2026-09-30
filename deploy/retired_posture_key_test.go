// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retired_posture_key_test.go — ЧАРТ НЕ ЧИТАЕТ КЛЮЧА ПОСАДКИ И ОТВЕРГАЕТ ЕГО
// ВСЛУХ (kaname#363).
//
// У службы одна посадка, и ключ `authn.identityProvider`, выбиравший её, снят.
// Опасность снятия — МОЛЧАЛИВОЕ переворачивание условий шаблона: `eq` со снятым
// значением даёт ложь и снимает правила тревоги полосы входа и страж
// токен-эндпоинта, а `ne` даёт истину и рендерит порт хуков поставщика, которых
// нет. Поэтому три утверждения, и у каждого законный близнец:
//
//	Ч1  ни один шаблон не читает значение ключа — перепись действий шаблонов;
//	Ч2  ключ, поданный профилем значений либо окружением пода, — отказ рендера,
//	    называющий ключ и что сделать; близнец — поставляемый профиль без
//	    `--set` рендерится;
//	Ч3  каждый поставляемый профиль БЕЗ ключа рендерит полосу своего входа:
//	    правила её тревоги есть, хуков поставщика нет ни правилом, ни портом;
//	    страж токен-эндпоинта отказывает на выключенном эндпоинте, а близнец —
//	    включённый эндпоинт — проходит.
//
// Путь процесса (файл настройки и переменная) судит
// `internal/apps/kaname/config/retired_posture_key_test.go`.
package deploy_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// retiredPostureValuesKey / retiredPostureVariable — координаты снятого ключа
// так, как их знал оператор чарта. Литералы: проба судит ИМЕННО то, что
// оператор мог написать.
const (
	retiredPostureValuesKey = "authn.identityProvider"
	retiredPostureVariable  = "KANAME_AUTHN__IDENTITY_PROVIDER"
)

// shippedProfileChains — каждая поставляемая цепочка профилей чарта.
var shippedProfileChains = [][]string{
	{"values.yaml", "values.prod.yaml"},
	{"values.yaml", "values.dev.yaml"},
}

// templateActionRe — действие шаблона `{{ … }}`; комментарии `{{/* … */}}`
// отсеиваются отдельно — прозу о снятом ключе читателем не считаем.
var templateActionRe = regexp.MustCompile(`(?s)\{\{-?(.*?)-?\}\}`)

// postureReadRe — ЧТЕНИЕ значения ключа посадки: обращение к полю
// `.identityProvider` любой цепочкой (`$authn.identityProvider`,
// `.Values.authn.identityProvider`). Строковые литералы из действия вынимаются
// до сверки (templateStringRe): имя ключа в тексте отказа либо в перечне
// координат значения не читает. Проверка присутствия ключа по имени
// (`hasKey … "identityProvider"`) — тоже не читатель: это отказ.
var postureReadRe = regexp.MustCompile(`\.identityProvider\b`)

// templateStringRe — строковый литерал шаблона в двойных кавычках либо обратных
// апострофах.
var templateStringRe = regexp.MustCompile("(?s)\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`")

// postureReadersIn — СУЖДЕНИЕ Ч1, отделённое от обхода: доказательство
// способности гейта упасть обязано звать его же, а не свою копию.
// Принимает текст шаблонов по имени файла; отдаёт читателей и число
// прочитанных действий.
func postureReadersIn(templates map[string]string) (readers []string, actions int) {
	for f, text := range templates {
		for _, m := range templateActionRe.FindAllStringSubmatch(text, -1) {
			body := strings.TrimSpace(m[1])
			if strings.HasPrefix(body, "/*") {
				continue
			}
			actions++
			if postureReadRe.MatchString(templateStringRe.ReplaceAllString(body, `""`)) {
				readers = append(readers, f+": {{"+body+"}}")
			}
		}
	}
	sort.Strings(readers)
	return readers, actions
}

// Ч1.
func TestNoChartTemplateReadsThePostureKey(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("templates", "*"))
	require.NoError(t, err)
	templates := map[string]string{}
	for _, f := range files {
		raw, err := os.ReadFile(f) // #nosec G304 -- путь из дерева чарта
		require.NoError(t, err)
		templates[f] = string(raw)
	}
	readers, actions := postureReadersIn(templates)
	t.Logf("перепись: файлов шаблонов %d · действий прочитано %d · читателей ключа посадки %d",
		len(files), actions, len(readers))
	require.NotZero(t, actions, "обход пуст: ни одного действия шаблона не прочитано")
	require.Emptyf(t, readers,
		"шаблоны читают снятый ключ посадки — условие, собранное на снятом значении, переворачивается "+
			"молча:\n  %s", strings.Join(readers, "\n  "))
}

// Способность Ч1 упасть и промолчать — на синтетике, а не на дереве: чтение
// значения любой цепочкой — находка; имя ключа в строке, проверка присутствия
// по имени и комментарий — молчание.
func TestPostureReaderJudgeFindsAReadAndSparesTheLawfulForms(t *testing.T) {
	for _, c := range []struct {
		name, text string
		readers    int
	}{
		{"чтение через переменную", `{{- if eq $authn.identityProvider "own" }}`, 1},
		{"чтение полной цепочкой", `{{ .Values.authn.identityProvider | quote }}`, 1},
		{"имя ключа в тексте отказа", `{{- fail "уберите authn.identityProvider из профиля" -}}`, 0},
		{"проверка присутствия по имени", `{{- if hasKey $authn "identityProvider" -}}`, 0},
		{"комментарий", `{{/* $authn.identityProvider читался здесь */}}`, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			readers, actions := postureReadersIn(map[string]string{"t.tpl": c.text})
			require.Equal(t, c.readers, len(readers), "читателей найдено %v", readers)
			if !strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(c.text, "{{")), "/*") {
				require.Equal(t, 1, actions, "действие шаблона не прочитано")
			}
		})
	}
}

// requireRetiredPostureRefusal — рендер отказал, и отказ называет снятый ключ,
// слово «снят» и шаг «уберите».
func requireRetiredPostureRefusal(t *testing.T, out string, err error, names string) {
	t.Helper()
	require.Errorf(t, err, "рендер принял снятый ключ посадки (%s) — «принято и проигнорировано»:\n%s",
		names, headOf(out))
	for _, want := range []string{names, "снят", "уберите"} {
		require.Containsf(t, out, want, "отказ рендера о снятом ключе не называет %q:\n%s", want, out)
	}
}

// Ч2, путь «профиль значений».
func TestChartRefusesTheRetiredPostureKeyInValues(t *testing.T) {
	for _, v := range []string{"own", "external", ""} {
		t.Run("value="+v, func(t *testing.T) {
			out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, retiredPostureValuesKey+"="+v)
			requireRetiredPostureRefusal(t, out, err, retiredPostureValuesKey)
		})
	}
}

// Ч2, путь «окружение пода»: переменная процесса в картах env и secrets.
func TestChartRefusesTheRetiredPostureVariableInPodEnvironment(t *testing.T) {
	for _, set := range [][]string{
		{"env." + retiredPostureVariable + "=own"},
		{"secrets." + retiredPostureVariable + ".secretName=x", "secrets." + retiredPostureVariable + ".secretKey=y"},
	} {
		t.Run(strings.SplitN(set[0], ".", 2)[0], func(t *testing.T) {
			out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, set...)
			requireRetiredPostureRefusal(t, out, err, retiredPostureVariable)
		})
	}
}

// Законный близнец Ч2: поставляемый профиль без `--set` рендерится.
func TestShippedProfileRendersWithoutARetiredKey(t *testing.T) {
	out, err := renderChartAtAllowingFailure(t, ".", chartProfiles)
	require.NoErrorf(t, err, "поставляемый профиль не рендерится:\n%s", headOf(out))
}

// withoutPostureKey — `--set`, снимающий ключ посадки из слитых значений:
// поставляемый профиль, который его ещё несёт, проверяется так, будто ключа нет.
const withoutPostureKey = retiredPostureValuesKey + "=null"

// Ч3.
func TestEveryShippedProfileRendersTheOwnLaneWithoutThePostureKey(t *testing.T) {
	for _, chain := range shippedProfileChains {
		t.Run(chain[len(chain)-1], func(t *testing.T) {
			out, err := renderChartAtAllowingFailure(t, ".", chain, withoutPostureKey)
			require.NoErrorf(t, err, "профиль без ключа посадки не рендерится — это «не выполнилось»:\n%s", headOf(out))

			rules, objects := chartAlertRules(t, out)
			require.NotZero(t, objects, "в рендере нет объекта правил тревоги — судить нечего")
			names := map[string]bool{}
			for _, r := range rules {
				names[r.Alert] = true
				require.Falsef(t, strings.HasPrefix(r.Alert, "KanameAuthnHook"),
					"рендер без ключа посадки везёт правило хуков поставщика %s — поставщика нет", r.Alert)
			}
			for _, want := range []string{"KanameLoginLaneFailing", "KanameLoginVerifierCapacityExhausted"} {
				require.Truef(t, names[want],
					"рендер без ключа посадки не везёт правило полосы своего входа %s — условие "+
						"на снятом значении перевернулось молча", want)
			}

			hooksPorts := 0
			forEachDoc(t, out, func(doc map[string]any) {
				if kind, _ := doc["kind"].(string); kind != "Service" && kind != "Deployment" {
					return
				}
				if strings.Contains(stringOfDoc(t, doc), "http-hooks") {
					hooksPorts++
				}
			})
			require.Zerof(t, hooksPorts, "рендер без ключа посадки несёт порт хуков поставщика в %d объектах", hooksPorts)
			t.Logf("перепись: правил тревоги %d · объектов правил %d · объектов с портом хуков %d",
				len(rules), objects, hooksPorts)
		})
	}
}

// Ч3, страж токен-эндпоинта: без ключа посадки выключенный эндпоинт — отказ.
func TestChartRefusesADisabledClientTokenEndpointWithoutThePostureKey(t *testing.T) {
	out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, withoutPostureKey, clientTokenEnabledKnob+"=false")
	require.Errorf(t, err, "рендер без ключа посадки собрал выключенный токен-эндпоинт — ключу служебной "+
		"учётки некуда пойти, и отказ пришёл бы уже в кластере:\n%s", headOf(out))
	require.Contains(t, out, clientTokenEnabledKnob)
	require.NotContains(t, out, retiredPostureValuesKey+"=own", "отказ называет снятый ключ посадки условием")
}

// Законный близнец: тот же рендер со включённым эндпоинтом проходит.
func TestChartRendersAnEnabledClientTokenEndpointWithoutThePostureKey(t *testing.T) {
	out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, withoutPostureKey, clientTokenEnabledKnob+"=true")
	require.NoErrorf(t, err, "рендер без ключа посадки со включённым эндпоинтом отказал:\n%s", headOf(out))
}

// stringOfDoc — объект рендера одной строкой для поиска имени порта.
func stringOfDoc(t *testing.T, doc map[string]any) string {
	t.Helper()
	var b strings.Builder
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				b.WriteString(k)
				b.WriteByte(' ')
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		default:
			if s, ok := x.(string); ok {
				b.WriteString(s)
				b.WriteByte(' ')
			}
		}
	}
	walk(doc)
	return b.String()
}
