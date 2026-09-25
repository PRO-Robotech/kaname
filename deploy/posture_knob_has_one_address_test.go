// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// posture_knob_has_one_address_test.go — У РУЧЕК СТРАЖА ПОСАДКИ ОДИН АДРЕС:
// КЛЮЧ ЗНАЧЕНИЙ ЧАРТА. Окружение пода их не несёт (задача #392).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Страж шаблона `kaname-svc.requireClientTokenEndpoint` судит посадку `own` и
// токен-эндпоинт по ключам значений (`authn.identityProvider`,
// `authn.clientToken.*`). Окружение пода отдаётся процессу как есть, а
// переменная перекрывает файл настроек. Поэтому посадка, объявленная
// переменной `KANAME_AUTHN__IDENTITY_PROVIDER=own` без эндпоинта, проходила
// рендер, и отказ приходил только от стража старта, уже в кластере.
//
// ВЫБРАН ВТОРОЙ ВАРИАНТ ЗАДАЧИ: окружение не может нести ручку стража, и отказ
// рендера называет каноническую координату. Довод: судить «обе формы» значило
// бы повторить в шаблоне правило старшинства процесса (переменная перекрывает
// файл) — второе место об одном предмете, и не одно: посадку читают ещё карта
// настроек и правила тревоги. Один адрес разойтись с собой не может.
//
// Класс, а не экземпляр: ручек у стража шесть (посадка, выключатель
// эндпоинта и четыре его величины), и каждая обходит отказ рендера одинаково.
// Популяция берётся у таблицы стража старта (`config.RequiredSettings`), а
// источники окружения пода — обходом шаблона развёртывания: всякий
// `range $k, $v := .Values.<карта>`, чей ключ становится `- name:` переменной.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ЕСТЬ
//
//	Р1  (без helm) источники окружения выведены обходом, и страж шаблона
//	    называет в своём перечне ровно популяцию таблицы — в обе стороны;
//	Р2  (helm) предикат задачи: `env.KANAME_AUTHN__IDENTITY_PROVIDER=own` без
//	    эндпоинта — отказ рендера с канонической координатой;
//	Р3  (helm) близнец одним фактом: накладка `own` с эндпоинтом рендерится,
//	    а та же накладка, где посадка перенесена в окружение, — отказ;
//	Р4  (helm) класс: каждая ручка × каждый источник окружения — отказ с именем
//	    источника и канонической координатой; все сразу — один перечень;
//	    соседняя ручка той же полосы в окружении — рендер.
package deploy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// postureGuardHelper — страж шаблона, чьи ручки судятся.
const postureGuardHelper = "kaname-svc.requireClientTokenEndpoint"

// postureShadowMark — чем отказ ЭТОГО правила отличим от прочих отказов.
const postureShadowMark = "ручки стража посадки"

// postureGuardRow — ручка стража: переменная процесса и ключ значений чарта.
type postureGuardRow struct {
	env   string
	knob  string
	value string
}

// postureGuardRows — популяция у таблицы стража старта: посадка и все ручки
// токен-эндпоинта. Не выписывается: новая строка таблицы попадает сюда сама.
func postureGuardRows(t *testing.T) []postureGuardRow {
	t.Helper()
	var rows []postureGuardRow
	for _, s := range config.RequiredSettings {
		if s.Key != config.IdentityProviderSetting && !strings.HasPrefix(s.Key, "authn.client-token.") {
			continue
		}
		require.NotEmptyf(t, s.Env, "строка таблицы %s без переменной — источника в окружении у неё нет", s.Key)
		rows = append(rows, postureGuardRow{env: s.Env, knob: valuesKeyOf(s.Key), value: s.Sample})
	}
	require.NotEmpty(t, rows, "в таблице стража старта нет ни посадки, ни ручек эндпоинта — обход пуст")
	sort.Slice(rows, func(i, j int) bool { return rows[i].env < rows[j].env })
	return rows
}

var (
	envRangeRe = regexp.MustCompile(`^range\s+\$(\w+)\s*,\s*\$\w+\s*:=\s*\.Values\.([A-Za-z][A-Za-z0-9]*)$`)
	envKeyRe   = regexp.MustCompile(`^\$(\w+)$`)
	envNameRe  = regexp.MustCompile(`^KANAME_[A-Z0-9_]+$`)
)

// podEnvSources выводит карты значений, чьи КЛЮЧИ становятся именами
// переменных окружения пода: `range $k, $v := .Values.<карта>`, а в теле —
// `- name: {{ $k }}`. Форма, которую он знает, — единственная, которой шаблон
// развёртывания даёт переменной имя из значений.
func podEnvSources(src string) ([]string, error) {
	actions, _, err := scanTemplateActions(src)
	if err != nil {
		return nil, err
	}
	var out []string
	for i, a := range actions {
		m := envRangeRe.FindStringSubmatch(strings.TrimSpace(a.normalized()))
		if m == nil {
			continue
		}
		for _, b := range actions[i+1:] {
			code := strings.TrimSpace(b.normalized())
			if endBlockRe.MatchString(code) {
				break
			}
			k := envKeyRe.FindStringSubmatch(code)
			if k == nil || k[1] != m[1] {
				continue
			}
			before := src[:b.start]
			lastLine := strings.TrimSpace(before[strings.LastIndexByte(before, '\n')+1:])
			if lastLine == "- name:" {
				out = append(out, m[2])
			}
			break
		}
	}
	sort.Strings(out)
	return out, nil
}

// guardEnvRoster — перечень ручек в теле стража шаблона: пары литералов
// «переменная → ключ значений» его словаря.
func guardEnvRoster(src string) (map[string]string, error) {
	actions, _, err := scanTemplateActions(src)
	if err != nil {
		return nil, err
	}
	roster := map[string]string{}
	depth := -1
	for _, a := range actions {
		code := strings.TrimSpace(a.normalized())
		lits := a.literals()
		switch {
		case depth < 0:
			if switchDefineRe.MatchString(code) && len(lits) > 0 && lits[0] == postureGuardHelper {
				depth = 0
			}
			continue
		case openBlockRe.MatchString(code):
			depth++
		case endBlockRe.MatchString(code):
			if depth == 0 {
				return roster, nil
			}
			depth--
		}
		for i := 0; i+1 < len(lits); i++ {
			if envNameRe.MatchString(lits[i]) {
				roster[lits[i]] = lits[i+1]
				i++
			}
		}
	}
	return roster, nil
}

// ── Р1 ───────────────────────────────────────────────────────────────────────

// judgePostureGuardRoster сверяет перечень стража шаблона в каталоге dir с
// таблицей стража старта в обе стороны и выводит источники окружения пода.
func judgePostureGuardRoster(t *testing.T, dir string) (drift, sources []string, roster map[string]string) {
	t.Helper()
	deployment, err := os.ReadFile(filepath.Join(dir, "deployment.yaml")) // #nosec G304 -- путь из дерева чарта либо t.TempDir
	require.NoError(t, err)
	sources, err = podEnvSources(string(deployment))
	require.NoError(t, err)
	require.NotEmpty(t, sources, "в шаблоне развёртывания не найдено ни одной карты, дающей имя переменной — "+
		"обход пуст, и «ни одной тени» было бы неотличимо от «ни одного прочитанного источника»")

	helpers, err := os.ReadFile(filepath.Join(dir, "_helpers.tpl")) // #nosec G304 -- путь из дерева чарта либо t.TempDir
	require.NoError(t, err)
	roster, err = guardEnvRoster(string(helpers))
	require.NoError(t, err)

	want := map[string]bool{}
	for _, r := range postureGuardRows(t) {
		want[r.env] = true
		switch got, ok := roster[r.env]; {
		case !ok:
			drift = append(drift, fmt.Sprintf("%s (ручка %s) не значится в перечне стража %s — переменная обойдёт отказ рендера",
				r.env, r.knob, postureGuardHelper))
		case got != r.knob:
			drift = append(drift, fmt.Sprintf("%s: страж называет координатой %q, таблица стража старта — %q", r.env, got, r.knob))
		}
	}
	for env := range roster {
		if !want[env] {
			drift = append(drift, fmt.Sprintf("%s в перечне стража %s, а в таблице стража старта ручкой посадки не значится — "+
				"отказ без предмета", env, postureGuardHelper))
		}
	}
	sort.Strings(drift)
	return drift, sources, roster
}

func TestPostureGuardNamesEveryShadowOfItsKnobs(t *testing.T) {
	drift, sources, roster := judgePostureGuardRoster(t, "templates")
	require.Emptyf(t, drift, "перечень стража шаблона и таблица стража старта разошлись:\n%s", strings.Join(drift, "\n"))
	t.Logf("перепись: источников окружения пода %d (%s) · ручек стража в таблице %d · в перечне шаблона %d",
		len(sources), strings.Join(sources, ", "), len(postureGuardRows(t)), len(roster))
}

// ── helm: общая часть Р2–Р4 ──────────────────────────────────────────────────

// shadowSets — `--set`, кладущие ручку в названный источник окружения. У
// `secrets` значение — ссылка на объект Secret, иначе рендер отказал бы
// раньше и не тем.
func shadowSets(source string, r postureGuardRow) []string {
	if source == "secrets" {
		return []string{
			fmt.Sprintf("secrets.%s.secretName=kaname-authn", r.env),
			fmt.Sprintf("secrets.%s.secretKey=%s", r.env, strings.ToLower(r.env)),
		}
	}
	return []string{fmt.Sprintf("%s.%s=%s", source, r.env, strings.ReplaceAll(r.value, ",", `\,`))}
}

// ── Р2 ───────────────────────────────────────────────────────────────────────

func TestChartRefusesOwnPostureDeclaredThroughThePodEnvironment(t *testing.T) {
	out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, "env.KANAME_AUTHN__IDENTITY_PROVIDER=own")
	requireRenderRefusal(t, out, err, postureShadowMark, "env.KANAME_AUTHN__IDENTITY_PROVIDER", identityProviderKnob)
}

// ── Р3 ───────────────────────────────────────────────────────────────────────

func TestOwnPostureOverlayMovedIntoTheEnvironmentIsRefused(t *testing.T) {
	_, err := renderChartAtAllowingFailure(t, ".", chartProfiles, ownPostureOverlay...)
	require.NoError(t, err, "близнец: накладка `own` ключами значений обязана рендериться — иначе отказ ниже ничего не доказал бы")

	moved := []string{"env.KANAME_AUTHN__IDENTITY_PROVIDER=own"}
	for _, kv := range ownPostureOverlay {
		if !strings.HasPrefix(kv, identityProviderKnob+"=") {
			moved = append(moved, kv)
		}
	}
	require.Len(t, moved, len(ownPostureOverlay), "перенос изменил не ровно один факт")
	out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, moved...)
	requireRenderRefusal(t, out, err, postureShadowMark, "env.KANAME_AUTHN__IDENTITY_PROVIDER", identityProviderKnob)
}

// ── Р4 ───────────────────────────────────────────────────────────────────────

// postureShadowFindings судит чарт по пути dir: каждая ручка стража в каждом
// источнике окружения — отказ правила тени с источником и канонической
// координатой; все сразу — один перечень с числом; соседняя ручка — рендер.
func postureShadowFindings(t *testing.T, dir string) (findings []string, renders int) {
	t.Helper()
	deployment, err := os.ReadFile(filepath.Join(dir, "templates", "deployment.yaml")) // #nosec G304 -- путь из дерева чарта либо t.TempDir
	require.NoError(t, err)
	sources, err := podEnvSources(string(deployment))
	require.NoError(t, err)
	require.NotEmpty(t, sources, "источников окружения пода не выведено — обход пуст")
	rows := postureGuardRows(t)

	judge := func(what string, out string, err error, source string, want []postureGuardRow) {
		switch {
		case err == nil:
			findings = append(findings, fmt.Sprintf("%s: рендер прошёл — ручка стража посадки уехала в окружение пода мимо отказа", what))
		case !strings.Contains(out, postureShadowMark):
			findings = append(findings, fmt.Sprintf("%s: рендер отказал, но не правилом тени (нет %q):\n%s", what, postureShadowMark, headOf(out)))
		default:
			for _, r := range want {
				if !strings.Contains(out, source+"."+r.env) || !strings.Contains(out, r.knob) {
					findings = append(findings, fmt.Sprintf("%s: отказ не называет %s.%s и координату %s:\n%s", what, source, r.env, r.knob, headOf(out)))
				}
			}
		}
	}
	for _, source := range sources {
		var all []string
		for _, r := range rows {
			out, err := renderChartAtAllowingFailure(t, dir, chartProfiles, withOwnPosture(shadowSets(source, r)...)...)
			renders++
			judge(source+"."+r.env, out, err, source, []postureGuardRow{r})
			all = append(all, shadowSets(source, r)...)
		}
		out, err := renderChartAtAllowingFailure(t, dir, chartProfiles, withOwnPosture(all...)...)
		renders++
		judge(source+" (все ручки сразу)", out, err, source, rows)
		if err != nil && !strings.Contains(out, fmt.Sprintf("— %d.", len(rows))) {
			findings = append(findings, fmt.Sprintf("%s (все ручки сразу): отказ не называет число теней %d:\n%s", source, len(rows), headOf(out)))
		}
	}
	out, err := renderChartAtAllowingFailure(t, dir, chartProfiles, withOwnPosture("env.KANAME_AUTHN__DOMAIN=access.example.invalid")...)
	renders++
	if err != nil {
		findings = append(findings, fmt.Sprintf("близнец env.KANAME_AUTHN__DOMAIN: ручка, которую страж шаблона не судит, отвергнута — "+
			"правило шире своего предмета:\n%s", headOf(out)))
	}
	return findings, renders
}

func TestEveryPostureGuardKnobIsRefusedInEveryPodEnvSource(t *testing.T) {
	findings, renders := postureShadowFindings(t, ".")
	require.Emptyf(t, findings, "ручка стража посадки проходит рендер через окружение пода — находок %d:\n%s",
		len(findings), strings.Join(findings, "\n"))
	t.Logf("перепись: ручек %d · рендеров %d · находок 0", len(postureGuardRows(t)), renders)
}
