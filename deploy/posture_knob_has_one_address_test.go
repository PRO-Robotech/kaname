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
// источники окружения пода выводятся в две ступени
// (`pod_env_source_recognizer_test.go`): разбор всех шаблонов чарта называет
// кандидатов — карты, по чьим ключам проходит шаблон, в любой законной форме
// адреса; адрес, который разбор не выводит, — отказ с координатой, а не
// пропуск. Рендер с пробным ключом вида ручки при каждом условии суда решает,
// чей ключ стал ИМЕНЕМ переменной окружения пода, в каких формах и при каком
// условии; кандидат, которого рендер не подтвердил и не опроверг, — находка.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ЕСТЬ
//
//	Р1  (без helm) кандидаты выведены разбором всех шаблонов, и страж шаблона
//	    называет в своём перечне ровно популяцию таблицы — в обе стороны;
//	Р2  (helm) предикат задачи: `env.KANAME_AUTHN__IDENTITY_PROVIDER=own` без
//	    эндпоинта — отказ рендера с канонической координатой;
//	Р3  (helm) близнец одним фактом: накладка `own` с эндпоинтом рендерится,
//	    а та же накладка, где посадка перенесена в окружение, — отказ;
//	Р4  (helm) класс: источники подтверждены рендером, и каждая ручка × каждый
//	    источник — отказ с именем источника и канонической координатой; все
//	    сразу — один перечень; соседняя ручка той же полосы в окружении —
//	    рендер.
package deploy_test

import (
	"fmt"
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

// envNameRe — литерал имени переменной процесса в словаре стража шаблона.
var envNameRe = regexp.MustCompile(`^KANAME_[A-Z0-9_]+$`)

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
// таблицей стража старта в обе стороны и выводит кандидатов в источники
// окружения пода разбором всех шаблонов каталога.
func judgePostureGuardRoster(t *testing.T, dir string) (drift, sources []string, roster map[string]string) {
	t.Helper()
	files := chartTemplates(t, dir)
	cands, err := podEnvSourcesIn(files)
	require.NoError(t, err)
	for _, c := range cands {
		sources = append(sources, c.path)
	}
	require.NotEmpty(t, sources, "в шаблонах чарта не найдено ни одной карты, по чьим ключам шёл бы проход — "+
		"обход пуст, и «ни одной тени» было бы неотличимо от «ни одного прочитанного источника»")

	helpers, ok := files["_helpers.tpl"]
	require.True(t, ok, "в каталоге шаблонов нет _helpers.tpl — стража шаблона читать неоткуда")
	roster, err = guardEnvRoster(helpers)
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
	t.Logf("перепись: кандидатов в источники окружения пода %d (%s) · ручек стража в таблице %d · в перечне шаблона %d",
		len(sources), strings.Join(sources, ", "), len(postureGuardRows(t)), len(roster))
}

// ── helm: общая часть Р2–Р4 ──────────────────────────────────────────────────

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

// postureShadowFindings судит чарт по пути dir: источники окружения пода
// подтверждены рендером, и каждая ручка стража в каждом источнике — в каждой
// показанной форме имени, при первом условии, её показавшем, — отказ правила
// тени с источником и канонической координатой; все сразу — один перечень с
// числом; соседняя ручка — рендер. Кандидат, которого рендер не подтвердил и
// не опроверг, — находка; ручка, которой не достигает ни одна показанная форма
// карты с проходом под условием, — тоже.
func postureShadowFindings(t *testing.T, dir string) (findings []string, renders int) {
	t.Helper()
	cands, err := podEnvSourcesIn(chartTemplates(t, filepath.Join(dir, "templates")))
	require.NoError(t, err)
	require.NotEmpty(t, cands, "кандидатов в источники окружения пода не выведено — обход пуст")
	sources, refuted, unconfirmed, confirmRenders := confirmPodEnvSources(t, dir, cands)
	findings = append(findings, unconfirmed...)
	renders += confirmRenders
	require.NotEmpty(t, sources, "ни один кандидат не подтверждён рендером источником окружения пода — "+
		"суд теней судил бы пустое множество")
	rows := postureGuardRows(t)

	unreachable := 0
	// reached — путь кандидата → ручки, имя которых даёт хоть одна показанная
	// рендером форма; order — пути в порядке источников.
	reached := map[string]map[string]bool{}
	candOf := map[string]envSource{}
	formsOf := map[string][]string{}
	var order []string
	for _, src := range sources {
		if reached[src.path] == nil {
			reached[src.path] = map[string]bool{}
			candOf[src.path] = src
			order = append(order, src.path)
		}
		formsOf[src.path] = append(formsOf[src.path], src.form())
		var all []string
		var judged []postureGuardRow
		var keys []string
		for _, r := range rows {
			key, ok := src.keyFor(r.env)
			if !ok {
				unreachable++
				continue
			}
			reached[src.path][r.env] = true
			sets := valueSets(src.envCandidate, key, r.value)
			out, err := renderChartAtAllowingFailure(t, dir, chartProfiles, src.cond.with(sets...)...)
			renders++
			findings = append(findings, judgeShadow(t, src, src.label(key, r.env), out, err,
				[]postureGuardRow{r}, []string{key})...)
			all = append(all, sets...)
			judged = append(judged, r)
			keys = append(keys, key)
		}
		if len(judged) == 0 {
			continue
		}
		out, err := renderChartAtAllowingFailure(t, dir, chartProfiles, src.cond.with(all...)...)
		renders++
		findings = append(findings, judgeShadow(t, src, src.path+" (все ручки сразу)", out, err, judged, keys)...)
		if err != nil && !strings.Contains(out, fmt.Sprintf("— %d.", len(judged))) {
			findings = append(findings, fmt.Sprintf("%s (все ручки сразу): отказ не называет число теней %d:\n%s",
				src.path, len(judged), headOf(out)))
		}
	}
	// Ручка, имени которой не даёт ни одна показанная форма, молчит, лишь когда
	// каждый проход по карте вне условия и упоминает ключ безусловно: тогда
	// рендер исполнил каждое упоминание, и других форм у карты нет. Иначе форму,
	// которую дала бы невыполненная ветвь, рендер не называет — находка.
	for _, p := range order {
		if !candOf[p].branched {
			continue
		}
		var missed []string
		for _, r := range rows {
			if !reached[p][r.env] {
				missed = append(missed, r.env)
			}
		}
		if len(missed) > 0 {
			findings = append(findings, fmt.Sprintf("кандидат %s: пробный ключ дал имя переменной пода лишь формами %s — "+
				"ручек стража ими недостижимо %d из %d (%s), а проход по карте стоит под условием либо ключ в его теле "+
				"под ветвью или уходит из него: какую форму имени дала бы невыполненная ветвь, рендер не называет — "+
				"источник не подтверждён и не опровергнут", p, strings.Join(formsOf[p], ", "), len(missed), len(rows),
				strings.Join(missed, ", ")))
		}
	}
	out, err := renderChartAtAllowingFailure(t, dir, chartProfiles, withOwnPosture("env.KANAME_AUTHN__DOMAIN=access.example.invalid")...)
	renders++
	if err != nil {
		findings = append(findings, fmt.Sprintf("близнец env.KANAME_AUTHN__DOMAIN: ручка, которую страж шаблона не судит, отвергнута — "+
			"правило шире своего предмета:\n%s", headOf(out)))
	}
	names := make([]string, 0, len(sources))
	for _, s := range sources {
		name := s.path
		if f := s.form(); f != "<ключ>" {
			name += " " + f
		}
		if s.cond.name != podEnvConditions[0].name {
			name += " — " + s.cond.name
		}
		names = append(names, name)
	}
	t.Logf("перепись: кандидатов %d · подтверждено рендером источников %d (%s) · опровергнуто %d (%s) · не подтверждено %d · "+
		"ручек %d · недостижимых пар %d · рендеров %d · находок %d",
		len(cands), len(sources), strings.Join(names, ", "), len(refuted), strings.Join(refuted, ", "), len(unconfirmed),
		len(rows), unreachable, renders, len(findings))
	return findings, renders
}

// judgeShadow — исход одного рендера тени: отказ правилом тени, называющий
// ключ в источнике и координату каждой ручки, — законно; рендер, положивший
// ручку в под, — находка; рендер, ручку в под не положивший, — несостоявшийся
// суд (источник подтверждён, а тень не доехала), тоже находка.
func judgeShadow(t *testing.T, src envSource, what, out string, err error, want []postureGuardRow, keys []string) []string {
	t.Helper()
	switch {
	case err == nil:
		names := podEnvNames(t, out)
		var reached, missing []string
		for _, r := range want {
			if containsName(names, r.env) {
				reached = append(reached, r.env)
				continue
			}
			missing = append(missing, r.env)
		}
		var findings []string
		if len(reached) > 0 {
			findings = append(findings, fmt.Sprintf("%s: рендер прошёл — ручка стража посадки уехала в окружение пода мимо отказа", what))
		}
		if len(missing) > 0 {
			findings = append(findings, fmt.Sprintf("%s: рендер прошёл, а переменной %s в поде нет — источник подтверждён, "+
				"а тень не доехала: суд не выполнился", what, strings.Join(missing, ", ")))
		}
		return findings
	case !strings.Contains(out, postureShadowMark):
		return []string{fmt.Sprintf("%s: рендер отказал, но не правилом тени (нет %q):\n%s", what, postureShadowMark, headOf(out))}
	}
	var findings []string
	for i, r := range want {
		if !strings.Contains(out, src.path+"."+keys[i]) || !strings.Contains(out, r.knob) {
			findings = append(findings, fmt.Sprintf("%s: отказ не называет %s.%s и координату %s:\n%s", what, src.path, keys[i], r.knob, headOf(out)))
		}
	}
	return findings
}

func TestEveryPostureGuardKnobIsRefusedInEveryPodEnvSource(t *testing.T) {
	findings, renders := postureShadowFindings(t, ".")
	require.Emptyf(t, findings, "ручка стража посадки проходит рендер через окружение пода — находок %d:\n%s",
		len(findings), strings.Join(findings, "\n"))
	t.Logf("перепись: ручек %d · рендеров %d · находок 0", len(postureGuardRows(t)), renders)
}
