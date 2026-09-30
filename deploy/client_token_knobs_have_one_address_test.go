// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_token_knobs_have_one_address_test.go — У РУЧЕК СТРАЖА ТОКЕН-ЭНДПОИНТА
// ОДИН АДРЕС: КЛЮЧ ЗНАЧЕНИЙ ЧАРТА. Окружение пода их не несёт (задача #392).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Страж шаблона `kaname-svc.requireClientTokenEndpoint` судит токен-эндпоинт по
// ключам значений (`authn.clientToken.*`). Окружение пода отдаётся процессу как
// есть, а переменная перекрывает файл настроек. Поэтому ручка, объявленная
// переменной, проходила бы рендер, и отказ приходил бы только от стража старта,
// уже в кластере.
//
// ВЫБРАН ВТОРОЙ ВАРИАНТ ЗАДАЧИ: окружение не может нести ручку стража, и отказ
// рендера называет каноническую координату. Довод: судить «обе формы» значило
// бы повторить в шаблоне правило старшинства процесса (переменная перекрывает
// файл) — второе место об одном предмете. Один адрес разойтись с собой не может.
//
// Прежде ручек у стража было на одну больше — ключ посадки личности. Ключ снят
// (kaname#363), и его переменную в окружении пода отвергает отдельное правило
// снятых ручек (`kaname-svc.requireNoRetiredKnobs`, `retired_posture_key_test.go`):
// у снятого ключа адреса нет вовсе, а не «один».
//
// Класс, а не экземпляр: ручки стража — выключатель эндпоинта и его величины,
// и каждая обходит отказ рендера одинаково. Популяция ручек берётся у таблицы
// стража старта (`config.RequiredSettings`), а источники окружения пода судит
// ИСПОЛНЕНИЕ чарта, а не текст шаблонов (`pod_env_execution_test.go`, задача
// #433): пробный ключ в каждой карте дерева значений каждого входа, каждый узел
// управления шаблонов принуждён в обе ветви, и судится итоговое имя каждой
// переменной каждого контейнера. Карта, чей ключ стал именем в любой форме,
// либо судится стражем — и тогда дословно, — либо это находка со входом,
// исполнением и контейнером.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ЕСТЬ
//
//	Р1  (без helm) страж шаблона называет в своём перечне ровно популяцию
//	    таблицы — в обе стороны;
//	Р2  (helm) предикат задачи: `env.KANAME_AUTHN__CLIENT_TOKEN__ENABLED=true`
//	    — отказ рендера с канонической координатой;
//	Р3  (helm) близнец одним фактом: накладка оператора ключами значений
//	    рендерится, а та же накладка, где выключатель перенесён в окружение, —
//	    отказ;
//	Р4  (helm) класс: источник — карта, чей пробный ключ стал именем
//	    переменной пода при каком-либо исполнении; каждая ручка × каждый
//	    источник — отказ с именем источника и канонической координатой, и имя —
//	    ключ дословно; все сразу — один перечень; соседняя ручка вне стража в
//	    окружении — рендер.
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
const postureShadowMark = "ручки стража токен-эндпоинта"

// postureGuardRow — ручка стража: переменная процесса и ключ значений чарта.
type postureGuardRow struct {
	env   string
	knob  string
	value string
}

// postureGuardRows — популяция у таблицы стража старта: все ручки
// токен-эндпоинта. Не выписывается: новая строка таблицы попадает сюда сама.
func postureGuardRows(t *testing.T) []postureGuardRow {
	t.Helper()
	var rows []postureGuardRow
	for _, s := range config.RequiredSettings {
		if !strings.HasPrefix(s.Key, "authn.client-token.") {
			continue
		}
		require.NotEmptyf(t, s.Env, "строка таблицы %s без переменной — источника в окружении у неё нет", s.Key)
		rows = append(rows, postureGuardRow{env: s.Env, knob: valuesKeyOf(s.Key), value: s.Sample})
	}
	require.NotEmpty(t, rows, "в таблице стража старта нет ни одной ручки эндпоинта — обход пуст")
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

// judgePostureGuardRoster сверяет перечень стража шаблона в каталоге шаблонов
// dir с таблицей стража старта в обе стороны.
func judgePostureGuardRoster(t *testing.T, dir string) (drift []string, roster map[string]string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "_helpers.tpl")) // #nosec G304 -- путь из дерева чарта либо t.TempDir
	require.NoError(t, err, "в каталоге шаблонов нет _helpers.tpl — стража шаблона читать неоткуда")
	roster, err = guardEnvRoster(string(b))
	require.NoError(t, err)
	require.NotEmpty(t, roster, "в теле стража %s ни одной пары «переменная → ключ» — сверять не с чем", postureGuardHelper)

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
			drift = append(drift, fmt.Sprintf("%s в перечне стража %s, а в таблице стража старта ручкой эндпоинта не значится — "+
				"отказ без предмета", env, postureGuardHelper))
		}
	}
	sort.Strings(drift)
	return drift, roster
}

func TestPostureGuardNamesEveryShadowOfItsKnobs(t *testing.T) {
	drift, roster := judgePostureGuardRoster(t, "templates")
	require.Emptyf(t, drift, "перечень стража шаблона и таблица стража старта разошлись:\n%s", strings.Join(drift, "\n"))
	t.Logf("перепись: ручек стража в таблице %d · в перечне шаблона %d", len(postureGuardRows(t)), len(roster))
}

// ── helm: общая часть Р2–Р4 ──────────────────────────────────────────────────

// ── Р2 ───────────────────────────────────────────────────────────────────────

func TestChartRefusesTheEndpointSwitchDeclaredThroughThePodEnvironment(t *testing.T) {
	out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, "env.KANAME_AUTHN__CLIENT_TOKEN__ENABLED=true")
	requireRenderRefusal(t, out, err, postureShadowMark, "env.KANAME_AUTHN__CLIENT_TOKEN__ENABLED", clientTokenEnabledKnob)
}

// ── Р3 ───────────────────────────────────────────────────────────────────────

func TestOperatorOverlayMovedIntoTheEnvironmentIsRefused(t *testing.T) {
	_, err := renderChartAtAllowingFailure(t, ".", chartProfiles, operatorOverlay...)
	require.NoError(t, err, "близнец: накладка оператора ключами значений обязана рендериться — иначе отказ ниже ничего не доказал бы")

	moved := []string{"env.KANAME_AUTHN__CLIENT_TOKEN__ENABLED=true"}
	for _, kv := range operatorOverlay {
		if !strings.HasPrefix(kv, clientTokenEnabledKnob+"=") {
			moved = append(moved, kv)
		}
	}
	require.Len(t, moved, len(operatorOverlay), "перенос изменил не ровно один факт")
	out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, moved...)
	requireRenderRefusal(t, out, err, postureShadowMark, "env.KANAME_AUTHN__CLIENT_TOKEN__ENABLED", clientTokenEnabledKnob)
}

// ── Р4 ───────────────────────────────────────────────────────────────────────

// Суд теней — по исполнению чарта (`judgePodEnvByExecution`,
// pod_env_execution_test.go): каждая карта дерева значений каждой посадки при
// каждом принуждённом исполнении ветвей; находка называет посадку, исполнение,
// документ и контейнер.
func TestEveryPostureGuardKnobIsRefusedInEveryPodEnvSource(t *testing.T) {
	findings, census, err := judgePodEnvByExecution(t, ".", podEnvConditions)
	require.NoError(t, err)
	t.Logf("перепись: %s · ручек %d · находок %d", census, len(postureGuardRows(t)), len(findings))
	require.Emptyf(t, findings, "имя переменной пода взято из ключа карты мимо суда стража — находок %d:\n%s",
		len(findings), strings.Join(findings, "\n"))
}
