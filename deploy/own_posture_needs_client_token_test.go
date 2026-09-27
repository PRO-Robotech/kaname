// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_posture_needs_client_token_test.go — ЧАРТ НЕ СОБИРАЕТ ПОСАДКУ `own` БЕЗ
// ТОКЕН-ЭНДПОИНТА ПЛАТФОРМЫ И НЕ СОБИРАЕТ ВКЛЮЧЁННЫЙ ЭНДПОИНТ БЕЗ ЕГО ВЕЛИЧИН.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (задача #337, предикат 2)
//
// Посадка `own` исполнима только с включённым токен-эндпоинтом платформы, и
// страж старта процесса другую комбинацию не поднимает (строка таблицы
// требований полос, `config.LaneRequirements`). Пока чарт эту комбинацию
// СОБИРАЕТ, отказ приходит уже в кластере, после выкатки. Поэтому чарт обязан
// быть на неё неспособен: рендер отказывает и называет обе ручки — ту же пару,
// что называет страж процесса.
//
// Вторая ось — величины включённого эндпоинта. Профиля `own` в поставке нет
// (INSTALL.md §1): перевод — накладка оператора, и объявить величины негде,
// кроме неё. Поэтому включённый эндпоинт без величин тоже отвергается рендером,
// одним перечнем. Шаблон судит только ОБЪЯВЛЕННОСТЬ; согласованность величин
// (адресат по умолчанию — член перечня, срок не выше потолка платформы, потолок
// тела положителен) остаётся предметом стража старта, и второго места о ней
// здесь не заводится.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ЕСТЬ
//
//	О1  own без эндпоинта — отказ рендера с обеими ручками; ручка не задана
//	    профилем и ручка задана ложью — два входа одного отказа;
//	О2  законный близнец: own с эндпоинтом и его величинами — рендер проходит,
//	    блок в карте настроек, и вход принимает страж старта;
//	О3  external без блока — рендер проходит, блока нет, явная ложь и явный
//	    external дают тот же рендер байт в байт;
//	О4  включённый эндпоинт без величин — отказ рендера; ПОПУЛЯЦИЯ величин
//	    берётся у стража (`config.RequiredSettings`), а не выписывается: каждая
//	    недостающая названа, названная — только она.
//
// Пода проба НЕ поднимает: об установке в кластере она не утверждает ничего.
package deploy_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/multierr"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/testsupport/postureoverlay"
)

// Ручки пары — ключи ЗНАЧЕНИЙ чарта, как их пишет оператор.
const (
	identityProviderKnob   = "authn.identityProvider"
	clientTokenEnabledKnob = "authn.clientToken.enabled"
)

// ownPostureOverlay — накладка оператора, переводящая боевую цепочку на `own`
// (INSTALL.md §1): посадка, включённый эндпоинт и его четыре величины.
//
// Берётся у ЕДИНСТВЕННОГО источника накладок (`postureoverlay.Own`): её же
// читает гейт покрытия полос, засчитывая посадку, объявленную накладкой,
// объявленной (kaname#232). Своя копия здесь разошлась бы с его молча.
var ownPostureOverlay = postureoverlay.Own.Sets()

// withOwnPosture — накладка `own` плюс названные `--set`; копия, а не общий
// срез: append в общий срез переписал бы его соседям.
func withOwnPosture(extra ...string) []string {
	return append(append([]string{}, ownPostureOverlay...), extra...)
}

// requireRenderRefusal — рендер ОТКАЗАЛ, и текст отказа несёт каждую названную
// подстроку. Отказ без неё — отказ не о том: читатель пошёл бы чинить не то.
func requireRenderRefusal(t *testing.T, out string, err error, want ...string) {
	t.Helper()
	require.Errorf(t, err, "рендер прошёл — чарт собрал вход, который обязан был отвергнуть:\n%s", headOf(out))
	for _, w := range want {
		require.Containsf(t, out, w, "отказ рендера не называет %q:\n%s", w, out)
	}
}

// headOf — начало рендера для текста отказа: целиком он нечитаем.
func headOf(s string) string {
	const limit = 2000
	if len(s) > limit {
		return s[:limit] + "\n…"
	}
	return s
}

// ── О1 ───────────────────────────────────────────────────────────────────────

func TestChartRefusesOwnPostureWithoutTheClientTokenEndpoint(t *testing.T) {
	cases := []struct {
		name string
		sets []string
	}{
		// Боевой профиль ручку не задаёт; ложь приходит из базовых значений.
		{name: "ручка эндпоинта не задана профилем", sets: []string{identityProviderKnob + "=own"}},
		{name: "ручка эндпоинта задана ложью", sets: []string{identityProviderKnob + "=own", clientTokenEnabledKnob + "=false"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, c.sets...)
			requireRenderRefusal(t, out, err, identityProviderKnob, clientTokenEnabledKnob)
		})
	}
}

// ── О2 ───────────────────────────────────────────────────────────────────────

func TestChartRendersOwnPostureWithTheClientTokenEndpoint(t *testing.T) {
	// Накладка объявляет, ПОВЕРХ ЧЕГО она ложится, и рендер кладёт её ровно
	// туда: иначе гейт покрытия полос засчитывал бы посадку по накладке поверх
	// профиля, поверх которого её никто не рендерил.
	require.Equal(t, chartProfiles[len(chartProfiles)-1], postureoverlay.Own.Base(),
		"накладка `own` объявляет своим профилем не тот, поверх которого её рендерит эта проба")
	rendered := renderStandaloneChart(t, chartProfiles, ownPostureOverlay...)
	in := readRenderedInput(t, rendered)
	tree := renderedConfigTree(t, rendered)

	require.Equal(t, "own", configString(tree, "authn.identity-provider"),
		"накладка не перевела рендер на `own` — близнец проверял бы не ту посадку")
	require.Equal(t, true, at(tree, "authn", "client-token", "enabled"),
		"под `own` с включённым эндпоинтом блок authn.client-token в карте настроек не несёт enabled: true")
	want := map[string]any{
		"allowed-audiences": "registry.example.invalid,https://access.example.invalid",
		"default-audience":  "https://access.example.invalid",
		"token-ttl":         "15m",
		"body-ceiling":      65536,
	}
	for key, value := range want {
		require.Equalf(t, value, at(tree, "authn", "client-token", key),
			"authn.client-token.%s в карте настроек не та, что назвала накладка", key)
	}

	require.NoError(t, renderedVerdict(t, in),
		"накладка `own`, названная INSTALL.md §1, отрендерена и не принята стражем старта: "+
			"под с этим входом не поднимется")
	t.Logf("перепись: накладка %d ключей · документов рендера %d · величин блока %d",
		len(ownPostureOverlay), in.Docs, len(want))
}

// ── О3 ───────────────────────────────────────────────────────────────────────

func TestExternalPostureRenderCarriesNoClientTokenBlock(t *testing.T) {
	asDelivered := renderStandaloneChart(t, chartProfiles)
	in := readRenderedInput(t, asDelivered)
	require.Equal(t, "external", configString(renderedConfigTree(t, asDelivered), "authn.identity-provider"),
		"боевой профиль больше не стоит на `external` — близнец проверял бы не ту посадку")
	require.NotContains(t, in.ConfigBody, "client-token",
		"под `external` с невключённым эндпоинтом карта настроек несёт блок authn.client-token")

	for _, sets := range [][]string{
		{clientTokenEnabledKnob + "=false"},
		{identityProviderKnob + "=external"},
		{identityProviderKnob + "=external", clientTokenEnabledKnob + "=false"},
	} {
		require.Equalf(t, asDelivered, renderStandaloneChart(t, chartProfiles, sets...),
			"рендер боевого профиля с %v отличается от поставляемого: названная явно ложь "+
				"обязана значить то же, что умолчание", sets)
	}
	t.Logf("перепись: байт рендера %d · близнецов, совпавших байт в байт, 3", len(asDelivered))
}

// ── О4 ───────────────────────────────────────────────────────────────────────

// clientTokenValueRows — строки таблицы стража о величинах эндпоинта: те, что
// требуются только при включённом эндпоинте.
func clientTokenValueRows(t *testing.T) []config.RequiredSetting {
	t.Helper()
	var rows []config.RequiredSetting
	for _, s := range config.RequiredSettings {
		if s.Conditional && strings.HasPrefix(s.Key, "authn.client-token.") {
			rows = append(rows, s)
		}
	}
	require.NotEmpty(t, rows, "в таблице стража нет ни одной величины эндпоинта — "+
		"обход пуст, и «ни одной ненайденной» было бы неотличимо от «ни одной прочитанной»")
	sort.Slice(rows, func(i, j int) bool { return rows[i].Key < rows[j].Key })
	return rows
}

// valuesKeyOf — ключ значений чарта для ключа настройки: сегменты через дефис
// пишутся верблюжьим регистром (`client-token.token-ttl` → `clientToken.tokenTtl`).
func valuesKeyOf(configKey string) string {
	segs := strings.Split(configKey, ".")
	for i, seg := range segs {
		parts := strings.Split(seg, "-")
		for j := 1; j < len(parts); j++ {
			if parts[j] != "" {
				parts[j] = strings.ToUpper(parts[j][:1]) + parts[j][1:]
			}
		}
		segs[i] = strings.Join(parts, "")
	}
	return strings.Join(segs, ".")
}

// valueSetOf — `--set` строки образцом стража; запятая в образце экранируется,
// иначе `--set` разрезал бы перечень на два ключа.
func valueSetOf(row config.RequiredSetting) string {
	return valuesKeyOf(row.Key) + "=" + strings.ReplaceAll(row.Sample, ",", `\,`)
}

func TestChartRefusesAnEnabledClientTokenWithoutItsValues(t *testing.T) {
	rows := clientTokenValueRows(t)
	var renders int

	for _, posture := range []string{"own", "external"} {
		base := []string{identityProviderKnob + "=" + posture, clientTokenEnabledKnob + "=true"}

		t.Run(posture+"/ни одной величины", func(t *testing.T) {
			out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, base...)
			renders++
			want := []string{clientTokenEnabledKnob}
			for _, r := range rows {
				want = append(want, valuesKeyOf(r.Key), r.Key)
			}
			requireRenderRefusal(t, out, err, want...)
		})

		for _, missing := range rows {
			t.Run(posture+"/без "+missing.Key, func(t *testing.T) {
				sets := append([]string{}, base...)
				for _, r := range rows {
					if r.Key != missing.Key {
						sets = append(sets, valueSetOf(r))
					}
				}
				out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, sets...)
				renders++
				requireRenderRefusal(t, out, err, valuesKeyOf(missing.Key), missing.Key)
				var named error
				for _, r := range rows {
					if r.Key != missing.Key && strings.Contains(out, r.Key) {
						named = multierr.Append(named, fmt.Errorf("%s", r.Key))
					}
				}
				require.NoErrorf(t, named, "отказ называет величины, которые накладка задала — "+
					"оператор пошёл бы задавать уже заданное:\n%s", out)
			})
		}

		t.Run(posture+"/все величины", func(t *testing.T) {
			sets := append([]string{}, base...)
			for _, r := range rows {
				sets = append(sets, valueSetOf(r))
			}
			out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, sets...)
			renders++
			require.NoErrorf(t, err, "включённый эндпоинт со всеми величинами стража отвергнут "+
				"рендером — шаблон строже стража:\n%s", out)
		})
	}
	t.Logf("перепись: величин эндпоинта в таблице стража %d · посадок 2 · рендеров %d", len(rows), renders)
}
