// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_token_endpoint_chart_test.go — ЧАРТ НЕ СОБИРАЕТ БОЕВУЮ УСТАНОВКУ БЕЗ
// ТОКЕН-ЭНДПОИНТА ПЛАТФОРМЫ И НЕ СОБИРАЕТ ВКЛЮЧЁННЫЙ ЭНДПОИНТ БЕЗ ЕГО ВЕЛИЧИН.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (задачи #337, предикат 2; #363)
//
// Ключ служебной учётки обменивается на токен токен-эндпоинтом платформы, и
// другого исполнителя выдачи у службы нет: страж старта процесса боевой старт
// без эндпоинта не поднимает (строка `config.LaneRequirements`). Пока чарт эту
// комбинацию СОБИРАЕТ, отказ приходит уже в кластере, после выкатки. Поэтому
// чарт обязан быть на неё неспособен. Прежде условием стража была посадка
// `own`; посадка у службы одна (kaname#363), и условием стал боевой режим.
//
// Вторая ось — величины включённого эндпоинта. Боевой профиль объявляет их
// заглушками (#424, INSTALL.md §1), накладка оператора их переопределяет, и
// снятая любая из них — отказ рендера, одним перечнем. Шаблон судит только
// ОБЪЯВЛЕННОСТЬ; согласованность величин (адресат по умолчанию — член перечня,
// срок не выше потолка платформы, потолок тела положителен) остаётся предметом
// стража старта, и второго места о ней здесь не заводится.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ЕСТЬ
//
//	О1  боевой профиль с выключенным эндпоинтом — отказ рендера, называющий
//	    ручку эндпоинта; законный близнец — тот же вход в режиме разработчика
//	    рендерится (отличие одно — режим; прежде близнецом служила посадка
//	    внешнего поставщика, которой больше нет);
//	О2  законный близнец: накладка оператора с эндпоинтом и его величинами —
//	    рендер проходит, блок в карте настроек, и вход принимает страж старта;
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
)

// clientTokenEnabledKnob — выключатель эндпоинта: ключ ЗНАЧЕНИЙ чарта, как
// его пишет оператор.
const clientTokenEnabledKnob = "authn.clientToken.enabled"

// operatorOverlay — накладка оператора поверх боевого профиля (INSTALL.md §1):
// включённый токен-эндпоинт платформы, его четыре величины выдачи и шесть
// величин темпа поверхности выдачи (kaname#315) — своими числами вместо
// заглушек профиля.
//
// Величины согласованы с заглушками боевого профиля, а не взяты образцами
// таблицы стража: образец перечня адресатов называет адресат докерной полосы
// ДРУГОЙ установки, и страж старта, требующий его внутри перечня, отверг бы
// накладку поверх ЭТОГО профиля.
//
// Прежде накладка жила общим пакетом и переводила профиль на посадку `own`; у
// неё было два читателя — эта проба и гейт покрытия полос посадки. Посадка у
// службы одна (kaname#363), гейт снят вместе с осью, и читатель у накладки
// остался один — этот каталог.
var operatorOverlay = []string{
	"authn.clientToken.enabled=true",
	`authn.clientToken.allowedAudiences=registry.example.invalid\,https://access.example.invalid`,
	"authn.clientToken.defaultAudience=https://access.example.invalid",
	"authn.clientToken.tokenTtl=15m",
	"authn.clientToken.bodyCeiling=65536",
	// Темп поверхности выдачи — числа §3 приёмки ceremony-pace-is-named-by-number.md.
	"authn.clientToken.inFlightCeiling=32",
	"authn.clientToken.exchangesPerClientPerSec=5",
	"authn.clientToken.failedProofsPerSource=50",
	"authn.clientToken.failedProofWindow=15m",
	"authn.clientToken.authorizePerSourcePerSec=10",
	"authn.clientToken.authorizeInFlightCeiling=32",
}

// withOperatorOverlay — накладка оператора плюс названные `--set`; копия, а
// не общий срез: append в общий срез переписал бы его соседям.
func withOperatorOverlay(extra ...string) []string {
	return append(append([]string{}, operatorOverlay...), extra...)
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

func TestChartRefusesAProductionInstallWithoutTheClientTokenEndpoint(t *testing.T) {
	out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, clientTokenEnabledKnob+"=false")
	requireRenderRefusal(t, out, err, clientTokenEnabledKnob)
	require.NotContains(t, out, "authn.identityProvider", "отказ называет снятый ключ посадки условием")
}

// Законный близнец О1: тот же вход в режиме разработчика рендерится — страж
// судит боевой старт, а не выключатель сам по себе.
func TestChartRendersADevInstallWithoutTheClientTokenEndpoint(t *testing.T) {
	out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, clientTokenEnabledKnob+"=false", "authMode=dev")
	require.NoErrorf(t, err, "режим разработчика с выключенным эндпоинтом отвергнут рендером — страж судит "+
		"не боевой старт, а выключатель:\n%s", headOf(out))
}

// ── О2 ───────────────────────────────────────────────────────────────────────

func TestChartRendersTheOperatorOverlayWithTheClientTokenEndpoint(t *testing.T) {
	rendered := renderStandaloneChart(t, chartProfiles, operatorOverlay...)
	in := readRenderedInput(t, rendered)
	tree := renderedConfigTree(t, rendered)

	require.Empty(t, configString(tree, "authn.identity-provider"),
		"карта настроек несёт снятый ключ посадки — загрузчик процесса отверг бы её при старте")
	require.Equal(t, true, at(tree, "authn", "client-token", "enabled"),
		"с включённым эндпоинтом блок authn.client-token в карте настроек не несёт enabled: true")
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
		"накладка оператора, названная INSTALL.md §1, отрендерена и не принята стражем старта: "+
			"под с этим входом не поднимется")
	t.Logf("перепись: накладка %d ключей · документов рендера %d · величин блока %d",
		len(operatorOverlay), in.Docs, len(want))
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

	// Величины, которые боевой профиль объявляет заглушками, снимаются явно:
	// иначе «без величины» проверяло бы профиль, в котором она есть.
	unset := make([]string, 0, len(rows))
	for _, r := range rows {
		unset = append(unset, valuesKeyOf(r.Key)+"=null")
	}
	for _, posture := range []string{"боевой"} {
		base := append([]string{clientTokenEnabledKnob + "=true"}, unset...)

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
			// KN-PACE-38b: карта настроек несёт каждую величину дословно — рендер,
			// прошедший и потерявший ключ, отдал бы процессу нулевую величину.
			tree := renderedConfigTreeOf(out)
			require.NotNil(t, tree, "в рендере нет карты настроек")
			for _, r := range rows {
				require.Equalf(t, r.Sample, configScalar(tree, r.Key),
					"карта настроек не несёт %s дословно", r.Key)
			}
		})
	}
	t.Logf("перепись: величин эндпоинта в таблице стража %d · профилей 1 · рендеров %d", len(rows), renders)
}

// configScalar — значение по точечному ключу карты настроек строкой, какого бы
// типа оно ни было в YAML; ключа нет — пустая строка.
func configScalar(tree map[string]any, key string) string {
	cur := any(tree)
	for _, seg := range strings.Split(key, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		if cur, ok = m[seg]; !ok {
			return ""
		}
	}
	return fmt.Sprint(cur)
}

// TestKNPACE39_ProdProfileDeclaresTheIssuingListenerMode — боевой профиль
// объявляет режим слушателя выдачи `optional-mutual` и корень внутреннего УЦ
// для проверки клиентских сертификатов (приёмка
// ceremony-pace-is-named-by-number.md, KN-PACE-39): без режима собранная
// церемония не стартует, а без корня режим не собирается.
func TestKNPACE39_ProdProfileDeclaresTheIssuingListenerMode(t *testing.T) {
	in := readRenderedInput(t, renderStandaloneChart(t, chartProfiles))
	require.Equal(t, config.IssuingListenerRequestingModeName(), in.Envs["KANAME_REGISTRYTOKEN_SERVER_MTLS_CLIENTAUTHMODE"],
		"окружение пода не объявляет режим слушателя выдачи")
	roots := in.Envs["KANAME_REGISTRYTOKEN_SERVER_MTLS_CLIENTCAFILES"]
	require.NotEmpty(t, roots, "окружение пода не несёт корня УЦ для проверки клиентских сертификатов слушателя выдачи")
	var mounted bool
	for _, m := range in.Mounts {
		if strings.HasPrefix(roots, strings.TrimSuffix(m, "/")+"/") {
			mounted = true
		}
	}
	require.Truef(t, mounted, "корень %s не лежит ни под одним томом контейнера %v", roots, in.Mounts)
}
