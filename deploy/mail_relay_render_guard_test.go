// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package deploy_test

// mail_relay_render_guard_test.go — чарт отказывает НА РЕНДЕРЕ боевой посадке
// без почтового узла (kaname#475, остаток предиката).
//
// Страж старта процесса уже отвергает такой пуск строкой требований полосы
// «почтовый узел объявлен» (config.LaneRequirements); без отказа рендера
// установка узнавала об этом только в кластере, падающим подом. Шаблон судит
// то же условие, что процесс: боевой режим (всё, кроме `dev`) и пустой после
// обрезки пробелов `inviteMail.relay` либо `inviteMail.from`.
//
// Каждое отрицание — в паре с законным близнецом, отличающимся одним фактом:
//   - боевой профиль как есть рендерится (заглушки профиля — объявленный узел);
//   - снятый узел, снятый отправитель, снятые оба, узел из одних пробелов —
//     отказ, и текст называет каждый незаданный ключ и боевой режим;
//   - тот же снятый узел вне боевого режима рендерится: пустой узел там законен.
//
// Вход собирается настоящим `helm template`; без helm проба — третья категория.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	mailRelayKey = "inviteMail.relay"
	mailFromKey  = "inviteMail.from"
	// mailRelayRefusal — неизменная часть текста отказа: по ней отказ этого
	// стража отличим от отказа любого другого.
	mailRelayRefusal = "почтовый узел не объявлен"
)

func TestChartRendersTheProductionProfileWithItsMailRelay(t *testing.T) {
	out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, operatorOverlay...)
	require.NoErrorf(t, err, "боевой профиль с объявленным узлом отвергнут рендером:\n%s", headOf(out))
	tree := renderedConfigTree(t, out)
	require.NotEmpty(t, configString(tree, "invite-mail.relay"), "узел профиля не доехал до карты настроек")
	require.NotEmpty(t, configString(tree, "invite-mail.from"), "отправитель профиля не доехал до карты настроек")
}

func TestChartRefusesAProductionInstallWithoutTheMailRelay(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sets    []string
		want    []string
		notWant []string
	}{
		{"сняты узел и отправитель", []string{mailRelayKey + "=", mailFromKey + "="},
			[]string{mailRelayKey, mailFromKey}, nil},
		{"снят узел", []string{mailRelayKey + "="},
			[]string{mailRelayKey}, []string{mailFromKey + " "}},
		{"снят отправитель", []string{mailFromKey + "="},
			[]string{mailFromKey}, []string{mailRelayKey + " "}},
		{"узел из одних пробелов", []string{mailRelayKey + "=   "},
			[]string{mailRelayKey}, nil},
		{"режим production, а не production-strict профиля", []string{"authMode=production", mailRelayKey + "=", mailFromKey + "="},
			[]string{mailRelayKey, mailFromKey, `"production"`}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, withOperatorOverlay(tc.sets...)...)
			requireRenderRefusal(t, out, err, append([]string{mailRelayRefusal, "invite-mail.relay"}, tc.want...)...)
			for _, nw := range tc.notWant {
				require.NotContainsf(t, out, "  "+nw, "отказ называет заданный ключ как незаданный:\n%s", out)
			}
		})
	}
}

// Законный близнец: тот же снятый узел вне боевого режима рендерится, и секции
// узла в карте нет — «полосы нет» там законно и видно счётчиком исходов.
func TestChartRendersADevInstallWithoutTheMailRelay(t *testing.T) {
	out, err := renderChartAtAllowingFailure(t, ".", chartProfiles,
		withOperatorOverlay("authMode=dev", mailRelayKey+"=", mailFromKey+"=")...)
	require.NoErrorf(t, err, "режим разработчика без узла отвергнут рендером — страж судит не боевой старт:\n%s", headOf(out))
	require.False(t, strings.Contains(out, "invite-mail:"), "незаданный узел отрендерен секцией карты настроек")
}
