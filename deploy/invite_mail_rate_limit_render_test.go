// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package deploy_test

// invite_mail_rate_limit_render_test.go — страж рендера чарта (место С1
// решения Р4а) отвергает попытку снять ограничение частоты писем (приёмка
// ID-MAIL-1, MAIL-42, MAIL-43; задача продукта #1775).
//
// Что утверждается, каждое отрицание — в паре с положительным контролем:
//   - молчащий профиль рендерится, и ключей ограничения в карте нет: молчание
//     означает согласие с умолчанием процесса, а не второе объявление величины;
//   - объявленная положительная пара рендерится в карту дословно;
//   - ноль, отрицательное число, слово вместо числа, нулевое либо словесное
//     окно — ОТКАЗ рендера, и текст называет ручку и требование положительного.
//
// Вход собирается настоящим `helm template`; без helm проба — третья категория,
// а на объявленной полосе рендера (deploy/render-guard.sh) — отказ.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInviteMailRateLimit_SilentProfileRendersNoSecondDeclaration(t *testing.T) {
	out := renderStandaloneChart(t, []string{"values.yaml", "values.dev.yaml"})
	require.NotContains(t, out, "mail-rate-limit",
		"молчащий профиль отрендерил ограничение частоты — второе объявление умолчания, которое разойдётся с процессом")
}

func TestInviteMailRateLimit_DeclaredPairIsRendered(t *testing.T) {
	out, err := renderChartAtAllowingFailure(t, ".", []string{"values.yaml", "values.dev.yaml"},
		"invite.mailRateLimit.maxPerWindow=5", "invite.mailRateLimit.window=30m")
	require.NoErrorf(t, err, "законная пара отвергнута рендером:\n%s", out)
	tree := renderedConfigTree(t, out)
	inv, _ := tree["invite"].(map[string]any)
	require.NotNil(t, inv, "раздел invite не отрендерен")
	lim, _ := inv["mail-rate-limit"].(map[string]any)
	require.NotNil(t, lim, "раздел invite.mail-rate-limit не отрендерен")
	require.EqualValues(t, 5, lim["max-per-window"])
	require.Equal(t, "30m", lim["window"])
}

func TestInviteMailRateLimit_RenderRefusesToLiftTheCap(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  string
		knob string
	}{
		{"ноль писем", "invite.mailRateLimit.maxPerWindow=0", "invite.mailRateLimit.maxPerWindow"},
		{"отрицательное число писем", "invite.mailRateLimit.maxPerWindow=-2", "invite.mailRateLimit.maxPerWindow"},
		{"слово вместо числа", "invite.mailRateLimit.maxPerWindow=unlimited", "invite.mailRateLimit.maxPerWindow"},
		{"нулевое окно", "invite.mailRateLimit.window=0s", "invite.mailRateLimit.window"},
		{"отрицательное окно", "invite.mailRateLimit.window=-1h", "invite.mailRateLimit.window"},
		{"слово вместо окна", "invite.mailRateLimit.window=off", "invite.mailRateLimit.window"},
	} {
		out, err := renderChartAtAllowingFailure(t, ".", []string{"values.yaml", "values.dev.yaml"}, tc.set)
		require.Errorf(t, err, "%s: рендер принял величину, снимающую ограничение (%s)", tc.name, tc.set)
		require.Containsf(t, out, tc.knob, "%s: отказ не называет ручку:\n%s", tc.name, out)
		require.Truef(t, strings.Contains(out, "положительн"), "%s: отказ не называет требование положительного значения:\n%s", tc.name, out)
	}
}
