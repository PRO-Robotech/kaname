// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// invite_mail_rate_limit_test.go — ограничение частоты писем на адрес
// (приёмка ID-MAIL-1, Р14, MAIL-42, MAIL-43; задача продукта #1775).
//
// Три утверждения, и каждое стоит в паре с противоположным:
//   - молчащий профиль ограничение НЕ снимает: умолчание непустое и положительное
//     (MAIL-42), — и объявленная величина применяется;
//   - ноль и отрицательное отвергаются стражем старта с именем ручки (MAIL-43),
//     — и положительная величина проходит;
//   - слова «без ограничения» в словаре ручки нет: явный ноль есть попытка снять
//     ограничение, и она отвергается, а не обращается в умолчание молча. Это
//     отличие от `invite.ttl`, где ноль читается как «не объявлено»: здесь
//     умолчание объявлено ЗАГРУЗЧИКУ, поэтому ноль до поля доезжает только
//     написанным рукой.

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

func TestInviteMailRateLimit_SilentPostureKeepsTheLimit(t *testing.T) {
	cfg, err := config.Load("")
	require.NoError(t, err)
	lim := cfg.Invite.MailRateLimit
	require.Greater(t, lim.MaxPerWindow, 0,
		"молчащий профиль дал %d писем на адрес за окно — ограничение снято молчанием", lim.MaxPerWindow)
	require.Greater(t, lim.Window, time.Duration(0),
		"молчащий профиль дал окно %s — ограничение снято молчанием", lim.Window)
	require.NoError(t, cfg.Invite.Validate(), "молчание профиля отвергнуто стражем")
}

func TestInviteMailRateLimit_DeclaredValueWins(t *testing.T) {
	t.Setenv("KANAME_INVITE__MAIL_RATE_LIMIT__MAX_PER_WINDOW", "11")
	t.Setenv("KANAME_INVITE__MAIL_RATE_LIMIT__WINDOW", "90m")
	cfg, err := config.Load("")
	require.NoError(t, err)
	require.Equal(t, 11, cfg.Invite.MailRateLimit.MaxPerWindow, "объявленная величина не применилась")
	require.Equal(t, 90*time.Minute, cfg.Invite.MailRateLimit.Window, "объявленное окно не применилось")
	require.NoError(t, cfg.Invite.Validate())
}

func TestInviteMailRateLimit_NonPositiveIsRefusedAtStart(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		lim  config.InviteMailRateLimitConfig
		knob string
	}{
		{"ноль писем", config.InviteMailRateLimitConfig{MaxPerWindow: 0, Window: time.Hour}, "invite.mail-rate-limit.max-per-window"},
		{"отрицательное число писем", config.InviteMailRateLimitConfig{MaxPerWindow: -1, Window: time.Hour}, "invite.mail-rate-limit.max-per-window"},
		{"нулевое окно", config.InviteMailRateLimitConfig{MaxPerWindow: 3, Window: 0}, "invite.mail-rate-limit.window"},
		{"отрицательное окно", config.InviteMailRateLimitConfig{MaxPerWindow: 3, Window: -time.Minute}, "invite.mail-rate-limit.window"},
	} {
		err := config.InviteConfig{MailRateLimit: tc.lim}.Validate()
		require.Error(t, err, "%s: принято — страж зелен при входе, снимающем ограничение", tc.name)
		require.Contains(t, err.Error(), tc.knob, "%s: отказ не называет ручку", tc.name)
		require.Contains(t, strings.ToLower(err.Error()), "positive", "%s: отказ не называет требование положительного значения", tc.name)
	}
	// Положительный контроль: законная пара проходит.
	require.NoError(t, config.InviteConfig{MailRateLimit: config.InviteMailRateLimitConfig{MaxPerWindow: 1, Window: time.Second}}.Validate())
}

// Явный ноль, доехавший переменной окружения, — ОТКАЗ, а не умолчание: у
// ручки нет значения «без ограничения».
func TestInviteMailRateLimit_ExplicitZeroIsNotTheDefault(t *testing.T) {
	t.Setenv("KANAME_INVITE__MAIL_RATE_LIMIT__MAX_PER_WINDOW", "0")
	cfg, err := config.Load("")
	require.NoError(t, err, "загрузка не судит величины — судит страж")
	require.Equal(t, 0, cfg.Invite.MailRateLimit.MaxPerWindow, "явный ноль обращён в умолчание молча")
	require.Error(t, cfg.Invite.Validate(), "явный ноль принят стражем")
}
