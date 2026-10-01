// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// invite_test.go — срок строки приглашения: ручка таблицы границ Р8 без
// умолчания (приёмка NTF-2 Р8, замысел З23). Молчащий профиль — отказ старта с
// именем ключа; величина вне [1 сут, 30 сут] — отказ с названной границой;
// значения «без срока» в словаре нет.
//
// Прежде у ручки было умолчание (неделя) и ноль читался как «не объявлено».
// С таблицей границ отсутствие представимо отдельно от значения (указатель), и
// подставленная величина предметом стража быть не может — она зелена при любом
// входе. Ориентир базового профиля — те же семь суток, но живёт он в профиле.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// TestInviteTTL_SilentPostureIsRefused — профиль о сроке не высказался: отказ
// называет ключ и переменную.
func TestInviteTTL_SilentPostureIsRefused(t *testing.T) {
	cfg := goodEndpoints(config.ModeProduction, "require")
	require.NoError(t, cfg.ValidateMailBounds(), "близнец: срок объявлен — старт")
	cfg.Invite.TTL = nil
	err := cfg.ValidateMailBounds()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invite.ttl must be declared")
	require.Contains(t, err.Error(), "KANAME_INVITE__TTL")
}

// TestInviteTTL_BoundsAreInclusive — обе стороны каждой границы.
func TestInviteTTL_BoundsAreInclusive(t *testing.T) {
	for _, c := range []struct {
		ttl time.Duration
		ok  bool
	}{
		{24 * time.Hour, true},
		{30 * 24 * time.Hour, true},
		{24*time.Hour - time.Second, false},
		{30*24*time.Hour + time.Second, false},
		{0, false},
		{-time.Second, false},
	} {
		cfg := goodEndpoints(config.ModeProduction, "require")
		cfg.Invite.TTL = ref(c.ttl)
		err := cfg.ValidateMailBounds()
		if c.ok {
			require.NoError(t, err, "срок %s в границах", c.ttl)
			continue
		}
		require.Error(t, err, "срок %s вне границ — отказ", c.ttl)
		require.Contains(t, err.Error(), "invite.ttl = "+c.ttl.String())
	}
}

// TestInviteTTL_EnvKnobReachesTheProcess — ручка доезжает до процесса
// переменной окружения ровно тем именем, которым её называет документ
// установки. Молчание окружения — контроль: без него утверждение зеленело бы и
// на ручке, которая всегда отдаёт одно и то же.
func TestInviteTTL_EnvKnobReachesTheProcess(t *testing.T) {
	silent, err := config.Load("")
	require.NoError(t, err)
	require.Nil(t, silent.Invite.TTL, "молчащее окружение обязано оставлять величину незаданной")

	t.Setenv("KANAME_INVITE__TTL", "36h")
	got, err := config.Load("")
	require.NoError(t, err)
	require.NotNil(t, got.Invite.TTL, "ручка `invite.ttl` не связана с переменной `KANAME_INVITE__TTL`")
	require.Equal(t, 36*time.Hour, *got.Invite.TTL)
}
