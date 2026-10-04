// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// invite_ttl_wiring_test.go — срок приглашения в сборке служб.
//
// Ручка `invite.ttl` без умолчания. Сборка читает её ОДНИМ суждением
// (`config.Declared`) и берёт величину из него же: вызванная мимо стража
// старта, она обязана отказать с именем ключа, а не паниковать на
// разыменовании поля. Отрицательный кейс меняет против близнеца РОВНО ОДИН
// факт — объявлен ли срок; пул, реестр и прочие зависимости общие.
package main

import (
	"fmt"
	"io"
	"log/slog"
	"runtime/debug"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// buildServicesNoPanic — сборка служб с перехватом паники: паника — не исход
// сборки, а дефект, и проба называет её текстом и стеком.
func buildServicesNoPanic(t *testing.T, cfg config.Config) (svcs *services, err error) {
	t.Helper()
	pool := deadPool(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("сборка служб ПАНИКУЕТ: %v\n%s", r, debug.Stack())
			svcs = nil
		}
	}()
	return buildServices(pool, nil, nil, nil, nil, nil, nil, metrics.NewRegistry(), cfg, nil, logger)
}

// inviteWiringBaseCfg — общая часть обоих кейсов: пустая настройка с
// объявленным классом хешера полосы входа. Исполнитель заведения
// интерактивных клиентов строится над хешером на ЛЮБОМ старте (kaname#405,
// #363), и без него сборка уходит в отказ старта раньше, чем дойдёт до
// службы приглашений, — близнец не дошёл бы до своего предмета.
func inviteWiringBaseCfg() config.Config {
	cfg := config.Config{}
	cfg.AuthN.Login.HasherFormat = "argon2id"
	cfg.AuthN.Login.HasherMemory = 65536
	cfg.AuthN.Login.HasherIterations = 3
	cfg.AuthN.Login.HasherParallelism = 4
	// Полоса отсечки службы выдачи уведомлений (NTF-1 Р5) — тоже ручка без
	// умолчания, судимая сборкой служб: без неё близнец остановился бы на
	// отказе полосы, не дойдя до срока приглашения.
	guard := 30 * time.Second
	cfg.Notifications.CutoffGuard = &guard
	return cfg
}

func TestBuildServices_UndeclaredInviteTTLRefusesWithTheKeyNotAPanic(t *testing.T) {
	t.Run("срок не объявлен — отказ с именем ключа и переменной", func(t *testing.T) {
		svcs, err := buildServicesNoPanic(t, inviteWiringBaseCfg())
		require.Error(t, err)
		require.NotContains(t, err.Error(), "ПАНИКУЕТ")
		require.Contains(t, err.Error(), "invite.ttl")
		require.Contains(t, err.Error(), config.EnvNameOfKey("invite.ttl"))
		require.Nil(t, svcs)
	})

	t.Run("близнец: срок объявлен — службы собраны", func(t *testing.T) {
		ttl := 72 * time.Hour
		cfg := inviteWiringBaseCfg()
		cfg.Invite.TTL = &ttl
		svcs, err := buildServicesNoPanic(t, cfg)
		require.NoError(t, err)
		require.NotNil(t, svcs)
	})
}
