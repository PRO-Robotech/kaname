// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// loginlane_addr_test.go — АДРЕС СЛУШАТЕЛЯ ПОЛОСЫ ВХОДА НОРМАЛИЗУЕТСЯ ТЕМ ЖЕ
// ПРАВИЛОМ, ЧТО У ОСТАЛЬНЫХ ПОВЕРХНОСТЕЙ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (задача kaname#21, живой старт посадки `own`, 2026-09-17)
//
// Профиль объявляет адреса всех поверхностей одной формой — `tcp://0.0.0.0:<порт>`
// — и каждая поверхность снимает схему перед привязкой (`listenAddress`:
// `MetricsListenAddress`, `HooksHTTPListenAddress`, `RESTListenAddress`, …).
// Полоса входа брала объявление СЫРЫМ: под `own` процесс проходил стража
// посадки, стража памяти, накат и обёртку ключей — и падал на привязке
// последней поверхности:
//
//	listen tcp: address tcp://0.0.0.0:9100: too many colons in address
//
// Ни один страж этого не видел by construction: посадка судит ВЕЛИЧИНЫ, а
// отказ приходил от сети. Поставляемый профиль (`deploy/values.prod.yaml`,
// `loginLaneEndpoint: tcp://0.0.0.0:9100`) был исполним для семи поверхностей
// и неисполним для восьмой — при одинаковой записи.
//
// Проба зовёт ТОТ ЖЕ строитель поверхности, что композиционный корень, и
// сверяет ось адреса с общим нормализатором: второе правило разбора адреса
// разошлось бы с первым молча.
package main

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/servicecontract"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// TestLoginLane_SurfaceAddressIsNormalisedLikeEveryOtherSurface — объявленная
// профилем форма даёт адрес, который принимает `net.Listen`; форма без схемы —
// законный близнец, адрес тот же; пустая полоса — поверхность выключена с
// причиной, адреса нет.
func TestLoginLane_SurfaceAddressIsNormalisedLikeEveryOtherSurface(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, declared := range []string{"tcp://0.0.0.0:9100", "0.0.0.0:9100", "9100"} {
		cfg := loginLaneCfg(config.IdentityProviderOwn)
		cfg.APIServer.LoginLaneEndpoint = declared
		desc, err := loginLaneSurface(cfg, servicecontract.ModeProduction, logger, &loginLane{}, config.MTLSConfig{})
		require.NoError(t, err, declared)
		addr, given := desc.Spec().Addr.Get()
		require.True(t, given, "%s: полоса поднята — адрес обязан быть объявлен значением", declared)
		require.Equal(t, cfg.APIServer.LoginLaneListenAddress(), addr,
			"%s: ось адреса поверхности разошлась с общим нормализатором", declared)
		require.False(t, strings.Contains(addr, "://"),
			"%s: адрес несёт схему — `net.Listen` ответит «too many colons in address»", declared)
		require.True(t, strings.HasSuffix(addr, ":9100"), "%s → %s", declared, addr)
	}

	cfg := loginLaneCfg(config.IdentityProviderExternal)
	cfg.APIServer.LoginLaneEndpoint = "tcp://0.0.0.0:9100"
	desc, err := loginLaneSurface(cfg, servicecontract.ModeProduction, logger, nil, config.MTLSConfig{})
	require.NoError(t, err)
	_, given := desc.Spec().Addr.Get()
	require.False(t, given, "под external полосы нет — адрес не объявляется значением")
	require.False(t, desc.Enabled())
}

// TestLoginLane_ListenAddressAccessorMatchesTheCommonRule — нормализатор полосы
// — тот же, что у соседей: три формы записи дают одно.
func TestLoginLane_ListenAddressAccessorMatchesTheCommonRule(t *testing.T) {
	for declared, want := range map[string]string{
		"tcp://0.0.0.0:9100": "0.0.0.0:9100",
		"0.0.0.0:9100":       "0.0.0.0:9100",
		"9100":               ":9100",
		"  tcp://[::]:9100 ": "[::]:9100",
		"":                   "",
	} {
		c := config.APIServerConfig{LoginLaneEndpoint: declared, RESTEndpoint: declared}
		require.Equal(t, want, c.LoginLaneListenAddress(), "%q", declared)
		require.Equal(t, c.RESTListenAddress(), c.LoginLaneListenAddress(),
			"%q: полоса и REST-фронт читают одну запись по-разному", declared)
	}
}
