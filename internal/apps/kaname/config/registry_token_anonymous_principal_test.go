// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// registry_token_anonymous_principal_test.go — РУЧКА ПУБЛИЧНОГО ПРИНЦИПАЛА
// АНОНИМНОГО ЧТЕНИЯ (kaname#495, исход (а)).
//
// Страж старта утверждается ПАРОЙ, и обе половины идут через настройку службы
// (переменную окружения → Load → Validate), а не через структуру:
//   - значение объявленной формы принимается;
//   - значение иной формы отвергается, и отказ называет ручку.
//
// Без первой половины отказ на любом значении был бы неотличим от исправного
// стража; без второй — ручка открывала бы выдачу за принципала, которого
// посадка не выбирала.
package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

const (
	anonPrincipalEnv = "KANAME_API_SERVER__REGISTRY_TOKEN__ANONYMOUS_CLIENT_ID"
	anonServiceEnv   = "KANAME_API_SERVER__REGISTRY_TOKEN__SERVICE"
	anonPrincipalKey = "api-server.registry-token.anonymous-client-id"
)

// loadRegistryLane загружает настройку службы так, как её загружает процесс, и
// возвращает исход стража старта докерной полосы.
func loadRegistryLane(t *testing.T, principal string) (config.Config, error) {
	t.Helper()
	t.Setenv(anonServiceEnv, "registry.probe.local")
	t.Setenv(anonPrincipalEnv, principal)
	cfg, err := config.Load("")
	require.NoError(t, err)
	return cfg, cfg.APIServer.RegistryToken.Validate(cfg.AuthN.ClientToken)
}

// Половина первая: объявленная форма — имя в нижнем регистре из слов через
// дефис — принимается стражем.
func TestAnonymousPrincipal_DeclaredFormIsAccepted(t *testing.T) {
	for _, v := range []string{"registry-anonymous", "public-pull", "kacho-registry-anon-1"} {
		t.Run(v, func(t *testing.T) {
			_, err := loadRegistryLane(t, v)
			require.NoError(t, err, "значение объявленной формы обязано приниматься: %q", v)
		})
	}
}

// Незаданная ручка — анонимный поток ВЫКЛЮЧЕН, и это законное состояние, а не
// отказ (fail-closed: умолчания, тихо открывающего доступ, нет).
func TestAnonymousPrincipal_UnsetIsAccepted(t *testing.T) {
	_, err := loadRegistryLane(t, "")
	require.NoError(t, err, "незаданная ручка — анонимный поток выключен, отказывать не за что")
}

// Половина вторая: значение иной формы — отказ в старте с именем ручки.
//
// Несущий случай — идентификатор настоящего принципала: анонимный токен,
// выпущенный за `sva…`, неотличим от токена этой служебной учётки, и ручка
// превратилась бы в выдачу её прав всякому без удостоверения.
func TestAnonymousPrincipal_OtherFormRefusesToStartNamingTheKnob(t *testing.T) {
	for name, v := range map[string]string{
		"идентификатор служебной учётки":        "sva0000000000000bat1",
		"идентификатор человека":                "usr0000000000000bat1",
		"прежняя форма идентификатора":          "sva_0000000000000bat1",
		"порождённый идентификатор через дефис": "ak-0123456789abcdefg",
		"говорящий модели прав":                 "system_class:anonymous",
		"подстановка":                           "user:*",
		"верхний регистр":                       "Registry-Anonymous",
		"одно слово без дефиса":                 "anonymous",
		"пробел по краю":                        " registry-anonymous",
		"одни пробелы":                          "   ",
		"дефис в конце":                         "registry-",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadRegistryLane(t, v)
			require.Error(t, err, "значение иной формы обязано отказывать в старте: %q", v)
			require.Contains(t, err.Error(), anonPrincipalKey,
				"отказ обязан называть РУЧКУ — иначе оператор ищет вслепую: %v", err)
			require.Contains(t, err.Error(), anonPrincipalEnv,
				"отказ обязан называть и переменную окружения: %v", err)
		})
	}
}

// Объявленное значение ДОЕЗЖАЕТ до загруженной настройки: ручка, принятая
// стражем и не прочитанная, — ручка без читателя.
func TestAnonymousPrincipal_DeclaredValueReachesTheLoadedSetting(t *testing.T) {
	cfg, err := loadRegistryLane(t, "registry-anonymous")
	require.NoError(t, err)
	got, err := cfg.APIServer.RegistryToken.AnonymousPrincipal()
	require.NoError(t, err)
	require.Equal(t, "registry-anonymous", got)

	cfg, err = loadRegistryLane(t, "")
	require.NoError(t, err)
	got, err = cfg.APIServer.RegistryToken.AnonymousPrincipal()
	require.NoError(t, err)
	require.Empty(t, got, "незаданная ручка обязана давать пустое — поток выключен")
}
