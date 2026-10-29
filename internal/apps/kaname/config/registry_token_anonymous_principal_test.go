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
	"strings"
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
	t.Setenv(registryIssuerEnv, probeIssuer)
	t.Setenv(anonPrincipalEnv, principal)
	// Темп анонимной выдачи объявлен: предмет этих проб — форма принципала, а
	// поток без темпа страж отвергает отдельно (kaname#928).
	t.Setenv(anonPaceEnv, "20")
	// Доверенный пересыльщик объявлен по той же причине (kaname#930).
	t.Setenv(trustDomainEnv, probeTrustDomain)
	t.Setenv(anonForwarderEnv, registryForwarderSAN)
	cfg, err := config.Load("")
	require.NoError(t, err)
	return cfg, cfg.APIServer.RegistryToken.Validate(cfg.AuthN.ClientToken, cfg.AuthN.TrustDomain())
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

// Граница длины — парой, которая отличается ОДНИМ знаком: 63 знака объявленной
// формы принимаются, 64 той же формы — отказ в старте с именем ручки. Обе
// строки — одно и то же имя из двух слов, удлинённое во втором слове, поэтому
// отказ на 64 приходит от длины, а не от формы.
func TestAnonymousPrincipal_LengthBoundaryIsSixtyThreeCharacters(t *testing.T) {
	atLimit := "a-" + strings.Repeat("b", 61)
	overLimit := "a-" + strings.Repeat("b", 62)
	require.Len(t, atLimit, 63)
	require.Len(t, overLimit, 64)

	_, err := loadRegistryLane(t, atLimit)
	require.NoError(t, err, "имя объявленной формы длиной ровно 63 знака обязано приниматься")

	_, err = loadRegistryLane(t, overLimit)
	require.Error(t, err, "имя объявленной формы длиной 64 знака обязано отказывать в старте")
	require.Contains(t, err.Error(), anonPrincipalKey,
		"отказ по длине обязан называть РУЧКУ: %v", err)
	require.Contains(t, err.Error(), "at most 63 characters",
		"отказ по длине обязан называть предел: %v", err)
}

// Законный близнец отказа «порождённый идентификатор через дефис»: тот же
// префикс `ak-` и те же знаки crockford-base32, но 16 знаков вместо 17 —
// порождённым идентификатором продукта это быть не может, и имя объявленной
// формы принимается. Пара отделяет страж формы порождённого идентификатора от
// стража общей формы: без близнеца отказ на `ak-…17` был бы неотличим от отказа
// на любом имени с префиксом `ak-`.
func TestAnonymousPrincipal_GeneratedShapeTwinOneCharacterShortIsAccepted(t *testing.T) {
	const twin = "ak-0123456789abcdef"
	const generated = twin + "g"
	require.Len(t, strings.TrimPrefix(twin, "ak-"), 16)
	require.Len(t, strings.TrimPrefix(generated, "ak-"), 17)

	_, err := loadRegistryLane(t, twin)
	require.NoError(t, err, "имя с 16 знаками после `ak-` — не порождённый идентификатор и обязано приниматься")

	_, err = loadRegistryLane(t, generated)
	require.Error(t, err, "имя с 17 знаками после `ak-` — форма порождённого идентификатора, отказ")
	require.Contains(t, err.Error(), anonPrincipalKey, "отказ обязан называть РУЧКУ: %v", err)
}
