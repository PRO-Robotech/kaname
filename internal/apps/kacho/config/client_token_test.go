// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_token_test.go — страж старта токен-эндпоинта (приёмка F2, сценарии
// F2-16, F2-22 сторона стража, F2-43 сторона стража).
//
// # Почему каждая проба здесь идёт ПАРОЙ
//
// Страж, отвергающий всё, зелен на любом отрицании. Поэтому у каждой
// вырожденной настройки рядом стоит та же настройка с заданным значением, и
// она обязана СТАРТОВАТЬ. Без второй половины проба измеряла бы существование
// стража, а не то, что он различает.
//
// # Почему вырожденное значение, а не только отсутствующее
//
// Перечень адресатов приезжает строкой через запятую. Одинокая запятая непуста
// по длине и пуста по существу: страж, меряющий длину строки, объявил бы такой
// перечень заданным, а сверка адресата свелась бы к «принимаем любой».
package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

// signingOn — своя чеканка, настроенная полностью. Токен-эндпоинт выпускает
// НАШИМ подписантом, поэтому его страж обязан требовать её включённой.
func signingOn() config.TokenSigningConfig {
	return config.TokenSigningConfig{
		Enabled:           true,
		Issuer:            "https://iam.kacho.local",
		Algorithm:         tokenpolicy.AlgES256,
		AllowedAlgorithms: tokenpolicy.AlgES256,
		KeySetPath:        "/.well-known/kacho/jwks.json",
	}
}

// clientTokenOn — полная настройка эндпоинта. Всякая проба ниже портит РОВНО
// одно поле, чтобы отказ нельзя было списать на соседнее.
const hostListener = "0.0.0.0:9096"

func clientTokenOn() config.ClientTokenConfig {
	return config.ClientTokenConfig{
		Enabled:          true,
		AllowedAudiences: "registry.kacho.local, api.kacho.local",
		DefaultAudience:  "api.kacho.local",
		TokenTTL:         15 * time.Minute,
		BodyCeiling:      64 << 10,
	}
}

// TestF2_16_ClientTokenBootGuardRefusesTheDegenerateAndStartsOnTheDeclared —
// каждая вырожденная величина отвергает старт, полная — стартует.
func TestF2_16_ClientTokenBootGuardRefusesTheDegenerateAndStartsOnTheDeclared(t *testing.T) {
	// Положительный контроль ПЕРВЫМ: без него всё, что ниже, зелено на страже,
	// не пускающем никого.
	require.NoError(t, clientTokenOn().Validate(signingOn(), hostListener),
		"полная настройка обязана стартовать")

	cases := []struct {
		name    string
		mutate  func(*config.ClientTokenConfig, *config.TokenSigningConfig)
		mustSay string
	}{
		{
			// F2-16: ожидаемый адресат утверждения — идентификатор НАШЕГО
			// издателя. Незаданный означает «принимаем любой адресат», то есть
			// утверждение, выписанное для чужой стороны, прошло бы у нас.
			name: "идентификатор издателя не задан",
			mutate: func(_ *config.ClientTokenConfig, s *config.TokenSigningConfig) {
				s.Issuer = "   "
			},
			mustSay: "issuer",
		},
		{
			// Эндпоинт выпускает НАШИМ подписантом. Выключенная чеканка
			// означает, что выпускать нечем, — и обнаружилось бы это на первом
			// запросе, а не на старте.
			name: "своя чеканка выключена",
			mutate: func(_ *config.ClientTokenConfig, s *config.TokenSigningConfig) {
				s.Enabled = false
			},
			mustSay: "token-signing",
		},
		{
			name:    "перечень адресатов пуст",
			mutate:  func(c *config.ClientTokenConfig, _ *config.TokenSigningConfig) { c.AllowedAudiences = "" },
			mustSay: "allowed-audiences",
		},
		{
			// Вырожденное значение, а не отсутствующее: длина 1, элементов 0.
			name:    "перечень адресатов вырожден одинокой запятой",
			mutate:  func(c *config.ClientTokenConfig, _ *config.TokenSigningConfig) { c.AllowedAudiences = "," },
			mustSay: "allowed-audiences",
		},
		{
			name:    "адресат по умолчанию не задан",
			mutate:  func(c *config.ClientTokenConfig, _ *config.TokenSigningConfig) { c.DefaultAudience = " " },
			mustSay: "default-audience",
		},
		{
			// Умолчание вне перечня отвергалось бы собственной проверкой, и
			// глагол не работал бы НИ ПРИ КАКОМ входе — при том что обе
			// половины настройки по отдельности выглядят разумными.
			name:    "адресат по умолчанию вне перечня",
			mutate:  func(c *config.ClientTokenConfig, _ *config.TokenSigningConfig) { c.DefaultAudience = "elsewhere.local" },
			mustSay: "default-audience",
		},
		{
			name:    "срок токена не задан",
			mutate:  func(c *config.ClientTokenConfig, _ *config.TokenSigningConfig) { c.TokenTTL = 0 },
			mustSay: "token-ttl",
		},
		{
			// Срок сверх платформенного потолка не «урезается на выпуске»:
			// молчаливое урезание сделало бы слагаемое неизвестным тому, кто
			// его настраивал.
			name: "срок токена сверх платформенного потолка",
			mutate: func(c *config.ClientTokenConfig, _ *config.TokenSigningConfig) {
				c.TokenTTL = tokenpolicy.MaxTokenTTL + time.Second
			},
			mustSay: "token-ttl",
		},
		{
			// F2-43: потолок тела. Ноль означает «без потолка».
			name:    "потолок тела не задан",
			mutate:  func(c *config.ClientTokenConfig, _ *config.TokenSigningConfig) { c.BodyCeiling = 0 },
			mustSay: "body-ceiling",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, s := clientTokenOn(), signingOn()
			tc.mutate(&c, &s)

			err := c.Validate(s, hostListener)
			require.Error(t, err, "вырожденная настройка обязана отвергать старт")
			require.Contains(t, err.Error(), tc.mustSay,
				"текст отказа обязан называть НАСТРОЙКУ: оператор читает его, чтобы починить")
		})
	}
}

// TestF2_16_EnabledEndpointWithoutItsHostListenerRefusesTheStart — эндпоинт,
// объявленный включённым и не имеющий слушателя, не обслуживается.
//
// Состояние неотличимо от исправного до первого запроса клиента: сервис
// поднялся, журнал чист, поверхности объявлены. Поэтому отказ в старте, а не
// «включён, но молчит».
func TestF2_16_EnabledEndpointWithoutItsHostListenerRefusesTheStart(t *testing.T) {
	err := clientTokenOn().Validate(signingOn(), "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "registry-token.endpoint")

	// Положительный контроль: тот же вход с поднятым слушателем стартует.
	require.NoError(t, clientTokenOn().Validate(signingOn(), hostListener))
}

// TestClientTokenGuardIsSilentWhileTheEndpointIsOff — страж, требующий того,
// чем не пользуются, есть отказ в старте без предмета.
func TestClientTokenGuardIsSilentWhileTheEndpointIsOff(t *testing.T) {
	off := config.ClientTokenConfig{}
	require.NoError(t, off.Validate(config.TokenSigningConfig{}, ""))
	require.NoError(t, off.Validate(signingOn(), hostListener))
}

// TestClientTokenRefusalNamesNoSecretValue — текст отказа читает оператор, а не
// предъявитель.
//
// Подсажено заведомо присутствующее значение, и проба обязана НЕ найти его в
// тексте: утверждение об отсутствии зелено на читателе, который не читает
// ничего, поэтому рядом утверждается, что найдено имя настройки.
func TestClientTokenRefusalNamesNoSecretValue(t *testing.T) {
	c, s := clientTokenOn(), signingOn()
	c.TokenTTL = 0
	s.Issuer = ""

	err := c.Validate(s, hostListener)
	require.Error(t, err)
	require.Contains(t, err.Error(), "token-ttl")
	require.Contains(t, err.Error(), "issuer")
}

// TestAudienceListCountsElementsNotStringLength — один предикат для стража и
// для вызывающего.
//
// Два места об одном предмете разошлись бы ровно на вырожденном значении, и
// разошлись бы молча: страж объявил бы перечень непустым, а сверка адресата
// свелась бы к «принимаем любой».
func TestAudienceListCountsElementsNotStringLength(t *testing.T) {
	for raw, want := range map[string]int{
		"":                                  0,
		" ":                                 0,
		",":                                 0,
		" , , ":                             0,
		"api.kacho.local":                   1,
		" api.kacho.local , registry.local": 2,
		"api.kacho.local,,registry.local":   2,
	} {
		got := config.ClientTokenConfig{AllowedAudiences: raw}.AudienceList()
		require.Len(t, got, want, "перечень %q", raw)
		for _, a := range got {
			require.Equal(t, strings.TrimSpace(a), a, "элемент %q обязан приезжать обрезанным", a)
		}
	}
}
