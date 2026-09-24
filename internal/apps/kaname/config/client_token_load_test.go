// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// client_token_load_test.go — НЕЗАДАННАЯ величина токен-эндпоинта доезжает до
// стража незаданной (#112).
//
// # Чем эта проба отличается от соседней, и почему без неё та ничего не держит
//
// `client_token_test.go` обнуляет ПОЛЕ СТРУКТУРЫ и зовёт `Validate` — то есть
// проверяет РЕШЕНИЕ стража на входе, который он получает. Она молчит о том,
// бывает ли такой вход: пока загрузчик подставляет величину умолчанием, поле не
// бывает нулевым НИ ПРИ КАКОМ профиле, ветвь стража не исполняется ни разу, и
// сценарий приёмки «страж отвергает пуск при незаданном потолке тела» (F2-43)
// продуктом не исполнен.
//
// Величина, которую подставляет построение, предметом стража быть не может: он
// зелен при любом входе.
//
// Поэтому здесь проба идёт через `config.Load` — тем самым путём, которым
// профиль доезжает до службы.
//
// # Почему у этих двух величин умолчания нет, а у соседних есть
//
// Обе объявляют ГРАНИЦУ, и незаданная граница означает «не сужаем»: потолок
// тела в ноль байт читается как «читаем, сколько пришлют», а срок токена —
// как «решим за оператора, сколько живёт выданное им удостоверение». Ключ при
// этом остаётся зарегистрированным с вырожденным значением: без регистрации
// переменная окружения не разрешалась бы вовсе.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// profileWithClientTokenOn — профиль, включающий эндпоинт и задающий ВСЁ, кроме
// перечисленного в `omit`. Форма — та же, что пишет чарт.
func profileWithClientTokenOn(omit ...string) string {
	skip := map[string]bool{}
	for _, k := range omit {
		skip[k] = true
	}
	var b strings.Builder
	b.WriteString("api-server:\n  registry-token:\n    endpoint: \"tcp://0.0.0.0:9096\"\n")
	b.WriteString("authn:\n  token-signing:\n    enabled: true\n    issuer: \"https://iam.example.invalid\"\n")
	b.WriteString("    algorithm: \"RS256\"\n")
	b.WriteString("  client-token:\n    enabled: true\n")
	b.WriteString("    allowed-audiences: \"https://api.example.invalid\"\n")
	b.WriteString("    default-audience: \"https://api.example.invalid\"\n")
	if !skip["token-ttl"] {
		b.WriteString("    token-ttl: \"15m\"\n")
	}
	if !skip["body-ceiling"] {
		b.WriteString("    body-ceiling: 65536\n")
	}
	if !skip["exchanges-per-client-per-sec"] {
		b.WriteString("    exchanges-per-client-per-sec: 5\n")
	}
	if !skip["in-flight-ceiling"] {
		b.WriteString("    in-flight-ceiling: 64\n")
	}
	return b.String()
}

// loadClientToken — загрузка профиля и настройка эндпоинта, как её увидит страж.
func loadClientToken(t *testing.T, yaml string) config.ClientTokenConfig {
	t.Helper()
	cfg, err := config.Load(writeConfig(t, yaml))
	require.NoError(t, err, "профиль обязан загружаться: предмет пробы — величина, а не разбор")
	return cfg.AuthN.ClientToken
}

// validateLoaded — тот же вызов стража, что делает `Config.Validate`.
func validateLoaded(t *testing.T, yaml string) error {
	t.Helper()
	cfg, err := config.Load(writeConfig(t, yaml))
	require.NoError(t, err)
	return cfg.AuthN.ClientToken.Validate(cfg.AuthN.TokenSigning, cfg.APIServer.RegistryToken.ListenAddress())
}

// TestF2_43_LoadDoesNotSupplyTheBodyCeiling — ОТРИЦАНИЕ: сценарий приёмки F2-43
// («страж старта отвергает пуск при незаданном потолке тела») обязан быть
// исполним продуктом.
func TestF2_43_LoadDoesNotSupplyTheBodyCeiling(t *testing.T) {
	yaml := profileWithClientTokenOn("body-ceiling")

	got := loadClientToken(t, yaml)
	require.Zero(t, got.BodyCeiling,
		"потолок тела, не названный профилем, обязан доехать до стража НЕЗАДАННЫМ: "+
			"подставленный построением, он не бывает нулевым, и ветвь стража не исполняется ни разу")

	err := validateLoaded(t, yaml)
	require.Error(t, err, "профиль без потолка тела обязан отвергать пуск")
	require.Contains(t, err.Error(), "body-ceiling",
		"отказ обязан назвать КЛЮЧ: оператор читает его, чтобы починить: %v", err)
}

// TestLoadDoesNotSupplyTheTokenTTL — та же ось у второй величины.
func TestLoadDoesNotSupplyTheTokenTTL(t *testing.T) {
	yaml := profileWithClientTokenOn("token-ttl")

	got := loadClientToken(t, yaml)
	require.Zero(t, got.TokenTTL,
		"срок выдаваемого токена, не названный профилем, обязан доехать до стража НЕЗАДАННЫМ")

	err := validateLoaded(t, yaml)
	require.Error(t, err, "профиль без срока токена обязан отвергать пуск")
	require.Contains(t, err.Error(), "token-ttl",
		"отказ обязан назвать КЛЮЧ: %v", err)
}

// TestFullyDeclaredClientTokenProfileStarts — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
//
// Без него отрицания выше выполняются тождественно: страж, отвергающий всякий
// профиль, прошёл бы обе пробы и не дал бы подняться ни одной установке.
func TestFullyDeclaredClientTokenProfileStarts(t *testing.T) {
	yaml := profileWithClientTokenOn()

	got := loadClientToken(t, yaml)
	require.NotZero(t, got.BodyCeiling, "названный профилем потолок обязан доехать")
	require.NotZero(t, got.TokenTTL, "названный профилем срок обязан доехать")
	require.Equal(t, 5, got.ExchangesPerClientPerSec, "названный профилем темп на клиента обязан доехать")
	require.Equal(t, 64, got.InFlightCeiling, "названный профилем потолок одновременных обязан доехать")

	require.NoError(t, validateLoaded(t, yaml),
		"полностью объявленный профиль обязан стартовать")
}

// TestClientTokenKeysStayResolvableFromTheEnvironment — вырожденное умолчание
// не должно стоить разрешения переменной окружения.
//
// `AutomaticEnv` резолвит переменную только для ключа, который випер уже знает.
// Снять регистрацию вместе с умолчанием значило бы закрыть оператору запасной
// путь настройки, не сказав об этом ни слова.
func TestClientTokenKeysStayResolvableFromTheEnvironment(t *testing.T) {
	t.Setenv("KANAME_AUTHN__CLIENT_TOKEN__TOKEN_TTL", "7m")
	t.Setenv("KANAME_AUTHN__CLIENT_TOKEN__BODY_CEILING", "4096")

	got := loadClientToken(t, profileWithClientTokenOn("token-ttl", "body-ceiling"))
	require.EqualValues(t, 4096, got.BodyCeiling, "переменная окружения обязана разрешаться")
	require.Equal(t, "7m0s", got.TokenTTL.String(), "переменная окружения обязана разрешаться")
}
