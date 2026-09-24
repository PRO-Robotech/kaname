// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// client_token_pace_load_test.go — величины ТЕМПА токен-эндпоинта доезжают до
// стража НЕЗАДАННЫМИ, если профиль их не назвал (kaname#315, п. 2 предиката
// снятия).
//
// Проба идёт ЧЕРЕЗ загрузчик, а не обнулением поля структуры: обнуление
// проверяет решение стража на входе, который он получает, и молчит о том,
// бывает ли такой вход. Величина, подставленная загрузчиком, не бывает
// нулевой ни при каком профиле, и ветвь стража не исполняется ни разу — это
// тот же класс, что закрыт для потолка тела (#112).
//
// Ось на пробу — своя: общий цикл по двум ключам покраснел бы на любом одном и
// не сказал бы, на каком.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestClientTokenPace_LoadDoesNotSupplyExchangesPerClient — ось «обменов в
// секунду на идентификатор клиента».
func TestClientTokenPace_LoadDoesNotSupplyExchangesPerClient(t *testing.T) {
	yaml := profileWithClientTokenOn("exchanges-per-client-per-sec")

	got := loadClientToken(t, yaml)
	require.Zero(t, got.ExchangesPerClientPerSec,
		"темп на клиента, не названный профилем, обязан доехать до стража НЕЗАДАННЫМ")
	require.NotZero(t, got.InFlightCeiling, "различие с близнецом — ровно одна величина")

	err := validateLoaded(t, yaml)
	require.Error(t, err, "профиль без темпа на клиента обязан отвергать пуск при поднятом эндпоинте")
	require.Contains(t, err.Error(), "authn.client-token.exchanges-per-client-per-sec",
		"отказ обязан назвать КЛЮЧ: %v", err)
}

// TestClientTokenPace_LoadDoesNotSupplyTheInFlightCeiling — ось «потолок
// одновременных обменов».
func TestClientTokenPace_LoadDoesNotSupplyTheInFlightCeiling(t *testing.T) {
	yaml := profileWithClientTokenOn("in-flight-ceiling")

	got := loadClientToken(t, yaml)
	require.Zero(t, got.InFlightCeiling,
		"потолок одновременных, не названный профилем, обязан доехать до стража НЕЗАДАННЫМ")
	require.NotZero(t, got.ExchangesPerClientPerSec, "различие с близнецом — ровно одна величина")

	err := validateLoaded(t, yaml)
	require.Error(t, err, "профиль без потолка одновременных обязан отвергать пуск при поднятом эндпоинте")
	require.Contains(t, err.Error(), "authn.client-token.in-flight-ceiling",
		"отказ обязан назвать КЛЮЧ: %v", err)
}

// TestClientTokenPace_KeysResolveFromTheEnvironment — вырожденное умолчание не
// стоит разрешения переменной окружения: имена печатает документ установки.
func TestClientTokenPace_KeysResolveFromTheEnvironment(t *testing.T) {
	t.Setenv("KANAME_AUTHN__CLIENT_TOKEN__EXCHANGES_PER_CLIENT_PER_SEC", "7")
	t.Setenv("KANAME_AUTHN__CLIENT_TOKEN__IN_FLIGHT_CEILING", "33")

	got := loadClientToken(t, profileWithClientTokenOn("exchanges-per-client-per-sec", "in-flight-ceiling"))
	require.Equal(t, 7, got.ExchangesPerClientPerSec, "переменная окружения обязана разрешаться")
	require.Equal(t, 33, got.InFlightCeiling, "переменная окружения обязана разрешаться")
	require.NoError(t, validateLoaded(t, profileWithClientTokenOn("exchanges-per-client-per-sec", "in-flight-ceiling")),
		"величины, поданные окружением, обязаны пускать службу")
}

// TestClientTokenPace_IsNotRequiredWhileTheEndpointIsOff — страж, требующий
// того, чем не пользуются, есть отказ в старте без предмета.
func TestClientTokenPace_IsNotRequiredWhileTheEndpointIsOff(t *testing.T) {
	const off = "authn:\n  client-token:\n    enabled: false\n"
	got := loadClientToken(t, off)
	require.Zero(t, got.ExchangesPerClientPerSec)
	require.Zero(t, got.InFlightCeiling)
	require.NoError(t, validateLoaded(t, off))
}
