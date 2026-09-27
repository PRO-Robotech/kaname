// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// client_token_ceremony_pace_test.go — шесть величин темпа поверхности выдачи
// (приёмка ceremony-pace-is-named-by-number.md, kaname#315, группа A:
// KN-PACE-01 … 04).
//
// Проба идёт ЧЕРЕЗ загрузчик (`config.Load`) и страж, а не обнулением поля:
// величина, подставленная загрузчиком, не бывает нулевой ни при каком профиле,
// и ветвь стража не исполнялась бы ни разу. Строка на величину — своя: общий
// цикл без имени строки покраснел бы на любой и не сказал бы, на какой.

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/multierr"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// ceremonyPaceValue — величина §3: ключ, число и его нулевая форма.
type ceremonyPaceValue struct {
	key, sample, zero string
}

// ceremonyPaceValues — шесть величин §3 приёмки числами §3.
var ceremonyPaceValues = []ceremonyPaceValue{
	{"in-flight-ceiling", "32", "0"},
	{"exchanges-per-client-per-sec", "5", "0"},
	{"failed-proofs-per-source", "50", "0"},
	{"failed-proof-window", "15m", "0s"},
	{"authorize-per-source-per-sec", "10", "0"},
	{"authorize-in-flight-ceiling", "32", "0"},
}

// ownCeremonyProfile — посадка own с включённым эндпоинтом: шесть величин
// числами §3, кроме zero (задана нулём) и omit (сняты).
func ownCeremonyProfile(zero string, omit ...string) string {
	skip := map[string]bool{}
	for _, k := range omit {
		skip[k] = true
	}
	var b strings.Builder
	b.WriteString("api-server:\n  registry-token:\n    endpoint: \"tcp://0.0.0.0:9096\"\n")
	b.WriteString("authn:\n  identity-provider: own\n")
	b.WriteString("  token-signing:\n    enabled: true\n    issuer: \"https://iam.example.invalid\"\n")
	b.WriteString("    algorithm: \"RS256\"\n")
	b.WriteString("  client-token:\n    enabled: true\n")
	b.WriteString("    allowed-audiences: \"https://api.example.invalid\"\n")
	b.WriteString("    default-audience: \"https://api.example.invalid\"\n")
	b.WriteString("    token-ttl: \"15m\"\n    body-ceiling: 65536\n")
	for _, v := range ceremonyPaceValues {
		switch {
		case skip[v.key]:
			continue
		case v.key == zero:
			b.WriteString("    " + v.key + ": \"" + v.zero + "\"\n")
		default:
			b.WriteString("    " + v.key + ": \"" + v.sample + "\"\n")
		}
	}
	return b.String()
}

// ceremonyPaceRefusal — отказ стража, как его производит `Config.Validate` для
// блока эндпоинта: страж величин эндпоинта и страж величин церемонии.
func ceremonyPaceRefusal(t *testing.T, yaml string) (config.Config, error) {
	t.Helper()
	cfg, err := config.Load(writeConfig(t, yaml))
	require.NoError(t, err, "профиль обязан загружаться: предмет пробы — величина, а не разбор")
	return cfg, multierr.Append(
		cfg.AuthN.ClientToken.Validate(cfg.AuthN.TokenSigning, cfg.APIServer.RegistryToken.ListenAddress()),
		cfg.AuthN.ValidateCeremonyPace())
}

// KN-PACE-01 — незаданная величина: отказ старта с именем ключа.
func TestKNPACE01_UndeclaredValueRefusesStartNamingTheKey(t *testing.T) {
	for _, v := range ceremonyPaceValues {
		t.Run(v.key, func(t *testing.T) {
			_, err := ceremonyPaceRefusal(t, ownCeremonyProfile("", v.key))
			require.Error(t, err, "профиль без %s обязан отвергать пуск", v.key)
			require.Contains(t, err.Error(), "authn.client-token."+v.key, "отказ обязан назвать КЛЮЧ")
		})
	}
}

// KN-PACE-02 — все шесть заданы: загрузка проходит, и числа доезжают.
func TestKNPACE02_AllSixDeclaredStartAndArrive(t *testing.T) {
	cfg, err := ceremonyPaceRefusal(t, ownCeremonyProfile(""))
	require.NoError(t, err, "полностью объявленный профиль обязан стартовать")
	ct := cfg.AuthN.ClientToken
	require.Equal(t, 32, ct.InFlightCeiling)
	require.Equal(t, 5, ct.ExchangesPerClientPerSec)
	require.Equal(t, 50, ct.FailedProofsPerSource)
	require.Equal(t, 15*time.Minute, ct.FailedProofWindow)
	require.Equal(t, 10, ct.AuthorizePerSourcePerSec)
	require.Equal(t, 32, ct.AuthorizeInFlightCeiling)
	require.True(t, cfg.AuthN.CeremonyAssembled(), "предпосылка: own и включённый эндпоинт — церемония собрана")
}

// KN-PACE-03 — нулевая величина — не величина.
func TestKNPACE03_ZeroValueIsNotAValue(t *testing.T) {
	for _, v := range ceremonyPaceValues {
		t.Run(v.key, func(t *testing.T) {
			_, err := ceremonyPaceRefusal(t, ownCeremonyProfile(v.key))
			require.Error(t, err, "%s=%s обязан отвергать пуск", v.key, v.zero)
			require.Contains(t, err.Error(), "authn.client-token."+v.key)
		})
	}
}

// KN-PACE-04 — выключенный эндпоинт величин не требует.
func TestKNPACE04_DisabledEndpointRequiresNoneOfTheSix(t *testing.T) {
	const off = "authn:\n  identity-provider: own\n  client-token:\n    enabled: false\n"
	cfg, err := ceremonyPaceRefusal(t, off)
	for _, v := range ceremonyPaceValues {
		if err != nil {
			require.NotContains(t, err.Error(), "authn.client-token."+v.key)
		}
	}
	require.NoError(t, err)
	require.False(t, cfg.AuthN.CeremonyAssembled())
}

// Величины точки авторизации требует собранная церемония, а не включённый
// эндпоинт: под external церемонии нет, и её величины не читаются.
func TestAuthorizeValuesAreNotRequiredWithoutTheCeremony(t *testing.T) {
	yaml := strings.Replace(ownCeremonyProfile("", "authorize-per-source-per-sec", "authorize-in-flight-ceiling"),
		"identity-provider: own", "identity-provider: external", 1)
	cfg, err := ceremonyPaceRefusal(t, yaml)
	require.False(t, cfg.AuthN.CeremonyAssembled(), "предпосылка: под external церемонии нет")
	require.NoError(t, err)

	// Близнец — та же пара под own: отказ по обеим.
	_, err = ceremonyPaceRefusal(t, ownCeremonyProfile("", "authorize-per-source-per-sec", "authorize-in-flight-ceiling"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "authn.client-token.authorize-per-source-per-sec")
	require.Contains(t, err.Error(), "authn.client-token.authorize-in-flight-ceiling")
}

// Ключи разрешаются из окружения — имена печатает руководство установки.
func TestCeremonyPaceKeysResolveFromTheEnvironment(t *testing.T) {
	t.Setenv("KANAME_AUTHN__CLIENT_TOKEN__FAILED_PROOFS_PER_SOURCE", "51")
	t.Setenv("KANAME_AUTHN__CLIENT_TOKEN__FAILED_PROOF_WINDOW", "16m")
	t.Setenv("KANAME_AUTHN__CLIENT_TOKEN__AUTHORIZE_PER_SOURCE_PER_SEC", "11")
	t.Setenv("KANAME_AUTHN__CLIENT_TOKEN__AUTHORIZE_IN_FLIGHT_CEILING", "33")
	yaml := ownCeremonyProfile("", "failed-proofs-per-source", "failed-proof-window",
		"authorize-per-source-per-sec", "authorize-in-flight-ceiling")
	cfg, err := ceremonyPaceRefusal(t, yaml)
	require.NoError(t, err)
	require.Equal(t, 51, cfg.AuthN.ClientToken.FailedProofsPerSource)
	require.Equal(t, 16*time.Minute, cfg.AuthN.ClientToken.FailedProofWindow)
	require.Equal(t, 11, cfg.AuthN.ClientToken.AuthorizePerSourcePerSec)
	require.Equal(t, 33, cfg.AuthN.ClientToken.AuthorizeInFlightCeiling)
}
