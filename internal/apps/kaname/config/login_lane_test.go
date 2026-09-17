// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// login_lane_test.go — стражи настройки полосы входа (Ф3-06, Ф3-28, Ф3-33,
// Ф3-41, Ф3-42): незаданная величина — отказ с именем ручки; под `external`
// не требуется ничего; положительный контроль — годный профиль стартует.
package config_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

func TestLoginLane_F3_28_33_41_EveryKnobRefusesByNameUnderOwnAndIsFreeUnderExternal(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*config.LoginLaneConfig)
		knobs []string
	}{
		{"срок", func(l *config.LoginLaneConfig) { l.SessionTTL = 0 }, []string{"authn.login.session-ttl", "KANAME_AUTHN__LOGIN__SESSION_TTL"}},
		{"домен пропущен", func(l *config.LoginLaneConfig) { l.CookieDomain = "" }, []string{"authn.login.cookie-domain", "KANAME_AUTHN__LOGIN__COOKIE_DOMAIN"}},
		{"частота: адрес N", func(l *config.LoginLaneConfig) { l.AddressAttempts = 0 }, []string{"authn.login.address-attempts"}},
		{"частота: адрес T", func(l *config.LoginLaneConfig) { l.AddressWindow = 0 }, []string{"authn.login.address-window"}},
		{"частота: источник N", func(l *config.LoginLaneConfig) { l.SourceAttempts = 0 }, []string{"authn.login.source-attempts"}},
		{"частота: источник T", func(l *config.LoginLaneConfig) { l.SourceWindow = 0 }, []string{"authn.login.source-window"}},
		{"длина пароля", func(l *config.LoginLaneConfig) { l.PasswordMinLength = 0 }, []string{"authn.login.password-min-length"}},
		{"проверка утечек не объявлена", func(l *config.LoginLaneConfig) { l.BreachCheck = "" }, []string{"authn.login.breach-check", "KANAME_AUTHN__LOGIN__BREACH_CHECK"}},
		{"проверка утечек включена без адреса", func(l *config.LoginLaneConfig) { l.BreachCheck = "enabled"; l.BreachCheckURL = "" }, []string{"authn.login.breach-check-url"}},
		{"проверка утечек словом вне перечня", func(l *config.LoginLaneConfig) { l.BreachCheck = "maybe" }, []string{"authn.login.breach-check"}},
		{"формат не задан", func(l *config.LoginLaneConfig) { l.HasherFormat = "" }, []string{"authn.login.hasher-format"}},
		{"формат только читаемый", func(l *config.LoginLaneConfig) { l.HasherFormat = "2a" }, []string{"only-readable"}},
		{"параметр выше потолка", func(l *config.LoginLaneConfig) { l.HasherMemory = 1 << 30 }, []string{"ceiling"}},
		{"параметр ниже пола", func(l *config.LoginLaneConfig) { l.HasherIterations = 1 }, []string{"floor"}},
		{"ёмкость", func(l *config.LoginLaneConfig) { l.VerifierCapacity = 0 }, []string{"authn.login.verifier-capacity", "KANAME_AUTHN__LOGIN__VERIFIER_CAPACITY"}},
		{"резерв", func(l *config.LoginLaneConfig) { l.MemoryReserveBytes = 0 }, []string{"authn.login.memory-reserve-bytes"}},
	}
	for _, c := range cases {
		t.Run("own/"+c.name, func(t *testing.T) {
			cfg := laneCfg(config.IdentityProviderOwn)
			c.mut(&cfg.AuthN.Login)
			err := cfg.Validate()
			require.Error(t, err, "под own незаданная величина — отказ")
			for _, k := range c.knobs {
				require.Contains(t, err.Error(), k)
			}
			require.Contains(t, err.Error(), "declare authn.identity-provider=external and this requirement is lifted")
		})
		t.Run("external/"+c.name, func(t *testing.T) {
			cfg := laneCfg(config.IdentityProviderExternal)
			c.mut(&cfg.AuthN.Login)
			err := cfg.Validate()
			if err != nil {
				require.NotContains(t, err.Error(), "authn.login.", "под external величины полосы не требуются")
			}
		})
	}
	t.Run("положительный контроль: годный профиль стартует, домен none — пустой ключ", func(t *testing.T) {
		cfg := laneCfg(config.IdentityProviderOwn)
		require.NoError(t, cfg.Validate())
		require.Empty(t, cfg.AuthN.Login.ResolvedCookieDomain())
		cfg.AuthN.Login.CookieDomain = "console.example.invalid"
		require.NoError(t, cfg.Validate())
		require.Equal(t, "console.example.invalid", cfg.AuthN.Login.ResolvedCookieDomain())
		cfg.AuthN.Login.BreachCheck = "enabled"
		cfg.AuthN.Login.BreachCheckURL = "https://breach.example.invalid"
		require.NoError(t, cfg.Validate(), "Ф3-33: включена с адресом — старт")
	})
}

// TestLoginLane_F3_42_MemoryBudgetArithmetic — ёмкость × память на потолке +
// резерв ≤ предел; предел не наложен — отказ с числами.
func TestLoginLane_F3_42_MemoryBudgetArithmetic(t *testing.T) {
	l := loginLaneSettings()
	per := config.MemoryPerVerificationAtCeilingBytes()
	require.Equal(t, uint64(128<<20), per, "память на потолке — argon2id 128 МиБ")
	need := uint64(l.VerifierCapacity)*per + l.MemoryReserveBytes
	require.NoError(t, l.ValidateMemoryBudget(need, true), "(б) в пределе — старт")
	err := l.ValidateMemoryBudget(need-1, true)
	require.Error(t, err, "(а) больше предела — отказ")
	require.Contains(t, err.Error(), "authn.login.verifier-capacity")
	require.Contains(t, err.Error(), strconv.FormatUint(need, 10), "отказ называет числа")
	err = l.ValidateMemoryBudget(0, false)
	require.Error(t, err, "(г) предел средой не наложен — отказ")
	require.Contains(t, err.Error(), "не наложен")
	l.VerifierCapacity = 0
	require.Error(t, l.ValidateMemoryBudget(need, true), "(в) ёмкость не задана")
}

// TestLoginLane_KnobsAreBoundToEnv — каждая ручка полосы читается из среды тем
// именем, которое называет отказ.
func TestLoginLane_KnobsAreBoundToEnv(t *testing.T) {
	for _, k := range config.LoginLaneKnobs {
		require.True(t, strings.HasPrefix(k.Env, "KANAME_AUTHN__LOGIN__"), k.Env)
		require.True(t, strings.HasPrefix(k.Key, "authn.login."), k.Key)
	}
	t.Setenv("KANAME_AUTHN__LOGIN__SESSION_TTL", "36h")
	t.Setenv("KANAME_AUTHN__LOGIN__COOKIE_DOMAIN", "console.example.invalid")
	t.Setenv("KANAME_AUTHN__LOGIN__ADDRESS_ATTEMPTS", "7")
	t.Setenv("KANAME_AUTHN__LOGIN__HASHER_MEMORY", "65536")
	cfg, err := config.Load("")
	require.NoError(t, err)
	require.Equal(t, "36h0m0s", cfg.AuthN.Login.SessionTTL.String())
	require.Equal(t, "console.example.invalid", cfg.AuthN.Login.CookieDomain)
	require.Equal(t, 7, cfg.AuthN.Login.AddressAttempts)
	require.EqualValues(t, 65536, cfg.AuthN.Login.HasherMemory)
}
