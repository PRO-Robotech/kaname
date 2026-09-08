// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// authn_domain_test.go — АДРЕСАТ выпущенного токена объявляется величиной, а не
// подставляется построением (задача #2127).
//
// # Предмет
//
// `authn.domain` — не косметика: из него выводится клеймо адресата, которое
// уезжает в КАЖДОМ выпущенном удостоверении и читается всяким, кто токен
// разбирает. Пока построение подставляет за оператора доменное имя чужого
// продукта, всякая посадка — включая чужое облако — чеканит удостоверения,
// адресованные не туда, и выглядит настроенной.
//
// # Почему страж, а не «разумное умолчание»
//
// Величина, которую построение подставляет молча, предметом стража быть НЕ
// МОЖЕТ: он зелен при любом входе, потому что незаданной величина не бывает.
// Это та же норма, по которой у посадки личности умолчания нет вовсе
// (`defaults.go`, задача #1125), и та же, по которой её нет у издателя своей
// чеканки.
package config_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// domainCfg — годная production-настройка с объявленным доменом.
func domainCfg(domain string) config.Config {
	cfg := goodEndpoints(config.ModeProduction, "require")
	cfg.AuthN.HookSharedSecret = "hook-secret"
	cfg.AuthN.JWKSEncryptionKeyHex = strings.Repeat("ab", 32)
	cfg.AuthN.IdentityProvider = config.IdentityProviderOwn
	cfg.AuthN.TokenSigning = ownMintingSettings()
	cfg.AuthN.PresentedCredential = presentedCredentialSettings()
	cfg.AuthN.Domain = domain
	return cfg
}

// TestUnsetDomainRefusesTheStart — профиль, не объявивший адресата, старт не
// проходит, и отказ называет ПОЛЕ (оператору иначе нечего искать).
func TestUnsetDomainRefusesTheStart(t *testing.T) {
	err := domainCfg("").Validate()
	require.Error(t, err,
		"адресат выпускаемых удостоверений не объявлен — старт обязан быть отвергнут: "+
			"иначе каждый выпущенный токен адресован тому, кого выбрал не оператор")
	require.Contains(t, err.Error(), "authn.domain",
		"отказ обязан называть поле; оператору иначе нечего искать")
}

// TestDeclaredDomainPassesTheStart — парный ПОЛОЖИТЕЛЬНЫЙ контроль. Без него
// отрицание выше зеленело бы на проверке, отвергающей всё.
func TestDeclaredDomainPassesTheStart(t *testing.T) {
	require.NoError(t, domainCfg("access.example.test").Validate(),
		"объявленный адресат обязан проходить старт")
}

// TestDomainHasNoCompiledInDefault — незаданное значение доезжает до стража, а
// не замещается построением.
//
// Утверждение о ЗАГРУЗКЕ, а не о структуре: умолчание живёт в двух местах —
// регистрации ключа (`defaults.go`) и резолве (`authn.go`), — и проба,
// читающая одно, зеленела бы при живом другом.
func TestDomainHasNoCompiledInDefault(t *testing.T) {
	for _, k := range []string{"KANAME_AUTHN__DOMAIN"} {
		if old, ok := os.LookupEnv(k); ok {
			require.NoError(t, os.Unsetenv(k))
			t.Cleanup(func() { _ = os.Setenv(k, old) })
		}
	}

	cfg, err := config.Load("")
	require.NoError(t, err)

	require.Empty(t, cfg.AuthN.Domain,
		"у адресата умолчания быть не должно: подставленное построением значение "+
			"делает стража тождественно истинным")
	require.Empty(t, cfg.AuthN.ResolveDomain(),
		"резолв тоже не подставляет: два места об одном умолчании разошлись бы молча, "+
			"и живым оказалось бы то, которое забыли снять")
}

// TestDeclaredDomainIsTheKnob — ручка объявлена и меняет исход загрузки.
//
// Имена ENV этого сервиса выводятся випером из пути ключа, и в коде литералами
// не встречаются: без этой пробы переименование ключа молча отвязало бы
// документированную ручку (см. `env_names_documented_test.go`).
func TestDeclaredDomainIsTheKnob(t *testing.T) {
	t.Setenv("KANAME_AUTHN__DOMAIN", "access.example.test")

	cfg, err := config.Load("")
	require.NoError(t, err)

	require.Equal(t, "access.example.test", cfg.AuthN.ResolveDomain(),
		"ENV KANAME_AUTHN__DOMAIN обязана менять исход загрузки")
	require.Equal(t, "access.example.test", cfg.AuthN.ResolveAudience(),
		"клеймо адресата выводится из того же объявления — второго входа у него нет")
}
