// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// registry_token_anonymous_forwarder_test.go — ДОВЕРЕННЫЙ ПЕРЕСЫЛЬЩИК точки
// анонимной выдачи докерной полосы (kaname#930).
//
// Анонимный вход докер-клиента приходит к службе не напрямую, а через прокси
// реестра. Без признанного пересыльщика ключ темпа на источник — адрес этого
// прокси, и предел становится общим на всех клиентов за ним. Ручка называет
// пересыльщика ТОЧНЫМ идентификатором клиентского сертификата (SAN) — той же
// формой, что круги отправителей соседних ручек (`authn.trusted-forwarder-sans`,
// `authn.bootstrap-mint.allowed-client-sans`).
//
// Страж утверждается ПАРОЙ через настройку службы (переменная → Load →
// Validate): поток без пересыльщика не стартует, называя ручку; объявленный
// пересыльщик законной формы принимается и доходит до поля.
package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

const (
	anonForwarderEnv = "KANAME_API_SERVER__REGISTRY_TOKEN__ANONYMOUS_FORWARDER_SAN"
	anonForwarderKey = "api-server.registry-token.anonymous-forwarder-san"
	trustDomainEnv   = "KANAME_AUTHN__TRUST_DOMAIN"
	probeTrustDomain = "kacho.cloud"
	// registryForwarderSAN — идентификатор прокси реестра в домене доверия пробы.
	registryForwarderSAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-registry"
)

// noTrustDomain — домен доверия не объявлен: вход стража для проб, чей предмет —
// не пересыльщик анонимного потока.
var noTrustDomain grpcsrv.TrustDomain

// loadForwarderLane — настройка службы с анонимным потоком (принципал и темп
// объявлены) и пересыльщиком forwarder (пусто — переменная не задана).
func loadForwarderLane(t *testing.T, principal, forwarder string) (config.Config, error) {
	t.Helper()
	t.Setenv(anonServiceEnv, "registry.probe.local")
	t.Setenv(registryIssuerEnv, probeIssuer)
	t.Setenv(anonPrincipalEnv, principal)
	t.Setenv(anonPaceEnv, "20")
	t.Setenv(trustDomainEnv, probeTrustDomain)
	if forwarder != "" {
		t.Setenv(anonForwarderEnv, forwarder)
	}
	cfg, err := config.Load("")
	require.NoError(t, err)
	return cfg, cfg.APIServer.RegistryToken.Validate(cfg.AuthN.ClientToken, cfg.AuthN.TrustDomain())
}

func TestAnonymousForwarder_LoaderDoesNotSupplyIt(t *testing.T) {
	cfg, _ := loadForwarderLane(t, "", "")
	require.Empty(t, cfg.APIServer.RegistryToken.AnonymousForwarderSAN,
		"загрузчик подставил пересыльщика: доверие к пересылке, выбранное за оператора")
}

// Отрицание: поток объявлен, пересыльщик — нет. Источник был бы адресом прокси
// реестра, и темп стал бы общим на всех клиентов.
func TestAnonymousForwarder_UndeclaredWithTheAnonymousLaneRefusesToStartNamingTheKnob(t *testing.T) {
	_, err := loadForwarderLane(t, "registry-anonymous", "")
	require.Error(t, err, "анонимный поток без доверенного пересыльщика делил бы один темп на всех клиентов")
	require.Contains(t, err.Error(), anonForwarderKey, "отказ обязан называть ручку: %v", err)
	require.Contains(t, err.Error(), anonForwarderEnv, "отказ обязан называть переменную: %v", err)
}

// Положительный близнец отрицания выше: тот же поток с объявленным пересыльщиком.
func TestAnonymousForwarder_DeclaredSANIsAcceptedAndReachesTheSetting(t *testing.T) {
	cfg, err := loadForwarderLane(t, "registry-anonymous", registryForwarderSAN)
	require.NoError(t, err)
	require.Equal(t, registryForwarderSAN, cfg.APIServer.RegistryToken.AnonymousForwarderSAN)
}

func TestAnonymousForwarder_IsNotRequiredWithoutTheAnonymousLane(t *testing.T) {
	_, err := loadForwarderLane(t, "", "")
	require.NoError(t, err, "страж требует пересыльщика потока, которого нет")
}

// Написанное значение не той формы — отказ при любом составе полос: такой
// пересыльщик не совпал бы ни с одним предъявленным сертификатом, и поток
// поднимался бы с общим темпом молча.
func TestAnonymousForwarder_ValueOutsideTheDeclaredFormRefusesNamingTheKnob(t *testing.T) {
	for name, v := range map[string]string{
		"короткое имя службы":     "registry",
		"чужой домен доверия":     "spiffe://other.example/ns/kacho/sa/kacho-registry",
		"нет учётной записи":      "spiffe://kacho.cloud/ns/kacho",
		"пустое пространство":     "spiffe://kacho.cloud/ns//sa/kacho-registry",
		"пустая учётная запись":   "spiffe://kacho.cloud/ns/kacho/sa/",
		"хвост после записи":      "spiffe://kacho.cloud/ns/kacho/sa/kacho-registry/extra",
		"пробел по краю":          " " + registryForwarderSAN,
		"верхний регистр":         "spiffe://kacho.cloud/ns/kacho/sa/Kacho-Registry",
		"запрос в идентификаторе": registryForwarderSAN + "?x=1",
	} {
		t.Run(name, func(t *testing.T) {
			for _, principal := range []string{"registry-anonymous", ""} {
				_, err := loadForwarderLane(t, principal, v)
				require.Errorf(t, err, "значение %q принято (принципал %q)", v, principal)
				require.Contains(t, err.Error(), anonForwarderKey, "отказ обязан называть ручку: %v", err)
			}
		})
	}
}

// Пересыльщик объявлен, домен доверия — нет: необъявленный домен не узнаёт
// никого, и пересыльщик не был бы опознан ни разу.
func TestAnonymousForwarder_WithoutTheTrustDomainRefuses(t *testing.T) {
	err := config.RegistryTokenConfig{
		Endpoint: "tcp://0.0.0.0:9096", Issuer: probeIssuer, Service: "registry.probe.local",
		AnonymousClientID: "registry-anonymous", AnonymousPerSourcePerSec: 5,
		AnonymousForwarderSAN: registryForwarderSAN,
	}.Validate(config.ClientTokenConfig{}, noTrustDomain)
	require.Error(t, err)
	require.Contains(t, err.Error(), anonForwarderKey)
	require.Contains(t, err.Error(), "authn.trust-domain")
}
