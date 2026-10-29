// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// registry_token_issuer_guard_test.go — ИЗДАТЕЛЬ докерной полосы объявляется
// посадкой и встроенной подмены не имеет (kaname#309).
//
// Издатель — величина того же рода, что соседний адресат (`service`): он и есть
// адрес нашей полосы, а адрес у каждой установки свой. Прежнее встроенное
// умолчание называло координату соседнего продукта, и страж старта по этой
// величине не исполнялся ни разу: установка поднималась зелёной, чеканила
// удостоверения с чужим издателем и объявляла клиенту область по адресу,
// которого у неё нет. Потребитель выбирает запись набора ключей по
// объявленному издателю, отката между записями нет — вход докерным клиентом
// отказывал, а самоотчёт процесса ручку не называл.
//
// Отказ называет ключ и переменную той же формой, что у соседней величины.
// Каждое отрицание идёт в паре с положительным близнецом, отличным ровно одним
// фактом.
package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

const (
	registryIssuerKey = "api-server.registry-token.issuer"
	registryIssuerEnv = "KANAME_API_SERVER__REGISTRY_TOKEN__ISSUER"
	probeIssuer       = "https://access.example.test/iam/token"
)

// issuerLane — полоса с поднятым слушателем и объявленным адресатом; издатель —
// единственная переменная пробы.
func issuerLane(issuer string) config.RegistryTokenConfig {
	return config.RegistryTokenConfig{
		Endpoint: "tcp://0.0.0.0:9096",
		Service:  "registry.probe.local",
		Issuer:   issuer,
	}
}

// Отрицание: слушатель поднят, издатель не объявлен — пуск отвергается, и отказ
// называет ключ и переменную.
func TestRegistryTokenIssuer_UndeclaredWithTheListenerUpRefusesNamingTheKnob(t *testing.T) {
	err := issuerLane("").Validate(config.ClientTokenConfig{}, noTrustDomain)
	require.Error(t, err, "полоса поднята без издателя: удостоверения ушли бы с издателем, "+
		"которого посадка не объявляла")
	require.Contains(t, err.Error(), registryIssuerKey, "отказ обязан называть ключ: %v", err)
	require.Contains(t, err.Error(), registryIssuerEnv, "отказ обязан называть переменную: %v", err)
}

// Строка из одних пробелов объявлением не является — тот же отказ.
func TestRegistryTokenIssuer_BlankIsNotADeclaration(t *testing.T) {
	err := issuerLane("   ").Validate(config.ClientTokenConfig{}, noTrustDomain)
	require.Error(t, err)
	require.Contains(t, err.Error(), registryIssuerKey)
}

// Положительный близнец: тот же вход с объявленным издателем проходит, и
// действующая величина — объявленная, а не подставленная.
func TestRegistryTokenIssuer_DeclaredIsAcceptedAndIsTheEffectiveValue(t *testing.T) {
	lane := issuerLane(probeIssuer)
	require.NoError(t, lane.Validate(config.ClientTokenConfig{}, noTrustDomain))
	require.Equal(t, probeIssuer, lane.TokenIssuer())
}

// Без слушателя полосы нет, и требовать издателя не за что.
func TestRegistryTokenIssuer_IsNotRequiredWithTheListenerDown(t *testing.T) {
	require.NoError(t, config.RegistryTokenConfig{}.Validate(config.ClientTokenConfig{}, noTrustDomain))
}

// Путь подачи: переменная доезжает до поля через загрузчик.
func TestRegistryTokenIssuer_EnvReachesTheSetting(t *testing.T) {
	t.Setenv(registryIssuerEnv, probeIssuer)
	cfg, err := config.Load("")
	require.NoError(t, err)
	require.Equal(t, probeIssuer, cfg.APIServer.RegistryToken.TokenIssuer())
}
