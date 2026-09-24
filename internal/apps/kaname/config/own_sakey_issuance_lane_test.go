// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_sakey_issuance_lane_test.go — посадка `own` без своего контура выдачи
// ключей служебных учёток не поднимается (задача #337).
//
// # Предмет
//
// Две ручки посадки независимы: `authn.identity-provider` и
// `authn.client-token.enabled`. Контур выдачи ключей переведён на свою чеканку
// ровно тогда, когда включён токен-эндпоинт платформы
// (`Config.SAKeyIssuanceIsOurs`); непереведённый контур заводит зеркало клиента
// у внешнего поставщика. На посадке `own` внешнего поставщика нет вовсе, и
// непереведённая выдача отказывает на всяком входе — служба при этом
// поднимается и выглядит исправной до первого вызова.
//
// Комбинация обязана быть либо невозможной, либо исполняемой. Исполнить её
// нечем: ключу без токен-эндпоинта некуда пойти. Поэтому она невозможна —
// отказ старта, называющий обе ручки.
//
// # Законный близнец
//
// Тот же вход с включённым токен-эндпоинтом стартует, и та же выключенная ручка
// на посадке `external` старт не останавливает: там зеркало заводится у
// существующего поставщика, и у непереведённого контура есть исполнитель.
// Без близнецов отрицание зеленело бы на страже, отвергающем всё.
package config_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// withoutOwnSAKeyIssuance — вход случая: всё прочее выполнено, ломается ровно
// один факт — токен-эндпоинт платформы не включён.
func withoutOwnSAKeyIssuance(p config.IdentityProvider) config.Config {
	cfg := laneCfg(p)
	cfg.AuthN.ClientToken = config.ClientTokenConfig{}
	return cfg
}

// withOwnSAKeyIssuance — законный близнец: тот же вход, токен-эндпоинт
// объявлен полностью, и слушатель, на котором он монтируется, поднят.
func withOwnSAKeyIssuance(p config.IdentityProvider) config.Config {
	cfg := laneCfg(p)
	cfg.APIServer.RegistryToken = registryTokenLaneSettings()
	cfg.AuthN.ClientToken = clientTokenLaneSettings()
	return cfg
}

// TestOwnPostureWithoutOwnSAKeyIssuanceRefusesTheStart — комбинация «`own` +
// невключённый токен-эндпоинт» не поднимается, и отказ называет ОБЕ ручки:
// оператору, получившему одну, нечего править во второй.
func TestOwnPostureWithoutOwnSAKeyIssuanceRefusesTheStart(t *testing.T) {
	cfg := withoutOwnSAKeyIssuance(config.IdentityProviderOwn)
	if cfg.SAKeyIssuanceIsOurs() {
		t.Fatal("предпосылка случая не создана: контур выдачи уже переведён на свою чеканку")
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil: посадка own без своего контура выдачи поднимается, " +
			"а выдача ключа служебной учётки уходит к внешнему поставщику, которого на ней нет")
	}
	msg := err.Error()
	for _, want := range []string{
		config.IdentityProviderSetting + "=" + config.IdentityProviderOwn.String(),
		"authn.client-token.enabled",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("отказ обязан называть %q, получено: %q", want, msg)
		}
	}
}

// TestOwnPostureWithOwnSAKeyIssuanceStarts — законный близнец: тот же вход с
// включённым токен-эндпоинтом стартует.
func TestOwnPostureWithOwnSAKeyIssuanceStarts(t *testing.T) {
	cfg := withOwnSAKeyIssuance(config.IdentityProviderOwn)
	if !cfg.SAKeyIssuanceIsOurs() {
		t.Fatal("предпосылка близнеца не создана: контур выдачи не переведён")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v: посадка own со своим контуром выдачи обязана подниматься", err)
	}
}

// TestExternalPostureWithoutOwnSAKeyIssuanceStarts — полосность: на посадке
// `external` у непереведённого контура исполнитель есть, и та же выключенная
// ручка старт не останавливает.
func TestExternalPostureWithoutOwnSAKeyIssuanceStarts(t *testing.T) {
	cfg := withoutOwnSAKeyIssuance(config.IdentityProviderExternal)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v: под external зеркало заводится у существующего поставщика, "+
			"и невключённый токен-эндпоинт отказом старта не является", err)
	}
}
