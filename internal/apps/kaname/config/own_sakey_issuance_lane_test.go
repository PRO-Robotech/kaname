// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_sakey_issuance_lane_test.go — боевой старт без своего контура выдачи
// ключей служебных учёток не поднимается (задача #337).
//
// # Предмет
//
// Контур выдачи ключей переведён на свою чеканку ровно тогда, когда включён
// токен-эндпоинт платформы (`Config.SAKeyIssuanceIsOurs`). Внешнего поставщика
// у службы нет, и непереведённая выдача отказывает на всяком входе — служба при
// этом поднималась бы и выглядела исправной до первого вызова.
//
// Комбинация обязана быть либо невозможной, либо исполняемой. Исполнить её
// нечем: ключу без токен-эндпоинта некуда пойти. Поэтому она невозможна —
// отказ старта, называющий ручку эндпоинта.
//
// # Законный близнец
//
// Тот же вход с включённым токен-эндпоинтом стартует. Прежде вторым близнецом
// была та же выключенная ручка на посадке `external`, где зеркало клиента
// заводилось у поставщика; посадка снята вместе с ключом (kaname#363).
package config_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// withoutOwnSAKeyIssuance — вход случая: всё прочее выполнено, ломается ровно
// один факт — токен-эндпоинт платформы не включён.
func withoutOwnSAKeyIssuance() config.Config {
	cfg := laneCfg()
	cfg.AuthN.ClientToken = config.ClientTokenConfig{}
	return cfg
}

// withOwnSAKeyIssuance — законный близнец: тот же вход, токен-эндпоинт
// объявлен полностью, и слушатель, на котором он монтируется, поднят.
func withOwnSAKeyIssuance() config.Config {
	cfg := laneCfg()
	cfg.APIServer.RegistryToken = registryTokenLaneSettings()
	cfg.AuthN.ClientToken = clientTokenLaneSettings()
	return cfg
}

// TestOwnPostureWithoutOwnSAKeyIssuanceRefusesTheStart — боевой старт с
// невключённым токен-эндпоинтом не поднимается, и отказ называет ручку
// эндпоинта и НЕ называет снятого ключа посадки.
func TestOwnPostureWithoutOwnSAKeyIssuanceRefusesTheStart(t *testing.T) {
	cfg := withoutOwnSAKeyIssuance()
	if cfg.SAKeyIssuanceIsOurs() {
		t.Fatal("предпосылка случая не создана: контур выдачи уже переведён на свою чеканку")
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil: посадка own без своего контура выдачи поднимается, " +
			"а выдача ключа служебной учётки уходит к внешнему поставщику, которого на ней нет")
	}
	msg := err.Error()
	if !strings.Contains(msg, "authn.client-token.enabled") {
		t.Fatalf("отказ обязан называть authn.client-token.enabled, получено: %q", msg)
	}
	if strings.Contains(msg, "identity-provider") {
		t.Fatalf("отказ называет снятый ключ посадки: %q", msg)
	}
}

// TestOwnPostureWithOwnSAKeyIssuanceStarts — законный близнец: тот же вход с
// включённым токен-эндпоинтом стартует.
func TestOwnPostureWithOwnSAKeyIssuanceStarts(t *testing.T) {
	cfg := withOwnSAKeyIssuance()
	if !cfg.SAKeyIssuanceIsOurs() {
		t.Fatal("предпосылка близнеца не создана: контур выдачи не переведён")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v: посадка own со своим контуром выдачи обязана подниматься", err)
	}
}
