// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
	"time"
)

// presented_credential_binding_test.go — семейство BIND приёмки KAN-AUTHN-1
// (задача продукта #2191).
//
// # Предмет
//
// Боевой старт без читателя предъявленного удостоверения выглядит настроенным:
// арендатор дотягивается до поверхности, предъявляет годное удостоверение и
// получает тот же отказ, что и предъявивший мусор, — потому что назвать его
// нечем.
//
// # Антецедент — БОЕВОЙ РЕЖИМ
//
// Прежде антецедент был дизъюнкцией «поднят собственный фронт ЛИБО посадка без
// внешнего поставщика», и пробы доказывали обе половины порознь, в том числе
// «без фронта на посадке external требования нет». Посадка у службы одна
// (kaname#363): вторая половина наступает на всяком боевом старте, и случай
// «без фронта требования нет» стал ложным — он снят, а не ослаблен.

const bindTokenTTL = 15 * time.Minute

// bindSigningOn — включённая своя чеканка: читатель проверяет подпись СВОИМ
// реестром ключей, и без неё он неисполним.
func bindSigningOn() TokenSigningConfig {
	return TokenSigningConfig{Enabled: true, Issuer: "https://kaname.example", Algorithm: "ES256"}
}

// bindReaderOn — включённый читатель со всеми величинами.
func bindReaderOn() PresentedCredentialConfig {
	return PresentedCredentialConfig{
		Enabled:            true,
		Audience:           "https://api.example",
		RevocationCacheTTL: time.Minute,
	}
}

// TestKAN_BIND_01_ProductionWithoutAReaderRefusesToStart — боевой старт без
// читателя ⇒ отказ, и он называет ручку читателя и НЕ называет снятого ключа
// посадки: совет объявить его послал бы оператора за вторым отказом.
func TestKAN_BIND_01_ProductionWithoutAReaderRefusesToStart(t *testing.T) {
	var off PresentedCredentialConfig
	err := off.ValidateBinding(true)
	if err == nil {
		t.Fatal("боевой старт без читателя предъявленного принят: арендатору нечем назваться")
	}
	msg := err.Error()
	if !strings.Contains(msg, "authn.presented-credential.enabled") {
		t.Errorf("отказ не называет ручку читателя — оператору нечем снять требование:\n%s", msg)
	}
	if strings.Contains(msg, "identity-provider") {
		t.Errorf("отказ называет снятый ключ посадки:\n%s", msg)
	}
}

// TestKAN_BIND_02_TheSameProfileWithAReaderStarts — ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ,
// отличается ровно одним фактом: читатель включён.
//
// Без него «отказывает в старте» зеленело бы на страже, отвергающем любой
// профиль.
func TestKAN_BIND_02_TheSameProfileWithAReaderStarts(t *testing.T) {
	on := bindReaderOn()
	if err := on.ValidateBinding(true); err != nil {
		t.Fatalf("законный боевой старт отвергнут: читатель включён: %v", err)
	}
	// И величины читателя при этом обязаны быть годными — связывание не
	// подменяет проверку самих величин.
	if err := on.Validate(bindSigningOn(), bindTokenTTL); err != nil {
		t.Fatalf("величины включённого читателя отвергнуты: %v", err)
	}
}

// TestKAN_BIND_05_DevPostureIsAnInstallStep — дев-посадка требования не несёт, и
// это ГРАНИЦА, а не послабление.
//
// Подъём стенда собирает боевую посадку не одним прогоном: базовый профиль
// ставит службу в дев-посадке, где своей чеканки ещё нет, и только наложенный
// сверху боевой профиль включает и её, и читателя. Страж, действующий в дев,
// отвергал бы промежуточный шаг установки — то есть требовал бы того, чего на
// нём не бывает by construction.
//
// Положительный близнец — прямо здесь: тот же вход в БОЕВОЙ посадке отвергается.
// Без него «в дев не требуем» зеленело бы на страже, снятом целиком.
func TestKAN_BIND_05_DevPostureIsAnInstallStep(t *testing.T) {
	var off PresentedCredentialConfig
	if err := off.ValidateBinding(false); err != nil {
		t.Errorf("промежуточный шаг установки отвергнут: %v", err)
	}
	if err := off.ValidateBinding(true); err == nil {
		t.Error("страж снят целиком: боевая посадка приняла отсутствие читателя")
	}
}
