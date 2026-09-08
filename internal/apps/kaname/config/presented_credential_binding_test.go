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
// Половина пары «публичный фронт поднят, читателя предъявленного нет» хуже
// отсутствия обеих: она выглядит настроенной. Арендатор дотягивается до
// поверхности, предъявляет годное удостоверение и получает тот же отказ, что и
// предъявивший мусор, — потому что назвать его нечем.
//
// # Антецедент — ПОДНЯТЫЙ ФРОНТ, а не объявленная посадка
//
// Прежнее связывание требовало читателя при посадке `own`, которую не выбирает
// ни один профиль развёртывания. Собственный публичный фронт при этом
// поднимается на ЛЮБОЙ посадке: его поднимает объявленный адрес, а не выбор
// посадки. Связывание существовало, его антецедент не наступал никогда, и
// выглядело всё настроенным.

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

// TestKAN_BIND_01_PublicFrontWithoutAReaderRefusesToStart — фронт поднят,
// читателя нет ⇒ отказ в старте, и он называет ОБЕ ручки.
func TestKAN_BIND_01_PublicFrontWithoutAReaderRefusesToStart(t *testing.T) {
	var off PresentedCredentialConfig
	err := off.ValidateBinding(true, "tcp://0.0.0.0:9098", IdentityProviderExternal)
	if err == nil {
		t.Fatal("поднятый публичный фронт без читателя предъявленного принят: половина пары " +
			"выглядит настроенной, а арендатору нечем назваться")
	}
	msg := err.Error()
	for _, knob := range []string{"api-server.rest-endpoint", "authn.presented-credential.enabled"} {
		if !strings.Contains(msg, knob) {
			t.Errorf("отказ не называет ручку %q — оператору нечем снять требование:\n%s", knob, msg)
		}
	}
}

// TestKAN_BIND_02_TheSameProfileWithAReaderStarts — ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ,
// отличается ровно одним фактом: читатель включён.
//
// Без него «отказывает в старте» зеленело бы на страже, отвергающем любой
// профиль.
func TestKAN_BIND_02_TheSameProfileWithAReaderStarts(t *testing.T) {
	on := bindReaderOn()
	if err := on.ValidateBinding(true, "tcp://0.0.0.0:9098", IdentityProviderExternal); err != nil {
		t.Fatalf("законная посадка отвергнута: фронт поднят И читатель включён: %v", err)
	}
	// И величины читателя при этом обязаны быть годными — связывание не
	// подменяет проверку самих величин.
	if err := on.Validate(bindSigningOn(), bindTokenTTL); err != nil {
		t.Fatalf("величины включённого читателя отвергнуты: %v", err)
	}
}

// TestKAN_BIND_03_NoFrontMeansNoRequirement — ВТОРАЯ ПОЛОВИНА связывания.
//
// Страж, требующий читателя там, где предъявлять его некому, отвергал бы
// законную посадку — то есть требовал бы того, чем не пользуются. Предмет
// стража — ПРОТИВОРЕЧИЕ, а не наличие ручки.
func TestKAN_BIND_03_NoFrontMeansNoRequirement(t *testing.T) {
	var off PresentedCredentialConfig
	for _, addr := range []string{"", "   "} {
		if err := off.ValidateBinding(true, addr, IdentityProviderExternal); err != nil {
			t.Errorf("посадка БЕЗ собственного публичного фронта отвергнута (адрес %q): %v", addr, err)
		}
	}
}

// TestKAN_BIND_04_OwnPostureStillRequiresTheReader — прежний антецедент НЕ
// потерян: посадка, у которой нет края платформы, требует читателя и без
// поднятого фронта.
//
// Требование ПЕРЕЕХАЛО из таблицы полос сюда, а не исчезло: два стража об одном
// предмете разошлись бы молча, поэтому он один, а антецедент у него —
// дизъюнкция.
func TestKAN_BIND_04_OwnPostureStillRequiresTheReader(t *testing.T) {
	var off PresentedCredentialConfig
	err := off.ValidateBinding(true, "", IdentityProviderOwn)
	if err == nil {
		t.Fatal("посадка без края платформы принята без читателя предъявленного — " +
			"арендатору нечем назваться, и все публичные RPC отвечают честным " +
			"и бесполезным отказом")
	}
	if !strings.Contains(err.Error(), IdentityProviderSetting) {
		t.Errorf("отказ не называет ручку посадки:\n%s", err)
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
	if err := off.ValidateBinding(false, "tcp://0.0.0.0:9098", IdentityProviderOwn); err != nil {
		t.Errorf("промежуточный шаг установки отвергнут: %v", err)
	}
	if err := off.ValidateBinding(true, "tcp://0.0.0.0:9098", IdentityProviderOwn); err == nil {
		t.Error("страж снят целиком: боевая посадка приняла фронт без читателя")
	}
}
