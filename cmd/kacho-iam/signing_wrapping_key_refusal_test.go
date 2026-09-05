// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// signing_wrapping_key_refusal_test.go — текст отказа старта при смене ключа
// обёртки (задача #1062).
//
// Отказ при старте — та самая рантайм-диагностика, без которой стенд не
// поднять: он ОБЯЗАН называть ручку и причину (security.md §«Три места, которые
// НЕ подпадают»). Проба утверждает именно это, а не факт наличия ветки.
package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/signingkeys"
	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
)

func TestSigningKeyStartupRefusalNamesTheKnob(t *testing.T) {
	inner := signingkeys.ErrWrappingKeyMismatch
	err := signingKeyStartupRefusal(config.AuthNConfig{}, inner)

	if !errors.Is(err, signingkeys.ErrWrappingKeyMismatch) {
		t.Fatalf("отказ обязан оставаться опознаваемым машинно: %v", err)
	}
	msg := err.Error()
	for _, want := range []string{
		"authn.jwks-encryption-key-hex", // ручка настройки
		"KACHO_IAM_JWKS_ENC_KEY",        // переменная окружения того же предмета
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("отказ не называет %q: %s", want, msg)
		}
	}

	// Имя переменной берётся ИЗ НАСТРОЙКИ, а не из копии: профиль, переназвавший
	// переменную, обязан увидеть в отказе своё имя, иначе оператор ищет не ту.
	renamed := signingKeyStartupRefusal(
		config.AuthNConfig{JWKSEncryptionKeyHexEnv: "KACHO_IAM_JWKS_ENC_KEY_ALT"}, inner)
	if !strings.Contains(renamed.Error(), "KACHO_IAM_JWKS_ENC_KEY_ALT") {
		t.Fatalf("отказ называет умолчание вместо заданного имени: %s", renamed.Error())
	}

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ В ДРУГУЮ СТОРОНУ: недоступное хранилище НЕ
	// выдаётся за смену ключа обёртки. Иначе отказ был бы формой без
	// содержания — он назывался бы одинаково при любой беде на старте.
	other := signingKeyStartupRefusal(config.AuthNConfig{}, errors.New("store is unavailable"))
	if errors.Is(other, signingkeys.ErrWrappingKeyMismatch) {
		t.Fatalf("посторонний отказ выдан за смену ключа обёртки: %v", other)
	}
	if strings.Contains(other.Error(), "authn.jwks-encryption-key-hex") {
		t.Fatalf("посторонний отказ называет ручку, к которой не относится: %v", other)
	}
	if !strings.Contains(other.Error(), "store is unavailable") {
		t.Fatalf("посторонний отказ потерял свою причину: %v", other)
	}
}
