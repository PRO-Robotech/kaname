// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// wrapping_key_test.go — F1-09: ручка ключа ОБЁРТКИ приватной половины.
//
// Ручка та же, что была; сменился её смысл, и вместе со смыслом у неё снова
// появился потребитель — ключница. Проба утверждает обе половины: страж
// отвергает старт без годной ручки И пропускает с годной.
package config

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/keywrap"
)

func TestF1_09_WrappingKeyGuardRefusesAndAdmits(t *testing.T) {
	const goodHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

	// Форма ручки и размер ключа обёртки — ОДНА величина, а не две похожие.
	// Расхождение здесь означало бы, что страж пропускает то, чем обернуть
	// нельзя, и узналось бы это на первом порождении ключа.
	raw, err := hex.DecodeString(goodHex)
	if err != nil {
		t.Fatalf("контроль пробы сам неверен: %v", err)
	}
	if len(raw) != keywrap.KeySize {
		t.Fatalf("страж требует %d байт, обёртка — %d: два места об одном предмете", len(raw), keywrap.KeySize)
	}
	if _, err := keywrap.New(raw); err != nil {
		t.Fatalf("ключ, который страж считает годным, обёрткой не принимается: %v", err)
	}

	for name, val := range map[string]string{
		"пусто":         "",
		"не hex":        "zzzz",
		"короче нормы":  "00010203",
		"длиннее нормы": goodHex + "00",
	} {
		cfg := AuthNConfig{JWKSEncryptionKeyHex: val, JWKSEncryptionKeyHexEnv: "KACHO_IAM_JWKS_ENC_KEY_ABSENT_FOR_TEST"}
		_, err := cfg.ResolveJWKSEncryptionKeys()
		if err == nil {
			t.Fatalf("%s: негодная ручка принята — старт обязан отвергаться", name)
		}
		if !strings.Contains(err.Error(), "authn.jwks-encryption-key-hex") {
			t.Fatalf("%s: отказ обязан называть ручку: %v", name, err)
		}
		// И НИКОГДА — значение: текст отказа читает оператор, и он не обязан
		// становиться носителем секрета.
		if val != "" && strings.Contains(err.Error(), val) {
			t.Fatalf("%s: отказ вынес значение секрета наружу: %v", name, err)
		}
	}

	// Положительный контроль — с годной по длине ручкой резолв проходит. Без
	// него отрицания выше зелены на страже, не пускающем никого.
	cfg := AuthNConfig{JWKSEncryptionKeyHex: goodHex}
	keys, err := cfg.ResolveJWKSEncryptionKeys()
	if err != nil {
		t.Fatalf("годная ручка отвергнута: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("одиночная ручка дала %d ключей вместо одного", len(keys))
	}
	if len(keys[0]) != keywrap.KeySize {
		t.Fatalf("резолв вернул %d байт вместо %d", len(keys[0]), keywrap.KeySize)
	}
}
