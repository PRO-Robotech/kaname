// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// wrapping_key_list_test.go — ручка ключа обёртки принимает ПЕРЕЧЕНЬ (задача
// #1065): первый оборачивает, все открывают.
//
// Ручка та же — второй об этом предмете не заводится: одна из двух неизбежно
// оказалась бы необязательной, и профиль, задавший «не ту», выглядел бы
// настроенным. Проба утверждает порядок, вырожденное значение и то, что
// одиночное значение остаётся законным входом.
package config

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/keywrap"
)

const (
	keyHexA = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	keyHexB = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
	keyHexC = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("контроль пробы сам неверен: %v", err)
	}
	return b
}

// absentEnv — имя переменной, которой заведомо нет: иначе проба читала бы
// окружение прогоняющего и её вердикт зависел бы от машины.
const absentEnv = "KANAME_JWKS_ENC_KEY_ABSENT_FOR_TEST"

// TestWrappingKeyListKeepsTheDeclaredOrder — перечень читается В ПОРЯДКЕ
// объявления, и первый остаётся первым.
//
// Порядок здесь несущий: первым ключом делается КАЖДАЯ новая обёртка, поэтому
// перестановка означала бы, что хранилище шифруется прежним ключом и переход
// не завершается никогда.
func TestWrappingKeyListKeepsTheDeclaredOrder(t *testing.T) {
	cfg := AuthNConfig{
		JWKSEncryptionKeyHex:    keyHexA + "," + keyHexB + "," + keyHexC,
		JWKSEncryptionKeyHexEnv: absentEnv,
	}
	keys, err := cfg.ResolveJWKSEncryptionKeys()
	if err != nil {
		t.Fatalf("годный перечень отвергнут: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("названо ключей 3, резолв вернул %d", len(keys))
	}
	for i, want := range []string{keyHexA, keyHexB, keyHexC} {
		if string(keys[i]) != string(mustDecodeHex(t, want)) {
			t.Fatalf("ключ на позиции %d не тот, что назван %d-м", i+1, i+1)
		}
		if len(keys[i]) != keywrap.KeySize {
			t.Fatalf("ключ на позиции %d — %d байт вместо %d", i+1, len(keys[i]), keywrap.KeySize)
		}
	}

	// Перечень принимается ОБЁРТКОЙ ровно в том виде, в каком его вернул
	// резолв: два места об одном предмете разошлись бы молча.
	if _, err := keywrap.New(keys...); err != nil {
		t.Fatalf("перечень, который страж считает годным, обёрткой не принимается: %v", err)
	}
}

// TestASingleWrappingKeyRemainsALawfulValue — одиночное значение остаётся
// законным входом.
//
// Положительный контроль обратной совместимости: перечень из одного — это
// сегодняшний профиль развёртывания, и ни один из них не обязан меняться
// оттого, что смена ключа стала возможной.
func TestASingleWrappingKeyRemainsALawfulValue(t *testing.T) {
	cfg := AuthNConfig{JWKSEncryptionKeyHex: keyHexA, JWKSEncryptionKeyHexEnv: absentEnv}
	keys, err := cfg.ResolveJWKSEncryptionKeys()
	if err != nil {
		t.Fatalf("одиночное значение отвергнуто: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("одиночное значение дало %d ключей", len(keys))
	}
}

// TestDegenerateWrappingKeyListIsEmptyNotOne — вырожденное значение читается
// как ПУСТОЕ, а не как перечень из одного.
//
// Канонический вход этого класса — одинокая запятая: длина строки 1, элементов
// ноль. Страж, меряющий длину, объявил бы перечень непустым, и служба
// поднялась бы без ключа обёртки вовсе.
func TestDegenerateWrappingKeyListIsEmptyNotOne(t *testing.T) {
	for name, raw := range map[string]string{
		"пусто":             "",
		"одинокая запятая":  ",",
		"только запятые":    ",,,",
		"запятые и пробелы": " , , ",
		"пробельная строка": "   ",
	} {
		cfg := AuthNConfig{JWKSEncryptionKeyHex: raw, JWKSEncryptionKeyHexEnv: absentEnv}
		_, err := cfg.ResolveJWKSEncryptionKeys()
		if err == nil {
			t.Fatalf("%s: вырожденное значение принято как перечень", name)
		}
		if !strings.Contains(err.Error(), "authn.jwks-encryption-key-hex") {
			t.Fatalf("%s: отказ обязан называть ручку: %v", name, err)
		}
	}
}

// TestBadEntryOfTheListNamesItsPositionAndNeverTheValue — негодная запись
// отвергается с НОМЕРОМ позиции и без значения.
func TestBadEntryOfTheListNamesItsPositionAndNeverTheValue(t *testing.T) {
	const bad = "zzzz"
	for name, tc := range map[string]struct {
		raw  string
		want string
	}{
		"не hex вторым":         {keyHexA + "," + bad, "2"},
		"короче нормы вторым":   {keyHexA + ",00010203", "2"},
		"длиннее нормы третьим": {keyHexA + "," + keyHexB + "," + keyHexC + "00", "3"},
	} {
		cfg := AuthNConfig{JWKSEncryptionKeyHex: tc.raw, JWKSEncryptionKeyHexEnv: absentEnv}
		_, err := cfg.ResolveJWKSEncryptionKeys()
		if err == nil {
			t.Fatalf("%s: негодная запись перечня принята", name)
		}
		msg := err.Error()
		if !strings.Contains(msg, "authn.jwks-encryption-key-hex") {
			t.Fatalf("%s: отказ не называет ручку: %v", name, err)
		}
		if !strings.Contains(msg, tc.want) {
			t.Fatalf("%s: отказ не называет позицию %s: %v", name, tc.want, err)
		}
		// И НИКОГДА — значение: текст отказа читает оператор, и он не обязан
		// становиться носителем секрета.
		for _, secret := range []string{keyHexA, keyHexB, keyHexC} {
			if strings.Contains(msg, secret) {
				t.Fatalf("%s: отказ вынес значение наружу: %v", name, err)
			}
		}
	}
}

// TestRepeatedWrappingKeyIsRefused — повтор одного значения ОТВЕРГАЕТСЯ.
//
// Повтор означает смену, которой не было: оператор считает, что ключ сменён,
// а обёрнуто и открывается всё тем же. Молча принять значило бы, что число
// названных ключей перестаёт совпадать с числом ключей, которыми что-то
// можно открыть, — и печатаемая при старте величина начинает лгать.
func TestRepeatedWrappingKeyIsRefused(t *testing.T) {
	cfg := AuthNConfig{
		JWKSEncryptionKeyHex:    keyHexA + "," + keyHexB + "," + keyHexA,
		JWKSEncryptionKeyHexEnv: absentEnv,
	}
	_, err := cfg.ResolveJWKSEncryptionKeys()
	if err == nil {
		t.Fatalf("перечень с повтором принят")
	}
	msg := err.Error()
	if !strings.Contains(msg, "authn.jwks-encryption-key-hex") {
		t.Fatalf("отказ не называет ручку: %v", err)
	}
	// Названы ОБЕ позиции: без второй оператор не знает, какую запись снять.
	for _, want := range []string{"1", "3"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("отказ не называет позицию %s: %v", want, err)
		}
	}
	if strings.Contains(msg, keyHexA) {
		t.Fatalf("отказ вынес значение наружу: %v", err)
	}

	// Положительный контроль: РАЗНЫЕ значения на тех же позициях проходят.
	ok := AuthNConfig{
		JWKSEncryptionKeyHex:    keyHexA + "," + keyHexB + "," + keyHexC,
		JWKSEncryptionKeyHexEnv: absentEnv,
	}
	if _, err := ok.ResolveJWKSEncryptionKeys(); err != nil {
		t.Fatalf("перечень без повторов отвергнут: %v", err)
	}
}
