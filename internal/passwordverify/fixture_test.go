// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// fixture_test.go — построение проверочных значений для проб.
//
// Значения строит СТОРОННЯЯ библиотека, а не продукт: значение наследуемого
// формата продукт не пишет вовсе, и построй его проба нашим кодом — фикстура
// стала бы снисходительнее продукта (`e2e-flow.md` §5), а заодно доказывала бы
// саму себя.
package passwordverify_test

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// bcryptValue — значение наследуемого формата с названной стоимостью.
func bcryptValue(t *testing.T, password string, cost int) string {
	t.Helper()
	raw, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		t.Fatalf("фикстура НЕ ПОСТРОЕНА: значение bcrypt стоимости %d не построено: %v", cost, err)
	}
	return string(raw)
}

// argon2idValue — значение объявленного формата с названными параметрами, в
// разметке PHC — той самой, в какой его кладёт прежний поставщик личности.
func argon2idValue(t *testing.T, password string, memory, iterations uint32, parallelism uint8, keyLen uint32) string {
	t.Helper()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("фикстура НЕ ПОСТРОЕНА: соль не получена: %v", err)
	}
	key := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory, iterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// argon2idValueWithParams — значение, чья РАЗМЕТКА объявляет названные
// параметры, а тело посчитано ими же. Отличается от предыдущей тем, что
// принимает параллельность числом сверх однобайтового диапазона: такое значение
// продукт обязан отвергнуть разбором, не приводя его к типу читателя.
func argon2idValueWithParams(t *testing.T, memory, iterations, parallelism uint32) string {
	t.Helper()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("фикстура НЕ ПОСТРОЕНА: соль не получена: %v", err)
	}
	body := make([]byte, 32)
	if _, err := rand.Read(body); err != nil {
		t.Fatalf("фикстура НЕ ПОСТРОЕНА: тело не получено: %v", err)
	}
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory, iterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(body))
}
