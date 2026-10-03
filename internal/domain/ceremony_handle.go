// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// ceremony_handle.go — РУКОЯТКА ЦЕРЕМОНИИ: `user.id`, который церемония
// регистрации ключа доступа кладёт в аутентификатор (приёмка
// `passwordless-login-with-access-key.md`, Р3 редакции 9; держатель Ф13-33).
//
// # Почему это отдельное случайное значение, а не наш идентификатор
//
// Рукоятка записывается В АУТЕНТИФИКАТОР и в синхронизируемое хранилище
// держателя, возвращается в каждом утверждении обнаруживаемого удостоверения и
// видна в интерфейсе управления удостоверениями операционной системы. Отозвать
// её оттуда нечем. Поэтому значение не выводится ни из чего нашего: 64
// случайных байта (верхняя граница нормы WebAuthn для `user.id`, §14.6.1),
// одно на человека, неизменное после заведения. Снятие человека уносит строку
// каскадом — это и есть развязка: значение в чужом хранилище больше не называет
// ничего нашего.
//
// # Почему тип непрозрачен
//
// Байты внутри не экспортируются, а производителей два и оба названы:
// `NewCeremonyHandle` — без входа, из источника случайности; и
// `RestoreCeremonyHandle` — из значения, СОХРАНЁННОГО ранее (зовёт его только
// адаптер хранилища; держит гейт `ceremony_handle_gate_test.go`). Значение,
// собранное из `id`, адреса или имени человека, подписью ни одного из них не
// выражается без обхода этих двух дверей.

import (
	"bytes"
	"crypto/rand"
	"fmt"
)

// CeremonyHandleBytes — длина рукоятки: верхняя граница нормы для `user.id`.
const CeremonyHandleBytes = 64

// CeremonyHandle — рукоятка человека: случайные байты, ни с чем не связанные.
// Нулевое значение — «рукоятки нет», а не рукоятка.
type CeremonyHandle struct{ b []byte }

// NewCeremonyHandle — производитель новой рукоятки. Входа у него нет by
// construction: значение, выводимое из чего бы то ни было о человеке, этой
// подписью не выражается.
func NewCeremonyHandle() (CeremonyHandle, error) {
	b := make([]byte, CeremonyHandleBytes)
	if _, err := rand.Read(b); err != nil {
		return CeremonyHandle{}, fmt.Errorf("ceremony handle: %w", err)
	}
	return CeremonyHandle{b: b}, nil
}

// RestoreCeremonyHandle — рукоятка из значения, сохранённого ранее; негодная
// форма — ошибка, а не рукоятка. Только для адаптера хранилища.
func RestoreCeremonyHandle(stored []byte) (CeremonyHandle, error) {
	h := CeremonyHandle{b: bytes.Clone(stored)}
	if err := h.Validate(); err != nil {
		return CeremonyHandle{}, err
	}
	return h, nil
}

// Bytes — копия байтов рукоятки: единственный выход значения наружу.
func (h CeremonyHandle) Bytes() []byte { return bytes.Clone(h.b) }

// IsZero — рукоятки нет.
func (h CeremonyHandle) IsZero() bool { return len(h.b) == 0 }

// Validate — длина нормы и не нули. Все нули означали бы, что значение не
// чеканили, а забыли, — это отличимо от негодной длины, потому что чинится
// другим.
func (h CeremonyHandle) Validate() error {
	if len(h.b) != CeremonyHandleBytes {
		return fmt.Errorf("Illegal argument user_handle: must be %d random bytes, got %d", CeremonyHandleBytes, len(h.b))
	}
	if bytes.Equal(h.b, make([]byte, CeremonyHandleBytes)) {
		return fmt.Errorf("Illegal argument user_handle: all-zero handle was not minted")
	}
	return nil
}

// CarriesNoNameOf — ЗАМОК: рукоятка не несёт ни одного ИДЕНТИФИКАТОРА
// человека — ни платформенного `id`, ни адреса почты.
//
// Проверяется ВХОЖДЕНИЕ, а не равенство: подставленный адрес, дополненный до
// длины рукоятки, равенства не дал бы, а уехал бы так же безвозвратно. Регистр
// не различается: адрес хранится приведённым, а в церемонию попадает как есть.
//
// Отображаемое имя НЕ судится, и это решение, а не пропуск. Вхождение имеет
// смысл, только пока случайные 64 байта его практически не несут: `id` — 20
// знаков, адрес — не короче пяти (`x@y.z`), и случайное вхождение того и
// другого — порядка 1e-9 и меньше на чеканку. Имя бывает в один символ, и его
// вхождение случайно — около 40% чеканок (замер: 7922 из 20000 для «A»);
// рукоятка после заведения не меняется, поэтому такой отказ был бы вечным
// отказом человеку в регистрации. Имя к тому же не идентификатор: им ничего не
// ключуют, и в церемонии оно стоит законно в соседнем поле.
func (h CeremonyHandle) CarriesNoNameOf(u User) error {
	lower := bytes.ToLower(h.b)
	for _, name := range []struct{ field, value string }{
		{"id", string(u.ID)},
		{"email", string(u.Email)},
	} {
		if name.value == "" {
			continue
		}
		if bytes.Contains(lower, bytes.ToLower([]byte(name.value))) {
			return fmt.Errorf("Illegal argument user_handle: carries the person's %s", name.field)
		}
	}
	return nil
}
