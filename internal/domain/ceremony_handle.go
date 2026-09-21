// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// ceremony_handle.go — РУКОЯТКА ЦЕРЕМОНИИ: `user.id`, который церемония
// регистрации кладёт в аутентификатор.
//
// # Почему это отдельное случайное значение, а не наш идентификатор
//
// Рукоятка записывается В АУТЕНТИФИКАТОР и в синхронизируемое хранилище
// держателя, возвращается в каждом утверждении обнаруживаемого удостоверения и
// видна в интерфейсе управления удостоверениями операционной системы. Отозвать
// её нечем: писать в чужое хранилище мы не можем. Значит, всё, что в неё
// положено, уехало навсегда — и платформенный `id`, и адрес, и имя.
//
// Отсюда два следствия, и оба несущие. Первое: рукоятка не выводима из
// личности — норма (§14.6.1) рекомендует ровно 64 случайных байта, хранимых у
// доверяющей стороны. Второе: снятие человека РАЗВЯЗЫВАЕТ его с рукояткой —
// строка уходит каскадом, и значение, оставшееся в чужом аутентификаторе,
// больше не называет ничего нашего.
//
// # Что здесь есть и чего здесь нет
//
// Есть производитель (единственный) и две самопроверки. Нет смены: рукоятка
// заводится один раз и не меняется — смена рассинхронизировала бы строки ключей
// с тем, что уже лежит в аутентификаторах, и ни один держатель об этом не узнал
// бы до первого отказа входа.

import (
	"bytes"
	"crypto/rand"
	"fmt"
)

// CeremonyHandleBytes — длина рукоятки: рекомендация нормы §14.6.1 («64 random
// bytes»), она же предел колонки `user_access_keys.user_handle`.
const CeremonyHandleBytes = 64

// CeremonyHandle — рукоятка человека: случайные байты, не связанные ни с чем.
type CeremonyHandle []byte

// NewCeremonyHandle — ЕДИНСТВЕННЫЙ производитель рукоятки. Входа у него нет by
// construction: значение, выводимое из чего бы то ни было о человеке, этой
// подписью не выражается.
func NewCeremonyHandle() (CeremonyHandle, error) {
	h := make(CeremonyHandle, CeremonyHandleBytes)
	if _, err := rand.Read(h); err != nil {
		return nil, fmt.Errorf("ceremony handle: %w", err)
	}
	return h, nil
}

// Validate — самопроверка записываемой рукоятки: длина нормы и не нули.
// Все нули означали бы, что значение не чеканили, а забыли, — и это отличимо
// от негодной длины, потому что чинится оно другим.
func (h CeremonyHandle) Validate() error {
	if len(h) != CeremonyHandleBytes {
		return fmt.Errorf("Illegal argument user_handle: must be %d random bytes, got %d", CeremonyHandleBytes, len(h))
	}
	for _, b := range h {
		if b != 0 {
			return nil
		}
	}
	return fmt.Errorf("Illegal argument user_handle: all-zero handle was not minted, it was forgotten")
}

// CarriesNoNameOf — ЗАМОК: рукоятка не несёт ни одного имени человека.
//
// Проверяется ВХОЖДЕНИЕ, а не равенство: подставленный адрес, дополненный до
// длины рукоятки, равенства не дал бы, а уехал бы так же безвозвратно. Регистр
// не различается — адрес у нас хранится приведённым, а в церемонию попадает как
// есть.
func (h CeremonyHandle) CarriesNoNameOf(u User) error {
	for _, name := range []struct{ field, value string }{
		{"id", string(u.ID)},
		{"email", string(u.Email)},
		{"display_name", string(u.DisplayName)},
	} {
		if name.value == "" {
			continue
		}
		if bytes.Contains(bytes.ToLower(h), bytes.ToLower([]byte(name.value))) {
			return fmt.Errorf("Illegal argument user_handle: carries the person's %s — a handle already written "+
				"into an authenticator cannot be revoked or rewritten", name.field)
		}
	}
	return nil
}
