// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package keywrap — обёртка приватной половины подписного ключа для хранения
// в базе.
//
// # Чей это ключ
//
// Ключ обёртки — уже объявленная ручка `authn.jwks-encryption-key-hex`
// (приёмка §2.5). Второй ручки об этом предмете не заводится: одна из двух
// неизбежно оказалась бы необязательной, и профиль развёртывания, задавший
// «не ту», выглядел бы настроенным.
//
// # Почему AES-256-GCM
//
// Форма ручки уже объявлена ровно 32 байтами, то есть размером ключа
// симметричного шифра. Изобретать второй размер незачем. GCM выбран потому,
// что даёт подлинность вместе с сокрытием: подменённая в базе строка не
// разворачивается, а не разворачивается в мусор, который потом окажется
// «ключом».
//
// # Что этот пакет НЕ делает
//
// Он не журналирует, не оборачивает ошибки текстом, содержащим материал, и не
// печатает ни одного байта ни на каком пути (§6.10). Текст отказа называет
// операцию, а не значение.
package keywrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// KeySize — размер ключа обёртки в байтах. Объявлен ЧИСЛОМ ровно здесь;
// страж старта конфигурации сверяется с этим числом, а не со своей копией.
const KeySize = 32

// ErrNotWrapped — предъявленное значение обёрткой не является (слишком
// коротко, чтобы нести хотя бы вектор инициализации).
var ErrNotWrapped = errors.New("keywrap: value is not a wrapped key")

// ErrUnwrap — обёртка не снимается: ключ не тот, значение повреждено или
// подменено. Причина НЕ различается намеренно — различение подсказывало бы
// предъявителю, какая половина неверна.
var ErrUnwrap = errors.New("keywrap: unwrap failed")

// Wrapper оборачивает и разворачивает приватный материал.
type Wrapper struct {
	aead cipher.AEAD
}

// New строит обёртку на ключе объявленного размера.
//
// Ключ негодного размера — ОТКАЗ, а не усечение и не растяжение: «привели к
// нужной длине» означает, что ошибка настройки становится рабочим режимом.
func New(key []byte) (*Wrapper, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("keywrap: key must be exactly %d bytes (got %d)", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("keywrap: cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keywrap: aead: %w", err)
	}
	return &Wrapper{aead: aead}, nil
}

// Wrap оборачивает приватный материал. Вектор инициализации свой у каждого
// вызова и хранится префиксом — двух одинаковых обёрток одного ключа не бывает.
func (w *Wrapper) Wrap(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, errors.New("keywrap: nothing to wrap")
	}
	nonce := make([]byte, w.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("keywrap: nonce: %w", err)
	}
	return w.aead.Seal(nonce, nonce, plain, nil), nil
}

// Unwrap снимает обёртку.
//
// Текст отказа не несёт ни байта материала и не называет, чем именно значение
// негодно: у сообщения об ошибке нет адресата, которому эта разница помогала бы
// законно.
func (w *Wrapper) Unwrap(wrapped []byte) ([]byte, error) {
	n := w.aead.NonceSize()
	if len(wrapped) <= n {
		return nil, ErrNotWrapped
	}
	plain, err := w.aead.Open(nil, wrapped[:n], wrapped[n:], nil)
	if err != nil {
		return nil, ErrUnwrap
	}
	return plain, nil
}
