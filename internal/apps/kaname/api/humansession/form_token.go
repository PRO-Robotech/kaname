// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// form_token.go — защита форм от подделки запроса (Р12): признак привязан к
// КОНТЕКСТУ формы (печенье `kaname_form`) и к её ВИДУ; контекст сменяется выдачей
// сессии, выход его не трогает.
//
// # Устройство — вычисляемый признак, без хранилища
//
// Контекст — случайное значение, которое держит только браузер (печенье, только
// по протоколу). Признак вида k для контекста K — свёртка HMAC-SHA256 с ключом K
// над строкой вида. Подделать признак, не зная K, нельзя; из признака K не
// читается (свёртка односторонняя); признак вида `logout` форме `password` не
// подходит (строка вида входит в свёртку). Хранилища у механизма нет: контекст
// сравнивается с тем, что прислано, а не с тем, что положено.
//
// Чужой контекст и чужой вид дают ОДИН отказ — различимость подсказала бы, что
// из двух подобрать (Ф3-36).

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// formContextBytes — 32 байта случайности контекста.
const formContextBytes = 32

// NewFormContext — свежий контекст формы (значение печенья `kaname_form`).
func NewFormContext() (string, error) {
	var raw [formContextBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("form context: random source: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// FormToken — признак вида kind для контекста context.
func FormToken(context string, kind domain.FormKind) string {
	mac := hmac.New(sha256.New, []byte(context))
	_, _ = mac.Write([]byte("kaname_form:" + string(kind)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// JudgeFormToken — проверка на форме, меняющей состояние: признак есть, его
// вид — вид этой формы, его контекст — контекст печенья запроса. Отказы:
// отсутствует — *FieldError по полю `csrfToken`; есть и не подошёл (чужой вид
// либо чужой контекст либо контекста нет) — ErrFormTokenRejected.
func JudgeFormToken(context string, kind domain.FormKind, presented string) error {
	if presented == "" {
		return FieldRequired("csrfToken")
	}
	if context == "" {
		return ErrFormTokenRejected
	}
	want := FormToken(context, kind)
	if subtle.ConstantTimeCompare([]byte(want), []byte(presented)) != 1 {
		return ErrFormTokenRejected
	}
	return nil
}
