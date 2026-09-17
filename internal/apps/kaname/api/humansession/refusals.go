// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// refusals.go — отказы полосы (Р2, Р10, Р11, Р12). Каждый — свой тип либо
// сентинел: транспорт ветвится по типу, а тексты, уходящие клиенту, стоят
// ЗДЕСЬ константами — они контракт (§8 инв. 3) и не несут причины.

import (
	"errors"
	"fmt"
	"time"
)

// Тексты отказов — контракт полосы. Один текст на все причины отказа входа
// (Ф1 Р3, F4d-16), фиксированные тексты недоступности (форма Ф-п).
const (
	TextAuthenticationFailed = "authentication failed"
	TextTooManyAttempts      = "too many attempts; try again later"
	// #nosec G101 -- ТЕКСТ ОТКАЗА, уезжающий клиенту, а не значение удостоверения.
	TextFormTokenRejected   = "form token rejected"
	TextLogoutNotPerformed  = "logout not performed; try again later"
	TextRequestNotPerformed = "request not performed; try again later"
)

// Причины из закрытого перечня (`ErrorInfo.reason`, Р2). Причины
// «требуется сменить пароль» в перечне НЕТ: поле сессии, которое её
// производило бы, снято с контракта (kacho#2697, kaname#201).
const (
	// #nosec G101 -- машинный ПРИЗНАК ПРИЧИНЫ ОТКАЗА (`ErrorInfo.reason`), не секрет.
	ReasonFormTokenRejected = "FORM_TOKEN_REJECTED"
	ReasonTooManyAttempts   = "TOO_MANY_ATTEMPTS"
)

// ErrAuthenticationFailed — ОДИН отказ на все причины входа и на неподошедшее
// подтверждение смены пароля (Ф3-02, Ф3-20 б/в).
var ErrAuthenticationFailed = errors.New(TextAuthenticationFailed)

// ErrStoreUnavailable — хранилище не ответило; глагол не выполнен, состояние
// не изменено. Текст выбирает транспорт по глаголу (Ф3-17).
var ErrStoreUnavailable = errors.New("store unavailable")

// ErrBreachAuthorityMisconfigured — по адресу авторитета утечек отвечает не то
// (Ф3-34 б): отказ операции, а не проход.
var ErrBreachAuthorityMisconfigured = errors.New("breach check authority misconfigured")

// TooManyAttemptsError — отказ по частоте (Р10); RetryAfter — до конца окна.
type TooManyAttemptsError struct {
	Scope      FailureScope
	RetryAfter time.Duration
}

func (e *TooManyAttemptsError) Error() string { return TextTooManyAttempts }

// FieldError — отказ формы: поле названо, состояние не изменено (Ф3-05,
// Ф3-20 а, Ф3-22, Ф3-35, Ф3-36 а).
type FieldError struct {
	Field string
	Rule  string
}

func (e *FieldError) Error() string {
	if e.Rule == "" {
		return fmt.Sprintf("Illegal argument %s: required", e.Field)
	}
	return fmt.Sprintf("Illegal argument %s: %s", e.Field, e.Rule)
}

// FieldRequired — отказ формы на отсутствующем поле.
func FieldRequired(field string) error { return &FieldError{Field: field} }

// FormTokenRejectedError — признак есть и не подошёл (Ф3-36 б, Ф3-37, Ф3-38):
// чужой контекст и чужой вид не различаются.
type FormTokenRejectedError struct{}

func (e *FormTokenRejectedError) Error() string { return TextFormTokenRejected }

// ErrFormTokenRejected — сентинел того же отказа.
var ErrFormTokenRejected error = &FormTokenRejectedError{}
