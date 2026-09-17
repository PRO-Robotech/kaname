// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package registration

// refusals.go — отказы регистрации (Р3). Тексты — контракт; причины наружу не
// уходят.

import "errors"

// TextRegistrationRefused — ОДИН текст отказа на занятость адреса и потолок
// темпа заведения (Р3, Ф4-11/12): ни занятости, ни величины предела он не
// называет. Отказы правила пароля — осознанное исключение: они называют поле и
// правило (Ф1-32), потому что пароль вызывающий знает сам.
const TextRegistrationRefused = "registration refused"

// ReasonRegistrationRefused — машинный признак того же отказа
// (`ErrorInfo.reason`); один на обе причины.
const ReasonRegistrationRefused = "REGISTRATION_REFUSED"

// ErrRefused — единый отказ регистрации. Занятый адрес и исчерпанный предел
// темпа возвращают ЭТОТ сентинел без обёртки: тело отказа побайтово равно.
var ErrRefused = errors.New(TextRegistrationRefused)

// AuditUserRegistered — событие регистрации в очереди аудита (Ф3-47: своё
// событие, выдача сессии его не дублирует).
const AuditUserRegistered = "iam.user.registered"
