// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// email_verification_code.go — КОД ПОДТВЕРЖДЕНИЯ АДРЕСА и его запись (задача
// PRO-Robotech/kaname#456; приёмка
// `docs/engineering/acceptance/access-beyond-login-needs-a-verified-address.md`,
// решение Р7).
//
// # Форма — та же, что у кода восстановления, и это тот же тип, а не копия
//
// Десять знаков алфавита Крокфорда из криптографического источника, свёртка в
// хранилище, приведение регистра, разделителей и знаков-двойников при
// предъявлении (Ф5 Р1). Значение — [RecoveryCodeValue]: тип не печатается, не
// пишется в журнал и не сериализуется, а выходит ровно двумя путями — свёрткой
// в хранилище и формой для письма. Второй тип с тем же поведением разошёлся бы
// с первым на первой правке одного из них.
//
// # Код принадлежит человеку И значению адреса
//
// Запись несёт адрес, на который код выдан (Ф6 Р10): оператор применения
// сверяет его с текущим адресом строки человека, и смена адреса после выдачи
// делает код неподходящим механизмом базы, без второй проверки в коде.

import (
	"fmt"
	"strings"
	"time"
)

// VerificationCodeValue — значение кода подтверждения: тип кода-предъявителя
// Ф5 Р1.
type VerificationCodeValue = RecoveryCodeValue

// NewVerificationCodeValue — свежий код из криптографического источника.
func NewVerificationCodeValue() (VerificationCodeValue, error) { return NewRecoveryCodeValue() }

// PresentedVerificationCode — код, как его прислал человек: регистр,
// разделители и знаки-двойники не значимы. Пустое после приведения —
// отсутствие кода.
func PresentedVerificationCode(value string) VerificationCodeValue {
	return PresentedRecoveryCode(value)
}

// VerificationCodeID — идентификатор строки кода подтверждения. Наружу не
// адресуется.
type VerificationCodeID string

// VerificationCode — запись кода подтверждения (Р7). Состав закрыт.
type VerificationCode struct {
	ID     VerificationCodeID
	UserID UserID
	// Email — значение адреса, на которое код выдан.
	Email  Email
	Digest CodeDigest
	// IssuedAt — момент выдачи (часы полосы); по нему считаются письма (Р9).
	IssuedAt time.Time
	// ExpiresAt — абсолютный срок; величина — настройка.
	ExpiresAt time.Time
	// Attempts — сколько неподошедших предъявлений засчитано коду.
	Attempts int
}

// Validate — запись, годная к выдаче: судится до базы то, что база держит
// ограничениями.
func (c VerificationCode) Validate() error {
	switch {
	case c.ID == "":
		return fmt.Errorf("Illegal argument verification_code.id: required")
	case c.UserID == "":
		return fmt.Errorf("Illegal argument verification_code.user_id: required")
	case strings.TrimSpace(string(c.Email)) == "":
		return fmt.Errorf("Illegal argument verification_code.email: required")
	case len(c.Digest) != 64 || strings.Trim(string(c.Digest), "0123456789abcdef") != "":
		return fmt.Errorf("Illegal argument verification_code.code_digest: must be a hex SHA-256")
	case c.IssuedAt.IsZero():
		return fmt.Errorf("Illegal argument verification_code.issued_at: required")
	case !c.ExpiresAt.After(c.IssuedAt):
		return fmt.Errorf("Illegal argument verification_code.expires_at: must follow issued_at")
	case c.Attempts < 0:
		return fmt.Errorf("Illegal argument verification_code.attempts: must not be negative")
	}
	return nil
}
