// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// email_change_code.go — ОТЛОЖЕННАЯ СМЕНА АДРЕСА и её код (задача
// PRO-Robotech/kaname#635; приёмка
// `docs/engineering/acceptance/email-change-is-confirmed-from-the-new-address.md`,
// решения Р4, Р5).
//
// # Форма кода — та же, что у кода подтверждения, и это тот же тип
//
// Значение — [RecoveryCodeValue] (форма F6b Р7): десять знаков Крокфорда из
// криптографического источника, свёртка в хранилище, приведение при
// предъявлении. Второй тип с тем же поведением разошёлся бы с первым.
//
// # Запись — принятый запрос смены, и у запроса на занятый адрес кода нет
//
// Строка заводится на каждый ПРИНЯТЫЙ запрос (Р6: она и есть единица счёта
// темпа человека) и несёт новый адрес в приведённом виде. Запрос на адрес,
// который уже занят, записывается так же, но БЕЗ свёртки (Р4): кода, который
// мог бы подойти, не существует, и такую строку не применит ни одно значение.

import (
	"fmt"
	"strings"
	"time"
)

// EmailChangeCodeID — идентификатор строки отложенной смены. Наружу не
// адресуется.
type EmailChangeCodeID string

// EmailChangeCode — запись принятого запроса смены адреса. Состав закрыт.
type EmailChangeCode struct {
	ID     EmailChangeCodeID
	UserID UserID
	// NewEmail — новый адрес в приведённом виде.
	NewEmail Email
	// Digest — свёртка кода; пусто — новый адрес занят на запросе, кода нет.
	Digest CodeDigest
	// IssuedAt — момент запроса (часы полосы); по нему считается темп (Р6).
	IssuedAt time.Time
	// ExpiresAt — абсолютный срок; величина — настройка.
	ExpiresAt time.Time
}

// Validate — запись, годная к записи: судится до базы то, что база держит
// ограничениями.
func (c EmailChangeCode) Validate() error {
	switch {
	case c.ID == "":
		return fmt.Errorf("Illegal argument email_change_code.id: required")
	case c.UserID == "":
		return fmt.Errorf("Illegal argument email_change_code.user_id: required")
	case strings.TrimSpace(string(c.NewEmail)) == "" || string(c.NewEmail) != strings.ToLower(string(c.NewEmail)):
		return fmt.Errorf("Illegal argument email_change_code.new_email: required in the normalized form")
	case c.Digest != "" && (len(c.Digest) != 64 || strings.Trim(string(c.Digest), "0123456789abcdef") != ""):
		return fmt.Errorf("Illegal argument email_change_code.code_digest: must be a hex SHA-256 or absent")
	case c.IssuedAt.IsZero():
		return fmt.Errorf("Illegal argument email_change_code.issued_at: required")
	case !c.ExpiresAt.After(c.IssuedAt):
		return fmt.Errorf("Illegal argument email_change_code.expires_at: must follow issued_at")
	}
	return nil
}
