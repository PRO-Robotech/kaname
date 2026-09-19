// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// access_key_login.go — ИСПЫТАНИЕ ПОЛОСЫ ВХОДА ключом (Ф13 Р2).
//
// # Почему это своя строка, а не строка испытания церемонии
//
// Испытание церемоний Ф7 привязано к ВЫЗЫВАЮЩЕМУ (`AccessKeyChallenge.UserID`):
// там человек уже назван сессией, и чужое испытание не находится by
// construction. У входа вызывающего нет вовсе — полоса обнаруживает человека
// по предъявленному удостоверению и до сверки не знает, кто он. Поэтому
// испытание входа привязано к КОНТЕКСТУ ФОРМЫ (печенье `kaname_form`), а
// ключом строки остаются его же байты.
//
// Две величины различаются не только ключом: у испытания входа нет процедуры
// (она одна), нет ссылки на человека (её не из чего взять) и нет права
// предъявиться в церемонии Ф7 — словари не пересекаются, потому что таблицы
// разные.
//
// Срок — та же величина контракта, что у обеих процедур Ф7 (§7 инв. 5):
// третья процедура своей величины не заводит.

import (
	"fmt"
	"time"
)

// AccessKeyLoginChallengeContextMax — предел длины контекста формы: контекст —
// 32 случайных байта в base64url без дополнения (43 знака); предел взят с
// запасом и держится ограничением схемы, а не доверием к вызывающему.
const AccessKeyLoginChallengeContextMax = 128

// AccessKeyLoginChallenge — выданное испытание полосы входа: привязано к
// контексту формы (Р2), однократно (Ф13-08) и срочно.
type AccessKeyLoginChallenge struct {
	// Challenge — случайные байты; ключ строки. Длина — та же, что у
	// испытаний церемоний (`AccessKeyChallengeBytes`).
	Challenge []byte
	// FormContext — контекст формы, под которым испытание выдано: значение
	// печенья `kaname_form`. Одно ЖИВОЕ испытание на контекст — держит
	// частичная уникальность схемы, не проверка перед вставкой (ban #10).
	FormContext string
	// IssuedAt / ExpiresAt — момент выдачи и предел срока.
	IssuedAt  time.Time
	ExpiresAt time.Time
	// ConsumedAt — момент предъявления; нулевой указатель — не предъявлено.
	ConsumedAt *time.Time
}

// Validate — самопроверка записываемого испытания.
func (c AccessKeyLoginChallenge) Validate() error {
	if len(c.Challenge) != AccessKeyChallengeBytes {
		return fmt.Errorf("Illegal argument challenge: must be %d bytes", AccessKeyChallengeBytes)
	}
	if c.FormContext == "" {
		return fmt.Errorf("Illegal argument form_context: required")
	}
	if len(c.FormContext) > AccessKeyLoginChallengeContextMax {
		return fmt.Errorf("Illegal argument form_context: must be at most %d bytes", AccessKeyLoginChallengeContextMax)
	}
	if c.IssuedAt.IsZero() || !c.ExpiresAt.After(c.IssuedAt) {
		return fmt.Errorf("Illegal argument expires_at: must be after issued_at")
	}
	return nil
}
