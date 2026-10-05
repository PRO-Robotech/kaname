// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// access_key_login.go — ИСПЫТАНИЕ ПОЛОСЫ ВХОДА ключом доступа (Ф13 Р2; задача
// PRO-Robotech/kaname#613).
//
// # Почему это своя строка, а не строка испытания церемонии
//
// Испытание церемоний Ф7 привязано к ВЫЗЫВАЮЩЕМУ (`AccessKeyChallenge.UserID`):
// там человек уже назван сессией. У входа вызывающего нет — полоса
// обнаруживает человека по предъявленному удостоверению и до сверки не знает,
// кто он. Поэтому испытание входа привязано к КОНТЕКСТУ ФОРМЫ (печенье
// `kaname_form`), а ключом строки остаются его же байты; словари двух видов
// испытаний не пересекаются, потому что таблицы разные.
//
// # Моменты ставит база
//
// Выдача, срок и предъявление сравниваются одними часами — часами базы: у
// службы больше одной реплики, и испытание, выданное одной, предъявляется
// другой. Поэтому в этом значении моментов НЕТ вовсе: срок приносится
// величиной (та же, что у обеих процедур Ф7 — §7 инв. 5), а момент выдачи и
// предел ставит оператор хранилища.

import "fmt"

// AccessKeyLoginChallengeContextMax — предел длины контекста формы: контекст —
// 32 случайных байта в base64url без дополнения (43 знака); предел с запасом
// держит ограничение схемы, а не доверие к вызывающему.
const AccessKeyLoginChallengeContextMax = 128

// AccessKeyLoginChallenge — выдаваемое испытание полосы входа: привязано к
// контексту формы (Р2), однократно (Ф13-08) и срочно.
type AccessKeyLoginChallenge struct {
	// Challenge — случайные байты; ключ строки. Длина — та же, что у
	// испытаний церемоний (`AccessKeyChallengeBytes`).
	Challenge []byte
	// FormContext — контекст формы, под которым испытание выдано. Одно ЖИВОЕ
	// испытание на контекст держит частичная уникальность схемы, а не
	// проверка перед вставкой (ban #10).
	FormContext string
}

// Validate — самопроверка выдаваемого испытания.
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
	return nil
}
