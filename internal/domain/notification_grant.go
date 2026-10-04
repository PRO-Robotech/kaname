// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// notification_grant.go — запись выдачи пространства уведомлений и решение о
// письме (приёмка NTF-1 Р5; замысел З18).
//
// Решение — чистая функция состояния записи, момента постановки строки и
// полосы: ни часов, ни хранилища здесь нет. Сравнение — на полной точности
// обеих сторон (CX1-08): отсечка не усекается, момент постановки не
// округляется.

import (
	"errors"
	"time"
)

// ErrNotificationGrantNotFound — записи выдачи пространства нет (переход
// `Revoke`/`Restore` с шаблоном и без).
var ErrNotificationGrantNotFound = errors.New("notification grant: no grant record for the namespace")

// ErrNotificationGrantState — переход не применим к состоянию записи: `Revoke`
// отозванного либо `Restore` без надгробия.
var ErrNotificationGrantState = errors.New("notification grant: transition does not apply to the record state")

// NotificationGrantState — состояние записи выдачи пространства и записи
// шаблона строки, прочитанное одним оператором.
type NotificationGrantState struct {
	// Revoked — надгробие на записи пространства.
	Revoked bool
	// Cutoff — отсечка пространства (момент последнего Restore); nil — не
	// восстанавливалась ни разу.
	Cutoff *time.Time
	// TemplateRevoked — надгробие на записи шаблона строки.
	TemplateRevoked bool
	// TemplateCutoff — отсечка шаблона строки; nil — нет записи шаблона либо
	// она не восстанавливалась.
	TemplateCutoff *time.Time
}

// SendDecision — исход решения о письме.
type SendDecision int

const (
	// SendDecisionUnspecified — не назван; решением не является.
	SendDecisionUnspecified SendDecision = iota
	// SendAllow — письмо разрешено.
	SendAllow
	// SendNotYetGranted — записи выдачи нет (включая неизвестное пространство).
	SendNotYetGranted
	// SendRevoked — надгробие либо строка поставлена раньше отсечки плюс полоса.
	SendRevoked
)

// DecideSend — решение о строке ленты, поставленной в enqueuedAt.
//
// found == false — записи выдачи нет: NOT_YET_GRANTED (надгробия без записи не
// бывает — запись шаблона ссылается на запись пространства внешним ключом).
// Надгробие пространства либо шаблона — REVOKED. Иначе для КАЖДОЙ имеющейся
// отсечки строка обязана быть не раньше `отсечка + полоса`, иначе REVOKED.
func DecideSend(found bool, st NotificationGrantState, enqueuedAt time.Time, guard time.Duration) SendDecision {
	if !found {
		return SendNotYetGranted
	}
	if st.Revoked || st.TemplateRevoked {
		return SendRevoked
	}
	for _, c := range []*time.Time{st.Cutoff, st.TemplateCutoff} {
		if c != nil && enqueuedAt.Before(c.Add(guard)) {
			return SendRevoked
		}
	}
	return SendAllow
}
