// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"go.uber.org/multierr"
)

// AuditOutboxEntry — строка журнала аудита `kacho_iam.audit_outbox` (заведён
// миграцией `0001_initial.sql`), дописываемая только вперёд.
//
// # Что происходит на самом деле
//
// Строка ложится в ТУ ЖЕ транзакцию, что и мутация домена, — и на этом всё
// заканчивается. Дренажа у журнала нет, приёмника аудита в продукте не
// существует ни одного, поэтому из четырёх объявленных состояний ([Status])
// достижимо ровно одно: `pending`, в котором строка и остаётся навсегда.
//
// Отсутствие доставки — не забывчивость и не «пока»: это записанное решение с
// предикатом пересмотра, и оно объясняет, почему дренаж сегодня неконструируем
// и почему журнал при этом не снят —
// `services/iam/docs/engineering/architecture/audit-outbox-has-no-receiver.md`.
// Чтобы «ноль доставленных строк за всю жизнь очереди» было ЗАМЕТНО
// (`data-integrity.md`), состояние журнала снимает периодический сканер
// (`services/iam/cmd/kacho-iam/outbox_metrics_wiring.go`), а гейт дерева
// `internal/repohygiene` требует, чтобы у объявленных колонок доставки был либо
// движитель, либо названная запись о его отсутствии.
//
// # Здесь стояло описание, неверное ЧЕТЫРЕЖДЫ
//
// Прежняя редакция объявляла: дренаж отправляет строки в топик брокера; журнал
// заведён миграцией 0013; идентификатор — ULID; ULID сортируется по времени.
// Верно из этого ноль. Брокера в продукте нет и он запрещён non-negotiable #7;
// миграция 0013 — про снятие перечня условий обхода; идентификатор собирается из
// СЛУЧАЙНЫХ байт (`newAuditEventID`, 22 символа crockford-base32), то есть по
// времени не сортируется ни в каком порядке. Опасен был не сам текст, а его
// направление: он описывал систему СЛОЖНЕЕ и исправнее, чем она есть, поэтому
// читатель уходил искать дренаж и топик вместо того, чтобы увидеть, что доставки
// нет вовсе.
type AuditOutboxEntry struct {
	ID              AuditEventID
	EventType       EventTypeName
	TenantAccountID *AccountID
	EventPayload    json.RawMessage
	Status          AuditOutboxStatus
	Attempts        int
	CreatedAt       time.Time
	NextAttemptAt   time.Time
}

func (e AuditOutboxEntry) Validate() error {
	var errs error
	errs = multierr.Append(errs, e.ID.Validate())
	errs = multierr.Append(errs, e.EventType.Validate())
	errs = multierr.Append(errs, e.Status.Validate())
	if len(e.EventPayload) == 0 {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument event_payload: required (JSON object)"))
	}
	if e.Attempts < 0 {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument attempts: must be ≥0"))
	}
	return errs
}

// AuditEventID — идентификатор записи журнала: `evt_` плюс 20…30 символов
// crockford-base32 (ограничение `audit_outbox_id_check`, миграция
// `0001_initial.sql`).
//
// Тело СЛУЧАЙНО, а не производно от времени: производитель
// (`pg.newAuditEventID`) берёт 14 байт у источника случайности и печатает из них
// 22 символа. Порядок по идентификатору поэтому НЕ является порядком по времени;
// сортировать журнал надо по `created_at`. Прежняя редакция называла его ULID —
// то есть обещала ровно ту сортируемость, которой нет.
type AuditEventID string

var evtIDRe = regexp.MustCompile(`^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$`)

func (id AuditEventID) Validate() error {
	if !evtIDRe.MatchString(string(id)) {
		return fmt.Errorf("Illegal argument id: must match ^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$")
	}
	return nil
}

// EventTypeName — `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$` (CHECK).
type EventTypeName string

var eventTypeRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

func (n EventTypeName) Validate() error {
	s := string(n)
	if l := len(s); l < 1 || l > 128 {
		return fmt.Errorf("Illegal argument event_type: length must be 1..128")
	}
	if !eventTypeRe.MatchString(s) {
		return fmt.Errorf("Illegal argument event_type: invalid format (expected `domain.action`)")
	}
	return nil
}

// AuditOutboxStatus — enum.
type AuditOutboxStatus string

const (
	AuditOutboxStatusPending  AuditOutboxStatus = "pending"
	AuditOutboxStatusInFlight AuditOutboxStatus = "in_flight"
	AuditOutboxStatusSent     AuditOutboxStatus = "sent"
	AuditOutboxStatusFailed   AuditOutboxStatus = "failed"
)

func (s AuditOutboxStatus) Validate() error {
	switch s {
	case AuditOutboxStatusPending, AuditOutboxStatusInFlight, AuditOutboxStatusSent, AuditOutboxStatusFailed:
		return nil
	default:
		return fmt.Errorf("Illegal argument status %q (allowed: pending|in_flight|sent|failed)", string(s))
	}
}
