// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
// Строка ложится в ТУ ЖЕ транзакцию, что и мутация домена, и оттуда вывозится в
// приёмник журнала — поток структурных записей службы
// (`services/iam/cmd/kacho-iam/audit_shipper_wiring.go`, механизм — `pkg/audit`).
// Состояние строки после этого помечено доставленным, а состояние очереди
// целиком снимает периодический сканер
// (`services/iam/cmd/kacho-iam/outbox_metrics_wiring.go`).
//
// # Здесь было описано ОТСУТСТВИЕ доставки — у него больше нет предмета
//
// Прежняя редакция объясняла, почему дренаж неконструируем: приёмника аудита не
// существовало ни одного, и из четырёх объявленных состояний достижимо было
// ровно одно. Оба утверждения были верны на день записи и перестали быть
// верными вместе с приёмником (#812): состояний теперь ДВА и оба достижимы,
// потому что словарь сужен до того, что продукт производит.
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

// AuditOutboxStatus — состояние ДОСТАВКИ строки журнала.
//
// Значений ровно два, и столько же допускает ограничение таблицы (миграция
// `20260823001500_audit_journal_gets_its_receiver.sql`). Прежде их объявлялось четыре:
// «в полёте» и «отказ» не писал никто и никогда — полёта не существует, потому
// что строка держится блокировкой своей транзакции от клейма до пометки, а
// терминального отказа не существует, потому что у приёмника нет класса «не
// приму никогда». Значение, которого продукт произвести не умеет, обещает
// подсистему, которой нет.
type AuditOutboxStatus string

const (
	AuditOutboxStatusPending AuditOutboxStatus = "pending"
	AuditOutboxStatusSent    AuditOutboxStatus = "sent"
)

func (s AuditOutboxStatus) Validate() error {
	switch s {
	case AuditOutboxStatusPending, AuditOutboxStatusSent:
		return nil
	default:
		return fmt.Errorf("Illegal argument status %q (allowed: pending|sent)", string(s))
	}
}
