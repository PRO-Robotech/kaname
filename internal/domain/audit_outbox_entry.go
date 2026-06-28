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

// AuditOutboxEntry — append-only IAM event-log row. ULID id (sortable by
// time). Migration 0013 audit_outbox.
//
// A drainer streams these into the Kafka audit-topic; the kacho-iam side
// commits domain mutation + audit_outbox row atomically (single TX).
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

// AuditEventID — ULID (26 chars base32) but DB accepts 20..30 — format
// `evt_<20..30>` (migration 0013 CHECK).
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
