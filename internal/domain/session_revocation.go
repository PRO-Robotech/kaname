// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"fmt"
	"time"

	"go.uber.org/multierr"
)

// SessionRevocation — fast lookup table keyed by token_jti (PK). A cron
// cleanup deletes rows past ttl_expires_at (`DeleteExpired`,
// `pg/audit_session_revocation_repos.go`). Migration `0001_initial.sql`.
//
// Номер миграции здесь был неверен — стояло 0013, а это про снятие перечня
// условий обхода. Правится вместе с тем же дефектом у соседа
// (`audit_outbox_entry.go`): радиус берётся по МЕХАНИЗМУ — «номер миграции,
// названный в шапке сущности», — а не по файлу, где дефект заметили.
type SessionRevocation struct {
	TokenJTI     string
	RevokedAt    time.Time
	Reason       string
	UserID       UserID
	TTLExpiresAt time.Time
}

func (s SessionRevocation) Validate() error {
	var errs error
	if l := len(s.TokenJTI); l < 1 || l > 128 {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument token_jti: length must be 1..128"))
	}
	if len(s.Reason) > 256 {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument reason: length must be <=256"))
	}
	if s.UserID == "" {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument user_id: required"))
	}
	if s.TTLExpiresAt.IsZero() {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument ttl_expires_at: required (NOT NULL)"))
	}
	if !s.RevokedAt.IsZero() && !s.TTLExpiresAt.After(s.RevokedAt) {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument ttl_expires_at: must be > revoked_at"))
	}
	return errs
}
