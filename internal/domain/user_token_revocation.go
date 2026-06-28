// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"fmt"
	"time"

	"go.uber.org/multierr"
)

// UserTokenRevocation — per-user "revoke-all-before" cutoff (migration 0012).
// Backs admin ForceLogout + Revoke(revoke_all_user_tokens): any token whose
// originating session authenticated at or before RevokeBefore is denied at
// refresh. One row per user (PK user_id); the cutoff only ever advances
// (monotonic GREATEST upsert at the repo layer) so a re-auth past the cutoff
// is allowed again (no permanent lockout).
type UserTokenRevocation struct {
	UserID       UserID
	RevokeBefore time.Time
	Reason       string
	RevokedBy    UserID
}

// Validate — self-validating domain entity.
func (u UserTokenRevocation) Validate() error {
	var errs error
	if u.UserID == "" {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument user_id: required"))
	}
	if u.RevokeBefore.IsZero() {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument revoke_before: required (NOT NULL)"))
	}
	if len(u.Reason) > 256 {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument reason: length must be <=256"))
	}
	return errs
}
