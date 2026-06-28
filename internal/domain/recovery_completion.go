// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"fmt"

	"go.uber.org/multierr"
)

// RecoveryCompletion — one row of the Kratos recovery-completed idempotency
// ledger (migration 0015). PK recovery_jti dedups at-least-once webhook
// delivery. The row stores the deterministic primary
// user_id (first row by created_at ASC) and the revoked session count so a
// duplicate delivery can replay the same Operation.metadata without re-running
// any side-effect.
type RecoveryCompletion struct {
	RecoveryJTI         string
	ExternalID          ExternalSubject
	UserID              UserID
	RevokedSessionCount int32
}

// Validate — self-validating domain entity. Length bounds
// mirror the migration CHECK constraints + the proto field annotations.
func (r RecoveryCompletion) Validate() error {
	var errs error
	if l := len(r.RecoveryJTI); l == 0 || l > 128 {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument recovery_jti: length must be 1..128"))
	}
	if l := len(r.ExternalID); l == 0 || l > 128 {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument external_id: length must be 1..128"))
	}
	if l := len(r.UserID); l == 0 || l > 64 {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument user_id: length must be 1..64"))
	}
	if r.RevokedSessionCount < 0 {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument revoked_session_count: must be >= 0"))
	}
	return errs
}
