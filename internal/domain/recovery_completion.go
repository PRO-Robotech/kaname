// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"fmt"

	"go.uber.org/multierr"
)

// RecoveryCompletion — one row of the recovery-completed idempotency ledger.
// PK recovery_jti dedups at-least-once delivery. The row stores the
// deterministic primary user_id and the revoked session count so a duplicate
// delivery can replay the same Operation.metadata without re-running any
// side-effect.
//
// Источника события ДВА (Ф5 Р4): обратный вызов поставщика личности называет
// внешнего субъекта; наш поток восстановления (Ф5, `kacho#1271`) называет
// человека его строкой, а внешнего субъекта не несёт — у личности, заведённой
// нашей регистрацией, его нет. Поэтому `ExternalID` необязателен; заданный
// по-прежнему ограничен длиной.
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
	if l := len(r.ExternalID); l > 128 {
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
