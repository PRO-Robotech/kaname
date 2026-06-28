// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// audit_emit.go — log helper for non-silent audit-event emit failures.
//
// Audit events are written to durable outbox tables (audit_outbox) by their
// adapters. Emit calls run AFTER the resource transaction has committed,
// so a failed emit cannot be remedied by a fail-closed rollback — the
// action has already succeeded.
//
// What an emit failure means: the action happened but its compliance trail
// is incomplete. That is a real signal — never silently dropped. Routine
// events are logged at Warn; security-critical events are logged at Error
// so they surface on alerting.
package service

import (
	"log/slog"
)

// logEmitFailure records a non-nil audit/CAEP emit error at the appropriate
// severity. emitErr == nil is a no-op. `critical` selects Error vs Warn.
func logEmitFailure(logger *slog.Logger, critical bool, channel, eventType string, emitErr error) {
	if emitErr == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	msg := channel + " emit failed"
	attrs := []any{"event_type", eventType, "err", emitErr}
	if critical {
		logger.Error(msg, attrs...)
		return
	}
	logger.Warn(msg, attrs...)
}
