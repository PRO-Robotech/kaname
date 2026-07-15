// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package shared

// audit.go — small helpers shared by the CRUD use-cases that emit durable
// audit_outbox compliance rows. The emit itself goes
// through Writer.EmitAuditEvent (atomic in the writer-tx); these helpers only
// support the emit-per-committed-change contract (a no-op update emits nothing).

import "github.com/PRO-Robotech/kacho/services/iam/internal/domain"

// LabelsEqual reports whether two label maps are equal (same keys + values).
// Used by Update use-cases to decide whether `labels` is a real change for the
// audit `changed_fields` set (no-op label re-set must not count as a change).
func LabelsEqual(a, b domain.Labels) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}
