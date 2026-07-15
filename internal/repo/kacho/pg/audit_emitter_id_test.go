// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

import (
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// TestAuditEmitterAdapter_EventIDPassesCheck guards the fix where
// AuditEmitterAdapter.Emit minted its audit_outbox id with
// domain.NewKac127ID("evt") — a 17-char body that FAILS audit_outbox_id_check
// (`^evt_…{20,30}$`). Every AuthN-hook audit Emit was therefore silently
// rejected at INSERT (SQLSTATE 23514) → lost compliance trail. The adapter now
// uses newAuditEventID() (22-char body), the same generator the grant/revoke and
// bootstrap audit paths use.
func TestAuditEmitterAdapter_EventIDPassesCheck(t *testing.T) {
	// Regression: the OLD generator must NOT validate (so a revert to it fails
	// here instead of silently in production).
	if err := domain.AuditEventID(domain.NewKac127ID("evt")).Validate(); err == nil {
		t.Fatal("NewKac127ID(\"evt\") unexpectedly passed audit_outbox_id_check — the adapter must not use it")
	}
	// The generator the adapter now uses must always satisfy the CHECK.
	for i := 0; i < 1000; i++ {
		id := newAuditEventID()
		if err := domain.AuditEventID(id).Validate(); err != nil {
			t.Fatalf("newAuditEventID() produced CHECK-invalid id %q: %v", id, err)
		}
	}
}
