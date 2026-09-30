// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TestAuditEventID_PassesCheck guards the fix where an audit writer minted its
// audit_outbox id with domain.NewKac127ID("evt") — a 17-char body that FAILS
// audit_outbox_id_check (`^evt_…{20,30}$`), so every Emit was silently rejected
// at INSERT (SQLSTATE 23514) → lost compliance trail. The writer that carried
// the defect — the pool-scoped emitter of the external provider's hooks — is
// gone with the hooks (kaname#363); the generator it was switched to,
// newAuditEventID() (22-char body), is the one every audit path uses.
func TestAuditEventID_PassesCheck(t *testing.T) {
	// Regression: the OLD generator must NOT validate (so a revert to it fails
	// here instead of silently in production).
	if err := domain.AuditEventID(domain.NewKac127ID("evt")).Validate(); err == nil {
		t.Fatal("NewKac127ID(\"evt\") unexpectedly passed audit_outbox_id_check — no audit writer may use it")
	}
	// The generator every audit path uses must always satisfy the CHECK.
	for i := 0; i < 1000; i++ {
		id := newAuditEventID()
		if err := domain.AuditEventID(id).Validate(); err != nil {
			t.Fatalf("newAuditEventID() produced CHECK-invalid id %q: %v", id, err)
		}
	}
}
