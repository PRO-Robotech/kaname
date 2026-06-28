// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// audit_event_id_test.go — unit test for newAuditEventID.
//
// The audit_outbox id CHECK (migration 0001 audit_outbox_id_check) requires
// `^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$` — a 20..30 char body after the
// `evt_` prefix. domain.NewKac127ID produces only a 17-char body, which would
// be REJECTED by the CHECK at INSERT time; newAuditEventID emits a 22-char body
// to stay inside the bound. This test pins that invariant so a refactor back to
// the 17-char generator fails loudly here rather than at runtime in the
// AccessBinding grant/revoke writer-tx.

import (
	"regexp"
	"testing"
)

var auditEventIDCheckRe = regexp.MustCompile(`^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$`)

func TestNewAuditEventID_MatchesAuditOutboxCheck(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 1000; i++ {
		id := newAuditEventID()
		if !auditEventIDCheckRe.MatchString(id) {
			t.Fatalf("newAuditEventID()=%q does not match audit_outbox_id_check %s", id, auditEventIDCheckRe)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("newAuditEventID() produced a duplicate id %q within 1000 iterations", id)
		}
		seen[id] = struct{}{}
	}
}
