// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
)

func TestRID06ClosedSecretLiteralCensus(t *testing.T) {
	for id, actor := range map[string]string{"registry-installation-rid06-S1-BEFORE-REVOKE": "O",
		"registry-installation-rid06-S1-REVOKE-ACT":               "O",
		"registry-installation-rid06-S1-AFTER-REVOKE":             "O",
		"registry-installation-rid06-S1-SEQUENTIAL-BEFORE-REVOKE": "O",
		"registry-installation-rid06-S1-SEQUENTIAL-AFTER-OVERLAP": "O",
		"registry-installation-rid06-S1-AFTER-SEQUENTIAL-REFUSAL": "O",
		"registry-installation-rid06-S1-NO-REVOKE-BEFORE":         "O",
		"registry-installation-rid06-S1-NO-REVOKE-TWIN":           "O",
		"registry-installation-rid06-S1-RECOVERY-BEFORE-REVOKE":   "O",
		"registry-installation-rid06-S1-RECOVERY-AFTER-REVOKE":    "O",
		"registry-installation-rid06-S1-EXPLICIT-CREATE-ACT":      "C",
		"registry-installation-rid06-S1-EXPLICIT-CREATE-VERIFY":   "O",
		"registry-installation-rid06-S1-RECOVERY-REAPPLY":         "O",
		"registry-installation-rid06-S1-EXPLICIT-RECOVERY-ACT":    "I",
		"registry-installation-rid06-S1-EXPLICIT-RECOVERY-VERIFY": "O",
		"registry-installation-rid06-S2-BEFORE-REVOKE":            "O",
		"registry-installation-rid06-S2-REVOKE-ACT":               "O",
		"registry-installation-rid06-S2-AFTER-REVOKE":             "O",
		"registry-installation-rid06-S2-SEQUENTIAL-BEFORE-REVOKE": "O",
		"registry-installation-rid06-S2-SEQUENTIAL-AFTER-OVERLAP": "O",
		"registry-installation-rid06-S2-AFTER-SEQUENTIAL-REFUSAL": "O",
		"registry-installation-rid06-S2-NO-REVOKE-BEFORE":         "O",
		"registry-installation-rid06-S2-NO-REVOKE-TWIN":           "O",
		"registry-installation-rid06-S2-RECOVERY-BEFORE-REVOKE":   "O",
		"registry-installation-rid06-S2-RECOVERY-AFTER-REVOKE":    "O",
		"registry-installation-rid06-S2-EXPLICIT-CREATE-ACT":      "C",
		"registry-installation-rid06-S2-EXPLICIT-CREATE-VERIFY":   "O",
		"registry-installation-rid06-S2-RECOVERY-REAPPLY":         "O",
		"registry-installation-rid06-S2-EXPLICIT-RECOVERY-ACT":    "I",
		"registry-installation-rid06-S2-EXPLICIT-RECOVERY-VERIFY": "O"} {
		t.Run(id, func(t *testing.T) {
			v := map[string]any{"jwtRIDOperator": "O"}
			want := []string{"O"}
			if actor == "I" {
				v["jwtRIDIssuer"] = "I"
				want = append(want, "I")
			}
			if actor == "C" {
				v["jwtRIDCreator"] = "C"
				want = append(want, "C")
			}
			got, err := ridNewmanClientSecrets("registry-installation-rid06", id, v)
			require.NoError(t, err)
			require.Equal(t, want, got)
			p, err := ridNewmanParentRequestPolicy(id, "https://localhost:22222", "https://localhost:9096", v)
			require.NoError(t, err)
			require.Nil(t, p)
		})
	}
}
func TestRID06SecretAdmissionRejects(t *testing.T) {
	for _, name := range []string{"unknown-phase", "missing-C", "missing-I", "empty-C", "type-I", "oversize-I", "VERIFY-C", "VERIFY-I", "READ-I", "revoke-I", "mixed-C-I", "assertion01", "assertion05", "issuance01", "issuance05"} {
		t.Run(name, func(t *testing.T) {
			id := "registry-installation-rid06-S1-EXPLICIT-CREATE-ACT"
			v := map[string]any{"jwtRIDOperator": "O", "jwtRIDCreator": "C"}
			switch name {
			case "unknown-phase":
				id = "registry-installation-rid06-S1-OTHER"
				delete(v, "jwtRIDCreator")
			case "missing-C":
				delete(v, "jwtRIDCreator")
			case "missing-I":
				id = "registry-installation-rid06-S1-EXPLICIT-RECOVERY-ACT"
				delete(v, "jwtRIDCreator")
			case "empty-C":
				v["jwtRIDCreator"] = ""
			case "type-I", "oversize-I":
				id = "registry-installation-rid06-S1-EXPLICIT-RECOVERY-ACT"
				delete(v, "jwtRIDCreator")
				v["jwtRIDIssuer"] = 1
				if name == "oversize-I" {
					v["jwtRIDIssuer"] = strings.Repeat("x", 16385)
				}
			case "VERIFY-C":
				id = "registry-installation-rid06-S1-EXPLICIT-CREATE-VERIFY"
			case "VERIFY-I", "READ-I", "revoke-I":
				delete(v, "jwtRIDCreator")
				v["jwtRIDIssuer"] = "I"
				id = map[string]string{"VERIFY-I": "registry-installation-rid06-S1-EXPLICIT-RECOVERY-VERIFY", "READ-I": "registry-installation-rid06-S1-NO-REVOKE-TWIN", "revoke-I": "registry-installation-rid06-S1-REVOKE-ACT"}[name]
			case "mixed-C-I":
				v["jwtRIDIssuer"] = "I"
			case "assertion01":
				v["rid01ClientAssertion"] = "A"
			case "assertion05":
				v["rid05ClientAssertion"] = "A"
			case "issuance01":
				v["rid01IssuanceOrigin"] = "https://localhost:9096"
			case "issuance05":
				v["rid05IssuanceOrigin"] = "https://localhost:9096"
			}
			_, err := ridNewmanClientSecrets("registry-installation-rid06", id, v)
			require.Error(t, err)
		})
	}
}
func TestRID06LiteralOwnerAndPhaseCensus(t *testing.T) {
	seen := map[string]bool{}
	for _, owner := range []string{"revoke", "sequential", "twin", "recovery"} {
		for _, mode := range []string{"S1", "S2"} {
			for _, suffix := range rid06PublicOwners[owner] {
				id := "registry-installation-rid06-" + mode + "-" + suffix
				require.False(t, seen[id])
				seen[id] = true
				_, ok := rid06PublicActor(id)
				require.True(t, ok)
			}
		}
	}
	require.Len(t, seen, 30)
	require.Len(t, rid06PublicActors, 30)
}
func TestRID06ReceiptCompositionKeepsPriorClosed(t *testing.T) {
	for _, tc := range []struct {
		id, phase string
		want      bool
	}{{"registry-installation-rid06-S1-EXPLICIT-RECOVERY-ACT", "ACT", true}, {"registry-installation-rid06-S1-EXPLICIT-RECOVERY-ACT", "VERIFY", false}, {"registry-installation-rid06-S1-OTHER", "ACT", false}} {
		t.Run(tc.id+tc.phase, func(t *testing.T) {
			e, a, b, p := rid03UnitEvidenceInputs(t)
			e.CaseID = tc.id
			e.Phase = tc.phase
			_, ok := rid06BuildTechnicalReceipt(e, a, b, &p)
			require.Equal(t, tc.want, ok)
			_, old03 := rid03BuildTechnicalReceipt(e, a, b, &p)
			_, old04 := rid04BuildTechnicalReceipt(e, a, b, &p)
			_, old05 := rid05BuildTechnicalReceipt(e, a, b, &p)
			require.False(t, old03)
			require.False(t, old04)
			require.False(t, old05)
		})
	}
}
func rid06UnitRevoke(t *testing.T, held bool) (rid03NewmanSnapshot, rid03NewmanSnapshot) {
	base := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	at := base.Add(time.Second)
	row := func(v map[string]any) rid09PrimaryRow { return rid03UnitRow(t, v) }
	gd := row(map[string]any{"id": "GD", "account_id": "A", "delegate_id": "I", "active_delegate_id": "I", "status": "ACTIVE", "revoked_at": nil, "revoked_by_type": nil, "revoked_by_id": nil, "created_at": base.Add(-time.Minute), "future": "preserved"})
	g := row(map[string]any{"id": "G", "delegation_id": "GD", "subject_type": "service_account", "subject_id": "U", "role_id": "role", "resource_type": "account", "resource_id": "A", "status": "ACTIVE", "revoked_at": nil, "revoked_by_user_id": nil, "revocation_reason": nil, "created_at": base.Add(-time.Minute), "future": "preserved"})
	ledger := row(map[string]any{"binding_id": "G", "source": "member", "member_object_type": "registry.registries", "member_object_id": "R", "fga_user": "service_account:U", "relation": "viewer", "object": "registry_registry:R"})
	fact := row(map[string]any{"object_type": "registry_registry", "object_id": "R", "relation": "viewer", "subject": "service_account:U", "source_version": base.Add(-time.Second), "created_at": base.Add(-time.Minute), "condition_name": "", "condition_params": map[string]any{}})
	a := rid03NewmanSnapshot{Raw: map[string][]rid09PrimaryRow{"grant_delegations": {gd}, "access_bindings": {g}, "access_binding_subjects": {row(map[string]any{"binding_id": "G", "subject_type": "service_account", "subject_id": "U"})}, "access_binding_emitted_tuples": {ledger}, "relation_fact": {fact}, "fga_outbox": {}, "subject_change_outbox": {}, "resource_journal": {}, "access_binding_target_members": {}, "cluster_admin_grants": {}, "operations": {}, "future_table": {}}}
	a.Whole.PrimaryFinishedAt = base
	a.Projection = rid09NewmanProjection{Accounts: []map[string]any{{"id": "A"}}, Bindings: []map[string]any{{"id": "G", "status": "ACTIVE", "revokedAt": nil, "revokedByUserId": "", "revocationReason": "REVOCATION_REASON_UNSPECIFIED", "materializedAt": "before", "createdAt": "before", "delegationId": "GD"}}, Delegations: []map[string]any{{"id": "GD", "status": "ACTIVE", "revokedAt": nil, "revokedBy": nil, "createdAt": "before"}}, Materialization: "unchanged"}
	if held {
		a.Raw["access_bindings"] = append(a.Raw["access_bindings"], row(map[string]any{"id": "otherG", "status": "ACTIVE", "revoked_at": nil}))
		a.Projection.Bindings = append(a.Projection.Bindings, map[string]any{"id": "otherG", "status": "ACTIVE"})
		a.Raw["access_binding_emitted_tuples"] = append(a.Raw["access_binding_emitted_tuples"], row(map[string]any{"binding_id": "otherG", "source": "member", "fga_user": "service_account:U", "relation": "viewer", "object": "registry_registry:R"}))
	}
	b := rid03NewmanSnapshot{Raw: map[string][]rid09PrimaryRow{}}
	raw, err := json.Marshal(a.Raw)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &b.Raw))
	raw, err = json.Marshal(a.Projection)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &b.Projection))
	b.Projection.Materialization = a.Projection.Materialization
	b.Whole.PrimaryStartedAt = base.Add(2 * time.Second)
	b.Raw["grant_delegations"][0]["status"] = json.RawMessage(`"REVOKED"`)
	b.Raw["grant_delegations"][0]["active_delegate_id"] = json.RawMessage(`null`)
	b.Raw["grant_delegations"][0]["revoked_by_type"] = json.RawMessage(`"user"`)
	b.Raw["grant_delegations"][0]["revoked_by_id"] = json.RawMessage(`"O"`)
	b.Raw["grant_delegations"][0]["revoked_at"], _ = json.Marshal(at)
	for k, v := range map[string]any{"status": "REVOKED", "revoked_by_user_id": "O", "revocation_reason": "DELEGATION_REVOKED", "revoked_at": at} {
		b.Raw["access_bindings"][0][k], _ = json.Marshal(v)
	}
	if !held {
		b.Raw["relation_fact"] = []rid09PrimaryRow{}
	}
	b.Raw["fga_outbox"] = []rid09PrimaryRow{row(map[string]any{"id": int64(1), "event_type": "fga.tuple.delete", "created_at": at, "payload": map[string]any{"user": "service_account:U", "relation": "viewer", "object": "registry_registry:R"}})}
	payload := map[string]any{"subject_id": "U", "subject_type": "service_account", "op": "binding_delete", "event_type": "binding_revoke"}
	b.Raw["subject_change_outbox"] = []rid09PrimaryRow{row(map[string]any{"id": int64(1), "subject_id": "U", "op": "binding_delete", "event_type": "binding_revoke", "payload": payload, "created_at": at})}
	b.Raw["resource_journal"] = []rid09PrimaryRow{row(map[string]any{"sequence_no": int64(1), "resource_kind": "iam_access_binding", "resource_id": "G", "project_id": "", "scope": []any{map[string]any{"type": "account", "id": "A"}}, "event_type": "UPDATED", "payload": map[string]any{"id": "G"}, "created_at": at})}
	audit := func(id, event string, payload map[string]any) rid09PrimaryRow {
		return row(map[string]any{"id": id, "event_type": event, "tenant_account_id": "A", "event_payload": payload, "created_at": at})
	}
	b.BusinessAudit = []rid09PrimaryRow{audit("evt_11111111111111111111111111", "iam.grant_delegation.revoked", map[string]any{"actor": "O", "delegation_id": "GD", "account_id": "A", "revoked_binding_count": 1}), audit("evt_22222222222222222222222222", "iam.access_binding.delegation_revoked", map[string]any{"actor": "O", "subject_type": "service_account", "subject_id": "U", "resource_type": "account", "resource_id": "A", "role_id": "role", "binding_id": "G", "delegation_id": "GD", "revocation_reason": "delegation_revoked"})}
	b.Projection.Delegations[0]["status"] = "REVOKED"
	b.Projection.Delegations[0]["revokedAt"] = "2026-11-03T12:00:01Z"
	b.Projection.Delegations[0]["revokedBy"] = map[string]any{"type": "user", "id": "O"}
	for k, v := range map[string]any{"status": "REVOKED", "revokedAt": "2026-11-03T12:00:01Z", "revokedByUserId": "O", "revocationReason": "REVOCATION_REASON_DELEGATION_REVOKED"} {
		b.Projection.Bindings[0][k] = v
	}
	return a, b
}
func TestRID06ClosedRevokeDelta(t *testing.T) {
	for _, name := range []string{"legal", "held-fact-retained", "repeated-technical-intent", "missing-intent", "extra-relation", "extra-object", "producer-clock-future", "missing-fact-removal", "held-fact-lost", "old-member-added", "old-ledger-changed", "unknown-table", "unknown-column", "GD-history-changed", "G-history-changed", "new-active-pair", "missing-business-audit", "duplicate-business-audit", "wrong-audit-actor", "wrong-audit-tenant", "wrong-subject-event", "wrong-journal-target", "projection-materialization-changed", "projection-other-account-changed", "grouped-delete-with-v-intent", "delete-set-echo", "unsorted-delete-set", "wrong-binding-audit", "wrong-GD-audit", "unknown-audit-field", "missing-revoked-column", "malformed-revoked-column", "wrong-revoking-actor"} {
		t.Run(name, func(t *testing.T) {
			held := name == "held-fact-retained" || name == "held-fact-lost"
			a, b := rid06UnitRevoke(t, held)
			switch name {
			case "grouped-delete-with-v-intent", "delete-set-echo", "unsorted-delete-set":
				ledger := rid09PrimaryRow{}
				for k, v := range a.Raw["access_binding_emitted_tuples"][0] {
					ledger[k] = v
				}
				ledger["relation"] = json.RawMessage(`"v_get"`)
				a.Raw["access_binding_emitted_tuples"] = append(a.Raw["access_binding_emitted_tuples"], ledger)
				b.Raw["access_binding_emitted_tuples"] = append(b.Raw["access_binding_emitted_tuples"], ledger)
				payload := map[string]any{"user": "service_account:U", "object": "registry_registry:R", "relations": []string{"v_get", "viewer"}}
				if name == "delete-set-echo" {
					payload["relation"] = "v_get"
				}
				if name == "unsorted-delete-set" {
					payload["relations"] = []string{"viewer", "v_get"}
				}
				b.Raw["fga_outbox"][0]["payload"], _ = json.Marshal(payload)
			case "wrong-binding-audit":
				b.BusinessAudit[1]["event_payload"] = json.RawMessage(`{"actor":"O","subject_type":"service_account","subject_id":"U","resource_type":"account","resource_id":"A","role_id":"role","binding_id":"OTHER","delegation_id":"GD","revocation_reason":"delegation_revoked"}`)
			case "wrong-GD-audit":
				b.BusinessAudit[0]["event_payload"] = json.RawMessage(`{"actor":"O","delegation_id":"OTHER","account_id":"A","revoked_binding_count":1}`)
			case "unknown-audit-field":
				b.BusinessAudit[0]["future"] = json.RawMessage(`true`)
			case "missing-revoked-column":
				delete(b.Raw["access_bindings"][0], "revoked_at")
			case "malformed-revoked-column":
				b.Raw["access_bindings"][0]["revoked_at"] = json.RawMessage(`null`)
			case "wrong-revoking-actor":
				b.Raw["grant_delegations"][0]["revoked_by_type"] = json.RawMessage(`"service_account"`)
			case "repeated-technical-intent":
				r := rid09PrimaryRow{}
				for k, v := range b.Raw["fga_outbox"][0] {
					r[k] = v
				}
				r["id"] = json.RawMessage(`2`)
				b.Raw["fga_outbox"] = append(b.Raw["fga_outbox"], r)
			case "missing-intent":
				b.Raw["fga_outbox"] = nil
			case "extra-relation":
				b.Raw["fga_outbox"][0]["payload"] = json.RawMessage(`{"user":"service_account:U","relation":"admin","object":"registry_registry:R"}`)
			case "extra-object":
				b.Raw["fga_outbox"][0]["payload"] = json.RawMessage(`{"user":"service_account:U","relation":"viewer","object":"registry_registry:other"}`)
			case "producer-clock-future":
				b.Raw["fga_outbox"][0]["created_at"] = json.RawMessage(`"2099-01-01T00:00:00Z"`)
			case "missing-fact-removal":
				b.Raw["relation_fact"] = a.Raw["relation_fact"]
			case "held-fact-lost":
				b.Raw["relation_fact"] = nil
			case "old-member-added":
				b.Raw["access_binding_target_members"] = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"binding_id": "G", "object_id": "extra"})}
			case "old-ledger-changed":
				b.Raw["access_binding_emitted_tuples"][0]["relation"] = json.RawMessage(`"admin"`)
			case "unknown-table":
				b.Raw["unknown"] = nil
			case "unknown-column":
				b.Raw["grant_delegations"][0]["future"] = json.RawMessage(`"changed"`)
			case "GD-history-changed":
				b.Raw["grant_delegations"][0]["created_at"] = json.RawMessage(`"2099-01-01T00:00:00Z"`)
			case "G-history-changed":
				b.Raw["access_bindings"][0]["created_at"] = json.RawMessage(`"2099-01-01T00:00:00Z"`)
			case "new-active-pair":
				b.Raw["grant_delegations"] = append(b.Raw["grant_delegations"], rid03UnitRow(t, map[string]any{"id": "extra", "status": "ACTIVE"}))
			case "missing-business-audit":
				b.BusinessAudit = b.BusinessAudit[:1]
			case "duplicate-business-audit":
				b.BusinessAudit = append(b.BusinessAudit, b.BusinessAudit[0])
			case "wrong-audit-actor":
				b.BusinessAudit[0]["event_payload"] = json.RawMessage(`{"actor":"C","delegation_id":"GD","account_id":"A","revoked_binding_count":1}`)
			case "wrong-audit-tenant":
				b.BusinessAudit[0]["tenant_account_id"] = json.RawMessage(`"other"`)
			case "wrong-subject-event":
				b.Raw["subject_change_outbox"][0]["subject_id"] = json.RawMessage(`"other"`)
			case "wrong-journal-target":
				b.Raw["resource_journal"][0]["resource_id"] = json.RawMessage(`"otherG"`)
			case "projection-materialization-changed":
				b.Projection.Materialization = "changed"
			case "projection-other-account-changed":
				b.Projection.Accounts[0]["id"] = "other"
			}
			_, ok := rid06RevokeRawDelta(a, b, "GD", "O")
			require.Equal(t, name == "legal" || name == "held-fact-retained" || name == "repeated-technical-intent" || name == "grouped-delete-with-v-intent", ok)
		})
	}
}

func TestRID06FailedStartupDeliveryBoundary(t *testing.T) {
	for _, name := range []string{"legal-native-operation-only", "unrelated-delivery-update", "unknown-table", "missing-table", "business-event", "public-projection"} {
		t.Run(name, func(t *testing.T) {
			a, b := rid06UnitRevoke(t, false)
			b = a
			b.Raw = map[string][]rid09PrimaryRow{}
			for table, rows := range a.Raw {
				if rows == nil {
					b.Raw[table] = nil
				} else {
					b.Raw[table] = make([]rid09PrimaryRow, len(rows))
					copy(b.Raw[table], rows)
				}
			}
			switch name {
			case "legal-native-operation-only":
				b.Raw["operations"] = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"id": "native-op"})}
			case "unrelated-delivery-update":
				b.Raw["future_table"] = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"id": "unexpected"})}
			case "unknown-table":
				b.Raw["unknown"] = nil
			case "missing-table":
				delete(b.Raw, "future_table")
			case "business-event":
				b.BusinessAudit = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"id": "unexpected"})}
			case "public-projection":
				b.Projection.Materialization = "changed"
			}
			require.Equal(t, name == "legal-native-operation-only", rid06FailedDeliveryEqual(a, b))
		})
	}
}
func TestRID06PauseDeadlineNeverExtends(t *testing.T) {
	spawned := time.Now()
	for _, name := range []string{"no-parent", "earlier-parent", "later-parent", "expired-parent"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			want := spawned.Add(20 * time.Second)
			if name != "no-parent" {
				at := spawned.Add(map[string]time.Duration{"earlier-parent": time.Second, "later-parent": time.Minute, "expired-parent": -time.Second}[name])
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, at)
				defer cancel()
				if at.Before(want) {
					want = at
				}
			}
			got := rid06PauseDeadline(ctx, spawned)
			require.True(t, got.Equal(want))
			require.False(t, got.After(spawned.Add(20*time.Second)))
		})
	}
}

// These controls run the SAME optional critical-stage controller used by every
// observer owner. They inject cancellation at real progression boundaries, not
// just the arithmetic which computes a timestamp. No PG/HTTP/child is started.
type rid06UnitBudgetWriter struct {
	deadline              time.Time
	deadlines, writes     int
	frames                []byte
	onDeadline, onWrite   func()
	deadlineErr, writeErr error
}

func (w *rid06UnitBudgetWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadlines++
	w.deadline = deadline
	if w.onDeadline != nil {
		w.onDeadline()
	}
	return w.deadlineErr
}
func (w *rid06UnitBudgetWriter) Write(raw []byte) (int, error) {
	w.writes++
	if w.onWrite != nil {
		w.onWrite()
	}
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	w.frames = append(w.frames, raw...)
	return len(raw), nil
}
func TestRID06CriticalExpiryStopsProgression(t *testing.T) {
	for _, owner := range []string{"revoke", "sequential", "recovery", "twin"} {
		for _, point := range []string{"legal", "after-pending", "after-Revoke", "before-actual-release", "after-actual-release"} {
			t.Run(owner+"/"+point, func(t *testing.T) {
				deadline := time.Now().Add(time.Minute)
				parent, end := context.WithDeadline(context.Background(), deadline)
				defer end()
				ctx, cancel := context.WithCancel(parent)
				defer cancel()
				out := &rid06UnitBudgetWriter{}
				if point == "after-actual-release" {
					out.onWrite = cancel
				}
				trace := []string{}
				actionPath := map[string]string{"revoke": "Newman-O-Revoke", "sequential": "native-O-Revoke", "recovery": "native-O-Revoke", "twin": "no-Revoke"}[owner]
				written, err := rid06RunCritical(ctx, rid06CriticalActions{
					Await: func(context.Context) error { trace = append(trace, "await"); return nil },
					Pending: func(context.Context) error {
						trace = append(trace, "pending-SQL")
						if point == "after-pending" {
							cancel()
						}
						return nil
					},
					Revoke: func(context.Context) error {
						trace = append(trace, actionPath)
						if point == "after-Revoke" {
							cancel()
						}
						return nil
					},
					Boundary: func(context.Context) error { trace = append(trace, "boundary-SQL"); return nil },
					Release: func(ctx context.Context) (bool, error) {
						trace = append(trace, "release-call")
						if point == "before-actual-release" {
							cancel()
						}
						return ridNewmanBudgetWrite(ctx, out, "continue", 20*time.Second)
					},
				})
				if point == "legal" {
					require.NoError(t, err)
					require.True(t, written)
					require.Equal(t, 1, out.writes)
					var frame string
					require.NoError(t, json.Unmarshal(out.frames, &frame))
					require.Equal(t, "continue", frame)
					require.False(t, out.deadline.After(deadline))
					return
				}
				require.Error(t, err)
				require.Equal(t, point == "after-actual-release", written)
				if point == "after-actual-release" {
					require.Equal(t, 1, out.writes)
				} else {
					require.Zero(t, out.writes)
				}
				want := []string{"await", "pending-SQL"}
				if point != "after-pending" {
					want = append(want, actionPath)
				}
				if point == "before-actual-release" || point == "after-actual-release" {
					want = append(want, "boundary-SQL", "release-call")
				}
				require.Equal(t, want, trace)
			})
		}
	}
}
func TestRID06AdmissionIPCExpiry(t *testing.T) {
	for _, frame := range []string{"payload-admission", "admit-owned-node", "run-owned-node"} {
		for _, point := range []string{"before-admission", "during-deadline-set", "after-actual-write", "write-failure", "deadline-failure", "legal"} {
			t.Run(frame+"/"+point, func(t *testing.T) {
				parent, end := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
				defer end()
				ctx, cancel := context.WithCancel(parent)
				defer cancel()
				out := &rid06UnitBudgetWriter{}
				switch point {
				case "before-admission":
					cancel()
				case "during-deadline-set":
					out.onDeadline = cancel
				case "after-actual-write":
					out.onWrite = cancel
				case "write-failure":
					out.writeErr = errors.New("controlled write failure")
				case "deadline-failure":
					out.deadlineErr = errors.New("controlled deadline failure")
				}
				wireFrame := frame
				if frame == "run-owned-node" {
					wireFrame = ridNewmanPermitMessage("")
				}
				written, err := ridNewmanBudgetWrite(ctx, out, wireFrame, 10*time.Second)
				if point == "legal" {
					require.NoError(t, err)
					require.True(t, written)
					require.Equal(t, 1, out.writes)
					return
				}
				require.Error(t, err)
				require.Equal(t, point == "after-actual-write", written)
				if point == "before-admission" {
					require.Zero(t, out.deadlines)
				}
				if point == "before-admission" || point == "during-deadline-set" || point == "deadline-failure" {
					require.Zero(t, out.writes)
				} else {
					require.Equal(t, 1, out.writes)
				}
			})
		}
	}
}
func TestRID06RevokeCreatedByIdentity(t *testing.T) {
	for _, name := range []string{"legal", "empty-typed-created_by", "foreign-typed-created_by", "empty-raw-created_by", "foreign-raw-created_by", "missing-raw-created_by", "malformed-raw-created_by", "principal-mismatch", "principal-type-mismatch", "principal-display-mismatch"} {
		t.Run(name, func(t *testing.T) {
			op := &operations.Operation{CreatedBy: "O", Principal: operations.Principal{Type: "user", ID: "O", DisplayName: "O"}}
			raw := rid03UnitRow(t, map[string]any{"created_by": "O"})
			switch name {
			case "empty-typed-created_by":
				op.CreatedBy = ""
			case "foreign-typed-created_by":
				op.CreatedBy = "C"
			case "empty-raw-created_by":
				raw["created_by"] = json.RawMessage(`""`)
			case "foreign-raw-created_by":
				raw["created_by"] = json.RawMessage(`"C"`)
			case "missing-raw-created_by":
				delete(raw, "created_by")
			case "malformed-raw-created_by":
				raw["created_by"] = json.RawMessage(`7`)
			case "principal-mismatch":
				op.Principal.ID = "C"
			case "principal-type-mismatch":
				op.Principal.Type = "service_account"
			case "principal-display-mismatch":
				op.Principal.DisplayName = "C"
			}
			require.Equal(t, name == "legal", rid06RevokeCreatorValid(op, raw, "O"))
		})
	}
}
