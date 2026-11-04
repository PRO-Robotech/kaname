// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestRID05ClosedSecretLiteralCensus(t *testing.T) {
	for id, actor := range map[string]string{
		"registry-installation-rid05-S1-KEYS-AND-REFERENCES-CLEAN":      "O",
		"registry-installation-rid05-S1-DELETED-C-SNAPSHOT":             "O",
		"registry-installation-rid05-S1-OLD-C-TOKEN-REFUSED":            "A",
		"registry-installation-rid05-S1-DELETED-C-GRANT-ACT":            "I",
		"registry-installation-rid05-S1-DELETED-C-GRANT-VERIFY":         "O",
		"registry-installation-rid05-S1-SAME-NAME-C2-SNAPSHOT":          "O",
		"registry-installation-rid05-S1-C2-NO-REVIVAL-ACT":              "I",
		"registry-installation-rid05-S1-C2-NO-REVIVAL-VERIFY":           "O",
		"registry-installation-rid05-S1-ACTIVE-DELEGATE-DELETE-ACT":     "O",
		"registry-installation-rid05-S1-ACTIVE-DELEGATE-DELETE-VERIFY":  "O",
		"registry-installation-rid05-S1-REVOKE-ONLY-DELETE-TWIN-ACT":    "O",
		"registry-installation-rid05-S1-REVOKE-ONLY-DELETE-TWIN-VERIFY": "O",
		"registry-installation-rid05-S1-EXPLICIT-C2-RECOVERY-ACT":       "I",
		"registry-installation-rid05-S1-EXPLICIT-C2-RECOVERY-VERIFY":    "O",
		"registry-installation-rid05-S1-RECOVERY-REAPPLY":               "O",
		"registry-installation-rid05-S2-KEYS-AND-REFERENCES-CLEAN":      "O",
		"registry-installation-rid05-S2-DELETED-C-SNAPSHOT":             "O",
		"registry-installation-rid05-S2-OLD-C-TOKEN-REFUSED":            "A",
		"registry-installation-rid05-S2-DELETED-C-GRANT-ACT":            "I",
		"registry-installation-rid05-S2-DELETED-C-GRANT-VERIFY":         "O",
		"registry-installation-rid05-S2-SAME-NAME-C2-SNAPSHOT":          "O",
		"registry-installation-rid05-S2-C2-NO-REVIVAL-ACT":              "I",
		"registry-installation-rid05-S2-C2-NO-REVIVAL-VERIFY":           "O",
		"registry-installation-rid05-S2-ACTIVE-DELEGATE-DELETE-ACT":     "O",
		"registry-installation-rid05-S2-ACTIVE-DELEGATE-DELETE-VERIFY":  "O",
		"registry-installation-rid05-S2-REVOKE-ONLY-DELETE-TWIN-ACT":    "O",
		"registry-installation-rid05-S2-REVOKE-ONLY-DELETE-TWIN-VERIFY": "O",
		"registry-installation-rid05-S2-EXPLICIT-C2-RECOVERY-ACT":       "I",
		"registry-installation-rid05-S2-EXPLICIT-C2-RECOVERY-VERIFY":    "O",
		"registry-installation-rid05-S2-RECOVERY-REAPPLY":               "O",
	} {
		t.Run(id, func(t *testing.T) {
			v := map[string]any{"jwtRIDOperator": "O"}
			want := []string{"O"}
			if actor == "I" {
				v["jwtRIDIssuer"] = "I"
				want = append(want, "I")
			}
			if actor == "A" {
				v["rid05ClientAssertion"] = "original-C-standing-key-signature"
				want = append(want, "original-C-standing-key-signature")
			}
			got, err := ridNewmanClientSecrets("registry-installation-rid05", id, v)
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}
func TestRID05SecretAdmissionRejects(t *testing.T) {
	for _, tc := range []struct {
		name, id string
		v        map[string]any
	}{
		{"unknown-phase", "registry-installation-rid05-S1-OTHER", map[string]any{"jwtRIDOperator": "O"}},
		{"missing-I", "registry-installation-rid05-S1-DELETED-C-GRANT-ACT", map[string]any{"jwtRIDOperator": "O"}},
		{"VERIFY-I", "registry-installation-rid05-S1-EXPLICIT-C2-RECOVERY-VERIFY", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": "I"}},
		{"C2-bearer-not-permitted", "registry-installation-rid05-S1-EXPLICIT-C2-RECOVERY-ACT", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": "I", "jwtRIDCreator": "C2"}},
		{"old-C-bearer-not-permitted", "registry-installation-rid05-S1-OLD-C-TOKEN-REFUSED", map[string]any{"jwtRIDOperator": "O", "rid05ClientAssertion": "A", "jwtRIDExpiredCreator": "C"}},
		{"missing-assertion", "registry-installation-rid05-S1-OLD-C-TOKEN-REFUSED", map[string]any{"jwtRIDOperator": "O"}},
		{"empty-assertion", "registry-installation-rid05-S1-OLD-C-TOKEN-REFUSED", map[string]any{"jwtRIDOperator": "O", "rid05ClientAssertion": ""}},
		{"type-assertion", "registry-installation-rid05-S1-OLD-C-TOKEN-REFUSED", map[string]any{"jwtRIDOperator": "O", "rid05ClientAssertion": 1}},
		{"oversize-assertion", "registry-installation-rid05-S1-OLD-C-TOKEN-REFUSED", map[string]any{"jwtRIDOperator": "O", "rid05ClientAssertion": strings.Repeat("x", 16385)}},
		{"READ-assertion", "registry-installation-rid05-S1-DELETED-C-SNAPSHOT", map[string]any{"jwtRIDOperator": "O", "rid05ClientAssertion": "A"}},
		{"other-assertion", "registry-installation-rid05-S1-OLD-C-TOKEN-REFUSED", map[string]any{"jwtRIDOperator": "O", "rid05ClientAssertion": "A", "rid01ClientAssertion": "A"}},
		{"READ-origin", "registry-installation-rid05-S1-DELETED-C-SNAPSHOT", map[string]any{"jwtRIDOperator": "O", "rid05IssuanceOrigin": "https://localhost:9096"}},
		{"03-assertion", "registry-installation-rid03-S1-GRANT-ACT", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": "I", "rid05ClientAssertion": "A"}},
		{"04-origin", "registry-installation-rid04-S1-BEFORE-RETIREMENT", map[string]any{"jwtRIDOperator": "O", "rid05IssuanceOrigin": "https://localhost:9096"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stem := "registry-installation-rid05"
			if strings.Contains(tc.id, "rid03") {
				stem = "registry-installation-rid03"
			}
			if strings.Contains(tc.id, "rid04") {
				stem = "registry-installation-rid04"
			}
			_, err := ridNewmanClientSecrets(stem, tc.id, tc.v)
			require.Error(t, err)
		})
	}
}
func TestRID05ScopedOwnedIssuancePolicy(t *testing.T) {
	for _, mode := range []string{"S1", "S2"} {
		t.Run(mode, func(t *testing.T) {
			id := "registry-installation-rid05-" + mode + "-OLD-C-TOKEN-REFUSED"
			pub, tok := "https://localhost:9098", "https://localhost:9096"
			if mode == "S2" {
				pub, tok = "https://localhost:9198", "https://localhost:9196"
			}
			p, err := ridNewmanParentRequestPolicy(id, pub, tok, map[string]any{"rid05IssuanceOrigin": tok})
			require.NoError(t, err)
			require.Equal(t, id+" :: old-standing-key-token-refusal", p.RequestName)
		})
	}
}
func TestRID05IssuancePolicyRejects(t *testing.T) {
	for _, name := range []string{"wrong-phase", "wrong-leaf", "wrong-method", "wrong-path", "wrong-port", "wrong-host", "query", "credentials", "dynamic-public-token", "other-variable", "missing-variable", "missing-policy"} {
		t.Run(name, func(t *testing.T) {
			id := "registry-installation-rid05-S1-OLD-C-TOKEN-REFUSED"
			pub := "https://localhost:9098"
			p := &ridNewmanRequestPolicy{id, id + " :: old-standing-key-token-refusal", "POST", "/iam/v1/token", "https://localhost:9096"}
			v := map[string]any{"rid05IssuanceOrigin": p.Origin}
			switch name {
			case "wrong-phase":
				id = "registry-installation-rid05-S1-DELETED-C-SNAPSHOT"
			case "wrong-leaf":
				p.RequestName += "-other"
			case "wrong-method":
				p.Method = "GET"
			case "wrong-path":
				p.Path += "/other"
			case "wrong-port":
				p.Origin = "https://localhost:9097"
				v["rid05IssuanceOrigin"] = p.Origin
			case "wrong-host":
				p.Origin = "https://127.0.0.1:9096"
				v["rid05IssuanceOrigin"] = p.Origin
			case "query":
				p.Origin += "?x=1"
			case "credentials":
				p.Origin = "https://x@localhost:9096"
			case "dynamic-public-token":
				pub = "https://localhost:22222"
			case "other-variable":
				v["rid01IssuanceOrigin"] = p.Origin
			case "missing-variable":
				delete(v, "rid05IssuanceOrigin")
			case "missing-policy":
				p = nil
			}
			require.Error(t, ridNewmanValidateRequestPolicy(id, pub, p, v))
		})
	}
}
func TestRID05DefaultDynamicPublicOriginPreserved(t *testing.T) {
	p, err := ridNewmanParentRequestPolicy("registry-installation-rid05-S1-DELETED-C-SNAPSHOT", "https://localhost:22222", "", map[string]any{})
	require.NoError(t, err)
	require.Nil(t, p)
}
func TestRID05LiteralOwnersUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, owner := range []string{"deleted", "same-name", "delete-guard", "recovery"} {
		for _, mode := range []string{"S1", "S2"} {
			for _, s := range rid05OwnedSuffixes(owner) {
				id := "registry-installation-rid05-" + mode + "-" + s
				require.False(t, seen[id])
				seen[id] = true
				_, ok := rid05NewmanActor(id)
				require.True(t, ok)
			}
		}
	}
	require.Len(t, seen, 30)
	require.Len(t, rid05NewmanActors, 30)
}
func TestRID05TechnicalReceiptCompositionKeeps03And04Closed(t *testing.T) {
	for _, tc := range []struct {
		id, phase string
		want      bool
	}{{"registry-installation-rid05-S1-EXPLICIT-C2-RECOVERY-ACT", "ACT", true}, {"registry-installation-rid05-S1-EXPLICIT-C2-RECOVERY-ACT", "VERIFY", false}, {"registry-installation-rid05-S1-OTHER", "ACT", false}} {
		t.Run(tc.id+tc.phase, func(t *testing.T) {
			e, a, b, p := rid03UnitEvidenceInputs(t)
			e.CaseID = tc.id
			e.Phase = tc.phase
			_, ok := rid05BuildTechnicalReceipt(e, a, b, &p)
			require.Equal(t, tc.want, ok)
			_, old03 := rid03BuildTechnicalReceipt(e, a, b, &p)
			_, old04 := rid04BuildTechnicalReceipt(e, a, b, &p)
			require.False(t, old03)
			require.False(t, old04)
		})
	}
}
func rid05UnitDeleteRow(t *testing.T, payload map[string]any) rid09PrimaryRow {
	return rid03UnitRow(t, map[string]any{"id": int64(1), "created_at": time.Date(2026, 11, 3, 12, 0, 1, 0, time.UTC), "event_type": "fga.tuple.delete", "payload": payload})
}
func TestRID05DeleteIntentClosedCoordinates(t *testing.T) {
	for _, name := range []string{"singleton", "grouped", "wrong-relation", "wrong-object", "wrong-user", "extra-column", "extra-payload-field", "hidden-ID", "unsorted", "duplicate-relation", "missing-relation", "write-event", "outside-clock"} {
		t.Run(name, func(t *testing.T) {
			base := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
			payload := map[string]any{"user": "service_account:I", "object": "iam_service_account:C", "relation": "v_get"}
			expected := map[rid03Tuple]bool{{"service_account:I", "v_get", "iam_service_account", "C"}: true, {"service_account:I", "v_list", "iam_service_account", "C"}: true}
			if name == "grouped" || name == "unsorted" || name == "duplicate-relation" {
				delete(payload, "relation")
				payload["relations"] = []string{"v_get", "v_list"}
			}
			switch name {
			case "wrong-relation":
				payload["relation"] = "delete"
			case "wrong-object":
				payload["object"] = "iam_service_account:C2"
			case "wrong-user":
				payload["user"] = "service_account:C2"
			case "extra-payload-field":
				payload["unknown"] = "C"
			case "hidden-ID":
				payload["object"] = "iam_service_account:other"
				payload["unknown"] = "C"
			case "unsorted":
				payload["relations"] = []string{"v_list", "v_get"}
			case "duplicate-relation":
				payload["relations"] = []string{"v_get", "v_get"}
			case "missing-relation":
				delete(payload, "relation")
			}
			row := rid05UnitDeleteRow(t, payload)
			if name == "extra-column" {
				row["future"] = json.RawMessage(`true`)
			}
			if name == "write-event" {
				row["event_type"] = json.RawMessage(`"fga.tuple.write"`)
			}
			end := base.Add(2 * time.Second)
			if name == "outside-clock" {
				end = base
			}
			_, ok := rid05DeletePayload(row, expected, base, end)
			require.Equal(t, name == "singleton" || name == "grouped", ok)
		})
	}
}
func TestRID05DeleteBusinessAuditExact(t *testing.T) {
	for _, name := range []string{"exact", "missing", "duplicate", "wrong-event", "wrong-actor", "wrong-tenant", "wrong-creator", "unknown-payload", "unknown-column", "denial-event", "old-history-changed"} {
		t.Run(name, func(t *testing.T) {
			base := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
			payload := map[string]any{"actor": "O", "resource_type": "service_account", "resource_id": "C", "account_id": "SYS"}
			switch name {
			case "wrong-actor":
				payload["actor"] = "C2"
			case "wrong-creator":
				payload["resource_id"] = "C2"
			case "unknown-payload":
				payload["future"] = true
			}
			row := rid03UnitRow(t, map[string]any{"id": "evt_11111111111111111111111111", "event_type": "iam.service_account.deleted", "tenant_account_id": "SYS", "event_payload": payload, "created_at": base.Add(time.Second)})
			if name == "wrong-event" {
				row["event_type"] = json.RawMessage(`"iam.access_binding.granted"`)
			}
			if name == "wrong-tenant" {
				row["tenant_account_id"] = json.RawMessage(`"other"`)
			}
			if name == "unknown-column" {
				row["future"] = json.RawMessage(`true`)
			}
			after := []rid09PrimaryRow{row}
			if name == "missing" {
				after = nil
			}
			if name == "duplicate" {
				copy := rid03UnitRow(t, map[string]any{})
				for k, v := range row {
					copy[k] = v
				}
				copy["id"] = json.RawMessage(`"evt_22222222222222222222222222"`)
				after = append(after, copy)
			}
			before := []rid09PrimaryRow{}
			if name == "old-history-changed" {
				before = []rid09PrimaryRow{row}
				after = nil
			}
			_, ok := rid05DeleteAuditDelta(before, after, "C", "SYS", "O", base, base.Add(2*time.Second), name == "denial-event")
			require.Equal(t, name == "exact", ok)
		})
	}
}
func TestRID05TypedDeleteAnyAndPrincipal(t *testing.T) {
	for _, name := range []string{"exact", "missing", "wrong-C2", "wrong-account", "wrong-principal", "wrong-type", "unknown-meta", "unknown-response", "not-done", "response-type-substitution"} {
		t.Run(name, func(t *testing.T) {
			meta, err := anypb.New(&iamv1.DeleteServiceAccountMetadata{ServiceAccountId: "C", AccountId: "SYS"})
			require.NoError(t, err)
			response, err := anypb.New(&emptypb.Empty{})
			require.NoError(t, err)
			op := &operations.Operation{Done: true, Principal: operations.Principal{Type: "user", ID: "O", DisplayName: "O"}, Metadata: meta, Response: response}
			switch name {
			case "missing":
				op = nil
			case "wrong-C2":
				op.Metadata, _ = anypb.New(&iamv1.DeleteServiceAccountMetadata{ServiceAccountId: "C2", AccountId: "SYS"})
			case "wrong-account":
				op.Metadata, _ = anypb.New(&iamv1.DeleteServiceAccountMetadata{ServiceAccountId: "C", AccountId: "OTHER"})
			case "wrong-principal":
				op.Principal.ID = "C2"
			case "wrong-type":
				op.Metadata.TypeUrl = "type.googleapis.com/other.DeleteServiceAccountMetadata"
			case "unknown-meta":
				op.Metadata.Value = append(op.Metadata.Value, 0x78, 1)
			case "unknown-response":
				op.Response.Value = []byte{0x78, 1}
			case "not-done":
				op.Done = false
			case "response-type-substitution":
				op.Response.TypeUrl = "type.googleapis.com/other.Empty"
			}
			require.Equal(t, name == "exact", rid05TypedDeleteValid(op, "C", "SYS", "O", false, ""))
		})
	}
}

func rid05UnitDeleteSnapshots(t *testing.T) (rid03NewmanSnapshot, rid03NewmanSnapshot) {
	base := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	a := rid03NewmanSnapshot{Raw: map[string][]rid09PrimaryRow{}}
	a.Whole.PrimaryFinishedAt = base
	a.Raw["service_accounts"] = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"id": "C", "account_id": "SYS", "name": "same-name"}), rid03UnitRow(t, map[string]any{"id": "C2", "account_id": "SYS", "name": "same-name"})}
	a.Raw["project_resource_quotas"] = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"carrier_type": "iam.serviceAccount", "carrier_id": "C", "kind": "iam.serviceAccount.credential"})}
	a.Raw["access_binding_target_members"] = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"binding_id": "ownerG", "role_id": "owner", "rule_fp": "fp", "object_type": "iam.serviceAccount", "object_id": "C", "verification_status": "ACTIVE", "updated_at": base.Add(-time.Second)})}
	a.Raw["access_binding_emitted_tuples"] = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"binding_id": "ownerG", "role_id": "owner", "rule_fp": "fp", "member_object_type": "iam.serviceAccount", "member_object_id": "C", "source": "member", "fga_user": "service_account:I", "relation": "viewer", "object": "iam_service_account:C"})}
	a.Raw["relation_fact"] = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"subject": "service_account:I", "relation": "viewer", "object_type": "iam_service_account", "object_id": "C", "source_version": base.Add(-time.Second), "created_at": base.Add(-2 * time.Second)})}
	a.Raw["access_bindings"] = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"id": "oldG", "created_at": base.Add(-time.Minute), "status": "ACTIVE", "future": "retained"})}
	a.Raw["grant_delegations"] = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"id": "oldGD", "delegated_by_id": "C", "status": "ACTIVE"})}
	for _, table := range []string{"fga_outbox", "resource_journal", "resource_reconcile_outbox", "operations", "future_history"} {
		a.Raw[table] = []rid09PrimaryRow{}
	}
	b := rid03NewmanSnapshot{Raw: map[string][]rid09PrimaryRow{}}
	b.Whole.PrimaryStartedAt = base.Add(2 * time.Second)
	for table, rows := range a.Raw {
		b.Raw[table] = append([]rid09PrimaryRow{}, rows...)
	}
	b.Raw["service_accounts"] = b.Raw["service_accounts"][1:]
	for _, table := range []string{"project_resource_quotas", "access_binding_target_members", "access_binding_emitted_tuples", "relation_fact"} {
		b.Raw[table] = []rid09PrimaryRow{}
	}
	b.Raw["fga_outbox"] = []rid09PrimaryRow{rid05UnitDeleteRow(t, map[string]any{"user": "service_account:I", "object": "iam_service_account:C", "relation": "viewer"})}
	b.Raw["resource_journal"] = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"sequence_no": int64(1), "resource_kind": "iam_service_account", "resource_id": "C", "project_id": "", "scope": []any{map[string]any{"type": "account", "id": "SYS"}}, "event_type": "DELETED", "payload": map[string]any{"id": "C"}, "created_at": base.Add(time.Second)})}
	b.Raw["resource_reconcile_outbox"] = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"id": int64(1), "object_type": "iam.serviceAccount", "object_id": "C", "event_type": "mirror.delete", "created_at": base.Add(time.Second), "sent_at": base.Add(time.Second), "last_error": nil, "attempt_count": 0})}
	return a, b
}
func TestRID05DeleteCleanupClosedFullRawDelta(t *testing.T) {
	for _, name := range []string{"exact", "repeated-technical-intent", "missing-tuple", "wrong-binding", "wrong-role", "wrong-rule", "wrong-object-type", "wrong-status", "unknown-table", "unknown-new-column", "extra-oldG-edge", "oldG-changed", "oldGD-C2-retie", "C2-deleted", "C-not-deleted", "missing-journal", "extra-journal", "forged-clock", "false-fact-version"} {
		t.Run(name, func(t *testing.T) {
			a, b := rid05UnitDeleteSnapshots(t)
			switch name {
			case "repeated-technical-intent":
				r := rid05UnitDeleteRow(t, map[string]any{"user": "service_account:I", "object": "iam_service_account:C", "relation": "viewer"})
				r["id"] = json.RawMessage(`2`)
				b.Raw["fga_outbox"] = append(b.Raw["fga_outbox"], r)
			case "missing-tuple":
				b.Raw["fga_outbox"] = nil
			case "wrong-binding", "wrong-role", "wrong-rule", "wrong-object-type", "wrong-status":
				r := rid03UnitRow(t, map[string]any{})
				for k, v := range a.Raw["access_binding_target_members"][0] {
					r[k] = v
				}
				key := map[string]string{"wrong-binding": "binding_id", "wrong-role": "role_id", "wrong-rule": "rule_fp", "wrong-object-type": "object_type", "wrong-status": "verification_status"}[name]
				r[key] = json.RawMessage(`"wrong"`)
				b.Raw["access_binding_target_members"] = []rid09PrimaryRow{r}
			case "unknown-table":
				b.Raw["future_new"] = nil
			case "unknown-new-column":
				b.Raw["resource_journal"][0]["future"] = json.RawMessage(`true`)
			case "extra-oldG-edge":
				b.Raw["relation_fact"] = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"subject": "service_account:I", "relation": "admin", "object_type": "iam_service_account", "object_id": "C"})}
			case "oldG-changed":
				b.Raw["access_bindings"] = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"id": "oldG", "status": "REVOKED"})}
			case "oldGD-C2-retie":
				b.Raw["grant_delegations"] = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"id": "oldGD", "delegated_by_id": "C2", "status": "ACTIVE"})}
			case "C2-deleted":
				b.Raw["service_accounts"] = nil
			case "C-not-deleted":
				b.Raw["service_accounts"] = a.Raw["service_accounts"]
			case "missing-journal":
				b.Raw["resource_journal"] = nil
			case "extra-journal":
				b.Raw["resource_journal"] = append(b.Raw["resource_journal"], b.Raw["resource_journal"][0])
			case "forged-clock":
				b.Raw["fga_outbox"][0]["created_at"] = json.RawMessage(`"2099-01-01T00:00:00Z"`)
			case "false-fact-version":
				a.Raw["relation_fact"][0]["source_version"] = json.RawMessage(`"2099-01-01T00:00:00Z"`)
			}
			_, ok := rid05DeleteRawDelta(a, b, "C", "SYS", false)
			require.Equal(t, name == "exact" || name == "repeated-technical-intent", ok)
		})
	}
}
func TestRID05FailedDeleteOnlyOperationOutsideRawDelta(t *testing.T) {
	a, _ := rid05UnitDeleteSnapshots(t)
	b := a
	b.Raw = map[string][]rid09PrimaryRow{}
	for k, v := range a.Raw {
		b.Raw[k] = append([]rid09PrimaryRow{}, v...)
	}
	_, ok := rid05DeleteRawDelta(a, b, "C", "SYS", true)
	require.True(t, ok)
	b.Raw["service_accounts"] = b.Raw["service_accounts"][1:]
	_, ok = rid05DeleteRawDelta(a, b, "C", "SYS", true)
	require.False(t, ok)
}

func TestRID05RawCreatorReferenceCensus(t *testing.T) {
	for _, name := range []string{"legacy-active-blocks", "secondary-active-blocks", "legacy-revoked-permitted", "secondary-revoked-permitted", "other-subject-ID", "other-subject-type", "narrowed-still-blocks", "expired-still-blocks", "secondary-narrowed-still-blocks", "secondary-expired-still-blocks", "missing-revoked-column", "malformed-revoked-string", "malformed-revoked-number", "malformed-revoked-boolean", "quoted-null-not-timestamp", "secondary-missing-binding-ID", "secondary-dangling-binding-ID", "secondary-other-legacy-subject-still-blocks", "missing-bindings-table", "missing-subjects-table", "missing-legacy-ID", "duplicate-legacy-ID", "malformed-legacy-subject-type", "missing-legacy-subject-ID", "null-legacy-subject-ID", "missing-secondary-subject-ID", "null-secondary-subject-type", "malformed-secondary-binding-ID", "missing-revoked-on-unrelated-row", "exact-empty-inventory", "empty-legacy-subject-ID", "empty-secondary-subject-ID"} {
		t.Run(name, func(t *testing.T) {
			row := rid03UnitRow(t, map[string]any{"id": "G", "subject_type": "service_account", "subject_id": "C", "revoked_at": nil, "narrowed_at": nil, "expires_at": nil})
			raw := map[string][]rid09PrimaryRow{"access_bindings": {row}, "access_binding_subjects": {}}
			wantLegacy, wantSecondary, wantValid := 1, 0, true
			if strings.HasPrefix(name, "secondary-") || name == "missing-secondary-subject-ID" || name == "null-secondary-subject-type" || name == "malformed-secondary-binding-ID" || name == "empty-secondary-subject-ID" {
				row["subject_id"] = json.RawMessage(`"other"`)
				raw["access_binding_subjects"] = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"binding_id": "G", "subject_type": "service_account", "subject_id": "C"})}
				wantLegacy, wantSecondary = 0, 1
			}
			switch name {
			case "legacy-revoked-permitted", "secondary-revoked-permitted":
				row["revoked_at"] = json.RawMessage(`"2026-11-03T12:00:00Z"`)
				wantLegacy, wantSecondary = 0, 0
			case "other-subject-ID":
				row["subject_id"] = json.RawMessage(`"C2"`)
				wantLegacy = 0
			case "other-subject-type":
				row["subject_type"] = json.RawMessage(`"user"`)
				wantLegacy = 0
			case "narrowed-still-blocks", "secondary-narrowed-still-blocks":
				row["narrowed_at"] = json.RawMessage(`"2026-11-03T12:00:00Z"`)
			case "expired-still-blocks", "secondary-expired-still-blocks":
				row["expires_at"] = json.RawMessage(`"2000-01-01T00:00:00Z"`)
			case "missing-revoked-column":
				delete(row, "revoked_at")
				wantValid = false
			case "malformed-revoked-string":
				row["revoked_at"] = json.RawMessage(`"not-a-timestamp"`)
				wantValid = false
			case "malformed-revoked-number":
				row["revoked_at"] = json.RawMessage(`42`)
				wantValid = false
			case "malformed-revoked-boolean":
				row["revoked_at"] = json.RawMessage(`true`)
				wantValid = false
			case "quoted-null-not-timestamp":
				row["revoked_at"] = json.RawMessage(`"null"`)
				wantValid = false
			case "secondary-missing-binding-ID":
				delete(raw["access_binding_subjects"][0], "binding_id")
				wantValid = false
			case "secondary-dangling-binding-ID":
				raw["access_binding_subjects"][0]["binding_id"] = json.RawMessage(`"missing-G"`)
				wantValid = false
			case "missing-bindings-table":
				delete(raw, "access_bindings")
				wantValid = false
			case "missing-subjects-table":
				delete(raw, "access_binding_subjects")
				wantValid = false
			case "missing-legacy-ID":
				delete(row, "id")
				wantValid = false
			case "duplicate-legacy-ID":
				raw["access_bindings"] = append(raw["access_bindings"], row)
				wantValid = false
			case "malformed-legacy-subject-type":
				row["subject_type"] = json.RawMessage(`true`)
				wantValid = false
			case "empty-legacy-subject-ID":
				row["subject_id"] = json.RawMessage(`""`)
				wantValid = false
			case "empty-secondary-subject-ID":
				raw["access_binding_subjects"][0]["subject_id"] = json.RawMessage(`""`)
				wantValid = false
			case "missing-legacy-subject-ID":
				delete(row, "subject_id")
				wantValid = false
			case "null-legacy-subject-ID":
				row["subject_id"] = json.RawMessage(`null`)
				wantValid = false
			case "missing-secondary-subject-ID":
				delete(raw["access_binding_subjects"][0], "subject_id")
				wantValid = false
			case "null-secondary-subject-type":
				raw["access_binding_subjects"][0]["subject_type"] = json.RawMessage(`null`)
				wantValid = false
			case "malformed-secondary-binding-ID":
				raw["access_binding_subjects"][0]["binding_id"] = json.RawMessage(`42`)
				wantValid = false
			case "missing-revoked-on-unrelated-row":
				row["subject_id"] = json.RawMessage(`"C2"`)
				delete(row, "revoked_at")
				wantValid = false
			case "exact-empty-inventory":
				raw["access_bindings"] = nil
				wantLegacy = 0
			}
			legacy, secondary, valid := rid05CreatorSubjectReferences(raw, "C")
			require.Equal(t, wantValid, valid, "raw schema validity")
			if valid {
				require.Equal(t, wantLegacy, legacy, "legacy active-reference count")
				require.Equal(t, wantSecondary, secondary, "secondary active-reference count")
			}
		})
	}
}
