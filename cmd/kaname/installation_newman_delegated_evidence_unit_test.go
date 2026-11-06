// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func rid03UnitAuditExpectation() *rid03NewmanExpectation {
	return &rid03NewmanExpectation{CaseID: "registry-installation-rid03-S1-GRANT-ACT", Phase: "ACT", Actor: "issuer", Tenant: "account", InstallationGD: "delegation", Path: "/iam/v1/accessBindings", Request: map[string]any{"subjectType": "service_account", "subjectId": "grantee", "roleId": "role"}}
}
func rid03UnitBusinessEvent(t *testing.T, e *rid03NewmanExpectation, id string, at time.Time) rid09PrimaryRow {
	event, tenant := "iam.access_binding.granted", e.Tenant
	payload := map[string]any{"actor": e.Actor, "subject_type": "service_account", "subject_id": "grantee", "resource_type": "account", "resource_id": "account", "role_id": "role", "binding_id": id, "delegation_id": "delegation"}
	if e.Path == "/iam/v1/grantDelegations" {
		event = "iam.grant_delegation.created"
		tenant = "other-account"
		payload = map[string]any{"actor": e.Actor, "delegation_id": id, "account_id": tenant, "delegate": "new-delegate", "module": "registry", "role_ids": []string{"role"}, "target_types": []string{"registry.registries"}, "subject_types": []string{"service_account"}}
	}
	return rid03UnitRow(t, map[string]any{"id": "evt_aaaaaaaaaaaaaaaaaaaaaa", "event_type": event, "tenant_account_id": tenant, "event_payload": payload, "created_at": at})
}
func rid03UnitAuditPayloadChange(t *testing.T, row rid09PrimaryRow, key string, value any) {
	var payload map[string]any
	require.NoError(t, json.Unmarshal(row["event_payload"], &payload))
	payload[key] = value
	row["event_payload"], _ = json.Marshal(payload)
}
func TestRID03BusinessAuditPrimaryDelta(t *testing.T) {
	for _, tc := range []struct {
		name   string
		gd     bool
		change func(*testing.T, *rid03NewmanExpectation, *[]rid09PrimaryRow)
		want   bool
	}{
		{"legal-AB-exact-one", false, nil, true},
		{"legal-GD-exact-one", true, nil, true},
		{"missing-business-event", false, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) { *rows = nil }, false},
		{"duplicate-business-event", false, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) {
			row := rid03UnitBusinessEvent(t, e, "new-binding", time.Date(2026, 11, 3, 12, 0, 1, 0, time.UTC))
			row["id"] = json.RawMessage(`"evt_bbbbbbbbbbbbbbbbbbbbbb"`)
			*rows = append(*rows, row)
		}, false},
		{"wrong-business-event", false, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) {
			(*rows)[0]["event_type"] = json.RawMessage(`"iam.access_binding.revoked"`)
		}, false},
		{"wrong-actor", false, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) {
			rid03UnitAuditPayloadChange(t, (*rows)[0], "actor", "other")
		}, false},
		{"wrong-actor-encoding", false, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) {
			rid03UnitAuditPayloadChange(t, (*rows)[0], "actor", "service_account:issuer")
		}, false},
		{"wrong-tenant", false, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) {
			(*rows)[0]["tenant_account_id"] = json.RawMessage(`"other"`)
		}, false},
		{"wrong-binding", false, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) {
			rid03UnitAuditPayloadChange(t, (*rows)[0], "binding_id", "other")
		}, false},
		{"wrong-delegation", false, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) {
			rid03UnitAuditPayloadChange(t, (*rows)[0], "delegation_id", "other")
		}, false},
		{"wrong-subject", false, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) {
			rid03UnitAuditPayloadChange(t, (*rows)[0], "subject_id", "other")
		}, false},
		{"wrong-role", false, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) {
			rid03UnitAuditPayloadChange(t, (*rows)[0], "role_id", "other")
		}, false},
		{"wrong-resource", false, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) {
			rid03UnitAuditPayloadChange(t, (*rows)[0], "resource_id", "other")
		}, false},
		{"GD-wrong-delegate", true, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) {
			rid03UnitAuditPayloadChange(t, (*rows)[0], "delegate", "other")
		}, false},
		{"GD-wrong-axes", true, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) {
			rid03UnitAuditPayloadChange(t, (*rows)[0], "target_types", []string{"iam.accessBinding"})
		}, false},
		{"GD-wrong-module", true, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) {
			rid03UnitAuditPayloadChange(t, (*rows)[0], "module", "other")
		}, false},
		{"unknown-payload-field", false, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) {
			rid03UnitAuditPayloadChange(t, (*rows)[0], "unexpected", true)
		}, false},
		{"unknown-immutable-column", false, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) {
			(*rows)[0]["unexpected"] = json.RawMessage(`true`)
		}, false},
		{"clock-outside-phase", false, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) {
			(*rows)[0]["created_at"] = json.RawMessage(`"2099-11-03T12:00:01Z"`)
		}, false},
		{"denial-event-forbidden", false, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) { e.Denied = true }, false},
		{"VERIFY-event-forbidden", false, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) { e.Phase = "VERIFY" }, false},
		{"legal-denial-zero", false, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) { e.Denied = true; *rows = nil }, true},
		{"legal-VERIFY-zero", false, func(t *testing.T, e *rid03NewmanExpectation, rows *[]rid09PrimaryRow) {
			e.Phase = "VERIFY"
			*rows = nil
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, _, _ := rid03UnitPolicy(t)
			e := rid03UnitAuditExpectation()
			if tc.gd {
				e.Path = "/iam/v1/grantDelegations"
				e.Snapshot.Raw = map[string][]rid09PrimaryRow{"roles": {rid03UnitRow(t, map[string]any{"id": "role", "owner_module": "registry"})}}
				e.Request = map[string]any{"accountId": "other-account", "delegate": map[string]any{"id": "new-delegate"}, "roleIds": []string{"role"}, "targetTypes": []string{"registry.registries"}, "subjectTypes": []string{"SUBJECT_TYPE_SERVICE_ACCOUNT"}}
			}
			rows := []rid09PrimaryRow{rid03UnitBusinessEvent(t, e, p.NewID, p.Start.Add(time.Second))}
			if tc.change != nil {
				tc.change(t, e, &rows)
			}
			_, ok := rid03BusinessAuditDelta(e, p.NewID, nil, rows, p.Start, p.End)
			require.Equal(t, tc.want, ok)
		})
	}
}
func TestRID03AuditHistoryTransportBoundary(t *testing.T) {
	for _, name := range []string{"transport-progress-allowed", "unknown-SQL-column-rejected", "old-payload-change-rejected", "old-row-removal-rejected"} {
		t.Run(name, func(t *testing.T) {
			p, _, _, _ := rid03UnitPolicy(t)
			e := rid03UnitAuditExpectation()
			e.Denied = true
			immutable := rid03UnitBusinessEvent(t, e, p.NewID, p.Start)
			full := rid09PrimaryRow{}
			for k, v := range immutable {
				full[k] = v
			}
			for k, v := range rid03UnitRow(t, map[string]any{"status": "pending", "attempts": 0, "next_attempt_at": p.Start, "sent_at": nil, "last_error": nil}) {
				full[k] = v
			}
			old, ok := rid03ImmutableBusinessAudit(full)
			require.True(t, ok)
			full["status"] = json.RawMessage(`"sent"`)
			full["attempts"] = json.RawMessage(`2`)
			full["sent_at"], _ = json.Marshal(p.End)
			if name == "unknown-SQL-column-rejected" {
				full["new_column"] = json.RawMessage(`true`)
			}
			current, ok := rid03ImmutableBusinessAudit(full)
			if name == "unknown-SQL-column-rejected" {
				require.False(t, ok)
				return
			}
			require.True(t, ok)
			after := []rid09PrimaryRow{current}
			if name == "old-payload-change-rejected" {
				rid03UnitAuditPayloadChange(t, current, "actor", "other")
			}
			if name == "old-row-removal-rejected" {
				after = nil
			}
			_, ok = rid03BusinessAuditDelta(e, "", []rid09PrimaryRow{old}, after, p.Start, p.End)
			require.Equal(t, name == "transport-progress-allowed", ok)
		})
	}
}
func rid03UnitEvidenceInputs(t *testing.T) (*rid03NewmanExpectation, rid03NewmanSnapshot, rid03NewmanSnapshot, rid03DeltaPolicy) {
	p, _, fact, _ := rid03UnitPolicy(t)
	e := rid03UnitAuditExpectation()
	a, b := rid03NewmanSnapshot{}, rid03NewmanSnapshot{}
	a.Whole.PrimaryFinishedAt = p.Start
	b.Whole.PrimaryStartedAt = p.End
	a.Raw = map[string][]rid09PrimaryRow{"fga_outbox": {}, "relation_fact": {}}
	b.Raw = map[string][]rid09PrimaryRow{"fga_outbox": {rid03UnitProducer(t, p)}, "relation_fact": {fact}}
	b.BusinessAudit = []rid09PrimaryRow{rid03UnitBusinessEvent(t, e, p.NewID, p.Start.Add(time.Second))}
	return e, a, b, p
}
func TestRID03ClosedTechnicalEvidenceReceipt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *rid03NewmanExpectation, *rid03NewmanSnapshot, *rid03NewmanSnapshot, *rid03DeltaPolicy)
		want   bool
	}{
		{"legal-crosscheckable-primary-receipt", nil, true},
		{"legal-repeated-intents-retained", func(t *testing.T, e *rid03NewmanExpectation, a, b *rid03NewmanSnapshot, p *rid03DeltaPolicy) {
			row := rid03UnitProducer(t, *p)
			row["id"] = json.RawMessage(`2`)
			b.Raw["fga_outbox"] = append(b.Raw["fga_outbox"], row)
		}, true},
		{"wrong-phase", func(t *testing.T, e *rid03NewmanExpectation, a, b *rid03NewmanSnapshot, p *rid03DeltaPolicy) {
			e.Phase = "VERIFY"
		}, false},
		{"missing-producer", func(t *testing.T, e *rid03NewmanExpectation, a, b *rid03NewmanSnapshot, p *rid03DeltaPolicy) {
			b.Raw["fga_outbox"] = nil
		}, false},
		{"missing-fact", func(t *testing.T, e *rid03NewmanExpectation, a, b *rid03NewmanSnapshot, p *rid03DeltaPolicy) {
			b.Raw["relation_fact"] = nil
		}, false},
		{"missing-audit", func(t *testing.T, e *rid03NewmanExpectation, a, b *rid03NewmanSnapshot, p *rid03DeltaPolicy) {
			b.BusinessAudit = nil
		}, false},
		{"unknown-producer-column", func(t *testing.T, e *rid03NewmanExpectation, a, b *rid03NewmanSnapshot, p *rid03DeltaPolicy) {
			b.Raw["fga_outbox"][0]["secret"] = json.RawMessage(`"must-never-export"`)
		}, false},
		{"unbacked-fact-clock", func(t *testing.T, e *rid03NewmanExpectation, a, b *rid03NewmanSnapshot, p *rid03DeltaPolicy) {
			b.Raw["relation_fact"][0]["created_at"], _ = json.Marshal(p.Start)
		}, false},
		{"changed-old-row", func(t *testing.T, e *rid03NewmanExpectation, a, b *rid03NewmanSnapshot, p *rid03DeltaPolicy) {
			a.Raw["fga_outbox"] = []rid09PrimaryRow{rid03UnitProducer(t, *p)}
			b.Raw["fga_outbox"][0]["created_at"], _ = json.Marshal(p.End)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, a, b, p := rid03UnitEvidenceInputs(t)
			// Посторонний столбец SQL с удостоверяющим материалом НИКОГДА не является источником квитанции.
			b.Raw["operations"] = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"response_data": "credential-canary-must-not-serialize"})}
			if tc.change != nil {
				tc.change(t, e, &a, &b, &p)
			}
			proof, ok := rid03BuildTechnicalReceipt(e, a, b, &p)
			require.Equal(t, tc.want, ok)
			if !ok {
				return
			}
			require.Equal(t, len(b.Raw["fga_outbox"]), proof.NewProducerRows)
			require.Len(t, proof.Producers, proof.NewProducerRows)
			require.Len(t, proof.DirectFacts, 1)
			require.Equal(t, proof.ExpectedEmittedUnion, proof.ActualEmittedUnion)
			require.Equal(t, proof.ExpectedDirectUnion, proof.ActualDirectUnion)
			require.Equal(t, 1, proof.NewBusinessEvents)
			require.False(t, proof.WholeDoDAccepted)
			for _, fact := range proof.DirectFacts {
				require.Contains(t, fact.MatchingProducerClocks, fact.CreatedAt)
				require.Equal(t, fact.ExpectedMaxSourceVersion, fact.SourceVersion)
			}
			raw, err := json.Marshal(proof)
			require.NoError(t, err)
			require.False(t, strings.Contains(string(raw), "credential-canary"))
			require.False(t, strings.Contains(string(raw), "response_data"))
		})
	}
}
func TestRID03ZeroTechnicalEvidenceReceipt(t *testing.T) {
	for _, phase := range []string{"ACT", "VERIFY"} {
		t.Run(phase, func(t *testing.T) {
			e, a, b, _ := rid03UnitEvidenceInputs(t)
			e.Phase = phase
			e.Denied = phase == "ACT"
			if phase == "ACT" {
				e.CaseID = "registry-installation-rid03-S1-ROLE-DENIED-ACT"
			} else {
				e.CaseID = "registry-installation-rid03-S1-GRANT-VERIFY"
			}
			b.Raw = a.Raw
			b.BusinessAudit = a.BusinessAudit
			proof, ok := rid03BuildTechnicalReceipt(e, a, b, nil)
			require.True(t, ok)
			require.Zero(t, proof.NewProducerRows)
			require.Zero(t, proof.NewDirectFactRows)
			require.Zero(t, proof.NewBusinessEvents)
		})
	}
}
