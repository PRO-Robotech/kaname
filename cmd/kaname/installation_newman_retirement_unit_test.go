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

func TestRID04ClosedSecretLiteralCensus(t *testing.T) {
	for _, id := range []string{
		"registry-installation-rid04-S1-BEFORE-RETIREMENT",
		"registry-installation-rid04-S1-RETIRED-DENIED-ACT",
		"registry-installation-rid04-S1-RETIRED-DENIED-VERIFY",
		"registry-installation-rid04-S1-REFUSED-APPLY-SNAPSHOT",
		"registry-installation-rid04-S1-RESTORED-GRANT-ACT",
		"registry-installation-rid04-S1-RESTORED-GRANT-VERIFY",
		"registry-installation-rid04-S1-RESTORED-REAPPLY",
		"registry-installation-rid04-S2-BEFORE-RETIREMENT",
		"registry-installation-rid04-S2-RETIRED-DENIED-ACT",
		"registry-installation-rid04-S2-RETIRED-DENIED-VERIFY",
		"registry-installation-rid04-S2-REFUSED-APPLY-SNAPSHOT",
		"registry-installation-rid04-S2-RESTORED-GRANT-ACT",
		"registry-installation-rid04-S2-RESTORED-GRANT-VERIFY",
		"registry-installation-rid04-S2-RESTORED-REAPPLY",
	} {
		t.Run(id, func(t *testing.T) {
			vars := map[string]any{"jwtRIDOperator": "ordinary-O"}
			want := []string{"ordinary-O"}
			if strings.HasSuffix(id, "-ACT") {
				vars["jwtRIDIssuer"] = "ordinary-I"
				want = append(want, "ordinary-I")
			}
			got, err := ridNewmanClientSecrets("registry-installation-rid04", id, vars)
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}
func TestRID04SecretAdmissionRejects(t *testing.T) {
	for _, tc := range []struct {
		name, id string
		vars     map[string]any
	}{
		{"unknown-phase", "registry-installation-rid04-S1-OTHER", map[string]any{"jwtRIDOperator": "O"}},
		{"missing-I", "registry-installation-rid04-S1-RETIRED-DENIED-ACT", map[string]any{"jwtRIDOperator": "O"}},
		{"empty-I", "registry-installation-rid04-S1-RESTORED-GRANT-ACT", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": ""}},
		{"invalid-I-type", "registry-installation-rid04-S1-RESTORED-GRANT-ACT", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": 1}},
		{"oversize-I", "registry-installation-rid04-S1-RESTORED-GRANT-ACT", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": strings.Repeat("x", 16385)}},
		{"VERIFY-I-forbidden", "registry-installation-rid04-S1-RESTORED-GRANT-VERIFY", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": "I"}},
		{"READ-I-forbidden", "registry-installation-rid04-S1-BEFORE-RETIREMENT", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": "I"}},
		{"C-forbidden", "registry-installation-rid04-S1-RESTORED-GRANT-ACT", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": "I", "jwtRIDCreator": "C"}},
		{"assertion-forbidden", "registry-installation-rid04-S1-RESTORED-GRANT-ACT", map[string]any{"jwtRIDOperator": "O", "jwtRIDIssuer": "I", "rid01ClientAssertion": "assertion"}},
		{"issuance-origin-forbidden", "registry-installation-rid04-S1-BEFORE-RETIREMENT", map[string]any{"jwtRIDOperator": "O", "rid01IssuanceOrigin": "https://localhost:9096"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ridNewmanClientSecrets("registry-installation-rid04", tc.id, tc.vars)
			require.Error(t, err)
		})
	}
}
func TestRID04ReceiptCompositionKeepsClosed03(t *testing.T) {
	for _, tc := range []struct {
		name, id, phase string
		want04, want03  bool
	}{
		{"04-positive-primary-proof", "registry-installation-rid04-S1-RESTORED-GRANT-ACT", "ACT", true, false},
		{"03-positive-unmodified", "registry-installation-rid03-S1-GRANT-ACT", "ACT", false, true},
		{"unknown-04-rejected", "registry-installation-rid04-S1-OTHER", "ACT", false, false},
		{"wrong-04-phase-rejected", "registry-installation-rid04-S1-RESTORED-GRANT-ACT", "VERIFY", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, a, b, p := rid03UnitEvidenceInputs(t)
			e.CaseID = tc.id
			e.Phase = tc.phase
			_, ok04 := rid04BuildTechnicalReceipt(e, a, b, &p)
			_, ok03 := rid03BuildTechnicalReceipt(e, a, b, &p)
			require.Equal(t, tc.want04, ok04)
			require.Equal(t, tc.want03, ok03)
		})
	}
}
func TestRID04AuthorityCurrentPrimary(t *testing.T) {
	for _, tc := range []struct {
		name                string
		grant, fact         bool
		expired             bool
		wantGrant, wantFact int
	}{
		{"active-durable-and-materialized", true, true, false, 1, 1},
		{"retired-both-absent", false, false, false, 0, 0},
		{"stale-fact-visible", false, true, false, 0, 1},
		{"unmaterialized-grant-visible", true, false, false, 1, 0},
		{"expired-grant-not-current", true, true, true, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := rid03NewmanSnapshot{Raw: map[string][]rid09PrimaryRow{}}
			s.Whole.PrimaryStartedAt = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
			if tc.grant {
				var until any
				if tc.expired {
					until = s.Whole.PrimaryStartedAt.Add(-time.Second)
				}
				s.Raw["cluster_admin_grants"] = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"cluster_id": "cluster_root", "subject_type": "service_account", "subject_id": "C", "granted_until": until})}
			}
			if tc.fact {
				s.Raw["relation_fact"] = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"object_type": "cluster", "object_id": "cluster_root", "relation": "system_admin", "subject": "service_account:C"})}
			}
			grants, facts := rid04AuthorityCounts(s, "service_account", "C")
			require.Equal(t, tc.wantGrant, grants)
			require.Equal(t, tc.wantFact, facts)
		})
	}
}
func TestRID04FullHistoricalIdentity(t *testing.T) {
	for _, name := range []string{"exact", "GD-createdAt", "G-createdAt", "G-materializedAt", "old-history", "unknown-G-column", "unknown-G-table", "missing-G-row"} {
		t.Run(name, func(t *testing.T) {
			row := rid03UnitRow(t, map[string]any{"id": "old-G", "created_at": "2026-11-03T12:00:00Z", "materialized_at": "2026-11-03T12:00:01Z"})
			a := rid03NewmanSnapshot{Raw: map[string][]rid09PrimaryRow{"access_bindings": {row}, "grant_delegations": {rid03UnitRow(t, map[string]any{"id": "GD", "created_at": "2026-11-03T12:00:00Z"})}}}
			bytes, err := json.Marshal(a.Raw)
			require.NoError(t, err)
			b := rid03NewmanSnapshot{Raw: map[string][]rid09PrimaryRow{}}
			require.NoError(t, json.Unmarshal(bytes, &b.Raw))
			switch name {
			case "GD-createdAt":
				b.Raw["grant_delegations"][0]["created_at"] = json.RawMessage(`"changed"`)
			case "G-createdAt":
				b.Raw["access_bindings"][0]["created_at"] = json.RawMessage(`"changed"`)
			case "G-materializedAt":
				b.Raw["access_bindings"][0]["materialized_at"] = json.RawMessage(`"changed"`)
			case "old-history":
				b.Raw["access_binding_emitted_tuples"] = []rid09PrimaryRow{rid03UnitRow(t, map[string]any{"binding_id": "old-G"})}
			case "unknown-G-column":
				b.Raw["access_bindings"][0]["unknown"] = json.RawMessage(`true`)
			case "unknown-G-table":
				b.Raw["access_binding_future_history"] = []rid09PrimaryRow{}
			case "missing-G-row":
				b.Raw["access_bindings"] = nil
			}
			require.Equal(t, name == "exact", rid04GDGHistoryEqual(a, b))
		})
	}
}
func TestRID04PreRestoreProofMandatory(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    *rid04PublicContext
		want bool
	}{
		{"nil-consumer-not-proof", nil, false},
		{"no-proof", &rid04PublicContext{}, false},
		{"flag-alone-insufficient", &rid04PublicContext{refusalProof: true}, false},
		{"missing-preRestore", &rid04PublicContext{refusalProof: true, beforeFailure: &rid03NewmanSnapshot{}}, false},
		{"full-checkpoint-proof", &rid04PublicContext{refusalProof: true, beforeFailure: &rid03NewmanSnapshot{}, preRestore: &rid03NewmanSnapshot{}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) { require.Equal(t, tc.want, rid04RefusalProofReady(tc.p)) })
	}
}
func TestRID04LiteralOwnersUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, owner := range []string{"retired", "apply-denied", "recovery"} {
		for _, mode := range []string{"S1", "S2"} {
			for _, suffix := range rid04OwnedSuffixes(owner) {
				id := "registry-installation-rid04-" + mode + "-" + suffix
				require.False(t, seen[id])
				seen[id] = true
				_, ok := rid04NewmanActor(id)
				require.True(t, ok)
			}
		}
	}
	require.Len(t, seen, 14)
	require.Len(t, rid04NewmanActors, 14)
	require.Len(t, rid04NewmanPhases, 14)
}
