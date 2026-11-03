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

func rid03UnitRow(t *testing.T, values map[string]any) rid09PrimaryRow {
	t.Helper()
	out := rid09PrimaryRow{}
	for k, v := range values {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		out[k] = raw
	}
	return out
}
func rid03UnitPolicy(t *testing.T) (rid03DeltaPolicy, rid09PrimaryRow, rid09PrimaryRow, rid09PrimaryRow) {
	t.Helper()
	start := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	at := start.Add(time.Second)
	m := rid03Member{"new-binding", "role", "rule-fingerprint", "registry.registries", "target"}
	tuple := rid03Tuple{"service_account:grantee", "v_get", "registry_registry", "target"}
	ledger := rid03Ledger{m.Binding, "member", m.Type, m.ID, tuple}
	owner := rid03Member{"old-owner-binding", "owner-role", "owner-rule", "iam.accessBinding", "new-binding"}
	p := rid03DeltaPolicy{NewID: m.Binding, Path: "/iam/v1/accessBindings", Account: "account", Start: start, End: start.Add(2 * time.Second), Members: map[rid03Member]bool{m: true, owner: true}, Ledger: map[rid03Ledger]bool{ledger: true}, Tuples: map[rid03Tuple]bool{tuple: true}}
	direct := rid03Tuple{tuple.Subject, "viewer", tuple.Type, tuple.ID}
	p.Tuples[direct] = true
	p.Tuples[rid03Tuple{tuple.Subject, "v_list", tuple.Type, tuple.ID}] = true
	p.DirectTuples = map[rid03Tuple]bool{direct: true}

	require.True(t, p.bindProducers([]rid09PrimaryRow{rid03UnitProducer(t, p)}))
	member := rid03UnitRow(t, map[string]any{"binding_id": m.Binding, "role_id": m.Role, "rule_fp": m.Rule, "object_type": m.Type, "object_id": m.ID, "verification_status": "ACTIVE", "created_at": at, "updated_at": at, "live": true})
	fact := rid03UnitRow(t, map[string]any{"object_type": tuple.Type, "object_id": tuple.ID, "subject": tuple.Subject, "relation": direct.Relation, "source_version": at, "created_at": at, "condition_name": "", "condition_params": map[string]any{}})
	emitted := rid03UnitRow(t, map[string]any{"binding_id": m.Binding, "fga_user": tuple.Subject, "relation": tuple.Relation, "object": tuple.Type + ":" + tuple.ID, "source": "member", "member_object_type": m.Type, "member_object_id": m.ID})
	return p, member, fact, emitted
}
func rid03UnitProducer(t *testing.T, p rid03DeltaPolicy) rid09PrimaryRow {
	return rid03UnitRow(t, map[string]any{"id": int64(1), "event_type": "fga.tuple.write", "created_at": p.Start.Add(time.Second), "payload": map[string]any{"user": "service_account:grantee", "object": "registry_registry:target", "relations": []string{"v_get", "v_list", "viewer"}, "relation": "v_get"}})
}
func TestRID03ProducerFoldOracle(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *rid03DeltaPolicy, *[]rid09PrimaryRow, rid09PrimaryRow)
		want   bool
	}{
		{"legal-production-grouped-fold", nil, true},
		{"legal-production-singleton-fold", func(t *testing.T, p *rid03DeltaPolicy, rows *[]rid09PrimaryRow, fact rid09PrimaryRow) {
			tuple := rid03Tuple{"service_account:grantee", "viewer", "registry_registry", "target"}
			p.Tuples = map[rid03Tuple]bool{tuple: true}

			(*rows)[0]["payload"], _ = json.Marshal(map[string]any{"user": tuple.Subject, "object": tuple.Type + ":" + tuple.ID, "relation": tuple.Relation})
		}, true},
		{"wrong-fact-version", func(t *testing.T, p *rid03DeltaPolicy, rows *[]rid09PrimaryRow, fact rid09PrimaryRow) {
			fact["source_version"], _ = json.Marshal(p.Start)
		}, false},
		{"legacy-minus-infinity-version", func(t *testing.T, p *rid03DeltaPolicy, rows *[]rid09PrimaryRow, fact rid09PrimaryRow) {
			fact["source_version"] = json.RawMessage(`"-infinity"`)
		}, false},
		{"forged-producer", func(t *testing.T, p *rid03DeltaPolicy, rows *[]rid09PrimaryRow, fact rid09PrimaryRow) {
			(*rows)[0]["payload"], _ = json.Marshal(map[string]any{"user": "service_account:forged", "object": "registry_registry:target", "relations": []string{"v_get", "v_list", "viewer"}, "relation": "v_get"})
		}, false},
		{"producer-outside-primary-window", func(t *testing.T, p *rid03DeltaPolicy, rows *[]rid09PrimaryRow, fact rid09PrimaryRow) {
			(*rows)[0]["created_at"], _ = json.Marshal(p.End.Add(time.Second))
		}, false},
		{"producer-before-primary-window", func(t *testing.T, p *rid03DeltaPolicy, rows *[]rid09PrimaryRow, fact rid09PrimaryRow) {
			(*rows)[0]["created_at"], _ = json.Marshal(p.Start.Add(-time.Second))
		}, false},
		{"missing-producer", func(t *testing.T, p *rid03DeltaPolicy, rows *[]rid09PrimaryRow, fact rid09PrimaryRow) { *rows = nil }, false},
		{"legal-repeated-technical-intent", func(t *testing.T, p *rid03DeltaPolicy, rows *[]rid09PrimaryRow, fact rid09PrimaryRow) {
			*rows = append(*rows, rid03UnitProducer(t, *p))
			(*rows)[1]["id"] = json.RawMessage(`2`)
		}, true},
		{"ordinary-verb-not-direct-fact", func(t *testing.T, p *rid03DeltaPolicy, rows *[]rid09PrimaryRow, fact rid09PrimaryRow) {
			fact["relation"] = json.RawMessage(`"v_get"`)
		}, false},
		{"wrong-fact-created-at", func(t *testing.T, p *rid03DeltaPolicy, rows *[]rid09PrimaryRow, fact rid09PrimaryRow) {
			fact["created_at"], _ = json.Marshal(p.Start)
		}, false},
		{"producer-unknown-column", func(t *testing.T, p *rid03DeltaPolicy, rows *[]rid09PrimaryRow, fact rid09PrimaryRow) {
			(*rows)[0]["unknown"] = json.RawMessage(`true`)
		}, false},
		{"producer-wrong-event", func(t *testing.T, p *rid03DeltaPolicy, rows *[]rid09PrimaryRow, fact rid09PrimaryRow) {
			(*rows)[0]["event_type"] = json.RawMessage(`"fga.tuple.delete"`)
		}, false},
		{"producer-missing-time", func(t *testing.T, p *rid03DeltaPolicy, rows *[]rid09PrimaryRow, fact rid09PrimaryRow) {
			delete((*rows)[0], "created_at")
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, fact, _ := rid03UnitPolicy(t)
			rows := []rid09PrimaryRow{rid03UnitProducer(t, p)}
			if tc.change != nil {
				tc.change(t, &p, &rows, fact)
			}
			bound := p.bindProducers(rows)
			require.Equal(t, tc.want, bound && p.allows("relation_fact", fact))
			if !bound {
				require.Empty(t, p.FactVersions)
				require.Empty(t, p.FactCreated)
			}
		})
	}
}
func TestRID03ClosedProducerPayload(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload map[string]any
		want    bool
	}{
		{"legal-complete-grouped-set", map[string]any{"relations": []string{"v_get", "v_list", "viewer"}, "relation": "v_get"}, true},
		{"missing-echo", map[string]any{"relations": []string{"v_get", "v_list", "viewer"}}, false},
		{"wrong-echo", map[string]any{"relations": []string{"v_get", "v_list", "viewer"}, "relation": "viewer"}, false},
		{"legal-scalar-intent-requires-union", map[string]any{"relation": "viewer"}, true},
		{"legal-group-partition-requires-union", map[string]any{"relations": []string{"v_get", "viewer"}, "relation": "v_get"}, true},
		{"duplicate-relation", map[string]any{"relations": []string{"v_get", "v_get", "viewer"}, "relation": "v_get"}, false},
		{"unsorted-relations", map[string]any{"relations": []string{"viewer", "v_get", "v_list"}, "relation": "viewer"}, false},
		{"singleton-array-not-singleton-form", map[string]any{"relations": []string{"viewer"}, "relation": "viewer"}, false},
		{"unknown-extra-key", map[string]any{"relations": []string{"v_get", "v_list", "viewer"}, "relation": "v_get", "unknown": true}, false},
		{"owner-version-not-ordinary-producer", map[string]any{"relations": []string{"v_get", "v_list", "viewer"}, "relation": "v_get", "source_version": "2026-11-03T12:00:01Z"}, false},
		{"extra-privilege", map[string]any{"relations": []string{"admin", "v_get", "v_list", "viewer"}, "relation": "admin"}, false},
		{"empty-relations", map[string]any{"relations": []string{}, "relation": "v_get"}, false},
		{"wrong-relations-type", map[string]any{"relations": "v_get", "relation": "v_get"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, _, _ := rid03UnitPolicy(t)
			row := rid03UnitProducer(t, p)
			tc.payload["user"] = "service_account:grantee"
			tc.payload["object"] = "registry_registry:target"
			row["payload"], _ = json.Marshal(tc.payload)
			_, _, ok := p.producer(row)
			require.Equal(t, tc.want, ok)
		})
	}
}
func TestRID03VerbOnlyProducerDoesNotBecomeFact(t *testing.T) {
	p, _, fact, ledger := rid03UnitPolicy(t)
	tuple := rid03Tuple{"service_account:grantee", "v_get", "registry_registry", "target"}
	p.Tuples = map[rid03Tuple]bool{tuple: true}
	p.DirectTuples = map[rid03Tuple]bool{}

	row := rid03UnitProducer(t, p)
	row["payload"], _ = json.Marshal(map[string]any{"user": tuple.Subject, "object": tuple.Type + ":" + tuple.ID, "relation": tuple.Relation})
	require.True(t, p.bindProducers([]rid09PrimaryRow{row}))
	require.True(t, p.allows("fga_outbox", row))
	require.True(t, p.allows("access_binding_emitted_tuples", ledger))
	require.Empty(t, p.FactVersions)
	fact["relation"] = json.RawMessage(`"v_get"`)
	require.False(t, p.allows("relation_fact", fact))
}

// Разные начала транзакций не устанавливают порядок вставки/фиксации.
func TestRID03TechnicalIntentConvergence(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		partition, repeat            bool
		createdOffset, versionOffset time.Duration
		missing                      bool
		want                         bool
	}{
		{"legal-partition-complete-union", true, false, time.Second, time.Second, false, true},
		{"partition-missing-tuple-rejected", true, false, time.Second, time.Second, true, false},
		{"legal-repeat-first-older-clock", false, true, time.Second, 1500 * time.Millisecond, false, true},
		{"legal-repeat-first-later-clock", false, true, 1500 * time.Millisecond, 1500 * time.Millisecond, false, true},
		{"unbacked-created-clock-rejected", false, true, 1200 * time.Millisecond, 1500 * time.Millisecond, false, false},
		{"nonmax-source-version-rejected", false, true, time.Second, time.Second, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, fact, _ := rid03UnitPolicy(t)
			rows := []rid09PrimaryRow{rid03UnitProducer(t, p)}
			if tc.partition {
				rows = nil
				for i, relation := range []string{"v_get", "v_list", "viewer"} {
					if tc.missing && relation == "v_list" {
						continue
					}
					row := rid03UnitProducer(t, p)
					row["id"], _ = json.Marshal(i + 1)
					row["payload"], _ = json.Marshal(map[string]any{"user": "service_account:grantee", "object": "registry_registry:target", "relation": relation})
					rows = append(rows, row)
				}
			}
			if tc.repeat {
				second := rid03UnitProducer(t, p)
				second["id"] = json.RawMessage(`2`)
				second["created_at"], _ = json.Marshal(p.Start.Add(1500 * time.Millisecond))
				// Позднее начавшаяся транзакция может вставить первой, даже если порядок строк снимка
				// случайно перечисляет раньше производителя, начавшегося ранее.
				rows = append(rows, second)
			}
			fact["created_at"], _ = json.Marshal(p.Start.Add(tc.createdOffset))
			fact["source_version"], _ = json.Marshal(p.Start.Add(tc.versionOffset))
			bound := p.bindProducers(rows)
			require.Equal(t, tc.want, bound && p.allows("relation_fact", fact))
		})
	}
}
func TestRID03BusinessMultiplicityStaysStrict(t *testing.T) {
	for _, tc := range []struct{ name, table string }{
		{"duplicate-G", "access_bindings"},
		{"duplicate-subject-event", "subject_change_outbox"},
		{"duplicate-reconcile-event", "resource_reconcile_outbox"},
		{"duplicate-business-journal", "resource_journal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			counts := map[string]int{"access_bindings": 1, "access_binding_subjects": 1, "subject_change_outbox": 1, "resource_reconcile_outbox": 1, "resource_journal": 2, "journal-CREATED": 1, "journal-UPDATED": 1}
			require.True(t, rid03BusinessCountsValid(counts))
			counts[tc.table]++
			require.False(t, rid03BusinessCountsValid(counts))
		})
	}
}
func TestRID03ClosedRawDeltaCoordinates(t *testing.T) {
	for _, tc := range []struct {
		name, table string
		change      func(*testing.T, *rid03DeltaPolicy, rid09PrimaryRow)
		kind        string
		want        bool
	}{
		{"legal-exact-member", "access_binding_target_members", nil, "member", true},
		{"legal-exact-fact", "relation_fact", nil, "fact", true},
		{"legal-exact-ledger", "access_binding_emitted_tuples", nil, "ledger", true},
		{"legal-exact-old-owner-member", "access_binding_target_members", func(t *testing.T, p *rid03DeltaPolicy, r rid09PrimaryRow) {
			r["binding_id"] = json.RawMessage(`"old-owner-binding"`)
			r["role_id"] = json.RawMessage(`"owner-role"`)
			r["rule_fp"] = json.RawMessage(`"owner-rule"`)
			r["object_type"] = json.RawMessage(`"iam.accessBinding"`)
			r["object_id"] = json.RawMessage(`"new-binding"`)
		}, "member", true},
		{"wrong-relation-same-endpoints", "relation_fact", func(t *testing.T, p *rid03DeltaPolicy, r rid09PrimaryRow) {
			r["relation"] = json.RawMessage(`"v_delete"`)
		}, "fact", false},
		{"wrong-binding", "access_binding_target_members", func(t *testing.T, p *rid03DeltaPolicy, r rid09PrimaryRow) {
			r["binding_id"] = json.RawMessage(`"other-binding"`)
		}, "member", false},
		{"wrong-role", "access_binding_target_members", func(t *testing.T, p *rid03DeltaPolicy, r rid09PrimaryRow) {
			r["role_id"] = json.RawMessage(`"other-role"`)
		}, "member", false},
		{"wrong-rule", "access_binding_target_members", func(t *testing.T, p *rid03DeltaPolicy, r rid09PrimaryRow) {
			r["rule_fp"] = json.RawMessage(`"other-rule"`)
		}, "member", false},
		{"wrong-status", "access_binding_target_members", func(t *testing.T, p *rid03DeltaPolicy, r rid09PrimaryRow) {
			r["verification_status"] = json.RawMessage(`"REJECTED"`)
		}, "member", false},
		{"wrong-object-type", "access_binding_target_members", func(t *testing.T, p *rid03DeltaPolicy, r rid09PrimaryRow) {
			r["object_type"] = json.RawMessage(`"iam.accessBinding"`)
		}, "member", false},
		{"wrong-member-time", "access_binding_target_members", func(t *testing.T, p *rid03DeltaPolicy, r rid09PrimaryRow) {
			r["updated_at"], _ = json.Marshal(p.End.Add(time.Hour))
		}, "member", false},
		{"hidden-ID-other-field", "access_binding_target_members", func(t *testing.T, p *rid03DeltaPolicy, r rid09PrimaryRow) {
			r["binding_id"] = json.RawMessage(`"other-binding"`)
			r["rule_fp"] = json.RawMessage(`"new-binding"`)
		}, "member", false},
		{"hidden-ID-unknown-column", "access_binding_target_members", func(t *testing.T, p *rid03DeltaPolicy, r rid09PrimaryRow) {
			r["unexpected"] = json.RawMessage(`"new-binding"`)
		}, "member", false},
		{"old-G-extra-edge", "access_binding_target_members", func(t *testing.T, p *rid03DeltaPolicy, r rid09PrimaryRow) {
			r["binding_id"] = json.RawMessage(`"old-owner-binding"`)
			r["role_id"] = json.RawMessage(`"owner-role"`)
			r["rule_fp"] = json.RawMessage(`"owner-rule"`)
			r["object_type"] = json.RawMessage(`"registry.registries"`)
			r["object_id"] = json.RawMessage(`"new-binding"`)
		}, "member", false},
		{"unknown-addition", "unknown_table", nil, "member", false},
		{"missing-column", "access_binding_target_members", func(t *testing.T, p *rid03DeltaPolicy, r rid09PrimaryRow) { delete(r, "live") }, "member", false},
		{"ledger-wrong-source", "access_binding_emitted_tuples", func(t *testing.T, p *rid03DeltaPolicy, r rid09PrimaryRow) { r["source"] = json.RawMessage(`"binding"`) }, "ledger", false},
		{"ledger-wrong-member-object", "access_binding_emitted_tuples", func(t *testing.T, p *rid03DeltaPolicy, r rid09PrimaryRow) {
			r["member_object_id"] = json.RawMessage(`"other"`)
		}, "ledger", false},
		{"fact-condition-privilege", "relation_fact", func(t *testing.T, p *rid03DeltaPolicy, r rid09PrimaryRow) {
			r["condition_name"] = json.RawMessage(`"extra-condition"`)
		}, "fact", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, member, fact, ledger := rid03UnitPolicy(t)
			row := member
			if tc.kind == "fact" {
				row = fact
			}
			if tc.kind == "ledger" {
				row = ledger
			}
			if tc.change != nil {
				tc.change(t, &p, row)
			}
			require.Equal(t, tc.want, p.allows(tc.table, row))
		})
	}
}
func rid03UnitObservation() (*rid03NewmanExpectation, *rid03ActGetObservation, rid03NewmanSnapshot, rid03NewmanSnapshot) {
	e := &rid03NewmanExpectation{CaseID: "registry-installation-rid03-S1-GRANT-ACT", Phase: "ACT", Path: "/iam/v1/accessBindings", Request: map[string]any{"subjectType": "service_account", "subjectId": "grantee", "roleId": "role", "scopeType": "iam.account", "scopeId": "account", "target": map[string]any{"resources": map[string]any{"resources": []any{map[string]any{"type": "registry.registries", "id": "target"}}}}}, Resource: map[string]any{"id": "binding", "materializedAt": "2026-11-03T12:00:01Z", "createdAt": "2026-11-03T12:00:00Z", "delegationId": "delegation"}}
	o := &rid03ActGetObservation{Version: 1, CaseID: e.CaseID, RequestName: e.CaseID + " :: actual-action-resource-Get", Method: "GET", Path: "/iam/v1/accessBindings/binding", ResourceID: "binding", MaterializedAt: "2026-11-03T12:00:01Z", CreatedAt: "2026-11-03T12:00:00Z", DelegationID: "delegation", SubjectType: "service_account", SubjectID: "grantee", RoleID: "role", ScopeType: "iam.account", ScopeID: "account", TargetType: "registry.registries", TargetID: "target", StartedAt: "2026-11-03T12:00:01.100Z", CompletedAt: "2026-11-03T12:00:01.200Z"}
	before, after := rid03NewmanSnapshot{}, rid03NewmanSnapshot{}
	before.Whole.PrimaryFinishedAt = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	after.Whole.PrimaryStartedAt = time.Date(2026, 11, 3, 12, 0, 2, 0, time.UTC)
	return e, o, before, after
}
func TestRID03ActualGetIndependentOracle(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*rid03NewmanExpectation, **rid03ActGetObservation, *rid03NewmanSnapshot, *rid03NewmanSnapshot)
		want   bool
	}{
		{"exact-primary-twin", nil, true},
		{"forged-timestamp", func(e *rid03NewmanExpectation, o **rid03ActGetObservation, a, b *rid03NewmanSnapshot) {
			(*o).MaterializedAt = "2026-11-03T12:00:00Z"
		}, false},
		{"far-future", func(e *rid03NewmanExpectation, o **rid03ActGetObservation, a, b *rid03NewmanSnapshot) {
			(*o).MaterializedAt = "2099-11-03T12:00:01Z"
		}, false},
		{"wrong-ID", func(e *rid03NewmanExpectation, o **rid03ActGetObservation, a, b *rid03NewmanSnapshot) {
			(*o).ResourceID = "other"
			(*o).Path = "/iam/v1/accessBindings/other"
		}, false},
		{"wrong-phase", func(e *rid03NewmanExpectation, o **rid03ActGetObservation, a, b *rid03NewmanSnapshot) {
			e.CaseID = "registry-installation-rid03-S1-GRANT-VERIFY"
		}, false},
		{"wrong-request-identity", func(e *rid03NewmanExpectation, o **rid03ActGetObservation, a, b *rid03NewmanSnapshot) {
			(*o).RoleID = "other-role"
		}, false},
		{"missing", func(e *rid03NewmanExpectation, o **rid03ActGetObservation, a, b *rid03NewmanSnapshot) { *o = nil }, false},
		{"pre-baseline-request", func(e *rid03NewmanExpectation, o **rid03ActGetObservation, a, b *rid03NewmanSnapshot) {
			a.Whole.PrimaryFinishedAt = a.Whole.PrimaryFinishedAt.Add(time.Hour)
		}, false},
		{"after-primary-request", func(e *rid03NewmanExpectation, o **rid03ActGetObservation, a, b *rid03NewmanSnapshot) {
			b.Whole.PrimaryStartedAt = b.Whole.PrimaryStartedAt.Add(-time.Hour)
		}, false},
		{"moving-primary-materialization", func(e *rid03NewmanExpectation, o **rid03ActGetObservation, a, b *rid03NewmanSnapshot) {
			e.Resource["materializedAt"] = "2026-11-03T12:00:02Z"
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, o, a, b := rid03UnitObservation()
			if tc.change != nil {
				tc.change(e, &o, &a, &b)
			}
			err := rid03MatchActObservation(e, o, a, b)
			if tc.want {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
func TestRID03ClosedObservationJSON(t *testing.T) {
	_, o, _, _ := rid03UnitObservation()
	raw, err := json.Marshal(o)
	require.NoError(t, err)
	for _, tc := range []struct {
		name string
		raw  []byte
		want bool
	}{
		{"closed-exact", raw, true},
		{"duplicate", []byte(strings.TrimSuffix(string(raw), "}") + `,"version":1}`), false},
		{"unknown-extra", []byte(strings.TrimSuffix(string(raw), "}") + `,"body":"withheld"}`), false},
		{"extra-observations-array", []byte("[" + string(raw) + "," + string(raw) + "]"), false},
		{"wrong-type", []byte(strings.Replace(string(raw), `"version":1`, `"version":true`, 1)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got rid03ActGetObservation
			err := json.Unmarshal(tc.raw, &got)
			if tc.want {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestRID03ReceiptObservationScope(t *testing.T) {
	_, o, _, _ := rid03UnitObservation()
	raw, err := json.Marshal(o)
	require.NoError(t, err)
	for _, tc := range []struct {
		name, caseID string
		raw          json.RawMessage
		want         bool
	}{
		{"eligible-exact", o.CaseID, raw, true},
		{"eligible-missing", o.CaseID, nil, false},
		{"default-absent", "registry-installation-rid10-FAULT-PARTIAL", nil, true},
		{"wrong-phase", "registry-installation-rid03-S1-GRANT-VERIFY", raw, false},
		{"GD-no-observation", "registry-installation-rid03-S1-CREATOR-GD-TWIN-ACT", raw, false},
		{"outside-null", "registry-installation-rid10-FAULT-PARTIAL", json.RawMessage("null"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rid03DecodeReceiptObservation(tc.caseID, tc.raw)
			if tc.want {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
	for _, tc := range []struct {
		name, wire string
		want       bool
	}{
		{"one-slot", `{"rid03ActGet":` + string(raw) + `}`, true},
		{"duplicate-slot", `{"rid03ActGet":` + string(raw) + `,"rid03ActGet":` + string(raw) + `}`, false},
		{"unknown-extra-slot", `{"rid03OtherObservation":{}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := rid03CheckReceiptObservationField([]byte(tc.wire))
			if tc.want {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
