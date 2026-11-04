// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Фикстура проходит настоящий разбор SQL-байтов и построитель доказательства.
func rid06UnitReadSnapshot(t *testing.T, rows []rid09PrimaryRow, after bool) rid03NewmanSnapshot {
	t.Helper()
	at := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	start := at.Add(9 * time.Second)
	if after {
		start = at.Add(29 * time.Second)
	}
	whole := ridWholeDeliverySnapshot{PrimaryStartedAt: start, PrimaryFinishedAt: start.Add(time.Second), Delivery: map[string]ridWholeTable{"domain": {Columns: []string{"id"}, Rows: []string{"same-domain"}}}, Bookkeeping: map[string]ridWholeTable{}, Separation: map[string]string{}}
	for table, reason := range ridWholeBookkeeping {
		whole.Bookkeeping[table] = ridWholeTable{Columns: []string{"id"}, Rows: []string{}}
		whole.Separation[table] = reason
	}
	entry := ridWholeTable{Columns: strings.Fields(rid11AuthnColumns["audit_outbox"]), Rows: []string{}}
	for _, row := range rows {
		raw, err := json.Marshal(row)
		require.NoError(t, err)
		whole.auditSQLRows = append(whole.auditSQLRows, raw)
		entry.Rows = append(entry.Rows, rid06ByteSHA(raw))
	}
	sort.Strings(entry.Rows)
	whole.Bookkeeping["audit_outbox"] = entry
	return rid03NewmanSnapshot{Whole: whole, Raw: map[string][]rid09PrimaryRow{}, BusinessAudit: []rid09PrimaryRow{}}
}

func TestRID06ReadBoundaryAuditProof(t *testing.T) {
	for _, name := range []string{"unchanged", "claim", "backoff", "sent", "empty", "immutable-id", "immutable-event", "immutable-tenant", "immutable-payload", "immutable-created", "insert", "delete", "duplicate-id", "illegal-transition", "unknown-column", "missing-column", "raw-hash-mismatch", "column-roster-mismatch", "column-order-mismatch", "invalid-time", "bounds-mismatch", "other-bookkeeping", "auth-bookkeeping", "missing-bookkeeping", "unknown-bookkeeping", "separation-mismatch", "delivery-delta", "unknown-case", "act-case", "explicit-verify-case", "foreign-run", "malformed-json", "duplicate-json-key"} {
		t.Run(name, func(t *testing.T) {
			old, now := rid11UnitAuditRow(), rid11UnitAuditRow()
			at, _ := rid03Cell[time.Time](old, "created_at")
			caseID, runID := "registry-installation-rid06-S1-BEFORE-REVOKE", "rid06-unit-owned-run-20261104"
			want := false
			switch name {
			case "unchanged", "empty":
				want = true
			case "claim":
				rid11UnitSet(now, "attempts", 1)
				want = true
			case "backoff":
				rid11UnitSet(now, "attempts", 1)
				rid11UnitSet(now, "next_attempt_at", at.Add(22*time.Second))
				rid11UnitSet(now, "last_error", "private-safe-unit-cause")
				want = true
			case "sent":
				rid11UnitSet(now, "attempts", 1)
				rid11UnitSet(now, "status", "sent")
				rid11UnitSet(now, "sent_at", at.Add(20*time.Second))
				want = true
			case "immutable-id":
				rid11UnitSet(now, "id", "foreign-event")
			case "immutable-event":
				rid11UnitSet(now, "event_type", "changed")
			case "immutable-tenant":
				rid11UnitSet(now, "tenant_account_id", "different")
			case "immutable-payload":
				rid11UnitSet(now, "event_payload", map[string]any{"key_id": "changed"})
			case "immutable-created":
				rid11UnitSet(now, "created_at", at.Add(-time.Second))
			case "illegal-transition":
				rid11UnitSet(now, "status", "sent")
			case "unknown-column":
				rid11UnitSet(now, "future", true)
			case "missing-column":
				delete(now, "event_payload")
			case "invalid-time":
				rid11UnitSet(now, "created_at", at.Add(time.Hour))
			case "unknown-case":
				caseID = "registry-installation-rid06-S1-UNKNOWN"
			case "act-case":
				caseID = "registry-installation-rid06-S1-REVOKE-ACT"
			case "explicit-verify-case":
				caseID = "registry-installation-rid06-S1-EXPLICIT-CREATE-VERIFY"
			case "foreign-run":
				runID = "bad/run"
			}
			a := rid06UnitReadSnapshot(t, []rid09PrimaryRow{old}, false)
			b := rid06UnitReadSnapshot(t, []rid09PrimaryRow{now}, true)
			switch name {
			case "empty":
				a = rid06UnitReadSnapshot(t, nil, false)
				b = rid06UnitReadSnapshot(t, nil, true)
			case "insert":
				extra := rid11UnitAuditRow()
				rid11UnitSet(extra, "id", "extra-event")
				b = rid06UnitReadSnapshot(t, []rid09PrimaryRow{now, extra}, true)
			case "delete":
				b = rid06UnitReadSnapshot(t, nil, true)
			case "duplicate-id":
				b = rid06UnitReadSnapshot(t, []rid09PrimaryRow{now, now}, true)
			case "raw-hash-mismatch":
				b.Whole.Bookkeeping["audit_outbox"].Rows[0] = strings.Repeat("0", 64)
			case "column-roster-mismatch":
				entry := b.Whole.Bookkeeping["audit_outbox"]
				entry.Columns = append(entry.Columns, "future")
				b.Whole.Bookkeeping["audit_outbox"] = entry
			case "column-order-mismatch":
				cols := b.Whole.Bookkeeping["audit_outbox"].Columns
				cols[0], cols[1] = cols[1], cols[0]
			case "bounds-mismatch":
				b.Whole.PrimaryStartedAt = a.Whole.PrimaryFinishedAt.Add(-time.Second)
			case "other-bookkeeping":
				b.Whole.Bookkeeping["operations"] = ridWholeTable{Rows: []string{"changed"}}
			case "auth-bookkeeping":
				b.Whole.Bookkeeping["access_tokens"] = ridWholeTable{Rows: []string{"changed"}}
			case "missing-bookkeeping":
				delete(b.Whole.Bookkeeping, "refresh_tokens")
			case "unknown-bookkeeping":
				b.Whole.Bookkeeping["future"] = ridWholeTable{}
			case "separation-mismatch":
				b.Whole.Separation["audit_outbox"] = "different"
			case "delivery-delta":
				b.Whole.Delivery["domain"] = ridWholeTable{Rows: []string{"changed"}}
			case "malformed-json", "duplicate-json-key":
				raw := []byte(`{"broken"`)
				if name == "duplicate-json-key" {
					raw = append([]byte(`{"status":"sent",`), b.Whole.auditSQLRows[0][1:]...)
				}
				b.Whole.auditSQLRows[0] = raw
				b.Whole.Bookkeeping["audit_outbox"].Rows[0] = rid06ByteSHA(raw)
			}
			proof, ok := rid06BuildReadBoundary(caseID, runID, a, b)
			require.Equal(t, want, ok)
			if !ok {
				require.Empty(t, proof)
				return
			}
			require.Equal(t, caseID, proof.CaseID)
			require.Equal(t, runID, proof.RunID)
			require.Equal(t, a.Whole.PrimaryStartedAt, proof.BeforeStartedAt)
			require.Equal(t, b.Whole.PrimaryFinishedAt, proof.AfterFinishedAt)
			require.Equal(t, a.Whole.Bookkeeping["audit_outbox"].Rows, proof.BeforeSQLRowSHA256)
			require.Equal(t, b.Whole.Bookkeeping["audit_outbox"].Rows, proof.AfterSQLRowSHA256)
			require.Len(t, proof.Rows, len(b.Whole.auditSQLRows))
			for _, row := range proof.Rows {
				require.Equal(t, row.BeforeImmutableSHA256, row.AfterImmutableSHA256)
				require.Contains(t, proof.BeforeSQLRowSHA256, row.BeforeRowSHA256)
				require.Contains(t, proof.AfterSQLRowSHA256, row.AfterRowSHA256)
				require.Equal(t, at, row.CreatedAt)
				if name == "backoff" {
					require.True(t, row.After.ErrorPresent)
					require.Equal(t, rid06ByteSHA([]byte("private-safe-unit-cause")), row.After.ErrorSHA256)
				}
			}
			raw, err := json.Marshal(proof)
			require.NoError(t, err)
			require.NotContains(t, string(raw), "private-safe-unit-cause")
			require.NotContains(t, string(raw), "unit-key")
			// Имена столбцов допустимы как строки; исходные данные не становятся JSON-полями.
			object := rid06UnitClosedJSONObject(t, raw, []string{"caseId", "runId", "beforePrimaryStartedAt", "beforePrimaryFinishedAt", "afterPrimaryStartedAt", "afterPrimaryFinishedAt", "columns", "beforeSQLRowSHA256", "afterSQLRowSHA256", "rows"})
			var columns []string
			require.NoError(t, json.Unmarshal(object["columns"], &columns))
			require.Contains(t, columns, "event_payload")
			var rows []json.RawMessage
			require.NoError(t, json.Unmarshal(object["rows"], &rows))
			for _, rowRaw := range rows {
				row := rid06UnitClosedJSONObject(t, rowRaw, []string{"id", "createdAt", "beforeRowSHA256", "afterRowSHA256", "beforeImmutableSHA256", "afterImmutableSHA256", "before", "after"})
				for _, side := range []string{"before", "after"} {
					rid06UnitClosedJSONObject(t, row[side], []string{"status", "attempts", "nextAttemptAt", "sentAt", "errorPresent", "errorSHA256"})
				}
			}
			wholeRaw, err := json.Marshal(b.Whole)
			require.NoError(t, err)
			require.NotContains(t, string(wholeRaw), "unit-key")
			require.NotContains(t, string(wholeRaw), "private-safe-unit-cause")
			require.NotContains(t, string(wholeRaw), "auditSQLRows")
		})
	}
}

func TestRID06PreparationPreservesSerializedExpectation(t *testing.T) {
	for _, name := range []string{"same", "operator-auth-only", "delivery", "raw", "projection", "operations", "own-ceilings", "separation", "bounds"} {
		t.Run(name, func(t *testing.T) {
			a := rid06UnitReadSnapshot(t, []rid09PrimaryRow{rid11UnitAuditRow()}, false)
			b := rid06UnitReadSnapshot(t, []rid09PrimaryRow{rid11UnitAuditRow()}, true)
			want := name == "same" || name == "operator-auth-only"
			switch name {
			case "operator-auth-only":
				b.Whole.Bookkeeping["access_tokens"] = ridWholeTable{Rows: []string{"new-auth"}}
			case "delivery":
				b.Whole.Delivery["domain"] = ridWholeTable{Rows: []string{"changed"}}
			case "raw":
				b.Raw["future"] = []rid09PrimaryRow{}
			case "projection":
				b.Projection.Materialization = "changed"
			case "operations":
				b.Whole.Bookkeeping["operations"] = ridWholeTable{Rows: []string{"changed"}}
			case "own-ceilings":
				b.Whole.OwnCeilings.Raw.Rows = []string{"changed"}
			case "separation":
				b.Whole.Separation["audit_outbox"] = "changed"
			case "bounds":
				b.Whole.PrimaryStartedAt = a.Whole.PrimaryFinishedAt.Add(-time.Second)
			}
			require.Equal(t, want, rid06PreparationEqual(a, b))
		})
	}
}

func TestRID06ReadBoundaryClosedCases(t *testing.T) {
	count := 0
	for id, actor := range rid06PublicActors {
		if rid06ReadBracketCase(id) {
			count++
			require.Equal(t, "O", actor)
			require.Contains(t, []string{"READ", "VERIFY"}, rid06PublicPhase(id))
			a := rid06UnitReadSnapshot(t, []rid09PrimaryRow{rid11UnitAuditRow()}, false)
			b := rid06UnitReadSnapshot(t, []rid09PrimaryRow{rid11UnitAuditRow()}, true)
			_, ok := rid06BuildReadBoundary(id, "rid06-unit-owned-run-20261104", a, b)
			require.True(t, ok)
		}
	}
	require.Equal(t, 20, count)
	for _, mode := range []string{"S1", "S2"} {
		for _, suffix := range []string{"EXPLICIT-CREATE-ACT", "EXPLICIT-CREATE-VERIFY", "EXPLICIT-RECOVERY-ACT", "EXPLICIT-RECOVERY-VERIFY", "REVOKE-ACT", "UNKNOWN"} {
			require.False(t, rid06ReadBracketCase("registry-installation-rid06-"+mode+"-"+suffix))
		}
	}
}

func TestRID06ReadBoundaryEveryBookkeepingTable(t *testing.T) {
	for _, table := range []string{"client_assertion_replay", "access_tokens", "authorization_codes", "refresh_tokens", "token_families", "human_sessions", "human_first_authentications", "login_failures", "operations"} {
		t.Run(table, func(t *testing.T) {
			a := rid06UnitReadSnapshot(t, []rid09PrimaryRow{rid11UnitAuditRow()}, false)
			b := rid06UnitReadSnapshot(t, []rid09PrimaryRow{rid11UnitAuditRow()}, true)
			b.Whole.Bookkeeping[table] = ridWholeTable{Columns: []string{"id"}, Rows: []string{"changed"}}
			_, ok := rid06BuildReadBoundary("registry-installation-rid06-S1-BEFORE-REVOKE", "rid06-unit-owned-run-20261104", a, b)
			require.False(t, ok)
		})
	}
}

// Закрытая схема отвергает добавление payload/error/SQL-полей на каждом уровне proof.
func rid06UnitClosedJSONObject(t *testing.T, raw []byte, keys []string) map[string]json.RawMessage {
	t.Helper()
	var object map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &object))
	require.NotNil(t, object)
	require.Len(t, object, len(keys))
	for _, key := range keys {
		require.Contains(t, object, key)
	}
	return object
}
