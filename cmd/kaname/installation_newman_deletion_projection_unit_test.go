// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

// Независимо построенные ожидания публичного состояния/журнала: исправленный построитель
// ожидаемой проекции не используется для построения собственного положительного оракула.
func rid05ProjectionControl(t *testing.T, kind string) (rid03NewmanSnapshot, rid03NewmanSnapshot) {
	base := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	member := func(binding, typ, id string, at time.Time, status string) rid09PrimaryRow {
		return rid03UnitRow(t, map[string]any{"binding_id": binding, "role_id": "role", "rule_fp": "fp", "object_type": typ, "object_id": id, "verification_status": status, "updated_at": at, "created_at": base, "future": map[string]any{"preserved": true}})
	}
	removed := member("ownerG", "iam.serviceAccount", "C", base.Add(5*time.Second+123456789*time.Nanosecond), "ACTIVE")
	kept := member("ownerG", "iam.serviceAccount", "C2", base.Add(4*time.Second+987654321*time.Nanosecond), "ACTIVE")
	if kind == "microseconds" {
		kept = member("ownerG", "iam.serviceAccount", "C2", base.Add(4*time.Second+987654*time.Microsecond), "ACTIVE")
	}
	other := member("otherG", "iam.group", "C", base.Add(7*time.Second+123456789*time.Nanosecond), "ACTIVE")
	before := []rid09PrimaryRow{removed, kept, other}
	after := []rid09PrimaryRow{kept, other}
	var expectedAt any = "2026-11-03T12:00:04Z"
	if kind == "zero-null" {
		before = []rid09PrimaryRow{removed, other}
		after = []rid09PrimaryRow{other}
		expectedAt = nil
	}
	if kind == "inactive-retained-null" {
		kept["verification_status"] = json.RawMessage(`"REJECTED"`)
		expectedAt = nil
	}
	if kind == "empty-ledger-null" {
		before = []rid09PrimaryRow{removed}
		after = []rid09PrimaryRow{}
		expectedAt = nil
	}
	projection := rid09NewmanProjection{Accounts: []map[string]any{{"id": "SYS", "createdAt": "before"}}, ServiceAccounts: []map[string]any{{"id": "C", "name": "same"}, {"id": "C2", "name": "same"}}, Groups: []map[string]any{{"id": "group"}}, Members: map[string][]map[string]any{"group": {}}, Roles: []map[string]any{{"id": "role", "rules": "whole"}}, Bindings: []map[string]any{{"id": "ownerG", "status": "ACTIVE", "delegationId": "", "createdAt": "before", "materializedAt": "2026-11-03T12:00:05Z", "unknown": "retained"}, {"id": "otherG", "status": "ACTIVE", "delegationId": "GD", "createdAt": "before", "materializedAt": "2026-11-03T12:00:07Z"}}, Delegations: []map[string]any{{"id": "GD", "status": "ACTIVE", "delegatedBy": "originalC", "createdAt": "before"}}, Catalog: map[string]any{"full": "catalog"}, Materialization: ridWholeDigest(t, before)}
	if kind == "empty-ledger-null" {
		projection.Bindings[1]["materializedAt"] = nil
		projection.Bindings[1]["delegationId"] = ""
	}
	a := rid03NewmanSnapshot{Projection: projection, Raw: map[string][]rid09PrimaryRow{"access_binding_target_members": before}}
	b := rid03NewmanSnapshot{Raw: map[string][]rid09PrimaryRow{"access_binding_target_members": after}}
	// Оборот JSON создаёт независимые безопасные карты; намеренно несериализуемый
	// внутренний барьер восстанавливается отдельно из независимого полного журнала.
	raw, err := json.Marshal(projection)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &b.Projection))
	b.Projection.ServiceAccounts = []map[string]any{{"id": "C2", "name": "same"}}
	b.Projection.Bindings[0]["materializedAt"] = expectedAt
	b.Projection.Materialization = ridWholeDigest(t, after)
	return a, b
}
func TestRID05DeleteProjectionCanonicalLedgerTwin(t *testing.T) {
	for _, name := range []string{"nanoseconds", "microseconds", "zero-null", "inactive-retained-null", "empty-ledger-null"} {
		t.Run(name, func(t *testing.T) {
			a, b := rid05ProjectionControl(t, name)
			require.NotEqual(t, a.Projection.Materialization, b.Projection.Materialization, "authorized member removal changes the full hidden fence")
			require.True(t, rid05DeleteProjectionValid(a, b, "C", false))
			require.Equal(t, ridWholeDigest(t, b.Raw["access_binding_target_members"]), b.Projection.Materialization)
		})
	}
}
func TestRID05DeleteProjectionRejectsUnexplainedChanges(t *testing.T) {
	for _, name := range []string{"retained-BEFORE-fence", "forged-AFTER-fence", "unrelated-member-clock-same-wire-second", "remaining-unknown-column-changed", "wrong-type-same-ID-removed", "retained-row-reordered", "wrong-wire-fraction", "wrong-wire-second", "missing-materializedAt", "zero-is-not-epoch", "zero-is-not-absent", "C-still-present", "C2-removed", "binding-createdAt", "binding-delegation", "binding-extra-field", "unrelated-binding-time", "GD-retied", "GD-history-time", "account-changed", "role-changed", "catalog-changed", "group-member-added"} {
		t.Run(name, func(t *testing.T) {
			kind := "nanoseconds"
			if name == "zero-is-not-epoch" || name == "zero-is-not-absent" {
				kind = "zero-null"
			}
			a, b := rid05ProjectionControl(t, kind)
			switch name {
			case "retained-BEFORE-fence":
				b.Projection.Materialization = a.Projection.Materialization
			case "forged-AFTER-fence":
				b.Projection.Materialization = "unbacked"
			case "unrelated-member-clock-same-wire-second", "remaining-unknown-column-changed":
				r := rid09PrimaryRow{}
				for k, v := range b.Raw["access_binding_target_members"][0] {
					r[k] = v
				}
				if name == "unrelated-member-clock-same-wire-second" {
					r["updated_at"] = json.RawMessage(`"2026-11-03T12:00:04.987654322Z"`)
				} else {
					r["future"] = json.RawMessage(`{"preserved":false}`)
				}
				b.Raw["access_binding_target_members"][0] = r
				b.Projection.Materialization = ridWholeDigest(t, b.Raw["access_binding_target_members"])
			case "wrong-type-same-ID-removed":
				b.Projection.Materialization = ridWholeDigest(t, b.Raw["access_binding_target_members"][:1])
			case "retained-row-reordered":
				rows := b.Raw["access_binding_target_members"]
				b.Projection.Materialization = ridWholeDigest(t, []rid09PrimaryRow{rows[1], rows[0]})
			case "wrong-wire-fraction":
				b.Projection.Bindings[0]["materializedAt"] = "2026-11-03T12:00:04.987654321Z"
			case "wrong-wire-second":
				b.Projection.Bindings[0]["materializedAt"] = "2026-11-03T12:00:05Z"
			case "missing-materializedAt", "zero-is-not-absent":
				delete(b.Projection.Bindings[0], "materializedAt")
			case "zero-is-not-epoch":
				b.Projection.Bindings[0]["materializedAt"] = "1970-01-01T00:00:00Z"
			case "C-still-present":
				b.Projection.ServiceAccounts = a.Projection.ServiceAccounts
			case "C2-removed":
				b.Projection.ServiceAccounts = []map[string]any{}
			case "binding-createdAt":
				b.Projection.Bindings[0]["createdAt"] = "changed"
			case "binding-delegation":
				b.Projection.Bindings[0]["delegationId"] = "different"
			case "binding-extra-field":
				b.Projection.Bindings[0]["future-added"] = "changed"
			case "unrelated-binding-time":
				b.Projection.Bindings[1]["materializedAt"] = "changed"
			case "GD-retied":
				b.Projection.Delegations[0]["delegatedBy"] = "C2"
			case "GD-history-time":
				b.Projection.Delegations[0]["createdAt"] = "changed"
			case "account-changed":
				b.Projection.Accounts[0]["createdAt"] = "changed"
			case "role-changed":
				b.Projection.Roles[0]["rules"] = "extra"
			case "catalog-changed":
				b.Projection.Catalog["full"] = "other"
			case "group-member-added":
				b.Projection.Members["group"] = []map[string]any{{"memberType": "service_account", "memberId": "C2"}}
			}
			require.False(t, rid05DeleteProjectionValid(a, b, "C", false))
		})
	}
}
func TestRID05DeleteProjectionRejectsInconsistentBefore(t *testing.T) {
	for _, name := range []string{"missing-ledger", "unbacked-BEFORE-fence", "missing-binding-coordinate", "missing-member-time", "malformed-member-time", "null-member-time", "missing-creator", "duplicate-creator"} {
		t.Run(name, func(t *testing.T) {
			a, b := rid05ProjectionControl(t, "nanoseconds")
			switch name {
			case "missing-ledger":
				delete(a.Raw, "access_binding_target_members")
			case "unbacked-BEFORE-fence":
				a.Projection.Materialization = "unbacked"
			case "missing-binding-coordinate":
				delete(a.Raw["access_binding_target_members"][0], "binding_id")
				a.Projection.Materialization = ridWholeDigest(t, a.Raw["access_binding_target_members"])
			case "missing-member-time":
				delete(a.Raw["access_binding_target_members"][0], "updated_at")
				a.Projection.Materialization = ridWholeDigest(t, a.Raw["access_binding_target_members"])
			case "malformed-member-time":
				a.Raw["access_binding_target_members"][0]["updated_at"] = json.RawMessage(`"not-time"`)
				a.Projection.Materialization = ridWholeDigest(t, a.Raw["access_binding_target_members"])
			case "null-member-time":
				a.Raw["access_binding_target_members"][0]["updated_at"] = json.RawMessage(`null`)
				a.Projection.Materialization = ridWholeDigest(t, a.Raw["access_binding_target_members"])
			case "missing-creator":
				a.Projection.ServiceAccounts = a.Projection.ServiceAccounts[1:]
			case "duplicate-creator":
				a.Projection.ServiceAccounts = append(a.Projection.ServiceAccounts, a.Projection.ServiceAccounts[0])
			}
			require.False(t, rid05DeleteProjectionValid(a, b, "C", false))
		})
	}
}
func TestRID05FailedDeleteProjectionStillFullyUnchanged(t *testing.T) {
	a, b := rid05ProjectionControl(t, "nanoseconds")
	require.True(t, rid05DeleteProjectionValid(a, a, "C", true))
	require.False(t, rid05DeleteProjectionValid(a, b, "C", true))
}
