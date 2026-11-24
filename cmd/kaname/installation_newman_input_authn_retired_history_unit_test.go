// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
)

// Форма взята из начального seed, ownership-миграции и RevokeGuarded.
// Идентификаторы legacy — исходные migration literals; времена синтетические.
// Три новых члена и пятнадцать tuples задаёт прежний независимый fixture.
func rid11RetiredBindingFixture(t *testing.T) (rid03NewmanSnapshot, rid03NewmanSnapshot, *catalog.Facts) {
	t.Helper()
	a, b, facts := rid11BindingFixture(t)
	at := a.Whole.PrimaryStartedAt
	for _, s := range []*rid03NewmanSnapshot{&a, &b} {
		s.Raw["clusters"] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"id": "cluster_fixture"})}
		s.Raw["accounts"] = append(s.Raw["accounts"], rid11RestoreRow(map[string]any{"id": "acc1a18042d81fb438d6"}))
		s.Raw["groups"] = append(s.Raw["groups"], rid11RestoreRow(map[string]any{"id": "grp258e6bbe9bbe45568", "account_id": "acc1a18042d81fb438d6"}))
		s.Raw["registration_legacy_cluster_writer_identity"] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"singleton": true, "account_id": "acc1a18042d81fb438d6", "group_id": "grp258e6bbe9bbe45568", "cluster_id": "cluster_fixture", "original_binding_id": "acb9e920fb038c7e4f74", "original_seed_name": "module-relation-writers", "granted_relation": "fga_writer"})}
		s.Raw["registration_account_writer_switch"] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"singleton": true, "switched_at": at.Add(-3 * time.Minute), "disabled_modules": []any{}, "cluster_writer_retired_at": at.Add(-time.Minute)})}
		legacy := rid11RestoreRow(map[string]any{"id": "acb9e920fb038c7e4f74", "role_id": nil, "subject_type": "group", "subject_id": "grp258e6bbe9bbe45568", "resource_type": "cluster", "resource_id": "cluster_fixture", "created_at": at.Add(-time.Hour), "status": "REVOKED", "expires_at": nil, "granted_by_user_id": "", "revoked_at": at.Add(-2 * time.Minute), "revoked_by_user_id": "system:registration-account-writers", "revocation_reason": "REVOKE", "scope": 1, "deletion_protection": false, "labels": map[string]string{}, "target": map[string]any{"allInScope": true}, "target_digest": (domain.AccessTarget{AllInScope: true}).Digest(), "granted_relation": "fga_writer", "is_system": true, "narrowed_at": nil, "delegation_id": nil})
		// У настоящей таблицы одинаковые колонки у всех строк; дополняем старый
		// минимальный активный пример полями истории, не меняя его полномочий.
		for key := range legacy {
			if _, exists := s.Raw["access_bindings"][0][key]; !exists {
				s.Raw["access_bindings"][0][key] = json.RawMessage(`null`)
			}
		}
		s.Raw["access_bindings"] = append(s.Raw["access_bindings"], legacy)
		s.Raw["access_binding_subjects"] = append(s.Raw["access_binding_subjects"], rid11RestoreRow(map[string]any{"binding_id": "acb9e920fb038c7e4f74", "subject_type": "group", "subject_id": "grp258e6bbe9bbe45568", "ordinal": 0, "resource_type": "cluster", "resource_id": "cluster_fixture"}))
		s.Raw["access_binding_emitted_tuples"] = append(s.Raw["access_binding_emitted_tuples"], rid11RestoreRow(map[string]any{"binding_id": "acb9e920fb038c7e4f74", "source": "binding", "member_object_type": "", "member_object_id": "", "fga_user": "group:grp258e6bbe9bbe45568#member", "relation": "fga_writer", "object": "cluster:cluster_fixture"}))
		rid11RetiredUnitCounts(s)
	}
	return a, b, facts
}

// Обновление census в отрицательных примерах не даёт пройти только из-за старого
// hash: проверяем смысл изменённой строки, а не случайную несогласованность fixture.
func rid11RetiredUnitCounts(s *rid03NewmanSnapshot) {
	rid11BindingUnitCounts(s)
	for _, table := range []string{"registration_legacy_cluster_writer_identity", "registration_account_writer_switch", "clusters", "accounts", "groups", "access_bindings", "access_binding_subjects"} {
		rows, exists := s.Raw[table]
		if !exists {
			delete(s.Whole.Delivery, table)
			continue
		}
		keys := []string{}
		if len(rows) > 0 {
			for key := range rows[0] {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		hashes, _ := rid11BindingWholeHashes(rows)
		s.Whole.Delivery[table] = ridWholeTable{Columns: keys, Rows: hashes}
	}
}

func TestRID11BindingRestore_RetiredHistoryColdProductionShape(t *testing.T) {
	a, b, facts := rid11RetiredBindingFixture(t)
	require.True(t, rid11BindingUnitAccepted(a, b, facts))
	p, ok := rid11BuildBindingRestore(a, facts, b.Whole.PrimaryStartedAt)
	require.True(t, ok)
	require.Len(t, p.Policy.Members, 3)
	require.Len(t, p.Policy.Ledger, 15)
	require.Len(t, p.Policy.DirectTuples, 3)
	for member := range p.Desired {
		require.NotEqual(t, "acb9e920fb038c7e4f74", member.Binding)
	}
}

func TestRID11BindingRestore_RetiredHistoryConverged(t *testing.T) {
	_, b, facts := rid11RetiredBindingFixture(t)
	a := b
	b.Whole.PrimaryStartedAt = b.Whole.PrimaryFinishedAt.Add(time.Second)
	b.Whole.PrimaryFinishedAt = b.Whole.PrimaryStartedAt.Add(time.Second)
	require.True(t, rid11BindingUnitAccepted(a, b, facts))
	p, ok := rid11BuildBindingRestore(a, facts, b.Whole.PrimaryStartedAt)
	require.True(t, ok)
	require.Empty(t, p.Policy.Members)
	require.Empty(t, p.Policy.Ledger)
}

// Та же immutable assignment сохраняет ownership при ином ID строки;
// сохранённый original_binding_id остаётся исходным свидетельством lineage.
func TestRID11BindingRestore_RetiredHistoryOwnedReplacementID(t *testing.T) {
	a, b, facts := rid11RetiredBindingFixture(t)
	for _, snapshot := range []*rid03NewmanSnapshot{&a, &b} {
		snapshot.Raw["access_bindings"][1]["id"] = json.RawMessage(`"acbOWNED"`)
		snapshot.Raw["access_binding_subjects"][1]["binding_id"] = json.RawMessage(`"acbOWNED"`)
		rows := snapshot.Raw["access_binding_emitted_tuples"]
		rows[len(rows)-1]["binding_id"] = json.RawMessage(`"acbOWNED"`)
		rid11RetiredUnitCounts(snapshot)
	}
	require.True(t, rid11BindingUnitAccepted(a, b, facts))
}

func TestRID11BindingRestore_RetiredHistoryRejectBefore(t *testing.T) {
	cases := []struct {
		name   string
		change func(*rid03NewmanSnapshot)
	}{
		{"additional-foreign-revoked", func(s *rid03NewmanSnapshot) {
			row := rid11RestoreClone(s.Raw["access_bindings"][1])
			row["id"] = json.RawMessage(`"acbFOREIGN"`)
			row["subject_id"] = json.RawMessage(`"grp00001"`)
			s.Raw["access_bindings"] = append(s.Raw["access_bindings"], row)
			subject := rid11RestoreClone(s.Raw["access_binding_subjects"][1])
			subject["binding_id"] = json.RawMessage(`"acbFOREIGN"`)
			subject["subject_id"] = json.RawMessage(`"grp00001"`)
			s.Raw["access_binding_subjects"] = append(s.Raw["access_binding_subjects"], subject)
		}},
		{"retired-before-member", func(s *rid03NewmanSnapshot) {
			row := rid11RestoreClone(s.Raw["access_binding_target_members"][0])
			row["binding_id"] = json.RawMessage(`"acb9e920fb038c7e4f74"`)
			s.Raw["access_binding_target_members"] = append(s.Raw["access_binding_target_members"], row)
		}},
		{"null-switched-clock", func(s *rid03NewmanSnapshot) {
			s.Raw["registration_account_writer_switch"][0]["switched_at"] = json.RawMessage(`null`)
		}},
		{"second-owned-binding", func(s *rid03NewmanSnapshot) {
			row := rid11RestoreClone(s.Raw["access_bindings"][1])
			row["id"] = json.RawMessage(`"acbSECOND"`)
			s.Raw["access_bindings"] = append(s.Raw["access_bindings"], row)
		}},
		{"foreign-binding", func(s *rid03NewmanSnapshot) {
			s.Raw["access_bindings"][1]["subject_id"] = json.RawMessage(`"grpOTHER"`)
		}},
		{"foreign-identity", func(s *rid03NewmanSnapshot) {
			s.Raw["registration_legacy_cluster_writer_identity"][0]["original_binding_id"] = json.RawMessage(`"acbOTHER"`)
		}},
		{"foreign-group-account", func(s *rid03NewmanSnapshot) { s.Raw["groups"][1]["account_id"] = json.RawMessage(`"acc00001"`) }},
		{"foreign-anchor", func(s *rid03NewmanSnapshot) { s.Raw["clusters"][0]["id"] = json.RawMessage(`"cluster_other"`) }},
		{"missing-identity", func(s *rid03NewmanSnapshot) { delete(s.Raw, "registration_legacy_cluster_writer_identity") }},
		{"duplicate-identity", func(s *rid03NewmanSnapshot) {
			s.Raw["registration_legacy_cluster_writer_identity"] = append(s.Raw["registration_legacy_cluster_writer_identity"], rid11RestoreClone(s.Raw["registration_legacy_cluster_writer_identity"][0]))
		}},
		{"missing-switch", func(s *rid03NewmanSnapshot) { delete(s.Raw, "registration_account_writer_switch") }},
		{"wrong-actor", func(s *rid03NewmanSnapshot) {
			s.Raw["access_bindings"][1]["revoked_by_user_id"] = json.RawMessage(`"system:other"`)
		}},
		{"wrong-reason", func(s *rid03NewmanSnapshot) {
			s.Raw["access_bindings"][1]["revocation_reason"] = json.RawMessage(`"EXPIRED"`)
		}},
		{"wrong-subject", func(s *rid03NewmanSnapshot) { s.Raw["access_bindings"][1]["subject_type"] = json.RawMessage(`"user"`) }},
		{"wrong-resource", func(s *rid03NewmanSnapshot) {
			s.Raw["access_bindings"][1]["resource_type"] = json.RawMessage(`"account"`)
		}},
		{"role-backed", func(s *rid03NewmanSnapshot) { s.Raw["access_bindings"][1]["role_id"] = json.RawMessage(`"rol00001"`) }},
		{"non-system", func(s *rid03NewmanSnapshot) { s.Raw["access_bindings"][1]["is_system"] = json.RawMessage(`false`) }},
		{"wrong-target", func(s *rid03NewmanSnapshot) { s.Raw["access_bindings"][1]["target"] = json.RawMessage(`{}`) }},
		{"null-revoked-clock", func(s *rid03NewmanSnapshot) { s.Raw["access_bindings"][1]["revoked_at"] = json.RawMessage(`null`) }},
		{"future-revoked-clock", func(s *rid03NewmanSnapshot) {
			s.Raw["access_bindings"][1]["revoked_at"], _ = json.Marshal(s.Whole.PrimaryFinishedAt.Add(time.Second))
		}},
		{"revoked-before-switch", func(s *rid03NewmanSnapshot) {
			s.Raw["access_bindings"][1]["revoked_at"], _ = json.Marshal(s.Whole.PrimaryStartedAt.Add(-4 * time.Minute))
		}},
		{"null-retired-clock", func(s *rid03NewmanSnapshot) {
			s.Raw["registration_account_writer_switch"][0]["cluster_writer_retired_at"] = json.RawMessage(`null`)
		}},
		{"future-retired-clock", func(s *rid03NewmanSnapshot) {
			s.Raw["registration_account_writer_switch"][0]["cluster_writer_retired_at"], _ = json.Marshal(s.Whole.PrimaryFinishedAt.Add(time.Second))
		}},
		{"removed-history", func(s *rid03NewmanSnapshot) { s.Raw["access_bindings"] = s.Raw["access_bindings"][:1] }},
		{"removed-subject", func(s *rid03NewmanSnapshot) { s.Raw["access_binding_subjects"] = s.Raw["access_binding_subjects"][:1] }},
		{"removed-ledger", func(s *rid03NewmanSnapshot) {
			rows := s.Raw["access_binding_emitted_tuples"]
			s.Raw["access_binding_emitted_tuples"] = rows[:len(rows)-1]
		}},
		{"wrong-ledger", func(s *rid03NewmanSnapshot) {
			rows := s.Raw["access_binding_emitted_tuples"]
			rows[len(rows)-1]["relation"] = json.RawMessage(`"admin"`)
		}},
		{"reactivated", func(s *rid03NewmanSnapshot) { s.Raw["access_bindings"][1]["status"] = json.RawMessage(`"ACTIVE"`) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, _, facts := rid11RetiredBindingFixture(t)
			tc.change(&a)
			rid11RetiredUnitCounts(&a)
			_, ok := rid11BuildBindingRestore(a, facts, a.Whole.PrimaryFinishedAt.Add(time.Second))
			require.False(t, ok)
		})
	}
}

func TestRID11BindingRestore_RetiredHistoryRejectAfter(t *testing.T) {
	cases := []struct {
		name   string
		change func(*rid03NewmanSnapshot)
	}{
		{"changed-history-labels", func(s *rid03NewmanSnapshot) {
			s.Raw["access_bindings"][1]["labels"] = json.RawMessage(`{"changed":"history"}`)
		}},
		{"removed-history", func(s *rid03NewmanSnapshot) { s.Raw["access_bindings"] = s.Raw["access_bindings"][:1] }},
		{"changed-subject", func(s *rid03NewmanSnapshot) { s.Raw["access_binding_subjects"][1]["ordinal"] = json.RawMessage(`1`) }},
		{"removed-ledger", func(s *rid03NewmanSnapshot) {
			rows := s.Raw["access_binding_emitted_tuples"]
			s.Raw["access_binding_emitted_tuples"] = rows[:len(rows)-1]
		}},
		{"changed-ledger", func(s *rid03NewmanSnapshot) {
			rows := s.Raw["access_binding_emitted_tuples"]
			rows[len(rows)-1]["object"] = json.RawMessage(`"cluster:other"`)
		}},
		{"new-retired-member", func(s *rid03NewmanSnapshot) {
			row := rid11RestoreClone(s.Raw["access_binding_target_members"][0])
			row["binding_id"] = json.RawMessage(`"acb9e920fb038c7e4f74"`)
			s.Raw["access_binding_target_members"] = append(s.Raw["access_binding_target_members"], row)
		}},
		{"new-retired-ledger", func(s *rid03NewmanSnapshot) {
			row := rid11RestoreClone(s.Raw["access_binding_emitted_tuples"][0])
			row["binding_id"] = json.RawMessage(`"acb9e920fb038c7e4f74"`)
			s.Raw["access_binding_emitted_tuples"] = append(s.Raw["access_binding_emitted_tuples"], row)
		}},
		{"new-retired-fact", func(s *rid03NewmanSnapshot) {
			clock := s.Whole.PrimaryStartedAt.Add(-time.Millisecond)
			s.Raw["relation_fact"] = append(s.Raw["relation_fact"], rid11RestoreRow(map[string]any{"subject": "group:grp258e6bbe9bbe45568#member", "relation": "fga_writer", "object_type": "cluster", "object_id": "cluster_fixture", "source_version": clock, "created_at": clock, "condition_name": "", "condition_params": map[string]string{}}))
		}},
		{"new-retired-outbox", func(s *rid03NewmanSnapshot) {
			s.Raw["fga_outbox"] = append(s.Raw["fga_outbox"], rid11RestoreRow(map[string]any{"id": 99, "event_type": "fga.tuple.write", "created_at": s.Whole.PrimaryStartedAt.Add(-time.Millisecond), "payload": map[string]any{"user": "group:grp258e6bbe9bbe45568#member", "object": "cluster:cluster_fixture", "relation": "fga_writer"}}))
		}},
		{"incomplete-members", func(s *rid03NewmanSnapshot) {
			rows := s.Raw["access_binding_target_members"]
			for index, row := range rows {
				if rid03S(row, "object_type") == "iam.serviceAccount" && rid03S(row, "object_id") == "sva00002" {
					s.Raw["access_binding_target_members"] = append(rows[:index], rows[index+1:]...)
					return
				}
			}
		}},
		{"incomplete-new-ledger", func(s *rid03NewmanSnapshot) {
			rows := s.Raw["access_binding_emitted_tuples"]
			s.Raw["access_binding_emitted_tuples"] = append(rows[:10], rows[11:]...)
		}},
		{"incomplete-producers", func(s *rid03NewmanSnapshot) { s.Raw["fga_outbox"] = s.Raw["fga_outbox"][:2] }},
		{"incomplete-facts", func(s *rid03NewmanSnapshot) { s.Raw["relation_fact"] = s.Raw["relation_fact"][:2] }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b, facts := rid11RetiredBindingFixture(t)
			tc.change(&b)
			rid11RetiredUnitCounts(&b)
			require.False(t, rid11BindingUnitAccepted(a, b, facts))
		})
	}
}

func TestRID11BindingRestore_RetiredHistoryRejectUnboundWitness(t *testing.T) {
	a, b, facts := rid11RetiredBindingFixture(t)
	whole := a.Whole.Delivery["registration_legacy_cluster_writer_identity"]
	whole.Rows = []string{"not-the-primary-row-hash"}
	a.Whole.Delivery["registration_legacy_cluster_writer_identity"] = whole
	require.False(t, rid11BindingUnitAccepted(a, b, facts))
}
