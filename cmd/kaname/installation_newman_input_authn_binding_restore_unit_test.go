// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
)

// Независимый пример формы обычного producer: одно старое owner-покрытие,
// две новые SA и одна группа. Ожидаемые строки заданы явно, не взяты из oracle.
func rid11BindingFixture(t *testing.T) (rid03NewmanSnapshot, rid03NewmanSnapshot, *catalog.Facts) {
	t.Helper()
	at := time.Date(2026, 11, 3, 21, 50, 40, 0, time.UTC)
	clock := at.Add(2*time.Second + 123000*time.Nanosecond)
	facts, err := catalog.NewFacts(catalog.Halves{Live: catalog.Rows{Modules: []string{"iam"}, Resources: []catalog.ResourceRow{{Module: "iam", Resource: "account", ObjectType: "account"}, {Module: "iam", Resource: "serviceAccount", ObjectType: "iam_service_account"}, {Module: "iam", Resource: "group", ObjectType: "iam_group"}}, Verbs: []catalog.VerbRow{
		{Module: "iam", Resource: "account", Verb: "get", PerObject: true}, {Module: "iam", Resource: "account", Verb: "list", PerObject: true}, {Module: "iam", Resource: "account", Verb: "update", PerObject: true}, {Module: "iam", Resource: "account", Verb: "delete", PerObject: true},
		{Module: "iam", Resource: "serviceAccount", Verb: "get", PerObject: true}, {Module: "iam", Resource: "serviceAccount", Verb: "list", PerObject: true}, {Module: "iam", Resource: "serviceAccount", Verb: "update", PerObject: true}, {Module: "iam", Resource: "serviceAccount", Verb: "delete", PerObject: true},
		{Module: "iam", Resource: "group", Verb: "get", PerObject: true}, {Module: "iam", Resource: "group", Verb: "list", PerObject: true}, {Module: "iam", Resource: "group", Verb: "update", PerObject: true}, {Module: "iam", Resource: "group", Verb: "delete", PerObject: true}}}})
	require.True(t, err == nil)
	rules := domain.Rules{{Module: "iam", Resources: []string{"account", "serviceAccount", "group"}, Verbs: []string{"*"}}}
	encoded, err := domain.EncodeRules(rules)
	require.True(t, err == nil)
	selectors := rules.MaterializingSelectorsInScope(domain.ScopeAccount)
	require.Len(t, selectors, 1)
	fp := selectors[0].RuleFP
	a := rid03NewmanSnapshot{Raw: map[string][]rid09PrimaryRow{}, Facts: facts, Whole: ridWholeDeliverySnapshot{PrimaryStartedAt: at, PrimaryFinishedAt: at.Add(time.Second), Delivery: map[string]ridWholeTable{}, Bookkeeping: map[string]ridWholeTable{}}}
	for _, table := range []string{"accounts", "projects", "groups", "service_accounts", "users", "roles", "access_bindings", "access_binding_subjects", "memberships", "resource_mirror", "resource_parent_edge", "grant_delegations", "access_binding_target_members", "access_binding_emitted_tuples", "fga_outbox", "relation_fact", "operations"} {
		a.Raw[table] = []rid09PrimaryRow{}
	}
	a.Raw["accounts"] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"id": "acc00001"})}
	a.Raw["users"] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"id": "usr00001"})}
	a.Raw["memberships"] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"user_id": "usr00001", "account_id": "acc00001"})}
	for _, id := range []string{"sva00001", "sva00002", "sva00003"} {
		a.Raw["service_accounts"] = append(a.Raw["service_accounts"], rid11RestoreRow(map[string]any{"id": id, "account_id": "acc00001"}))
	}
	a.Raw["groups"] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"id": "grp00001", "account_id": "acc00001"})}
	role := rid11RestoreRow(map[string]any{"id": "rol00001", "is_system": true, "owner_module": nil, "live": true, "account_id": nil, "project_id": nil})
	role["rules"] = encoded
	a.Raw["roles"] = []rid09PrimaryRow{role}
	a.Raw["access_bindings"] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"id": "acb00001", "role_id": "rol00001", "subject_type": "user", "subject_id": "usr00001", "resource_type": "account", "resource_id": "acc00001", "scope": 2, "status": "ACTIVE", "expires_at": nil, "revoked_at": nil, "narrowed_at": nil, "delegation_id": nil, "target": map[string]any{"allInScope": true}, "target_digest": (domain.AccessTarget{AllInScope: true}).Digest()})}
	a.Raw["access_binding_subjects"] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"binding_id": "acb00001", "subject_type": "user", "subject_id": "usr00001", "ordinal": 0, "resource_type": "account", "resource_id": "acc00001"})}
	member := func(typ, id, rule string, tm time.Time) rid09PrimaryRow {
		return rid11RestoreRow(map[string]any{"binding_id": "acb00001", "role_id": "rol00001", "rule_fp": rule, "object_type": typ, "object_id": id, "verification_status": "ACTIVE", "live": true, "created_at": tm, "updated_at": tm})
	}
	a.Raw["access_binding_target_members"] = rid11BindingSortMembers([]rid09PrimaryRow{member("iam.account", "acc00001", fp, at.Add(-time.Hour)), member("iam.account", "acc00001", "scope_self", at.Add(-time.Hour)), member("iam.serviceAccount", "sva00001", fp, at.Add(-time.Hour))})
	for _, o := range []struct{ typ, model, id string }{{"iam.account", "account", "acc00001"}, {"iam.serviceAccount", "iam_service_account", "sva00001"}} {
		for _, rel := range []string{"admin", "v_delete", "v_get", "v_list", "v_update"} {
			a.Raw["access_binding_emitted_tuples"] = append(a.Raw["access_binding_emitted_tuples"], rid11RestoreRow(map[string]any{"binding_id": "acb00001", "source": "member", "member_object_type": o.typ, "member_object_id": o.id, "fga_user": "user:usr00001", "relation": rel, "object": o.model + ":" + o.id}))
		}
	}
	oldValue, ok := rid05CanonicalMaterializedAt(at.Add(-time.Hour))
	require.True(t, ok)
	a.Projection = rid09NewmanProjection{Bindings: []map[string]any{{"id": "acb00001", "createdAt": "unchanged", "materializedAt": oldValue, "unknown": "preserved"}}, Materialization: rid03EvidenceHash(a.Raw["access_binding_target_members"])}
	b := a
	b.Raw = map[string][]rid09PrimaryRow{}
	for k, rows := range a.Raw {
		b.Raw[k] = []rid09PrimaryRow{}
		for _, r := range rows {
			b.Raw[k] = append(b.Raw[k], rid11RestoreClone(r))
		}
	}
	b.Whole = a.Whole
	b.Whole.PrimaryStartedAt = at.Add(3 * time.Second)
	b.Whole.PrimaryFinishedAt = at.Add(4 * time.Second)
	b.Whole.Delivery = map[string]ridWholeTable{}
	relations := []string{"admin", "v_delete", "v_get", "v_list", "v_update"}
	for i, o := range []struct{ typ, model, id string }{{"iam.serviceAccount", "iam_service_account", "sva00002"}, {"iam.serviceAccount", "iam_service_account", "sva00003"}, {"iam.group", "iam_group", "grp00001"}} {
		b.Raw["access_binding_target_members"] = append(b.Raw["access_binding_target_members"], member(o.typ, o.id, fp, clock))
		for _, rel := range relations {
			b.Raw["access_binding_emitted_tuples"] = append(b.Raw["access_binding_emitted_tuples"], rid11RestoreRow(map[string]any{"binding_id": "acb00001", "source": "member", "member_object_type": o.typ, "member_object_id": o.id, "fga_user": "user:usr00001", "relation": rel, "object": o.model + ":" + o.id}))
		}
		b.Raw["fga_outbox"] = append(b.Raw["fga_outbox"], rid11RestoreRow(map[string]any{"id": i + 1, "event_type": "fga.tuple.write", "created_at": clock, "payload": map[string]any{"user": "user:usr00001", "object": o.model + ":" + o.id, "relation": "admin", "relations": relations}}))
		b.Raw["relation_fact"] = append(b.Raw["relation_fact"], rid11RestoreRow(map[string]any{"subject": "user:usr00001", "relation": "admin", "object_type": o.model, "object_id": o.id, "source_version": clock, "created_at": clock, "condition_name": "", "condition_params": map[string]string{}}))
	}
	b.Raw["access_binding_target_members"] = rid11BindingSortMembers(b.Raw["access_binding_target_members"])
	value, ok := rid05CanonicalMaterializedAt(clock)
	require.True(t, ok)
	b.Projection = a.Projection
	b.Projection.Bindings = []map[string]any{{"id": "acb00001", "createdAt": "unchanged", "materializedAt": value, "unknown": "preserved"}}
	b.Projection.Materialization = rid03EvidenceHash(b.Raw["access_binding_target_members"])
	rid11BindingUnitCounts(&a)
	rid11BindingUnitCounts(&b)
	return a, b, facts
}
func rid11BindingUnitCounts(s *rid03NewmanSnapshot) {
	for table, keys := range rid11BindingSchemas {
		hashes, _ := rid11BindingWholeHashes(s.Raw[table])
		s.Whole.Delivery[table] = ridWholeTable{Columns: append([]string(nil), keys...), Rows: hashes}
	}
}

func rid11BindingUnitAccepted(a, b rid03NewmanSnapshot, facts *catalog.Facts) bool {
	p, ok := rid11BuildBindingRestore(a, facts, b.Whole.PrimaryStartedAt)
	if !ok {
		return false
	}
	proof, ok := rid11ValidateBindingRestore(a, b, p)
	if !ok {
		return false
	}
	expected, ok := rid11BindingProjection(a, proof.Raw["access_binding_target_members"])
	raw := map[string][]rid09PrimaryRow{}
	for k, v := range a.Raw {
		raw[k] = v
	}
	for k, v := range proof.Raw {
		raw[k] = v
	}
	return ok && rid11RestoreRawValid(rid11RestorePlan{Raw: raw}, a, b, proof) && reflect.DeepEqual(expected, b.Projection)
}
func rid11BindingReject(t *testing.T, change func(*rid03NewmanSnapshot, *rid03NewmanSnapshot)) {
	t.Helper()
	a, b, f := rid11BindingFixture(t)
	change(&a, &b)
	rid11BindingUnitCounts(&a)
	rid11BindingUnitCounts(&b)
	require.False(t, rid11BindingUnitAccepted(a, b, f), "замкнутая проверка восстановления должна отказать")
}
func TestRID11BindingRestore_ThreeObjectsProductionShape(t *testing.T) {
	a, b, f := rid11BindingFixture(t)
	require.True(t, rid11BindingUnitAccepted(a, b, f))
	p, ok := rid11BuildBindingRestore(a, f, b.Whole.PrimaryStartedAt)
	require.True(t, ok)
	require.Equal(t, 3, len(p.Policy.Members))
	require.Equal(t, 15, len(p.Policy.Ledger))
	require.Equal(t, 3, len(p.Policy.DirectTuples))
}
func TestRID11BindingRestore_RepeatedConvergedState(t *testing.T) {
	_, b, f := rid11BindingFixture(t)
	a := b
	b.Whole.PrimaryStartedAt = b.Whole.PrimaryFinishedAt.Add(time.Second)
	b.Whole.PrimaryFinishedAt = b.Whole.PrimaryStartedAt.Add(time.Second)
	require.True(t, rid11BindingUnitAccepted(a, b, f))
}
func TestRID11BindingRestore_TransportPartitionNotBusinessCount(t *testing.T) {
	a, b, f := rid11BindingFixture(t)
	r := rid11RestoreClone(b.Raw["fga_outbox"][0])
	r["id"] = json.RawMessage(`99`)
	b.Raw["fga_outbox"] = append(b.Raw["fga_outbox"], r)
	rid11BindingUnitCounts(&b)
	require.True(t, rid11BindingUnitAccepted(a, b, f))
}
func TestRID11BindingRestore_RejectWrongBinding(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["access_binding_target_members"][len(b.Raw["access_binding_target_members"])-1]["binding_id"] = json.RawMessage(`"acbOTHER"`)
	})
}
func TestRID11BindingRestore_RejectWrongRole(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["access_binding_target_members"][len(b.Raw["access_binding_target_members"])-1]["role_id"] = json.RawMessage(`"rolOTHER"`)
	})
}
func TestRID11BindingRestore_RejectWrongRuleFP(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["access_binding_target_members"][len(b.Raw["access_binding_target_members"])-1]["rule_fp"] = json.RawMessage(`"wrong"`)
	})
}
func TestRID11BindingRestore_RejectMemberStatus(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["access_binding_target_members"][len(b.Raw["access_binding_target_members"])-1]["verification_status"] = json.RawMessage(`"PENDING"`)
	})
}
func TestRID11BindingRestore_RejectMemberLive(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["access_binding_target_members"][len(b.Raw["access_binding_target_members"])-1]["live"] = json.RawMessage(`false`)
	})
}
func TestRID11BindingRestore_RejectBeforeForeignAccount(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		a.Raw["service_accounts"][1]["account_id"] = json.RawMessage(`"accFOREIGN"`)
	})
}
func TestRID11BindingRestore_RejectBeforeSubjectChanged(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		a.Raw["access_binding_subjects"][0]["subject_id"] = json.RawMessage(`"usrOTHER"`)
	})
}
func TestRID11BindingRestore_RejectBeforeUnknownUser(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) { a.Raw["users"] = nil })
}
func TestRID11BindingRestore_RejectBeforeTargetNarrowing(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		a.Raw["access_bindings"][0]["target"] = json.RawMessage(`{"resources":[]}`)
	})
}
func TestRID11BindingRestore_RejectBeforeExpired(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		a.Raw["access_bindings"][0]["expires_at"], _ = json.Marshal(a.Whole.PrimaryStartedAt)
	})
}
func TestRID11BindingRestore_RejectBeforeRevoked(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		a.Raw["access_bindings"][0]["revoked_at"], _ = json.Marshal(a.Whole.PrimaryStartedAt)
	})
}
func TestRID11BindingRestore_RejectBeforeMissingTable(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) { delete(a.Raw, "memberships") })
}
func TestRID11BindingRestore_RejectBeforeDuplicateIdentity(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		a.Raw["service_accounts"] = append(a.Raw["service_accounts"], rid11RestoreClone(a.Raw["service_accounts"][0]))
	})
}
func TestRID11BindingRestore_RejectExternalMirrorProfile(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		a.Raw["resource_mirror"] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"id": "external"})}
	})
}
func TestRID11BindingRestore_RejectAfterOnlyIdentity(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) { a.Raw["service_accounts"] = a.Raw["service_accounts"][:2] })
}
func TestRID11BindingRestore_RejectAdditionalBeforeObjectMissingAfter(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		a.Raw["service_accounts"] = append(a.Raw["service_accounts"], rid11RestoreRow(map[string]any{"id": "svaEXTRA", "account_id": "acc00001"}))
	})
}
func TestRID11BindingRestore_RejectExtraRelation(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["access_binding_emitted_tuples"][0]["relation"] = json.RawMessage(`"system_admin"`)
	})
}
func TestRID11BindingRestore_RejectMissingLedger(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["access_binding_emitted_tuples"] = b.Raw["access_binding_emitted_tuples"][:len(b.Raw["access_binding_emitted_tuples"])-1]
	})
}
func TestRID11BindingRestore_RejectLedgerSource(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["access_binding_emitted_tuples"][0]["source"] = json.RawMessage(`"binding"`)
	})
}
func TestRID11BindingRestore_RejectLedgerTypeDictionary(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["access_binding_emitted_tuples"][0]["member_object_type"] = json.RawMessage(`"iam_service_account"`)
	})
}
func TestRID11BindingRestore_RejectProducerMissing(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) { b.Raw["fga_outbox"] = b.Raw["fga_outbox"][:2] })
}
func TestRID11BindingRestore_RejectProducerExtraKey(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		var p map[string]any
		_ = json.Unmarshal(b.Raw["fga_outbox"][0]["payload"], &p)
		p["secret"] = "not-allowed"
		b.Raw["fga_outbox"][0]["payload"], _ = json.Marshal(p)
	})
}
func TestRID11BindingRestore_RejectProducerSubject(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		var p map[string]any
		_ = json.Unmarshal(b.Raw["fga_outbox"][0]["payload"], &p)
		p["user"] = "user:usrOTHER"
		b.Raw["fga_outbox"][0]["payload"], _ = json.Marshal(p)
	})
}
func TestRID11BindingRestore_RejectProducerEcho(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		var p map[string]any
		_ = json.Unmarshal(b.Raw["fga_outbox"][0]["payload"], &p)
		p["relation"] = "v_get"
		b.Raw["fga_outbox"][0]["payload"], _ = json.Marshal(p)
	})
}
func TestRID11BindingRestore_RejectProducerFutureClock(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["fga_outbox"][0]["created_at"], _ = json.Marshal(b.Whole.PrimaryStartedAt.Add(time.Second))
	})
}
func TestRID11BindingRestore_RejectProducerPastClock(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["fga_outbox"][0]["created_at"], _ = json.Marshal(a.Whole.PrimaryStartedAt)
	})
}
func TestRID11BindingRestore_RejectProducerDuplicateID(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) { b.Raw["fga_outbox"][1]["id"] = b.Raw["fga_outbox"][0]["id"] })
}
func TestRID11BindingRestore_RejectFactVersion(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["relation_fact"][0]["source_version"], _ = json.Marshal(a.Whole.PrimaryFinishedAt)
	})
}
func TestRID11BindingRestore_RejectFactCondition(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["relation_fact"][0]["condition_name"] = json.RawMessage(`"conditional"`)
	})
}
func TestRID11BindingRestore_RejectFactConditionParameters(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["relation_fact"][0]["condition_params"] = json.RawMessage(`{"x":"y"}`)
	})
}
func TestRID11BindingRestore_RejectFactMissing(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) { b.Raw["relation_fact"] = b.Raw["relation_fact"][:2] })
}
func TestRID11BindingRestore_RejectPhysicalVerbFact(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		r := rid11RestoreClone(b.Raw["relation_fact"][0])
		r["relation"] = json.RawMessage(`"v_get"`)
		b.Raw["relation_fact"] = append(b.Raw["relation_fact"], r)
	})
}
func TestRID11BindingRestore_RejectOldMemberChanged(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		for _, r := range b.Raw["access_binding_target_members"] {
			if rid03S(r, "rule_fp") == "scope_self" {
				r["updated_at"], _ = json.Marshal(b.Whole.PrimaryStartedAt)
			}
		}
	})
}
func TestRID11BindingRestore_RejectOldMemberDeleted(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["access_binding_target_members"] = b.Raw["access_binding_target_members"][1:]
	})
}
func TestRID11BindingRestore_RejectUnknownMemberColumn(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["access_binding_target_members"][0]["future"] = json.RawMessage(`1`)
	})
}
func TestRID11BindingRestore_RejectMaterializationDigest(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) { b.Projection.Materialization = "wrong" })
}
func TestRID11BindingRestore_RejectMaterializedAt(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) { b.Projection.Bindings[0]["materializedAt"] = "2026-11-03T21:50:41Z" })
}
func TestRID11BindingRestore_RejectProjectionUnknownField(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) { b.Projection.Bindings[0]["unknown"] = "changed" })
}
func TestRID11BindingRestore_RejectBeforeDigestFence(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) { a.Projection.Materialization = "wrong" })
}
func TestRID11BindingRestore_RejectBeforeProjectionClockFence(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) { a.Projection.Bindings[0]["materializedAt"] = nil })
}
func TestRID11BindingRestore_RejectZeroLower(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) { a.Whole.PrimaryFinishedAt = time.Time{} })
}
func TestRID11BindingRestore_RejectReversedClocks(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) { b.Whole.PrimaryStartedAt = a.Whole.PrimaryStartedAt })
}

func TestRID11BindingRestore_RejectNewOperation(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["operations"] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"id": "op-new"})}
	})
}
func TestRID11BindingRestore_RejectChangedOldOperation(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		a.Raw["operations"] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"id": "op-old", "result": "before"})}
		b.Raw["operations"] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"id": "op-old", "result": "after"})}
	})
}
func TestRID11BindingRestore_RejectBusinessAudit(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.BusinessAudit = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"id": "event"})}
	})
}
func TestRID11BindingRestore_RejectNewGD(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["grant_delegations"] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"id": "gdl-new"})}
	})
}
func TestRID11BindingRestore_RejectOldBindingChanged(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) { b.Raw["access_bindings"][0]["status"] = json.RawMessage(`"REVOKED"`) })
}
func TestRID11BindingRestore_RejectOldRoleChanged(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) { b.Raw["roles"][0]["live"] = json.RawMessage(`false`) })
}
func TestRID11BindingRestore_RejectUnknownRawTable(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) { b.Raw["unknown"] = []rid09PrimaryRow{} })
}
func TestRID11BindingRestore_RejectMissingWholeTable(t *testing.T) {
	a, b, f := rid11BindingFixture(t)
	delete(b.Whole.Delivery, "fga_outbox")
	require.False(t, rid11BindingUnitAccepted(a, b, f))
}
func TestRID11BindingRestore_RejectUnknownWholeColumn(t *testing.T) {
	a, b, f := rid11BindingFixture(t)
	v := b.Whole.Delivery["fga_outbox"]
	v.Columns = append(v.Columns, "future")
	b.Whole.Delivery["fga_outbox"] = v
	require.False(t, rid11BindingUnitAccepted(a, b, f))
}
func TestRID11BindingRestore_RejectWholeCountMismatch(t *testing.T) {
	a, b, f := rid11BindingFixture(t)
	v := b.Whole.Delivery["fga_outbox"]
	v.Rows = v.Rows[:2]
	b.Whole.Delivery["fga_outbox"] = v
	require.False(t, rid11BindingUnitAccepted(a, b, f))
}
func TestRID11BindingRestore_RejectWrongCatalogType(t *testing.T) {
	a, b, _ := rid11BindingFixture(t)
	f, err := catalog.NewFacts(catalog.Halves{Live: catalog.Rows{Modules: []string{"iam"}, Resources: []catalog.ResourceRow{{Module: "iam", Resource: "serviceAccount", ObjectType: "wrong_service_account"}}, Verbs: []catalog.VerbRow{{Module: "iam", Resource: "serviceAccount", Verb: "get", PerObject: true}}}})
	require.True(t, err == nil)
	require.False(t, rid11BindingUnitAccepted(a, b, f))
}
func TestRID11BindingRestore_RejectMemberClockWithoutProducer(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		for _, r := range b.Raw["access_binding_target_members"] {
			if rid03S(r, "object_id") == "sva00002" {
				r["created_at"], _ = json.Marshal(b.Whole.PrimaryStartedAt)
				r["updated_at"] = r["created_at"]
			}
		}
	})
}
func TestRID11BindingRestore_RejectProducerEvent(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["fga_outbox"][0]["event_type"] = json.RawMessage(`"fga.tuple.delete"`)
	})
}
func TestRID11BindingRestore_RejectFactCreationClock(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["relation_fact"][0]["created_at"], _ = json.Marshal(b.Whole.PrimaryStartedAt)
	})
}
func TestRID11BindingRestore_RejectMemberDuplicateCoordinate(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["access_binding_target_members"] = append(b.Raw["access_binding_target_members"], rid11RestoreClone(b.Raw["access_binding_target_members"][0]))
	})
}
func TestRID11BindingRestore_RejectLedgerDuplicateCoordinate(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["access_binding_emitted_tuples"] = append(b.Raw["access_binding_emitted_tuples"], rid11RestoreClone(b.Raw["access_binding_emitted_tuples"][0]))
	})
}
func TestRID11BindingRestore_RejectFactDuplicateCoordinate(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		b.Raw["relation_fact"] = append(b.Raw["relation_fact"], rid11RestoreClone(b.Raw["relation_fact"][0]))
	})
}

func TestRID11BindingRestore_RejectDanglingSubjectReference(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		r := rid11RestoreClone(a.Raw["access_binding_subjects"][0])
		r["binding_id"] = json.RawMessage(`"acbUNKNOWN"`)
		a.Raw["access_binding_subjects"] = append(a.Raw["access_binding_subjects"], r)
	})
}
func TestRID11BindingRestore_RejectMissingSubjectReference(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) { a.Raw["access_binding_subjects"] = nil })
}
func TestRID11BindingRestore_RejectMissingOldScopeSelf(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		rows := []rid09PrimaryRow{}
		for _, r := range a.Raw["access_binding_target_members"] {
			if rid03S(r, "rule_fp") != "scope_self" {
				rows = append(rows, r)
			}
		}
		a.Raw["access_binding_target_members"] = rows
	})
}
func TestRID11BindingRestore_CanonicalMemberOrderHasNoIDShortcut(t *testing.T) {
	a, b, _ := rid11BindingFixture(t)
	rows := append([]rid09PrimaryRow{}, b.Raw["access_binding_target_members"]...)
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	require.Equal(t, rid03EvidenceHash(b.Raw["access_binding_target_members"]), rid03EvidenceHash(rid11BindingSortMembers(rows)))
	expected, ok := rid11BindingProjection(a, rows)
	require.True(t, ok)
	require.True(t, reflect.DeepEqual(expected, b.Projection))
}

func TestRID11BindingRestore_RejectWholeHashMismatch(t *testing.T) {
	a, b, f := rid11BindingFixture(t)
	v := b.Whole.Delivery["fga_outbox"]
	v.Rows = append([]string(nil), v.Rows...)
	v.Rows[0] = "forged"
	b.Whole.Delivery["fga_outbox"] = v
	require.False(t, rid11BindingUnitAccepted(a, b, f))
}
func TestRID11BindingRestore_JSONBTextContract(t *testing.T) {
	raw := json.RawMessage(`{"long_key":["user:usr00001",null],"id":12,"live":true,"map":{"zz":1,"a":"value"}}`)
	value, ok := rid11CoordinateDecode(raw)
	require.True(t, ok)
	text, ok := rid11BindingJSONB(value)
	require.True(t, ok)
	require.Equal(t, `{"id": 12, "map": {"a": "value", "zz": 1}, "live": true, "long_key": ["user:usr00001", null]}`, text)
}

func TestRID11BindingRestore_RejectBeforeIncompleteOldLedger(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		a.Raw["access_binding_emitted_tuples"] = a.Raw["access_binding_emitted_tuples"][1:]
	})
}
func TestRID11BindingRestore_RejectBeforeStaleOldMember(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		r := rid11RestoreClone(a.Raw["access_binding_target_members"][0])
		r["object_id"] = json.RawMessage(`"svaSTALE"`)
		a.Raw["access_binding_target_members"] = append(a.Raw["access_binding_target_members"], r)
	})
}

func TestRID11BindingRestore_RejectBeforeFutureMemberClock(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		a.Raw["access_binding_target_members"][0]["updated_at"], _ = json.Marshal(b.Whole.PrimaryFinishedAt)
	})
}
func TestRID11BindingRestore_RejectBeforeZeroMemberClock(t *testing.T) {
	rid11BindingReject(t, func(a, b *rid03NewmanSnapshot) {
		a.Raw["access_binding_target_members"][0]["created_at"], _ = json.Marshal(time.Time{})
	})
}

func TestRID11BindingRestore_InventoryRetainsRetiredRoleTarget(t *testing.T) {
	a, _, _ := rid11BindingFixture(t)
	a.Raw["roles"] = append(a.Raw["roles"], rid11RestoreRow(map[string]any{"id": "rol00002", "live": false, "account_id": "acc00001", "project_id": nil}))
	objects, ok := rid11BindingInventory(a.Raw)
	require.True(t, ok)
	require.Contains(t, objects, rid11BindingObject{"iam.role", "rol00002", "acc00001"})
}

func TestRID11BindingRestore_RejectTwoSidedOmittedRetiredRoleTarget(t *testing.T) {
	a, b, _ := rid11BindingFixture(t)
	// Политика выбирает role на обеих сторонах; добавочный объект не является
	// роли полномочий. Её неизменная строка не может скрыть пропущенное покрытие.
	rows := catalog.Rows{Modules: []string{"iam"}}
	for _, resource := range []struct{ name, model string }{{"account", "account"}, {"serviceAccount", "iam_service_account"}, {"group", "iam_group"}, {"role", "iam_role"}} {
		rows.Resources = append(rows.Resources, catalog.ResourceRow{Module: "iam", Resource: resource.name, ObjectType: resource.model})
		for _, verb := range []string{"get", "list", "update", "delete"} {
			rows.Verbs = append(rows.Verbs, catalog.VerbRow{Module: "iam", Resource: resource.name, Verb: verb, PerObject: true})
		}
	}
	facts, err := catalog.NewFacts(catalog.Halves{Live: rows})
	require.True(t, err == nil)
	rules := domain.Rules{{Module: "iam", Resources: []string{"account", "serviceAccount", "group", "role"}, Verbs: []string{"*"}}}
	encoded, err := domain.EncodeRules(rules)
	require.True(t, err == nil)
	selectors := rules.MaterializingSelectorsInScope(domain.ScopeAccount)
	require.Equal(t, 1, len(selectors))
	for _, snapshot := range []*rid03NewmanSnapshot{&a, &b} {
		snapshot.Raw["roles"][0]["rules"] = append(json.RawMessage(nil), encoded...)
		for _, member := range snapshot.Raw["access_binding_target_members"] {
			if rid03S(member, "rule_fp") != "scope_self" {
				member["rule_fp"], err = json.Marshal(selectors[0].RuleFP)
				require.True(t, err == nil)
			}
		}
		snapshot.Raw["access_binding_target_members"] = rid11BindingSortMembers(snapshot.Raw["access_binding_target_members"])
		snapshot.Projection.Materialization = rid03EvidenceHash(snapshot.Raw["access_binding_target_members"])
		rid11BindingUnitCounts(snapshot)
	}
	// Та же расширенная политика без пропущенного объекта должна оставаться законной.
	require.True(t, rid11BindingUnitAccepted(a, b, facts))
	retired := rid11RestoreRow(map[string]any{"id": "rol00002", "live": false, "account_id": "acc00001", "project_id": nil})
	a.Raw["roles"] = append(a.Raw["roles"], rid11RestoreClone(retired))
	b.Raw["roles"] = append(b.Raw["roles"], rid11RestoreClone(retired))
	require.True(t, reflect.DeepEqual(a.Raw["roles"], b.Raw["roles"]))
	require.False(t, rid11BindingUnitAccepted(a, b, facts), "неизменный retired target не разрешает неполную материализацию")
}
