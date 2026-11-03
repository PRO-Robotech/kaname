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
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
)

func rid11RestoreFixture(t *testing.T) (rid03NewmanSnapshot, rid03NewmanSnapshot, rid11RestorePlan) {
	t.Helper()
	at := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	facts, err := catalog.NewFacts(catalog.Halves{Live: catalog.Rows{Modules: []string{"test"}, Resources: []catalog.ResourceRow{{Module: "test", Resource: "objects", ObjectType: "test_object"}}, Verbs: []catalog.VerbRow{{Module: "test", Resource: "objects", Verb: "get", PerObject: true}, {Module: "test", Resource: "objects", Verb: "delete", PerObject: true}}}})
	require.True(t, err == nil)
	rules, err := domain.EncodeRules(domain.Rules{{Module: "test", Resources: []string{"objects"}, Verbs: []string{"get"}}})
	require.True(t, err == nil)
	role := rid11RestoreRow(map[string]any{"id": "role-one", "cluster_id": "cluster", "account_id": "", "project_id": "", "name": "reader", "description": "", "is_system": true, "owner_module": "test", "created_at": at.Add(-time.Hour), "updated_at": at.Add(-time.Hour), "labels": map[string]string{}, "live": true, "retired_at": nil, "retired_reason": "", "retired_by": ""})
	role["rules"] = rules
	a := rid03NewmanSnapshot{Raw: map[string][]rid09PrimaryRow{}, Whole: ridWholeDeliverySnapshot{PrimaryStartedAt: at, PrimaryFinishedAt: at.Add(time.Second), Delivery: map[string]ridWholeTable{}, Bookkeeping: map[string]ridWholeTable{}, Separation: map[string]string{}}, BusinessAudit: []rid09PrimaryRow{}, Facts: facts}
	for k := range rid11RestoreSchemas {
		a.Raw[k] = []rid09PrimaryRow{}
	}
	for _, k := range []string{"catalog_module", "catalog_resource", "catalog_verb", "role_grant_orphan", "role_selector_prune", "grant_delegations", "access_bindings", "access_binding_target_members", "operations"} {
		a.Raw[k] = []rid09PrimaryRow{}
	}
	a.Raw["roles"] = []rid09PrimaryRow{role}
	p, err := rid11BuildRestorePlan(a.Raw, facts)
	require.True(t, err == nil)
	// Предыдущий сохранённый селектор существует, но его материализующая проекция пуста.
	for _, r := range p.Selectors {
		r = rid11RestoreClone(r)
		r["created_at"], _ = json.Marshal(at.Add(-time.Hour))
		r["updated_at"], _ = json.Marshal(at.Add(-time.Hour))
		r["verbs_by_type"] = json.RawMessage(`{}`)
		a.Raw["role_rule_selectors"] = append(a.Raw["role_rule_selectors"], r)
	}
	a.Raw["role_selector_verbs_pending"] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"role_id": "role-one", "enqueued_at": at.Add(-time.Minute)})}
	p, err = rid11BuildRestorePlan(a.Raw, facts)
	require.True(t, err == nil)
	b := a
	b.Raw = map[string][]rid09PrimaryRow{}
	for k, rows := range p.Raw {
		b.Raw[k] = []rid09PrimaryRow{}
		for _, r := range rows {
			b.Raw[k] = append(b.Raw[k], rid11RestoreClone(r))
		}
	}
	b.Raw["role_rule_selectors"] = []rid09PrimaryRow{}
	for key, r := range p.Selectors {
		r = rid11RestoreClone(r)
		r["created_at"] = append(json.RawMessage(nil), p.ExistingSelectors[key]["created_at"]...)
		r["updated_at"], _ = json.Marshal(at.Add(2 * time.Second))
		b.Raw["role_rule_selectors"] = append(b.Raw["role_rule_selectors"], r)
	}
	b.Whole = a.Whole
	b.Whole.PrimaryStartedAt = at.Add(3 * time.Second)
	b.Whole.PrimaryFinishedAt = at.Add(4 * time.Second)
	for k := range a.Raw {
		if k != "operations" {
			cols := []string{}
			if keys, ok := rid11RestoreSchemas[k]; ok {
				cols = append(cols, keys...)
			}
			a.Whole.Delivery[k] = ridWholeTable{Columns: cols, Rows: []string{}}
		}
	}
	a.Projection.Roles = rid11RestoreRoles(t, a.Raw, facts)
	b.Projection.Roles = rid11RestoreRoles(t, p.Raw, facts)
	b.Whole.Delivery = map[string]ridWholeTable{}
	for k, v := range a.Whole.Delivery {
		b.Whole.Delivery[k] = v
	}
	return a, b, p
}
func rid11RestoreUnitAccepted(t *testing.T, a, b rid03NewmanSnapshot, p rid11RestorePlan) bool {
	t.Helper()
	e := a.Projection
	e.Roles = rid11RestoreRoles(t, p.Raw, p.Facts)
	return rid11RestoreRawValid(p, a, b) && reflect.DeepEqual(e, b.Projection)
}
func TestRID11Restore_EmptyToHealthyExactTwin(t *testing.T) {
	a, b, p := rid11RestoreFixture(t)
	require.Equal(t, iamv1.RoleHealth_ROLE_HEALTH_EMPTY.String(), a.Projection.Roles[0]["health"])
	require.Equal(t, iamv1.RoleHealth_ROLE_HEALTH_HEALTHY.String(), b.Projection.Roles[0]["health"])
	require.True(t, rid11RestoreUnitAccepted(t, a, b, p))
}
func TestRID11Restore_ResolvedPublicIdentity(t *testing.T) {
	a, b, p := rid11RestoreFixture(t)
	a.Projection = b.Projection
	a.Raw["role_verb"] = p.Raw["role_verb"]
	q, e := rid11BuildRestorePlan(a.Raw, p.Facts)
	require.True(t, e == nil)
	require.True(t, rid11RestoreUnitAccepted(t, a, b, q))
}
func TestRID11Restore_AnchorRuleRefUsesNull(t *testing.T) {
	a, _, p := rid11RestoreFixture(t)
	authored := domain.Rules{{Module: "test", Resources: []string{"objects"}, Verbs: []string{"*"}}}
	require.True(t, authored.Validate(domain.PolicyOfRole(true, "test"), domain.ModuleSetOf("test")) == nil, "positive anchor must be a valid normal authored rule")
	rules, e := domain.EncodeRules(authored)
	require.True(t, e == nil)
	a.Raw["roles"][0]["rules"] = rules
	p, e = rid11BuildRestorePlan(a.Raw, p.Facts)
	require.True(t, e == nil)
	require.Len(t, p.Raw["role_rule_ref"], 1)
	require.True(t, string(p.Raw["role_rule_ref"][0]["verb"]) == "null")
	require.Equal(t, "role-one", rid03S(p.Raw["role_rule_ref"][0], "role_id"))
	require.Equal(t, "test", rid03S(p.Raw["role_rule_ref"][0], "module"))
	require.Equal(t, "objects", rid03S(p.Raw["role_rule_ref"][0], "resource"))
}
func rid11RestoreReject(t *testing.T, mutate func(*rid03NewmanSnapshot, *rid03NewmanSnapshot, *rid11RestorePlan)) {
	t.Helper()
	a, b, p := rid11RestoreFixture(t)
	mutate(&a, &b, &p)
	require.False(t, rid11RestoreUnitAccepted(t, a, b, p), "closed restoration must reject adversarial delta")
}

func TestRID11Restore_RejectMissingVerb(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) { b.Raw["role_verb"] = nil })
}

func TestRID11Restore_RejectExtraVerb(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["role_verb"] = append(b.Raw["role_verb"], rid11RestoreRow(map[string]any{"role_id": "role-one", "object_type": "test.objects", "verb": "delete", "live": true}))
	})
}

func TestRID11Restore_RejectDuplicateVerb(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["role_verb"] = append(b.Raw["role_verb"], rid11RestoreClone(b.Raw["role_verb"][0]))
	})
}

func TestRID11Restore_RejectWrongVerbRole(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["role_verb"][0]["role_id"] = json.RawMessage(`"foreign"`)
	})
}

func TestRID11Restore_RejectWrongVerbObject(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["role_verb"][0]["object_type"] = json.RawMessage(`"foreign.objects"`)
	})
}

func TestRID11Restore_RejectWrongVerbLive(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["role_verb"][0]["live"] = json.RawMessage(`false`)
	})
}

func TestRID11Restore_RejectUnknownVerbColumn(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["role_verb"][0]["future"] = json.RawMessage(`true`)
	})
}

func TestRID11Restore_RejectMissingRuleRef(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) { b.Raw["role_rule_ref"] = nil })
}

func TestRID11Restore_RejectWrongRuleRef(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["role_rule_ref"][0]["module"] = json.RawMessage(`"foreign"`)
	})
}

func TestRID11Restore_RejectPendingNotDequeued(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["role_selector_verbs_pending"] = a.Raw["role_selector_verbs_pending"]
	})
}

func TestRID11Restore_RejectForeignPendingAdded(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["role_selector_verbs_pending"] = append(b.Raw["role_selector_verbs_pending"], rid11RestoreRow(map[string]any{"role_id": "foreign", "enqueued_at": a.Whole.PrimaryStartedAt}))
	})
}

func TestRID11Restore_RejectMissingSelector(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) { b.Raw["role_rule_selectors"] = nil })
}

func TestRID11Restore_RejectExtraSelector(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["role_rule_selectors"] = append(b.Raw["role_rule_selectors"], rid11RestoreClone(b.Raw["role_rule_selectors"][0]))
	})
}

func TestRID11Restore_RejectWrongSelectorFingerprint(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["role_rule_selectors"][0]["rule_fp"] = json.RawMessage(`"wrong"`)
	})
}

func TestRID11Restore_RejectWrongSelectorGrant(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["role_rule_selectors"][0]["verbs_by_type"] = json.RawMessage(`{"test.objects":["delete"]}`)
	})
}

func TestRID11Restore_RejectWrongSelectorScope(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["role_rule_selectors"][0]["object_types"] = json.RawMessage(`["foreign.objects"]`)
	})
}

func TestRID11Restore_RejectWrongSelectorCreator(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["role_rule_selectors"][0]["created_by_subject"] = json.RawMessage(`true`)
	})
}

func TestRID11Restore_RejectWrongSelectorLabels(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["role_rule_selectors"][0]["match_labels"] = json.RawMessage(`{"foreign":"true"}`)
	})
}

func TestRID11Restore_RejectUnknownSelectorColumn(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["role_rule_selectors"][0]["future"] = json.RawMessage(`true`)
	})
}

func TestRID11Restore_RejectPastSyncClock(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["role_rule_selectors"][0]["updated_at"], _ = json.Marshal(a.Whole.PrimaryStartedAt)
	})
}

func TestRID11Restore_RejectFutureSyncClock(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["role_rule_selectors"][0]["updated_at"], _ = json.Marshal(b.Whole.PrimaryFinishedAt)
	})
}

func TestRID11Restore_RejectMalformedSyncClock(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["role_rule_selectors"][0]["updated_at"] = json.RawMessage(`"bad"`)
	})
}

func TestRID11Restore_RejectMissingSyncClock(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		delete(b.Raw["role_rule_selectors"][0], "updated_at")
	})
}

func TestRID11Restore_RejectChangedCreatedAt(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["role_rule_selectors"][0]["created_at"], _ = json.Marshal(a.Whole.PrimaryStartedAt)
	})
}

func TestRID11Restore_RejectChangedRolePolicy(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["roles"][0]["owner_module"] = json.RawMessage(`"foreign"`)
	})
}

func TestRID11Restore_RejectChangedRoleRules(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["roles"][0]["rules"] = json.RawMessage(`[]`)
	})
}

func TestRID11Restore_RejectCatalogFingerprint(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["catalog_verb"] = append(b.Raw["catalog_verb"], rid11RestoreRow(map[string]any{"verb": "delete"}))
	})
}

func TestRID11Restore_RejectPublicDerivedHealth(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Projection.Roles[0]["health"] = iamv1.RoleHealth_ROLE_HEALTH_EMPTY.String()
	})
}

func TestRID11Restore_RejectPublicUnresolved(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Projection.Roles[0]["unresolvedSegments"] = float64(9)
	})
}

func TestRID11Restore_RejectPublicRuleStates(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) { b.Projection.Roles[0]["ruleStates"] = []any{} })
}

func TestRID11Restore_RejectOtherPublicField(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) { b.Projection.Materialization = "changed" })
}

func TestRID11Restore_RejectGDHistory(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["grant_delegations"] = append(b.Raw["grant_delegations"], rid11RestoreRow(map[string]any{"id": "extra"}))
	})
}

func TestRID11Restore_RejectGHistory(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["access_bindings"] = append(b.Raw["access_bindings"], rid11RestoreRow(map[string]any{"id": "extra"}))
	})
}

func TestRID11Restore_RejectMemberLedger(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["access_binding_target_members"] = append(b.Raw["access_binding_target_members"], rid11RestoreRow(map[string]any{"id": "extra"}))
	})
}

func TestRID11Restore_RejectNewOperation(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Raw["operations"] = append(b.Raw["operations"], rid11RestoreRow(map[string]any{"id": "extra"}))
	})
}

func TestRID11Restore_RejectBusinessEvent(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.BusinessAudit = append(b.BusinessAudit, rid11RestoreRow(map[string]any{"id": "extra"}))
	})
}

func TestRID11Restore_RejectUnknownTable(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) { b.Raw["future"] = []rid09PrimaryRow{} })
}

func TestRID11Restore_RejectUnknownPhysicalSchema(t *testing.T) {
	rid11RestoreReject(t, func(a, b *rid03NewmanSnapshot, p *rid11RestorePlan) {
		b.Whole.Delivery["role_verb"] = ridWholeTable{Columns: []string{"future"}, Rows: []string{}}
	})
}

func TestRID11Restore_RejectUnknownBeforeSchema(t *testing.T) {
	a, _, p := rid11RestoreFixture(t)
	a.Raw["role_verb"] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"role_id": "role-one", "object_type": "test.objects", "verb": "get", "live": true, "future": true})}
	_, e := rid11BuildRestorePlan(a.Raw, p.Facts)
	require.True(t, e != nil)
}
func TestRID11Restore_InputOrderIndependent(t *testing.T) {
	a, b, p := rid11RestoreFixture(t)
	for k, rows := range b.Raw {
		for l, r := 0, len(rows)-1; l < r; l, r = l+1, r-1 {
			rows[l], rows[r] = rows[r], rows[l]
		}
		b.Raw[k] = rows
	}
	require.True(t, rid11RestoreUnitAccepted(t, a, b, p))
}
func TestRID11Restore_MissingFactsRejected(t *testing.T) {
	a, _, _ := rid11RestoreFixture(t)
	_, e := rid11BuildRestorePlan(a.Raw, nil)
	require.True(t, e != nil)
}

func TestRID11Restore_ModulePolicyDoesNotInventDelete(t *testing.T) {
	a, _, p := rid11RestoreFixture(t)
	rules, e := domain.EncodeRules(domain.Rules{{Module: "test", Resources: []string{"objects"}, Verbs: []string{"get", "update"}}})
	require.True(t, e == nil)
	a.Raw["roles"][0]["rules"] = rules
	h := catalog.Halves{Live: catalog.Rows{Modules: []string{"test"}, Resources: []catalog.ResourceRow{{Module: "test", Resource: "objects", ObjectType: "test_object"}}, Verbs: []catalog.VerbRow{{Module: "test", Resource: "objects", Verb: "get", PerObject: true}, {Module: "test", Resource: "objects", Verb: "update", PerObject: true}, {Module: "test", Resource: "objects", Verb: "delete", PerObject: true}}}}
	f, e := catalog.NewFacts(h)
	require.True(t, e == nil)
	p, e = rid11BuildRestorePlan(a.Raw, f)
	require.True(t, e == nil)
	hasDelete := func(p rid11RestorePlan) bool {
		for _, r := range p.Raw["role_verb"] {
			if rid03S(r, "verb") == "delete" {
				return true
			}
		}
		return false
	}
	require.False(t, hasDelete(p))
	a.Raw["roles"][0]["owner_module"] = json.RawMessage(`""`)
	q, e := rid11BuildRestorePlan(a.Raw, f)
	require.True(t, e == nil)
	require.True(t, hasDelete(q))
}
func TestRID11Restore_NewSelectorRequiresEqualCreationClock(t *testing.T) {
	a, b, p := rid11RestoreFixture(t)
	for k := range p.ExistingSelectors {
		delete(p.ExistingSelectors, k)
	}
	r := b.Raw["role_rule_selectors"][0]
	r["created_at"] = append(json.RawMessage(nil), r["updated_at"]...)
	require.True(t, rid11RestoreUnitAccepted(t, a, b, p))
	r["created_at"], _ = json.Marshal(a.Whole.PrimaryFinishedAt)
	require.False(t, rid11RestoreUnitAccepted(t, a, b, p))
}
func TestRID11Restore_ForeignSelectorMustRemainExact(t *testing.T) {
	a, b, p := rid11RestoreFixture(t)
	r := rid11RestoreClone(b.Raw["role_rule_selectors"][0])
	r["role_id"] = json.RawMessage(`"foreign"`)
	key := "foreign\x00" + rid03S(r, "rule_fp")
	p.ExistingSelectors[key] = r
	b.Raw["role_rule_selectors"] = append(b.Raw["role_rule_selectors"], rid11RestoreClone(r))
	require.True(t, rid11RestoreUnitAccepted(t, a, b, p))
	b.Raw["role_rule_selectors"][1]["verbs_by_type"] = json.RawMessage(`{}`)
	require.False(t, rid11RestoreUnitAccepted(t, a, b, p))
}
func TestRID11Restore_ForeignPendingMustRemainExact(t *testing.T) {
	a, b, p := rid11RestoreFixture(t)
	r := rid11RestoreRow(map[string]any{"role_id": "foreign", "enqueued_at": a.Whole.PrimaryStartedAt})
	p.Raw["role_selector_verbs_pending"] = []rid09PrimaryRow{r}
	b.Raw["role_selector_verbs_pending"] = []rid09PrimaryRow{rid11RestoreClone(r)}
	require.True(t, rid11RestoreUnitAccepted(t, a, b, p))
	b.Raw["role_selector_verbs_pending"] = nil
	require.False(t, rid11RestoreUnitAccepted(t, a, b, p))
}
func TestRID11Restore_RejectClockMismatchBetweenSyncRows(t *testing.T) {
	a, b, p := rid11RestoreFixture(t)
	for k, r := range p.Selectors {
		n := rid11RestoreClone(r)
		n["rule_fp"] = json.RawMessage(`"second"`)
		p.Selectors[rid03S(n, "role_id")+"\x00second"] = n
		old := rid11RestoreClone(p.ExistingSelectors[k])
		old["rule_fp"] = n["rule_fp"]
		p.ExistingSelectors[rid03S(n, "role_id")+"\x00second"] = old
		break
	}
	n := rid11RestoreClone(b.Raw["role_rule_selectors"][0])
	n["rule_fp"] = json.RawMessage(`"second"`)
	n["updated_at"], _ = json.Marshal(a.Whole.PrimaryFinishedAt.Add(1500 * time.Millisecond))
	b.Raw["role_rule_selectors"] = append(b.Raw["role_rule_selectors"], n)
	require.False(t, rid11RestoreUnitAccepted(t, a, b, p))
}
func TestRID11Restore_RejectOldOperationColumnChange(t *testing.T) {
	a, b, p := rid11RestoreFixture(t)
	old := rid11RestoreRow(map[string]any{"id": "old", "response_data": "private-not-persisted"})
	p.Raw["operations"] = []rid09PrimaryRow{old}
	b.Raw["operations"] = []rid09PrimaryRow{rid11RestoreClone(old)}
	b.Raw["operations"][0]["response_data"] = json.RawMessage(`"changed"`)
	require.False(t, rid11RestoreUnitAccepted(t, a, b, p))
}
func TestRID11Restore_RejectBusinessHistoryMutation(t *testing.T) {
	a, b, p := rid11RestoreFixture(t)
	a.BusinessAudit = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"id": "old", "event_type": "iam.access_binding.granted"})}
	b.BusinessAudit = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"id": "old", "event_type": "iam.grant_delegation.created"})}
	require.False(t, rid11RestoreUnitAccepted(t, a, b, p))
}

func TestRID11Restore_RejectForeignSelectorRemoval(t *testing.T) {
	a, b, p := rid11RestoreFixture(t)
	r := rid11RestoreClone(b.Raw["role_rule_selectors"][0])
	r["role_id"] = json.RawMessage(`"foreign"`)
	p.ExistingSelectors["foreign\x00"+rid03S(r, "rule_fp")] = r
	require.False(t, rid11RestoreUnitAccepted(t, a, b, p))
}
func TestRID11Restore_UnknownCatalogVerbGivesNoPrivilege(t *testing.T) {
	a, _, p := rid11RestoreFixture(t)
	rules, e := domain.EncodeRules(domain.Rules{{Module: "test", Resources: []string{"objects"}, Verbs: []string{"noSuchVerb"}}})
	require.True(t, e == nil)
	a.Raw["roles"][0]["rules"] = rules
	q, e := rid11BuildRestorePlan(a.Raw, p.Facts)
	require.True(t, e == nil)
	require.Zero(t, len(q.Raw["role_verb"]))
	require.Equal(t, 1, len(q.Raw["role_rule_ref"]))
}
func TestRID11Restore_RejectNilUpperClock(t *testing.T) {
	a, b, p := rid11RestoreFixture(t)
	b.Whole.PrimaryStartedAt = time.Time{}
	require.False(t, rid11RestoreUnitAccepted(t, a, b, p))
}
func TestRID11Restore_RejectChangedTransportPartition(t *testing.T) {
	a, b, p := rid11RestoreFixture(t)
	b.Whole.Separation = map[string]string{"new": "unknown"}
	require.False(t, rid11RestoreUnitAccepted(t, a, b, p))
}
func TestRID11Restore_SelectorTimestampNotRegrainException(t *testing.T) {
	a, b, p := rid11RestoreFixture(t)
	r := b.Raw["role_rule_selectors"][0]
	r["updated_at"] = append(json.RawMessage(nil), a.Raw["role_rule_selectors"][0]["updated_at"]...)
	require.False(t, rid11RestoreUnitAccepted(t, a, b, p))
}
func TestRID11Restore_TwoPoliciesHaveIndependentGrantSets(t *testing.T) {
	a, _, p := rid11RestoreFixture(t)
	r := rid11RestoreClone(a.Raw["roles"][0])
	r["id"] = json.RawMessage(`"second"`)
	r["owner_module"] = json.RawMessage(`""`)
	a.Raw["roles"] = append(a.Raw["roles"], r)
	q, e := rid11BuildRestorePlan(a.Raw, p.Facts)
	require.True(t, e == nil)
	require.Equal(t, 2, len(q.Eligible))
	require.Equal(t, 2, len(q.Raw["role_verb"]))
	for _, v := range q.Raw["role_verb"] {
		require.Equal(t, "get", rid03S(v, "verb"))
	}
}

// Пустой список действий не является документированным универсальным якорем. Это
// неверная предпосылка первого неудачного положительного случая, сохранённая отрицательным случаем.
func TestRID11Restore_EmptyVerbsCannotProveAnchor(t *testing.T) {
	a, _, p := rid11RestoreFixture(t)
	authored := domain.Rules{{Module: "test", Resources: []string{"objects"}}}
	require.True(t, authored.Validate(domain.PolicyOfRole(true, "test"), domain.ModuleSetOf("test")) != nil, "empty verb list is not a valid anchor premise")
	rules, e := domain.EncodeRules(authored)
	require.True(t, e == nil)
	a.Raw["roles"][0]["rules"] = rules
	p, e = rid11BuildRestorePlan(a.Raw, p.Facts)
	require.True(t, e == nil)
	require.Zero(t, len(p.Raw["role_rule_ref"]))
	require.Zero(t, len(p.Raw["role_verb"]))
}
