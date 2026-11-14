// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resourceeffect_test

import (
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/resourceeffect"
	"github.com/stretchr/testify/require"
)

var (
	boxX = domain.ResourceRef{Type: "probe.boxes", ID: "x"}
	boxY = domain.ResourceRef{Type: "probe.boxes", ID: "y"}
	tagX = domain.ResourceRef{Type: "probe.tags", ID: "x"}
)

func facts(t *testing.T) *catalog.Facts {
	t.Helper()
	f, err := catalog.NewFacts(catalog.Halves{Live: catalog.Rows{
		Modules: []string{"probe", "iam"},
		Resources: []catalog.ResourceRow{
			{Module: "probe", Resource: "boxes", ObjectType: "probe_box"},
			{Module: "probe", Resource: "tags", ObjectType: "probe_tag"},
			{Module: "iam", Resource: "role", ObjectType: "iam_role"},
		},
		Verbs: []catalog.VerbRow{
			{Module: "probe", Resource: "boxes", Verb: "get", PerObject: true},
			{Module: "probe", Resource: "boxes", Verb: "list", PerObject: true},
			{Module: "probe", Resource: "tags", Verb: "get", PerObject: true},
			{Module: "iam", Resource: "role", Verb: "list", PerObject: true},
			{Module: "iam", Resource: "role", Verb: "bind"},
		},
	}})
	require.NoError(t, err)
	return f
}

func binding(id domain.AccessBindingID, refs ...domain.ResourceRef) resourceeffect.WithdrawalBinding {
	return resourceeffect.WithdrawalBinding{Binding: domain.AccessBinding{
		ID: id, SubjectType: domain.SubjectTypeUser, SubjectID: "usr_legacy", RoleID: "rol_read",
		ResourceType: "account", ResourceID: "acc_a", Status: domain.AccessBindingStatusActive,
		Target: domain.AccessTarget{Resources: refs},
	}}
}

func TestWithdrawalSequentialKeysKeepLastTargetAndAllSubjects(t *testing.T) {
	b := binding("acb_a", boxX, boxY)
	b.Subjects = []domain.Subject{{Type: domain.SubjectTypeUser, ID: "usr_a"}, {Type: domain.SubjectTypeGroup, ID: "grp_a"}}
	b.Emitted = []abrepo.RelationTuple{{User: "user:usr_a", Relation: "v_get", Object: "probe_box:x"}, {User: "group:grp_a#member", Relation: "v_get", Object: "probe_box:y"}}
	p, err := resourceeffect.CompileWithdrawal([]domain.ResourceRef{boxX, boxY, boxX}, "service_account:sva_module", resourceeffect.WithdrawalSnapshot{Bindings: []resourceeffect.WithdrawalBinding{b}}, nil)
	require.NoError(t, err)
	require.Len(t, p.Steps, 3)
	first := p.Steps[0].Bindings
	require.Len(t, first, 1)
	require.Equal(t, resourceeffect.BindingNarrow, first[0].Action)
	require.Equal(t, []domain.ResourceRef{boxX, boxY}, first[0].BeforeTarget.Resources)
	require.Equal(t, []domain.ResourceRef{boxY}, first[0].Target.Resources)
	require.Empty(t, first[0].TupleDeletes, "сужение не отзывает весь реестр")
	require.Empty(t, first[0].SubjectChanges, "сохранён прежний явный fanout только полного отзыва")
	require.Len(t, first[0].Audits, 2)
	require.Equal(t, 1, first[0].Audits[0].ExtraPayload["remaining_resource_count"])
	last := p.Steps[1].Bindings
	require.Len(t, last, 1)
	require.Equal(t, resourceeffect.BindingRevoke, last[0].Action)
	require.Equal(t, []domain.ResourceRef{boxY}, last[0].BeforeTarget.Resources)
	require.Equal(t, []domain.ResourceRef{boxY}, last[0].Target.Resources, "пустая цель не записывается; остаётся последний снятый ключ")
	require.Equal(t, domain.RevocationReasonResourceUnregistered, last[0].RevocationReason)
	require.Equal(t, b.Emitted, last[0].TupleDeletes, "снимается весь реестр, включая другой объект")
	require.Equal(t, []abrepo.SubjectChangeEvent{
		{SubjectType: "user", SubjectID: "usr_a", EventType: "binding_revoke", Op: "binding_delete"},
		{SubjectType: "group", SubjectID: "grp_a", EventType: "binding_revoke", Op: "binding_delete"},
	}, last[0].SubjectChanges)
	require.Len(t, last[0].Audits, 2)
	for _, audit := range last[0].Audits {
		require.Equal(t, "service_account:sva_module", audit.Actor)
		require.Equal(t, "acc_a", audit.TenantAccountID)
		require.Equal(t, "resource_unregistered", audit.ExtraPayload["revocation_reason"])
		require.Equal(t, map[string]any{"type": boxY.Type, "id": boxY.ID}, audit.ExtraPayload["unregistered_resource"])
	}
	require.Empty(t, p.Steps[2].Bindings, "повтор ключа не удваивает отзыв или аудит")
}

func TestWithdrawalKeepsPendingExpiryProtectionAndLegacySemantics(t *testing.T) {
	at := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, test := range []struct {
		name string
		edit func(*resourceeffect.WithdrawalBinding)
		want bool
	}{
		{"active", func(*resourceeffect.WithdrawalBinding) {}, true},
		{"pending", func(b *resourceeffect.WithdrawalBinding) { b.Binding.Status = domain.AccessBindingStatusPending }, true},
		{"expired_not_revoked", func(b *resourceeffect.WithdrawalBinding) { b.Binding.ExpiresAt = &at }, true},
		{"deletion_protected", func(b *resourceeffect.WithdrawalBinding) { b.Binding.DeletionProtection = true }, true},
		{"already_revoked", func(b *resourceeffect.WithdrawalBinding) {
			b.Binding.Status = domain.AccessBindingStatusRevoked
			b.Binding.RevokedAt = &at
		}, false},
		{"whole_scope", func(b *resourceeffect.WithdrawalBinding) { b.Binding.Target = domain.AccessTarget{AllInScope: true} }, false},
		{"another_key", func(b *resourceeffect.WithdrawalBinding) { b.Binding.Target.Resources = []domain.ResourceRef{boxY} }, false},
		{"project_audit_scope", func(b *resourceeffect.WithdrawalBinding) {
			b.Binding.ResourceType = "project"
			b.Binding.ResourceID = "prj_p"
		}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := binding("acb_a", boxX)
			test.edit(&b)
			p, err := resourceeffect.CompileWithdrawal([]domain.ResourceRef{boxX}, "module", resourceeffect.WithdrawalSnapshot{Bindings: []resourceeffect.WithdrawalBinding{b}}, nil)
			require.NoError(t, err)
			if !test.want {
				require.Empty(t, p.Steps[0].Bindings)
				return
			}
			require.Len(t, p.Steps[0].Bindings, 1)
			got := p.Steps[0].Bindings[0]
			require.Equal(t, resourceeffect.BindingRevoke, got.Action)
			require.Equal(t, b.Binding.Status, got.BeforeStatus)
			require.Equal(t, "usr_legacy", got.SubjectChanges[0].SubjectID)
			require.Equal(t, "user", got.SubjectChanges[0].SubjectType)
			if b.Binding.ResourceType == "project" {
				require.Empty(t, got.Audits[0].TenantAccountID)
			} else {
				require.Equal(t, "acc_a", got.Audits[0].TenantAccountID)
			}
		})
	}
}

func TestWithdrawalRoleNamesKeepOtherTypesNestedNamesAndEmptyRole(t *testing.T) {
	for _, test := range []struct {
		name          string
		key           domain.ResourceRef
		before, after domain.Rules
		removed       int
	}{
		{"other_type_kept", boxX,
			domain.Rules{{Module: "probe", Resources: []string{"boxes", "tags"}, Verbs: []string{"get"}, ResourceNames: []string{"x", "y"}}},
			domain.Rules{{Module: "probe", Resources: []string{"tags"}, Verbs: []string{"get"}, ResourceNames: []string{"x", "y"}}, {Module: "probe", Resources: []string{"boxes"}, Verbs: []string{"get"}, ResourceNames: []string{"y"}}}, 0},
		{"nested_name_kept", tagX,
			domain.Rules{{Module: "probe", Resources: []string{"boxes"}, Verbs: []string{"get"}, Children: []domain.Rule{{Resources: []string{"tags"}, Verbs: []string{"get"}, ResourceNames: []string{"x", "y"}}}}},
			domain.Rules{{Module: "probe", Resources: []string{"boxes"}, Verbs: []string{"get"}, Children: []domain.Rule{{Resources: []string{"tags"}, Verbs: []string{"get"}, ResourceNames: []string{"y"}}}}}, 0},
		{"last_rule_removed", boxX,
			domain.Rules{{Module: "probe", Resources: []string{"boxes"}, Verbs: []string{"get"}, ResourceNames: []string{"x"}}},
			nil, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := domain.Role{ID: "rol_a", AccountID: "acc_a", Rules: test.before}
			p, err := resourceeffect.CompileWithdrawal([]domain.ResourceRef{test.key}, "module", resourceeffect.WithdrawalSnapshot{Roles: []domain.Role{r}}, facts(t))
			require.NoError(t, err)
			require.Len(t, p.Steps[0].Roles, 1)
			got := p.Steps[0].Roles[0]
			require.Equal(t, test.before, got.BeforeRules)
			require.Equal(t, test.after, got.Rules)
			require.Equal(t, test.removed, got.Audit.Payload["removed_rule_count"])
			require.Equal(t, len(test.after), got.Audit.Payload["remaining_rule_count"])
			require.Equal(t, "acc_a", got.Audit.TenantAccountID)
			require.Nil(t, got.Retain)
			if len(test.after) == 0 {
				require.Empty(t, got.Permissions)
				require.Empty(t, got.Selectors)
				require.Empty(t, got.Verbs)
				require.Empty(t, got.Refs)
			} else {
				require.NotEmpty(t, got.Permissions)
				require.NotEmpty(t, got.Selectors)
				require.NotEmpty(t, got.Verbs)
				require.NotEmpty(t, got.Refs)
			}
		})
	}
}

func TestWithdrawalPreservesMetaReferencesAndRequestsProjectionRetention(t *testing.T) {
	const first, second = "rol00000000000000001", "rol00000000000000002"
	key := domain.ResourceRef{Type: "iam.role", ID: first}
	mixed := domain.Role{ID: "rol_mixed", AccountID: "acc_a", Rules: domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"list", "bind"}, ResourceNames: []string{first, second}}}}
	meta := domain.Role{ID: "rol_meta", AccountID: "acc_a", Rules: domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{first}}}}
	p, err := resourceeffect.CompileWithdrawal([]domain.ResourceRef{key}, "module", resourceeffect.WithdrawalSnapshot{Roles: []domain.Role{mixed, meta}}, facts(t))
	require.NoError(t, err)
	require.Len(t, p.Steps[0].Roles, 1, "чистая meta-ссылка не снимается как зеркальная регистрация")
	r := p.Steps[0].Roles[0]
	require.Equal(t, mixed.ID, r.ID)
	require.Equal(t, domain.Rules{
		{Module: "iam", Resources: []string{"role"}, Verbs: []string{"list"}, ResourceNames: []string{second}},
		{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{first, second}},
	}, r.Rules)
	require.NotNil(t, r.Retain)
	require.Len(t, r.Retain.Before, 2)
	require.Len(t, r.Retain.After, 2)
	for _, caps := range [][]domain.GrantCapabilityRule{r.Retain.Before, r.Retain.After} {
		require.Equal(t, domain.GrantCapabilityBindRole, caps[0].Kind)
		require.Equal(t, domain.GrantCapabilityBindRole, caps[1].Kind)
		require.ElementsMatch(t, []domain.RoleID{first, second}, []domain.RoleID{caps[0].BoundRoleID, caps[1].BoundRoleID})
	}
	require.Len(t, r.Selectors, 1)
	require.Equal(t, []string{second}, r.Selectors[0].ResourceNames)
	require.Equal(t, []domain.RoleVerb{{ObjectType: "iam.role", Verb: "list"}}, r.Verbs)
}

func TestWithdrawalIsDeterministicDoesNotMutateOrAliasInput(t *testing.T) {
	// Два независимых мира дают typed-оракул без JSON: domain.Role содержит
	// TypeVerbLookup, который JSON не кодирует даже при нулевом значении.
	fixture := func() resourceeffect.WithdrawalSnapshot {
		b := binding("acb_b", boxX, boxY)
		b.Subjects = []domain.Subject{{Type: domain.SubjectTypeServiceAccount, ID: "sva_a"}}
		b.Emitted = []abrepo.RelationTuple{{User: "service_account:sva_a", Relation: "v_get", Object: "probe_box:y"}}
		r := domain.Role{ID: "rol_b", Rules: domain.Rules{{Module: "probe", Resources: []string{"boxes"}, Verbs: []string{"get"}, ResourceNames: []string{"x", "y"}}}}
		return resourceeffect.WithdrawalSnapshot{Bindings: []resourceeffect.WithdrawalBinding{b, binding("acb_a", boxX)}, Roles: []domain.Role{r}}
	}
	snapshot, before := fixture(), fixture()
	require.Equal(t, before, snapshot)
	keys := []domain.ResourceRef{boxX, boxY}
	p, err := resourceeffect.CompileWithdrawal(keys, "module", snapshot, facts(t))
	require.NoError(t, err)
	again, err := resourceeffect.CompileWithdrawal(keys, "module", snapshot, facts(t))
	require.NoError(t, err)
	require.Equal(t, p, again)
	require.Equal(t, domain.AccessBindingID("acb_a"), p.Steps[0].Bindings[0].ID)
	p.Steps[0].Bindings[1].BeforeTarget.Resources[0].ID = "mutated"
	p.Steps[0].Bindings[1].Target.Resources[0].ID = "mutated"
	p.Steps[0].Roles[0].BeforeRules[0].ResourceNames[0] = "mutated"
	p.Steps[0].Roles[0].Rules[0].ResourceNames[0] = "mutated"
	p.Steps[1].Bindings[0].TupleDeletes[0].User = "mutated"
	require.Equal(t, before, snapshot, "компиляция и изменения выхода не меняют исходный снимок")
	require.Equal(t, []domain.ResourceRef{boxX, boxY}, keys)
}

func TestWithdrawalRejectsMalformedCapturedRowsWithoutPartialPlan(t *testing.T) {
	for _, test := range []struct {
		name     string
		keys     []domain.ResourceRef
		snapshot resourceeffect.WithdrawalSnapshot
	}{
		{"missing_key_type", []domain.ResourceRef{{ID: "x"}}, resourceeffect.WithdrawalSnapshot{}},
		{"missing_binding_id", []domain.ResourceRef{boxX}, resourceeffect.WithdrawalSnapshot{Bindings: []resourceeffect.WithdrawalBinding{binding("", boxX)}}},
		{"duplicate_binding", []domain.ResourceRef{boxX}, resourceeffect.WithdrawalSnapshot{Bindings: []resourceeffect.WithdrawalBinding{binding("acb_a", boxX), binding("acb_a", boxY)}}},
		{"bad_status", []domain.ResourceRef{boxX}, resourceeffect.WithdrawalSnapshot{Bindings: []resourceeffect.WithdrawalBinding{{Binding: domain.AccessBinding{ID: "acb_a", Status: "OTHER"}}}}},
		{"missing_role_id", []domain.ResourceRef{boxX}, resourceeffect.WithdrawalSnapshot{Roles: []domain.Role{{}}}},
		{"duplicate_role", []domain.ResourceRef{boxX}, resourceeffect.WithdrawalSnapshot{Roles: []domain.Role{{ID: "rol_a"}, {ID: "rol_a"}}}},
		{"invalid_subject", []domain.ResourceRef{boxX}, resourceeffect.WithdrawalSnapshot{Bindings: []resourceeffect.WithdrawalBinding{{Binding: binding("acb_a", boxX).Binding, Subjects: []domain.Subject{{Type: "OTHER", ID: "x"}}}}}},
		{"missing_catalog_for_role_change", []domain.ResourceRef{boxX}, resourceeffect.WithdrawalSnapshot{Roles: []domain.Role{{ID: "rol_a", Rules: domain.Rules{{Module: "probe", Resources: []string{"boxes"}, Verbs: []string{"get"}, ResourceNames: []string{"x"}}}}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, err := resourceeffect.CompileWithdrawal(test.keys, "module", test.snapshot, nil)
			require.ErrorIs(t, err, resourceeffect.ErrInvalidSnapshot)
			require.Empty(t, p.Steps, "ошибка не возвращает применимый частичный план")
		})
	}
}
