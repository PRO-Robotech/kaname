// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestAccessLabelSelectorMoveCarrierCensusKeepsDormantStoredMembers(t *testing.T) {
	source, tx, _ := resourceSourceFixture(t)
	role := domain.RoleID("rol-census")
	at := time.Date(2026, 11, 24, 18, 0, 0, 0, time.UTC)
	makeRow := func(value map[string]any) resourceSourceRow {
		raw, err := json.Marshal(value)
		require.NoError(t, err)
		return resourceSourceRow{state: string(raw), value: raw}
	}
	makeBinding := func(id string, status domain.AccessBindingStatus, expiry, revoked *time.Time) resourceSourceRow {
		return makeRow(map[string]any{
			"id": id, "role_id": role, "status": status, "created_at": at.Add(-time.Hour),
			"expires_at": expiry, "revoked_at": revoked, "resource_type": "account", "resource_id": "acc-census",
			"scope": domain.ScopeAccount, "subject_type": "user", "subject_id": "usr-primary",
			"labels": map[string]string{}, "target": map[string]bool{"allInScope": true},
		})
	}
	roleKey := resourceSourceKey{kind: resourceSourceRoleBindings, typ: "role", id: string(role)}
	source.entries[roleKey] = []resourceSourceRow{
		makeBinding("revoked", domain.AccessBindingStatusRevoked, nil, &at),
		makeBinding("pending", domain.AccessBindingStatusPending, nil, nil),
		makeBinding("expires-now", domain.AccessBindingStatusActive, &at, nil),
		makeBinding("active", domain.AccessBindingStatusActive, nil, nil),
	}
	makeSubject := func(id, subject, scope string, ordinal int) resourceSourceRow {
		return makeRow(map[string]any{
			"binding_id": id, "subject_type": "user", "subject_id": subject, "ordinal": ordinal,
			"resource_type": "account", "resource_id": scope,
		})
	}
	bindingKey := func(k resourceSourceKind, id string) resourceSourceKey {
		return resourceSourceKey{kind: k, typ: "binding", id: id}
	}
	for _, id := range []string{"active", "expires-now", "pending", "revoked"} {
		source.entries[bindingKey(resourceSourceBindingSubjects, id)] = []resourceSourceRow{makeSubject(id, "usr-primary", "acc-census", 1)}
		source.entries[bindingKey(resourceSourceBindingMembers, id)] = nil
		source.entries[bindingKey(resourceSourceBindingLedger, id)] = nil
	}
	revokedSubjects := bindingKey(resourceSourceBindingSubjects, "revoked")
	source.entries[revokedSubjects] = append(source.entries[revokedSubjects], makeSubject("revoked", "usr-other", "acc-census", 0))
	source.entries[bindingKey(resourceSourceBindingMembers, "revoked")] = []resourceSourceRow{makeRow(map[string]any{
		"binding_id": "revoked", "role_id": role, "rule_fp": "public_reader:old@authenticated",
		"object_type": "registry.registries", "object_id": "reg-retained", "verification_status": "ACTIVE",
	})}
	source.entries[bindingKey(resourceSourceBindingLedger, "revoked")] = []resourceSourceRow{makeRow(map[string]any{
		"binding_id": "revoked", "member_object_type": "registry.registries", "member_object_id": "reg-retained",
		"fga_user": "user:usr-primary", "relation": "v_get", "object": "registry_registry:reg-retained",
	})}

	got, err := readAccessLabelSelectorMoveCarriers(t.Context(), tx, source, role)
	require.NoError(t, err)
	require.Len(t, got, 4)
	require.True(t, got[0].activeAt(at))
	require.False(t, got[1].activeAt(at))
	require.False(t, got[2].activeAt(at))
	require.False(t, got[3].activeAt(at))
	require.Equal(t, domain.AccessBindingID("revoked"), got[3].Binding.ID)
	require.Equal(t, []domain.Subject{{Type: domain.SubjectTypeUser, ID: "usr-other"}, {Type: domain.SubjectTypeUser, ID: "usr-primary"}}, got[3].Binding.Subjects)
	require.Equal(t, map[domain.ResourceRef]bool{{Type: "registry.registries", ID: "reg-retained"}: true}, got[3].Coordinates)
	require.Len(t, got[3].Members, 1)
	require.Equal(t, "public_reader:old@authenticated", got[3].Members[0].RuleFP)
	require.Len(t, got[3].Ledger, 1)

	source.entries[revokedSubjects][1] = makeSubject("revoked", "usr-other", "acc-mismatch", 0)
	got, err = readAccessLabelSelectorMoveCarriers(t.Context(), tx, source, role)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	require.Nil(t, got)
}

type selectorMoveRulesTestRow struct {
	image json.RawMessage
	count int
}

func (r selectorMoveRulesTestRow) Scan(dest ...any) error {
	*dest[0].(*json.RawMessage) = r.image
	*dest[1].(*int) = r.count
	return nil
}

type selectorMoveRulesTestTx struct {
	*resourceSourceTx
	row   selectorMoveRulesTestRow
	calls int
	sql   string
	args  []any
}

func (t *selectorMoveRulesTestTx) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	t.calls++
	t.sql, t.args = sql, args
	return t.row
}

func TestAccessLabelSelectorMoveCaptureBindsRequestToRoleVersion(t *testing.T) {
	source, base, _ := resourceSourceFixture(t)
	tx := &selectorMoveRulesTestTx{resourceSourceTx: base}
	source.stageTX = tx
	parents, err := newResourceParentCapture(tx, source)
	require.NoError(t, err)
	facts, err := catalog.NewFacts(catalog.Halves{Live: catalog.Rows{
		Modules:   []string{"iam"},
		Resources: []catalog.ResourceRow{{Module: "iam", Resource: "project", ObjectType: "project"}},
		Verbs:     []catalog.VerbRow{{Module: "iam", Resource: "project", Verb: "get", PerObject: true}},
	}})
	require.NoError(t, err)
	roleID := domain.RoleID("rol-census")
	declared := domain.Rules{{
		Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"team": "red"},
	}}
	rules, err := domain.EncodeRules(declared)
	require.NoError(t, err)
	raw, err := json.Marshal(map[string]any{
		"id": roleID, "account_id": "acc-census", "rules": json.RawMessage(rules),
		"permissions": []string{}, "labels": map[string]string{}, "live": true,
	})
	require.NoError(t, err)
	state, err := json.Marshal([]any{"31", "(0,1)", json.RawMessage(raw)})
	require.NoError(t, err)
	roleKey := resourceSourceKey{kind: resourceSourceRole, typ: "role", id: string(roleID)}
	source.entries[roleKey] = []resourceSourceRow{{state: string(state), value: raw}}
	source.entries[resourceSourceKey{kind: resourceSourceRoleSelectors, typ: "role", id: string(roleID)}] = nil
	source.entries[resourceSourceKey{kind: resourceSourceRoleBindings, typ: "role", id: string(roleID)}] = nil
	scope := domain.ScopeAnchor{Type: "account", ID: "acc-census"}
	parentCaptureRows(t, parents, resourceSourceKey{kind: resourceSourceAccount, typ: scope.Type, id: scope.ID}, map[string]string{"id": scope.ID})
	predicate, err := json.Marshal(resourceSelectorPredicate{
		RuleFP: declared[0].Fingerprint(), Arm: domain.ArmLabels, Scope: scope, Labels: declared[0].MatchLabels, Targets: []string{},
	})
	require.NoError(t, err)
	parentCaptureRows(t, parents, resourceSourceKey{kind: resourceSourceRoleSelectorObjects, typ: "iam.project", id: string(roleID), projection: string(predicate)})
	next := declared[0]
	next.MatchAccessLabels, next.MatchLabels = next.MatchLabels, nil
	predicate, err = json.Marshal(resourceSelectorPredicate{
		RuleFP: next.Fingerprint(), Arm: domain.ArmAccessLabels, Scope: scope, AccessLabels: next.MatchAccessLabels, Targets: []string{},
	})
	require.NoError(t, err)
	parentCaptureRows(t, parents, resourceSourceKey{kind: resourceSourceRoleSelectorObjects, typ: "iam.project", id: string(roleID), projection: string(predicate)})
	moves := []domain.AccessLabelSelectorMove{{RuleIndex: 0, Fingerprint: declared[0].Fingerprint()}}
	after := json.RawMessage(`[{"module":"iam","resources":["project"],"verbs":["get"],"match_access_labels":{"team":"red"}}]`)
	tx.row = selectorMoveRulesTestRow{image: after, count: 1}
	_, err = parents.captureAccessLabelSelectorMove(t.Context(), facts, roleID, "30", moves)
	require.ErrorIs(t, err, kaname.ErrAuthorityClassificationChanged)
	require.Zero(t, tx.calls, "устаревшую роль не передаём на преобразование")

	proposed, err := parents.captureAccessLabelSelectorMove(t.Context(), facts, roleID, "31", moves)
	require.NoError(t, err)
	require.Equal(t, "31", proposed.Before.ResourceVersion)
	require.Equal(t, declared, proposed.Before.Rules)
	require.Len(t, proposed.ProposedRules, 1)
	require.Empty(t, proposed.ProposedRules[0].MatchLabels)
	require.Equal(t, declared[0].MatchLabels, proposed.ProposedRules[0].MatchAccessLabels)
	require.Empty(t, proposed.Carriers)
	require.NotNil(t, proposed.DefinitionTargets, "пустая выборка области роли удерживается")
	require.Empty(t, proposed.DefinitionTargets)
	require.JSONEq(t, string(after), string(proposed.ProposedImage))
	require.Equal(t, selectorMoveRulesSQL, tx.sql)
	require.JSONEq(t, string(rules), string(tx.args[0].(json.RawMessage)))
	require.JSONEq(t, `[{"rule_index":0,"child_index":-1}]`, string(tx.args[1].([]byte)))
	require.Empty(t, tx.limits, "хватает строк зафиксированного снимка")

	tx.row.count = 0
	_, err = parents.captureAccessLabelSelectorMove(t.Context(), facts, roleID, "31", moves)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "все позиции должны быть перенесены")
	tx.row = selectorMoveRulesTestRow{image: rules, count: 1}
	_, err = parents.captureAccessLabelSelectorMove(t.Context(), facts, roleID, "31", moves)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "одного счётчика недостаточно")

	tampered := proposed
	tampered.ProposedImage, tampered.ProposedRules = rules, declared
	_, err = parents.sealAccessLabelMoveReplay(tampered)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "оба NEW-контейнера должны остаться в RR редакции")

	replay, err := parents.sealAccessLabelMoveReplay(proposed)
	require.NoError(t, err)
	require.Len(t, replay.predicates, 2, "оба пустых OLD/NEW предиката удерживают область")
	rc := &selectorMoveReplayTx{resourceSourceTx: base, role: source.entries[roleKey],
		account: source.entries[resourceSourceKey{kind: resourceSourceAccount, typ: scope.Type, id: scope.ID}]}
	writer := &authorityWriteTx{writeTx: &writeTx{readTx: readTx{tx: rc}}}
	request := kaname.RoleMutationRequest{Role: proposed.Before, Rules: true, Update: true,
		ExpectedVersion: proposed.Before.ResourceVersion, UpdateMask: []string{"rules"}}
	request.Role.Rules = proposed.ProposedRules
	image, err := replay.recheck(t.Context(), writer, request)
	require.NoError(t, err)
	require.JSONEq(t, string(proposed.ProposedImage), string(image))
	require.Equal(t, 2, rc.predicateReads)
}
