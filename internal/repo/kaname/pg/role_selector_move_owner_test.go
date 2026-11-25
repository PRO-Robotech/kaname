// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/stretchr/testify/require"
)

func TestRoleSelectorMoveOwnerBindsExactOldCopyAndClock(t *testing.T) {
	source, rr, _ := resourceSourceFixture(t)
	role := domain.Role{ID: "rol_moved", ResourceVersion: "23"}
	ref := domain.ResourceRef{Type: "iam.project", ID: "prj_copy"}
	physical := `["23","(0,4)",{"id":"rol_moved","rules":[],"name":"retained"}]`
	key := resourceSourceKey{kind: resourceSourceRole, typ: "role", id: string(role.ID)}
	source.entries[key] = []resourceSourceRow{{state: physical}}
	require.NoError(t, source.seal())
	plan := json.RawMessage(`[{"root_type":"iam.project","root_id":"prj_copy","physical":["25","(0,8)",{}],"new_access_labels":{"team":"red"}}]`)
	proposed := json.RawMessage(`[{"module":"iam","match_access_labels":{"team":"red"}}]`)
	stage := &roleSelectorMoveStage{
		captured: accessLabelSelectorMoveCapture{proof: &accessLabelMoveRRProof{
			source: source, role: role.ID, version: role.ResourceVersion, moves: []selectorMovePosition{{Rule: 0, Child: -1}},
		}},
		replay: &accessLabelMoveSourceReplay{parents: &resourceParentCapture{source: source}, role: role, version: role.ResourceVersion,
			image: proposed, copyPlan: plan, updates: accessLabelMoveObjectUpdates{ref: "project"}},
	}
	owner := resourceSourceWriter(t, source, rr)
	owner.producerBudget = source.budget
	raw, err := stage.ownerInput(t.Context(), owner)
	require.NoError(t, err)
	var input roleSelectorMoveOwnerInput
	require.NoError(t, json.Unmarshal(raw, &input))
	require.Equal(t, role.ID, input.Role)
	require.Equal(t, role.ResourceVersion, input.Version)
	require.JSONEq(t, physical, string(input.Physical))
	require.JSONEq(t, string(proposed), string(input.ProposedRules))
	require.JSONEq(t, string(plan), string(input.CopyCandidates))
	require.Equal(t, []selectorMovePosition{{Rule: 0, Child: -1}}, input.Moves)

	owner.fence.decisionAt = time.Date(2026, 11, 24, 8, 0, 0, 0, time.UTC)
	require.NoError(t, source.lifetime.bind(owner))
	writer := &semanticAuthorityWriteTx{authorityWriteTx: owner, bundle: source.lifetime.bundle}
	_, err = stage.recordOwnerDecision(t.Context(), writer, nil)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	labels := map[string]string{"team": "red"}
	decision, err := stage.recordOwnerDecision(t.Context(), writer, accessLabelMoveCopies{ref: labels})
	require.NoError(t, err)
	labels["team"] = "substitution"
	final, err := decision.copyInput(writer)
	require.NoError(t, err)
	require.JSONEq(t, `[{"root_type":"iam.project","root_id":"prj_copy","new_access_labels":{"team":"red"}}]`, string(final))
	final[0] = ' '
	final, err = decision.copyInput(writer)
	require.NoError(t, err)
	require.Equal(t, byte('['), final[0])
	_, err = stage.ownerInput(t.Context(), owner)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)

	owner.fence.decisionAt = owner.fence.decisionAt.Add(time.Nanosecond)
	_, err = decision.copyInput(writer)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}

func TestRoleSelectorMoveSequenceRequestPreservesStoredRuleFields(t *testing.T) {
	request := json.RawMessage(`{"create":false,"mask":["rules"],"version":"23","role":{"id":"rol_moved","rules":[],"description":"kept"}}`)
	exact := json.RawMessage(`[{"module":"iam","match_access_labels":{"team":"red"},"created_by_subject":null}]`)
	got, err := replaceSelectorMoveRules(request, exact)
	require.NoError(t, err)
	require.JSONEq(t, `{"create":false,"mask":["rules"],"version":"23","role":{"id":"rol_moved","rules":[{"module":"iam","match_access_labels":{"team":"red"},"created_by_subject":null}],"description":"kept"}}`, string(got))
	_, err = replaceSelectorMoveRules(request, json.RawMessage(`{}`))
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}

func TestRoleSelectorMovePrepareReceiptChargesSharedBudget(t *testing.T) {
	budget := &relverdict.AdministrativeReadBudget{}
	require.NoError(t, budget.Charge(99987, 4088))
	for _, raw := range []string{
		`{"access_label_mode":"ordinary","rows":13,"reads":8}`,
		`{"selector_move_transport":"other","access_label_mode":"ordinary","rows":13,"reads":8}`,
		`{"selector_move_transport":"pending_no_copy_v1","access_label_mode":"apply","rows":13,"reads":8}`,
		`{"selector_move_transport":"pending_no_copy_v1","access_label_mode":"ordinary","reads":8}`,
		`{"selector_move_transport":"pending_no_copy_v1","access_label_mode":"ordinary","rows":13,"reads":4}`,
	} {
		require.ErrorIs(t, chargeSelectorMovePrepareReceipt(budget, json.RawMessage(raw)), kaname.ErrSourceUnconfirmed)
	}
	receipt := json.RawMessage(`{"selector_move_transport":"pending_no_copy_v1","access_label_mode":"ordinary","rows":13,"reads":8}`)
	require.NoError(t, chargeSelectorMovePrepareReceipt(budget, receipt))
	require.Zero(t, budget.RemainingRows())
	require.Zero(t, budget.RemainingReads())
	require.ErrorIs(t, chargeSelectorMovePrepareReceipt(budget, receipt), kaname.ErrSourceReadLimit)
}

func TestRoleSelectorMovePendingSourceInputUsesFinalCoordinates(t *testing.T) {
	source, rr, _ := resourceSourceFixture(t)
	require.NoError(t, source.seal())
	owner := resourceSourceWriter(t, source, rr)
	owner.producerBudget = source.budget
	owner.fence.decisionAt = time.Date(2026, 11, 24, 8, 0, 0, 0, time.UTC)
	require.NoError(t, source.lifetime.bind(owner))
	writer := &semanticAuthorityWriteTx{authorityWriteTx: owner, bundle: source.lifetime.bundle}
	account := domain.ResourceRef{Type: "iam.account", ID: "acc_pending"}
	project := domain.ResourceRef{Type: "iam.project", ID: "prj_pending"}
	binding := domain.AccessBinding{
		ID: "acb_pending", RoleID: "rol_pending", Status: domain.AccessBindingStatusPending, ResourceType: "account",
		ResourceID: account.ID, Target: domain.AccessTarget{Resources: []domain.ResourceRef{project}},
	}
	stage := &roleSelectorMoveStage{
		captured: accessLabelSelectorMoveCapture{
			Before:   domain.Role{ID: binding.RoleID},
			Carriers: []accessLabelSelectorMoveScope{{Carrier: accessLabelSelectorMoveCarrier{Binding: binding}}},
			proof:    &accessLabelMoveRRProof{source: source},
		},
		replay: &accessLabelMoveSourceReplay{parents: &resourceParentCapture{source: source}},
	}
	seal, err := stage.recordOwnerDecision(t.Context(), writer, accessLabelMoveCopies{})
	require.NoError(t, err)
	effect := accessLabelMoveBindingEffect{BindingID: binding.ID, Pending: true, Coordinates: []accessLabelMoveCoordinateEffect{
		{Resource: account, Present: true}, {Resource: project, Present: true},
	}}
	decision := roleSelectorMoveAuthorizedChanges{copies: json.RawMessage("[]"), changes: roleSelectorMoveChanges{
		owner: seal, access: accessLabelMoveEffect{Bindings: []accessLabelMoveBindingEffect{effect}},
	}}
	raw, err := decision.pendingSourceInput(t.Context(), writer)
	require.NoError(t, err)
	require.JSONEq(t, `{"acb_pending":[
		{"Resource":{"Type":"iam.account","ID":"acc_pending"},"Present":true,"Before":null,"Proposed":null},
		{"Resource":{"Type":"iam.project","ID":"prj_pending"},"Present":true,"Before":null,"Proposed":null}]}`, string(raw))
	decision.changes.access.Bindings[0].Coordinates[1].Resource = account
	_, err = decision.pendingSourceInput(t.Context(), writer)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	decision.changes.access.Bindings[0].Coordinates[1].Resource = project
	owner.fence.decisionAt = owner.fence.decisionAt.Add(time.Microsecond)
	_, err = decision.pendingSourceInput(t.Context(), writer)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}
