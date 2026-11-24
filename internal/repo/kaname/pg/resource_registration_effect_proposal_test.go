// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/resourceeffect"
	"github.com/stretchr/testify/require"
)

func TestResourceRegistrationProposal_RetentionAbsenceIsNotEmptyProof(t *testing.T) {
	// Production constructor требует общий ограниченный бюджет даже для pure proposal.
	source := &resourceSourceCapture{budget: &relverdict.AdministrativeReadBudget{}}
	parents := &resourceParentCapture{source: source}
	registration := &resourceRegistrationPreparation{input: kaname.ResourceDecisionIntent{Action: kaname.ResourceDecisionUnregister}, parents: parents}
	withdrawal := &resourceWithdrawalBody{preparation: registration,
		plan: resourceeffect.WithdrawalPlan{Steps: []resourceeffect.WithdrawalStep{{
			Roles: []resourceeffect.RoleWithdrawal{{ID: "role-a", Retain: &resourceeffect.CapabilityRetention{}}},
		}}}, retained: map[resourceWithdrawalRoleStep][]domain.GrantCapabilityRule{}}
	unregistration := &resourceUnregistrationPreparation{registration: registration, withdrawal: withdrawal,
		root: resourceUnregisteredObject{modelType: "probe_item", id: "x", catalog: resourceCatalogRow{
			identity: domain.CatalogTypeIdentity{Dotted: "probe.items", ObjectType: "probe_item"}}}}
	stage := &resourceRegistrationStage{registration: registration, unregistration: unregistration, source: source}
	_, err := makeResourceRegistrationEffectProposal(stage)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "missing retention must not serialize as an empty safe projection")
	withdrawal.retained[resourceWithdrawalRoleStep{step: 0, role: "role-a"}] = []domain.GrantCapabilityRule{}
	proposal, err := makeResourceRegistrationEffectProposal(stage)
	require.NoError(t, err)
	require.Len(t, proposal.Retained, 1)
	require.Equal(t, domain.RoleID("role-a"), proposal.Retained[0].Role)
	require.Empty(t, proposal.Retained[0].Rules)
	withdrawal.retained[resourceWithdrawalRoleStep{step: 0, role: "foreign-role"}] = []domain.GrantCapabilityRule{}
	_, err = makeResourceRegistrationEffectProposal(stage)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "unreferenced retention must not cross the closed proposal")
	delete(withdrawal.retained, resourceWithdrawalRoleStep{step: 0, role: "foreign-role"})
	source.sealed = true
	_, err = makeResourceRegistrationEffectProposal(stage)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "no new effect program after source sealing")
}
