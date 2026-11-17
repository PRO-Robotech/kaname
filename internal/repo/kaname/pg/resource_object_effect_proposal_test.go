// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/stretchr/testify/require"
)

func resourceEffectProposalFixture() (*resourceObjectPreparation, domain.MembershipTuple) {
	tuple := domain.MembershipTuple{User: "user:user", Relation: "v_get", Object: "network:network"}
	coord := reconcile.MemberCoord{ObjectType: "vpc.network", ObjectID: "network"}
	old := reconcile.CapturedObjectDiff{Binding: reconcile.BindingScope{BindingID: "old", RoleID: "role", Active: true, Subjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: "user"}}},
		Current: []domain.TargetMember{{BindingID: "old", RoleID: "role", RuleFP: "old-rule", ObjectType: coord.ObjectType, ObjectID: coord.ObjectID, VerificationStatus: domain.VerificationActive}},
		Ledger:  []reconcile.LedgerRow{{Member: coord, Tuple: tuple}}, Live: map[reconcile.MemberCoord]bool{coord: true}}
	fresh := reconcile.CapturedObjectDiff{Binding: reconcile.BindingScope{BindingID: "new", RoleID: "role", Active: true, Subjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: "user"}}}, Additive: true,
		Desired: []reconcile.DesiredMember{{Derivation: "ordinary", RuleFP: "new-rule", ObjectType: coord.ObjectType, ObjectID: coord.ObjectID, Status: domain.VerificationActive, Tuples: []domain.MembershipTuple{tuple}}},
		Live:    map[reconcile.MemberCoord]bool{coord: true}}
	return &resourceObjectPreparation{source: &resourceSourceCapture{budget: &relverdict.AdministrativeReadBudget{}, entries: map[resourceSourceKey][]resourceSourceRow{
		{kind: resourceSourceRoleSelectors, typ: "role", id: "role"}:            {},
		{kind: resourceSourceMirror, typ: coord.ObjectType, id: coord.ObjectID}: {},
	}}, root: &resourceOutputCapture{bindings: map[string]domain.AccessBinding{"old": {ID: "old", RoleID: "role"}, "new": {ID: "new", RoleID: "role"}}},
		inputs: []reconcile.CapturedObjectDiff{old, fresh}}, tuple
}

// Это pure preflight-проверка набора возможных эффектов. Пустые свидетели здесь
// не проходят SQL verifier и не доказывают разрешение выдачи.
func TestResourceEffectProposalPreholdsDeleteReleasedByExpiredOtherCarrier(t *testing.T) {
	p, tuple := resourceEffectProposalFixture()
	live, err := reconcile.CompileCapturedObjectDiff(context.Background(), p.inputs)
	require.NoError(t, err)
	for _, command := range live {
		require.NotEqual(t, "delete", command.Kind)
	}
	proposal, err := compileResourceObjectEffectProposal(context.Background(), p)
	require.NoError(t, err)
	var heldDelete bool
	for _, binding := range proposal.Bindings {
		for _, command := range binding.Live {
			if command.Kind == "delete" {
				require.Contains(t, command.Tuples, tuple)
				heldDelete = true
			}
		}
	}
	require.True(t, heldDelete, "prewait должен покрыть delete, подавленный в общем RR diff")
	p.inputs[1].Binding.Active = false
	afterExpiry, err := reconcile.CompileCapturedObjectDiff(context.Background(), p.inputs)
	require.NoError(t, err)
	var actualDelete bool
	for _, command := range afterExpiry {
		if command.Kind == "delete" {
			require.Contains(t, command.Tuples, tuple)
			actualDelete = true
		}
	}
	require.True(t, actualDelete, "утрата write claim другого носителя добавляет delete")
	require.False(t, p.source.sealed, "effect proposal не является private SQL manifest")
}

func TestResourceEffectProposalRejectsMissingWitnessAndCancelledCapture(t *testing.T) {
	for _, key := range []resourceSourceKey{{kind: resourceSourceRoleSelectors, typ: "role", id: "role"}, {kind: resourceSourceMirror, typ: "vpc.network", id: "network"}} {
		p, _ := resourceEffectProposalFixture()
		delete(p.source.entries, key)
		_, err := compileResourceObjectEffectProposal(context.Background(), p)
		require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	}
	p, _ := resourceEffectProposalFixture()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := compileResourceObjectEffectProposal(ctx, p)
	require.ErrorIs(t, err, context.Canceled)
}

func TestResourceEffectProposalRejectsUnclassifiedDerivation(t *testing.T) {
	for _, branch := range []string{"", "source", "service_account_insert"} {
		t.Run(branch, func(t *testing.T) {
			p, _ := resourceEffectProposalFixture()
			p.inputs[1].Desired[0].Derivation = branch
			_, err := compileResourceObjectEffectProposal(context.Background(), p)
			require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
		})
	}
}
