// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/stretchr/testify/require"
)

func TestAccessLabelSelectorMoveCountsEffectsAcrossBindings(t *testing.T) {
	facts, err := catalog.NewFacts(catalog.Halves{Live: catalog.Rows{
		Modules:   []string{"iam"},
		Resources: []catalog.ResourceRow{{Module: "iam", Resource: "project", ObjectType: "project"}},
		Verbs:     []catalog.VerbRow{{Module: "iam", Resource: "project", Verb: "get", PerObject: true}},
	}})
	require.NoError(t, err)
	legacy := domain.Rules{{
		Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"team": "red"},
	}}
	moves := []domain.AccessLabelSelectorMove{{RuleIndex: 0, Fingerprint: legacy[0].Fingerprint()}}
	protected, predicates, err := legacy.PlanAccessLabelSelectorMoves(moves, domain.PolicyOfRole(false, ""), facts)
	require.NoError(t, err)

	copyKey := domain.ResourceRef{Type: "iam.project", ID: "prj-copy"}
	removedKey := domain.ResourceRef{Type: "iam.project", ID: "prj-no-copy"}
	absentKey := domain.ResourceRef{Type: "iam.project", ID: "prj-absent"}
	graphs := make(map[domain.ResourceRef]accessLabelMoveGraph)
	graphs[absentKey] = accessLabelMoveGraph{}
	for _, key := range []domain.ResourceRef{copyKey, removedKey} {
		graphs[key] = accessLabelMoveGraph{Present: true, Object: domain.MirrorObject{
			ObjectType: key.Type, ObjectID: key.ID, ParentAccountIDs: []string{"acc-move"},
			Labels: map[string]string{"team": "red"}, AccessLabels: map[string]string{"owner": "support"},
		}}
	}
	targets := map[domain.ResourceRef][]int{copyKey: {0}}
	copies, err := planAccessLabelMoveCopies(t.Context(), predicates, targets, graphs, &relverdict.AdministrativeReadBudget{})
	require.NoError(t, err)
	require.Equal(t, accessLabelMoveCopies{copyKey: {"team": "red", "owner": "support"}}, copies.labels)
	require.Equal(t, map[string]string{"owner": "support"}, graphs[copyKey].Object.AccessLabels)

	carrier := func(id domain.AccessBindingID, roleID domain.RoleID, subject string, before, after domain.Rules, coordinates ...domain.ResourceRef) accessLabelSelectorMoveScope {
		role := domain.Role{ID: roleID, Rules: before}
		role.Lifecycle.State = domain.RoleLifecycleDeclared
		proposed := role
		proposed.Rules = after
		binding := domain.AccessBinding{
			ID: id, RoleID: roleID, ResourceType: "account", ResourceID: "acc-move",
			Scope: domain.ScopeAccount, Status: domain.AccessBindingStatusActive,
			SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(subject),
		}
		return accessLabelSelectorMoveScope{
			Carrier: accessLabelSelectorMoveCarrier{Binding: binding},
			Before:  bindingScopeFrom(facts, binding, role), Proposed: bindingScopeFrom(facts, binding, proposed),
			Coordinates: coordinates,
		}
	}
	decision := time.Date(2026, 11, 24, 8, 0, 0, 0, time.UTC)
	moved := carrier("acb-moved", "rol-moved", "usr-original", legacy, protected, copyKey, removedKey, absentKey)
	for _, ref := range []domain.ResourceRef{copyKey, removedKey} {
		moved.Carrier.Members = append(moved.Carrier.Members, domain.TargetMember{
			BindingID: moved.Carrier.Binding.ID, RoleID: moved.Carrier.Binding.RoleID,
			RuleFP: legacy[0].Fingerprint(), ObjectType: ref.Type, ObjectID: ref.ID,
			VerificationStatus: domain.VerificationActive,
		})
		for _, relation := range []string{"v_get", "viewer"} {
			moved.Carrier.Ledger = append(moved.Carrier.Ledger, reconcile.LedgerRow{
				Member: reconcile.MemberCoord{ObjectType: ref.Type, ObjectID: ref.ID},
				Tuple:  domain.MembershipTuple{User: "user:usr-original", Relation: relation, Object: "project:" + ref.ID},
			})
		}
	}
	expired := carrier("acb-expired", "rol-moved", "usr-expired", legacy, protected, copyKey, removedKey)
	expired.Carrier.Binding.ExpiresAt = &decision
	stale := domain.MembershipTuple{User: "user:usr-expired", Relation: "v_get", Object: "project:prj-copy"}
	shared := domain.MembershipTuple{User: "user:usr-original", Relation: "v_get", Object: "project:prj-copy"}
	for _, tuple := range []domain.MembershipTuple{stale, shared} {
		expired.Carrier.Ledger = append(expired.Carrier.Ledger, reconcile.LedgerRow{
			Member: reconcile.MemberCoord{ObjectType: copyKey.Type, ObjectID: copyKey.ID}, Tuple: tuple,
		})
	}
	expired.Carrier.Ledger = append(expired.Carrier.Ledger, moved.Carrier.Ledger[2])
	neighbor := carrier("acb-neighbor", "rol-neighbor", "usr-neighbor", protected, protected, copyKey, removedKey)
	orphan := reconcile.LedgerRow{
		Member: reconcile.MemberCoord{ObjectType: removedKey.Type, ObjectID: removedKey.ID},
		Tuple:  domain.MembershipTuple{User: "user:usr-neighbor", Relation: "v_get", Object: "project:prj-no-copy"},
	}
	surplus := reconcile.LedgerRow{
		Member: reconcile.MemberCoord{ObjectType: copyKey.Type, ObjectID: copyKey.ID},
		Tuple:  domain.MembershipTuple{User: "user:usr-neighbor", Relation: "v_update", Object: "project:prj-copy"},
	}
	neighbor.Carrier.Members = []domain.TargetMember{{
		BindingID: neighbor.Carrier.Binding.ID, RoleID: neighbor.Carrier.Binding.RoleID,
		RuleFP: protected[0].Fingerprint(), ObjectType: copyKey.Type, ObjectID: copyKey.ID,
		VerificationStatus: domain.VerificationActive,
	}}
	neighbor.Carrier.Ledger = []reconcile.LedgerRow{orphan, surplus}
	pending := carrier("acb-pending", "rol-neighbor", "usr-pending", protected, protected, copyKey)
	pending.Carrier.Binding.Status = domain.AccessBindingStatusPending
	pending.Before.Active, pending.Proposed.Active = false, false
	scopes := []accessLabelSelectorMoveScope{moved, neighbor, expired, pending}
	effect, err := compileAccessLabelMoveEffect(t.Context(), facts, scopes, graphs, copies, nil, decision, &relverdict.AdministrativeReadBudget{})
	require.NoError(t, err)
	require.Equal(t, []domain.MembershipTuple{
		{User: "user:usr-neighbor", Relation: "v_get", Object: "project:prj-copy"},
		{User: "user:usr-neighbor", Relation: "viewer", Object: "project:prj-copy"},
	}, effect.Added, "копия может расширить права другой роли с прежним защищённым селектором")
	require.Equal(t, []domain.MembershipTuple{
		{User: "user:usr-original", Relation: "v_get", Object: "project:prj-no-copy"},
		{User: "user:usr-original", Relation: "viewer", Object: "project:prj-no-copy"},
	}, effect.Removed)
	require.Len(t, effect.Bindings, 4)
	pendingEffect := effect.Bindings[3]
	require.True(t, pendingEffect.Pending)
	require.Len(t, pendingEffect.Coordinates, 1)
	require.Empty(t, pendingEffect.Coordinates[0].Before)
	require.Len(t, pendingEffect.Coordinates[0].Proposed, 1, "будущий доступ отдельно измерен")
	require.Contains(t, pendingEffect.Coordinates[0].Proposed[0].Tuples, domain.MembershipTuple{
		User: "user:usr-pending", Relation: "v_get", Object: "project:prj-copy",
	})
	coordinates := effect.Bindings[0].Coordinates
	require.Len(t, coordinates, 3)
	require.Equal(t, copyKey, coordinates[0].Resource)
	require.True(t, coordinates[0].Present)
	require.Len(t, coordinates[0].Before, 1)
	require.Len(t, coordinates[0].Proposed, 1)
	require.Equal(t, coordinates[0].Before[0].Tuples, coordinates[0].Proposed[0].Tuples)
	require.NotEqual(t, coordinates[0].Before[0].RuleFP, coordinates[0].Proposed[0].RuleFP)
	require.Equal(t, removedKey, coordinates[1].Resource)
	require.True(t, coordinates[1].Present)
	require.Len(t, coordinates[1].Before, 1)
	require.Empty(t, coordinates[1].Proposed)
	require.Equal(t, accessLabelMoveCoordinateEffect{Resource: absentKey}, coordinates[2])
	require.Equal(t, []domain.MembershipTuple{stale, orphan.Tuple}, effect.ResidualFold)
	var removedFP, addedFP string
	var forgotten []reconcile.LedgerRow
	var deletes []domain.MembershipTuple
	for _, command := range effect.Commands {
		require.NotEqual(t, expired.Carrier.Binding.ID, command.Binding, "историческая выдача остаётся в хранилище")
		require.NotEqual(t, pending.Carrier.Binding.ID, command.Binding, "ожидающая выдача не сверяется как действующая")
		switch command.Kind {
		case "members":
			for _, member := range command.Members {
				require.NotEqual(t, expired.Carrier.Binding.ID, member.BindingID)
				require.NotEqual(t, pending.Carrier.Binding.ID, member.BindingID)
				if member.BindingID == moved.Carrier.Binding.ID && member.ObjectID == copyKey.ID {
					addedFP = member.RuleFP
				}
			}
		case "member_delete":
			if command.Binding == moved.Carrier.Binding.ID && command.Member.ObjectID == copyKey.ID {
				removedFP = command.RuleFP
			}
		case "record":
			for _, ref := range command.Refs {
				require.NotEqual(t, expired.Carrier.Binding.ID, ref.BindingID)
				require.NotEqual(t, pending.Carrier.Binding.ID, ref.BindingID)
			}
		case "forget":
			if command.Binding == neighbor.Carrier.Binding.ID {
				forgotten = append(forgotten, command.Rows...)
			}
		case "delete":
			deletes = append(deletes, command.Tuples...)
		}
	}
	require.ElementsMatch(t, []reconcile.LedgerRow{orphan, surplus}, forgotten)
	require.Equal(t, protected[0].Fingerprint(), addedFP)
	require.Equal(t, legacy[0].Fingerprint(), removedFP)
	wantDeletes := append([]domain.MembershipTuple{surplus.Tuple}, effect.Removed...)
	require.ElementsMatch(t, wantDeletes, deletes, "смена отпечатка не отзывает сохранившееся право")

	heldByOtherGrant, err := compileAccessLabelMoveEffect(t.Context(), facts, scopes, graphs, copies,
		effect.Removed, decision, &relverdict.AdministrativeReadBudget{})
	require.NoError(t, err)
	require.Empty(t, heldByOtherGrant.Removed, "сохраняем кортежи неизменного источника")
	require.Equal(t, effect.Added, heldByOtherGrant.Added)

	invalidCopies := accessLabelMoveCopies{copyKey: {"team": "blue", "owner": "support"}}
	_, err = compileAccessLabelMoveEffect(t.Context(), facts, scopes, graphs, accessLabelMoveCopyPlan{labels: invalidCopies}, nil,
		decision, &relverdict.AdministrativeReadBudget{})
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}

func TestAccessLabelMoveNewForeignMatchProducesRejectedAudit(t *testing.T) {
	facts, err := catalog.NewFacts(catalog.Halves{Live: catalog.Rows{
		Modules:   []string{"iam"},
		Resources: []catalog.ResourceRow{{Module: "iam", Resource: "project", ObjectType: "project"}},
		Verbs:     []catalog.VerbRow{{Module: "iam", Resource: "project", Verb: "get", PerObject: true}},
	}})
	require.NoError(t, err)
	ref := domain.ResourceRef{Type: "iam.project", ID: "prj-copied"}
	old := domain.MirrorObject{ObjectType: ref.Type, ObjectID: ref.ID, ParentAccountIDs: []string{"acc-other"},
		Labels: map[string]string{"team": "blue"}}
	copies := accessLabelMoveCopies{ref: {"team": "blue"}}
	role := domain.Role{ID: "rol-neighbor", Rules: domain.Rules{{
		Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}, MatchAccessLabels: copies[ref],
	}}}
	role.Lifecycle.State = domain.RoleLifecycleDeclared
	for _, tc := range []struct {
		name    string
		target  domain.AccessTarget
		matches bool
	}{
		{"вся область", domain.AccessTarget{AllInScope: true}, true},
		{"цель называет чужой объект", domain.AccessTarget{Resources: []domain.ResourceRef{ref}}, true},
		{"цель называет другой объект", domain.AccessTarget{Resources: []domain.ResourceRef{{Type: ref.Type, ID: "prj-elsewhere"}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := parentCaptureFixture(t)
			binding := domain.AccessBinding{ID: "acb-neighbor", RoleID: role.ID, ResourceType: "account", ResourceID: "acc-home",
				Scope: domain.ScopeAccount, Target: tc.target, Status: domain.AccessBindingStatusActive, SubjectType: domain.SubjectTypeUser, SubjectID: "usr-neighbor"}
			scope := bindingScopeFrom(facts, binding, role)
			coordinates, err := p.captureAccessLabelMoveCarrierOverlay(t.Context(), scope, map[string][]domain.MirrorObject{
				ref.Type: {overlaySelectorMoveLabels(old, copies)},
			})
			require.NoError(t, err)
			if !tc.matches {
				require.Empty(t, coordinates)
				return
			}
			require.Equal(t, []domain.ResourceRef{ref}, coordinates)
			effect, err := compileAccessLabelMoveEffect(t.Context(), facts, []accessLabelSelectorMoveScope{{
				Carrier: accessLabelSelectorMoveCarrier{Binding: binding}, Before: scope, Proposed: scope, Coordinates: coordinates,
			}}, map[domain.ResourceRef]accessLabelMoveGraph{ref: {Object: old, Present: true}}, accessLabelMoveCopyPlan{labels: copies}, nil, time.Unix(123456, 0), p.source.budget)
			require.NoError(t, err)
			require.Len(t, effect.Bindings, 1)
			require.Len(t, effect.Bindings[0].Coordinates, 1)
			require.Empty(t, effect.Bindings[0].Coordinates[0].Before)
			require.Empty(t, effect.Added)
			require.Len(t, effect.Commands, 2)
			require.Equal(t, "members", effect.Commands[0].Kind)
			require.Equal(t, []domain.TargetMember{{BindingID: binding.ID, RoleID: role.ID, RuleFP: role.Rules[0].Fingerprint(),
				ObjectType: ref.Type, ObjectID: ref.ID, VerificationStatus: domain.VerificationRejected}}, effect.Commands[0].Members)
			require.Equal(t, reconcile.BindingCommand{Kind: "audit", Binding: binding.ID,
				Member: reconcile.MemberCoord{ObjectType: ref.Type, ObjectID: ref.ID}, Scope: scope.Scope}, effect.Commands[1])
		})
	}
}
