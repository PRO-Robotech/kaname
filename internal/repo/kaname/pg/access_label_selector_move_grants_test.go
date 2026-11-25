// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/resourceeffect"
	"github.com/stretchr/testify/require"
)

func selectorMoveGrantScope(id domain.AccessBindingID, role domain.RoleID, status domain.AccessBindingStatus, expiry *time.Time, subjects ...domain.Subject) accessLabelSelectorMoveScope {
	b := domain.AccessBinding{
		ID: id, RoleID: role, ResourceType: "account", ResourceID: "acc-one", Scope: domain.ScopeAccount,
		Status: status, ExpiresAt: expiry, Subjects: subjects,
	}
	scope := reconcile.BindingScope{BindingID: b.ID, RoleID: string(role), Subjects: subjects, Scope: scopeAnchorFor(b)}
	return accessLabelSelectorMoveScope{
		Carrier: accessLabelSelectorMoveCarrier{Binding: b}, Before: scope, Proposed: scope,
		Coordinates: []domain.ResourceRef{{Type: "iam.project", ID: "prj-one"}},
	}
}

func selectorMoveGrantEffect(scope accessLabelSelectorMoveScope, pending bool, before, proposed []resourceeffect.ObjectDesiredMember) accessLabelMoveBindingEffect {
	return accessLabelMoveBindingEffect{BindingID: scope.Carrier.Binding.ID, Pending: pending,
		Coordinates: []accessLabelMoveCoordinateEffect{{Resource: scope.Coordinates[0], Present: true, Before: before, Proposed: proposed}}}
}

func selectorMoveGrantMembers(tuples ...domain.MembershipTuple) []resourceeffect.ObjectDesiredMember {
	return []resourceeffect.ObjectDesiredMember{{
		ObjectType: "iam.project", ObjectID: "prj-one", RuleFP: "rule", Derivation: "ordinary",
		Status: domain.VerificationActive, Tuples: tuples,
	}}
}

func TestAccessLabelMoveGrantResidualRequiresMatchingLifetime(t *testing.T) {
	at := time.Date(2026, 11, 24, 8, 0, 0, 0, time.UTC)
	short, long := at.Add(time.Hour), at.Add(2*time.Hour)
	subject := domain.Subject{Type: domain.SubjectTypeGroup, ID: "team"}
	tuple := domain.MembershipTuple{User: "group:team#member", Relation: "viewer", Object: "project:prj-one"}
	for _, tc := range []struct {
		name                     string
		priorStatus, grantStatus domain.AccessBindingStatus
		priorExpiry, grantExpiry *time.Time
		wantResidual             bool
	}{
		{"active covers equal expiry", domain.AccessBindingStatusActive, domain.AccessBindingStatusPending, &short, &short, false},
		{"active covers shorter", domain.AccessBindingStatusActive, domain.AccessBindingStatusActive, &long, &short, false},
		{"permanent covers permanent", domain.AccessBindingStatusActive, domain.AccessBindingStatusPending, nil, nil, false},
		{"shorter cannot cover longer", domain.AccessBindingStatusActive, domain.AccessBindingStatusActive, &short, &long, true},
		{"finite cannot cover permanent", domain.AccessBindingStatusActive, domain.AccessBindingStatusPending, &long, nil, true},
		{"other pending cannot cover active", domain.AccessBindingStatusPending, domain.AccessBindingStatusActive, nil, &short, true},
		{"other pending cannot cover pending", domain.AccessBindingStatusPending, domain.AccessBindingStatusPending, nil, nil, true},
		{"expired at decision", domain.AccessBindingStatusActive, domain.AccessBindingStatusActive, &at, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prior := selectorMoveGrantScope("source", "moved", tc.priorStatus, tc.priorExpiry, subject)
			grant := selectorMoveGrantScope("wanted", "foreign", tc.grantStatus, tc.grantExpiry, subject)
			// Даже запись ACTIVE в журнале не подтверждает прежний эффект носителя.
			grant.Carrier.Ledger = []reconcile.LedgerRow{{Tuple: tuple}}
			capture := accessLabelSelectorMoveCapture{Before: domain.Role{ID: "moved"},
				Carriers: []accessLabelSelectorMoveScope{prior}, Collateral: []accessLabelSelectorMoveScope{grant}}
			var before []resourceeffect.ObjectDesiredMember
			if prior.Carrier.canSelectAt(at) {
				before = selectorMoveGrantMembers(tuple)
			}
			had := selectorMoveGrantEffect(prior, tc.priorStatus == domain.AccessBindingStatusPending, before, nil)
			pending := tc.grantStatus == domain.AccessBindingStatusPending
			wanted := selectorMoveGrantEffect(grant, pending, nil, selectorMoveGrantMembers(tuple, tuple))
			got, err := accessLabelMoveGrantResidual(t.Context(), capture, []accessLabelMoveBindingEffect{wanted, had}, at, &relverdict.AdministrativeReadBudget{})
			require.NoError(t, err)
			if !tc.wantResidual {
				require.Empty(t, got)
				return
			}
			require.Equal(t, []accessLabelMoveGrant{{
				BindingID: "wanted", RoleID: "foreign", Scope: grant.Before.Scope, Recipient: subject, Tuple: tuple,
				Pending: pending, ExpiresAt: tc.grantExpiry,
			}}, got)
		})
	}
}

func TestAccessLabelMoveGrantResidualDistinguishesTypedRecipientsAndCarriers(t *testing.T) {
	at := time.Now().UTC()
	user := domain.Subject{Type: domain.SubjectTypeUser, ID: "same"}
	group := domain.Subject{Type: domain.SubjectTypeGroup, ID: "same"}
	before := domain.MembershipTuple{User: "user:same", Relation: "viewer", Object: "project:prj-one"}
	after := before
	after.User = "group:same#member"
	moved := selectorMoveGrantScope("first", "moved", domain.AccessBindingStatusPending, nil, user, group)
	foreign := selectorMoveGrantScope("second", "foreign", domain.AccessBindingStatusPending, nil, group)
	capture := accessLabelSelectorMoveCapture{Before: domain.Role{ID: "moved"},
		Carriers: []accessLabelSelectorMoveScope{moved}, Collateral: []accessLabelSelectorMoveScope{foreign}}
	effects := []accessLabelMoveBindingEffect{
		selectorMoveGrantEffect(moved, true, selectorMoveGrantMembers(before), selectorMoveGrantMembers(before, after)),
		selectorMoveGrantEffect(foreign, true, nil, selectorMoveGrantMembers(after)),
	}
	got, err := accessLabelMoveGrantResidual(t.Context(), capture, effects, at, &relverdict.AdministrativeReadBudget{})
	require.NoError(t, err)
	require.Equal(t, []accessLabelMoveGrant{
		{BindingID: "first", RoleID: "moved", Scope: moved.Before.Scope, Recipient: group, Tuple: after, Pending: true},
		{BindingID: "second", RoleID: "foreign", Scope: foreign.Before.Scope, Recipient: group, Tuple: after, Pending: true},
	}, got)
}

func TestAccessLabelMoveGrantResidualRejectsIncompleteCensus(t *testing.T) {
	at := time.Now().UTC()
	user := domain.Subject{Type: domain.SubjectTypeUser, ID: "same"}
	scope := selectorMoveGrantScope("one", "moved", domain.AccessBindingStatusActive, nil, user)
	capture := accessLabelSelectorMoveCapture{Before: domain.Role{ID: "moved"}, Carriers: []accessLabelSelectorMoveScope{scope}}
	bad := domain.MembershipTuple{User: "group:same#member", Relation: "viewer", Object: "project:prj-one"}
	good := domain.MembershipTuple{User: "user:same", Relation: "viewer", Object: "project:prj-one"}
	missing := selectorMoveGrantEffect(scope, false, nil, selectorMoveGrantMembers(good))
	missing.Coordinates[0].Present = false
	foreign := selectorMoveGrantMembers(good)
	foreign[0].ObjectID = "prj-other"
	rejected := selectorMoveGrantMembers(good)
	rejected[0].Status = domain.VerificationRejected
	for _, effects := range [][]accessLabelMoveBindingEffect{
		nil,
		{{BindingID: "another"}},
		{{BindingID: "one", Pending: true}},
		{{BindingID: "one"}},
		{selectorMoveGrantEffect(scope, false, nil, selectorMoveGrantMembers(bad))},
		{selectorMoveGrantEffect(scope, false, rejected, nil)},
		{selectorMoveGrantEffect(scope, false, nil, foreign)},
		{missing},
	} {
		got, err := accessLabelMoveGrantResidual(t.Context(), capture, effects, at, &relverdict.AdministrativeReadBudget{})
		require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
		require.Nil(t, got)
	}
	work := &relverdict.AdministrativeReadBudget{}
	require.NoError(t, work.Charge(work.RemainingRows(), 0))
	valid := []accessLabelMoveBindingEffect{selectorMoveGrantEffect(scope, false, nil, nil)}
	got, err := accessLabelMoveGrantResidual(t.Context(), capture, valid, at, work)
	require.ErrorIs(t, err, relverdict.ErrAdministrativeSourceLimit)
	require.Nil(t, got)
	expired := capture.Carriers[0]
	expired.Carrier.Binding.ExpiresAt = &at
	capture.Carriers = []accessLabelSelectorMoveScope{expired}
	work = &relverdict.AdministrativeReadBudget{}
	require.NoError(t, work.Charge(work.RemainingRows()-1, 0))
	got, err = accessLabelMoveGrantResidual(t.Context(), capture, valid, at, work)
	require.ErrorIs(t, err, relverdict.ErrAdministrativeSourceLimit, "пустая координата истёкшей выдачи считается в общем бюджете")
	require.Nil(t, got)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	got, err = accessLabelMoveGrantResidual(ctx, capture, valid, at, &relverdict.AdministrativeReadBudget{})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, got)
}
