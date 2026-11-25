// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

func TestSelectorMoveGrantBindingSourcesPreserveRecipientsAndCapabilityVersion(t *testing.T) {
	source, tx, _ := resourceSourceFixture(t)
	facts, err := catalog.NewFacts(catalog.Halves{Live: catalog.Rows{
		Modules:   []string{"iam"},
		Resources: []catalog.ResourceRow{{Module: "iam", Resource: "project", ObjectType: "project"}},
		Verbs:     []catalog.VerbRow{{Module: "iam", Resource: "project", Verb: "get", PerObject: true}},
	}})
	require.NoError(t, err)
	before := domain.Role{ID: "rol-moved", Rules: domain.Rules{{
		Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"team": "red"},
	}}}
	before.Lifecycle.State = domain.RoleLifecycleDeclared
	proposed := before.Rules[0]
	proposed.MatchAccessLabels, proposed.MatchLabels = proposed.MatchLabels, nil
	other := before
	other.ID = "rol-other"

	at := time.Date(2026, 11, 24, 18, 0, 0, 0, time.UTC)
	expiry := at.Add(time.Hour)
	target := domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "iam.project", ID: "prj-target"}}}
	subjects := []domain.Subject{{Type: domain.SubjectTypeUser, ID: "usr-a"}, {Type: domain.SubjectTypeGroup, ID: "grp-b"}}
	carrier := func(id domain.AccessBindingID, role domain.RoleID, status domain.AccessBindingStatus, expires *time.Time) accessLabelSelectorMoveScope {
		return accessLabelSelectorMoveScope{Carrier: accessLabelSelectorMoveCarrier{Binding: domain.AccessBinding{
			ID: id, RoleID: role, ResourceType: "account", ResourceID: "acc-own", Scope: domain.ScopeAccount,
			Status: status, ExpiresAt: expires, Target: target, Subjects: subjects,
		}}}
	}
	move := &roleSelectorMoveStage{facts: facts, captured: accessLabelSelectorMoveCapture{
		Before: before, ProposedRules: domain.Rules{proposed}, proof: &accessLabelMoveRRProof{source: source},
		Carriers: []accessLabelSelectorMoveScope{
			carrier("acb-pending", before.ID, domain.AccessBindingStatusPending, &expiry),
			carrier("acb-expires-now", before.ID, domain.AccessBindingStatusActive, &at),
		},
		Collateral: []accessLabelSelectorMoveScope{carrier("acb-other", other.ID, domain.AccessBindingStatusActive, nil)},
	}, replay: &accessLabelMoveSourceReplay{parents: &resourceParentCapture{source: source}}}
	source.entries[resourceSourceKey{kind: resourceSourceRoleBindings, typ: "role", id: string(before.ID)}] = []resourceSourceRow{
		{value: json.RawMessage(`{"id":"acb-expires-now","role_id":"rol-moved","grant_capability_version":0}`)},
		{value: json.RawMessage(`{"id":"acb-pending","role_id":"rol-moved","grant_capability_version":1}`)},
	}
	source.entries[resourceSourceKey{kind: resourceSourceBinding, typ: "binding", id: "acb-other"}] = []resourceSourceRow{
		{value: json.RawMessage(`{"id":"acb-other","role_id":"rol-other","grant_capability_version":0}`)},
	}
	require.NoError(t, source.seal())
	owner := resourceSourceWriter(t, source, tx)
	owner.fence.decisionAt, owner.producerBudget = at, source.budget
	writer := &semanticAuthorityWriteTx{authorityWriteTx: owner, bundle: source.lifetime.bundle}
	require.NoError(t, source.lifetime.bind(owner))
	projections := roleSelectorMoveGrantProjections{move: move, writer: owner, roles: map[domain.RoleID]roleSelectorMoveGrantProjection{
		before.ID: {role: before, confirmed: true},
		other.ID:  {role: other, confirmed: true},
	}}
	effects := []accessLabelMoveBindingEffect{{BindingID: "acb-pending", Pending: true}, {BindingID: "acb-expires-now"}, {BindingID: "acb-other"}}
	sources, err := move.grantBindingSources(t.Context(), writer, projections, effects)
	require.NoError(t, err)
	require.Len(t, sources, 4)
	for i, recipient := range subjects {
		pending, collateral := sources[i], sources[i+len(subjects)]
		require.Equal(t, "acb-pending", pending.Before.SourceID)
		require.Equal(t, domain.ScopeAnchor{Type: "account", ID: "acc-own"}, pending.Before.Scope)
		require.Equal(t, target, pending.Before.Target)
		require.Equal(t, before.Rules, pending.Before.Role.Rules)
		require.Equal(t, domain.Rules{proposed}, pending.After.Role.Rules)
		require.Equal(t, subjects, pending.Before.Subjects)
		require.Equal(t, subjects, pending.After.Subjects)
		require.Equal(t, recipient, pending.Before.Recipient)
		require.Equal(t, recipient, pending.After.Recipient)
		require.Equal(t, 1, pending.Before.CapabilityVersion)
		require.Equal(t, 1, pending.After.CapabilityVersion)
		require.True(t, pending.Changes)
		require.True(t, pending.Pending)
		require.Equal(t, &expiry, pending.ExpiresAt)
		require.Equal(t, "acb-other", collateral.Before.SourceID)
		require.Equal(t, recipient, collateral.Before.Recipient)
		require.Equal(t, 0, collateral.Before.CapabilityVersion)
		require.Equal(t, collateral.Before, collateral.After)
		require.False(t, collateral.Changes)
		require.False(t, collateral.Pending)
		require.Nil(t, collateral.ExpiresAt)
	}

	projections.roles[other.ID] = roleSelectorMoveGrantProjection{role: other}
	sources, err = move.grantBindingSources(t.Context(), writer, projections, effects)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "пустой физический diff соседней роли не подтверждает будущий эффект")
	require.Nil(t, sources)
}
