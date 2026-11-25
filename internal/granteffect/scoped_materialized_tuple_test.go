// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/stretchr/testify/require"
)

func TestScopedMaterializedTupleOrdinaryWitnessUsesOnlyOldLabels(t *testing.T) {
	b := bundleCanon(t)
	old := domain.MirrorObject{ObjectType: "iam.account", ObjectID: "acc-a", ParentAccountIDs: []string{"acc-a"},
		Labels: map[string]string{"team": "blue"}, AccessLabels: map[string]string{"retained": "yes"}}
	recipient := domain.Subject{Type: domain.SubjectTypeGroup, ID: "team"}
	tuple := domain.MembershipTuple{User: "group:team#member", Relation: "v_get", Object: "account:acc-a"}
	scope := domain.ScopeAnchor{Type: "account", ID: "acc-a"}
	physical := complete(t, b.CompileScopedMaterializedTuple("binding", old, scope, recipient, tuple))

	// Изменение исходных карт после компиляции не добавляет фактов в снимок.
	old.AccessLabels["team"] = "blue"
	for _, tc := range []struct {
		name   string
		labels map[string]string
		access map[string]string
		scope  domain.ScopeAnchor
		want   bool
	}{
		{"ordinary OLD label", map[string]string{"team": "blue"}, nil, scope, true},
		{"retained access label", nil, map[string]string{"retained": "yes"}, scope, true},
		{"newly copied access label", nil, map[string]string{"team": "blue"}, scope, false},
		{"other ordinary label", map[string]string{"team": "red"}, nil, scope, false},
		{"other binding scope", map[string]string{"team": "blue"}, nil, domain.ScopeAnchor{Type: "account", ID: "acc-other"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actor := binding(domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"},
				MatchLabels: tc.labels, MatchAccessLabels: tc.access})
			actor.Scope = tc.scope
			actor.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: old.ObjectType, ID: old.ObjectID}}}
			proves(t, complete(t, b.Compile(actor)), physical, tc.want)
		})
	}
}

func TestScopedMaterializedTupleRetainsPrimitiveOnInheritedPaths(t *testing.T) {
	b := bundleCanon(t)
	old := domain.MirrorObject{ObjectType: "iam.account", ObjectID: "acc-a", ParentAccountIDs: []string{"acc-a"},
		Labels: map[string]string{"team": "blue"}}
	scope := domain.ScopeAnchor{Type: "account", ID: "acc-a"}
	recipient := domain.Subject{Type: domain.SubjectTypeUser, ID: "alice"}
	tuple := domain.MembershipTuple{User: "user:alice", Relation: "admin", Object: "account:acc-a"}
	physical := complete(t, b.CompileScopedMaterializedTuple("binding", old, scope, recipient, tuple))
	found := false
	for _, effect := range physical.Effects() {
		require.Len(t, effect.Constraints, 1)
		c := effect.Constraints[0]
		require.Equal(t, "account", c.Type)
		require.Equal(t, grantcoverage.Objects{Kind: grantcoverage.ObjectIDs, IDs: []string{old.ObjectID}}, c.Region.Objects)
		require.Equal(t, &scope, c.Within)
		require.Equal(t, old.Labels, c.Region.Labels)
		if effect.Type == "project" && effect.Action == (grantcoverage.Action{Kind: grantcoverage.Relation, Name: "admin"}) {
			require.Equal(t, []authzmodel.EffectHop{{From: "project", Pointer: "account", To: "account"}}, c.Path)
			found = true
		}
	}
	require.True(t, found)

	for _, invalid := range []domain.ScopeAnchor{
		{Type: "account", ID: "acc-other"}, {Type: "project", ID: "prj-other"},
		{Type: "cluster", ID: "other-root"}, {Type: "unknown", ID: "acc-a"},
	} {
		result := b.CompileScopedMaterializedTuple("binding", old, invalid, recipient, tuple)
		require.False(t, result.Complete())
		require.Empty(t, result.Effects())
	}
	tuple.Object = "account:acc-other"
	require.False(t, b.CompileScopedMaterializedTuple("binding", old, scope, recipient, tuple).Complete())
}
