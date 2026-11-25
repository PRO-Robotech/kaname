// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"encoding/json"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/resourceeffect"
	"github.com/stretchr/testify/require"
)

func TestBindingStageNestedProjectRequiresItsNativeOwnerEdge(t *testing.T) {
	project := domain.MirrorObject{ObjectType: "iam.project", ObjectID: "project", ParentAccountIDs: []string{"owner"}}
	owner := domain.MirrorObject{ObjectType: "iam.account", ObjectID: "owner"}
	foreign := domain.MirrorObject{ObjectType: "iam.account", ObjectID: "foreign"}
	otherType := domain.MirrorObject{ObjectType: "other.container", ObjectID: "owner"}
	for _, tc := range []struct {
		name  string
		edges []domain.MirrorObject
		want  []domain.MirrorObject
	}{
		{"named owner edge", []domain.MirrorObject{owner}, []domain.MirrorObject{owner}},
		{"additional foreign edge", []domain.MirrorObject{foreign, owner}, []domain.MirrorObject{owner}},
		{"foreign edge alone", []domain.MirrorObject{foreign}, nil},
		{"same id of another type", []domain.MirrorObject{otherType}, nil},
		{"no typed edge", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			graph := resourceeffect.ProjectGraphProjection{Object: &project, Ancestors: tc.edges}
			require.NoError(t, retainBindingProjectOwner(project, &graph))
			require.ElementsMatch(t, tc.want, graph.Ancestors)
		})
	}
	t.Run("mirror names a foreign owner", func(t *testing.T) {
		mirror := project
		mirror.ParentAccountIDs = []string{foreign.ObjectID}
		graph := resourceeffect.ProjectGraphProjection{Object: &mirror, Ancestors: []domain.MirrorObject{owner}}
		require.ErrorIs(t, retainBindingProjectOwner(project, &graph), kaname.ErrSourceUnconfirmed)
	})
}

func TestBindingStageProtectedProjectRawOwnerEdge(t *testing.T) {
	project := domain.MirrorObject{ObjectType: "iam.project", ObjectID: "p", ParentAccountIDs: []string{"a"}}
	owner := domain.MirrorObject{ObjectType: "iam.account", ObjectID: "a"}
	graph := resourceeffect.ProjectGraphProjection{Object: &project, Ancestors: []domain.MirrorObject{owner}}
	row := func(obj, parent, id string, depth int) resourceSourceRow {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"object_type": obj, "object_id": "p", "parent_type": parent, "parent_id": id, "depth": depth})
		require.NoError(t, err)
		return resourceSourceRow{value: raw}
	}
	direct := row("project", "account", "a", 1)
	foreign := row("project", "account", "b", 2)
	for _, tc := range []struct {
		name  string
		rows  []resourceSourceRow
		valid bool
	}{
		{"direct owner", []resourceSourceRow{direct}, true},
		{"normal reconcile with additional foreign edge", []resourceSourceRow{direct, foreign}, true},
		{"owner only at depth two", []resourceSourceRow{row("project", "account", "a", 2)}, false},
		{"repeated owner at two depths", []resourceSourceRow{direct, row("project", "account", "a", 2)}, false},
		{"same parent id of another type", []resourceSourceRow{row("project", "external", "a", 1)}, false},
		{"wrong child model", []resourceSourceRow{row("other", "account", "a", 1)}, false},
		{"foreign only", []resourceSourceRow{foreign}, false},
		{"no physical witness", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyBindingProjectOwnerEdge(project, graph, "project", "account", tc.rows)
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
			}
		})
	}
}

func TestBindingStageNestedProjectSkipsUnselectedOwner(t *testing.T) {
	project := domain.MirrorObject{ObjectType: "iam.project", ObjectID: "p", ParentAccountIDs: []string{"a"}}
	bs := reconcile.BindingScope{Scope: domain.ScopeAnchor{Type: "account", ID: "a"}, Target: domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "iam.account", ID: "a"}}}}
	require.True(t, bindingCanSelectNativeOwner(bs, project))
	project.ParentAccountIDs = []string{"sibling"}
	require.False(t, bindingCanSelectNativeOwner(bs, project))
	bs.Scope = domain.ScopeAnchor{Type: "cluster", ID: "cluster_root"}
	require.False(t, bindingCanSelectNativeOwner(bs, project))
	bs.Target = domain.AccessTarget{AllInScope: true}
	require.True(t, bindingCanSelectNativeOwner(bs, project))
}
