// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
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
