// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

func TestResourceObjectAncestorCaptureUsesStoredLiveMirrorProjection(t *testing.T) {
	c := parentCaptureFixture(t)
	parentCaptureObject(t, c, "tag", "tag-a", "", domain.WritePolicy{})
	c.catalogs["example.tag"] = c.catalogs["tag"]
	parentCaptureObject(t, c, "item", "item-a", "project-a", domain.WritePolicy{})
	parentCaptureProject(t, c, "project-a", "account-a")
	parentCaptureRows(t, c, resourceSourceKey{kind: resourceSourceMirror, typ: "example.item", id: "item-a"}, map[string]any{"object_type": "example.item", "object_id": "item-a", "parent_project_id": "project-a", "labels": map[string]string{"match": "yes"}})
	c.catalogs["box"] = &resourceCatalogCapture{input: "box", rows: []resourceCatalogRow{{identity: domain.CatalogTypeIdentity{Dotted: "example.box", ObjectType: "box", Module: "example"}, live: false}}}
	c.catalogs["project"] = &resourceCatalogCapture{input: "project"}
	parentCaptureRows(t, c, resourceSourceKey{kind: resourceSourceParentEdges, typ: "tag", id: "tag-a"}, map[string]any{"parent_type": "project", "parent_id": "project-a", "depth": 3}, map[string]any{"parent_type": "item", "parent_id": "item-a", "depth": 1}, map[string]any{"parent_type": "box", "parent_id": "box-a", "depth": 2})
	objects, err := c.captureObjectAncestors(context.Background(), "example.tag", "tag-a", true)
	require.NoError(t, err)
	require.Equal(t, []domain.MirrorObject{{ObjectType: "example.item", ObjectID: "item-a", ParentProjectID: "project-a", ParentAccountIDs: []string{"account-a"}, Labels: map[string]string{"match": "yes"}}}, objects)
	// Retired catalog не порождает mirror read; его отсутствие из результата
	// подтверждено catalog witness, а не предположением о текущем pointer graph.
	_, read := c.source.entries[resourceSourceKey{kind: resourceSourceMirror, typ: "example.box", id: "box-a"}]
	require.False(t, read)
	parentCaptureRows(t, c, resourceSourceKey{kind: resourceSourceParentEdges, typ: "tag", id: "tag-a"}, map[string]any{"parent_type": "item", "parent_id": "item-a", "depth": 5})
	_, err = c.captureObjectAncestors(context.Background(), "example.tag", "tag-a", true)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}

func TestResourceObjectAncestorCaptureSkipsAbsentAndIAMSources(t *testing.T) {
	c := parentCaptureFixture(t)
	for _, tc := range []struct {
		typ     string
		present bool
	}{{"example.tag", false}, {"iam.user", true}} {
		objects, err := c.captureObjectAncestors(context.Background(), tc.typ, "key", tc.present)
		require.NoError(t, err)
		require.Empty(t, objects)
	}
	require.Empty(t, c.catalogs)
	require.Empty(t, c.source.entries)
}
