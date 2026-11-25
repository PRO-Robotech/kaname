// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

func TestAccessLabelMoveCopyPlanUsesExactPhysicalMirrorImage(t *testing.T) {
	source, rr, _ := resourceSourceFixture(t)
	parents, err := newResourceParentCapture(rr, source)
	require.NoError(t, err)
	ref := domain.ResourceRef{Type: "registry.repository", ID: "repo-one"}
	old := `["95","(0,8)",{"object_type":"registry.repository","object_id":"repo-one","access_labels":{},"producer_generation":24}]`
	overlay := map[domain.ResourceRef]domain.MirrorObject{ref: {
		ObjectType: ref.Type, ObjectID: ref.ID, AccessLabels: map[string]string{"stage": "ready"},
	}}
	key := resourceSourceKey{kind: resourceSourceMirror, typ: ref.Type, id: ref.ID}
	source.entries[key] = []resourceSourceRow{{state: old}}
	raw, err := parents.captureAccessLabelMoveCopyPlan(t.Context(), overlay, false)
	require.NoError(t, err)
	var proposals []accessLabelMoveCopyProposal
	require.NoError(t, json.Unmarshal(raw, &proposals))
	require.Len(t, proposals, 1)
	require.Equal(t, ref.Type, proposals[0].Type)
	require.Equal(t, ref.ID, proposals[0].ID)
	require.JSONEq(t, old, string(proposals[0].Physical))
	require.Equal(t, map[string]string{"stage": "ready"}, proposals[0].NewLabels)

	delete(source.entries, key)
	_, err = parents.captureAccessLabelMoveCopyPlan(t.Context(), overlay, false)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}

func TestAccessLabelMoveCopyPlanRetainsOnlyPhysicalProjectSource(t *testing.T) {
	source, rr, _ := resourceSourceFixture(t)
	parents, err := newResourceParentCapture(rr, source)
	require.NoError(t, err)
	ref := domain.ResourceRef{Type: "iam.project", ID: "prj-copy"}
	const nativeRow = `{"id":"prj-copy","labels":{"stage":"native","local":"native"},"access_labels":{"other":"kept"}}`
	const nativePhysical = `["95","(0,8)",` + nativeRow + `]`
	const mirrorPhysical = `["97","(0,3)",{"object_type":"iam.project","object_id":"prj-copy","labels":{"stage":"mirror"}}]`
	source.entries[resourceSourceKey{kind: resourceSourceIAMObject, typ: ref.Type, id: ref.ID}] =
		[]resourceSourceRow{{state: nativePhysical, value: json.RawMessage(nativeRow)}}
	mirrorKey := resourceSourceKey{kind: resourceSourceMirror, typ: ref.Type, id: ref.ID}
	source.entries[mirrorKey] = []resourceSourceRow{{state: mirrorPhysical}}
	overlay := map[domain.ResourceRef]domain.MirrorObject{ref: {
		ObjectType: ref.Type, ObjectID: ref.ID, AccessLabels: map[string]string{"stage": "mirror", "local": "native", "other": "kept"},
	}}
	raw, err := parents.captureAccessLabelMoveCopyPlan(t.Context(), overlay, false)
	require.NoError(t, err)
	require.JSONEq(t, `[{"root_type":"iam.project","root_id":"prj-copy","physical":`+nativePhysical+`,
		"new_access_labels":{"stage":"mirror","local":"native","other":"kept"},
		"project_source":{"mirror_physical":`+mirrorPhysical+`,"definition":false}}]`, string(raw))

	raw, err = parents.captureAccessLabelMoveCopyPlan(t.Context(), overlay, true)
	require.NoError(t, err)
	require.JSONEq(t, `[{"root_type":"iam.project","root_id":"prj-copy","physical":`+nativePhysical+`,
		"new_access_labels":{"stage":"mirror","local":"native","other":"kept"},
		"project_source":{"mirror_physical":`+mirrorPhysical+`,"definition":true}}]`, string(raw))

	delete(source.entries, mirrorKey)
	_, err = parents.captureAccessLabelMoveCopyPlan(t.Context(), overlay, true)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)

	delete(overlay[ref].AccessLabels, "stage")
	raw, err = parents.captureAccessLabelMoveCopyPlan(t.Context(), overlay, true)
	require.NoError(t, err)
	require.JSONEq(t, `[{"root_type":"iam.project","root_id":"prj-copy","physical":`+nativePhysical+`,
		"new_access_labels":{"local":"native","other":"kept"}}]`, string(raw))
}
