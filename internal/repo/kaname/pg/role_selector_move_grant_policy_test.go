// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestRoleSelectorMoveTakesForeignFocalFromPredicateWithoutDescendants(t *testing.T) {
	source, _, _ := resourceSourceFixture(t)
	parent := domain.ResourceRef{Type: "iam.account", ID: "acc-one"}
	outside := domain.ResourceRef{Type: "iam.account", ID: "acc-two"}
	metadataKey := func(kind resourceSourceKind, ref domain.ResourceRef) resourceSourceKey {
		return resourceSourceKey{kind: kind, typ: ref.Type, id: ref.ID}
	}
	source.entries[metadataKey(resourceSourceMetadataBindings, parent)] = []resourceSourceRow{
		{value: json.RawMessage(`{"binding_id":"acb-foreign","changes":true}`)},
	}
	source.entries[metadataKey(resourceSourceMetadataAuthoredBindings, parent)] = []resourceSourceRow{
		{value: json.RawMessage(`{"binding_id":"acb-foreign","changes":true}`)},
		{value: json.RawMessage(`{"binding_id":"acb-cover-only","changes":false}`)},
	}
	source.entries[metadataKey(resourceSourceMetadataBindings, outside)] = []resourceSourceRow{
		{value: json.RawMessage(`{"binding_id":"acb-outside","changes":true}`)},
	}
	require.NoError(t, source.seal())
	stage := &roleSelectorMoveStage{
		captured: accessLabelSelectorMoveCapture{
			proof: &accessLabelMoveRRProof{source: source},
			Collateral: []accessLabelSelectorMoveScope{{
				Carrier: accessLabelSelectorMoveCarrier{Binding: domain.AccessBinding{ID: "acb-foreign"}},
			}},
		},
		replay: &accessLabelMoveSourceReplay{parents: &resourceParentCapture{source: source}},
	}
	foci, _, err := stage.selectorMoveGrantFoci(t.Context(), accessLabelMoveCopies{parent: {"team": "new"}})
	require.NoError(t, err)
	require.Equal(t, map[domain.AccessBindingID][]domain.ResourceRef{"acb-foreign": {parent}}, foci)
}
