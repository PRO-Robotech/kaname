// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

// Использует unit-fixture предыдущего content-approval patch, не DB proof.
func approvedRoleCapabilitiesFixture(t *testing.T) (*preparedRoleWriteTx, *preparedRoleRowWriter, *roleProjectionRecordingTx) {
	t.Helper()
	w, _, _ := roleContentApprovalFixture()
	tx := &roleProjectionRecordingTx{}
	w.writeTx.readTx.tx = tx
	w.stage.request.Role = domain.Role{ID: "rol00000000000000001", AccountID: "acc00000000000000001",
		Rules: domain.Rules{{Module: "iam", Resources: []string{"accessLabel"}, Verbs: []string{"apply"}, ResourceNames: []string{"3d9cd5bf-906f-4bbe-8a8b-234ba2efa54a"}}}}
	w.stage.projection.Capabilities = []domain.GrantCapabilityRule{{Kind: domain.GrantCapabilityApplyAccessLabel,
		DefinitionID: "3d9cd5bf-906f-4bbe-8a8b-234ba2efa54a", RuleFP: strings.Repeat("a", 64)}}
	require.NoError(t, w.RecordRoleContentApproval(context.Background()))
	require.True(t, w.contentApprovalRecorded)
	tx.statements = nil
	return w, &preparedRoleRowWriter{WriterIface: &roleWriter{roleReader{tx: tx}}, owner: w}, tx
}

func TestPreparedRoleProjectionPreservesAllCapsAndOwnsReturnedMemory(t *testing.T) {
	w, _, tx := approvedRoleCapabilitiesFixture(t)
	ordinary := domain.GrantCapabilityRule{Kind: domain.GrantCapabilityCreateBinding, RuleFP: strings.Repeat("b", 64)}
	w.stage.projection.Capabilities = append(w.stage.projection.Capabilities, ordinary)
	projected, err := w.ProjectRoleMutationRules(context.Background(), w.stage.request.Role)
	require.NoError(t, err)
	require.Equal(t, w.stage.projection.Capabilities, projected.Capabilities)
	projected.Capabilities[0].DefinitionID = "9ca1658c-1ce8-408b-b051-9002f91cba51"
	require.NotEqual(t, projected.Capabilities[0], w.stage.projection.Capabilities[0])
	require.Empty(t, tx.statements)
	changed := w.stage.request.Role
	changed.ProjectID = "prj00000000000000001"
	_, err = w.ProjectRoleMutationRules(context.Background(), changed)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	w.contentApprovalRecorded = false
	_, err = w.ProjectRoleMutationRules(context.Background(), w.stage.request.Role)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}

func TestPreparedApplyAxesRequireSuccessfulContentAndExactCoordinate(t *testing.T) {
	w, rows, tx := approvedRoleCapabilitiesFixture(t)
	caps := append([]domain.GrantCapabilityRule{}, w.stage.projection.Capabilities...)
	require.NoError(t, rows.LockGrantAuthoringAxes(context.Background(), caps))
	require.Empty(t, tx.statements, "owner already holds apply axis and definition; no new query")
	caps[0].DefinitionID = "9ca1658c-1ce8-408b-b051-9002f91cba51"
	require.ErrorIs(t, rows.LockGrantAuthoringAxes(context.Background(), caps), kaname.ErrInvalidAuthorityFencePlan)
	w.contentApprovalRecorded = false
	require.ErrorIs(t, rows.LockGrantAuthoringAxes(context.Background(), w.stage.projection.Capabilities), kaname.ErrSourceUnconfirmed)
}

func TestPreparedApplyReplaceRequiresSuccessfulRowAndFullSet(t *testing.T) {
	for _, missing := range []string{"row", "stamp", "apply", "fingerprint"} {
		t.Run(missing, func(t *testing.T) {
			w, rows, tx := approvedRoleCapabilitiesFixture(t)
			w.roleWriteStarted = true
			w.roleWriteSucceeded = true
			caps := append([]domain.GrantCapabilityRule{}, w.stage.projection.Capabilities...)
			switch missing {
			case "row":
				w.roleWriteSucceeded = false
			case "stamp":
				w.contentApprovalRecorded = false
			case "apply":
				caps = nil
			case "fingerprint":
				caps[0].RuleFP = strings.Repeat("b", 64)
			}
			require.ErrorIs(t, rows.ReplaceGrantCapabilities(context.Background(), w.stage.request.Role.ID, caps), kaname.ErrSourceUnconfirmed)
			require.Empty(t, tx.statements)
		})
	}
	w, rows, tx := approvedRoleCapabilitiesFixture(t)
	w.stage.projection.Capabilities = append(w.stage.projection.Capabilities, domain.GrantCapabilityRule{Kind: domain.GrantCapabilityCreateBinding, RuleFP: strings.Repeat("b", 64)})
	w.roleWriteStarted = true
	w.roleWriteSucceeded = true
	w.applied = true // Update already reconciled tuples before Replace.
	require.NoError(t, rows.ReplaceGrantCapabilities(context.Background(), w.stage.request.Role.ID, w.stage.projection.Capabilities))
	require.Len(t, tx.statements, 3) // Two legacy DELETEs and one create-binding INSERT.
	for _, statement := range tx.statements {
		require.NotContains(t, statement.SQL, "access_label")
	}
	require.True(t, w.grantCapabilitiesReplaced)
	require.ErrorIs(t, rows.ReplaceGrantCapabilities(context.Background(), w.stage.request.Role.ID, w.stage.projection.Capabilities), kaname.ErrSourceUnconfirmed)
}

func TestRawApplyAuthoringPathsRemainClosed(t *testing.T) {
	w, rows, tx := approvedRoleCapabilitiesFixture(t)
	raw := rows.WriterIface.(*roleWriter)
	require.Error(t, raw.LockGrantAuthoringAxes(context.Background(), w.stage.projection.Capabilities))
	require.Error(t, raw.ReplaceGrantCapabilities(context.Background(), w.stage.request.Role.ID, w.stage.projection.Capabilities))
	require.Empty(t, tx.statements)
}
