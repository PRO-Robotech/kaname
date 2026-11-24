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

func TestResourceCapturedRoleRequiresActualLifecycleAndProjectionIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, live string
		state      domain.RoleLifecycleState
	}{
		{"declared", "true", domain.RoleLifecycleDeclared},
		{"withdrawn", "false", domain.RoleLifecycleWithdrawn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := json.RawMessage(`{"id":"rol_object","rules":[],"permissions":[],"labels":{},"live":` + tc.live + `}`)
			role, err := resourceCapturedMaterializingRole(raw, nil)
			require.NoError(t, err)
			require.Equal(t, tc.state, role.Lifecycle.State)
			_, err = resourceCapturedMaterializingRole(raw, []resourceSourceRow{{value: json.RawMessage(`{"role_id":"rol_foreign","rule_fp":"fp"}`)}})
			require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
		})
	}
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"id":"rol_object","rules":[],"permissions":[],"labels":{}}`),
		json.RawMessage(`{"id":"rol_object","rules":[],"permissions":[],"labels":{},"live":null}`),
	} {
		_, err := resourceCapturedMaterializingRole(raw, nil)
		require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	}
}

func TestResourceCapturedSubjectsRetainTypedOrderAndLegacyFallback(t *testing.T) {
	binding := domain.AccessBinding{ID: "abn_object", SubjectType: domain.SubjectTypeUser, SubjectID: "same"}
	rows := []resourceSourceRow{
		{value: json.RawMessage(`{"binding_id":"abn_object","subject_type":"service_account","subject_id":"same","ordinal":1}`)},
		{value: json.RawMessage(`{"binding_id":"abn_object","subject_type":"user","subject_id":"same","ordinal":0}`)},
	}
	subjects, err := resourceCapturedSubjects(binding, rows)
	require.NoError(t, err)
	require.Equal(t, []domain.Subject{{Type: domain.SubjectTypeUser, ID: "same"}, {Type: domain.SubjectTypeServiceAccount, ID: "same"}}, subjects)
	legacy, err := resourceCapturedSubjects(binding, nil)
	require.NoError(t, err)
	require.Equal(t, subjects[:1], legacy)
	rows[0].value = json.RawMessage(`{"binding_id":"abn_foreign","subject_type":"service_account","subject_id":"same","ordinal":1}`)
	_, err = resourceCapturedSubjects(binding, rows)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}
