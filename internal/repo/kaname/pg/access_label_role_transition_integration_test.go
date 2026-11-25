// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestAccessLabelRoleTransitionPlansExactOldAndNew(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	role := seedAccountRole(t, r.ctx, r.admin, domain.AccountID(r.a), "access_label_transition")
	definition := seedAccessDefinition(t, r, "account", r.a, "transition")
	rules := domain.Rules{accessRoleApply(definition.id)}
	encoded, err := domain.EncodeRules(rules)
	require.NoError(t, err)
	_, caps, err := domain.SplitGrantCapabilityRules(rules)
	require.NoError(t, err)
	require.Len(t, caps, 1)
	var before, next, creation json.RawMessage
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT to_jsonb(r),
	  to_jsonb(r)||jsonb_build_object('rules',$2::jsonb),
	  to_jsonb(r)||jsonb_build_object('rules',$2::jsonb,'id','rolb251ff4476dfeb42e')
	  FROM kaname.roles r WHERE id=$1`, role, encoded).Scan(&before, &next, &creation))
	const prepare = `SELECT kaname.authority_access_label_role_transition_prepare_v1($1,$2,$3,$4)`
	type plan struct {
		RoleID        string      `json:"role_id"`
		OldXmin       string      `json:"old_xmin"`
		OldDigest     *string     `json:"old_digest"`
		NewDigest     *string     `json:"new_digest"`
		OldProjection [][2]string `json:"old_projection"`
		NewProjection [][2]string `json:"new_projection"`
		Rows          int         `json:"rows"`
		Reads         int         `json:"reads"`
	}
	wantNew := [][2]string{{caps[0].RuleFP, definition.id}}
	for _, tc := range []struct {
		name     string
		old, new any
		add      bool
	}{
		{"create", nil, creation, true},
		{"update", before, next, true},
		{"delete", before, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var raw json.RawMessage
			require.NoError(t, r.admin.QueryRow(r.ctx, prepare, tc.old, tc.new, 100, 50).Scan(&raw))
			var got plan
			require.NoError(t, json.Unmarshal(raw, &got))
			require.NotEmpty(t, got.RoleID)
			require.Empty(t, got.OldProjection)
			require.Equal(t, tc.old == nil, got.OldDigest == nil)
			require.Equal(t, tc.old == nil, got.OldXmin == "")
			require.Equal(t, tc.new == nil, got.NewDigest == nil)
			if tc.add {
				require.Equal(t, wantNew, got.NewProjection)
				require.Equal(t, 6, got.Reads)
				require.Equal(t, 4, got.Rows)
			} else {
				require.Empty(t, got.NewProjection)
				require.Equal(t, 4, got.Reads)
				require.Equal(t, 1, got.Rows)
			}
		})
	}
	var unused json.RawMessage
	err = r.admin.QueryRow(r.ctx, prepare, next, next, 100, 50).Scan(&unused)
	requireAccessDefinitionSQLState(t, err, "40001")
	err = r.admin.QueryRow(r.ctx, prepare, before, next, 100, 5).Scan(&unused)
	requireAccessDefinitionSQLState(t, err, "54000")
	err = r.runtime.QueryRow(r.ctx, prepare, before, next, 100, 50).Scan(&unused)
	requireAccessDefinitionSQLState(t, err, "42501")
	var published int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.authority_role_access_label_rule`).Scan(&published))
	require.Zero(t, published)
}
