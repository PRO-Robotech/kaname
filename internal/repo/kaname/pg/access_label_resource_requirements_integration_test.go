// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

const resourceAccessLabelRequirementsSQL = `SELECT kaname._authority_resource_access_label_requirements_v1(
	$1, $2::jsonb, $3::jsonb, $4, $5
)`

type resourceAccessLabelDefinitionReceipt struct {
	Key          string  `json:"key"`
	OldValue     *string `json:"old_value"`
	NewValue     *string `json:"new_value"`
	DefinitionID string  `json:"definition_id"`
	ScopeKind    string  `json:"scope_kind"`
	ScopeID      string  `json:"scope_id"`
	Revision     int64   `json:"revision"`
	RowXmin      string  `json:"row_xmin"`
	RowCTID      string  `json:"row_ctid"`
}

func resourceAccessLabelImage(t *testing.T, id, accountID string, labels map[string]string) []byte {
	t.Helper()
	if labels == nil {
		labels = map[string]string{}
	}
	image := map[string]any{"id": id, "access_labels": labels}
	if accountID != "" {
		image["account_id"] = accountID
	}
	raw, err := json.Marshal(image)
	require.NoError(t, err)
	return raw
}

func TestResourceAccessLabelRequirementsBindDeltaAndScope(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	team := seedAccessDefinition(t, r, "account", r.a, "team", "b")
	tier := seedAccessDefinition(t, r, "account", r.a, "tier", "")
	seedAccessDefinition(t, r, "account", r.b, "team", "foreign")
	old := resourceAccessLabelImage(t, r.a, "", map[string]string{"team": "a", "tier": "old", "stable": "s"})
	next := resourceAccessLabelImage(t, r.a, "", map[string]string{"team": "b", "stable": "s"})
	var raw []byte
	require.NoError(t, r.admin.QueryRow(r.ctx, resourceAccessLabelRequirementsSQL, "account", old, next, 100, 20).Scan(&raw))
	var got struct {
		Requirements []resourceAccessLabelDefinitionReceipt `json:"requirements"`
		Rows         int                                    `json:"rows"`
		Reads        int                                    `json:"reads"`
	}
	require.NoError(t, json.Unmarshal(raw, &got))
	require.Len(t, got.Requirements, 2)
	fromA, toB, oldTier := "a", "b", "old"
	require.Equal(t, resourceAccessLabelDefinitionReceipt{
		Key: "team", OldValue: &fromA, NewValue: &toB, DefinitionID: team.id,
		ScopeKind: team.scopeKind, ScopeID: team.scopeID, Revision: team.revision, RowXmin: team.xmin, RowCTID: team.ctid,
	}, got.Requirements[0])
	require.Equal(t, resourceAccessLabelDefinitionReceipt{
		Key: "tier", OldValue: &oldTier, DefinitionID: tier.id,
		ScopeKind: tier.scopeKind, ScopeID: tier.scopeID, Revision: tier.revision, RowXmin: tier.xmin, RowCTID: tier.ctid,
	}, got.Requirements[1])
	require.Equal(t, 13, got.Rows)
	require.Equal(t, 7, got.Reads)

	t.Run("unchanged_key_does_not_resolve_definition", func(t *testing.T) {
		stable := resourceAccessLabelImage(t, r.a, "", map[string]string{"unmanaged": "same"})
		require.NoError(t, r.admin.QueryRow(r.ctx, resourceAccessLabelRequirementsSQL, "account", stable, stable, 2, 1).Scan(&raw))
		require.JSONEq(t, `{"requirements":[],"rows":2,"reads":1}`, string(raw))
	})
	t.Run("runtime_cannot_invoke", func(t *testing.T) {
		err := r.runtime.QueryRow(r.ctx, resourceAccessLabelRequirementsSQL, "account", old, next, 100, 20).Scan(&raw)
		requireAccessDefinitionSQLState(t, err, "42501")
	})
	t.Run("bounds_unknown_or_disallowed_value", func(t *testing.T) {
		for _, tc := range []struct {
			name, key, value, state string
			rows                    int
		}{
			{"undefined", "undefined", "b", "42501", 100},
			{"not_in_definition", "team", "c", "42501", 100},
			{"budget", "team", "b", "54000", 1},
		} {
			t.Run(tc.name, func(t *testing.T) {
				target := resourceAccessLabelImage(t, r.a, "", map[string]string{tc.key: tc.value})
				empty := resourceAccessLabelImage(t, r.a, "", nil)
				err := r.admin.QueryRow(r.ctx, resourceAccessLabelRequirementsSQL, "account", empty, target, tc.rows, 20).Scan(&raw)
				requireAccessDefinitionSQLState(t, err, tc.state)
			})
		}
	})
	t.Run("overlapping_scope_cannot_choose_definition", func(t *testing.T) {
		seedAccessDefinition(t, r, "cluster", "cluster_root", "team", "b")
		err := r.admin.QueryRow(r.ctx, resourceAccessLabelRequirementsSQL, "account", old, next, 100, 20).Scan(&raw)
		requireAccessDefinitionSQLState(t, err, "42501")
		require.ErrorContains(t, err, "ambiguous")
	})
}

func TestResourceAccessLabelRequirementsUseProjectOwnerAndExactProject(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	project := kac127SeedProject(t, r.ctx, r.admin, r.a, "label-main")
	sibling := kac127SeedProject(t, r.ctx, r.admin, r.a, "label-near")
	var wanted string
	for _, tc := range []struct {
		kind, scope, value string
	}{
		{"account", r.b, "foreign"},
		{"project", sibling, "sibling"},
		{"project", project, "exact"},
	} {
		var definitionID string
		require.NoError(t, r.admin.QueryRow(r.ctx, `
			INSERT INTO kaname.authority_access_label_definition(scope_kind,scope_id,module,resource,label_key)
			VALUES($1,$2,'iam','project','team') RETURNING id::text
		`, tc.kind, tc.scope).Scan(&definitionID))
		_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_value(definition_id,label_value) VALUES($1::uuid,$2)`, definitionID, tc.value)
		require.NoError(t, err)
		if tc.scope == project {
			wanted = definitionID
		}
	}
	old := resourceAccessLabelImage(t, project, r.a, nil)
	next := resourceAccessLabelImage(t, project, r.a, map[string]string{"team": "exact"})
	var raw []byte
	require.NoError(t, r.admin.QueryRow(r.ctx, resourceAccessLabelRequirementsSQL, "project", old, next, 6, 4).Scan(&raw))
	var readback struct {
		Requirements []resourceAccessLabelDefinitionReceipt `json:"requirements"`
	}
	require.NoError(t, json.Unmarshal(raw, &readback))
	require.Len(t, readback.Requirements, 1)
	require.Equal(t, wanted, readback.Requirements[0].DefinitionID)
	require.Equal(t, project, readback.Requirements[0].ScopeID)

	moved := resourceAccessLabelImage(t, project, r.b, map[string]string{"team": "foreign"})
	err := r.admin.QueryRow(r.ctx, resourceAccessLabelRequirementsSQL, "project", old, moved, 100, 20).Scan(&raw)
	requireAccessDefinitionSQLState(t, err, "42501")
	require.ErrorContains(t, err, "identity")
}
