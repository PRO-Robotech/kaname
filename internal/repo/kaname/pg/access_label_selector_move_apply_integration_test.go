// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

const moveIAMCopyHoldSQL = `SELECT kaname._authority_role_move_iam_copy_sources_hold_v1(
    $1,$2,$3::jsonb,$4::jsonb,'user',$5,$6,100)`

func TestSelectorMoveIAMCopyHoldsPhysicalRootAndApplySources(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	actor := bindingPublicOwner(t, r)
	project := kac127SeedProject(t, r.ctx, r.admin, r.a, "copy")
	sa := seedSA(t, r.ctx, owner, domain.AccountID(r.a), "copy-target")
	type copyRoot struct {
		resource, table, id, definition string
		physical                        json.RawMessage
	}
	roots := []copyRoot{
		{resource: "account", table: "accounts", id: r.a},
		{resource: "project", table: "projects", id: project},
		{resource: "serviceAccount", table: "service_accounts", id: string(sa.ID)},
	}
	var definitions []string
	for i := range roots {
		root := &roots[i]
		table := pgx.Identifier{"kaname", root.table}.Sanitize()
		require.NoError(t, r.admin.QueryRow(r.ctx, `UPDATE `+table+` AS o SET labels='{"stage":"ready","extra":"local"}'
		    WHERE id=$1 RETURNING jsonb_build_array(o.xmin::text,o.ctid::text,to_jsonb(o))`, root.id).Scan(&root.physical))
		require.NoError(t, r.admin.QueryRow(r.ctx, `INSERT INTO kaname.authority_access_label_definition
		    (scope_kind,scope_id,module,resource,label_key) VALUES ('account',$1,'iam',$2,'stage') RETURNING id::text`,
			r.a, root.resource).Scan(&root.definition))
		_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_value(definition_id,label_value) VALUES($1::uuid,'ready')`, root.definition)
		require.NoError(t, err)
		definitions = append(definitions, root.definition)
	}
	seedMetadataActualApplySource(t, r, actor, definitions...)
	for _, root := range roots {
		t.Run(root.resource, func(t *testing.T) {
			tx, err := r.admin.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, tx)
			var raw json.RawMessage
			require.NoError(t, tx.QueryRow(r.ctx, moveIAMCopyHoldSQL, "iam."+root.resource, root.id, root.physical, `{"stage":"ready"}`, actor, 1000).Scan(&raw))
			var receipt struct {
				RootType     string                                 `json:"root_type"`
				RootID       string                                 `json:"root_id"`
				Physical     json.RawMessage                        `json:"physical"`
				Proposed     json.RawMessage                        `json:"new_access_labels"`
				Requirements []resourceAccessLabelDefinitionReceipt `json:"requirements"`
			}
			require.NoError(t, json.Unmarshal(raw, &receipt))
			require.Equal(t, "iam."+root.resource, receipt.RootType)
			require.Equal(t, root.id, receipt.RootID)
			require.JSONEq(t, string(root.physical), string(receipt.Physical))
			require.JSONEq(t, `{"stage":"ready"}`, string(receipt.Proposed))
			require.Len(t, receipt.Requirements, 1)
			d := receipt.Requirements[0]
			require.Equal(t, root.definition, d.DefinitionID)
			require.Equal(t, "account", d.ScopeKind)
			require.Equal(t, r.a, d.ScopeID)
			require.Nil(t, d.OldValue)
			require.NotNil(t, d.NewValue)
			require.Equal(t, "ready", *d.NewValue)
			_, err = tx.Exec(r.ctx, `SELECT kaname._authority_resource_access_label_sources_require_v1(
			    $1::jsonb->'authority',$1::jsonb->'requirements',clock_timestamp(),1000,100)`, raw)
			require.NoError(t, err)
		})
	}

	root := roots[0]
	for _, tc := range []struct {
		name, typ, id, next, state string
		expected                   json.RawMessage
		rows                       int
	}{
		{"other_physical_root", "iam.account", r.b, `{"stage":"ready"}`, "40001", root.physical, 1000},
		{"external_root", "example.item", root.id, `{"stage":"ready"}`, "42501", root.physical, 1000},
		{"no_delta", "iam.account", root.id, `{}`, "42501", root.physical, 1000},
		{"fabricated_value", "iam.account", root.id, `{"stage":"other"}`, "42501", root.physical, 1000},
		{"absent_ordinary_key", "iam.account", root.id, `{"absent":""}`, "42501", root.physical, 1000},
		{"missing_definition", "iam.account", root.id, `{"extra":"local"}`, "42501", root.physical, 1000},
		{"shared_row_budget", "iam.account", root.id, `{"stage":"ready"}`, "54000", root.physical, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := r.admin.Exec(r.ctx, moveIAMCopyHoldSQL, tc.typ, tc.id, tc.expected, tc.next, actor, tc.rows)
			requireAccessDefinitionSQLState(t, err, tc.state)
		})
	}
	_, err := r.runtime.Exec(r.ctx, moveIAMCopyHoldSQL, "iam.account", root.id, root.physical, `{"stage":"ready"}`, actor, 1000)
	requireAccessDefinitionSQLState(t, err, "42501")

	t.Run("one_missing_apply_denies_the_root", func(t *testing.T) {
		seedAccessDefinition(t, r, "account", r.a, "extra", "local")
		tx, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		var held json.RawMessage
		require.NoError(t, tx.QueryRow(r.ctx, moveIAMCopyHoldSQL, "iam.account", root.id, root.physical, `{"stage":"ready","extra":"local"}`, actor, 1000).Scan(&held))
		_, err = tx.Exec(r.ctx, `SELECT kaname._authority_resource_access_label_sources_require_v1(
		    $1::jsonb->'authority',$1::jsonb->'requirements',clock_timestamp(),1000,100)`, held)
		requireAccessDefinitionSQLState(t, err, "42501")
	})

	t.Run("same_values_new_generation", func(t *testing.T) {
		_, err := r.admin.Exec(r.ctx, `UPDATE kaname.accounts SET labels=labels WHERE id=$1`, root.id)
		require.NoError(t, err)
		_, err = r.admin.Exec(r.ctx, moveIAMCopyHoldSQL, "iam.account", root.id, root.physical, `{"stage":"ready"}`, actor, 1000)
		requireAccessDefinitionSQLState(t, err, "40001")
	})
}
