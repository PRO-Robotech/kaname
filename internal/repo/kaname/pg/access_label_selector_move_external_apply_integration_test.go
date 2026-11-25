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

const moveExternalCopyHoldSQL = `SELECT kaname._authority_role_move_external_copy_sources_hold_v1(
    $1,$2,$3::jsonb,$4::jsonb,'user',$5,$6,$7)`

func TestSelectorMoveExternalCopyHoldsRegisteredScopeAndApplySources(t *testing.T) {
	const dotted, model, id = "vpc.network", "vpc_network", "external-copy/target"
	const proposed = `{"stage":"ready"}`
	r, _ := writerProtocolRigBeforePreparation(t)
	actor := bindingPublicOwner(t, r)
	project := kac127SeedProject(t, r.ctx, r.admin, r.a, "extcopy")
	var definition string
	require.NoError(t, r.admin.QueryRow(r.ctx, `INSERT INTO kaname.authority_access_label_definition
	    (scope_kind,scope_id,module,resource,label_key) VALUES('project',$1,'vpc','network','stage') RETURNING id::text`,
		project).Scan(&definition))
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_value(definition_id,label_value)
	    VALUES($1::uuid,'ready')`, definition)
	require.NoError(t, err)
	seedMetadataActualApplySourceInScope(t, r, actor, domain.ScopeAnchor{Type: "project", ID: project}, definition)
	var physical json.RawMessage
	require.NoError(t, r.admin.QueryRow(r.ctx, `INSERT INTO kaname.resource_mirror AS m
	    (object_type,object_id,parent_project_id,labels) VALUES($1,$2,$3,'{"stage":"ready","unprotected":"local"}')
	    RETURNING jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m))`, dotted, id, project).Scan(&physical))
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.object_project_binding(object_type,object_id,project_id)
	    VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, model, id, project)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_registration_scope(object_type,object_id,project_id,account_id)
	    VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, model, id, project, r.a)
	require.NoError(t, err)

	t.Run("physical_evidence_and_final_apply", func(t *testing.T) {
		tx, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		var receipt json.RawMessage
		require.NoError(t, tx.QueryRow(r.ctx, moveExternalCopyHoldSQL, dotted, id, physical, proposed, actor, 1000, 100).Scan(&receipt))
		var exact bool
		// Каждая сохранённая версия происходит из своей таблицы и составной координаты.
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT q->'physical'=$1::jsonb AND q->'new_access_labels'=$2::jsonb
		    AND q->>'root_type'=c.dotted AND q->>'root_id'=s.object_id
		    AND q->'catalog'=jsonb_build_array(c.xmin::text,c.ctid::text,to_jsonb(c))
		    AND q->'root_update_verb'=jsonb_build_array(v.xmin::text,v.ctid::text,to_jsonb(v))
		    AND q->'account'=jsonb_build_array(a.xmin::text,a.ctid::text,to_jsonb(a))
		    AND q->'project'=jsonb_build_array(p.xmin::text,p.ctid::text,to_jsonb(p))
		    AND q->'binding'=jsonb_build_array(b.xmin::text,b.ctid::text,to_jsonb(b))
		    AND q->'registration_scopes'=jsonb_build_array(jsonb_build_array(s.xmin::text,s.ctid::text,to_jsonb(s)))
		    FROM (SELECT $3::jsonb AS q) held, ONLY kaname.catalog_resource c
		    JOIN ONLY kaname.catalog_verb v ON (v.module,v.resource)=(c.module,c.resource)
		    JOIN ONLY kaname.resource_registration_scope s ON s.object_type=c.object_type
		    JOIN ONLY kaname.object_project_binding b ON (b.object_type,b.object_id,b.project_id)=(s.object_type,s.object_id,s.project_id)
		    JOIN ONLY kaname.projects p ON p.id=s.project_id
		    JOIN ONLY kaname.accounts a ON a.id=s.account_id
		    WHERE c.dotted=$4 AND v.verb='update' AND s.object_id=$5`, physical, proposed, receipt, dotted, id).Scan(&exact))
		require.True(t, exact)
		var held struct {
			Requirements []resourceAccessLabelDefinitionReceipt `json:"requirements"`
			Rows         int                                    `json:"rows"`
			Reads        int                                    `json:"reads"`
		}
		require.NoError(t, json.Unmarshal(receipt, &held))
		require.Len(t, held.Requirements, 1)
		d := held.Requirements[0]
		require.Equal(t, definition, d.DefinitionID)
		require.Equal(t, "project", d.ScopeKind)
		require.Equal(t, project, d.ScopeID)
		require.Equal(t, "stage", d.Key)
		require.Nil(t, d.OldValue)
		require.NotNil(t, d.NewValue)
		require.Equal(t, "ready", *d.NewValue)
		_, err = tx.Exec(r.ctx, `SELECT kaname._authority_resource_access_label_sources_require_v1(
		    $1::jsonb->'authority',$1::jsonb->'requirements',clock_timestamp(),1000,100)`, receipt)
		require.NoError(t, err)
		// Успешный ответ точно сообщает общую стоимость, включая удержание источников apply.
		_, err = tx.Exec(r.ctx, moveExternalCopyHoldSQL, dotted, id, physical, proposed, actor, held.Rows, held.Reads)
		require.NoError(t, err)
		for _, budgets := range [][2]int{{held.Rows - 1, held.Reads}, {held.Rows, held.Reads - 1}} {
			probe, err := tx.Begin(r.ctx)
			require.NoError(t, err)
			_, err = probe.Exec(r.ctx, moveExternalCopyHoldSQL, dotted, id, physical, proposed, actor, budgets[0], budgets[1])
			requireAccessDefinitionSQLState(t, err, "54000")
			require.NoError(t, probe.Rollback(r.ctx))
		}
	})

	t.Run("empty_registration_is_held", func(t *testing.T) {
		tx, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		const other = id + "/unbound"
		var old json.RawMessage
		require.NoError(t, tx.QueryRow(r.ctx, `INSERT INTO kaname.resource_mirror AS m
		    (object_type,object_id,parent_project_id,labels) VALUES($1,$2,$3,$4::jsonb)
		    RETURNING jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m))`, dotted, other, project, proposed).Scan(&old))
		var receipt json.RawMessage
		require.NoError(t, tx.QueryRow(r.ctx, moveExternalCopyHoldSQL, dotted, other, old, proposed, actor, 1000, 100).Scan(&receipt))
		var empty bool
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT $1::jsonb->'binding'='null'::jsonb
		    AND $1::jsonb->'registration_scopes'='[]'::jsonb`, receipt).Scan(&empty))
		require.True(t, empty)
		_, err = tx.Exec(r.ctx, `SELECT kaname._authority_resource_access_label_sources_require_v1(
		    $1::jsonb->'authority',$1::jsonb->'requirements',clock_timestamp(),1000,100)`, receipt)
		require.NoError(t, err)

		observer, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, observer)
		var acquired bool
		require.NoError(t, observer.QueryRow(r.ctx, `SELECT pg_try_advisory_xact_lock(
		    1262569300,hashtext(jsonb_build_array($1::text,$2::text)::text))`, model, other).Scan(&acquired))
		require.False(t, acquired)
		// Параллельная запись привязки для другого объекта разрешена.
		_, err = observer.Exec(r.ctx, `LOCK TABLE ONLY kaname.object_project_binding IN ROW EXCLUSIVE MODE NOWAIT`)
		require.NoError(t, err)
		_, err = observer.Exec(r.ctx, `LOCK TABLE ONLY kaname.resource_registration_scope IN ROW EXCLUSIVE MODE NOWAIT`)
		requireAccessDefinitionSQLState(t, err, "55P03")
	})

	t.Run("runtime_cannot_capture", func(t *testing.T) {
		_, err := r.runtime.Exec(r.ctx, moveExternalCopyHoldSQL, dotted, id, physical, proposed, actor, 1000, 100)
		requireAccessDefinitionSQLState(t, err, "42501")
	})

	for _, tc := range []struct {
		name, typ, root, next, state string
	}{
		{"iam_root", "iam.project", project, proposed, "42501"},
		{"absent_root", dotted, id + "/absent", proposed, "40001"},
		{"wrong_coordinate", "compute.instance", id, proposed, "40001"},
		{"unchanged", dotted, id, "{}", "42501"},
		{"missing_key", dotted, id, `{"other":""}`, "42501"},
		{"different_value", dotted, id, `{"stage":"local"}`, "42501"},
		{"undefined_key", dotted, id, `{"unprotected":"local"}`, "42501"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := r.admin.Exec(r.ctx, moveExternalCopyHoldSQL, tc.typ, tc.root, physical, tc.next, actor, 1000, 100)
			requireAccessDefinitionSQLState(t, err, tc.state)
		})
	}
	for _, tc := range []struct {
		name, query, state string
		args               []any
	}{
		{"foreign_registration", `INSERT INTO kaname.resource_registration_scope(object_type,object_id,project_id,account_id)
		    VALUES($1,$2,$3,$4)`, "42501", []any{model, id, project, r.b}},
		{"ambiguous_definition", `INSERT INTO kaname.authority_access_label_definition
		    (scope_kind,scope_id,module,resource,label_key) VALUES('account',$1,'vpc','network','stage')`, "42501", []any{r.a}},
		{"scope_only_update", `UPDATE kaname.catalog_verb SET per_object=false WHERE module='vpc' AND resource='network' AND verb='update'`, "42501", nil},
		{"new_generation", `UPDATE kaname.resource_mirror SET labels=labels WHERE object_type=$1 AND object_id=$2`, "40001", []any{dotted, id}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := r.admin.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, tx)
			tag, err := tx.Exec(r.ctx, tc.query, tc.args...)
			require.NoError(t, err)
			require.EqualValues(t, 1, tag.RowsAffected())
			_, err = tx.Exec(r.ctx, moveExternalCopyHoldSQL, dotted, id, physical, proposed, actor, 1000, 100)
			requireAccessDefinitionSQLState(t, err, tc.state)
		})
	}

	t.Run("another_writer_holds_registration", func(t *testing.T) {
		tx, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		_, err = tx.Exec(r.ctx, `SELECT pg_advisory_xact_lock(1262569300,hashtext(jsonb_build_array($1::text,$2::text)::text))`, model, id)
		require.NoError(t, err)
		_, err = r.admin.Exec(r.ctx, moveExternalCopyHoldSQL, dotted, id, physical, proposed, actor, 1000, 100)
		requireAccessDefinitionSQLState(t, err, "40001")
	})
	t.Run("rr_cannot_hold_sources", func(t *testing.T) {
		tx, err := r.admin.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		_, err = tx.Exec(r.ctx, moveExternalCopyHoldSQL, dotted, id, physical, proposed, actor, 1000, 100)
		requireAccessDefinitionSQLState(t, err, "25001")
	})
}
