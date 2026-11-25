// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestRoleMoveRoleImageHoldsPhysicalGenerationAndRebuildsRules(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	const oldRules = `[
		{"module":"storage","resources":["bucket"],"verbs":["get"],"match_labels":{"team":"red"},"resource_names":null,
		 "children":[{"resources":["version"],"verbs":["list","get"],"match_labels":{"stage":"ready"}},
		             {"resources":["object"],"verbs":["get"],"match_labels":{"team":"green"}}]},
		{"module":"iam","resources":["project"],"verbs":["list","get"],"match_labels":null}]`
	const newRules = `[
		{"module":"storage","resources":["bucket"],"verbs":["get"],"match_access_labels":{"team":"red"},
		 "children":[{"resources":["version"],"verbs":["list","get"],"match_labels":{"stage":"ready"}},
		             {"resources":["object"],"verbs":["get"],"match_access_labels":{"team":"green"}}]},
		{"module":"iam","resources":["project"],"verbs":["list","get"],"match_labels":null}]`
	const positions = `[{"rule_index":0,"child_index":1},{"rule_index":0,"child_index":-1}]`
	const hold = `SELECT kaname._authority_role_move_role_image_hold_v1($1,$2,$3,$4,$5,$6,$7)`
	const readPhysical = `SELECT xmin::text,jsonb_build_array(xmin::text,ctid::text,to_jsonb(r))
		FROM ONLY kaname.roles r WHERE id=$1`
	type role struct {
		id, version string
		physical    json.RawMessage
	}
	seed := func(account, project any) role {
		t.Helper()
		item := role{id: ids.NewID("rol")}
		err := r.admin.QueryRow(r.ctx, `INSERT INTO kaname.roles AS r (id,account_id,project_id,name,description,permissions,rules,labels)
			VALUES ($1,$2,$3,'move_role_image','stored description','[]',$4,'{"field":"kept"}')
			RETURNING xmin::text,jsonb_build_array(xmin::text,ctid::text,to_jsonb(r))`,
			item.id, account, project, oldRules).Scan(&item.version, &item.physical)
		require.NoError(t, err)
		return item
	}
	account := seed(r.a, nil)
	project := seed(nil, kac127SeedProject(t, r.ctx, r.admin, r.a, "moveimage"))

	for _, item := range []role{account, project} {
		t.Run("exact "+item.id, func(t *testing.T) {
			tx, err := r.admin.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, tx)
			var sameOld, sameNew bool
			var rows, reads int
			err = tx.QueryRow(r.ctx, `WITH h(image) AS (`+hold+`)
				SELECT image->'physical'=$3::jsonb,
				       image->'new_role'=jsonb_set($3::jsonb->2,'{rules}',$5::jsonb,false),
				       (image->>'rows')::int,(image->>'reads')::int FROM h`,
				item.id, item.version, item.physical, positions, newRules, 8, 3).Scan(&sameOld, &sameNew, &rows, &reads)
			require.NoError(t, err)
			require.True(t, sameOld)
			require.True(t, sameNew)
			require.Equal(t, 8, rows) // таблица, роль, две позиции, два корня, два ребёнка
			require.Equal(t, 3, reads)
			var actual json.RawMessage
			var version string
			require.NoError(t, tx.QueryRow(r.ctx, readPhysical, item.id).Scan(&version, &actual))
			require.JSONEq(t, string(item.physical), string(actual))
			_, err = r.admin.Exec(r.ctx, `SELECT id FROM ONLY kaname.roles WHERE id=$1 FOR UPDATE NOWAIT`, item.id)
			requireAccessDefinitionSQLState(t, err, "55P03")
		})
	}
	for _, tc := range []struct {
		name, moves, proposed, code string
		rows, reads                 int
	}{
		{"empty", `[]`, newRules, "42501", 8, 3},
		{"duplicate", `[{"rule_index":0,"child_index":1},{"rule_index":0,"child_index":1}]`, newRules, "42501", 8, 3},
		{"missing child", `[{"rule_index":0,"child_index":2}]`, newRules, "42501", 8, 3},
		{"missing root", `[{"rule_index":2,"child_index":-1}]`, newRules, "42501", 8, 3},
		{"ordinary selector absent", `[{"rule_index":1,"child_index":-1}]`, oldRules, "42501", 8, 3},
		{"coercible string", `[{"rule_index":"0","child_index":1}]`, newRules, "42501", 8, 3},
		{"fractional ordinal", `[{"rule_index":0.5,"child_index":1}]`, newRules, "42501", 8, 3},
		{"missing ordinal", `[{"rule_index":0}]`, newRules, "42501", 8, 3},
		{"negative child", `[{"rule_index":0,"child_index":-2}]`, newRules, "42501", 8, 3},
		{"unknown field", `[{"rule_index":0,"child_index":1,"extra":false}]`, newRules, "42501", 8, 3},
		{"unselected child rewritten", positions, strings.Replace(newRules, `"match_labels":{"stage"`, `"match_access_labels":{"stage"`, 1), "42501", 8, 3},
		{"untouched null discarded", positions, strings.Replace(newRules, `,"match_labels":null`, "", 1), "42501", 8, 3},
		{"short row budget", positions, newRules, "54000", 7, 3},
		{"short read budget", positions, newRules, "54000", 8, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := r.admin.Exec(r.ctx, hold, account.id, account.version, account.physical, tc.moves, tc.proposed, tc.rows, tc.reads)
			requireAccessDefinitionSQLState(t, err, tc.code)
		})
	}
	t.Run("different xmin", func(t *testing.T) {
		_, err := r.admin.Exec(r.ctx, hold, account.id, "0", account.physical, positions, newRules, 8, 3)
		requireAccessDefinitionSQLState(t, err, "40001")
	})
	t.Run("different role", func(t *testing.T) {
		_, err := r.admin.Exec(r.ctx, hold, project.id, account.version, account.physical, positions, newRules, 8, 3)
		requireAccessDefinitionSQLState(t, err, "40001")
	})
	t.Run("same xmin and row with different ctid", func(t *testing.T) {
		tx, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		const bump = `UPDATE ONLY kaname.roles AS r SET description=description WHERE id=$1
			RETURNING xmin::text,jsonb_build_array(xmin::text,ctid::text,to_jsonb(r))`
		var first, second json.RawMessage
		var version, nextVersion string
		require.NoError(t, tx.QueryRow(r.ctx, bump, account.id).Scan(&version, &first))
		require.NoError(t, tx.QueryRow(r.ctx, bump, account.id).Scan(&nextVersion, &second))
		require.Equal(t, version, nextVersion)
		var onlyCTIDChanged bool
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT $1::jsonb->1 <> $2::jsonb->1 AND $1::jsonb-1 = $2::jsonb-1`, first, second).Scan(&onlyCTIDChanged))
		require.True(t, onlyCTIDChanged)
		_, err = tx.Exec(r.ctx, hold, account.id, version, first, positions, newRules, 8, 3)
		requireAccessDefinitionSQLState(t, err, "40001")
	})
	t.Run("retired tenant", func(t *testing.T) {
		tx, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		var physical json.RawMessage
		var version string
		err = tx.QueryRow(r.ctx, `UPDATE ONLY kaname.roles AS r SET live=false,retired_at=now(),retired_reason='probe',retired_by='probe'
			WHERE id=$1 RETURNING xmin::text,jsonb_build_array(xmin::text,ctid::text,to_jsonb(r))`, account.id).Scan(&version, &physical)
		require.NoError(t, err)
		_, err = tx.Exec(r.ctx, hold, account.id, version, physical, positions, newRules, 8, 3)
		requireAccessDefinitionSQLState(t, err, "42501")
	})
	t.Run("system role", func(t *testing.T) {
		var system role
		err := r.admin.QueryRow(r.ctx, `SELECT id,xmin::text,jsonb_build_array(xmin::text,ctid::text,to_jsonb(r)) FROM ONLY kaname.roles r WHERE is_system LIMIT 1`).Scan(&system.id, &system.version, &system.physical)
		require.NoError(t, err)
		_, err = r.admin.Exec(r.ctx, hold, system.id, system.version, system.physical, positions, newRules, 8, 3)
		requireAccessDefinitionSQLState(t, err, "42501")
	})
	t.Run("changed table shape", func(t *testing.T) {
		tx, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		_, err = tx.Exec(r.ctx, "ALTER TABLE ONLY kaname.roles ENABLE ROW LEVEL SECURITY")
		require.NoError(t, err)
		_, err = tx.Exec(r.ctx, hold, account.id, account.version, account.physical, positions, newRules, 8, 3)
		requireAccessDefinitionSQLState(t, err, "42501")
	})
	t.Run("repeatable read", func(t *testing.T) {
		tx, err := r.admin.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		_, err = tx.Exec(r.ctx, hold, account.id, account.version, account.physical, positions, newRules, 8, 3)
		requireAccessDefinitionSQLState(t, err, "25001")
	})
	var executable bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,
		'kaname._authority_role_move_role_image_hold_v1(text,text,jsonb,jsonb,jsonb,integer,integer)','EXECUTE')`).Scan(&executable))
	require.False(t, executable)
	_, err := r.runtime.Exec(r.ctx, hold, account.id, account.version, account.physical, positions, newRules, 8, 3)
	requireAccessDefinitionSQLState(t, err, "42501")
}
