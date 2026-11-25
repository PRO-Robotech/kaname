// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestRoleSelectorMoveCensusRequiresAllNestedProjects(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	role, project, plainProject := ids.NewID("rol"), ids.NewID("prj"), ids.NewID("prj")
	rules, err := json.Marshal([]map[string]any{{
		"module": "iam", "resources": []string{"account"}, "verbs": []string{"get"}, "resource_names": []string{r.a},
		"children": []map[string]any{{
			"resources": []string{"project"}, "verbs": []string{"get"}, "match_labels": map[string]string{"team": "blue"},
		}},
	}, {
		"module": "iam", "resources": []string{"project"}, "verbs": []string{"get"},
		"match_labels": map[string]string{"zone": "west"},
	}})
	require.NoError(t, err)
	var oldRole json.RawMessage
	require.NoError(t, r.admin.QueryRow(r.ctx, `INSERT INTO kaname.roles AS r
		(id,account_id,name,permissions,rules,labels) VALUES($1,$2,'nested_project_census','[]',$3,'{}')
		RETURNING to_jsonb(r)`, role, r.a, rules).Scan(&oldRole))
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.projects(id,account_id,name,labels)
		VALUES ($1,$2,'nested-census','{"team":"blue","zone":"west"}'), ($3,$2,'direct-census','{"zone":"west"}')`, project, r.a, plainProject)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_mirror(object_type,object_id,parent_account_id,labels)
		VALUES ('iam.project',$1,$2,'{"team":"blue"}')`, project, r.a)
	require.NoError(t, err)
	tag, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_parent_edge(object_type,object_id,parent_type,parent_id,depth)
		SELECT p.object_type,$1,a.object_type,$2,1
		FROM ONLY kaname.catalog_resource p CROSS JOIN ONLY kaname.catalog_resource a
		WHERE p.dotted='iam.project' AND p.live AND a.dotted='iam.account' AND a.live`, project, r.a)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())

	var projectRole json.RawMessage
	require.NoError(t, r.admin.QueryRow(r.ctx, `INSERT INTO kaname.roles AS r
		(id,project_id,name,permissions,rules,labels) VALUES($1,$2,'mixed_project_scope','[]',$3,'{}')
		RETURNING to_jsonb(r)`, ids.NewID("rol"), plainProject, rules).Scan(&projectRole))

	pool, login, _ := roleActorFiniteLogin(t, r)
	var ddl string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT format($ddl$
		CREATE FUNCTION kaname.test_definition_project_copy_census(p_copies jsonb,p_expected jsonb,p_holders jsonb,p_mixed boolean,p_project_scope boolean) RETURNS jsonb
		LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $bridge$
		DECLARE
			moves jsonb:=CASE WHEN p_mixed THEN '[{"rule_index":0,"child_index":0},{"rule_index":1,"child_index":-1}]'::jsonb
				ELSE '[{"rule_index":0,"child_index":0}]'::jsonb END;
			role_image jsonb:=CASE WHEN p_project_scope THEN %3$L::jsonb ELSE %1$L::jsonb END;
		BEGIN
			IF session_user::text IS DISTINCT FROM %2$L THEN
				RAISE EXCEPTION 'unexpected definition census probe login' USING ERRCODE='42501';
			END IF;
			IF p_holders IS NULL THEN
				RETURN kaname._authority_role_move_definition_project_census_v1(
					role_image,moves,p_copies,p_expected,100000,4096)->'source';
			END IF;
			RETURN kaname._authority_role_move_bound_project_census_v1(
				role_image,moves,p_holders,p_copies,p_expected,100000,4096)->'source';
		END;
		$bridge$;
		REVOKE ALL ON FUNCTION kaname.test_definition_project_copy_census(jsonb,jsonb,jsonb,boolean,boolean) FROM PUBLIC;
		GRANT EXECUTE ON FUNCTION kaname.test_definition_project_copy_census(jsonb,jsonb,jsonb,boolean,boolean) TO %2$I;
	$ddl$, $1::text,$2::text,$3::text)`, string(oldRole), login, string(projectRole)).Scan(&ddl))
	_, err = r.admin.Exec(r.ctx, ddl)
	require.NoError(t, err)
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	fullContractActivate(t, r)
	begin := func(t *testing.T) pgx.Tx {
		t.Helper()
		tx, err := pool.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		i := r.bundle.Identity()
		_, err = tx.Exec(r.ctx, `SELECT kaname.authority_protocol_enter_typed_v3('global',ARRAY[]::text[],'[]'::jsonb,
			'role',$1,$2,$3,'decision')`, i.ModelID, i.CatalogID, i.ProjectorVersion)
		require.NoError(t, err)
		return tx
	}
	const probe = `SELECT kaname.test_definition_project_copy_census($1::jsonb,$2::jsonb,$3::jsonb,$4::boolean,$5::boolean)`
	copies, err := json.Marshal([]map[string]any{{
		"root_type": "iam.project", "root_id": project, "new_access_labels": map[string]string{"team": "blue"},
	}})
	require.NoError(t, err)
	t.Run("пустое предложение пропускает проект", func(t *testing.T) {
		tx := begin(t)
		var result json.RawMessage
		err := tx.QueryRow(r.ctx, probe, `[]`, nil, nil, false, false).Scan(&result)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "40001", pgErr.Code)
		require.Contains(t, pgErr.Message, "omits an OLD selector match")
	})
	t.Run("нативно совпадающая пара тоже входит в перепись", func(t *testing.T) {
		tx := begin(t)
		var prepared, replayed json.RawMessage
		require.NoError(t, tx.QueryRow(r.ctx, probe, copies, nil, nil, false, false).Scan(&prepared))
		require.NoError(t, tx.QueryRow(r.ctx, probe, copies, prepared, nil, false, false).Scan(&replayed))
		require.JSONEq(t, string(prepared), string(replayed))
		err = tx.QueryRow(r.ctx, probe, `[]`, prepared, nil, false, false).Scan(&replayed)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "40001", pgErr.Code)
		require.Contains(t, pgErr.Message, "omits an OLD selector match")
	})
	t.Run("ожидающая выдача сохраняет копию после истечения действующей", func(t *testing.T) {
		tx := begin(t)
		active := map[string]any{
			"class": "ACTIVE", "expires_at": nil, "scope": []string{"cluster", "cluster_root"},
			"target": map[string]bool{"allInScope": true}, "subjects": [][]string{{"user", r.a}},
			"binding_tuples": []map[string]string{{"fga_user": "cluster:cluster_root", "relation": "cluster", "object": "iam_access_binding:b-active"}},
		}
		pending := map[string]any{
			"class": "PENDING", "expires_at": nil, "scope": []string{"account", r.a},
			"target":   map[string]any{"resources": []map[string]string{{"type": "iam.account", "id": r.a}}},
			"subjects": [][]string{{"user", r.a}}, "binding_tuples": []any{},
		}
		preparedHolders, err := json.Marshal(map[string]any{"b-active": active, "b-pending": pending})
		require.NoError(t, err)
		finalHolders, err := json.Marshal(map[string]any{"b-pending": pending})
		require.NoError(t, err)
		var prepared, replayed json.RawMessage
		require.NoError(t, tx.QueryRow(r.ctx, probe, copies, nil, preparedHolders, false, false).Scan(&prepared))
		require.NoError(t, tx.QueryRow(r.ctx, probe, copies, prepared, finalHolders, false, false).Scan(&replayed))
		require.JSONEq(t, string(prepared), string(replayed))
		err = tx.QueryRow(r.ctx, probe, `[]`, prepared, finalHolders, false, false).Scan(&replayed)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "40001", pgErr.Code)
		require.Contains(t, pgErr.Message, "omits an OLD selector match")
	})

	t.Run("истечение единственной поддерживающей выдачи убирает нативно совпадающую пару", func(t *testing.T) {
		tx := begin(t)
		active := map[string]any{
			"class": "ACTIVE", "expires_at": nil, "scope": []string{"account", r.a},
			"target": map[string]bool{"allInScope": true}, "subjects": [][]string{{"user", r.a}},
			"binding_tuples": []map[string]string{{"fga_user": "account:" + r.a, "relation": "account", "object": "iam_access_binding:b-active"}},
		}
		other := map[string]any{
			"class": "PENDING", "expires_at": nil, "scope": []string{"account", r.a},
			"target":   map[string]any{"resources": []map[string]string{{"type": "iam.project", "id": project}}},
			"subjects": [][]string{{"user", r.a}}, "binding_tuples": []any{},
		}
		preparedHolders, err := json.Marshal(map[string]any{"b-active": active, "b-other": other})
		require.NoError(t, err)
		finalHolders, err := json.Marshal(map[string]any{"b-other": other})
		require.NoError(t, err)
		var prepared, replayed json.RawMessage
		require.NoError(t, tx.QueryRow(r.ctx, probe, copies, nil, preparedHolders, false, false).Scan(&prepared))
		require.NoError(t, tx.QueryRow(r.ctx, probe, `[]`, prepared, finalHolders, false, false).Scan(&replayed))
		require.JSONEq(t, string(prepared), string(replayed))
		err = tx.QueryRow(r.ctx, probe, copies, prepared, finalHolders, false, false).Scan(&replayed)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "40001", pgErr.Code)
		require.Contains(t, pgErr.Message, "without effective OLD support")
	})

	t.Run("прямые проекты без зеркала и вложенные проекты сверяются вместе", func(t *testing.T) {
		tx := begin(t)
		rows := []map[string]any{
			{"root_type": "iam.project", "root_id": project, "new_access_labels": map[string]string{"team": "blue", "zone": "west"}},
			{"root_type": "iam.project", "root_id": plainProject, "new_access_labels": map[string]string{"zone": "west"}},
		}
		mixed, err := json.Marshal(rows)
		require.NoError(t, err)
		var prepared, replayed json.RawMessage
		require.NoError(t, tx.QueryRow(r.ctx, probe, mixed, nil, nil, true, false).Scan(&prepared))
		require.NoError(t, tx.QueryRow(r.ctx, probe, mixed, prepared, nil, true, false).Scan(&replayed))
		require.JSONEq(t, string(prepared), string(replayed))
		missing, err := json.Marshal(rows[:1])
		require.NoError(t, err)
		err = tx.QueryRow(r.ctx, probe, missing, prepared, nil, true, false).Scan(&replayed)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "40001", pgErr.Code)
		require.Contains(t, pgErr.Message, "omits an OLD selector match")
	})

	t.Run("проектная роль ограничена собственным проектом без зеркала", func(t *testing.T) {
		tx := begin(t)
		own, err := json.Marshal([]map[string]any{{
			"root_type": "iam.project", "root_id": plainProject, "new_access_labels": map[string]string{"zone": "west"},
		}})
		require.NoError(t, err)
		var prepared, replayed json.RawMessage
		require.NoError(t, tx.QueryRow(r.ctx, probe, own, nil, nil, true, true).Scan(&prepared))
		require.NoError(t, tx.QueryRow(r.ctx, probe, own, prepared, nil, true, true).Scan(&replayed))
		require.JSONEq(t, string(prepared), string(replayed))
	})

}
