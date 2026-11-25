// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestRoleSelectorMoveProjectCopyCommitsWithRole(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	actor := bindingPublicOwner(t, r)
	role := ids.NewID("rol")
	projects := []struct {
		id, team string
		physical json.RawMessage
	}{
		{id: ids.NewID("prj"), team: "blue"},
		{id: ids.NewID("prj"), team: "red"},
	}
	ruleSet := `[
		{"module":"iam","resources":["project"],"verbs":["list"],%q:{"team":"blue"}},
		{"module":"iam","resources":["account"],"verbs":["get"],"resource_names":[%q],
		 "children":[{"resources":["project"],"verbs":["get"],%q:{"team":"red"}}]}
	]`
	oldRules := fmt.Sprintf(ruleSet, "match_labels", r.a, "match_labels")
	newRules := fmt.Sprintf(ruleSet, "match_access_labels", r.a, "match_access_labels")
	var version, definition string
	var oldRole json.RawMessage
	require.NoError(t, r.admin.QueryRow(r.ctx, `INSERT INTO kaname.roles AS r
		(id,account_id,name,permissions,rules,labels) VALUES ($1,$2,'project_copy','[]',$3,'{}')
		RETURNING xmin::text,jsonb_build_array(xmin::text,ctid::text,to_jsonb(r))`,
		role, r.a, oldRules).Scan(&version, &oldRole))
	copies := make([]map[string]any, 0, len(projects))
	for i := range projects {
		p := &projects[i]
		labels := map[string]string{"extra": "local"}
		if i == 0 {
			labels["team"] = p.team
		}
		require.NoError(t, r.admin.QueryRow(r.ctx, `INSERT INTO kaname.projects AS p (id,account_id,name,labels)
			VALUES ($1,$2,'project-copy-'||$3::text,$4)
			RETURNING jsonb_build_array(xmin::text,ctid::text,to_jsonb(p))`,
			p.id, r.a, p.team, labels).Scan(&p.physical))
		copies = append(copies, map[string]any{"root_type": "iam.project", "root_id": p.id,
			"physical": p.physical, "new_access_labels": map[string]string{"team": p.team}})
	}
	// Прямой проект читается из родной таблицы, вложенный — через типизированное ребро.
	var mirror json.RawMessage
	require.NoError(t, r.admin.QueryRow(r.ctx, `INSERT INTO kaname.resource_mirror AS m (object_type,object_id,parent_account_id,labels)
		VALUES ('iam.project',$1,$2,'{"team":"red"}')
		RETURNING jsonb_build_array(xmin::text,ctid::text,to_jsonb(m))`, projects[1].id, r.a).Scan(&mirror))
	copies[1]["project_source"] = map[string]any{"mirror_physical": mirror, "definition": true}
	tag, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_parent_edge(object_type,object_id,parent_type,parent_id,depth)
		SELECT p.object_type,$1,a.object_type,$2,1
		FROM ONLY kaname.catalog_resource p CROSS JOIN ONLY kaname.catalog_resource a
		WHERE p.dotted='iam.project' AND p.live AND a.dotted='iam.account' AND a.live`, projects[1].id, r.a)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	require.NoError(t, r.admin.QueryRow(r.ctx, `INSERT INTO kaname.authority_access_label_definition
		(scope_kind,scope_id,module,resource,label_key) VALUES ('account',$1,'iam','project','team')
		RETURNING id::text`, r.a).Scan(&definition))
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_value(definition_id,label_value)
		VALUES($1::uuid,'blue'),($1::uuid,'red')`, definition)
	require.NoError(t, err)
	seedMetadataActualApplySource(t, r, actor, definition)
	pool, login, _ := roleActorFiniteLogin(t, r)

	stampRequest, err := json.Marshal(map[string]any{
		"create": false, "rules": true, "retier": false, "version": version, "mask": []string{"rules"},
		"role": map[string]any{"id": role, "rules": json.RawMessage(newRules), "permissions": []string{}},
	})
	require.NoError(t, err)
	proposal, err := json.Marshal(map[string]any{
		"role_id": role, "version": version, "physical": oldRole, "proposed_rules": json.RawMessage(newRules),
		"moves":           []map[string]int{{"rule_index": 0, "child_index": -1}, {"rule_index": 1, "child_index": 0}},
		"copy_candidates": copies,
	})
	require.NoError(t, err)

	// Внутри этого вызова выделенный LOGIN получает право на столбец ровно на
	// время применения заранее заданных OLD. Другие сессии его не видят.
	var ddl string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT format($ddl$
		CREATE FUNCTION kaname.test_role_move_project_copy_v1() RETURNS jsonb
		LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $bridge$
		DECLARE
			move jsonb:=%1$L::jsonb;
			actor jsonb:=jsonb_build_object('type','user','id',%2$L::text);
			epoch jsonb:=kaname.authority_binding_epoch_read(NULL::text[]);
			frozen jsonb; reserved jsonb; final_copies jsonb;
			direct jsonb:=move#>'{copy_candidates,0}';
			nested jsonb:=move#>'{copy_candidates,1}';
			mirror jsonb:=nested#>'{project_source,mirror_physical}';
			held jsonb; mirror_key text;
		BEGIN
			IF session_user::text IS DISTINCT FROM %3$L THEN
				RAISE EXCEPTION 'unexpected project copy probe login' USING ERRCODE='42501';
			END IF;
			GRANT UPDATE(access_labels) ON kaname.projects TO %3$I;
			PERFORM kaname.authority_role_stage_epoch_lock(NULL::text[],epoch);
			PERFORM kaname._authority_role_move_sequence_prepare_v1(%4$L::jsonb||jsonb_build_object(
				'_access_label_authority',jsonb_build_object('actor',actor,'questions','[]'::jsonb)),move,actor,100000,4096);
			PERFORM kaname.authority_role_stage_epoch_lock(NULL::text[],epoch);
			held:=kaname._authority_role_move_project_member_graph_hold_v1(
				direct->>'root_id',direct->'physical',100000,4096);
			mirror_key:=jsonb_build_array(2,'iam.project',direct->>'root_id','')::text;
			IF held->'native' IS DISTINCT FROM direct->'physical'
				OR held#>'{graph,present}' IS DISTINCT FROM 'false'::jsonb
				OR held->'sources' IS DISTINCT FROM jsonb_build_object(mirror_key,
					jsonb_build_object('source','{}'::jsonb,'states','[]'::jsonb)) THEN
				RAISE EXCEPTION 'native project lost its exact absent mirror receipt';
			END IF;
			BEGIN
				PERFORM kaname._authority_role_move_project_copy_graph_hold_v1(
					direct->>'root_id',direct->'physical',mirror,100000,4096);
				RAISE EXCEPTION 'copy verification accepted a missing mirror';
			EXCEPTION WHEN serialization_failure THEN NULL;
			END;
			-- Устаревшая строка зеркала должна требовать повтора при бюджете,
			-- которого достаточно для физического чтения, но мало для рёбер.
			BEGIN
				PERFORM kaname._authority_role_move_project_copy_graph_hold_v1(
					nested->>'root_id',nested->'physical',jsonb_set(mirror,'{0}','"stale"'::jsonb),16,7);
				RAISE EXCEPTION 'stale project mirror generation accepted';
			EXCEPTION WHEN serialization_failure THEN NULL;
			END;
			held:=kaname._authority_role_move_project_member_graph_hold_v1(
				nested->>'root_id',nested->'physical',100000,4096);
			mirror_key:=jsonb_build_array(2,'iam.project',nested->>'root_id','')::text;
			IF held->'sources'->mirror_key->'states' IS DISTINCT FROM jsonb_build_array(mirror)
				OR held#>'{graph,present}' IS DISTINCT FROM 'true'::jsonb
				OR held#>'{graph,ancestors,0,projection,id}' IS DISTINCT FROM nested#>'{physical,2,account_id}'
				OR held IS DISTINCT FROM kaname._authority_role_move_project_copy_graph_hold_v1(
					nested->>'root_id',nested->'physical',mirror,100000,4096) THEN
				RAISE EXCEPTION 'physical project mirror or ancestor receipt differs';
			END IF;
			SELECT jsonb_agg(c.value-ARRAY['physical','project_source']
				ORDER BY (c.value->>'root_type') COLLATE "C",(c.value->>'root_id') COLLATE "C") INTO final_copies
			FROM jsonb_array_elements(move->'copy_candidates') c;
			PERFORM kaname._authority_role_move_sequence_finalize_v1(final_copies,100000,4096);
			PERFORM kaname._authority_role_move_sequence_approve_v1();
			SELECT jsonb_object_agg(e.origin#>>'{new,id}',e.reserved_id) INTO reserved
			FROM pg_temp.kaname_authority_sequence_effects e WHERE e.selected AND e.table_name='resource_journal';
			frozen:=kaname._authority_sequence_store_v3()->'frozen';
			PERFORM kaname._authority_role_move_roots_write_v1();
			REVOKE UPDATE(access_labels) ON kaname.projects FROM %3$I;
			RETURN jsonb_build_object('journal',reserved,'outputs',frozen->'selector_move_outputs');
		END;
		$bridge$;
		REVOKE ALL ON FUNCTION kaname.test_role_move_project_copy_v1() FROM PUBLIC;
		GRANT EXECUTE ON FUNCTION kaname.test_role_move_project_copy_v1() TO %3$I;
	$ddl$,$1::text,$2::text,$3::text,$4::text)`, string(proposal), actor, login, string(stampRequest)).Scan(&ddl))
	_, err = r.admin.Exec(r.ctx, ddl)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := r.admin.Exec(ctx, `DROP FUNCTION kaname.test_role_move_project_copy_v1()`)
		require.NoError(t, err)
	})
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	fullContractActivate(t, r)
	identity := r.bundle.Identity()
	begin := func(t *testing.T) pgx.Tx {
		t.Helper()
		tx, err := pool.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		_, err = tx.Exec(r.ctx, `SELECT kaname.authority_protocol_enter_typed_v3('global',ARRAY[]::text[],'[]'::jsonb,
			'role',$1,$2,$3,'decision')`, identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
		require.NoError(t, err)
		return tx
	}
	const applyRoots = `SELECT kaname.test_role_move_project_copy_v1(),transaction_timestamp()`
	const roleStamp = `SELECT kaname.authority_role_sequence_stamp_v3($1::jsonb)`
	t.Run("копии не фиксируются без записи роли", func(t *testing.T) {
		tx := begin(t)
		var reserved json.RawMessage
		var started, stamp time.Time
		require.NoError(t, tx.QueryRow(r.ctx, applyRoots).Scan(&reserved, &started))
		require.NoError(t, tx.QueryRow(r.ctx, roleStamp, stampRequest).Scan(&stamp))
		var pgErr *pgconn.PgError
		require.ErrorAs(t, tx.Commit(r.ctx), &pgErr)
		require.Equal(t, "42501", pgErr.Code)
		var journal, audit, reconcile int
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
			(SELECT count(*) FROM ONLY kaname.resource_journal WHERE created_at=$1),
			(SELECT count(*) FROM ONLY kaname.audit_outbox WHERE created_at=$1),
			(SELECT count(*) FROM ONLY kaname.resource_reconcile_outbox WHERE created_at=$1)`, started).
			Scan(&journal, &audit, &reconcile))
		require.Zero(t, journal)
		require.Zero(t, audit)
		require.Zero(t, reconcile)
		var roleUntouched bool
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT to_jsonb(r)=$2::jsonb->2
			FROM ONLY kaname.roles r WHERE r.id=$1`, role, oldRole).Scan(&roleUntouched))
		require.True(t, roleUntouched)
		for _, project := range projects {
			var untouched bool
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT to_jsonb(p)=$2::jsonb->2
				FROM ONLY kaname.projects p WHERE p.id=$1`, project.id, project.physical).Scan(&untouched))
			require.True(t, untouched, "проект %s после отката", project.id)
		}
	})

	tx := begin(t)
	var reserved json.RawMessage
	var started, stamp time.Time
	require.NoError(t, tx.QueryRow(r.ctx, applyRoots).Scan(&reserved, &started))
	require.NoError(t, tx.QueryRow(r.ctx, roleStamp, stampRequest).Scan(&stamp))
	tag, err = tx.Exec(r.ctx, `UPDATE ONLY kaname.roles SET rules=$2::jsonb,updated_at=$3 WHERE id=$1 AND xmin::text=$4`,
		role, newRules, stamp, version)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	require.NoError(t, tx.Commit(r.ctx))

	var projectEvents, roleEvents, auditEvents, reconcileEvents int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
		count(*) FILTER (WHERE resource_kind='project'),count(*) FILTER (WHERE resource_kind='iam_role'),
		(SELECT count(*) FROM ONLY kaname.audit_outbox WHERE created_at=$1),
		(SELECT count(*) FROM ONLY kaname.resource_reconcile_outbox WHERE created_at=$1)
		FROM ONLY kaname.resource_journal WHERE created_at=$1`, started).
		Scan(&projectEvents, &roleEvents, &auditEvents, &reconcileEvents))
	require.Equal(t, len(projects), projectEvents)
	require.Equal(t, 1, roleEvents)
	require.Equal(t, len(projects), auditEvents)
	require.Equal(t, len(projects), reconcileEvents)
	for _, project := range projects {
		var exactRole, exactProject, exactJournals, exactAudit, exactReconcile bool
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
		to_jsonb(r)=(($1::jsonb->2)||jsonb_build_object('rules',$3::jsonb,'updated_at',$4::timestamptz)),
		to_jsonb(p)=jsonb_set($2::jsonb->2,'{access_labels}',jsonb_build_object('team',$5::text),false),
		(SELECT count(*)=2 AND bool_and(j.event_type='UPDATED' AND j.created_at=$6::timestamptz
			AND j.scope=jsonb_build_array(jsonb_build_object('type','account','id',p.account_id))
			AND j.payload=jsonb_build_object('id',j.resource_id) AND
			(j.resource_kind,j.resource_id,j.project_id,j.sequence_no) IN (
				('project',p.id,p.id,($7::jsonb#>>ARRAY['journal',p.id])::bigint),
				('iam_role',r.id,'',($7::jsonb#>>ARRAY['journal',r.id])::bigint)))
			FROM ONLY kaname.resource_journal j WHERE j.created_at=$6 AND j.resource_id IN (p.id,r.id)),
		(SELECT count(*)=1 AND bool_and(to_jsonb(a)=jsonb_build_object('id',$7::jsonb#>>ARRAY['outputs','iam.project:'||p.id,'audit','id'],
			'event_type','iam.project.updated','tenant_account_id',p.account_id,'status','pending','attempts',0,
			'created_at',$6::timestamptz,'next_attempt_at',$6::timestamptz,'sent_at',NULL,'last_error',NULL,
			'event_payload',jsonb_build_object('actor',$8::text,'resource_type','project','resource_id',p.id,
				'account_id',p.account_id,'changed_fields',jsonb_build_array('access_labels'))))
			FROM ONLY kaname.audit_outbox a WHERE a.created_at=$6 AND a.event_payload->>'resource_id'=p.id),
		(SELECT count(*)=1 AND bool_and(to_jsonb(q)=jsonb_build_object('id',($7::jsonb#>>ARRAY['outputs','iam.project:'||p.id,'reconcile','id'])::bigint,
			'object_type','iam.project','object_id',p.id,'event_type','mirror.upsert','created_at',$6::timestamptz,
			'sent_at',NULL,'last_error',NULL,'attempt_count',0))
			FROM ONLY kaname.resource_reconcile_outbox q WHERE q.created_at=$6 AND q.object_id=p.id)
		FROM ONLY kaname.roles r, ONLY kaname.projects p
		WHERE r.id=$1::jsonb#>>'{2,id}' AND p.id=$2::jsonb#>>'{2,id}'`,
			oldRole, project.physical, newRules, stamp, project.team, started, reserved, actor).
			Scan(&exactRole, &exactProject, &exactJournals, &exactAudit, &exactReconcile))
		require.True(t, exactRole, "роль после фиксации")
		require.True(t, exactProject, "проект %s после фиксации", project.id)
		require.True(t, exactJournals, "журнал роли и проекта %s", project.id)
		require.True(t, exactAudit, "аудит проекта %s", project.id)
		require.True(t, exactReconcile, "очередь согласования проекта %s", project.id)
	}
}
