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
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
	"github.com/PRO-Robotech/kaname/internal/resourceeffect"
	"github.com/stretchr/testify/require"
)

func TestRoleSelectorMoveBindingNewKeepsRecipientsAndRejectsChangedCensus(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	actor := bindingPublicOwner(t, r)
	second := seedMemberUser(t, r.ctx, r.admin, r.a, "move-new-second")
	const childrenAndNamed = `,"children":[{"resources":["project"],"verbs":["get"]}]},{"module":"iam","resources":["project"],"verbs":["get"],"resource_names":["prj-named"]},{"module":"iam","resources":["accessBinding"],"verbs":["get"],"resource_names":["acb-retained-missing"]},{"module":"iam","resources":["accessBinding"],"verbs":["get"],`
	const wideChild = `,"children":[{"resources":["project"],"verbs":["get"]}]},{"module":"iam","resources":["project"],"verbs":["get"],`
	const oldRules = `[{"module":"iam","resources":["account"],"verbs":["get","list"],"match_labels":{"team":"blue"}` + childrenAndNamed + `"match_labels":{"stage":"whole-binding"}` + wideChild + `"match_labels":{"stage":"local-project"}}]`
	const newRules = `[{"module":"iam","resources":["account"],"verbs":["get","list"],"match_access_labels":{"team":"blue"}` + childrenAndNamed + `"match_access_labels":{"stage":"whole-binding"}` + wideChild + `"match_access_labels":{"stage":"local-project"}}]`
	role := ids.NewID("rol")
	var version string
	var physical json.RawMessage
	require.NoError(t, r.admin.QueryRow(r.ctx, `INSERT INTO kaname.roles AS r(id,account_id,name,permissions,rules)
		VALUES($1,$2,'binding_new_role','[]',$3) RETURNING xmin::text,jsonb_build_array(xmin::text,ctid::text,to_jsonb(r))`,
		role, r.a, oldRules).Scan(&version, &physical))
	// У старого участника другая родительская привязка. Её роль не меняется.
	var otherOwner string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.b).Scan(&otherOwner))
	independent := string(groupLifecycleBinding(t, r, r.b, otherOwner, "move_other",
		domain.Rule{Module: "iam", Resources: []string{"project"}, Verbs: []string{"list"}}))
	seed, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, seed)
	active := groupPendingBindingInHeldProducer(t, r, seed, role, r.a, "user", actor)
	pending := groupPendingBindingInHeldProducer(t, r, seed, role, r.a, "user", second)
	revoked := ids.NewID("acb")
	oldMemberProject, oldLedgerProject := ids.NewID("prj"), ids.NewID("prj")
	_, err = seed.Exec(r.ctx, `WITH b AS (
		INSERT INTO kaname.access_bindings(id,subject_type,subject_id,role_id,resource_type,resource_id,status,revoked_at)
		VALUES($1,'user',$2,$3,'account',$4,'REVOKED',now()) RETURNING id,subject_type,subject_id)
		INSERT INTO kaname.access_binding_subjects(binding_id,subject_type,subject_id) SELECT * FROM b`, revoked, actor, role, r.a)
	require.NoError(t, err)
	_, err = seed.Exec(r.ctx, `INSERT INTO kaname.access_binding_target_members(binding_id,role_id,rule_fp,object_type,object_id,verification_status)
		VALUES($1,$2,'historical-fp','iam.project',$3,'ACTIVE')`, revoked, role, oldMemberProject)
	require.NoError(t, err)
	_, err = seed.Exec(r.ctx, `INSERT INTO kaname.access_binding_emitted_tuples(binding_id,member_object_type,member_object_id,fga_user,relation,object,source)
		VALUES($1,'iam.project',$2,'user:'||$3::text,'v_get','iam_project:'||$2::text,'member')`, revoked, oldLedgerProject, actor)
	require.NoError(t, err)
	// Конечная цель называет два проекта. Один выбран именованным правилом,
	// у второго подтверждается отсутствие родной строки.
	const pendingTarget = `{"resources":[{"type":"iam.project","id":"prj-named"},{"type":"iam.project","id":"prj-other"}]}`
	_, err = seed.Exec(r.ctx, `UPDATE kaname.access_bindings SET target=$2::jsonb WHERE id=$1`, pending, pendingTarget)
	require.NoError(t, err)
	project := ids.NewID("prj")
	_, err = seed.Exec(r.ctx, `INSERT INTO kaname.projects(id,account_id,name,labels) VALUES($1,$2,'local-label-project','{"stage":"local-project"}')`, project, r.b)
	require.NoError(t, err)
	nativeOnly := ids.NewID("prj")
	_, err = seed.Exec(r.ctx, `INSERT INTO kaname.projects(id,account_id,name) VALUES($1,$2,'native-project-only')`, nativeOnly, r.b)
	require.NoError(t, err)
	const namedProject = "prj-named"
	_, err = seed.Exec(r.ctx, `INSERT INTO kaname.projects(id,account_id,name)
		VALUES($1,$2,'named-project-only')`, namedProject, r.a)
	require.NoError(t, err)
	// Реестр старой координаты сохранён под активной выдачей. Ожидающая
	// выдача сохраняет собственную историю до активации.
	_, err = seed.Exec(r.ctx, `INSERT INTO kaname.access_binding_target_members(binding_id,role_id,rule_fp,object_type,object_id,verification_status)
		VALUES($1,$3,'previous-project','iam.project',$4,'ACTIVE'),($2,$3,'pending-project','iam.project','prj-other','ACTIVE')`,
		active, pending, role, project)
	require.NoError(t, err)
	_, err = seed.Exec(r.ctx, `INSERT INTO kaname.access_binding_emitted_tuples(binding_id,member_object_type,member_object_id,fga_user,relation,object,source)
		VALUES($1,'iam.project',$4,'user:'||$3::text,'v_get','iam_project:'||$4::text,'member'),
		($2,'iam.project','prj-other','user:'||$3::text,'v_get','iam_project:prj-other','member')`, active, pending, actor, project)
	require.NoError(t, err)
	// Собственный проект записан под r.b. Единственный потомок r.a задаётся
	// парой физического зеркала и ребра в модельном словаре живого каталога.
	mirrorOnly, edgeOnly, wrongModel := ids.NewID("prj"), ids.NewID("prj"), ids.NewID("prj")
	_, err = seed.Exec(r.ctx, `INSERT INTO kaname.resource_mirror(object_type,object_id,parent_account_id)
		VALUES('iam.project',$1,$4),('iam.project',$2,$4),('iam.project',$3,$4)`, project, mirrorOnly, wrongModel, r.a)
	require.NoError(t, err)
	tag, err := seed.Exec(r.ctx, `INSERT INTO kaname.resource_parent_edge(object_type,object_id,parent_type,parent_id,depth)
		SELECT CASE WHEN x.id=$3 THEN parent.object_type ELSE child.object_type END,x.id,parent.object_type,$4,x.depth
		FROM kaname.catalog_resource child CROSS JOIN kaname.catalog_resource parent
		CROSS JOIN (VALUES($1::text,1),($1::text,2),($2::text,1),($3::text,1)) x(id,depth)
		WHERE child.dotted='iam.project' AND child.live AND parent.dotted='iam.account' AND parent.live`,
		project, edgeOnly, wrongModel, r.a)
	require.NoError(t, err)
	require.EqualValues(t, 4, tag.RowsAffected())
	// У аккаунта B есть собственное ребро с зеркалом и без родной строки.
	// Точная перепись аккаунта A обязана сохранить его физическую границу.
	orphanB := ids.NewID("prj")
	_, err = seed.Exec(r.ctx, `INSERT INTO kaname.resource_mirror(object_type,object_id,parent_account_id)
		VALUES('iam.project',$1,$2)`, orphanB, r.b)
	require.NoError(t, err)
	tag, err = seed.Exec(r.ctx, `INSERT INTO kaname.resource_parent_edge(object_type,object_id,parent_type,parent_id,depth)
		SELECT p.object_type,$1,a.object_type,$2,1 FROM ONLY kaname.catalog_resource p CROSS JOIN ONLY kaname.catalog_resource a
		WHERE p.dotted='iam.project' AND p.live AND a.dotted='iam.account' AND a.live`, orphanB, r.b)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	tag, err = seed.Exec(r.ctx, `INSERT INTO kaname.resource_parent_edge(object_type,object_id,parent_type,parent_id,depth)
		SELECT project.object_type,$1,parent.object_type,refs.id,refs.depth
		FROM ONLY kaname.catalog_resource project CROSS JOIN (VALUES('iam.project',$2::text,2),('iam.accessBinding',$3::text,3)) refs(typ,id,depth)
		JOIN ONLY kaname.catalog_resource parent ON parent.dotted=refs.typ AND parent.live
		WHERE project.dotted='iam.project' AND project.live`, orphanB, project, independent)
	require.NoError(t, err)
	require.EqualValues(t, 2, tag.RowsAffected())
	ordinaryChildren, err := resource_mirror.DescendantsOf(r.ctx, seed, []string{"iam.project"}, "iam.account", []string{r.a}, false, nil)
	require.NoError(t, err)
	require.Len(t, ordinaryChildren, 1)
	require.Equal(t, project, ordinaryChildren[0].ObjectID)
	protectedChildren, err := resource_mirror.DescendantsOf(r.ctx, seed, []string{"iam.project"}, "iam.account", []string{r.a}, true, nil)
	require.NoError(t, err)
	require.Empty(t, protectedChildren)
	_, err = seed.Exec(r.ctx, `UPDATE kaname.accounts SET labels='{"team":"blue"}' WHERE id=$1`, r.b)
	require.NoError(t, err)
	// Старый широкий предикат видит и привязку другого аккаунта.
	_, err = seed.Exec(r.ctx, `UPDATE kaname.access_bindings SET labels='{"stage":"whole-binding"}' WHERE id=$1`, independent)
	require.NoError(t, err)
	_, err = seed.Exec(r.ctx, `UPDATE kaname.access_bindings SET status='ACTIVE' WHERE id=$1`, active)
	require.NoError(t, err)
	_, err = seed.Exec(r.ctx, `INSERT INTO kaname.access_binding_subjects(binding_id,subject_type,subject_id,ordinal)
		VALUES($1,'user',$2,1)`, active, second)
	require.NoError(t, err)
	_, err = seed.Exec(r.ctx, `INSERT INTO kaname.access_binding_target_members(binding_id,role_id,rule_fp,object_type,object_id,verification_status)
		VALUES($1,$2,'historical-fp','iam.account',$3,'ACTIVE')`, independent, role, r.b)
	require.NoError(t, err)
	moveImage := func(id, xmin string, row json.RawMessage) json.RawMessage {
		t.Helper()
		data, err := json.Marshal(map[string]any{"role_id": id, "version": xmin, "physical": row,
			"proposed_rules": json.RawMessage(newRules), "copy_candidates": []any{},
			"moves": []map[string]int{{"rule_index": 0, "child_index": -1}, {"rule_index": 3, "child_index": -1}, {"rule_index": 4, "child_index": -1}}})
		require.NoError(t, err)
		return data
	}
	// Каждая проба подготовки получает свою роль и отдельную транзакцию.
	// Наличие строк в самой role_rule_selectors для проверки замка не требуется.
	lockMoves := map[string]json.RawMessage{}
	lockBindings := map[string]string{}
	for _, state := range []string{"empty", "revoked", "revoked_residual", "expired", "expired_pending", "active", "pending"} {
		id := ids.NewID("rol")
		var xmin string
		var row json.RawMessage
		require.NoError(t, seed.QueryRow(r.ctx, `INSERT INTO kaname.roles AS r(id,account_id,name,permissions,rules)
			VALUES($1,$2,$3,'[]',$4) RETURNING xmin::text,jsonb_build_array(xmin::text,ctid::text,to_jsonb(r))`,
			id, r.a, "selector_lock_"+state, oldRules).Scan(&xmin, &row))
		lockMoves[state] = moveImage(id, xmin, row)
		if state != "empty" {
			lockBindings[state] = ids.NewID("acb")
			status := state
			if state == "revoked_residual" {
				status = "revoked"
			}
			_, err = seed.Exec(r.ctx, `WITH b AS (
				INSERT INTO kaname.access_bindings(id,subject_type,subject_id,role_id,resource_type,resource_id,status,created_at,expires_at,revoked_at)
				VALUES($1,'user',$2,$3,'account',$4,CASE $5::text WHEN 'expired' THEN 'ACTIVE' WHEN 'expired_pending' THEN 'PENDING' ELSE upper($5) END,
					now()-interval '2 days',CASE WHEN $5 IN ('expired','expired_pending') THEN now()-interval '1 day' WHEN $5='pending' THEN now()+interval '1 day' END,
					CASE WHEN $5='revoked' THEN now() END)
				RETURNING id,subject_type,subject_id)
				INSERT INTO kaname.access_binding_subjects(binding_id,subject_type,subject_id) SELECT * FROM b`,
				lockBindings[state], actor, id, r.a, status)
			require.NoError(t, err)
			if status == "revoked" {
				_, err = seed.Exec(r.ctx, `INSERT INTO kaname.access_binding_target_members(binding_id,role_id,rule_fp,object_type,object_id,verification_status)
					VALUES($1,$2,'historical-fp','iam.project',$3,'ACTIVE')`, lockBindings[state], id, oldMemberProject)
				require.NoError(t, err)
			}
			if state == "revoked_residual" {
				_, err = seed.Exec(r.ctx, `INSERT INTO kaname.access_binding_emitted_tuples(binding_id,member_object_type,member_object_id,fga_user,relation,object,source)
					VALUES($1,'iam.project',$2,'user:'||$3::text,'v_get','iam_project:'||$2::text,'member')`, lockBindings[state], oldMemberProject, actor)
				require.NoError(t, err)
			}
		}
	}
	require.NoError(t, seed.Commit(r.ctx))
	move := moveImage(role, version, physical)
	lockInput, err := json.Marshal(lockMoves)
	require.NoError(t, err)
	pool, login, _ := roleActorFiniteLogin(t, r)
	// Закрытый мост привязан к этому OLD и LOGIN. В отрицательных фазах
	// меняется локальная копия квитанции, а не удержанная программа.
	var ddl string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT format($ddl$
		CREATE FUNCTION kaname.test_role_move_binding_new_v1(phase text,proposal jsonb DEFAULT NULL) RETURNS jsonb
		LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $bridge$
		DECLARE move jsonb:=%1$L::jsonb;actor jsonb:=jsonb_build_object('type','user','id',%2$L::text);
			epoch jsonb;program jsonb;prepared jsonb;request jsonb;position_no text;history text;lock_moves jsonb:=%6$L::jsonb;
		BEGIN
			IF session_user::text IS DISTINCT FROM %3$L THEN RAISE EXCEPTION 'unexpected login';END IF;
			IF phase='expired_final' THEN
				prepared:=kaname._authority_sequence_store_v3()#>'{frozen,selector_move}';
				IF prepared#>'{role,physical}' IS DISTINCT FROM lock_moves#>'{expired,physical}'
					AND prepared#>'{role,physical}' IS DISTINCT FROM lock_moves#>'{expired_pending,physical}' THEN
					RAISE EXCEPTION 'unexpected expired role probe' USING ERRCODE='42501';END IF;
				epoch:=kaname.authority_binding_epoch_read(NULL::text[]);
				PERFORM kaname.authority_role_stage_epoch_lock(NULL::text[],epoch);
				PERFORM kaname._authority_role_move_sequence_finalize_v1('[]'::jsonb,100000,4096);
				RETURN kaname._authority_sequence_store_v3()#>'{frozen,selector_move_decision}';
			END IF;
			IF phase IN ('history_revoked','history_revoked_residual','history_expired') THEN history:=substr(phase,9);END IF;
			IF history IS NOT NULL THEN move:=lock_moves->history;
			ELSIF lock_moves ? phase THEN move:=lock_moves->phase;END IF;
			IF phase='decide' OR lock_moves ? phase OR history IS NOT NULL THEN
				request:=jsonb_build_object('create',false,'rules',true,'retier',false,'version',move->'version',
					'mask',jsonb_build_array('rules'),'role',jsonb_build_object('id',move->'role_id','rules',move->'proposed_rules',
					'permissions','[]'::jsonb),'_access_label_authority',jsonb_build_object('actor',actor,'questions','[]'::jsonb));
				epoch:=kaname.authority_binding_epoch_read(NULL::text[]);
				PERFORM kaname.authority_role_stage_epoch_lock(NULL::text[],epoch);
				PERFORM kaname._authority_role_move_sequence_prepare_v1(request,move,actor,100000,4096);
				IF phase IN ('expired','expired_pending') THEN
					prepared:=kaname._authority_sequence_store_v3()#>'{frozen,selector_move}';
					RETURN jsonb_build_object('scopes',prepared#>'{expired_selector_reads,scopes}',
						'items',prepared#>'{expired_selector_reads,plan,items}',
						'positions',prepared#>'{expired_selector_reads,finite_positions}',
						'copies',prepared#>'{copies,roots}','bound_copy',prepared ? 'bound_project_copy');
				END IF;
				IF lock_moves ? phase THEN RETURN 'true'::jsonb;END IF;
				PERFORM kaname.authority_role_stage_epoch_lock(NULL::text[],epoch);
				PERFORM kaname._authority_role_move_sequence_finalize_v1('[]'::jsonb,100000,4096);
			END IF;
			program:=kaname._authority_sequence_store_v3();
			prepared:=program#>'{frozen,selector_move}';
			IF prepared#>'{role,physical}' IS DISTINCT FROM move->'physical' OR program->'selected' IS DISTINCT FROM 'null'::jsonb
				OR EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_effects WHERE selected OR registered OR claimed OR consumed) THEN
				RAISE EXCEPTION 'unexpected move program';
			END IF;
			IF history IS NOT NULL THEN RETURN kaname._authority_role_move_direct_member_sets_v1(proposal,100000,4096);END IF;
			IF phase='decide' THEN RETURN program#>'{frozen,selector_move_decision}'; END IF;
			IF phase IN ('named_parent_a','named_parent_b') THEN
				request:=jsonb_build_object('catalog_id',program#>'{frozen,selector_move_decision,predicate_plan,catalog_id}',
					'holders','[]'::jsonb,'items',jsonb_build_array(jsonb_build_object('side','new',
					'read_type',proposal->'type','child_type','iam.project','guard','objects',
					'scope',jsonb_build_array('account',CASE WHEN phase='named_parent_a' THEN %8$L ELSE %7$L END),
					'object_ids',jsonb_build_array(proposal->>'id'))));
				lock_moves:=(prepared->'binding_census')||jsonb_build_object('moved_role_id',prepared->'role_id');
				proposal:=kaname._authority_role_move_member_projects_v1(request,lock_moves,NULL,100000,4096);
				RETURN kaname._authority_role_move_member_projects_v1(request,lock_moves,proposal->'source',100000,4096)->'source';
			END IF;
			IF phase IN ('finite_parent_a','finite_parent_b','finite_parent_ttl','finite_parent_empty','finite_parent_new') THEN
				request:=jsonb_build_object('catalog_id',program#>'{frozen,selector_move_decision,predicate_plan,catalog_id}',
					'holders','[]'::jsonb,'items',jsonb_build_array(jsonb_build_object('side','old',
					'read_type','iam.account','child_type','iam.project','guard','objects',
					'scope',jsonb_build_array('account',CASE WHEN phase='finite_parent_b' THEN %7$L ELSE %8$L END),
					'object_ids',jsonb_build_array(%8$L,%7$L))));
				IF phase='finite_parent_new' THEN
					request:=jsonb_set(request,'{items}',(request->'items')||jsonb_build_array(jsonb_build_object(
						'side','new','read_type','iam.account','child_type','iam.project','guard','objects',
						'scope',jsonb_build_array('cluster','cluster_root'),'object_ids',jsonb_build_array('acc-new-position'))));
				END IF;
				IF phase='finite_parent_empty' THEN
					request:=jsonb_set(request,'{items,0,scope}',jsonb_build_array('cluster','cluster_root'));
					request:=jsonb_set(request,'{items,0,object_ids}','["acc-no-parent-edges"]'::jsonb);
				END IF;
				lock_moves:=(prepared->'binding_census')||jsonb_build_object('moved_role_id',prepared->'role_id');
				proposal:=kaname._authority_role_move_member_projects_v1(request,lock_moves,NULL,100000,4096);
				IF phase='finite_parent_ttl' THEN request:=jsonb_set(request,'{items}','[]'::jsonb);END IF;
				RETURN kaname._authority_role_move_member_projects_v1(request,lock_moves,proposal->'source',100000,4096)->'source';
			END IF;
			IF phase='member_projects' THEN
				RETURN jsonb_build_object('source',prepared->'member_projects',
					'verified',program#>'{frozen,selector_move_decision,member_projects_sha256}' =
						to_jsonb(encode(sha256(convert_to((prepared->'member_projects')::text,'UTF8')),'hex')));
			END IF;
			IF phase='member_project_omitted' THEN
				prepared:=prepared #- ARRAY['member_projects','projects',proposal->>'project_id'];
				RETURN kaname._authority_role_move_require_checks_v1(prepared,'[]'::jsonb,100000,4096);
			END IF;
			IF phase='project_certificate' THEN
				RETURN kaname._authority_role_move_project_member_certificate_v1(proposal->>'binding_id',
					proposal->>'project_id',proposal->'desired',100000,4096);
			END IF;
			IF phase='binding_member_set' THEN
				RETURN kaname._authority_role_move_binding_member_set_v1(proposal->>'binding_id',proposal->'coordinates',100000,4096);
			END IF;
			IF phase='direct_member_sets' THEN
				RETURN kaname._authority_role_move_direct_member_sets_v1(proposal,100000,4096);
			END IF;
			IF phase='member_certificate' THEN
				RETURN kaname._authority_role_move_account_member_certificate_v1(proposal->>'binding_id',
					proposal->>'account_id',proposal->'desired',100000,4096);
			END IF;
			IF phase='approve' THEN PERFORM kaname._authority_role_move_sequence_approve_v1();RETURN NULL; END IF;
			IF phase='label_budget' THEN
				request:=program#>'{frozen,selector_move_decision,predicate_plan}';
				RETURN kaname._authority_role_move_binding_label_candidates_v1(prepared,request,true,2*jsonb_array_length(request->'items'),0);
			END IF;
			IF phase IN ('local_budget','local_row_budget','local_overlay','local_overlay_in_scope') THEN
				request:=program#>'{frozen,selector_move_decision,predicate_plan}';
				IF phase='local_budget' THEN
					RETURN kaname._authority_role_move_local_label_candidates_v1(prepared,request,'[]'::jsonb,100000,0);
				END IF;
				IF phase='local_row_budget' THEN
					-- Шесть обязательных отметок, три служебных чтения и одна контрольная строка.
					RETURN kaname._authority_role_move_local_label_candidates_v1(prepared,request,'[]'::jsonb,
						jsonb_array_length(request->'items')+10,3);
				END IF;
				-- Закрытый вызов изолирует наложение одной выбранной команды.
				-- У проекта с подходящей обычной меткой итоговой команды нет.
				SELECT jsonb_build_array(jsonb_build_object('root_type','iam.account','root_id',a.id,
					'physical',jsonb_build_array(a.xmin::text,a.ctid::text,to_jsonb(a)),
					'access_labels',a.access_labels||'{"team":"blue"}')) INTO STRICT lock_moves
					FROM ONLY kaname.accounts a WHERE a.id=CASE WHEN phase='local_overlay_in_scope' THEN %8$L ELSE %7$L END;
				RETURN kaname._authority_role_move_local_label_candidates_v1(prepared,request,lock_moves,100000,4096);
			END IF;
			IF phase='raw_child_tiny' THEN
				request:=program#>'{frozen,selector_move_decision,predicate_plan}';
				RETURN kaname._authority_role_move_raw_project_children_v1(prepared,request,true,
					jsonb_array_length(request->'items')+13,12);
			END IF;
			IF phase IN ('raw_child_generation','raw_child_unknown','raw_child_count') THEN
				IF phase='raw_child_generation' THEN
					prepared:=jsonb_set(prepared,'{raw_project_children,sha256}',to_jsonb(repeat('0',64)),false);
				ELSIF phase='raw_child_unknown' THEN
					prepared:=jsonb_set(prepared,'{raw_project_children}','{}'::jsonb,false);
				ELSE
					prepared:=jsonb_set(prepared,'{raw_project_children,count}','0'::jsonb,false);
				END IF;
				RETURN kaname._authority_role_move_require_checks_v1(prepared,'[]'::jsonb,100000,4096);
			END IF;
			IF phase='local_generation' THEN
				prepared:=jsonb_set(prepared,'{local_label_sources,iam.project,sha256}','"forged"'::jsonb,false);
				RETURN kaname._authority_role_move_require_checks_v1(prepared,'[]'::jsonb,100000,4096);
			END IF;
			IF phase='label_generation' THEN
				prepared:=jsonb_set(prepared,'{binding_label_source,sha256}','"forged"'::jsonb,false);
				RETURN kaname._authority_role_move_require_checks_v1(prepared,'[]'::jsonb,100000,4096);
			END IF;
			IF phase='missing_position' THEN
				prepared:=jsonb_set(prepared,'{finite_positions,iam.project:prj-named,state}','"absent"'::jsonb,false);
				RETURN kaname._authority_role_move_require_checks_v1(prepared,'[]'::jsonb,100000,4096);
			END IF;
			IF phase='selector_versions' THEN
				prepared:=jsonb_set(prepared,'{selector_versions}','[["0","(0,0)","unexpected"]]'::jsonb,false);
				RETURN kaname._authority_role_move_require_checks_v1(prepared,'[]'::jsonb,100000,4096);
			END IF;
			SELECT (ordinality-1)::text INTO STRICT position_no FROM jsonb_array_elements(prepared#>'{binding_census,subjects}')
				WITH ORDINALITY s(image,ordinality) WHERE image#>>'{2,binding_id}'=%4$L AND image#>>'{2,subject_id}'=%5$L;
			IF phase='forged' THEN
				prepared:=jsonb_set(prepared,ARRAY['binding_census','subjects',position_no,'2','subject_id'],'"usr-forged"'::jsonb,false);
			ELSIF phase='missing' THEN prepared:=prepared #- ARRAY['binding_census','subjects',position_no];
			ELSE RAISE EXCEPTION 'unexpected phase';END IF;
			RETURN kaname._authority_role_move_require_checks_v1(prepared,'[]'::jsonb,100000,4096);
		END;
		$bridge$;
		REVOKE ALL ON FUNCTION kaname.test_role_move_binding_new_v1(text,jsonb) FROM PUBLIC;
		GRANT EXECUTE ON FUNCTION kaname.test_role_move_binding_new_v1(text,jsonb) TO %3$I;
	$ddl$,$1::text,$2::text,$3::text,$4::text,$5::text,$6::text,$7::text,$8::text)`, string(move), actor, login, active, second, string(lockInput), r.b, r.a).Scan(&ddl))
	_, err = r.admin.Exec(r.ctx, ddl)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := r.admin.Exec(ctx, `DROP FUNCTION kaname.test_role_move_binding_new_v1(text,jsonb)`)
		require.NoError(t, err)
	})
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	fullContractActivate(t, r)
	i := r.bundle.Identity()
	const enter = `SELECT kaname.authority_protocol_enter_typed_v3('global',ARRAY[]::text[],'[]'::jsonb,
		'role',$1,$2,$3,'decision')`
	const phase = `SELECT kaname.test_role_move_binding_new_v1($1)`
	const selectorLock = `SELECT EXISTS(SELECT FROM pg_locks WHERE pid=pg_backend_pid() AND granted
		AND relation='kaname.role_rule_selectors'::regclass AND mode='ShareLock')`
	t.Run("concurrent_edge_writer_retries_before_reading_graph", func(t *testing.T) {
		locker, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, locker)
		_, err = locker.Exec(r.ctx, `LOCK TABLE ONLY kaname.resource_parent_edge IN ROW EXCLUSIVE MODE`)
		require.NoError(t, err)
		probe, err := pool.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, probe)
		_, err = probe.Exec(r.ctx, enter, i.ModelID, i.CatalogID, i.ProjectorVersion)
		require.NoError(t, err)
		_, err = probe.Exec(r.ctx, phase, "active")
		requireAccessDefinitionSQLState(t, err, "40001")
		require.ErrorContains(t, err, "project child sources busy")
	})
	for _, state := range []string{"empty", "revoked", "expired", "expired_pending", "active", "pending"} {
		t.Run("prepare_"+state, func(t *testing.T) {
			probe, err := pool.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, probe)
			_, err = probe.Exec(r.ctx, enter, i.ModelID, i.CatalogID, i.ProjectorVersion)
			require.NoError(t, err)
			var held bool
			require.NoError(t, probe.QueryRow(r.ctx, selectorLock).Scan(&held))
			require.False(t, held)
			var raw json.RawMessage
			require.NoError(t, probe.QueryRow(r.ctx, phase, state).Scan(&raw))
			require.NoError(t, probe.QueryRow(r.ctx, selectorLock).Scan(&held))
			expired := state == "expired" || state == "expired_pending"
			require.Equal(t, expired || state == "active" || state == "pending", held)
			if expired {
				var read struct {
					Scopes map[string]json.RawMessage
					Items  []struct {
						BindingID string `json:"binding_id"`
						Side      string
					}
					Positions map[string]json.RawMessage
					Copies    json.RawMessage
					BoundCopy *bool `json:"bound_copy"`
				}
				require.NoError(t, json.Unmarshal(raw, &read))
				bindingID := lockBindings[state]
				require.Len(t, read.Scopes, 1)
				require.JSONEq(t, `{}`, string(read.Copies))
				require.NotNil(t, read.BoundCopy)
				require.False(t, *read.BoundCopy)
				var scope map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(read.Scopes[bindingID], &scope))
				require.Len(t, scope, 3)
				for _, key := range []string{"scope", "target", "subjects"} {
					require.Contains(t, scope, key)
				}
				sides := map[string]bool{}
				for _, item := range read.Items {
					require.Equal(t, bindingID, item.BindingID)
					sides[item.Side] = true
				}
				require.Equal(t, map[string]bool{"old": true, "new": true}, sides)
				require.Contains(t, read.Positions, "iam.account:"+r.a)
				require.Contains(t, read.Positions, "iam.project:prj-named")

				require.NoError(t, probe.QueryRow(r.ctx, phase, "expired_final").Scan(&raw))
				var decision struct {
					Status   map[string]string `json:"binding_status"`
					Holders  json.RawMessage   `json:"binding_new"`
					Commands json.RawMessage
				}
				require.NoError(t, json.Unmarshal(raw, &decision))
				require.Equal(t, map[string]string{bindingID: "EXPIRED"}, decision.Status)
				require.JSONEq(t, `{}`, string(decision.Holders))
				require.JSONEq(t, `[]`, string(decision.Commands))
			}
		})
	}
	// Для отозванной выдачи только сохранённые координаты входят в Go capture.
	// Старый ledger остаётся кандидатом общей свёртки и сам право не держит.
	history := []pg.AccessLabelMoveCoordinateEffect{{Resource: domain.ResourceRef{Type: "iam.project", ID: oldMemberProject}}}
	for _, tc := range []struct {
		name      string
		state     string
		coords    []pg.AccessLabelMoveCoordinateEffect
		wantError string
	}{
		{"revoked_keeps_history", "revoked", history, ""},
		{"revoked_requires_every_coordinate", "revoked", []pg.AccessLabelMoveCoordinateEffect{}, "coordinate count differs"},
		{"revoked_cannot_claim_a_missing_object", "revoked", []pg.AccessLabelMoveCoordinateEffect{{Resource: history[0].Resource, Present: true}}, "revoked binding coordinate"},
		{"revoked_has_no_proposed_effect", "revoked", []pg.AccessLabelMoveCoordinateEffect{{
			Resource: history[0].Resource, Proposed: []resourceeffect.ObjectDesiredMember{{RuleFP: "forged"}},
		}}, "revoked binding coordinate"},
		{"revoked_ledger_needs_independent_holder", "revoked_residual", history, "global member tuple removal"},
		{"expired_still_needs_selector_reads", "expired", []pg.AccessLabelMoveCoordinateEffect{}, "expired binding needs captured selector positions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe, err := pool.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, probe)
			_, err = probe.Exec(r.ctx, enter, i.ModelID, i.CatalogID, i.ProjectorVersion)
			require.NoError(t, err)
			payload, err := json.Marshal(map[string][]pg.AccessLabelMoveCoordinateEffect{lockBindings[tc.state]: tc.coords})
			require.NoError(t, err)
			var raw json.RawMessage
			err = probe.QueryRow(r.ctx, `SELECT kaname.test_role_move_binding_new_v1($1,$2::jsonb)`, "history_"+tc.state, payload).Scan(&raw)
			if tc.wantError != "" {
				requireAccessDefinitionSQLState(t, err, "42501")
				require.ErrorContains(t, err, tc.wantError)
				return
			}
			require.NoError(t, err)
			var receipt struct {
				Bindings map[string]string
				Claims   map[string]json.RawMessage `json:"proposed_claims"`
			}
			require.NoError(t, json.Unmarshal(raw, &receipt))
			require.Contains(t, receipt.Bindings, lockBindings[tc.state])
			require.Empty(t, receipt.Claims)
			var status string
			require.NoError(t, probe.QueryRow(r.ctx, `SELECT verification_status FROM ONLY kaname.access_binding_target_members
				WHERE binding_id=$1 AND rule_fp='historical-fp'`, lockBindings[tc.state]).Scan(&status))
			require.Equal(t, "ACTIVE", status)
		})
	}
	tx, err := pool.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	_, err = tx.Exec(r.ctx, enter, i.ModelID, i.CatalogID, i.ProjectorVersion)
	require.NoError(t, err)
	type sourceState struct {
		State string
		Count int
	}
	type bindingLabelCandidates struct {
		Source  sourceState            `json:"source"`
		Sources map[string]sourceState `json:"sources"`
		Items   []struct {
			PlanItem             int      `json:"plan_item"`
			BindingID            string   `json:"binding_id"`
			Side                 string   `json:"side"`
			RuleFP               string   `json:"rule_fp"`
			State                string   `json:"state"`
			CandidateIDs         []string `json:"candidate_ids"`
			Children             string   `json:"children"`
			RawChildCandidateIDs []string `json:"raw_child_candidate_ids"`
		} `json:"items"`
		OtherPredicates string `json:"other_predicates"`
	}
	var decision struct {
		BindingLabels bindingLabelCandidates `json:"binding_label_candidates"`
		LocalLabels   bindingLabelCandidates `json:"local_label_candidates"`
		Status        map[string]string      `json:"binding_status"`
		New           json.RawMessage        `json:"binding_new"`
		Positions     map[string]struct {
			State      string              `json:"state"`
			Generation []string            `json:"generation"`
			Row        struct{ ID string } `json:"row"`
		} `json:"finite_positions"`
		Plan struct {
			CatalogID    string `json:"catalog_id"`
			NewRoleIndex map[string]struct {
				Source map[string]json.RawMessage `json:"source"`
				States [][]json.RawMessage        `json:"states"`
			} `json:"new_role_index"`
			Holders []struct {
				BindingID  string         `json:"binding_id"`
				ScopeRoot  []string       `json:"scope_root"`
				Predicates map[string]int `json:"predicates"`
			} `json:"holders"`
			Items []struct {
				BindingID      string             `json:"binding_id"`
				Side           string             `json:"side"`
				RuleFP         string             `json:"rule_fp"`
				ReadType       string             `json:"read_type"`
				Guard          string             `json:"guard"`
				ChildType      string             `json:"child_type"`
				ObjectIDs      []string           `json:"object_ids"`
				ChildPredicate *struct{ Arm int } `json:"child_predicate"`
				Scope          []string           `json:"scope"`
				Predicate      struct {
					Arm                            int
					MatchLabels, MatchAccessLabels map[string]string
				} `json:"predicate"`
			} `json:"items"`
		} `json:"predicate_plan"`
	}
	var raw json.RawMessage
	require.NoError(t, tx.QueryRow(r.ctx, phase, "decide").Scan(&raw))
	require.NoError(t, json.Unmarshal(raw, &decision))
	var projectCensus struct {
		Verified bool
		Source   struct {
			AllNative bool `json:"all_native"`
			Projects  map[string]*struct {
				Graph struct{ Present bool }
			}
		}
	}
	require.NoError(t, tx.QueryRow(r.ctx, phase, "member_projects").Scan(&raw))
	require.NoError(t, json.Unmarshal(raw, &projectCensus))
	require.True(t, projectCensus.Verified)
	require.True(t, projectCensus.Source.AllNative)
	require.NotNil(t, projectCensus.Source.Projects[project])
	require.True(t, projectCensus.Source.Projects[project].Graph.Present)
	require.NotNil(t, projectCensus.Source.Projects[nativeOnly])
	require.False(t, projectCensus.Source.Projects[nativeOnly].Graph.Present)
	for _, id := range []string{oldMemberProject, oldLedgerProject} {
		require.Contains(t, projectCensus.Source.Projects, id)
		require.Nil(t, projectCensus.Source.Projects[id])
	}
	require.Contains(t, projectCensus.Source.Projects, "prj-other")
	require.Nil(t, projectCensus.Source.Projects["prj-other"])

	require.Equal(t, map[string]string{active: "ACTIVE", pending: "PENDING", independent: "ACTIVE", revoked: "REVOKED"}, decision.Status)
	scope := []string{"account", r.a}
	target := map[string]bool{"allInScope": true}
	wanted, err := json.Marshal(map[string]any{
		active: map[string]any{"class": "ACTIVE", "expires_at": nil, "scope": scope, "target": target,
			"subjects": [][]string{{"user", actor}, {"user", second}}, "binding_tuples": []map[string]string{
				{"relation": "account", "fga_user": "account:" + r.a, "object": "iam_access_binding:" + active}}},
		pending: map[string]any{"class": "PENDING", "expires_at": nil, "scope": scope, "target": json.RawMessage(pendingTarget),
			"subjects": [][]string{{"user", second}}, "binding_tuples": []any{}},
	})
	require.NoError(t, err)
	require.JSONEq(t, string(wanted), string(decision.New))
	require.Len(t, decision.Positions, 4)
	require.Equal(t, "pending_absence", decision.Positions["iam.project:prj-other"].State)
	scopeRow := decision.Positions["iam.account:"+r.a]
	require.Equal(t, "present", scopeRow.State)
	require.Equal(t, r.a, scopeRow.Row.ID)
	require.Len(t, scopeRow.Generation, 2)
	require.Equal(t, "absent", decision.Positions["iam.accessBinding:acb-retained-missing"].State)
	require.Equal(t, "present", decision.Positions["iam.project:prj-named"].State)
	require.Equal(t, i.CatalogID, decision.Plan.CatalogID)
	var declaredHolders []string
	for _, holder := range decision.Plan.Holders {
		declaredHolders = append(declaredHolders, holder.BindingID)
		require.Equal(t, []string{"iam.account", r.a}, holder.ScopeRoot)
		count := 2
		if holder.BindingID == active {
			count = 7
		}
		require.Equal(t, map[string]int{"old": count, "new": count}, holder.Predicates)
	}
	require.ElementsMatch(t, []string{active, pending}, declaredHolders)
	fingerprints := map[string]map[string]string{"old": {}, "new": {}}
	for _, item := range decision.Plan.Items {
		if item.BindingID == pending {
			require.Equal(t, "iam.project", item.ReadType)
			require.Equal(t, "objects", item.Guard)
			if item.Predicate.Arm == int(domain.ArmNames) {
				require.Equal(t, []string{namedProject}, item.ObjectIDs)
			} else {
				require.Equal(t, []string{namedProject, "prj-other"}, item.ObjectIDs)
			}
			continue
		}
		require.Equal(t, active, item.BindingID)
		require.Contains(t, fingerprints, item.Side)
		require.Equal(t, scope, item.Scope)
		require.Len(t, item.RuleFP, 64)
		key := item.ReadType + "/" + item.ChildType
		if item.Guard == "whole_type" && item.ReadType != "iam.account" {
			key += "#wide"
		}
		require.NotContains(t, fingerprints[item.Side], key)
		fingerprints[item.Side][key] = item.RuleFP
		if item.ReadType == "iam.accessBinding" && item.Guard == "whole_type" {
			if item.Side == "old" {
				require.Equal(t, map[string]string{"stage": "whole-binding"}, item.Predicate.MatchLabels)
			} else {
				require.Equal(t, map[string]string{"stage": "whole-binding"}, item.Predicate.MatchAccessLabels)
			}
			continue
		}
		if item.ReadType == "iam.accessBinding" {
			require.Empty(t, item.ChildType)
			require.Equal(t, "objects", item.Guard)
			require.Equal(t, []string{"acb-retained-missing"}, item.ObjectIDs)
			require.Equal(t, int(domain.ArmNames), item.Predicate.Arm)
			continue
		}
		if item.ReadType == "iam.project" && item.Guard == "whole_type" {
			require.Empty(t, item.ChildType)
			continue
		}
		if item.ReadType == "iam.project" {
			require.Empty(t, item.ChildType)
			require.Equal(t, "objects", item.Guard)
			require.Equal(t, []string{"prj-named"}, item.ObjectIDs)
			require.Equal(t, int(domain.ArmNames), item.Predicate.Arm)
			continue
		}
		require.Equal(t, "iam.account", item.ReadType)
		require.Equal(t, "whole_type", item.Guard)
		if item.ChildType != "" {
			require.Equal(t, "iam.project", item.ChildType)
			require.NotNil(t, item.ChildPredicate)
			require.Equal(t, int(domain.ArmAnchor), item.ChildPredicate.Arm)
		}
		switch item.Side {
		case "old":
			require.Equal(t, int(domain.ArmLabels), item.Predicate.Arm)
			require.Equal(t, map[string]string{"team": "blue"}, item.Predicate.MatchLabels)
			require.Empty(t, item.Predicate.MatchAccessLabels)
		case "new":
			require.Equal(t, int(domain.ArmAccessLabels), item.Predicate.Arm)
			require.Equal(t, map[string]string{"team": "blue"}, item.Predicate.MatchAccessLabels)
			require.Empty(t, item.Predicate.MatchLabels)
		default:
			t.Fatalf("unexpected selector side %q", item.Side)
		}
	}
	require.Len(t, decision.Plan.Items, 18)
	for _, side := range []string{"old", "new"} {
		require.Len(t, fingerprints[side], 7)
		require.NotEqual(t, fingerprints[side]["iam.account/"], fingerprints[side]["iam.account/iam.project"])
	}
	require.NotEqual(t, fingerprints["old"]["iam.account/"], fingerprints["new"]["iam.account/"])
	require.NotEqual(t, fingerprints["old"]["iam.account/iam.project"], fingerprints["new"]["iam.account/iam.project"])
	require.Equal(t, fingerprints["old"]["iam.project/"], fingerprints["new"]["iam.project/"])
	require.Len(t, decision.Plan.NewRoleIndex, 2)
	roleSource := decision.Plan.NewRoleIndex[fmt.Sprintf(`[12, "role", %q, ""]`, role)]
	selectorSource := decision.Plan.NewRoleIndex[fmt.Sprintf(`[13, "role", %q, ""]`, role)]
	require.NotNil(t, roleSource.Source)
	require.NotNil(t, selectorSource.Source)
	require.Empty(t, roleSource.Source)
	require.Empty(t, selectorSource.Source)
	require.Len(t, roleSource.States, 1)
	require.Len(t, roleSource.States[0], 3)
	require.JSONEq(t, `null`, string(roleSource.States[0][0]))
	require.JSONEq(t, `null`, string(roleSource.States[0][1]))
	var semanticRole struct {
		ID    string          `json:"id"`
		Rules json.RawMessage `json:"rules"`
	}
	require.NoError(t, json.Unmarshal(roleSource.States[0][2], &semanticRole))
	require.Equal(t, role, semanticRole.ID)
	require.JSONEq(t, newRules, string(semanticRole.Rules))
	type logicalSelector struct {
		Role            string            `json:"role_id"`
		FP              string            `json:"rule_fp"`
		Labels          map[string]string `json:"match_access_labels"`
		ContainerLabels map[string]string `json:"container_match_access_labels"`
	}
	logicalSelectors := make(map[string]logicalSelector)
	for _, state := range selectorSource.States {
		require.Len(t, state, 3)
		require.JSONEq(t, `null`, string(state[0]))
		require.JSONEq(t, `null`, string(state[1]))
		var selector logicalSelector
		require.NoError(t, json.Unmarshal(state[2], &selector))
		require.Equal(t, role, selector.Role)
		require.NotContains(t, logicalSelectors, selector.FP)
		logicalSelectors[selector.FP] = selector
	}
	for _, fingerprint := range fingerprints["new"] {
		require.Contains(t, logicalSelectors, fingerprint)
	}
	require.Len(t, logicalSelectors, len(fingerprints["new"]))
	require.NotContains(t, logicalSelectors, fingerprints["old"]["iam.account/"])
	require.NotContains(t, logicalSelectors, fingerprints["old"]["iam.account/iam.project"])
	require.Equal(t, map[string]string{"team": "blue"}, logicalSelectors[fingerprints["new"]["iam.account/"]].Labels)
	require.Equal(t, map[string]string{"team": "blue"}, logicalSelectors[fingerprints["new"]["iam.account/iam.project"]].ContainerLabels)
	require.Equal(t, "held", decision.BindingLabels.Source.State)
	require.Greater(t, decision.BindingLabels.Source.Count, 0)
	require.Equal(t, "pending", decision.BindingLabels.OtherPredicates)
	require.Len(t, decision.BindingLabels.Items, 4)
	seen := map[int]bool{}
	for _, item := range decision.BindingLabels.Items {
		require.Equal(t, "complete", item.State)
		require.Equal(t, active, item.BindingID)
		require.GreaterOrEqual(t, item.PlanItem, 1)
		require.LessOrEqual(t, item.PlanItem, len(decision.Plan.Items))
		require.False(t, seen[item.PlanItem])
		seen[item.PlanItem] = true
		planItem := decision.Plan.Items[item.PlanItem-1]
		require.Equal(t, "iam.accessBinding", planItem.ReadType)
		require.Equal(t, planItem.RuleFP, item.RuleFP)
		require.Equal(t, planItem.Side, item.Side)
		if item.Side == "old" {
			require.Equal(t, []string{independent}, item.CandidateIDs)
		} else {
			require.NotNil(t, item.CandidateIDs)
			require.Empty(t, item.CandidateIDs)
		}
		if planItem.ChildType == "" {
			require.Empty(t, item.Children)
		} else if item.Side == "old" {
			require.Equal(t, "pending", item.Children)
		} else {
			require.Equal(t, "empty", item.Children)
		}
	}
	checkLocal := func(candidates bindingLabelCandidates, newAccount string) {
		t.Helper()
		require.Equal(t, "pending", candidates.OtherPredicates)
		require.Len(t, candidates.Sources, 2)
		for _, typ := range []string{"iam.account", "iam.project"} {
			require.Equal(t, "held", candidates.Sources[typ].State)
			require.Positive(t, candidates.Sources[typ].Count)
		}
		require.Len(t, candidates.Items, 6)
		ordinals := map[int]bool{}
		for _, item := range candidates.Items {
			require.False(t, ordinals[item.PlanItem])
			ordinals[item.PlanItem] = true
			planItem := decision.Plan.Items[item.PlanItem-1]
			require.Equal(t, active, item.BindingID)
			require.Equal(t, planItem.RuleFP, item.RuleFP)
			require.Equal(t, planItem.Side, item.Side)
			require.Equal(t, "complete", item.State)
			hits := []string{}
			if planItem.ReadType == "iam.project" && item.Side == "old" {
				hits = []string{project}
			}
			if planItem.ReadType == "iam.account" {
				if item.Side == "old" {
					hits = []string{r.b}
				} else if newAccount != "" {
					hits = []string{newAccount}
				}
			}
			require.Equal(t, hits, item.CandidateIDs)
			if planItem.ChildType != "" {
				// Обычный предикат сохраняет чужой аккаунт среди кандидатов.
				// Вложенный до чтения потомков выбирает только контейнер своей области.
				if item.Side == "new" && newAccount == r.a {
					require.Equal(t, "pending", item.Children)
					require.Equal(t, []string{nativeChildren[0].ObjectID}, item.RawChildCandidateIDs)
				} else {
					require.Equal(t, "empty", item.Children)
					require.Nil(t, item.RawChildCandidateIDs)
				}
			}
		}
	}
	checkLocal(decision.LocalLabels, "")
	var selected bindingLabelCandidates
	require.NoError(t, tx.QueryRow(r.ctx, phase, "local_overlay").Scan(&raw))
	require.NoError(t, json.Unmarshal(raw, &selected))
	checkLocal(selected, r.b)
	var selectedInScope bindingLabelCandidates
	require.NoError(t, tx.QueryRow(r.ctx, phase, "local_overlay_in_scope").Scan(&raw))
	require.NoError(t, json.Unmarshal(raw, &selectedInScope))
	checkLocal(selectedInScope, r.a)
	var tiny struct {
		Source       sourceState `json:"source"`
		CandidateIDs []string    `json:"candidate_ids"`
		Reads        int         `json:"reads"`
		Rows         int         `json:"rows"`
	}
	require.NoError(t, tx.QueryRow(r.ctx, phase, "raw_child_tiny").Scan(&raw))
	require.NoError(t, json.Unmarshal(raw, &tiny))
	require.Equal(t, "pending_budget", tiny.Source.State)
	require.Nil(t, tiny.CandidateIDs)
	require.Equal(t, 12, tiny.Reads)
	require.Equal(t, len(decision.Plan.Items)+13, tiny.Rows)
	for _, budget := range []string{"local_budget", "local_row_budget"} {
		var localBudget bindingLabelCandidates
		require.NoError(t, tx.QueryRow(r.ctx, phase, budget).Scan(&raw))
		require.NoError(t, json.Unmarshal(raw, &localBudget))
		require.Len(t, localBudget.Sources, 2)
		for _, typ := range []string{"iam.account", "iam.project"} {
			require.Equal(t, "pending_budget", localBudget.Sources[typ].State)
		}
		require.Len(t, localBudget.Items, 6)
		for _, item := range localBudget.Items {
			require.Equal(t, "pending_budget", item.State)
			require.Nil(t, item.CandidateIDs)
		}
	}
	for _, table := range []string{"accounts", "projects", "catalog_resource", "resource_mirror", "resource_parent_edge"} {
		conflict, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		_, err = conflict.Exec(r.ctx, "LOCK TABLE ONLY kaname."+table+" IN ROW EXCLUSIVE MODE NOWAIT")
		requireAccessDefinitionSQLState(t, err, "55P03")
		require.NoError(t, conflict.Rollback(r.ctx))
	}
	var limited bindingLabelCandidates
	require.NoError(t, tx.QueryRow(r.ctx, phase, "label_budget").Scan(&raw))
	require.NoError(t, json.Unmarshal(raw, &limited))
	require.Equal(t, "pending_budget", limited.Source.State)
	require.Len(t, limited.Items, 4)
	for _, item := range limited.Items {
		require.Equal(t, "pending_budget", item.State)
		require.Nil(t, item.CandidateIDs)
	}
	rejected := func(code, query string, args ...any) error {
		t.Helper()
		attempt, err := tx.Begin(r.ctx)
		require.NoError(t, err)
		_, err = attempt.Exec(r.ctx, query, args...)
		requireAccessDefinitionSQLState(t, err, code)
		require.NoError(t, attempt.Rollback(r.ctx))
		return err
	}
	for _, name := range []string{"finite_parent_a", "finite_parent_ttl", "finite_parent_empty"} {
		var held struct {
			AllNative bool                           `json:"all_native"`
			Parents   [][]string                     `json:"finite_parents"`
			Edges     map[string]struct{ Count int } `json:"parent_edges"`
			Projects  map[string]json.RawMessage
		}
		require.NoError(t, tx.QueryRow(r.ctx, phase, name).Scan(&raw))
		require.NoError(t, json.Unmarshal(raw, &held))
		require.False(t, held.AllNative)
		require.NotContains(t, held.Projects, orphanB)
		require.NotContains(t, held.Projects, nativeOnly)
		if name == "finite_parent_empty" {
			require.Equal(t, [][]string{{"iam.account", "acc-no-parent-edges"}}, held.Parents)
			require.Empty(t, held.Edges)
			// Пустой родитель не добавляет потомков. Члены и журнал физических
			// привязок этой роли по-прежнему требуют проверки четырёх проектов.
			require.Len(t, held.Projects, 4)
			for _, id := range []string{"prj-other", oldMemberProject, oldLedgerProject} {
				require.Contains(t, held.Projects, id)
				require.JSONEq(t, "null", string(held.Projects[id]))
			}
			var certificate struct {
				ProjectID string `json:"project_id"`
				Graph     struct{ Present bool }
				Native    []json.RawMessage
			}
			require.NoError(t, json.Unmarshal(held.Projects[project], &certificate))
			require.Equal(t, project, certificate.ProjectID)
			require.True(t, certificate.Graph.Present)
			require.Len(t, certificate.Native, 3)
			var native struct {
				ID      string
				Account string `json:"account_id"`
			}
			require.NoError(t, json.Unmarshal(certificate.Native[2], &native))
			require.Equal(t, project, native.ID)
			require.Equal(t, r.b, native.Account)
		} else {
			require.Len(t, held.Edges, 1)
			require.Equal(t, [][]string{{"iam.account", r.a}}, held.Parents)
			// Родная строка проекта принадлежит B, но реальное ребро и зеркало выбраны под A.
			require.Contains(t, held.Projects, project)
		}
	}
	const namedParent = `SELECT kaname.test_role_move_binding_new_v1($1,jsonb_build_object('type',$2::text,'id',$3::text))`
	for _, ref := range []struct{ typ, id string }{{"iam.project", project}, {"iam.accessBinding", independent}} {
		var scoped struct {
			ParentStates map[string]struct{ Present, Included bool } `json:"parent_states"`
			ParentEdges  map[string]json.RawMessage                  `json:"parent_edges"`
		}
		require.NoError(t, tx.QueryRow(r.ctx, namedParent, "named_parent_a", ref.typ, ref.id).Scan(&raw))
		require.NoError(t, json.Unmarshal(raw, &scoped))
		require.Len(t, scoped.ParentStates, 1)
		require.Empty(t, scoped.ParentEdges)
		for _, state := range scoped.ParentStates {
			require.True(t, state.Present)
			require.False(t, state.Included)
		}
		require.ErrorContains(t, rejected("40001", namedParent, "named_parent_b", ref.typ, ref.id), "lack a native project")
	}
	var emptyPresent struct {
		ParentEdges map[string]struct{ Count int } `json:"parent_edges"`
	}
	require.NoError(t, tx.QueryRow(r.ctx, namedParent, "named_parent_b", "iam.project", nativeOnly).Scan(&raw))
	require.NoError(t, json.Unmarshal(raw, &emptyPresent))
	require.Len(t, emptyPresent.ParentEdges, 1)
	for _, edge := range emptyPresent.ParentEdges {
		require.Zero(t, edge.Count)
	}
	var newPositions struct {
		Parents [][]string `json:"finite_parents"`
	}
	require.NoError(t, tx.QueryRow(r.ctx, phase, "finite_parent_new").Scan(&raw))
	require.NoError(t, json.Unmarshal(raw, &newPositions))
	require.ElementsMatch(t, [][]string{{"iam.account", r.a}, {"iam.account", "acc-new-position"}}, newPositions.Parents)
	require.ErrorContains(t, rejected("40001", phase, "finite_parent_b"), "nested project mirror and edge lack a native project")
	require.ErrorContains(t, rejected("40001", `SELECT kaname.test_role_move_binding_new_v1(
		'member_project_omitted',jsonb_build_object('project_id',$1::text))`, nativeOnly), "role member project graph changed")
	// Сравниваем вычисление Go с независимой проверкой целого набора членов
	// удержанной координаты, включая полномочия получателей из обеих строк.
	var halves catalog.Halves
	require.NoError(t, json.Unmarshal(r.bundle.CanonicalCatalog(), &halves))
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	accountRule := domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get", "list"},
		MatchAccessLabels: map[string]string{"team": "blue"}, Children: []domain.Rule{{Resources: []string{"project"}, Verbs: []string{"get"}}}}
	projection, err := r.bundle.Projection(domain.Role{ID: domain.RoleID(role), Rules: domain.Rules{accountRule}})
	require.NoError(t, err)
	account := domain.MirrorObject{ObjectType: "iam.account", ObjectID: r.a, ParentAccountIDs: []string{r.a}}
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT labels,access_labels FROM ONLY kaname.accounts WHERE id=$1`, r.a).
		Scan(&account.Labels, &account.AccessLabels))
	desired, err := resourceeffect.CompileObjectDesired(facts, resourceeffect.ObjectBinding{
		BindingID: domain.AccessBindingID(active), RoleID: role,
		Scope:  domain.ScopeAnchor{Type: "account", ID: r.a},
		Policy: domain.PolicyOfRole(false, ""),
		Subjects: []domain.Subject{
			{Type: domain.SubjectTypeUser, ID: domain.SubjectID(actor)},
			{Type: domain.SubjectTypeUser, ID: domain.SubjectID(second)},
		},
		Selectors: projection.Selectors, ScopeSelfVerbs: accountRule.Verbs,
		Target: domain.AccessTarget{AllInScope: true}, Active: true,
	}, account, nil)
	require.NoError(t, err)
	require.NotEmpty(t, desired)
	projectRule := domain.Rule{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"},
		ResourceNames: []string{namedProject}}
	projectProjection, err := r.bundle.Projection(domain.Role{ID: domain.RoleID(role), Rules: domain.Rules{projectRule}})
	require.NoError(t, err)
	own := domain.MirrorObject{ObjectType: "iam.project", ObjectID: namedProject, ParentProjectID: namedProject, ParentAccountIDs: []string{r.a}}
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT labels,access_labels FROM ONLY kaname.projects WHERE id=$1`, namedProject).
		Scan(&own.Labels, &own.AccessLabels))
	projectDesired, err := resourceeffect.CompileProjectObjectDesired(facts, resourceeffect.ObjectBinding{
		BindingID: domain.AccessBindingID(active), RoleID: role, Scope: domain.ScopeAnchor{Type: "account", ID: r.a},
		Policy: domain.PolicyOfRole(false, ""), Active: true, Selectors: projectProjection.Selectors, Target: domain.AccessTarget{AllInScope: true},
		Subjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(actor)}, {Type: domain.SubjectTypeUser, ID: domain.SubjectID(second)}},
	}, own, resourceeffect.ProjectGraphProjection{ConfirmedAbsent: domain.ResourceRef{Type: own.ObjectType, ID: own.ObjectID}})
	require.NoError(t, err)
	require.NotEmpty(t, projectDesired)
	const certifyProject = `SELECT kaname.test_role_move_binding_new_v1('project_certificate',$1::jsonb)`
	projectProposal := func(binding, id string, members []resourceeffect.ObjectDesiredMember) json.RawMessage {
		data, err := json.Marshal(map[string]any{"binding_id": binding, "project_id": id, "desired": members})
		require.NoError(t, err)
		return data
	}
	type projectCertificate struct {
		Class         string
		Present       bool
		Desired       []resourceeffect.ObjectDesiredMember
		UpsertMembers map[string]string        `json:"upsert_members"`
		RemoveMembers map[string]string        `json:"remove_members"`
		AddLedger     []domain.MembershipTuple `json:"add_ledger"`
		RemoveLedger  []domain.MembershipTuple `json:"remove_ledger"`
	}
	var positive, removed, prospective projectCertificate
	emptyProject := []resourceeffect.ObjectDesiredMember{}
	require.NoError(t, tx.QueryRow(r.ctx, certifyProject, projectProposal(active, namedProject, projectDesired)).Scan(&raw))
	require.NoError(t, json.Unmarshal(raw, &positive))
	require.ElementsMatch(t, projectDesired, positive.Desired)
	require.True(t, positive.Present)
	require.Equal(t, "ACTIVE", positive.Class)
	require.NotEmpty(t, positive.UpsertMembers)
	require.NotEmpty(t, positive.AddLedger)
	rejected("42501", certifyProject, projectProposal(active, namedProject, emptyProject))
	require.NoError(t, tx.QueryRow(r.ctx, certifyProject, projectProposal(active, project, emptyProject)).Scan(&raw))
	require.NoError(t, json.Unmarshal(raw, &removed))
	require.Equal(t, map[string]string{"previous-project": "ACTIVE"}, removed.RemoveMembers)
	require.Len(t, removed.RemoveLedger, 1)
	require.NoError(t, tx.QueryRow(r.ctx, certifyProject, projectProposal(pending, "prj-other", emptyProject)).Scan(&raw))
	require.NoError(t, json.Unmarshal(raw, &prospective))
	require.False(t, prospective.Present)
	require.Equal(t, "PENDING", prospective.Class)
	require.Empty(t, prospective.RemoveMembers)
	require.Empty(t, prospective.RemoveLedger)
	pendingBinding := resourceeffect.ObjectBinding{
		BindingID: domain.AccessBindingID(pending), RoleID: role, Scope: domain.ScopeAnchor{Type: "account", ID: r.a},
		Policy: domain.PolicyOfRole(false, ""), Selectors: projectProjection.Selectors, Active: true,
		Subjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(second)}},
		Target:   domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "iam.project", ID: namedProject}, {Type: "iam.project", ID: "prj-other"}}},
	}
	pendingDesired, err := resourceeffect.CompileProjectObjectDesired(facts, pendingBinding, own,
		resourceeffect.ProjectGraphProjection{ConfirmedAbsent: domain.ResourceRef{Type: own.ObjectType, ID: own.ObjectID}})
	require.NoError(t, err)
	require.NotEmpty(t, pendingDesired)
	var pendingPositive projectCertificate
	require.NoError(t, tx.QueryRow(r.ctx, certifyProject, projectProposal(pending, namedProject, pendingDesired)).Scan(&raw))
	require.NoError(t, json.Unmarshal(raw, &pendingPositive))
	require.ElementsMatch(t, pendingDesired, pendingPositive.Desired)
	require.Equal(t, "PENDING", pendingPositive.Class)
	require.Empty(t, pendingPositive.UpsertMembers)
	require.Empty(t, pendingPositive.AddLedger)
	// Координаты одной выдачи включают собственный аккаунт, именованный
	// проект и историческую строку отсутствующего проекта. Ожидающая выдача
	// сохраняет оба вычисления, но не приобретает притязаний на кортежи.
	pendingBinding.Selectors = projection.Selectors
	pendingBinding.ScopeSelfVerbs = accountRule.Verbs
	pendingAccount, err := resourceeffect.CompileObjectDesired(facts, pendingBinding, account, nil)
	require.NoError(t, err)
	whole := []pg.AccessLabelMoveCoordinateEffect{
		{Resource: domain.ResourceRef{Type: "iam.account", ID: r.a}, Present: true, Before: pendingAccount, Proposed: pendingAccount},
		{Resource: domain.ResourceRef{Type: "iam.project", ID: namedProject}, Present: true, Before: pendingDesired, Proposed: pendingDesired},
		{Resource: domain.ResourceRef{Type: "iam.project", ID: "prj-other"}},
	}
	wholeProposal := func(coordinates []pg.AccessLabelMoveCoordinateEffect) json.RawMessage {
		t.Helper()
		value, err := json.Marshal(map[string]any{"binding_id": pending, "coordinates": coordinates})
		require.NoError(t, err)
		return value
	}
	const certifyWhole = `SELECT kaname.test_role_move_binding_new_v1('binding_member_set',$1::jsonb)`
	var confirmed struct {
		Coordinates    map[string][]string
		BeforeClaims   map[string]json.RawMessage `json:"before_claims"`
		ProposedClaims map[string]json.RawMessage `json:"proposed_claims"`
	}
	require.NoError(t, tx.QueryRow(r.ctx, certifyWhole, wholeProposal(whole)).Scan(&raw))
	require.NoError(t, json.Unmarshal(raw, &confirmed))
	require.Len(t, confirmed.Coordinates, 3)
	require.Empty(t, confirmed.BeforeClaims)
	require.Empty(t, confirmed.ProposedClaims)
	require.ErrorContains(t, rejected("42501", certifyWhole, wholeProposal(whole[:2])), "coordinate count differs")
	require.ErrorContains(t, rejected("42501", certifyWhole, wholeProposal([]pg.AccessLabelMoveCoordinateEffect{whole[0], whole[1], whole[1]})), "duplicate")
	forgedOld := append([]pg.AccessLabelMoveCoordinateEffect(nil), whole...)
	forgedOld[1].Before = nil
	rejected("42501", certifyWhole, wholeProposal(forgedOld))
	const certifyRole = `SELECT kaname.test_role_move_binding_new_v1('direct_member_sets',$1::jsonb)`
	partialRole, err := json.Marshal(map[string][]pg.AccessLabelMoveCoordinateEffect{pending: whole})
	require.NoError(t, err)
	require.ErrorContains(t, rejected("42501", certifyRole, partialRole), "whole role binding set differs")
	rejected("42501", certifyProject, projectProposal(independent, namedProject, projectDesired))
	const certifyMember = `SELECT kaname.test_role_move_binding_new_v1('member_certificate',$1::jsonb)`
	memberProposal := func(bindingID string, members []resourceeffect.ObjectDesiredMember) json.RawMessage {
		t.Helper()
		payload, err := json.Marshal(map[string]any{"binding_id": bindingID, "account_id": r.a, "desired": members})
		require.NoError(t, err)
		return payload
	}
	var memberResult struct {
		BindingID string                               `json:"binding_id"`
		RoleID    string                               `json:"role_id"`
		Desired   []resourceeffect.ObjectDesiredMember `json:"desired"`
	}
	require.NoError(t, tx.QueryRow(r.ctx, certifyMember, memberProposal(active, desired)).Scan(&raw))
	require.NoError(t, json.Unmarshal(raw, &memberResult))
	require.Equal(t, active, memberResult.BindingID)
	require.Equal(t, role, memberResult.RoleID)
	require.ElementsMatch(t, desired, memberResult.Desired)
	rejected("42501", certifyMember, memberProposal(active, []resourceeffect.ObjectDesiredMember{}))
	require.ErrorContains(t, rejected("42501", certifyMember, memberProposal(pending, []resourceeffect.ObjectDesiredMember{})), "outside held ACTIVE decision")
	require.ErrorContains(t, rejected("42501", certifyMember, memberProposal(independent, desired)), "outside held ACTIVE decision")
	for _, invalid := range []string{"forged", "missing"} {
		require.ErrorContains(t, rejected("40001", phase, invalid), "selector move subjects OLD")
	}
	require.ErrorContains(t, rejected("42501", phase, "raw_child_unknown"), "unknown prepared project child source")
	require.ErrorContains(t, rejected("40001", phase, "raw_child_count"), "project child census grew")
	require.ErrorContains(t, rejected("40001", phase, "raw_child_generation"), "project child census changed")
	require.ErrorContains(t, rejected("40001", phase, "local_generation"), "local label census differs")
	require.ErrorContains(t, rejected("40001", phase, "label_generation"), "binding label census differs")
	require.ErrorContains(t, rejected("40001", phase, "missing_position"), "finite position generation differs")
	require.ErrorContains(t, rejected("40001", phase, "selector_versions"), "selector layout changed")
	require.ErrorContains(t, rejected("42501", phase, "approve"), "requires NEW authority")
	rejected("42501", `UPDATE ONLY kaname.roles SET rules=$2::jsonb,updated_at=greatest(transaction_timestamp(),created_at)
		WHERE id=$1 AND xmin::text=$3`, role, newRules, version)
	require.NoError(t, tx.Rollback(r.ctx))
	var unchanged bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r))=$2::jsonb
		AND NOT EXISTS(SELECT FROM kaname.resource_journal WHERE event_type='UPDATED' AND resource_kind='iam_role' AND resource_id=r.id)
		FROM ONLY kaname.roles r WHERE r.id=$1`, role, physical).Scan(&unchanged))
	require.True(t, unchanged)
}
