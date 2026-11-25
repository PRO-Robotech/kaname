// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	projectapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/resourceeffect"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestRoleSelectorMovePendingSourcesAreBoundToDecision(t *testing.T) {
	testRoleSelectorMoveSources(t, false)
}

func TestRoleSelectorMoveActiveNoCopyMemberWitness(t *testing.T) {
	testRoleSelectorMoveSources(t, true)
}

func testRoleSelectorMoveSources(t *testing.T, active bool) {
	t.Helper()
	r, owner := writerProtocolRigBeforePreparation(t)
	actor := bindingPublicOwner(t, r)
	role := ids.NewID("rol")
	native := seedMetadataActualProject(t, r, "pending-source-project")
	project := string(native.ID)
	setProjectLabels(t, r.ctx, r.admin, native.ID, map[string]string{"team": "blue"})
	const previous = `[{"module":"iam","resources":["project"],"verbs":["get"],"match_labels":{"team":"blue"}}]`
	const proposed = `[{"module":"iam","resources":["project"],"verbs":["get"],"match_access_labels":{"team":"blue"}}]`
	var physical json.RawMessage
	var version string
	seed, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, seed)
	require.NoError(t, seed.QueryRow(r.ctx, `INSERT INTO kaname.roles AS r(id,account_id,name,permissions,rules)
		VALUES($1,$2,'pending_source_role','[]',$3) RETURNING xmin::text,jsonb_build_array(xmin::text,ctid::text,to_jsonb(r))`, role, r.a, previous).Scan(&version, &physical))
	binding := groupPendingBindingInHeldProducer(t, r, seed, role, r.a, "user", actor)
	_, err = seed.Exec(r.ctx, `UPDATE kaname.access_bindings SET target=jsonb_build_object('resources',jsonb_build_array(jsonb_build_object('type','iam.project','id',$2::text)))
		WHERE id=$1`, binding, project)
	require.NoError(t, err)
	_, err = seed.Exec(r.ctx, `INSERT INTO kaname.access_binding_emitted_tuples(binding_id,fga_user,relation,object,source)
		VALUES($1,'account:'||$2::text,'account','iam_access_binding:'||$1::text,'binding')`, binding, r.a)
	require.NoError(t, err)
	if active {
		// Физические OLD-строки независимы от предлагаемого p_coordinates.
		old := domain.Rule{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"team": "blue"}}
		_, err = seed.Exec(r.ctx, `UPDATE kaname.access_bindings SET status='ACTIVE' WHERE id=$1`, binding)
		require.NoError(t, err)
		_, err = seed.Exec(r.ctx, `INSERT INTO kaname.access_binding_target_members
			(binding_id,role_id,rule_fp,object_type,object_id,verification_status)
			VALUES($1,$2,$3,'iam.project',$4,'ACTIVE')`, binding, role, old.Fingerprint(), project)
		require.NoError(t, err)
		_, err = seed.Exec(r.ctx, `INSERT INTO kaname.access_binding_emitted_tuples
			(binding_id,source,member_object_type,member_object_id,fga_user,relation,object)
			SELECT $1,'member','iam.project',$2,'user:'||$3::text,verb,'project:'||$2::text
			FROM unnest(ARRAY['v_get','viewer']) AS verbs(verb)`, binding, project, actor)
		require.NoError(t, err)
	}
	require.NoError(t, seed.Commit(r.ctx))
	move, err := json.Marshal(map[string]any{"role_id": role, "version": version, "physical": physical, "proposed_rules": json.RawMessage(proposed),
		"moves": []map[string]int{{"rule_index": 0, "child_index": -1}}, "copy_candidates": []any{}})
	require.NoError(t, err)
	pool, login, _ := roleActorFiniteLogin(t, r)
	const bareTransport = `SELECT kaname.authority_role_sequence_prepare_v3('{"_selector_move":"pending_no_copy_v1","request":{},"hold":{}}'::jsonb,100000,4096)`
	_, err = r.runtime.Exec(r.ctx, bareTransport)
	requireAccessDefinitionSQLState(t, err, "42501")
	_, err = pool.Exec(r.ctx, bareTransport)
	requireAccessDefinitionSQLState(t, err, "42501")
	const finishDenied = `SELECT kaname.authority_role_move_pending_finalize_v1('{}',100000,4096)`
	_, err = r.runtime.Exec(r.ctx, finishDenied)
	requireAccessDefinitionSQLState(t, err, "42501")
	_, err = pool.Exec(r.ctx, finishDenied)
	requireAccessDefinitionSQLState(t, err, "42501")
	const enrolledFinish = `SELECT kaname.authority_role_move_enrolled_finish_v1($1::jsonb,$2,$3)`
	var sharedCanFinish, enrolledCanFinish, enrolledCanCallPrivate bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,
		'kaname.authority_role_move_enrolled_finish_v1(jsonb,integer,integer)','EXECUTE')`).Scan(&sharedCanFinish))
	require.NoError(t, pool.QueryRow(r.ctx, `SELECT
		has_function_privilege(current_user,'kaname.authority_role_move_enrolled_finish_v1(jsonb,integer,integer)','EXECUTE'),
		has_function_privilege(current_user,'kaname.authority_role_move_pending_finalize_v1(jsonb,integer,integer)','EXECUTE')`).Scan(&enrolledCanFinish, &enrolledCanCallPrivate))
	require.False(t, sharedCanFinish)
	require.True(t, enrolledCanFinish)
	require.False(t, enrolledCanCallPrivate)
	const publishBudget = `SELECT kaname._authority_role_move_sequence_approve_budget_v1(100000,4096)`
	_, err = r.runtime.Exec(r.ctx, publishBudget)
	requireAccessDefinitionSQLState(t, err, "42501")
	_, err = pool.Exec(r.ctx, publishBudget)
	requireAccessDefinitionSQLState(t, err, "42501")
	const metered = `SELECT kaname._authority_role_move_content_approve_budget_v1(100000,4096)`
	_, err = r.runtime.Exec(r.ctx, metered)
	requireAccessDefinitionSQLState(t, err, "42501")
	_, err = pool.Exec(r.ctx, metered)
	requireAccessDefinitionSQLState(t, err, "42501")
	const attest = `SELECT kaname.authority_role_move_content_approved_v1()`
	_, err = r.runtime.Exec(r.ctx, attest)
	requireAccessDefinitionSQLState(t, err, "42501")
	_, err = pool.Exec(r.ctx, attest)
	requireAccessDefinitionSQLState(t, err, "42501")
	var ddl string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT format($ddl$
	CREATE FUNCTION kaname.test_role_pending_source_v1(action text, coordinate_sets jsonb DEFAULT NULL) RETURNS jsonb
	LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $probe$
	DECLARE move jsonb:=%1$L::jsonb; actor jsonb:=jsonb_build_object('type','user','id',%2$L::text);
		epoch jsonb;request jsonb;f jsonb;receipt_key text;
	BEGIN
		IF session_user::text IS DISTINCT FROM %3$L THEN RAISE EXCEPTION 'wrong pending source login';END IF;
		IF action IN ('transport_clock','transport_finalize') THEN
			epoch:=kaname.authority_binding_epoch_read(NULL::text[]);
			PERFORM kaname.authority_role_stage_epoch_lock(NULL::text[],epoch);
			IF action='transport_finalize' THEN PERFORM kaname._authority_role_move_sequence_finalize_v1('[]'::jsonb,100000,4096);END IF;
			RETURN 'true'::jsonb;
		END IF;
		IF action='active_member_insert' THEN
			RETURN kaname._authority_role_move_active_member_insert_v1(100000,4096);
		END IF;
		IF action IN ('active_source_seal','active_source_replay','active_source_tamper') THEN
			IF action='active_source_tamper' THEN
				UPDATE pg_temp.kaname_authority_sequence_program SET frozen=jsonb_set(frozen,
					'{selector_move_active_project_seal,witness,ledger_sha256}','"stale"'::jsonb,false) WHERE singleton;
			END IF;
			RETURN kaname._authority_role_move_active_project_seal_v1(
				CASE WHEN action='active_source_seal' THEN coordinate_sets END,100000,4096);
		END IF;
		IF action IN ('active_witness','active_stale_member','active_stale_ledger') THEN
			IF action='active_stale_member' THEN
				UPDATE pg_temp.kaname_authority_sequence_program SET frozen=jsonb_set(frozen,
					'{selector_move,binding_census,members,0,0}','"stale"'::jsonb,false) WHERE singleton;
			ELSIF action='active_stale_ledger' THEN
				UPDATE pg_temp.kaname_authority_sequence_program SET frozen=jsonb_set(frozen,
					'{selector_move,binding_census,ledger,0,0}','"stale"'::jsonb,false) WHERE singleton;
			END IF;
			RETURN kaname._authority_role_move_active_project_witness_v1(coordinate_sets,100000,4096);
		END IF;
		IF action='content' THEN PERFORM kaname.authority_role_move_content_approved_v1();RETURN 'true'::jsonb;END IF;
		IF action='prepare' THEN
			request:=jsonb_build_object('create',false,'rules',true,'retier',true,'version',move->'version','mask',jsonb_build_array('rules'),
				'role',jsonb_build_object('id',move->'role_id','rules',move->'proposed_rules','permissions','[]'::jsonb),
				'_access_label_authority',jsonb_build_object('actor',actor,'questions','[]'::jsonb));
			epoch:=kaname.authority_binding_epoch_read(NULL::text[]);
			PERFORM kaname.authority_role_stage_epoch_lock(NULL::text[],epoch);
			PERFORM kaname._authority_role_move_sequence_prepare_v1(request,move,actor,100000,4096);
			PERFORM kaname.authority_role_stage_epoch_lock(NULL::text[],epoch);
			PERFORM kaname._authority_role_move_sequence_finalize_v1('[]'::jsonb,100000,4096);
			RETURN 'true'::jsonb;
		END IF;
		f:=kaname._authority_sequence_store_v3()->'frozen';
		IF f#>'{selector_move,role,physical}' IS DISTINCT FROM move->'physical' THEN RAISE EXCEPTION 'wrong pending source role';END IF;
		IF action='finish' THEN
			RETURN kaname.authority_role_move_pending_finalize_v1(coordinate_sets->'sets',
				(coordinate_sets->>'rows')::integer,(coordinate_sets->>'reads')::integer);
		END IF;
		IF action='native_cost' THEN
			RETURN kaname._authority_role_move_sequence_finalize_v1('[]'::jsonb,100000,4096);
		END IF;
		IF action='finish_pristine' THEN
			RETURN to_jsonb(NOT (f ?| ARRAY['selector_move_decision','selector_move_pending','selector_move_pending_sources','selector_move_content_approval',
				'selector_move_approved','selector_move_pending_sources_approved','selector_move_approved_content_sha256','selector_move_publication_budget']));
		END IF;
		IF action='budget_publish' THEN
			RETURN kaname._authority_role_move_sequence_approve_budget_v1((coordinate_sets->>0)::integer,(coordinate_sets->>1)::integer);
		END IF;
		IF action='publication_state' THEN
			RETURN jsonb_build_object('selected',f ? 'selector_move_approved','budget',f->'selector_move_publication_budget');
		END IF;
		IF action IN ('empty_deferred_rows','empty_deferred_reads') THEN
			receipt_key:=CASE action WHEN 'empty_deferred_rows' THEN 'rows' ELSE 'reads' END;
			UPDATE pg_temp.kaname_authority_sequence_program s SET frozen=jsonb_set(s.frozen,
				ARRAY['selector_move_publication_budget',receipt_key],'0'::jsonb,false) WHERE s.singleton;
			PERFORM kaname._authority_role_move_roots_complete_v1();RETURN 'true'::jsonb;
		END IF;
		IF action='measure_content' THEN
			RETURN kaname._authority_role_move_content_replay_cost_v1(100000,4096);
		END IF;
		IF action='budget_content' THEN
			RETURN kaname._authority_role_move_content_approve_budget_v1((coordinate_sets->>0)::integer,(coordinate_sets->>1)::integer);
		END IF;
		IF action='content_hash' THEN
			RETURN to_jsonb(encode(sha256(convert_to((f->'selector_move_content_approval')::text,'UTF8')),'hex'));
		END IF;
		IF action='change_content' THEN
			UPDATE pg_temp.kaname_authority_sequence_program s SET frozen=jsonb_set(s.frozen,
				'{selector_move_content_approval,source_sha256}','"changed"'::jsonb,false) WHERE s.singleton;
			PERFORM kaname._authority_role_move_sequence_approve_v1();RETURN 'true'::jsonb;
		END IF;
		IF action='published' THEN
			RETURN to_jsonb(f->>'selector_move_approved_content_sha256'=
				encode(sha256(convert_to((f->'selector_move_content_approval')::text,'UTF8')),'hex'));
		END IF;
		IF action='approve' THEN PERFORM kaname._authority_role_move_sequence_approve_v1();RETURN 'true'::jsonb;END IF;
		IF action='commit_check' THEN PERFORM kaname._authority_role_move_roots_complete_v1();RETURN 'true'::jsonb;END IF;
		IF action IN ('actor','nonce','role_generation','decision_at') THEN
			receipt_key:=action;
			UPDATE pg_temp.kaname_authority_sequence_program s SET frozen=jsonb_set(s.frozen,
				ARRAY['selector_move_pending_sources',receipt_key],'"changed"'::jsonb,false) WHERE s.singleton;
		ELSIF action='sets' THEN
			UPDATE pg_temp.kaname_authority_sequence_program s SET frozen=jsonb_set(s.frozen,
				ARRAY['selector_move_pending_sources','sets',%4$L],(SELECT jsonb_agg(c ORDER BY n DESC)
					FROM jsonb_array_elements(s.frozen#>ARRAY['selector_move_pending_sources','sets',%4$L]) WITH ORDINALITY a(c,n)),false)
				WHERE s.singleton;
		ELSIF action='change_clock' THEN
			epoch:=kaname.authority_binding_epoch_read(NULL::text[]);PERFORM kaname.authority_role_stage_epoch_lock(NULL::text[],epoch);
		ELSIF action NOT IN ('seal','replay') THEN RAISE EXCEPTION 'unknown pending source phase';END IF;
		RETURN kaname._authority_role_move_pending_sources_v1(CASE WHEN action='seal' THEN coordinate_sets END,100000,4096);
	END;
	$probe$;
	REVOKE ALL ON FUNCTION kaname.test_role_pending_source_v1(text,jsonb) FROM PUBLIC;
	GRANT EXECUTE ON FUNCTION kaname.test_role_pending_source_v1(text,jsonb) TO %3$I;
	$ddl$,$1::text,$2::text,$3::text,$4::text)`, string(move), actor, login, binding).Scan(&ddl))
	_, err = r.admin.Exec(r.ctx, ddl)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := r.admin.Exec(ctx, `DROP FUNCTION kaname.test_role_pending_source_v1(text,jsonb)`)
		require.NoError(t, err)
	})
	// Через закрытый тестовый адаптер проверяется и внутренняя граница входа.
	_, err = pool.Exec(r.ctx, `SELECT kaname.test_role_pending_source_v1('content')`)
	requireAccessDefinitionSQLState(t, err, "42501")
	pendingSourceApplyProjectLabel(t, r, owner, actor, native.ID)
	var halves catalog.Halves
	require.NoError(t, json.Unmarshal(r.bundle.CanonicalCatalog(), &halves))
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	projectObject := domain.MirrorObject{ObjectType: "iam.project", ObjectID: project, ParentProjectID: project, ParentAccountIDs: []string{r.a}}
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT labels,access_labels FROM ONLY kaname.projects WHERE id=$1`, project).
		Scan(&projectObject.Labels, &projectObject.AccessLabels))
	require.Equal(t, map[string]string{"team": "blue"}, projectObject.Labels)
	require.Equal(t, projectObject.Labels, projectObject.AccessLabels)
	scopeObject := domain.MirrorObject{ObjectType: "iam.account", ObjectID: r.a, ParentAccountIDs: []string{r.a}}
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT labels,access_labels FROM ONLY kaname.accounts WHERE id=$1`, r.a).Scan(&scopeObject.Labels, &scopeObject.AccessLabels))
	contributions := func(rule domain.Rule) ([]resourceeffect.ObjectDesiredMember, []resourceeffect.ObjectDesiredMember) {
		t.Helper()
		rules := domain.Rules{rule}
		projection, err := r.bundle.Projection(domain.Role{ID: domain.RoleID(role), Rules: rules})
		require.NoError(t, err)
		view := resourceeffect.ObjectBinding{BindingID: domain.AccessBindingID(binding), RoleID: role, Scope: domain.ScopeAnchor{Type: "account", ID: r.a},
			Target: domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "iam.project", ID: project}}}, Active: true, Policy: domain.PolicyOfRole(false, ""),
			Subjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(actor)}}, Selectors: projection.Selectors, ScopeSelfVerbs: rules.ScopeSelfVerbs("account", nil)}
		ac, err := resourceeffect.CompileObjectDesired(facts, view, scopeObject, nil)
		require.NoError(t, err)
		pr, err := resourceeffect.CompileProjectObjectDesired(facts, view, projectObject,
			resourceeffect.ProjectGraphProjection{ConfirmedAbsent: domain.ResourceRef{Type: "iam.project", ID: project}})
		require.NoError(t, err)
		require.NotEmpty(t, pr)
		return ac, pr
	}
	oldRule := domain.Rule{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"team": "blue"}}
	newRule := oldRule
	newRule.MatchLabels = nil
	newRule.MatchAccessLabels = map[string]string{"team": "blue"}
	oldAccount, oldProject := contributions(oldRule)
	newAccount, newProject := contributions(newRule)
	type coordinate struct {
		Resource         domain.ResourceRef
		Present          bool
		Before, Proposed []resourceeffect.ObjectDesiredMember
	}
	all := []coordinate{{domain.ResourceRef{Type: "iam.account", ID: r.a}, true, oldAccount, newAccount}, {domain.ResourceRef{Type: "iam.project", ID: project}, true, oldProject, newProject}}
	sets := func(coords []coordinate) json.RawMessage {
		t.Helper()
		raw, err := json.Marshal(map[string][]coordinate{binding: coords})
		require.NoError(t, err)
		return raw
	}
	conn, err := pool.Acquire(r.ctx)
	require.NoError(t, err)
	defer conn.Release()
	rr, err := conn.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	require.NoError(t, err)
	lifecycleRollback(t, rr)
	_, err = rr.Exec(r.ctx, `CREATE TEMP TABLE kaname_role_stage_tuples(binding_id text NOT NULL,side text NOT NULL,object text NOT NULL,fga_user text NOT NULL,relation text NOT NULL,
		PRIMARY KEY(binding_id,side,object,fga_user,relation)) ON COMMIT PRESERVE ROWS`)
	require.NoError(t, err)
	_, err = rr.Exec(r.ctx, kanamepg.RoleMoveStageTupleGrantSQL)
	require.NoError(t, err)
	_, err = rr.Exec(r.ctx, `INSERT INTO pg_temp.kaname_role_stage_tuples SELECT $1::text,s,'iam_access_binding:'||$1::text,'account:'||$2::text,'account' FROM unnest(ARRAY['old','new']) s`, binding, r.a)
	require.NoError(t, err)
	require.NoError(t, rr.Commit(r.ctx))
	tx, err := conn.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	identity := r.bundle.Identity()
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_protocol_enter_typed_v3('global',ARRAY[]::text[],'[]'::jsonb,'role',$1,$2,$3,'decision')`, identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
	require.NoError(t, err)
	const call = `SELECT kaname.test_role_pending_source_v1($1,$2::jsonb)`
	if active {
		const privilege = `SELECT has_function_privilege(current_user,'kaname._authority_role_move_active_project_witness_v1(jsonb,integer,integer)','EXECUTE')`
		var privileged bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, privilege).Scan(&privileged))
		require.False(t, privileged)
		require.NoError(t, tx.QueryRow(r.ctx, privilege).Scan(&privileged))
		require.False(t, privileged)
		_, err = tx.Exec(r.ctx, call, "prepare", nil)
		require.NoError(t, err)
		payload, err := json.Marshal(all)
		require.NoError(t, err)
		var report struct {
			Role        string            `json:"role_id"`
			Binding     string            `json:"binding_id"`
			Project     string            `json:"project_id"`
			Member      []json.RawMessage `json:"member_old"`
			NewFP       string            `json:"new_rule_fp"`
			LedgerHash  string            `json:"ledger_sha256"`
			Rows, Reads int
		}
		require.NoError(t, tx.QueryRow(r.ctx, call, "active_witness", payload).Scan(&report))
		require.Equal(t, role, report.Role)
		require.Equal(t, binding, report.Binding)
		require.Equal(t, project, report.Project)
		require.Len(t, report.Member, 3)
		var physicalMember struct {
			FP string `json:"rule_fp"`
		}
		require.NoError(t, json.Unmarshal(report.Member[2], &physicalMember))
		require.Equal(t, oldRule.Fingerprint(), physicalMember.FP)
		require.Equal(t, newRule.Fingerprint(), report.NewFP)
		require.Len(t, report.LedgerHash, 64)
		require.Positive(t, report.Rows)
		require.Positive(t, report.Reads)
		reject := func(action string, input json.RawMessage, state string) {
			t.Helper()
			probe, err := tx.Begin(r.ctx)
			require.NoError(t, err)
			_, err = probe.Exec(r.ctx, call, action, input)
			requireAccessDefinitionSQLState(t, err, state)
			require.NoError(t, probe.Rollback(r.ctx))
		}
		reject("active_stale_member", payload, "40001")
		reject("active_stale_ledger", payload, "40001")
		changed := append([]coordinate(nil), all...)
		changed[1].Proposed = nil
		forged, err := json.Marshal(changed)
		require.NoError(t, err)
		reject("active_witness", forged, "42501")
		const privateSeal = `SELECT has_function_privilege(current_user,'kaname._authority_role_move_active_project_seal_v1(jsonb,integer,integer)','EXECUTE')`
		require.NoError(t, r.runtime.QueryRow(r.ctx, privateSeal).Scan(&privileged))
		require.False(t, privileged)
		require.NoError(t, tx.QueryRow(r.ctx, privateSeal).Scan(&privileged))
		require.False(t, privileged)
		require.Len(t, oldProject, 1)
		require.Len(t, newProject, 1)
		prior, desired := oldProject[0], newProject[0]
		bid := domain.AccessBindingID(binding)
		key := reconcile.MemberCoord{ObjectType: "iam.project", ObjectID: project}
		input := reconcile.CapturedObjectDiff{
			Binding:  reconcile.BindingScope{BindingID: bid, RoleID: role, Active: true, Scope: domain.ScopeAnchor{Type: "account", ID: r.a}},
			Converge: true, Live: map[reconcile.MemberCoord]bool{key: true},
			Current: []domain.TargetMember{{BindingID: bid, RoleID: domain.RoleID(role), RuleFP: prior.RuleFP,
				ObjectType: key.ObjectType, ObjectID: key.ObjectID, VerificationStatus: prior.Status}},
			Desired: []reconcile.DesiredMember{{Derivation: desired.Derivation, RuleFP: desired.RuleFP, ObjectType: key.ObjectType,
				ObjectID: key.ObjectID, Status: desired.Status, Tuples: desired.Tuples}},
		}
		for _, tuple := range prior.Tuples {
			input.Ledger = append(input.Ledger, reconcile.LedgerRow{Member: key, Tuple: tuple})
		}
		commands, err := reconcile.CompileCapturedObjectDiff(r.ctx, []reconcile.CapturedObjectDiff{input})
		require.NoError(t, err)
		require.Len(t, commands, 4)
		proposal := func(commands []reconcile.BindingCommand) json.RawMessage {
			t.Helper()
			raw, err := json.Marshal(map[string]any{"coordinates": all, "commands": commands})
			require.NoError(t, err)
			return raw
		}
		const privateInsert = `SELECT has_function_privilege(current_user,'kaname._authority_role_move_active_member_insert_v1(integer,integer)','EXECUTE')`
		require.NoError(t, r.runtime.QueryRow(r.ctx, privateInsert).Scan(&privileged))
		require.False(t, privileged)
		require.NoError(t, tx.QueryRow(r.ctx, privateInsert).Scan(&privileged))
		require.False(t, privileged)
		reject("active_member_insert", nil, "42501")
		reject("active_source_replay", nil, "42501")
		bad := append([]reconcile.BindingCommand(nil), commands...)
		bad[3].RuleFP = newRule.Fingerprint()
		reject("active_source_seal", proposal(bad), "42501")
		bad = append([]reconcile.BindingCommand(nil), commands...)
		bad[1].Tuples = append([]domain.MembershipTuple(nil), commands[1].Tuples...)
		require.NotEmpty(t, bad[1].Tuples)
		bad[1].Tuples[0].Relation = "v_delete"
		reject("active_source_seal", proposal(bad), "42501")
		var sealed, replay struct {
			SHA256      string
			Rows, Reads int
		}
		require.NoError(t, tx.QueryRow(r.ctx, call, "active_source_seal", proposal(commands)).Scan(&sealed))
		require.Len(t, sealed.SHA256, 64)
		require.Positive(t, sealed.Rows)
		require.Positive(t, sealed.Reads)
		reject("active_source_seal", proposal(commands), "42501")
		reject("active_source_tamper", nil, "40001")
		require.NoError(t, tx.QueryRow(r.ctx, call, "active_source_replay", nil).Scan(&replay))
		require.Equal(t, sealed.SHA256, replay.SHA256)
		reject("seal", sets(all), "42501")
		var consumed struct {
			Ordinal   int               `json:"last_consumed"`
			Hash      string            `json:"seal_sha256"`
			NewMember []json.RawMessage `json:"member_new"`
		}
		require.NoError(t, tx.QueryRow(r.ctx, call, "active_member_insert", nil).Scan(&consumed))
		require.Equal(t, 1, consumed.Ordinal)
		require.Equal(t, sealed.SHA256, consumed.Hash)
		require.Len(t, consumed.NewMember, 3)
		var inserted struct {
			FP string `json:"rule_fp"`
		}
		require.NoError(t, json.Unmarshal(consumed.NewMember[2], &inserted))
		require.Equal(t, report.NewFP, inserted.FP)
		reject("active_member_insert", nil, "42501")
		const members = `SELECT count(*) FILTER (WHERE rule_fp=$4),count(*) FILTER (WHERE rule_fp=$5)
			FROM ONLY kaname.access_binding_target_members WHERE binding_id=$1 AND role_id=$2 AND
			object_type='iam.project' AND object_id=$3 AND verification_status='ACTIVE'`
		verify := func(row pgx.Row, wantNew int) {
			t.Helper()
			var oldCount, newCount int
			require.NoError(t, row.Scan(&oldCount, &newCount))
			require.Equal(t, 1, oldCount)
			require.Equal(t, wantNew, newCount)
		}
		args := []any{binding, role, project, oldRule.Fingerprint(), report.NewFP}
		verify(tx.QueryRow(r.ctx, members, args...), 1)
		verify(r.admin.QueryRow(r.ctx, members, args...), 0)
		requireAccessDefinitionSQLState(t, tx.Commit(r.ctx), "42501")
		verify(r.admin.QueryRow(r.ctx, members, args...), 0)
		return
	}
	// Штатный prepare удерживает OLD в той же backend-сессии. Самостоятельная
	// ветка savepoint показывает границу публичных методов до расчёта Grant.
	t.Run("публичный prepare удерживает без публикации", func(t *testing.T) {
		probe, err := tx.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, probe)
		request := map[string]any{
			"create": false, "rules": true, "retier": true, "version": version, "mask": []string{"rules"},
			"role":                    map[string]any{"id": role, "rules": json.RawMessage(proposed), "permissions": []string{}},
			"_access_label_authority": map[string]any{"actor": map[string]string{"type": "user", "id": actor}, "questions": []any{}},
		}
		envelope := map[string]any{"_selector_move": "pending_no_copy_v1", "request": request, "hold": json.RawMessage(move)}
		const prepare = `SELECT kaname.authority_role_sequence_prepare_v3($1::jsonb,100000,4096)`
		_, err = probe.Exec(r.ctx, call, "transport_clock", nil)
		require.NoError(t, err)
		deny := func(query string, args ...any) {
			t.Helper()
			check, err := probe.Begin(r.ctx)
			require.NoError(t, err)
			_, err = check.Exec(r.ctx, query, args...)
			requireAccessDefinitionSQLState(t, err, "42501")
			require.NoError(t, check.Rollback(r.ctx))
		}
		envelope["actor"] = actor
		deny(prepare, envelope)
		delete(envelope, "actor")
		var result struct {
			Mode      string `json:"access_label_mode"`
			Transport string `json:"selector_move_transport"`
			Rows      int
			Reads     int
		}
		require.NoError(t, probe.QueryRow(r.ctx, prepare, envelope).Scan(&result))
		require.Equal(t, "ordinary", result.Mode)
		require.Equal(t, "pending_no_copy_v1", result.Transport)
		require.Positive(t, result.Rows)
		require.Positive(t, result.Reads)
		_, err = probe.Exec(r.ctx, call, "transport_clock", nil)
		require.NoError(t, err)
		deny(`SELECT kaname.authority_role_sequence_finalize_v3()`)
		type usage struct{ Rows, Reads int }
		type selection struct {
			usage
			Transport     string `json:"selector_move_transport"`
			Phase         string
			DeferredRows  int    `json:"deferred_rows"`
			DeferredReads int    `json:"deferred_reads"`
			Source        string `json:"source_sha256"`
			Content       string `json:"content_sha256"`
		}
		args := func(rows, reads int) map[string]any {
			return map[string]any{"sets": sets(all), "rows": rows, "reads": reads}
		}
		// Отдельный savepoint оставляет исходный nonce и окончательные часы
		// для сверки тех же четырёх фаз по одной.
		composed, err := probe.Begin(r.ctx)
		require.NoError(t, err)
		var combined selection
		require.NoError(t, composed.QueryRow(r.ctx, call, "finish", args(100000, 4096)).Scan(&combined))
		require.Equal(t, "pending_no_copy_v1", combined.Transport)
		require.Equal(t, "selected", combined.Phase)
		require.Equal(t, 100000, combined.Rows+combined.DeferredRows)
		require.Equal(t, 4096, combined.Reads+combined.DeferredReads)
		repeated, err := composed.Begin(r.ctx)
		require.NoError(t, err)
		_, err = repeated.Exec(r.ctx, call, "finish", args(100000, 4096))
		requireAccessDefinitionSQLState(t, err, "42501")
		require.NoError(t, repeated.Rollback(r.ctx))
		require.NoError(t, composed.Rollback(r.ctx))

		// Выделенный LOGIN проходит тот же вход, которым пользуется Go writer.
		enrolled, err := probe.Begin(r.ctx)
		require.NoError(t, err)
		var viaRuntime selection
		require.NoError(t, enrolled.QueryRow(r.ctx, enrolledFinish, sets(all), 100000, 4096).Scan(&viaRuntime))
		require.Equal(t, combined, viaRuntime)
		require.NoError(t, enrolled.Rollback(r.ctx))
		for _, short := range [][2]int{{combined.Rows + 20, 4096}, {100000, combined.Reads + 9}} {
			trial, err := probe.Begin(r.ctx)
			require.NoError(t, err)
			_, err = trial.Exec(r.ctx, call, "finish", args(short[0], short[1]))
			requireAccessDefinitionSQLState(t, err, "54000")
			require.NoError(t, trial.Rollback(r.ctx))
			var pristine bool
			require.NoError(t, probe.QueryRow(r.ctx, call, "finish_pristine", nil).Scan(&pristine))
			require.True(t, pristine)
		}
		wrong := args(100000, 4096)
		wrong["sets"] = sets(all[:1])
		deny(call, "finish", wrong)
		var nativeCost usage
		require.NoError(t, probe.QueryRow(r.ctx, call, "native_cost", nil).Scan(&nativeCost))
		deny(call, "approve", nil)
		deny(call, "commit_check", nil)
		var sourceCost struct {
			usage
			SHA256 string
		}
		require.NoError(t, probe.QueryRow(r.ctx, call, "seal", sets(all)).Scan(&sourceCost))
		var contentCost struct {
			usage
			Hash string `json:"content_sha256"`
		}
		require.NoError(t, probe.QueryRow(r.ctx, call, "budget_content", []int{100000, 4096}).Scan(&contentCost))
		require.Equal(t, sourceCost.SHA256, combined.Source)
		require.Equal(t, contentCost.Hash, combined.Content)
		deny(call, "approve", nil)
		var replay struct{ Rows, Reads int }
		require.NoError(t, probe.QueryRow(r.ctx, call, "measure_content", nil).Scan(&replay))
		var state struct {
			Selected bool
			Budget   *struct {
				Phase       string
				Rows, Reads int
			}
		}
		insufficient := func(action string, budget []int) {
			t.Helper()
			sv, err := probe.Begin(r.ctx)
			require.NoError(t, err)
			_, err = sv.Exec(r.ctx, call, action, budget)
			requireAccessDefinitionSQLState(t, err, "54000")
			require.NoError(t, sv.Rollback(r.ctx))
		}
		// 13 расходов окружают измеренный replay до публикации. Оставляем на
		// один меньше минимального остатка deferred по каждой оси отдельно.
		insufficient("budget_publish", []int{13 + replay.Rows + 20, 4096})
		insufficient("budget_publish", []int{100000, 13 + replay.Reads + 9})
		require.NoError(t, probe.QueryRow(r.ctx, call, "publication_state", nil).Scan(&state))
		require.False(t, state.Selected)
		require.Nil(t, state.Budget)
		var spent struct {
			Rows, Reads   int
			DeferredRows  int `json:"deferred_rows"`
			DeferredReads int `json:"deferred_reads"`
		}
		require.NoError(t, probe.QueryRow(r.ctx, call, "budget_publish", []int{100000, 4096}).Scan(&spent))
		require.Equal(t, 5+nativeCost.Rows+sourceCost.Rows+contentCost.Rows+spent.Rows, combined.Rows)
		require.Equal(t, 5+nativeCost.Reads+sourceCost.Reads+contentCost.Reads+spent.Reads, combined.Reads)
		require.Equal(t, 13+replay.Rows, spent.Rows)
		require.Equal(t, 13+replay.Reads, spent.Reads)
		require.Equal(t, 100000, spent.Rows+spent.DeferredRows)
		require.Equal(t, 4096, spent.Reads+spent.DeferredReads)
		insufficient("empty_deferred_rows", nil)
		insufficient("empty_deferred_reads", nil)
		require.NoError(t, probe.QueryRow(r.ctx, call, "publication_state", nil).Scan(&state))
		require.True(t, state.Selected)
		require.NotNil(t, state.Budget)
		require.Equal(t, "deferred", state.Budget.Phase)
		require.Equal(t, spent.DeferredRows, state.Budget.Rows)
		require.Equal(t, spent.DeferredReads, state.Budget.Reads)
		deny(call, "budget_publish", []int{100000, 4096})
		require.NoError(t, probe.Rollback(r.ctx))
	})
	_, err = tx.Exec(r.ctx, call, "prepare", nil)
	require.NoError(t, err)
	reject := func(action string, proposal json.RawMessage, code string) {
		t.Helper()
		probe, err := tx.Begin(r.ctx)
		require.NoError(t, err)
		_, err = probe.Exec(r.ctx, call, action, proposal)
		requireAccessDefinitionSQLState(t, err, code)
		if (action == "approve" || action == "commit_check") && code == "42501" {
			require.ErrorContains(t, err, "require owner method and grant authority")
		}
		require.NoError(t, probe.Rollback(r.ctx))
	}
	reject("content", nil, "42501")
	reject("seal", sets(all[:1]), "42501")
	var first, second struct{ SHA256 string }
	var raw json.RawMessage
	require.NoError(t, tx.QueryRow(r.ctx, call, "seal", sets(all)).Scan(&raw))
	require.NoError(t, json.Unmarshal(raw, &first))
	require.Len(t, first.SHA256, 64)
	require.NoError(t, tx.QueryRow(r.ctx, call, "replay", nil).Scan(&raw))
	require.NoError(t, json.Unmarshal(raw, &second))
	require.Equal(t, first, second)
	reject("seal", sets(all), "42501")
	for _, field := range []string{"actor", "nonce", "role_generation", "decision_at", "sets"} {
		reject(field, nil, "40001")
	}
	reject("change_clock", nil, "42501")
	reject("approve", nil, "42501")
	reject("commit_check", nil, "42501")
	var replay struct {
		Rows    int
		Reads   int
		Receipt struct {
			SourceHash string `json:"source_sha256"`
		}
	}
	require.NoError(t, tx.QueryRow(r.ctx, call, "measure_content", nil).Scan(&replay))
	require.Greater(t, replay.Rows, 3)
	require.Greater(t, replay.Reads, 3)
	require.Equal(t, first.SHA256, replay.Receipt.SourceHash)
	allowance := func(rows, reads int) json.RawMessage {
		t.Helper()
		raw, err := json.Marshal([2]int{rows, reads})
		require.NoError(t, err)
		return raw
	}
	// Для записи нужны ещё два чтения writer и адресный UPDATE его программы.
	// Отказ в каждой оси предшествует записи этой квитанции.
	reject("budget_content", allowance(replay.Rows+2, 4096), "54000")
	reject("budget_content", allowance(100000, replay.Reads+2), "54000")
	accounted, err := tx.Begin(r.ctx)
	require.NoError(t, err)
	var recorded struct {
		Rows  int
		Reads int
		Hash  string `json:"content_sha256"`
	}
	require.NoError(t, accounted.QueryRow(r.ctx, call, "budget_content", allowance(100000, 4096)).Scan(&recorded))
	require.Equal(t, replay.Rows+3, recorded.Rows)
	require.Equal(t, replay.Reads+3, recorded.Reads)
	require.Len(t, recorded.Hash, 64)
	require.NoError(t, accounted.Rollback(r.ctx))
	_, err = tx.Exec(r.ctx, call, "content", nil)
	require.NoError(t, err)
	var contentHash string
	require.NoError(t, tx.QueryRow(r.ctx, call, "content_hash", nil).Scan(&raw))
	require.NoError(t, json.Unmarshal(raw, &contentHash))
	require.Equal(t, recorded.Hash, contentHash)
	reject("content", nil, "42501")
	unfinished, err := tx.Begin(r.ctx)
	require.NoError(t, err)
	_, err = unfinished.Exec(r.ctx, call, "commit_check", nil)
	requireAccessDefinitionSQLState(t, err, "42501")
	require.ErrorContains(t, err, "was not published")
	require.NoError(t, unfinished.Rollback(r.ctx))
	reject("change_content", nil, "42501")
	_, err = tx.Exec(r.ctx, call, "approve", nil)
	require.NoError(t, err)
	var published bool
	require.NoError(t, tx.QueryRow(r.ctx, call, "published", nil).Scan(&published))
	require.True(t, published)
	reject("content", nil, "42501")
	// Выбранный слот UPDATE ещё не потреблён. Проверяем ту же функцию, которую вызывает deferred trigger.
	reject("commit_check", nil, "40001")
	require.NoError(t, tx.Rollback(r.ctx))
	var oldRules bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT rules=$2::jsonb FROM ONLY kaname.roles WHERE id=$1`, role, previous).Scan(&oldRules))
	require.True(t, oldRules)
}

// У проектной строки уже есть обычная метка. Вторую карту заполняет штатный
// Project.Update после адресной выдачи Apply владельцу этого проекта.
func pendingSourceApplyProjectLabel(t *testing.T, r protocolRig, owner *kanamepg.Repository, actor string, project domain.ProjectID,
	otherEditors ...domain.AccessBindingID,
) (*kanamepg.Repository, *kanamepg.FullWriterContract) {
	t.Helper()
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.memberships(id,user_id,account_id,state)
		VALUES(kaname.membership_mirror_id($1,$2),$1,$2,'ACTIVE')
		ON CONFLICT(user_id,account_id) DO UPDATE SET state='ACTIVE'`, actor, r.a)
	require.NoError(t, err)
	definition, err := owner.AddAccessLabelValues(r.ctx, kanamepg.AccessLabelDeclaration{
		Account: r.a, Project: string(project), Module: "iam", Resource: "project", Key: "team", Values: []string{"blue"},
	})
	require.NoError(t, err)
	editor := groupLifecycleBinding(t, r, r.a, actor, "pending_source_project_update", domain.Rule{
		Module: "iam", Resources: []string{"project"}, Verbs: []string{"update"}, ResourceNames: []string{string(project)},
	})
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	source := rolePolicyCatalog(t, r)
	engine := reconcile.New(kanamepg.NewReconcileAdapter(r.admin, source), slog.Default(), source)
	for _, id := range append([]domain.AccessBindingID{editor}, otherEditors...) {
		require.NoError(t, engine.ReconcileBinding(r.ctx, id))
	}
	full, contract := fullContractActivate(t, r)
	_, err = owner.IssueInitialAccessLabelApply(r.ctx, kanamepg.InitialAccessLabelApply{
		Account: r.a, Project: string(project),
		DefinitionID: domain.AccessLabelDefinitionID(definition.ID), ExpectedRevision: definition.Revision,
	}, r.bundle)
	require.NoError(t, err)
	plans, err := authzmodel.New(r.bundle.ModelSource())
	require.NoError(t, err)
	door := authzcascade.WrapAdmitted(relverdict.NewPreparedAsker(r.runtime, plans), personmarks.New(r.runtime))
	ops := operations.NewRepo(r.runtime, "kaname")
	factory, err := kanamepg.NewMetadataMutationWriters(r.ctx, full, r.bundle)
	require.NoError(t, err)
	ports, err := factory.WithInstalledAccessLabels(r.ctx)
	require.NoError(t, err)
	update := projectapp.NewUpdateProjectUseCase(full, ops).
		WithRelationStore(door, nil).WithProjectMetadataWriter(ports)
	ctx := contract.Context(declarerCtx(r.ctx, actor))
	op, err := update.Execute(ctx, projectapp.UpdateProjectInput{
		ID: project, AccessLabels: domain.Labels{"team": "blue"}, UpdateMask: []string{"access_labels"},
	})
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, ctx, ops, op.ID).Error)
	return full, contract
}
