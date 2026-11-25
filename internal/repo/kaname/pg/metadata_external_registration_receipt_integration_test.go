// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestExternalMetadataSignedRegistrationReceipt(t *testing.T) {
	const dotted, model, otherDotted, otherModel = "vpc.network", "vpc_network", "compute.instance", "compute_instance"
	const objectID = "external-receipt/shared"
	w := metadataFixtureMode(t, false, "prepared")
	// Используем проект с уже зафиксированными структурными связями.
	// Второй проект изменил бы точную трёхобъектную выдачу metadata fixture.
	projectID := string(w.project.ID)
	var definitionID string
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `INSERT INTO kaname.authority_access_label_definition
 (scope_kind,scope_id,module,resource,label_key)
 VALUES('project',$1,'vpc','network','team') RETURNING id::text`, projectID).Scan(&definitionID))
	_, err := w.r.admin.Exec(w.r.ctx, `INSERT INTO kaname.authority_access_label_value(definition_id,label_value)
 VALUES($1::uuid,'after')`, definitionID)
	require.NoError(t, err)
	// Обе карты защищённых меток остаются штатным пустым DEFAULT.
	_, err = w.r.admin.Exec(w.r.ctx, `INSERT INTO kaname.resource_mirror
 (object_type,object_id,parent_account_id,parent_project_id)
 VALUES($1,$3,$4,$5),($2,$3,$4,$5)`, dotted, otherDotted, objectID, w.r.a, projectID)
	require.NoError(t, err)
	installExternalRegistrationReceiptProbe(t, w.r)
	var before json.RawMessage
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT to_jsonb(m) FROM kaname.resource_mirror m
 WHERE object_type=$1 AND object_id=$2`, dotted, objectID).Scan(&before))
	var bindings int
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.object_project_binding
 WHERE object_id=$1 AND object_type=ANY($2::text[])`, objectID, []string{model, otherModel}).Scan(&bindings))
	require.Zero(t, bindings, "пустой predicate — фактическое состояние, не fixture proof")

	trace, err := kanamepg.ProbeExternalRegistrationReceipt(w.r.ctx, w.factory, dotted, objectID, otherModel,
		domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.actor)}, false)
	require.NoError(t, err)
	require.True(t, trace.RRClosed)
	// Для внешнего модельного типа native-планировщик берёт GLOBAL.
	// Точные account/project остаются в полномочиях входа из RR-снимка.
	wantOwners := []kanamerepo.AuthorityOwnerRef{
		{Kind: "account", ID: w.r.a},
		{Kind: "project", ID: projectID},
	}
	require.Equal(t, kanamerepo.AuthorityFenceGlobal, trace.Mode)
	require.Empty(t, trace.Accounts)
	require.Equal(t, wantOwners, trace.Owners)
	var prepared struct {
		Invoker   string          `json:"invoker"`
		Finalized *bool           `json:"consumer_finalized"`
		Root      []string        `json:"root"`
		States    json.RawMessage `json:"states"`
		Sources   int             `json:"sources"`
	}
	require.NoError(t, json.Unmarshal(trace.Prepared, &prepared))
	require.Equal(t, w.r.role, prepared.Invoker)
	require.NotNil(t, prepared.Finalized)
	require.False(t, *prepared.Finalized)
	require.Equal(t, []string{dotted, objectID}, prepared.Root)
	require.JSONEq(t, `[]`, string(prepared.States))
	require.Positive(t, prepared.Sources)
	var held struct {
		Invoker     string          `json:"invoker"`
		Finalized   *bool           `json:"consumer_finalized"`
		Private     bool            `json:"stash_private"`
		Keys        int             `json:"keys"`
		CrossDenied bool            `json:"cross_identity_denied"`
		Rollback    bool            `json:"rollback_receipt_denied"`
		States      json.RawMessage `json:"states"`
	}
	require.NoError(t, json.Unmarshal(trace.Held, &held))
	require.Equal(t, w.r.role, held.Invoker)
	require.NotNil(t, held.Finalized)
	require.True(t, *held.Finalized)
	require.True(t, held.Private)
	require.Equal(t, 1, held.Keys)
	require.True(t, held.CrossDenied)
	require.True(t, held.Rollback)
	require.JSONEq(t, string(prepared.States), string(held.States))

	// Полный повторный обход выполняется в новой signed-транзакции.
	// Ранее взятые в узкой пробе блокировки не могут подтвердить этот проход.
	full, err := kanamepg.ProbeExternalRegistrationReceipt(w.r.ctx, w.factory, dotted, objectID, otherModel,
		domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.actor)}, true)
	require.NoError(t, err)
	require.True(t, full.RRClosed)
	require.Equal(t, kanamerepo.AuthorityFenceGlobal, full.Mode)
	require.Empty(t, full.Accounts)
	require.Equal(t, wantOwners, full.Owners)
	var replay struct {
		Program struct {
			Maximum json.RawMessage `json:"maximum"`
			Mode    string          `json:"frozen_mode"`
			Frozen  struct {
				Epoch   string          `json:"mirror_write_epoch"`
				State   json.RawMessage `json:"mirror_state"`
				Command struct {
					Audit struct {
						ID      string `json:"id"`
						Account string `json:"tenant_account_id"`
						Event   string `json:"event_type"`
						Payload struct {
							Actor struct {
								Type string
								ID   string
							} `json:"actor"`
							Type string `json:"resource_type"`
							ID   string `json:"resource_id"`
						} `json:"event_payload"`
					} `json:"audit_row"`
					Reconcile struct {
						ID       int64  `json:"id"`
						Type     string `json:"object_type"`
						ObjectID string `json:"object_id"`
						Event    string `json:"event_type"`
					} `json:"reconcile_row"`
					Reads int `json:"completion_reads"`
				} `json:"mirror_command"`
			} `json:"frozen"`
		} `json:"program"`
		RootPhysical struct {
			Table      string `json:"table"`
			ObjectType string `json:"object_type"`
			ID         string `json:"id"`
			Xmin       string `json:"xmin"`
			CTID       string `json:"ctid"`
		} `json:"root_physical"`
		Replay struct {
			SourceIndex map[string]json.RawMessage `json:"source_index"`
		} `json:"replay"`
		OldRow struct {
			Labels       json.RawMessage `json:"labels"`
			AccessLabels json.RawMessage `json:"access_labels"`
		} `json:"old_row"`
		NewRow struct {
			Labels       json.RawMessage `json:"labels"`
			AccessLabels json.RawMessage `json:"access_labels"`
		} `json:"new_row"`
		Requirements []struct {
			Key          string `json:"key"`
			ScopeKind    string `json:"scope_kind"`
			ScopeID      string `json:"scope_id"`
			DefinitionID string `json:"definition_id"`
		} `json:"resource_requirements"`
	}
	require.NoError(t, json.Unmarshal(full.Held, &replay))
	program := replay.Program
	command := program.Frozen.Command
	require.Equal(t, "external_access_labels", program.Mode)
	require.JSONEq(t, "[]", string(program.Maximum))
	require.Equal(t, "scope:"+w.r.a, program.Frozen.Epoch)
	require.JSONEq(t, `{"root_applied":false,"root_after":null,"audit_consumed":false,"reconcile_consumed":false}`, string(program.Frozen.State))
	require.Equal(t, 3, command.Reads)
	require.NotEmpty(t, command.Audit.ID)
	require.Equal(t, w.r.a, command.Audit.Account)
	require.Equal(t, "iam.resource_metadata.access_labels_updated", command.Audit.Event)
	require.Equal(t, "user", command.Audit.Payload.Actor.Type)
	require.Equal(t, w.actor, command.Audit.Payload.Actor.ID)
	require.Equal(t, dotted, command.Audit.Payload.Type)
	require.Equal(t, objectID, command.Audit.Payload.ID)
	require.Positive(t, command.Reconcile.ID)
	require.Equal(t, "mirror.upsert", command.Reconcile.Event)
	require.Equal(t, dotted, command.Reconcile.Type)
	require.Equal(t, objectID, command.Reconcile.ObjectID)
	var outputsAbsent bool
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT NOT EXISTS(SELECT FROM ONLY kaname.audit_outbox WHERE id=$1)
     AND NOT EXISTS(SELECT FROM ONLY kaname.resource_reconcile_outbox WHERE id=$2)`, command.Audit.ID, command.Reconcile.ID).Scan(&outputsAbsent))
	require.True(t, outputsAbsent, "откат резерва сохраняет исходные очереди")
	require.Equal(t, "resource_mirror", replay.RootPhysical.Table)
	require.Equal(t, dotted, replay.RootPhysical.ObjectType)
	require.Equal(t, objectID, replay.RootPhysical.ID)
	require.NotEmpty(t, replay.RootPhysical.Xmin)
	require.NotEmpty(t, replay.RootPhysical.CTID)
	require.Len(t, replay.Replay.SourceIndex, prepared.Sources)
	require.JSONEq(t, `{}`, string(replay.OldRow.AccessLabels))
	require.JSONEq(t, `{"team":"after"}`, string(replay.NewRow.AccessLabels))
	require.JSONEq(t, string(replay.OldRow.Labels), string(replay.NewRow.Labels))
	require.Len(t, replay.Requirements, 1)
	require.Equal(t, "team", replay.Requirements[0].Key)
	require.Equal(t, "project", replay.Requirements[0].ScopeKind)
	require.Equal(t, projectID, replay.Requirements[0].ScopeID)
	require.Equal(t, definitionID, replay.Requirements[0].DefinitionID)

	// Та же правка в новой транзакции должна отказать после отзыва значения.
	_, err = w.r.admin.Exec(w.r.ctx, `DELETE FROM kaname.authority_access_label_value
 WHERE definition_id=$1::uuid AND label_value='after'`, definitionID)
	require.NoError(t, err)
	_, err = kanamepg.ProbeExternalRegistrationReceipt(w.r.ctx, w.factory, dotted, objectID, otherModel,
		domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.actor)}, true)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "42501", pgErr.Code)
	require.Equal(t, "resource access label value or generation is not allowed", pgErr.Message)
	var after json.RawMessage
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT to_jsonb(m) FROM kaname.resource_mirror m
 WHERE object_type=$1 AND object_id=$2`, dotted, objectID).Scan(&after))
	require.JSONEq(t, string(before), string(after), "receipt-проба не вызывает external writer")
}

func installExternalRegistrationReceiptProbe(t *testing.T, r protocolRig) {
	t.Helper()
	private := []string{
		"kaname._authority_metadata_access_label_prepare_lockset_v1(text,text,text,jsonb,jsonb,jsonb,text[],integer,integer,integer)",
		"kaname._authority_metadata_access_label_stash_v1(jsonb)",
		"kaname._authority_metadata_access_label_stashed_v1()",
		"kaname._authority_metadata_registration_binding_holds_v1(integer)",
		"kaname._authority_metadata_registration_binding_check_v1(text,text)",
		"kaname._authority_metadata_access_label_held_source_v1(integer,text,text,integer,integer)",
		"kaname._authority_metadata_access_label_hold_and_replay_v1(jsonb,boolean,integer,integer,integer)",
		"kaname._authority_metadata_access_label_retention_prepare_v1(jsonb,boolean,integer,integer,integer)",
		"kaname._authority_metadata_access_label_retention_compile_v1(jsonb,integer)",
		"kaname._authority_metadata_mirror_epoch_hold_v1()",
		"kaname._authority_metadata_mirror_write_v1(text,text)",
		"kaname.authority_metadata_mirror_write_v1(text,text)",
		"kaname._authority_metadata_mirror_reserve_v1(jsonb,text,text,text,integer,integer,integer)",
	}
	for _, signature := range private {
		var permitted bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,$1,'EXECUTE')`, signature).Scan(&permitted))
		require.False(t, permitted, signature)
	}
	_, err := r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_external_registration_prepare(
 p_dotted text,p_id text,p_xmin text,p_old jsonb,p_policy jsonb,p_writes text[],
 p_rows integer,p_reads integer,p_work integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $prepare$
DECLARE prepared jsonb;proof jsonb;model text;source_key text;capture jsonb;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof->>'consumer_finalized' IS DISTINCT FROM 'false'
  OR (proof->>'invoker_oid')::oid IS DISTINCT FROM session_user::regrole::oid THEN
  RAISE EXCEPTION 'fixture needs original pending full runtime' USING ERRCODE='42501';END IF;
 prepared:=kaname._authority_metadata_access_label_prepare_lockset_v1(
  p_dotted,p_id,p_xmin,p_old,'{"team":"after"}',p_policy,p_writes,p_rows-1,p_reads-1,p_work-1);
 -- Полный пакет построен установленным owner helper; фикстура его не меняет.
 PERFORM kaname._authority_metadata_access_label_stash_v1(prepared);
 model:=prepared#>>'{root,census,root_scope_states,catalog,2,object_type}';
 source_key:=jsonb_build_array(5,model,p_id,'')::text;
 capture:=prepared#>ARRAY['discovery','source_index',source_key];
 IF jsonb_typeof(capture->'states') IS DISTINCT FROM 'array'
  OR prepared#>'{root,root_coordinate}' IS DISTINCT FROM jsonb_build_array(p_dotted,p_id)
  OR prepared#>'{root,census,binding_ids}' IS DISTINCT FROM '[]'::jsonb
  OR EXISTS(SELECT 1 FROM pg_temp.kaname_authority_consumer WHERE finalized) THEN
  RAISE EXCEPTION 'fixture external preparation incomplete' USING ERRCODE='42501';END IF;
 RETURN jsonb_build_object('invoker',session_user,'consumer_finalized',false,
  'root',prepared#>'{root,root_coordinate}','states',capture->'states',
  'sources',(SELECT count(*) FROM jsonb_object_keys(prepared#>'{discovery,source_index}')),
  'rows',1+(prepared->>'rows')::integer,'reads',1+(prepared->>'reads')::integer,
  'work',1+(prepared->>'work')::integer);
END;
$prepare$;

CREATE FUNCTION kaname.test_external_registration_receipt(
 p_other_model text,p_rows integer,p_reads integer,p_work integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $receipt$
DECLARE prepared jsonb;proof jsonb;model text;identifier text;key text;expected jsonb;capture jsonb;
 epoch record;locked_scope text;storage oid;private_storage boolean;
 cross_denied boolean:=false;rollback_denied boolean:=false;keys integer;
 used_rows integer:=0;used_reads integer:=4;used_work integer:=1;
BEGIN
 prepared:=kaname._authority_metadata_access_label_stashed_v1();
 proof:=kaname.authority_protocol_attestation();
 IF proof->>'consumer_finalized' IS DISTINCT FROM 'true'
  OR (proof->>'invoker_oid')::oid IS DISTINCT FROM session_user::regrole::oid THEN
  RAISE EXCEPTION 'fixture needs original protected full runtime' USING ERRCODE='42501';END IF;
 model:=prepared#>>'{root,census,root_scope_states,catalog,2,object_type}';
 identifier:=prepared#>>'{root,root_coordinate,1}';
 key:=jsonb_build_array(5,model,identifier,'')::text;
 expected:=prepared#>ARRAY['discovery','source_index',key,'states'];
 IF p_rows<4 OR p_reads<48 OR p_work<16 OR jsonb_typeof(expected) IS DISTINCT FROM 'array'
  OR p_other_model IS NOT DISTINCT FROM model OR NOT EXISTS(
   SELECT 1 FROM kaname.resource_mirror m JOIN kaname.catalog_resource c ON c.dotted=m.object_type
   WHERE c.live AND c.object_type=p_other_model AND m.object_id=identifier) THEN
  RAISE EXCEPTION 'fixture receipt inputs incomplete' USING ERRCODE='42501';END IF;
 -- До RB acquisition подтверждаем реальные строки эпох закрытого owner plan.
 -- Узкая проба отделяет receipt от полного повторного обхода.
 FOR epoch IN SELECT e.key,e.value FROM jsonb_each_text(prepared#>'{plan,binding_epochs}') e ORDER BY e.key COLLATE "C" LOOP
  IF used_rows>=p_rows OR used_reads>=p_reads THEN
   RAISE EXCEPTION 'fixture binding epoch budget exceeded' USING ERRCODE='54000';END IF;
  locked_scope:=NULL;
  IF epoch.value='write' THEN
   SELECT e.scope INTO locked_scope FROM ONLY kaname.authority_binding_epoch e WHERE e.scope=epoch.key FOR UPDATE;
  ELSIF epoch.value='share' THEN
   SELECT e.scope INTO locked_scope FROM ONLY kaname.authority_binding_epoch e WHERE e.scope=epoch.key FOR SHARE;
  ELSE RAISE EXCEPTION 'fixture binding epoch mode invalid' USING ERRCODE='42501';END IF;
  IF locked_scope IS NULL THEN RAISE EXCEPTION 'fixture binding epoch missing' USING ERRCODE='P1034';END IF;
  used_rows:=used_rows+1;used_reads:=used_reads+1;used_work:=used_work+1;
 END LOOP;
 BEGIN
  keys:=kaname._authority_metadata_registration_binding_holds_v1(least(p_work-used_work,4096));
  used_work:=used_work+keys;used_rows:=used_rows+keys;used_reads:=used_reads+16+keys;
  PERFORM kaname._authority_metadata_registration_binding_check_v1(model,identifier);
  capture:=kaname._authority_metadata_access_label_held_source_v1(5,model,identifier,p_rows-used_rows,p_reads-used_reads);
  used_rows:=used_rows+(capture->>'rows')::integer;used_reads:=used_reads+(capture->>'reads')::integer;
  IF capture->'states' IS DISTINCT FROM expected THEN
   RAISE EXCEPTION 'fixture first held binding differs' USING ERRCODE='40001';END IF;
  BEGIN
   PERFORM kaname._authority_metadata_registration_binding_check_v1(p_other_model,identifier);
  EXCEPTION WHEN insufficient_privilege THEN
   IF SQLERRM<>'metadata registration binding receipt absent for coordinate' THEN RAISE;END IF;
   cross_denied:=true;
  END;
  IF NOT cross_denied THEN RAISE EXCEPTION 'fixture cross identity was admitted';END IF;
  -- Откат реальных locks и receipt одним subtransaction; переменные PL/pgSQL
  -- сохраняют наблюдения и стоимость, но private temp row откатывается.
  RAISE EXCEPTION 'fixture rollback acquisition' USING ERRCODE='P1043';
 EXCEPTION WHEN SQLSTATE 'P1043' THEN NULL;
 END;
 BEGIN
  PERFORM kaname._authority_metadata_registration_binding_check_v1(model,identifier);
 EXCEPTION WHEN insufficient_privilege THEN
  IF SQLERRM<>'metadata registration binding receipt absent for coordinate' THEN RAISE;END IF;
  rollback_denied:=true;
 END;
 IF NOT rollback_denied OR (kaname._authority_metadata_access_label_stashed_v1()) ? 'registration_binding_holds' THEN
  RAISE EXCEPTION 'fixture receipt survived acquisition rollback';END IF;
 keys:=kaname._authority_metadata_registration_binding_holds_v1(least(p_work-used_work,4096));
 used_work:=used_work+keys;used_rows:=used_rows+keys;used_reads:=used_reads+16+keys;
 PERFORM kaname._authority_metadata_registration_binding_check_v1(model,identifier);
 capture:=kaname._authority_metadata_access_label_held_source_v1(5,model,identifier,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+(capture->>'rows')::integer;used_reads:=used_reads+(capture->>'reads')::integer;
 IF capture->'states' IS DISTINCT FROM expected OR used_rows>p_rows OR used_reads>p_reads OR used_work>p_work THEN
  RAISE EXCEPTION 'fixture final receipt or budget differs' USING ERRCODE='42501';END IF;
 storage:='pg_temp.kaname_authority_metadata_discovery'::regclass;
 SELECT c.relowner=current_user::regrole::oid AND NOT has_table_privilege(session_user,storage,'SELECT')
  AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee<>c.relowner)
 INTO STRICT private_storage FROM pg_class c WHERE c.oid=storage;
 RETURN jsonb_build_object('invoker',session_user,'consumer_finalized',true,'stash_private',private_storage,
  'keys',keys,'states',capture->'states','cross_identity_denied',cross_denied,'rollback_receipt_denied',rollback_denied,
  'rows',used_rows,'reads',used_reads,'work',used_work);
END;
$receipt$;

CREATE FUNCTION kaname.test_external_registration_full_hold(p_rows integer,p_reads integer,p_work integer,p_audit text,p_actor_type text,p_actor_id text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $full$
DECLARE envelope jsonb; prepared jsonb; compiled jsonb; reserved jsonb; program jsonb;
 used_rows integer; used_reads integer; used_work integer;
BEGIN
 envelope:=kaname._authority_metadata_access_label_retention_prepare_v1(
  '{"access_labels":{"team":"after"}}',false,p_rows,p_reads,p_work);
 IF envelope->'bindings' IS DISTINCT FROM '{}'::jsonb OR envelope->'coordinates' IS DISTINCT FROM '{}'::jsonb THEN
  RAISE EXCEPTION 'fixture expects a confirmed empty carrier set' USING ERRCODE='42501';END IF;
 prepared:=kaname._authority_metadata_access_label_stashed_v1();
 compiled:=kaname._authority_metadata_access_label_retention_compile_v1('{}'::jsonb,p_work-(envelope->>'work')::integer-1);
 used_rows:=1+(envelope->>'rows')::integer+(compiled->>'rows')::integer;
 used_reads:=1+(envelope->>'reads')::integer+(compiled->>'reads')::integer;
 used_work:=1+(envelope->>'work')::integer+(compiled->>'work')::integer;
 IF used_rows>p_rows OR used_reads>p_reads OR used_work>p_work THEN
  RAISE EXCEPTION 'fixture retention budget exceeded' USING ERRCODE='54000';END IF;
 SELECT jsonb_build_object('rows',r.used_rows,'reads',r.used_reads,'work',r.used_work) INTO reserved
 FROM kaname.authority_metadata_access_label_preflight_v2('{}'::jsonb,p_audit,p_actor_type,p_actor_id,
  p_rows-used_rows,p_reads-used_reads,p_work-used_work) r;
 program:=kaname._authority_sequence_store_v3();
 used_rows:=used_rows+(reserved->>'rows')::integer;
 used_reads:=used_reads+(reserved->>'reads')::integer;
 used_work:=used_work+(reserved->>'work')::integer;
 RETURN compiled||jsonb_build_object('program',program,
  'replay',jsonb_build_object('source_index',prepared#>'{retention,source_index}'),
  'rows',used_rows,'reads',used_reads,'work',used_work);
END;
$full$;

CREATE FUNCTION kaname.test_external_metadata_write(p_dotted text,p_id text)
RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fixture$
 SELECT kaname.authority_metadata_mirror_write_v1(p_dotted,p_id)
$fixture$;
DO $seal$
DECLARE signature text;recipient record;
BEGIN
 FOREACH signature IN ARRAY ARRAY[
 'kaname.test_external_registration_prepare(text,text,text,jsonb,jsonb,text[],integer,integer,integer)',
 'kaname.test_external_registration_receipt(text,integer,integer,integer)',
 'kaname.test_external_metadata_write(text,text)',
 'kaname.test_external_registration_full_hold(integer,integer,integer,text,text,text)'] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_proc p
   CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   JOIN pg_roles r ON r.oid=a.grantee WHERE p.oid=signature::regprocedure AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',signature,recipient.rolname);
  END LOOP;
 END LOOP;
END;
$seal$;
GRANT EXECUTE ON FUNCTION
 kaname.test_external_registration_prepare(text,text,text,jsonb,jsonb,text[],integer,integer,integer),
 kaname.test_external_registration_receipt(text,integer,integer,integer),
 kaname.test_external_metadata_write(text,text),
 kaname.test_external_registration_full_hold(integer,integer,integer,text,text,text) TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	// Проверка ACL полного обхода работает на явном узком праве фикстуры.
	_, err = r.admin.Exec(r.ctx, `GRANT UPDATE (access_labels) ON kaname.resource_mirror TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	for _, signature := range private {
		var permitted bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,$1,'EXECUTE')`, signature).Scan(&permitted))
		require.False(t, permitted, signature)
	}
}
