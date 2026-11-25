// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Only these two test wrappers receive a runtime grant. Every discovery/hold
// body must be installed by migrations, owned by the protocol owner and private.
func installMetadataOwnerHeldChainProbe(t *testing.T, r protocolRig) {
	t.Helper()
	signatures := []string{
		"kaname._authority_metadata_access_label_source_locks_v1(jsonb,jsonb,jsonb,integer,boolean)",
		"kaname._authority_metadata_access_label_prepare_lockset_v1(text,text,text,jsonb,jsonb,jsonb,text[],integer,integer,integer)",
		"kaname._authority_metadata_access_label_stash_v1(jsonb)",
		"kaname._authority_metadata_access_label_stashed_v1()",
		"kaname._authority_metadata_access_label_held_source_v1(integer,text,text,integer,integer)",
		"kaname._authority_metadata_access_label_held_frontier_v1(text,text,integer,integer)",
		"kaname._authority_metadata_access_label_held_replay_v1(jsonb,jsonb,jsonb,integer,integer,integer)",
		"kaname._authority_metadata_access_label_hold_and_replay_v1(jsonb,boolean,integer,integer,integer)",
	}
	for _, signature := range signatures {
		var installed, owned, permitted bool
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT to_regprocedure($1) IS NOT NULL,
 coalesce((SELECT p.proowner=c.relowner FROM pg_catalog.pg_proc p CROSS JOIN pg_catalog.pg_class c
 WHERE p.oid=to_regprocedure($1) AND c.oid='kaname.authority_writer_protocol'::regclass),false)`, signature).Scan(&installed, &owned))
		require.True(t, installed, "required installed helper absent: %s", signature)
		require.True(t, owned, "wrong owner: %s", signature)
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,$1,'EXECUTE')`, signature).Scan(&permitted))
		require.False(t, permitted, "production helper must remain private: %s", signature)
	}
	_, err := r.runtime.Exec(r.ctx, `SELECT kaname._authority_metadata_access_label_stashed_v1()`)
	var denied *pgconn.PgError
	require.ErrorAs(t, err, &denied)
	require.Equal(t, "42501", denied.Code)
	require.Equal(t, "permission denied for function _authority_metadata_access_label_stashed_v1", denied.Message)

	_, err = r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_metadata_owner_prepare(
 p_kind text,p_id text,p_old_xmin text,p_old jsonb,p_new_access jsonb,
 p_policy jsonb,p_writes text[],p_rows integer,p_reads integer,p_work integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $prepare_probe$
DECLARE prepared jsonb;packet jsonb;discovery jsonb;proof jsonb;accounts jsonb;outputs jsonb;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR (proof->>'invoker_oid')::oid IS DISTINCT FROM session_user::regrole::oid
  OR proof->>'consumer_finalized' IS DISTINCT FROM 'false' THEN
  RAISE EXCEPTION 'fixture prepare needs original prefinal runtime admission' USING ERRCODE='42501';END IF;
 prepared:=kaname._authority_metadata_access_label_prepare_lockset_v1(
  p_kind,p_id,p_old_xmin,p_old,p_new_access,p_policy,p_writes,p_rows-1,p_reads-1,p_work-1);
 PERFORM kaname._authority_metadata_access_label_stash_v1(prepared);
 packet:=prepared->'root';discovery:=prepared->'discovery';
 SELECT coalesce(jsonb_agg(a.id ORDER BY a.id COLLATE "C"),'[]'::jsonb) INTO accounts
 FROM (SELECT DISTINCT e.value#>>'{source,id}' AS id FROM jsonb_each(discovery->'source_index') e
  WHERE e.value#>>'{source,kind}'='23') a;
 SELECT coalesce(jsonb_agg(jsonb_build_object('Type',e.value->>'object_type','ID',e.value->>'object_id')
  ORDER BY e.key COLLATE "C"),'[]'::jsonb) INTO outputs FROM jsonb_each(discovery->'outputs') e;
 IF EXISTS(SELECT 1 FROM pg_temp.kaname_authority_consumer c WHERE c.finalized) THEN
  RAISE EXCEPTION 'fixture prepare unexpectedly finalized consumer' USING ERRCODE='42501';END IF;
 RETURN jsonb_build_object('status','observed','invoker',session_user,
  'consumer_finalized',false,'fence_checked',true,'accounts',accounts,
  'historical_bindings',packet#>'{census,binding_ids}','outputs',outputs,
  'source_guards',discovery->'carrier_source_guards',
  'rows',1+(prepared->>'rows')::integer,'reads',1+(prepared->>'reads')::integer,
  'work',1+(prepared->>'work')::integer);
END;
$prepare_probe$;
CREATE FUNCTION kaname.test_metadata_owner_replay(p_new_access jsonb,p_rows integer,p_reads integer,p_work integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $replay_probe$
DECLARE result jsonb;replayed jsonb;prepared jsonb;proof jsonb;header jsonb;
 storage oid;private_storage boolean;kinds jsonb;empty_predicates integer;
 bundle record;projection jsonb;ancestry jsonb;ancestor_capture jsonb;ancestor_projection jsonb;
 ancestor_cost integer:=0;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 SELECT q.proof,q.header INTO STRICT proof,header FROM kaname._authority_sequence_probe_v3() q;
 IF proof IS NULL OR (proof->>'invoker_oid')::oid IS DISTINCT FROM session_user::regrole::oid
  OR proof->>'consumer_finalized' IS DISTINCT FROM 'true' THEN
  RAISE EXCEPTION 'fixture replay needs original protected full admission' USING ERRCODE='42501';END IF;
 -- Full production-private holder handles exact root, canonical epoch rows,
 -- optional absent-cluster relation prewait and held replay. No waits are
 -- reimplemented by this test wrapper, and no final scalar command is selected.
 result:=kaname._authority_metadata_access_label_hold_and_replay_v1(
  jsonb_build_object('access_labels',p_new_access),false,p_rows-1,p_reads-1,p_work-1);
 replayed:=result->'replay';
 prepared:=kaname._authority_metadata_access_label_stashed_v1();
 IF jsonb_typeof(replayed) IS DISTINCT FROM 'object'
  OR jsonb_typeof(replayed->'source_index') IS DISTINCT FROM 'object'
  OR replayed->'census' IS DISTINCT FROM prepared#>'{root,census}'
  OR jsonb_typeof(result->'root_physical') IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'fixture holder returned incomplete replay' USING ERRCODE='42501';END IF;
 storage:='pg_temp.kaname_authority_metadata_discovery'::regclass;
 SELECT c.relowner=current_user::regrole::oid
  AND NOT has_table_privilege(session_user,storage,'SELECT')
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))) a
   WHERE a.grantee<>c.relowner)
 INTO STRICT private_storage FROM pg_catalog.pg_class c WHERE c.oid=storage;
 SELECT coalesce(jsonb_agg(k.kind ORDER BY k.kind),'[]'::jsonb) INTO kinds
 FROM (SELECT DISTINCT (e.value#>>'{source,kind}')::integer AS kind FROM jsonb_each(replayed->'source_index') e) k;
 SELECT count(*) INTO empty_predicates FROM jsonb_each(replayed->'source_index') e WHERE e.value->'states'='[]'::jsonb;

 -- В историческом сценарии проверяем проекцию предка штатным
 -- компилятором на повторно прочитанном наборе источников.
 IF prepared#>'{root,census,binding_ids}'<>'[]'::jsonb THEN
  ancestor_cost:=1;
  IF (result->>'rows')::integer+2>p_rows OR (result->>'reads')::integer+2>p_reads
   OR (result->>'work')::integer+2>p_work THEN
   RAISE EXCEPTION 'fixture ancestor catalog budget exhausted' USING ERRCODE='54000';END IF;
  SELECT * INTO STRICT bundle FROM kaname.authority_protocol_read_bundle();
  IF to_jsonb(bundle.catalog_id) IS DISTINCT FROM prepared->'catalog_id' THEN
   RAISE EXCEPTION 'fixture ancestor catalog changed' USING ERRCODE='P1034';END IF;
  ancestor_capture:=kaname._authority_resource_require_capture_v2(
   replayed->'source_index',2,'vpc.network','rr-retained-projection-only-parent')->'states';
  projection:=kaname._authority_resource_projection_v2(
   replayed->'source_index','vpc.network','rr-retained-foreign-output');
  ancestry:=kaname._authority_resource_ancestor_graph_v2(
   replayed->'source_index',convert_from(bundle.catalog_json,'UTF8')::jsonb,projection);
  SELECT a.value->'projection' INTO STRICT ancestor_projection
  FROM jsonb_array_elements(ancestry->'ancestors') a
  WHERE a.value->>'object_type'='vpc.network'
   AND a.value->>'object_id'='rr-retained-projection-only-parent';
 END IF;
 SELECT q.proof,q.header INTO STRICT proof,header FROM kaname._authority_sequence_probe_v3() q;
 RETURN jsonb_build_object('status','replayed','invoker',session_user,
  'consumer_finalized',proof->'consumer_finalized','stash_private',private_storage,
  'scalar_unselected',header IS NULL OR header->>'selected_count' IS NULL,'census_matched',true,
  'sources',(SELECT count(*) FROM jsonb_object_keys(replayed->'source_index')),
  'frontiers',(SELECT count(*) FROM jsonb_object_keys(replayed->'frontier_witnesses')),
  'held_rows',jsonb_array_length(replayed->'held_rows'),'empty_predicates',empty_predicates,'kinds',kinds,
  'ancestor_capture',ancestor_capture,'ancestor_projection',ancestor_projection,
  'rows',1+ancestor_cost+(result->>'rows')::integer,
  'reads',1+ancestor_cost+(result->>'reads')::integer,'work',1+ancestor_cost+(result->>'work')::integer);
END;
$replay_probe$;
DO $private$
DECLARE signature text;recipient record;
BEGIN
 FOREACH signature IN ARRAY ARRAY[
  'test_metadata_owner_prepare(text,text,text,jsonb,jsonb,jsonb,text[],integer,integer,integer)',
  'test_metadata_owner_replay(jsonb,integer,integer,integer)'
 ] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',signature);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
   JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE p.oid=to_regprocedure('kaname.'||signature) AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM %I',signature,recipient.rolname);
  END LOOP;
 END LOOP;
END;
$private$;
GRANT EXECUTE ON FUNCTION kaname.test_metadata_owner_prepare(text,text,text,jsonb,jsonb,jsonb,text[],integer,integer,integer),
 kaname.test_metadata_owner_replay(jsonb,integer,integer,integer) TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	for _, signature := range signatures {
		var permitted bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,$1,'EXECUTE')`, signature).Scan(&permitted))
		require.False(t, permitted, "test grants must not expose production helper: %s", signature)
	}
}
