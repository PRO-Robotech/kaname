-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Private retained-source replay after complete owner guards. The early discovery
-- phase is unchanged. No runtime grant, compiler entry, activation or final clock.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $dependencies$
DECLARE dependency record;
BEGIN
 FOR dependency IN SELECT * FROM (VALUES
  ('_authority_metadata_access_label_early_source_v1(integer,text,text,integer,integer)','0b20a22f6bdcc1e18e9de51fda69bfac31a86807e3f265ef05bf74c42d915f78'),
  ('_authority_metadata_access_label_early_frontier_v1(text,text,integer,integer)','9b5b80bf056943d737a373f112351d0ca4583ac3a27f95bbbf22672acb5f1fea'),
  ('_authority_metadata_access_label_carrier_census_v1(text,jsonb,jsonb,integer,integer,integer)','dbd3a92094d37acfc7c322a661ca1e3e44543eb44ba8f7f97329a2a81a40fe13')
 ) expected(signature,body_sha) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('kaname.'||dependency.signature)
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=dependency.body_sha
   AND p.proowner=(SELECT relowner FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass)) THEN
   RAISE EXCEPTION 'metadata replay discovery baseline differs: %',dependency.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF to_regprocedure('kaname._authority_sequence_probe_v3()') IS NULL
  OR to_regprocedure('kaname._authority_resource_preheld_key_v2(integer,text,boolean)') IS NULL
  OR kaname._authority_metadata_access_label_frontier_storage_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'metadata replay phase or guard dependency absent' USING ERRCODE='55000';END IF;
END;
$dependencies$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_access_label_held_source_v1(
 p_kind integer,p_type text,p_id text,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $capture$
DECLARE proof jsonb; table_name text; predicate text; required_type text;
 item record; states jsonb:='[]'; decoded jsonb:='[]'; held jsonb:='[]'; used integer:=0;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
 OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'full'
 OR NOT coalesce((proof->>'writer_contract'='2' AND proof->>'purpose'='decision')
      OR (proof->>'writer_contract'='1' AND proof->>'purpose'='participant'),false)
 OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
 OR NOT EXISTS(SELECT 1 FROM pg_temp.kaname_authority_consumer WHERE finalized) THEN
  RAISE EXCEPTION 'metadata physical capture requires finalized full consumer' USING ERRCODE='42501';END IF;
 IF coalesce(p_type,'')='' OR coalesce(p_id,'')=''
 OR octet_length(p_type)>16384 OR octet_length(p_id)>16384
 OR p_type ~ '[:#*[:space:][:cntrl:]]' OR p_id ~ '[:#*[:space:][:cntrl:]]'
 OR p_kind IS NULL OR p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000
 OR p_reads IS NULL OR p_reads NOT BETWEEN 1 AND 4096 THEN
  RAISE EXCEPTION 'metadata physical capture input or budget invalid' USING ERRCODE='54000';END IF;
 CASE p_kind
 WHEN 1 THEN table_name:='projects';predicate:='r.id=$2';required_type:='project';
 WHEN 2 THEN table_name:='resource_mirror';predicate:='r.object_type=$1 AND r.object_id=$2';
 WHEN 3 THEN table_name:='resource_parent_edge';predicate:='r.object_type=$1 AND r.object_id=$2';
 WHEN 4 THEN table_name:='resource_registration_scope';predicate:='r.object_type=$1 AND r.object_id=$2';
 WHEN 21 THEN table_name:='access_binding_target_members';predicate:='r.object_type=$1 AND r.object_id=$2';
 WHEN 22 THEN table_name:='access_binding_emitted_tuples';predicate:='r.member_object_type=$1 AND r.member_object_id=$2';
 WHEN 23 THEN table_name:='accounts';predicate:='r.id=$2';required_type:='account';
 WHEN 26 THEN table_name:='producer_source_receipt';predicate:='r.object_type=$1 AND r.object_id=$2';
 WHEN 27 THEN table_name:='public_read_publication';predicate:='r.object_type=$1 AND r.object_id=$2';
 WHEN 28 THEN table_name:='resource_registration_retirement';predicate:='r.object_type=$1 AND r.object_id=$2';
 WHEN 6 THEN table_name:='relation_fact';predicate:='r.object_type=$1 AND r.object_id=$2';
 WHEN 8 THEN table_name:='access_bindings';predicate:='r.id=$2';required_type:='binding';
 WHEN 9 THEN table_name:='access_binding_subjects';predicate:='r.binding_id=$2';required_type:='binding';
 WHEN 10 THEN table_name:='access_binding_target_members';predicate:='r.binding_id=$2';required_type:='binding';
 WHEN 11 THEN table_name:='access_binding_emitted_tuples';predicate:='r.binding_id=$2';required_type:='binding';
 WHEN 12 THEN table_name:='roles';predicate:='r.id=$2';required_type:='role';
 WHEN 13 THEN table_name:='role_rule_selectors';predicate:='r.role_id=$2';required_type:='role';
 WHEN 14 THEN table_name:='role_verb';predicate:='r.role_id=$2';required_type:='role';
 WHEN 15 THEN table_name:='role_rule_ref';predicate:='r.role_id=$2';required_type:='role';
 WHEN 25 THEN table_name:='resource_registration_pointer';predicate:='r.object_type=$1 AND r.object_id=$2';
 WHEN 35 THEN table_name:='access_binding_emitted_tuples';predicate:='r.object=$1::text || '':'' || $2::text';
 WHEN 36 THEN table_name:='cluster_admin_grants';predicate:='r.cluster_id=$2';required_type:='cluster';
 WHEN 37 THEN table_name:='role_selector_verbs_pending';predicate:='r.role_id=$2';required_type:='role';
 WHEN 30 THEN
  CASE p_type
   WHEN 'iam.account' THEN table_name:='accounts';
   WHEN 'iam.project' THEN table_name:='projects';
   WHEN 'iam.role' THEN table_name:='roles';
   WHEN 'iam.group' THEN table_name:='groups';
   WHEN 'iam.serviceAccount' THEN table_name:='service_accounts';
   WHEN 'iam.user' THEN table_name:='users';
   WHEN 'iam.accessBinding' THEN table_name:='access_bindings';
   ELSE RAISE EXCEPTION 'unsupported metadata IAM source type' USING ERRCODE='42501';
  END CASE;
  predicate:='r.id=$2';required_type:=p_type;
 WHEN 31 THEN table_name:='memberships';predicate:='r.user_id=$2';required_type:='iam.user';
 ELSE RAISE EXCEPTION 'unsupported metadata source predicate' USING ERRCODE='42501';
 END CASE;
 IF required_type IS NOT NULL AND required_type<>p_type THEN
  RAISE EXCEPTION 'metadata source coordinate differs' USING ERRCODE='42501';END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=to_regclass('kaname.'||table_name)
  AND c.relkind='r' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
  AND NOT c.relispartition AND NOT c.relhassubclass) THEN
  RAISE EXCEPTION 'early source shape requires ordinary unfiltered table' USING ERRCODE='42501';END IF;
 IF NOT coalesce(has_table_privilege((proof->>'invoker_oid')::oid,to_regclass(format('kaname.%I',table_name)),'SELECT'),false) THEN
  RAISE EXCEPTION 'metadata physical source SELECT required' USING ERRCODE='42501';END IF;
 FOR item IN EXECUTE format('SELECT r.tableoid relation_oid,r.ctid::text row_tid,r.xmin::text row_xmin,to_jsonb(r) row_data,
  jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r)) row_state
  FROM ONLY kaname.%I r WHERE $1::text IS NOT NULL AND (%s) ORDER BY r.ctid LIMIT $3 FOR SHARE OF r',table_name,predicate)
 USING p_type,p_id,p_rows+1 LOOP
  used:=used+1;
  IF used>p_rows THEN RAISE EXCEPTION 'metadata physical source sentinel exceeded' USING ERRCODE='54000';END IF;
  states:=states||jsonb_build_array(item.row_state::text);
  decoded:=decoded||jsonb_build_array(item.row_state);
  held:=held||jsonb_build_array(jsonb_build_object('relation',item.relation_oid,'tid',item.row_tid,
   'xmin',item.row_xmin,'data',item.row_data,'write',false));
 END LOOP;
 SELECT coalesce(jsonb_agg(v ORDER BY v#>>'{}' COLLATE "C"),'[]'::jsonb) INTO states FROM jsonb_array_elements(states) v;
 SELECT coalesce(jsonb_agg(v ORDER BY v::text COLLATE "C"),'[]'::jsonb) INTO decoded FROM jsonb_array_elements(decoded) v;
 RETURN jsonb_build_object('key',jsonb_build_array(p_kind,p_type,p_id,'')::text,
  'source',jsonb_build_object('kind',p_kind,'type',p_type,'id',p_id,'projection','','states',states),
  'states',decoded,'held_rows',held,'rows',used,'reads',1);
END;
$capture$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_access_label_held_frontier_v1(
 p_model text,p_id text,p_rows integer,p_reads integer
) RETURNS TABLE(frontier jsonb,source_index jsonb,cluster_states jsonb,
 logical_rows integer,logical_reads integer,held_rows jsonb)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $frontier$
DECLARE capture jsonb;row_value jsonb;state jsonb;triples jsonb:='[]';parents jsonb;
 table_type text;cluster_row record;proof jsonb;row_count integer;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF coalesce(p_model,'')='' OR p_model LIKE '%.%' OR coalesce(p_id,'')=''
 OR p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000
 OR p_reads IS NULL OR p_reads NOT BETWEEN 1 AND 4096 THEN
  RAISE EXCEPTION 'metadata physical frontier input invalid' USING ERRCODE='42501';END IF;
 IF kaname._authority_metadata_access_label_frontier_storage_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'metadata early frontier storage differs' USING ERRCODE='42501';END IF;
 source_index:='{}';held_rows:='[]';cluster_states:=NULL;logical_rows:=0;logical_reads:=0;
 -- Физические рёбра имеют приоритет над выводом из других таблиц.
 -- Сохраняем весь результат, включая отсутствие рёбер.
 capture:=kaname._authority_metadata_access_label_held_source_v1(3,p_model,p_id,least(p_rows,4),p_reads);
 source_index:=source_index||jsonb_build_object(capture->>'key',jsonb_build_object('source',capture->'source','states',capture->'states'));
 held_rows:=held_rows||(capture->'held_rows');
 logical_rows:=logical_rows+(capture->>'rows')::integer;logical_reads:=logical_reads+(capture->>'reads')::integer;
 FOR state IN SELECT value FROM jsonb_array_elements(capture->'states') LOOP
  row_value:=state->2;
  IF row_value->>'object_type' IS DISTINCT FROM p_model OR row_value->>'object_id' IS DISTINCT FROM p_id THEN
   RAISE EXCEPTION 'physical frontier edge identity differs' USING ERRCODE='42501';END IF;
  triples:=triples||jsonb_build_array(jsonb_build_object('parent_type',row_value->'parent_type',
   'parent_id',row_value->'parent_id','depth',row_value->'depth'));
 END LOOP;
 IF triples='[]'::jsonb THEN
  CASE p_model
  WHEN 'project' THEN
   -- Как и представление областей, используем связи из relation_fact.
   capture:=kaname._authority_metadata_access_label_held_source_v1(6,'project',p_id,p_rows-logical_rows,p_reads-logical_reads);
   source_index:=source_index||jsonb_build_object(capture->>'key',jsonb_build_object('source',capture->'source','states',capture->'states'));
   held_rows:=held_rows||(capture->'held_rows');
 logical_rows:=logical_rows+(capture->>'rows')::integer;logical_reads:=logical_reads+(capture->>'reads')::integer;
   FOR state IN SELECT value FROM jsonb_array_elements(capture->'states') LOOP
    row_value:=state->2;
    IF row_value->>'relation'=split_part(row_value->>'subject',':',1) AND position('#' IN row_value->>'subject')=0 THEN
     triples:=triples||jsonb_build_array(jsonb_build_object('parent_type',split_part(row_value->>'subject',':',1),
      'parent_id',substr(row_value->>'subject',position(':' IN row_value->>'subject')+1),'depth',1));
    END IF;
   END LOOP;
  WHEN 'account' THEN
   capture:=kaname._authority_metadata_access_label_held_source_v1(30,'iam.account',p_id,p_rows-logical_rows,p_reads-logical_reads);
   source_index:=source_index||jsonb_build_object(capture->>'key',jsonb_build_object('source',capture->'source','states',capture->'states'));
   held_rows:=held_rows||(capture->'held_rows');
 logical_rows:=logical_rows+(capture->>'rows')::integer;logical_reads:=logical_reads+(capture->>'reads')::integer;
   IF jsonb_array_length(capture->'states')=1 THEN
    -- Точечное чтение полно благодаря проверенному ограничению
    -- на единственную допустимую строку таблицы clusters.
    proof:=kaname.authority_protocol_attestation();
    IF EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid='kaname.clusters'::regclass
     AND (c.relrowsecurity OR c.relforcerowsecurity OR c.relispartition OR c.relhassubclass)) THEN
     RAISE EXCEPTION 'early frontier cluster shape differs' USING ERRCODE='42501';END IF;
    IF NOT coalesce(has_table_privilege((proof->>'invoker_oid')::oid,'kaname.clusters','SELECT'),false) THEN
     RAISE EXCEPTION 'metadata cluster fallback SELECT required' USING ERRCODE='42501';END IF;
    IF logical_reads>=p_reads THEN RAISE EXCEPTION 'metadata cluster frontier read budget exceeded' USING ERRCODE='54000';END IF;
    logical_reads:=logical_reads+1;cluster_states:='[]';
    FOR cluster_row IN SELECT c.tableoid relation_oid,c.ctid::text row_tid,c.xmin::text row_xmin,to_jsonb(c) row_data,
      jsonb_build_array(c.xmin::text,c.ctid::text,to_jsonb(c)) state
     FROM ONLY kaname.clusters c WHERE c.id='cluster_root' ORDER BY c.ctid LIMIT least(p_rows-logical_rows,1)+1 FOR SHARE OF c LOOP
     logical_rows:=logical_rows+1;
     IF logical_rows>p_rows THEN RAISE EXCEPTION 'metadata cluster frontier row budget exceeded' USING ERRCODE='54000';END IF;
     cluster_states:=cluster_states||jsonb_build_array(cluster_row.state);
     held_rows:=held_rows||jsonb_build_array(jsonb_build_object('relation',cluster_row.relation_oid,
      'tid',cluster_row.row_tid,'xmin',cluster_row.row_xmin,'data',cluster_row.row_data,'write',false));
     triples:=triples||jsonb_build_array(jsonb_build_object('parent_type','cluster','parent_id',cluster_row.state#>>'{2,id}','depth',1));
    END LOOP;
   END IF;
  WHEN 'iam_user' THEN
   -- Состояние членства не влияет на путь к родительской области.
   capture:=kaname._authority_metadata_access_label_held_source_v1(31,'iam.user',p_id,p_rows-logical_rows,p_reads-logical_reads);
   source_index:=source_index||jsonb_build_object(capture->>'key',jsonb_build_object('source',capture->'source','states',capture->'states'));
   held_rows:=held_rows||(capture->'held_rows');
 logical_rows:=logical_rows+(capture->>'rows')::integer;logical_reads:=logical_reads+(capture->>'reads')::integer;
   FOR state IN SELECT value FROM jsonb_array_elements(capture->'states') LOOP
    row_value:=state->2;
    IF coalesce(row_value->>'account_id','')<>'' THEN
     triples:=triples||jsonb_build_array(jsonb_build_object('parent_type','account','parent_id',row_value->>'account_id','depth',1));
    END IF;
   END LOOP;
  WHEN 'iam_group','iam_service_account','iam_role','iam_access_binding' THEN
   table_type:=CASE p_model WHEN 'iam_group' THEN 'iam.group' WHEN 'iam_service_account' THEN 'iam.serviceAccount'
    WHEN 'iam_role' THEN 'iam.role' ELSE 'iam.accessBinding' END;
   capture:=kaname._authority_metadata_access_label_held_source_v1(30,table_type,p_id,p_rows-logical_rows,p_reads-logical_reads);
   source_index:=source_index||jsonb_build_object(capture->>'key',jsonb_build_object('source',capture->'source','states',capture->'states'));
   held_rows:=held_rows||(capture->'held_rows');
 logical_rows:=logical_rows+(capture->>'rows')::integer;logical_reads:=logical_reads+(capture->>'reads')::integer;
   FOR state IN SELECT value FROM jsonb_array_elements(capture->'states') LOOP
    row_value:=state->2;
    IF p_model='iam_access_binding' THEN
     IF lower(row_value->>'resource_type') IN ('account','project','cluster') AND coalesce(row_value->>'resource_id','')<>'' THEN
      triples:=triples||jsonb_build_array(jsonb_build_object('parent_type',lower(row_value->>'resource_type'),
       'parent_id',row_value->>'resource_id','depth',1));
     END IF;
    ELSE
     IF coalesce(row_value->>'account_id','')<>'' THEN
      triples:=triples||jsonb_build_array(jsonb_build_object('parent_type','account','parent_id',row_value->>'account_id','depth',1));
     END IF;
     IF p_model='iam_role' AND coalesce(row_value->>'project_id','')<>'' THEN
      triples:=triples||jsonb_build_array(jsonb_build_object('parent_type','project','parent_id',row_value->>'project_id','depth',1));
     END IF;
    END IF;
   END LOOP;
  ELSE NULL; -- Для остальных типов дополнительных рёбер нет.
  END CASE;
 END IF;
 row_count:=jsonb_array_length(triples);
 IF row_count>4 THEN RAISE EXCEPTION 'metadata complete frontier fanout exceeded' USING ERRCODE='54000';END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(triples) t WHERE coalesce(t->>'parent_type','')=''
   OR t->>'parent_type' LIKE '%.%' OR coalesce(t->>'parent_id','')='' OR jsonb_typeof(t->'depth') IS DISTINCT FROM 'number') THEN
  RAISE EXCEPTION 'metadata physical frontier parent malformed' USING ERRCODE='42501';END IF;
 SELECT coalesce(jsonb_agg(t ORDER BY (t->>'depth')::integer,t->>'parent_type' COLLATE "C",t->>'parent_id' COLLATE "C"),'[]'::jsonb)
 INTO triples FROM jsonb_array_elements(triples) t;
 SELECT coalesce(jsonb_agg(jsonb_build_array(q.typ,q.id) ORDER BY q.typ COLLATE "C",q.id COLLATE "C"),'[]'::jsonb)
 INTO parents FROM (SELECT DISTINCT (t->>'parent_type') COLLATE "C" typ,(t->>'parent_id') COLLATE "C" id FROM jsonb_array_elements(triples) t) q;
 frontier:=jsonb_build_object('object_type',p_model,'object_id',p_id,'parents',parents,'states',triples,
  'logical_rows',row_count,'logical_reads',1);
 -- При начислении бюджета используем выходные колонки функции:
 -- они включают все чтения, в том числе пустые, и физические строки.
 RETURN NEXT;
END;
$frontier$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Owner-produced packet/closure/guard plan only. No runtime caller supplies a
-- purported held plan. The compiler acquires its complete strongest lock plan
-- before this call; this function verifies advisory witnesses without extending it.
CREATE FUNCTION kaname._authority_metadata_access_label_held_replay_v1(
 p_packet jsonb,p_closure jsonb,p_plan jsonb,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $replay$
DECLARE proof jsonb;header jsonb;entry record;guard_entry record;frontier_entry record;
 expected_entry jsonb;source jsonb;state jsonb;actual jsonb;actual_frontier record;
 expected_frontier jsonb;serialized jsonb;decoded jsonb;census jsonb;expected_census jsonb;
 held jsonb:='[]';replayed jsonb:='{}';replayed_frontiers jsonb:='{}';
 needed_guards jsonb:='{}';field_name text;guard_key text;account_id text;root_type text;root_id text;
 source_kind integer;namespace integer;used_rows integer:=0;used_reads integer:=0;work integer:=0;
 needs_global boolean:=false;empty_cluster boolean:=false;source_count integer;frontier_count integer;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 SELECT p.proof,p.header INTO STRICT proof,header FROM kaname._authority_sequence_probe_v3() p;
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
  OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'full'
  OR proof->>'consumer_finalized' IS DISTINCT FROM 'true'
  OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
  OR NOT coalesce((proof->>'writer_contract'='2' AND proof->>'purpose'='decision')
   OR (proof->>'writer_contract'='1' AND proof->>'purpose'='participant'),false)
  OR (header IS NOT NULL AND (header->>'family' IS DISTINCT FROM 'metadata'
   OR header->>'selected_count' IS NOT NULL)) THEN
  RAISE EXCEPTION 'metadata replay requires protected full admission before final scalar selection' USING ERRCODE='42501';END IF;
 IF proof->>'writer_contract'='1' AND NOT EXISTS(SELECT 1 FROM kaname.authority_writer_contract
  WHERE singleton AND required_contract=1 AND staged_contract=1) THEN
  RAISE EXCEPTION 'metadata held replay staged contract unavailable' USING ERRCODE='P1036';END IF;
 IF p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000
  OR p_reads IS NULL OR p_reads NOT BETWEEN 1 AND 4096
  OR p_work IS NULL OR p_work NOT BETWEEN 1 AND 400000
  OR jsonb_typeof(p_packet) IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_closure) IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_closure->'source_index') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_closure->'outputs') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_closure->'carrier_source_guards') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_closure#>'{frontier,frontiers}') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_closure#>'{frontier,witnesses}') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_closure#>'{frontier,source_index}') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_plan) IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_plan->'source_guards') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_plan->'policy_epochs') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_plan->'binding_epochs') IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'metadata held replay input shape invalid' USING ERRCODE='42501';END IF;
 FOREACH field_name IN ARRAY ARRAY['backend','transaction_id','invoker_oid','nonce','mode','accounts'] LOOP
  IF p_plan->field_name IS DISTINCT FROM proof->field_name OR NOT (p_plan ? field_name) THEN
   RAISE EXCEPTION 'metadata held plan belongs to another signed admission' USING ERRCODE='42501';END IF;
 END LOOP;
 expected_census:=p_packet->'census';root_type:=expected_census->>'root_type';root_id:=expected_census->>'root_id';
 IF jsonb_typeof(expected_census) IS DISTINCT FROM 'object'
  OR coalesce(root_type,'') NOT IN ('iam.account','iam.project') OR coalesce(root_id,'')=''
  OR jsonb_typeof(p_packet->'root_state') IS DISTINCT FROM 'array'
  OR jsonb_array_length(p_packet->'root_state') IS DISTINCT FROM 3
  OR expected_census->'old_root' IS DISTINCT FROM p_packet#>'{root_state,2}'
  OR expected_census->>'root_id' IS DISTINCT FROM p_packet#>>'{root_state,2,id}'
  OR expected_census->>'account_id' IS DISTINCT FROM p_packet->>'root_account'
  OR p_packet->'root_coordinate' IS DISTINCT FROM jsonb_build_array(root_type,root_id)
  OR coalesce(p_packet->>'root_account','')='' THEN
  RAISE EXCEPTION 'metadata held root packet incomplete' USING ERRCODE='42501';END IF;
 SELECT count(*) INTO source_count FROM jsonb_object_keys(p_closure->'source_index');
 SELECT count(*) INTO frontier_count FROM jsonb_object_keys(p_closure#>'{frontier,witnesses}');
 IF source_count NOT BETWEEN 1 AND 4096 OR frontier_count>4096
  OR (SELECT count(*) FROM jsonb_object_keys(p_closure->'outputs'))>4096
  OR (SELECT count(*) FROM jsonb_object_keys(p_closure->'carrier_source_guards'))>4096
  OR (SELECT count(*) FROM jsonb_object_keys(p_closure#>'{frontier,frontiers}'))<>frontier_count
  OR (SELECT count(*) FROM jsonb_object_keys(p_plan->'source_guards'))
    +(SELECT count(*) FROM jsonb_object_keys(p_plan->'policy_epochs'))
    +(SELECT count(*) FROM jsonb_object_keys(p_plan->'binding_epochs'))>4096 THEN
  RAISE EXCEPTION 'metadata held replay key budget exceeded' USING ERRCODE='54000';END IF;
 -- Validate every expected predicate before any new tuple wait. Serialized and
 -- decoded witnesses must be the same canonical sequence, including empty arrays.
 FOR entry IN SELECT e.key,e.value FROM jsonb_each(p_closure->'source_index') e ORDER BY e.key COLLATE "C" LOOP
  expected_entry:=entry.value;source:=expected_entry->'source';
  work:=work+1;
  IF work>p_work THEN RAISE EXCEPTION 'metadata replay shape work exhausted' USING ERRCODE='54000';END IF;
  IF jsonb_typeof(expected_entry) IS DISTINCT FROM 'object'
   OR expected_entry-ARRAY['source','states']<>'{}'::jsonb
   OR jsonb_typeof(source) IS DISTINCT FROM 'object'
   OR source-ARRAY['kind','type','id','projection','states']<>'{}'::jsonb
   OR jsonb_typeof(source->'kind') IS DISTINCT FROM 'number'
   OR coalesce(source->>'kind','') !~ '^[0-9]{1,2}$'
   OR jsonb_typeof(source->'type') IS DISTINCT FROM 'string'
   OR jsonb_typeof(source->'id') IS DISTINCT FROM 'string'
   OR coalesce(source->>'type','')='' OR coalesce(source->>'id','')=''
   OR octet_length(source->>'type')>16384 OR octet_length(source->>'id')>16384
   OR source->>'type' ~ '[:#*[:space:][:cntrl:]]' OR source->>'id' ~ '[:#*[:space:][:cntrl:]]'
   OR source->>'projection' IS DISTINCT FROM ''
   OR jsonb_typeof(source->'states') IS DISTINCT FROM 'array'
   OR jsonb_typeof(expected_entry->'states') IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'metadata held source witness malformed' USING ERRCODE='42501';END IF;
  source_kind:=(source->>'kind')::integer;
  IF source_kind NOT IN (1,2,3,4,6,8,9,10,11,12,13,14,15,21,22,23,25,26,27,28,30,31,35,36,37)
   OR entry.key IS DISTINCT FROM jsonb_build_array(source_kind,source->>'type',source->>'id','')::text
   OR jsonb_array_length(expected_entry->'states')>100000 THEN
   RAISE EXCEPTION 'metadata held source identity invalid' USING ERRCODE='42501';END IF;
  IF (source_kind=1 AND source->>'type'<>'project')
   OR (source_kind IN (8,9,10,11) AND source->>'type'<>'binding')
   OR (source_kind IN (12,13,14,15,37) AND source->>'type'<>'role')
   OR (source_kind=23 AND source->>'type'<>'account')
   OR (source_kind=31 AND source->>'type'<>'iam.user')
   OR (source_kind=36 AND source->>'type'<>'cluster')
   OR (source_kind=30 AND source->>'type' NOT IN ('iam.account','iam.project','iam.role','iam.group','iam.serviceAccount','iam.user','iam.accessBinding')) THEN
   RAISE EXCEPTION 'metadata held source kind/type ABI differs' USING ERRCODE='42501';END IF;
  FOR state IN SELECT v.value FROM jsonb_array_elements(expected_entry->'states') v LOOP
   work:=work+1;
   IF work>p_work THEN RAISE EXCEPTION 'metadata replay row-shape work exhausted' USING ERRCODE='54000';END IF;
   IF jsonb_typeof(state) IS DISTINCT FROM 'array' OR jsonb_array_length(state) IS DISTINCT FROM 3
    OR jsonb_typeof(state->0) IS DISTINCT FROM 'string' OR coalesce(state->>0,'')=''
    OR jsonb_typeof(state->1) IS DISTINCT FROM 'string' OR coalesce(state->>1,'')=''
    OR jsonb_typeof(state->2) IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION 'metadata held physical row malformed' USING ERRCODE='42501';END IF;
   IF source_kind IN (21,22,35) THEN
    guard_key:='binding:'||(state#>>'{2,binding_id}');
    IF guard_key IS NULL OR guard_key !~ '^binding:[^:#*[:space:][:cntrl:]]+$' THEN
     RAISE EXCEPTION 'metadata held holder identity malformed' USING ERRCODE='42501';END IF;
    needed_guards:=needed_guards||jsonb_build_object(guard_key,'share');
   END IF;
  END LOOP;
  SELECT coalesce(jsonb_agg(v.value::text ORDER BY v.value::text COLLATE "C"),'[]'::jsonb),
   coalesce(jsonb_agg(v.value ORDER BY v.value::text COLLATE "C"),'[]'::jsonb)
  INTO serialized,decoded FROM jsonb_array_elements(expected_entry->'states') v;
  IF source->'states' IS DISTINCT FROM serialized OR expected_entry->'states' IS DISTINCT FROM decoded THEN
   RAISE EXCEPTION 'metadata held source serialization or order differs' USING ERRCODE='42501';END IF;
  guard_key:=NULL;
  IF source_kind IN (8,9,10,11) THEN guard_key:='binding:'||(source->>'id');
  ELSIF source_kind IN (12,13,14,15,37) THEN guard_key:='role:'||(source->>'id');
  ELSIF source_kind=30 AND source->>'type' IN ('iam.role','iam.accessBinding') THEN
   guard_key:=CASE source->>'type' WHEN 'iam.role' THEN 'role:' ELSE 'binding:' END||(source->>'id');END IF;
  IF guard_key IS NOT NULL THEN needed_guards:=needed_guards||jsonb_build_object(guard_key,'share');END IF;
  IF source_kind=23 THEN
   account_id:=source->>'id';
   IF source->>'type' IS DISTINCT FROM 'account' OR jsonb_array_length(decoded) IS DISTINCT FROM 1
    OR decoded#>>'{0,2,id}' IS DISTINCT FROM account_id THEN
    RAISE EXCEPTION 'metadata held account source malformed' USING ERRCODE='42501';END IF;
   IF proof->>'mode'='accounts' AND NOT coalesce((proof->'accounts') ? account_id,false) THEN
    RAISE EXCEPTION 'metadata held closure exceeds signed accounts; restage required' USING ERRCODE='P1034';END IF;
   IF coalesce(p_plan#>>ARRAY['binding_epochs',account_id],'') NOT IN ('share','write')
    OR coalesce(p_plan#>>ARRAY['policy_epochs','scope:'||account_id],'') NOT IN ('share','write') THEN
    RAISE EXCEPTION 'metadata account absent from complete held guard plan' USING ERRCODE='42501';END IF;
  ELSIF source_kind=8 THEN
   FOR state IN SELECT v.value FROM jsonb_array_elements(decoded) v LOOP
    needs_global:=needs_global OR state#>>'{2,resource_type}'='cluster';
   END LOOP;
  END IF;
 END LOOP;
 IF needed_guards IS DISTINCT FROM p_closure->'carrier_source_guards' THEN
  RAISE EXCEPTION 'metadata held carrier source guard set differs' USING ERRCODE='42501';END IF;
 FOR entry IN SELECT e.key,e.value FROM jsonb_each(needed_guards) e LOOP
  work:=work+1;IF work>p_work THEN RAISE EXCEPTION 'metadata guard-shape work exhausted' USING ERRCODE='54000';END IF;
  IF coalesce(p_plan#>>ARRAY['source_guards',entry.key],'') NOT IN ('share','write') THEN
   RAISE EXCEPTION 'metadata source absent from complete held guard plan' USING ERRCODE='42501';END IF;
 END LOOP;
 IF coalesce(p_plan#>>ARRAY['binding_epochs',''],'') NOT IN ('share','write')
  OR p_plan#>>ARRAY['binding_epochs',p_packet->>'root_account'] IS DISTINCT FROM 'write'
  OR coalesce(p_plan#>>'{policy_epochs,*}','') NOT IN ('share','write') THEN
  RAISE EXCEPTION 'metadata census root or owning write guard missing' USING ERRCODE='42501';END IF;
 FOR entry IN SELECT e.key,e.value FROM jsonb_each(p_closure->'outputs') e LOOP
  work:=work+1;IF work>p_work THEN RAISE EXCEPTION 'metadata output-shape work exhausted' USING ERRCODE='54000';END IF;
  IF jsonb_typeof(entry.value) IS DISTINCT FROM 'object'
   OR entry.key IS DISTINCT FROM jsonb_build_array(entry.value->>'model_type',entry.value->>'object_id')::text THEN
   RAISE EXCEPTION 'metadata output witness identity malformed' USING ERRCODE='42501';END IF;
  needs_global:=needs_global OR entry.value->>'model_type'='cluster';
 END LOOP;
 IF coalesce(proof->>'mode','') NOT IN ('accounts','global')
  OR (needs_global AND proof->>'mode'<>'global') THEN
  RAISE EXCEPTION 'metadata closure requires fresh global entry' USING ERRCODE='P1034';END IF;
 IF proof->>'mode'='global' AND p_plan#>>'{policy_epochs,*}' IS DISTINCT FROM 'write' THEN
  RAISE EXCEPTION 'metadata global plan lacks strongest policy root guard' USING ERRCODE='42501';END IF;
 -- Exact physical history of root and every frontier source must belong to the
 -- same closure. No late coordinate discovery or guard acquisition is allowed.
 IF p_closure->'source_index'->(jsonb_build_array(30,root_type,root_id,'')::text)->'states'
  IS DISTINCT FROM jsonb_build_array(p_packet->'root_state') THEN
  RAISE EXCEPTION 'metadata held root history differs from packet' USING ERRCODE='42501';END IF;
 FOR entry IN SELECT e.key,e.value FROM jsonb_each(p_closure#>'{frontier,source_index}') e LOOP
  work:=work+1;IF work>p_work THEN RAISE EXCEPTION 'metadata frontier-index work exhausted' USING ERRCODE='54000';END IF;
  IF p_closure->'source_index'->entry.key IS DISTINCT FROM entry.value THEN
   RAISE EXCEPTION 'metadata held frontier source absent from closure' USING ERRCODE='42501';END IF;
 END LOOP;
 -- Validate frontier witnesses before the first tuple wait, and retain the
 -- absent singleton predicate through a preheld table lock. A present singleton
 -- needs only the exact row SHARE wait below: PK/CHECK exclude another root.
 FOR frontier_entry IN SELECT e.key,e.value FROM jsonb_each(p_closure#>'{frontier,witnesses}') e ORDER BY e.key COLLATE "C" LOOP
  expected_frontier:=frontier_entry.value;work:=work+1;
  IF work>p_work THEN RAISE EXCEPTION 'metadata frontier-shape work exhausted' USING ERRCODE='54000';END IF;
  IF jsonb_typeof(expected_frontier) IS DISTINCT FROM 'object'
   OR expected_frontier-ARRAY['frontier','source_index','cluster_states']<>'{}'::jsonb
   OR jsonb_typeof(expected_frontier->'frontier') IS DISTINCT FROM 'object'
   OR jsonb_typeof(expected_frontier#>'{frontier,parents}') IS DISTINCT FROM 'array'
   OR jsonb_typeof(expected_frontier->'source_index') IS DISTINCT FROM 'object'
   OR NOT (expected_frontier ? 'cluster_states')
   OR (expected_frontier->'cluster_states'<>'null'::jsonb AND jsonb_typeof(expected_frontier->'cluster_states') IS DISTINCT FROM 'array')
   OR frontier_entry.key IS DISTINCT FROM jsonb_build_array(expected_frontier#>>'{frontier,object_type}',expected_frontier#>>'{frontier,object_id}')::text
   OR expected_frontier->'frontier' IS DISTINCT FROM p_closure#>ARRAY['frontier','frontiers',frontier_entry.key] THEN
   RAISE EXCEPTION 'metadata physical frontier witness malformed' USING ERRCODE='42501';END IF;
  IF expected_frontier->'cluster_states'<>'null'::jsonb THEN
   IF jsonb_array_length(expected_frontier->'cluster_states')>1 THEN
    RAISE EXCEPTION 'metadata cluster singleton witness malformed' USING ERRCODE='42501';END IF;
   empty_cluster:=empty_cluster OR expected_frontier->'cluster_states'='[]'::jsonb;
  END IF;
 END LOOP;
 IF empty_cluster THEN
  used_reads:=used_reads+1;work:=work+1;
  IF used_reads>p_reads OR work>p_work THEN
   RAISE EXCEPTION 'metadata cluster empty-guard budget exhausted' USING ERRCODE='54000';END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_backend_pid()
   AND l.database=(SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname=current_database())
   AND l.locktype='relation' AND l.relation='kaname.clusters'::regclass AND l.granted
   AND l.mode IN ('ShareLock','ShareRowExclusiveLock','ExclusiveLock','AccessExclusiveLock')) THEN
   RAISE EXCEPTION 'metadata absent cluster requires preheld relation guard' USING ERRCODE='42501';END IF;
 END IF;
 -- Account endpoints found only by frontier fallback are part of the same
 -- signed fence. They must have an explicit physical account23 capture.
 FOR account_id IN
  SELECT f.value->>'object_id' FROM jsonb_each(p_closure#>'{frontier,frontiers}') f WHERE f.value->>'object_type'='account'
  UNION
  SELECT a.value->>1 FROM jsonb_each(p_closure#>'{frontier,frontiers}') f
   CROSS JOIN LATERAL jsonb_array_elements(f.value->'parents') a WHERE a.value->>0='account'
  UNION
  SELECT o.value->>'object_id' FROM jsonb_each(p_closure->'outputs') o WHERE o.value->>'model_type'='account'
 LOOP
  work:=work+1;
  IF work>p_work THEN RAISE EXCEPTION 'metadata endpoint validation work exhausted' USING ERRCODE='54000';END IF;
  IF coalesce(account_id,'')='' OR NOT coalesce((p_closure->'source_index') ? jsonb_build_array(23,'account',account_id,'')::text,false) THEN
   RAISE EXCEPTION 'metadata frontier account absent from held closure' USING ERRCODE='42501';END IF;
 END LOOP;
 -- Read-only verification of the complete compiler-supplied advisory maximum.
 -- Actual tuple epoch waits and strongest write waits belong to that compiler;
 -- pg_locks cannot certify an uncontended tuple lock owned by this backend.
 FOREACH field_name IN ARRAY ARRAY['source_guards','policy_epochs','binding_epochs'] LOOP
  namespace:=CASE field_name WHEN 'source_guards' THEN 1262569295 WHEN 'policy_epochs' THEN 1262569296 ELSE 1262569297 END;
  FOR guard_entry IN SELECT e.key,e.value FROM jsonb_each_text(p_plan->field_name) e ORDER BY e.key COLLATE "C" LOOP
   IF guard_entry.value IS NULL OR guard_entry.value NOT IN ('share','write')
    OR (field_name='source_guards' AND guard_entry.key !~ '^(role|binding):[^:#*[:space:][:cntrl:]]+$')
    OR (field_name='policy_epochs' AND guard_entry.key='') THEN
    RAISE EXCEPTION 'metadata held guard mode or identity invalid' USING ERRCODE='42501';END IF;
   used_reads:=used_reads+1;work:=work+1;
   IF used_reads>p_reads OR work>p_work THEN
    RAISE EXCEPTION 'metadata held guard verification budget exhausted' USING ERRCODE='54000';END IF;
   PERFORM kaname._authority_resource_preheld_key_v2(namespace,guard_entry.key,guard_entry.value='write');
  END LOOP;
 END LOOP;
 -- Canonical key order and canonical physical row order inside each predicate.
 -- Even an empty expected predicate is reread and charged one logical read.
 FOR entry IN SELECT e.key,e.value FROM jsonb_each(p_closure->'source_index') e ORDER BY e.key COLLATE "C" LOOP
  source:=entry.value->'source';
  actual:=kaname._authority_metadata_access_label_held_source_v1(
   (source->>'kind')::integer,source->>'type',source->>'id',p_rows-used_rows,p_reads-used_reads);
  used_rows:=used_rows+(actual->>'rows')::integer;used_reads:=used_reads+(actual->>'reads')::integer;
  work:=work+1+(actual->>'rows')::integer;
  IF work>p_work THEN RAISE EXCEPTION 'metadata source replay work exhausted' USING ERRCODE='54000';END IF;
  IF actual->>'key' IS DISTINCT FROM entry.key OR actual->'source' IS DISTINCT FROM source
   OR actual->'states' IS DISTINCT FROM entry.value->'states' THEN
   RAISE EXCEPTION 'metadata source closure stale after waits; restage required' USING ERRCODE='40001';END IF;
  replayed:=replayed||jsonb_build_object(entry.key,jsonb_build_object('source',actual->'source','states',actual->'states'));
  held:=held||(actual->'held_rows');
 END LOOP;
 -- Rebuild complete frontier rows as well as every physical source and the
 -- special cluster witness. Repeated reads are charged again, never deduplicated.
 FOR frontier_entry IN SELECT e.key,e.value FROM jsonb_each(p_closure#>'{frontier,witnesses}') e ORDER BY e.key COLLATE "C" LOOP
  expected_frontier:=frontier_entry.value;
  IF jsonb_typeof(expected_frontier) IS DISTINCT FROM 'object'
   OR jsonb_typeof(expected_frontier->'frontier') IS DISTINCT FROM 'object'
   OR jsonb_typeof(expected_frontier->'source_index') IS DISTINCT FROM 'object'
   OR NOT (expected_frontier ? 'cluster_states')
   OR (expected_frontier->'cluster_states'<>'null'::jsonb AND jsonb_typeof(expected_frontier->'cluster_states') IS DISTINCT FROM 'array')
   OR frontier_entry.key IS DISTINCT FROM jsonb_build_array(expected_frontier#>>'{frontier,object_type}',expected_frontier#>>'{frontier,object_id}')::text
   OR expected_frontier->'frontier' IS DISTINCT FROM p_closure#>ARRAY['frontier','frontiers',frontier_entry.key] THEN
   RAISE EXCEPTION 'metadata physical frontier witness malformed' USING ERRCODE='42501';END IF;
  FOR entry IN SELECT e.key,e.value FROM jsonb_each(expected_frontier->'source_index') e LOOP
   work:=work+1;IF work>p_work THEN RAISE EXCEPTION 'metadata frontier-merge work exhausted' USING ERRCODE='54000';END IF;
   IF replayed->entry.key IS DISTINCT FROM entry.value THEN
    RAISE EXCEPTION 'metadata frontier source absent from held closure' USING ERRCODE='42501';END IF;
  END LOOP;
  SELECT * INTO STRICT actual_frontier FROM kaname._authority_metadata_access_label_held_frontier_v1(
   expected_frontier#>>'{frontier,object_type}',expected_frontier#>>'{frontier,object_id}',p_rows-used_rows,p_reads-used_reads);
  used_rows:=used_rows+actual_frontier.logical_rows;used_reads:=used_reads+actual_frontier.logical_reads;
  work:=work+1+actual_frontier.logical_rows;
  IF work>p_work THEN RAISE EXCEPTION 'metadata frontier replay work exhausted' USING ERRCODE='54000';END IF;
  IF actual_frontier.frontier IS DISTINCT FROM expected_frontier->'frontier'
   OR actual_frontier.source_index IS DISTINCT FROM expected_frontier->'source_index'
   OR actual_frontier.cluster_states IS DISTINCT FROM nullif(expected_frontier->'cluster_states','null'::jsonb) THEN
   RAISE EXCEPTION 'metadata physical frontier closure stale; restage required' USING ERRCODE='40001';END IF;
  replayed_frontiers:=replayed_frontiers||jsonb_build_object(frontier_entry.key,jsonb_build_object(
   'frontier',actual_frontier.frontier,'source_index',actual_frontier.source_index,'cluster_states',actual_frontier.cluster_states));
  held:=held||actual_frontier.held_rows;
 END LOOP;
 -- Last reread covers the complete historical carrier predicate, including
 -- absence. Fixed owner-source guards and binding-root fence prevent phantoms;
 -- any new carrier is stale discovery, never permission to acquire a late key.
 FOREACH field_name IN ARRAY ARRAY['access_bindings','roles','projects'] LOOP
  used_reads:=used_reads+1;work:=work+1;
  IF used_reads>p_reads OR work>p_work THEN
   RAISE EXCEPTION 'metadata census privilege-check budget exhausted' USING ERRCODE='54000';END IF;
  IF NOT coalesce(has_table_privilege((proof->>'invoker_oid')::oid,to_regclass('kaname.'||field_name),'SELECT'),false) THEN
   RAISE EXCEPTION 'metadata replay census original SELECT required' USING ERRCODE='42501';END IF;
 END LOOP;
 census:=kaname._authority_metadata_access_label_carrier_census_v1(root_type,expected_census->'old_root',
  expected_census->'new_labels',p_rows-used_rows,p_reads-used_reads,p_work-work);
 used_rows:=used_rows+(census->>'logical_rows')::integer;
 used_reads:=used_reads+(census->>'logical_reads')::integer;work:=work+(census->>'work')::integer;
 IF census IS DISTINCT FROM expected_census THEN
  RAISE EXCEPTION 'metadata complete carrier census stale after waits; restage required' USING ERRCODE='40001';END IF;
 IF used_rows>p_rows OR used_reads>p_reads OR work>p_work THEN
  RAISE EXCEPTION 'metadata held replay shared budget exhausted' USING ERRCODE='54000';END IF;
 RETURN jsonb_build_object('source_index',replayed,'frontier_witnesses',replayed_frontiers,
  'census',census,'held_rows',held,'rows',used_rows,'reads',used_reads,'work',work,
  'backend',proof->'backend','transaction_id',proof->'transaction_id','nonce',proof->'nonce');
END;
$replay$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE signature text;recipient record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 FOREACH signature IN ARRAY ARRAY[
  '_authority_metadata_access_label_held_source_v1(integer,text,text,integer,integer)',
  '_authority_metadata_access_label_held_frontier_v1(text,text,integer,integer)',
  '_authority_metadata_access_label_held_replay_v1(jsonb,jsonb,jsonb,integer,integer,integer)'
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
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_metadata_access_label_held_replay_v1(jsonb,jsonb,jsonb,integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_access_label_held_frontier_v1(text,text,integer,integer);
DROP FUNCTION kaname._authority_metadata_access_label_held_source_v1(integer,text,text,integer,integer);
