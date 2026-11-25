-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Полные точечные источники для вычисления старых выдач. Функции доступны
-- только владельцу. Защита отсутствующих строк остаётся обязанностью
-- программы записи, которая удерживает область и повторяет чтение.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_access_label_source_capture_v1(
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
  RAISE EXCEPTION 'metadata physical capture requires held full consumer' USING ERRCODE='42501';END IF;
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
 IF NOT has_table_privilege((proof->>'invoker_oid')::oid,to_regclass(format('kaname.%I',table_name)),'SELECT') THEN
  RAISE EXCEPTION 'metadata physical source SELECT required' USING ERRCODE='42501';END IF;
 FOR item IN EXECUTE format('SELECT r.tableoid relation_oid,r.ctid::text row_tid,r.xmin::text row_xmin,to_jsonb(r) row_data,
  jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r)) row_state
  FROM kaname.%I r WHERE $1::text IS NOT NULL AND (%s) LIMIT $3 FOR SHARE OF r',table_name,predicate)
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
CREATE FUNCTION kaname._authority_metadata_access_label_frontier_capture_v1(
 p_model text,p_id text,p_rows integer,p_reads integer
) RETURNS TABLE(frontier jsonb,source_index jsonb,cluster_states jsonb,
 logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $frontier$
DECLARE capture jsonb;row_value jsonb;state jsonb;triples jsonb:='[]';parents jsonb;
 table_type text;cluster_row record;proof jsonb;row_count integer;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF coalesce(p_model,'')='' OR p_model LIKE '%.%' OR coalesce(p_id,'')=''
 OR p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000
 OR p_reads IS NULL OR p_reads NOT BETWEEN 1 AND 4096 THEN
  RAISE EXCEPTION 'metadata physical frontier input invalid' USING ERRCODE='42501';END IF;
 source_index:='{}';cluster_states:=NULL;logical_rows:=0;logical_reads:=0;
 -- Физические рёбра имеют приоритет над выводом из других таблиц.
 -- Сохраняем весь результат, включая отсутствие рёбер.
 capture:=kaname._authority_metadata_access_label_source_capture_v1(3,p_model,p_id,least(p_rows,4),p_reads);
 source_index:=source_index||jsonb_build_object(capture->>'key',jsonb_build_object('source',capture->'source','states',capture->'states'));
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
   capture:=kaname._authority_metadata_access_label_source_capture_v1(6,'project',p_id,p_rows-logical_rows,p_reads-logical_reads);
   source_index:=source_index||jsonb_build_object(capture->>'key',jsonb_build_object('source',capture->'source','states',capture->'states'));
   logical_rows:=logical_rows+(capture->>'rows')::integer;logical_reads:=logical_reads+(capture->>'reads')::integer;
   FOR state IN SELECT value FROM jsonb_array_elements(capture->'states') LOOP
    row_value:=state->2;
    IF row_value->>'relation'=split_part(row_value->>'subject',':',1) AND position('#' IN row_value->>'subject')=0 THEN
     triples:=triples||jsonb_build_array(jsonb_build_object('parent_type',split_part(row_value->>'subject',':',1),
      'parent_id',substr(row_value->>'subject',position(':' IN row_value->>'subject')+1),'depth',1));
    END IF;
   END LOOP;
  WHEN 'account' THEN
   capture:=kaname._authority_metadata_access_label_source_capture_v1(30,'iam.account',p_id,p_rows-logical_rows,p_reads-logical_reads);
   source_index:=source_index||jsonb_build_object(capture->>'key',jsonb_build_object('source',capture->'source','states',capture->'states'));
   logical_rows:=logical_rows+(capture->>'rows')::integer;logical_reads:=logical_reads+(capture->>'reads')::integer;
   IF jsonb_array_length(capture->'states')=1 THEN
    -- Точечное чтение полно благодаря проверенному ограничению
    -- на единственную допустимую строку таблицы clusters.
    proof:=kaname.authority_protocol_attestation();
    IF NOT has_table_privilege((proof->>'invoker_oid')::oid,'kaname.clusters','SELECT') THEN
     RAISE EXCEPTION 'metadata cluster fallback SELECT required' USING ERRCODE='42501';END IF;
    IF logical_reads>=p_reads THEN RAISE EXCEPTION 'metadata cluster frontier read budget exceeded' USING ERRCODE='54000';END IF;
    logical_reads:=logical_reads+1;cluster_states:='[]';
    FOR cluster_row IN SELECT jsonb_build_array(c.xmin::text,c.ctid::text,to_jsonb(c)) state
     FROM kaname.clusters c WHERE c.id='cluster_root' LIMIT least(p_rows-logical_rows,1)+1 FOR SHARE OF c LOOP
     logical_rows:=logical_rows+1;
     IF logical_rows>p_rows THEN RAISE EXCEPTION 'metadata cluster frontier row budget exceeded' USING ERRCODE='54000';END IF;
     cluster_states:=cluster_states||jsonb_build_array(cluster_row.state);
     triples:=triples||jsonb_build_array(jsonb_build_object('parent_type','cluster','parent_id',cluster_row.state#>>'{2,id}','depth',1));
    END LOOP;
   END IF;
  WHEN 'iam_user' THEN
   -- Состояние членства не влияет на путь к родительской области.
   capture:=kaname._authority_metadata_access_label_source_capture_v1(31,'iam.user',p_id,p_rows-logical_rows,p_reads-logical_reads);
   source_index:=source_index||jsonb_build_object(capture->>'key',jsonb_build_object('source',capture->'source','states',capture->'states'));
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
   capture:=kaname._authority_metadata_access_label_source_capture_v1(30,table_type,p_id,p_rows-logical_rows,p_reads-logical_reads);
   source_index:=source_index||jsonb_build_object(capture->>'key',jsonb_build_object('source',capture->'source','states',capture->'states'));
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
CREATE FUNCTION kaname._authority_metadata_access_label_frontier_recheck_v1(
 p_frontier jsonb,p_source_index jsonb,p_cluster_states jsonb,p_rows integer,p_reads integer
) RETURNS TABLE(logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $recheck$
DECLARE actual record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF jsonb_typeof(p_frontier) IS DISTINCT FROM 'object' OR jsonb_typeof(p_source_index) IS DISTINCT FROM 'object'
 OR (p_cluster_states IS NOT NULL AND jsonb_typeof(p_cluster_states) IS DISTINCT FROM 'array') THEN
  RAISE EXCEPTION 'metadata frontier physical history incomplete' USING ERRCODE='42501';END IF;
 SELECT * INTO STRICT actual FROM kaname._authority_metadata_access_label_frontier_capture_v1(
  p_frontier->>'object_type',p_frontier->>'object_id',p_rows,p_reads);
 IF actual.frontier IS DISTINCT FROM p_frontier OR actual.source_index IS DISTINCT FROM p_source_index
 OR actual.cluster_states IS DISTINCT FROM p_cluster_states THEN
  RAISE EXCEPTION 'metadata frontier or physical history changed' USING ERRCODE='40001';END IF;
 RETURN QUERY SELECT actual.logical_rows::integer,actual.logical_reads::integer;
END;
$recheck$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_access_label_frontier_storage_v1() RETURNS boolean
LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $storage$
 SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class v
  WHERE v.oid='kaname.resource_scope_edge'::regclass AND v.relkind='v'
   AND encode(sha256(convert_to(regexp_replace(pg_catalog.pg_get_viewdef(v.oid,false),'[[:space:]]+','','g'),'UTF8')),'hex')=
     '8706d0b9b37b9a09efce84bba86d2268c71af1476cb26cd5cd935fb5d3134ac1')
 AND EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a
  JOIN pg_catalog.pg_constraint pk ON pk.conrelid=a.attrelid AND pk.contype='p' AND pk.convalidated
   AND NOT pk.condeferrable AND pk.conkey=ARRAY[a.attnum]
  JOIN pg_catalog.pg_constraint ck ON ck.conrelid=a.attrelid AND ck.conname='clusters_id_singleton_ck'
   AND ck.contype='c' AND ck.convalidated AND ck.conkey=ARRAY[a.attnum]
  WHERE a.attrelid='kaname.clusters'::regclass AND a.attname='id' AND a.attnotnull AND NOT a.attisdropped
   AND regexp_replace(pg_catalog.pg_get_expr(ck.conbin,ck.conrelid),'[[:space:]()]','','g')='id=''cluster_root''::text');
$storage$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE signature text;recipient record;
BEGIN
 FOREACH signature IN ARRAY ARRAY[
  '_authority_metadata_access_label_source_capture_v1(integer,text,text,integer,integer)',
  '_authority_metadata_access_label_frontier_capture_v1(text,text,integer,integer)',
  '_authority_metadata_access_label_frontier_recheck_v1(jsonb,jsonb,jsonb,integer,integer)',
  '_authority_metadata_access_label_frontier_storage_v1()'
 ] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',signature);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE p.oid=to_regprocedure('kaname.'||signature) AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM %I',signature,recipient.rolname);
  END LOOP;
 END LOOP;
 IF NOT kaname._authority_metadata_access_label_frontier_storage_v1() THEN
  RAISE EXCEPTION 'metadata scope sources differ from canonical schema' USING ERRCODE='55000';END IF;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_metadata_access_label_frontier_storage_v1();
DROP FUNCTION kaname._authority_metadata_access_label_frontier_recheck_v1(jsonb,jsonb,jsonb,integer,integer);
DROP FUNCTION kaname._authority_metadata_access_label_frontier_capture_v1(text,text,integer,integer);
DROP FUNCTION kaname._authority_metadata_access_label_source_capture_v1(integer,text,text,integer,integer);
