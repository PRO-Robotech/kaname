-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Owner-private observations before policy finalization. No runtime entry,
-- readiness flag, grant, writer activation, or protected-write proof is added.
-- Caller must replay every predicate under the complete strongest guard plan.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $dependencies$
DECLARE dependency record; procedure_oid oid;
BEGIN
 FOR dependency IN SELECT * FROM (VALUES
  ('authority_protocol_require_owner()', 'void'),
  ('authority_protocol_attestation()', 'jsonb'),
  ('access_labels_valid_v1(jsonb)', 'boolean'),
  ('access_label_rules_valid_v1(jsonb)', 'boolean'),
  ('_authority_metadata_access_label_frontier_storage_v1()', 'boolean')
 ) AS required(signature,result_type) LOOP
  procedure_oid:=to_regprocedure('kaname.'||dependency.signature);
  IF procedure_oid IS NULL OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
   WHERE p.oid=procedure_oid AND p.prorettype=to_regtype(dependency.result_type)
    AND NOT p.proretset AND p.prokind='f'
    AND p.proowner=(SELECT c.relowner FROM pg_catalog.pg_class c
     WHERE c.oid='kaname.authority_writer_protocol'::regclass)) THEN
   RAISE EXCEPTION 'metadata discovery dependency ABI differs: %',dependency.signature USING ERRCODE='55000';
  END IF;
 END LOOP;
 IF kaname._authority_metadata_access_label_frontier_storage_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'metadata discovery frontier storage differs' USING ERRCODE='55000';END IF;
END;
$dependencies$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_access_label_carrier_census_v1(
 p_root_type text,p_old_root jsonb,p_new_labels jsonb,p_rows integer,p_reads integer,p_work integer)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE census_account_id text;root_id text;root_resource text;item record;owner_rule jsonb;node jsonb;
 states jsonb:='[]';selected jsonb:='[]';binding_ids text[]:=ARRAY[]::text[];
 used integer:=0;work integer:=0;changed boolean;rules jsonb;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_root_type IS NULL OR p_root_type NOT IN ('iam.account','iam.project')
 OR jsonb_typeof(p_old_root) IS DISTINCT FROM 'object' OR coalesce(p_old_root->>'id','')=''
 OR kaname.access_labels_valid_v1(p_old_root->'access_labels') IS DISTINCT FROM true
 OR kaname.access_labels_valid_v1(p_new_labels) IS DISTINCT FROM true
 OR p_old_root->'access_labels' IS NOT DISTINCT FROM p_new_labels
 OR p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000
 OR p_reads IS NULL OR p_reads NOT BETWEEN 1 AND 4096
 OR p_work IS NULL OR p_work NOT BETWEEN 0 AND 400000 THEN
  RAISE EXCEPTION 'protected metadata census shape invalid' USING ERRCODE='42501';END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY['access_bindings','roles','projects']) required(name)
  LEFT JOIN pg_catalog.pg_class c ON c.oid=to_regclass('kaname.'||required.name)
  WHERE c.oid IS NULL OR c.relkind<>'r' OR c.relrowsecurity OR c.relforcerowsecurity
   OR c.relispartition OR c.relhassubclass) THEN
  RAISE EXCEPTION 'metadata census source shape unsupported' USING ERRCODE='42501';END IF;
 root_id:=p_old_root->>'id';root_resource:=split_part(p_root_type,'.',2);
 census_account_id:=CASE WHEN p_root_type='iam.account' THEN root_id ELSE p_old_root->>'account_id' END;
 IF coalesce(census_account_id,'')='' THEN RAISE EXCEPTION 'protected metadata owner absent' USING ERRCODE='42501';END IF;
 -- Не фильтруем статус, expiry, live или presence member: это census старых
 -- выходов, а не кандидаты для выдачи нового права. Сначала bounded rows,
 -- затем проверка selectors. Пустой результат также входит в RC equality.
 FOR item IN SELECT to_jsonb(b) binding,to_jsonb(r) role,
  jsonb_build_array(b.xmin::text,b.ctid::text,to_jsonb(b),r.xmin::text,r.ctid::text,to_jsonb(r),
   p.xmin::text,p.ctid::text,to_jsonb(p)) state
 FROM ONLY kaname.access_bindings b
 LEFT JOIN ONLY kaname.roles r ON r.id=b.role_id
 LEFT JOIN ONLY kaname.projects p ON b.resource_type='project' AND p.id=b.resource_id
 WHERE (b.resource_type NOT IN ('account','project')
  OR (b.resource_type='account' AND b.resource_id=census_account_id)
  OR (b.resource_type='project' AND (
       (p_root_type='iam.account' AND p.account_id=census_account_id)
    OR (p_root_type='iam.project' AND b.resource_id=root_id)
    OR p.id IS NULL)))
  AND b.role_id IS NOT NULL
  AND (r.id IS NULL OR kaname.access_label_rules_valid_v1(r.rules) IS DISTINCT FROM true
   OR EXISTS (
    SELECT 1 FROM jsonb_array_elements(CASE WHEN kaname.access_label_rules_valid_v1(r.rules) THEN r.rules ELSE '[]'::jsonb END) authored_rules(owner_rule)
    CROSS JOIN LATERAL jsonb_array_elements(jsonb_build_array(authored_rules.owner_rule)||
      coalesce(nullif(authored_rules.owner_rule->'children','null'::jsonb),'[]'::jsonb)) nodes(node)
    WHERE authored_rules.owner_rule->>'module'='iam' AND nodes.node->'resources' ? root_resource
      AND nodes.node ? 'match_access_labels'
      AND (p_old_root->'access_labels' @> (nodes.node->'match_access_labels'))
       IS DISTINCT FROM (p_new_labels @> (nodes.node->'match_access_labels'))))
 LIMIT p_rows+1 LOOP
  used:=used+1+CASE WHEN item.state->3='null'::jsonb THEN 0 ELSE 1 END
   +CASE WHEN item.state->6='null'::jsonb THEN 0 ELSE 1 END;work:=work+1;
  IF used>p_rows OR work>p_work THEN RAISE EXCEPTION 'protected metadata carrier census budget exceeded' USING ERRCODE='54000';END IF;
  states:=states||jsonb_build_array(item.state);
  IF item.binding->>'resource_type' NOT IN ('account','project','cluster')
   OR coalesce(item.binding->>'resource_id','')=''
   OR (item.binding->>'resource_type'='project' AND item.state->8='null'::jsonb) THEN
   RAISE EXCEPTION 'protected metadata carrier scope unconfirmed' USING ERRCODE='42501';END IF;
  -- Relation-form carriers cannot contain a role selector. They are still in
  -- states so RC equality confirms the complete predicate rather than an allow.
  IF item.binding->>'role_id' IS NULL THEN
   IF coalesce(item.binding->>'granted_relation','')='' THEN
    RAISE EXCEPTION 'protected metadata carrier has no form' USING ERRCODE='42501';END IF;
   CONTINUE;
  END IF;
  IF item.role IS NULL OR item.role='null'::jsonb
   OR item.role->>'id' IS DISTINCT FROM item.binding->>'role_id'
   OR kaname.access_label_rules_valid_v1(item.role->'rules') IS DISTINCT FROM true THEN
   RAISE EXCEPTION 'protected metadata role source unconfirmed' USING ERRCODE='42501';END IF;
  changed:=false;rules:=item.role->'rules';
  FOR owner_rule IN SELECT value FROM jsonb_array_elements(rules) LOOP
   FOR node IN SELECT value FROM jsonb_array_elements(jsonb_build_array(owner_rule)||
     coalesce(nullif(owner_rule->'children','null'::jsonb),'[]'::jsonb)) LOOP
    work:=work+1;
    IF work>p_work THEN RAISE EXCEPTION 'protected metadata authored census work exceeded' USING ERRCODE='54000';END IF;
    IF node ? 'match_access_labels' AND owner_rule->>'module'='iam'
     AND node->'resources' ? root_resource
     AND ((p_old_root->'access_labels') @> (node->'match_access_labels'))
         IS DISTINCT FROM (p_new_labels @> (node->'match_access_labels')) THEN
     changed:=true;
    END IF;
   END LOOP;
  END LOOP;
  IF changed THEN
   binding_ids:=binding_ids||(item.binding->>'id');selected:=selected||jsonb_build_array(item.state);
   IF cardinality(binding_ids)>4096 THEN
    RAISE EXCEPTION 'protected metadata carrier set exceeded' USING ERRCODE='54000';END IF;
  END IF;
 END LOOP;
 SELECT coalesce(jsonb_agg(v ORDER BY v::text COLLATE "C"),'[]'::jsonb) INTO states FROM jsonb_array_elements(states) v;
 SELECT coalesce(jsonb_agg(v ORDER BY v::text COLLATE "C"),'[]'::jsonb) INTO selected FROM jsonb_array_elements(selected) v;
 SELECT coalesce(array_agg(v ORDER BY v COLLATE "C"),ARRAY[]::text[]) INTO binding_ids FROM unnest(binding_ids) v;
 RETURN jsonb_build_object('root_type',p_root_type,'root_id',root_id,'account_id',census_account_id,
  'old_root',p_old_root,'new_labels',p_new_labels,'states',states,'selected',selected,'binding_ids',binding_ids,
  'logical_rows',used,'logical_reads',1,'work',work);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_access_label_prefinal_carriers_v1(
 p_kind text,p_id text,p_old_xmin text,p_old jsonb,p_new_access jsonb,
 p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $discover$
DECLARE proof jsonb;owner_oid oid;invoker oid;consumer oid;table_name text;
 relation_id regclass;target text;root_state jsonb;account_id text;census jsonb;
 selected jsonb;binding jsonb;role_row jsonb;guards jsonb:='{}';seen jsonb:='{}';
 identifier text;role_id text;root_ref jsonb;work integer;used_rows integer;used_reads integer;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
  OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'full'
  OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
  OR NOT coalesce((proof->>'writer_contract'='2' AND proof->>'purpose'='decision')
   OR (proof->>'writer_contract'='1' AND proof->>'purpose'='participant'),false) THEN
  RAISE EXCEPTION 'metadata discovery requires signed full admission' USING ERRCODE='42501';END IF;
 SELECT relowner INTO STRICT owner_oid FROM pg_catalog.pg_class
 WHERE oid='kaname.authority_writer_protocol'::regclass;
 consumer:=to_regclass('pg_temp.kaname_authority_consumer');
 IF consumer IS NULL OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c
  WHERE c.oid=consumer AND c.relowner=owner_oid AND c.relpersistence='t' AND c.relkind='r') THEN
  RAISE EXCEPTION 'metadata discovery consumer custody missing' USING ERRCODE='42501';END IF;
 IF (SELECT count(*) FROM pg_temp.kaname_authority_consumer)<>1
  OR NOT EXISTS(SELECT 1 FROM pg_temp.kaname_authority_consumer WHERE NOT finalized) THEN
  RAISE EXCEPTION 'metadata discovery must precede policy finalization' USING ERRCODE='42501';END IF;
 IF proof->>'writer_contract'='1' AND NOT EXISTS(SELECT 1 FROM kaname.authority_writer_contract
  WHERE singleton AND required_contract=1 AND staged_contract=1) THEN
  RAISE EXCEPTION 'metadata discovery staged contract unavailable' USING ERRCODE='P1036';END IF;
 IF p_kind IS NULL OR p_kind NOT IN ('account','project') OR coalesce(p_id,'')=''
  OR octet_length(p_id)>16384 OR p_id ~ '[:#*[:space:][:cntrl:]]'
  OR coalesce(p_old_xmin,'')='' OR jsonb_typeof(p_old) IS DISTINCT FROM 'object'
  OR p_old->>'id' IS DISTINCT FROM p_id
  OR kaname.access_labels_valid_v1(p_new_access) IS DISTINCT FROM true
  OR p_old->'access_labels' IS NOT DISTINCT FROM p_new_access
  OR p_rows IS NULL OR p_rows NOT BETWEEN 1 AND 100000
  OR p_reads IS NULL OR p_reads NOT BETWEEN 2 AND 4096
  OR p_work IS NULL OR p_work NOT BETWEEN 1 AND 400000 THEN
  RAISE EXCEPTION 'metadata discovery coordinate or budget invalid' USING ERRCODE='42501';END IF;
 table_name:=CASE p_kind WHEN 'account' THEN 'accounts' ELSE 'projects' END;
 -- Владелец не подменяет обычные права LOGIN и не обходит его RLS.
 invoker:=(proof->>'invoker_oid')::oid;
 FOREACH target IN ARRAY ARRAY[table_name,'access_bindings','roles','projects'] LOOP
  relation_id:=to_regclass('kaname.'||target);
  IF invoker IS NULL OR relation_id IS NULL OR NOT coalesce(has_table_privilege(invoker,relation_id,'SELECT'),false)
   OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=relation_id
    AND (c.relkind<>'r' OR c.relrowsecurity OR c.relforcerowsecurity OR c.relispartition OR c.relhassubclass)) THEN
   RAISE EXCEPTION 'metadata discovery existing source read privilege required' USING ERRCODE='42501';END IF;
 END LOOP;
 -- Не берём tuple/advisory locks частичного графа: полный максимум должен
 -- быть выведен до первого acquisition. Здесь только наблюдение для discovery.
 EXECUTE format('SELECT jsonb_build_array(o.xmin::text,o.ctid::text,to_jsonb(o))
  FROM ONLY kaname.%I o WHERE o.id=$1',table_name) INTO root_state USING p_id;
 IF root_state IS NULL OR root_state->>0 IS DISTINCT FROM p_old_xmin
  OR root_state->2 IS DISTINCT FROM p_old THEN
  RAISE EXCEPTION 'metadata discovery root differs from RR' USING ERRCODE='P1034';END IF;
 account_id:=CASE p_kind WHEN 'account' THEN p_id ELSE p_old->>'account_id' END;
 IF coalesce(account_id,'')='' OR coalesce(proof->>'mode','') NOT IN ('accounts','global')
  OR (proof->>'mode'='accounts' AND NOT (proof->'accounts') ? account_id) THEN
  RAISE EXCEPTION 'metadata discovery root outside signed admission' USING ERRCODE='P1034';END IF;
 census:=kaname._authority_metadata_access_label_carrier_census_v1(
  'iam.'||p_kind,root_state->2,p_new_access,p_rows-1,p_reads-1,p_work-1);
 IF jsonb_typeof(census->'selected') IS DISTINCT FROM 'array'
  OR jsonb_typeof(census->'binding_ids') IS DISTINCT FROM 'array'
  OR census->>'root_type' IS DISTINCT FROM 'iam.'||p_kind
  OR census->>'root_id' IS DISTINCT FROM p_id OR census->'old_root' IS DISTINCT FROM p_old
  OR census->'new_labels' IS DISTINCT FROM p_new_access THEN
  RAISE EXCEPTION 'metadata discovery census identity differs' USING ERRCODE='42501';END IF;
 used_rows:=1+(census->>'logical_rows')::integer;
 used_reads:=1+(census->>'logical_reads')::integer;work:=1+(census->>'work')::integer;
 FOR selected IN SELECT value FROM jsonb_array_elements(census->'selected') LOOP
  binding:=selected->2;role_row:=selected->5;
  identifier:=binding->>'id';role_id:=binding->>'role_id';work:=work+1;
  IF jsonb_typeof(selected) IS DISTINCT FROM 'array' OR jsonb_array_length(selected)<>9
   OR coalesce(identifier,'')='' OR identifier ~ '[:#*[:space:][:cntrl:]]'
   OR coalesce(role_id,'')='' OR role_id ~ '[:#*[:space:][:cntrl:]]'
   OR role_row->>'id' IS DISTINCT FROM role_id OR seen ? identifier
   OR NOT (census->'binding_ids') ? identifier THEN
   RAISE EXCEPTION 'metadata discovery carrier identity differs' USING ERRCODE='42501';END IF;
  seen:=seen||jsonb_build_object(identifier,true);
  guards:=guards||jsonb_build_object('binding:'||identifier,'share','role:'||role_id,'share');
  IF work>p_work OR (SELECT count(*) FROM jsonb_object_keys(guards))>4096 THEN
   RAISE EXCEPTION 'metadata discovery source guards over budget' USING ERRCODE='54000';END IF;
 END LOOP;
 IF used_rows IS NULL OR used_rows>p_rows OR used_reads IS NULL OR used_reads>p_reads
  OR work IS NULL OR work>p_work
  OR (SELECT count(*) FROM jsonb_object_keys(seen))<>jsonb_array_length(census->'binding_ids') THEN
  RAISE EXCEPTION 'metadata discovery census budget or population differs' USING ERRCODE='54000';END IF;
 root_ref:=jsonb_build_array('iam.'||p_kind,p_id);
 RETURN jsonb_build_object('root_state',root_state,'census',census,
  'carrier_source_guards',guards,'root_coordinate',root_ref,'root_account',account_id,
  'rows',used_rows,'reads',used_reads,'work',work);
END;
$discover$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_access_label_early_source_v1(
 p_kind integer,p_type text,p_id text,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $capture$
DECLARE proof jsonb; table_name text; predicate text; required_type text;
 item record; states jsonb:='[]'; decoded jsonb:='[]'; used integer:=0;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
 OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'full'
 OR NOT coalesce((proof->>'writer_contract'='2' AND proof->>'purpose'='decision')
      OR (proof->>'writer_contract'='1' AND proof->>'purpose'='participant'),false)
 OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
 OR NOT EXISTS(SELECT 1 FROM pg_temp.kaname_authority_consumer WHERE NOT finalized) THEN
  RAISE EXCEPTION 'metadata physical capture requires pre-final full consumer' USING ERRCODE='42501';END IF;
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
  FROM ONLY kaname.%I r WHERE $1::text IS NOT NULL AND (%s) LIMIT $3',table_name,predicate)
 USING p_type,p_id,p_rows+1 LOOP
  used:=used+1;
  IF used>p_rows THEN RAISE EXCEPTION 'metadata physical source sentinel exceeded' USING ERRCODE='54000';END IF;
  states:=states||jsonb_build_array(item.row_state::text);
  decoded:=decoded||jsonb_build_array(item.row_state);
 END LOOP;
 SELECT coalesce(jsonb_agg(v ORDER BY v#>>'{}' COLLATE "C"),'[]'::jsonb) INTO states FROM jsonb_array_elements(states) v;
 SELECT coalesce(jsonb_agg(v ORDER BY v::text COLLATE "C"),'[]'::jsonb) INTO decoded FROM jsonb_array_elements(decoded) v;
 RETURN jsonb_build_object('key',jsonb_build_array(p_kind,p_type,p_id,'')::text,
  'source',jsonb_build_object('kind',p_kind,'type',p_type,'id',p_id,'projection','','states',states),
  'states',decoded,'rows',used,'reads',1);
END;
$capture$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_access_label_early_frontier_v1(
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
 IF kaname._authority_metadata_access_label_frontier_storage_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'metadata early frontier storage differs' USING ERRCODE='42501';END IF;
 source_index:='{}';cluster_states:=NULL;logical_rows:=0;logical_reads:=0;
 -- Физические рёбра имеют приоритет над выводом из других таблиц.
 -- Сохраняем весь результат, включая отсутствие рёбер.
 capture:=kaname._authority_metadata_access_label_early_source_v1(3,p_model,p_id,least(p_rows,4),p_reads);
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
   capture:=kaname._authority_metadata_access_label_early_source_v1(6,'project',p_id,p_rows-logical_rows,p_reads-logical_reads);
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
   capture:=kaname._authority_metadata_access_label_early_source_v1(30,'iam.account',p_id,p_rows-logical_rows,p_reads-logical_reads);
   source_index:=source_index||jsonb_build_object(capture->>'key',jsonb_build_object('source',capture->'source','states',capture->'states'));
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
    FOR cluster_row IN SELECT jsonb_build_array(c.xmin::text,c.ctid::text,to_jsonb(c)) state
     FROM ONLY kaname.clusters c WHERE c.id='cluster_root' LIMIT least(p_rows-logical_rows,1)+1 LOOP
     logical_rows:=logical_rows+1;
     IF logical_rows>p_rows THEN RAISE EXCEPTION 'metadata cluster frontier row budget exceeded' USING ERRCODE='54000';END IF;
     cluster_states:=cluster_states||jsonb_build_array(cluster_row.state);
     triples:=triples||jsonb_build_array(jsonb_build_object('parent_type','cluster','parent_id',cluster_row.state#>>'{2,id}','depth',1));
    END LOOP;
   END IF;
  WHEN 'iam_user' THEN
   -- Состояние членства не влияет на путь к родительской области.
   capture:=kaname._authority_metadata_access_label_early_source_v1(31,'iam.user',p_id,p_rows-logical_rows,p_reads-logical_reads);
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
   capture:=kaname._authority_metadata_access_label_early_source_v1(30,table_type,p_id,p_rows-logical_rows,p_reads-logical_reads);
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
CREATE FUNCTION kaname._authority_metadata_access_label_early_walk_v1(
 p_seeds jsonb,p_root_model text,p_root_id text,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $walk$
DECLARE seed jsonb;node jsonb;parent jsonb;frontier_key text;entry record;
 pending jsonb;seen jsonb;capture record;witness jsonb;found_root boolean;
 captured jsonb:='{}';frontiers jsonb:='{}';sources jsonb:='{}';reaches jsonb:='{}';
 pos integer;depth integer;frontier_count integer:=0;rows_used integer:=0;reads_used integer:=0;work_used integer:=0;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF jsonb_typeof(p_seeds) IS DISTINCT FROM 'array' OR jsonb_array_length(p_seeds)>4096
  OR coalesce(p_root_model,'') NOT IN ('account','project') OR coalesce(p_root_id,'')=''
  OR p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000
  OR p_reads IS NULL OR p_reads NOT BETWEEN 0 AND 4096
  OR p_work IS NULL OR p_work NOT BETWEEN 0 AND 400000 THEN
  RAISE EXCEPTION 'metadata scope walk input invalid' USING ERRCODE='42501';END IF;
 FOR seed IN SELECT DISTINCT v FROM jsonb_array_elements(p_seeds) v ORDER BY v LOOP
  IF jsonb_typeof(seed) IS DISTINCT FROM 'array' OR jsonb_array_length(seed)<>2
   OR jsonb_typeof(seed->0) IS DISTINCT FROM 'string' OR jsonb_typeof(seed->1) IS DISTINCT FROM 'string'
   OR coalesce(seed->>0,'')='' OR seed->>0 LIKE '%.%' OR coalesce(seed->>1,'')='' THEN
   RAISE EXCEPTION 'metadata scope seed invalid' USING ERRCODE='42501';END IF;
  pending:=jsonb_build_array(jsonb_build_array(seed->>0,seed->>1,0));seen:='{}';pos:=0;found_root:=false;
  WHILE pos<jsonb_array_length(pending) LOOP
   node:=pending->pos;pos:=pos+1;depth:=(node->>2)::integer;
   frontier_key:=jsonb_build_array(node->>0,node->>1)::text;
   work_used:=work_used+1;
   IF work_used>p_work THEN RAISE EXCEPTION 'metadata scope walk work exhausted' USING ERRCODE='54000';END IF;
   IF seen ? frontier_key THEN CONTINUE;END IF;
   seen:=seen||jsonb_build_object(frontier_key,true);
   IF node->>0=p_root_model AND node->>1=p_root_id THEN found_root:=true;EXIT;END IF;
   witness:=captured->frontier_key;
   IF witness IS NULL THEN
    IF reads_used>=p_reads OR frontier_count>=4096 THEN
     RAISE EXCEPTION 'metadata scope walk read budget exhausted' USING ERRCODE='54000';END IF;
    SELECT * INTO STRICT capture FROM kaname._authority_metadata_access_label_early_frontier_v1(
     node->>0,node->>1,p_rows-rows_used,p_reads-reads_used);
    rows_used:=rows_used+capture.logical_rows;reads_used:=reads_used+capture.logical_reads;
    witness:=jsonb_build_object('frontier',capture.frontier,'source_index',capture.source_index,'cluster_states',capture.cluster_states);
    captured:=captured||jsonb_build_object(frontier_key,witness);frontier_count:=frontier_count+1;
    frontiers:=frontiers||jsonb_build_object(frontier_key,capture.frontier);
    FOR entry IN SELECT key,value FROM jsonb_each(capture.source_index) LOOP
     work_used:=work_used+1;
     IF work_used>p_work THEN RAISE EXCEPTION 'metadata scope source merge budget exhausted' USING ERRCODE='54000';END IF;
     IF sources ? entry.key AND sources->entry.key IS DISTINCT FROM entry.value THEN
      RAISE EXCEPTION 'metadata scope source changed in walk' USING ERRCODE='40001';END IF;
     sources:=sources||jsonb_build_object(entry.key,entry.value);
    END LOOP;
   END IF;
   IF depth>=5 AND witness#>'{frontier,parents}'<>'[]'::jsonb THEN
    RAISE EXCEPTION 'metadata scope path exceeds proof depth' USING ERRCODE='54000';END IF;
   FOR parent IN SELECT value FROM jsonb_array_elements(witness#>'{frontier,parents}') LOOP
    pending:=pending||jsonb_build_array(jsonb_build_array(parent->>0,parent->>1,depth+1));
    IF jsonb_array_length(pending)>4096 THEN RAISE EXCEPTION 'metadata scope walk node limit exceeded' USING ERRCODE='54000';END IF;
   END LOOP;
  END LOOP;
  reaches:=reaches||jsonb_build_object(seed::text,found_root);
 END LOOP;
 RETURN jsonb_build_object('frontiers',frontiers,'witnesses',captured,'source_index',sources,'reaches',reaches,
  'rows',rows_used,'reads',reads_used,'work',work_used);
END;
$walk$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_access_label_early_closure_v1(
 p_packet jsonb,p_catalog jsonb,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $closure$
DECLARE queue jsonb:='[]';job jsonb;additions jsonb;seen jsonb:='{}';idx jsonb:='{}';
 outputs jsonb:='{}';seeds jsonb:='{}';guards jsonb:='{}';capture jsonb;state jsonb;row_value jsonb;
 k integer;pos integer:=0;n integer;typ text;identifier text;key text;model text;dotted text;
 ref text;account_id text;project_id text;binding_id text;role_id text;root_type text;root_id text;
 direct boolean;used_rows integer:=0;used_reads integer:=0;work integer:=0;
 walk jsonb;seed_list jsonb;item record;expected jsonb;source_key text;
 ancestor_keys jsonb:='{}';
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF jsonb_typeof(p_packet#>'{census,binding_ids}') IS DISTINCT FROM 'array'
  OR jsonb_typeof(p_packet#>'{census,selected}') IS DISTINCT FROM 'array'
  OR jsonb_typeof(p_packet->'root_state') IS DISTINCT FROM 'array'
  OR jsonb_typeof(p_catalog#>'{Live,Resources}') IS DISTINCT FROM 'array'
  OR p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000
  OR p_reads IS NULL OR p_reads NOT BETWEEN 1 AND 4096
  OR p_work IS NULL OR p_work NOT BETWEEN 1 AND 400000 THEN
  RAISE EXCEPTION 'early metadata closure input incomplete' USING ERRCODE='42501';END IF;
 root_type:=p_packet#>>'{census,root_type}';root_id:=p_packet#>>'{census,root_id}';
 IF coalesce(root_type,'') NOT IN ('iam.account','iam.project') OR coalesce(root_id,'')='' THEN
  RAISE EXCEPTION 'early metadata closure root invalid' USING ERRCODE='42501';END IF;
 queue:=jsonb_build_array(jsonb_build_array(0,root_type,root_id));
 FOR identifier IN SELECT jsonb_array_elements_text(p_packet#>'{census,binding_ids}') LOOP
  queue:=queue||jsonb_build_array(jsonb_build_array(8,'binding',identifier));
 END LOOP;
 WHILE pos<jsonb_array_length(queue) LOOP
  job:=queue->pos;pos:=pos+1;k:=(job->>0)::integer;typ:=job->>1;identifier:=job->>2;
  key:=jsonb_build_array(k,typ,identifier,'')::text;work:=work+1;
  IF work>p_work OR jsonb_array_length(queue)>16384 THEN
   RAISE EXCEPTION 'early metadata worklist budget exceeded' USING ERRCODE='54000';END IF;
  IF seen ? key THEN CONTINUE;END IF;
  seen:=seen||jsonb_build_object(key,true);additions:='[]';
  IF k=0 THEN
   -- Однозначное преобразование dotted member либо model Tuple.Object.
   SELECT min(r->>'ObjectType'),min((r->>'Module')||'.'||(r->>'Resource')) INTO model,dotted
   FROM jsonb_array_elements((p_catalog#>'{Live,Resources}')||
    coalesce(nullif(p_catalog#>'{Retired,Resources}','null'::jsonb),'[]'::jsonb)) r
   WHERE r->>'ObjectType'=typ OR (r->>'Module')||'.'||(r->>'Resource')=typ
   HAVING count(DISTINCT r->>'ObjectType')=1
    AND count(DISTINCT (r->>'Module')||'.'||(r->>'Resource'))=1;
   IF coalesce(model,'')='' OR coalesce(dotted,'')='' THEN
    RAISE EXCEPTION 'early output canonical catalog identity unavailable' USING ERRCODE='42501';END IF;
   key:=jsonb_build_array(model,identifier)::text;
   IF outputs ? key THEN CONTINUE;END IF;
   outputs:=outputs||jsonb_build_object(key,jsonb_build_object('model_type',model,'object_type',dotted,'object_id',identifier));
   seeds:=seeds||jsonb_build_object(key,true);
   FOREACH n IN ARRAY ARRAY[6,25,26,27,28,35] LOOP
    additions:=additions||jsonb_build_array(jsonb_build_array(n,model,identifier));
   END LOOP;
   FOREACH n IN ARRAY ARRAY[21,22] LOOP
    additions:=additions||jsonb_build_array(jsonb_build_array(n,dotted,identifier));
   END LOOP;
   direct:=dotted IN ('iam.account','iam.project','iam.role','iam.group','iam.serviceAccount','iam.accessBinding','iam.user');
   additions:=additions||jsonb_build_array(jsonb_build_array(CASE WHEN direct THEN 30 ELSE 2 END,dotted,identifier));
   IF NOT direct THEN
    additions:=additions||jsonb_build_array(jsonb_build_array(4,model,identifier));
    -- Материализатор читает все сохранённые рёбра предков, даже если
    -- обход области уже дошёл до изменяемого корня. Для выведенных из
    -- каталога типов материализатор предков не использует.
    IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_catalog#>'{Live,Resources}') r
     WHERE (r->>'Module')||'.'||(r->>'Resource')=dotted) THEN
     additions:=additions||jsonb_build_array(jsonb_build_array(3,model,identifier));
    END IF;
   END IF;
   IF model='cluster' THEN additions:=additions||jsonb_build_array(jsonb_build_array(36,'cluster',identifier));END IF;
   IF dotted='iam.user' THEN additions:=additions||jsonb_build_array(jsonb_build_array(31,dotted,identifier));END IF;
  ELSE
   capture:=kaname._authority_metadata_access_label_early_source_v1(k,typ,identifier,p_rows-used_rows,p_reads-used_reads);
   used_rows:=used_rows+(capture->>'rows')::integer;used_reads:=used_reads+(capture->>'reads')::integer;
   idx:=idx||jsonb_build_object(capture->>'key',jsonb_build_object('source',capture->'source','states',capture->'states'));
   IF (k IN (1,8,12,23) AND jsonb_array_length(capture->'states')<>1)
    OR (k IN (2,27,30) AND jsonb_array_length(capture->'states')>1)
    OR (k=3 AND jsonb_array_length(capture->'states')>4) THEN
    RAISE EXCEPTION 'early metadata source cardinality unconfirmed' USING ERRCODE='42501';END IF;
   FOR state IN SELECT value FROM jsonb_array_elements(capture->'states') LOOP
    row_value:=state->2;work:=work+1;
    IF work>p_work THEN RAISE EXCEPTION 'early metadata row work exceeded' USING ERRCODE='54000';END IF;
    IF k=3 THEN
     IF row_value->>'object_type' IS DISTINCT FROM typ
      OR row_value->>'object_id' IS DISTINCT FROM identifier
      OR coalesce(row_value->>'parent_type','')=''
      OR coalesce(row_value->>'parent_id','')=''
      OR coalesce(row_value->>'depth','') !~ '^[1-4]$' THEN
      RAISE EXCEPTION 'early materializer ancestor edge malformed' USING ERRCODE='42501';END IF;
     -- Берём отображение активного каталога, как _authority_resource_ancestor_graph_v2.
     -- Предок остаётся источником данных для вычисления.
     SELECT min((r->>'Module')||'.'||(r->>'Resource')) INTO dotted
     FROM jsonb_array_elements(p_catalog#>'{Live,Resources}') r
     WHERE r->>'ObjectType'=row_value->>'parent_type';
     IF dotted IS NOT NULL THEN
      IF (SELECT count(DISTINCT (r->>'Module')||'.'||(r->>'Resource'))
       FROM jsonb_array_elements(p_catalog#>'{Live,Resources}') r
       WHERE r->>'ObjectType'=row_value->>'parent_type')<>1 THEN
       RAISE EXCEPTION 'early ancestor catalog identity ambiguous' USING ERRCODE='42501';END IF;
      direct:=dotted IN ('iam.account','iam.project','iam.role','iam.group','iam.serviceAccount','iam.accessBinding','iam.user');
      additions:=additions||jsonb_build_array(jsonb_build_array(
       CASE WHEN direct THEN 30 ELSE 2 END,dotted,row_value->>'parent_id'));
      source_key:=jsonb_build_array(CASE WHEN direct THEN 30 ELSE 2 END,
       dotted,row_value->>'parent_id','')::text;
      ancestor_keys:=ancestor_keys||jsonb_build_object(source_key,true);
      IF dotted='iam.user' THEN
       additions:=additions||jsonb_build_array(jsonb_build_array(31,dotted,row_value->>'parent_id'));
      END IF;
     END IF;
    ELSIF k=8 THEN
     IF row_value->>'id' IS DISTINCT FROM identifier THEN
      RAISE EXCEPTION 'early binding source identity differs' USING ERRCODE='42501';END IF;
     guards:=guards||jsonb_build_object('binding:'||identifier,'share');
     FOREACH n IN ARRAY ARRAY[9,10,11] LOOP
      additions:=additions||jsonb_build_array(jsonb_build_array(n,'binding',identifier));
     END LOOP;
     role_id:=nullif(row_value->>'role_id','');
     IF role_id IS NOT NULL THEN
      guards:=guards||jsonb_build_object('role:'||role_id,'share');
      FOREACH n IN ARRAY ARRAY[12,13,14,15,37] LOOP
       additions:=additions||jsonb_build_array(jsonb_build_array(n,'role',role_id));
      END LOOP;
     END IF;
     CASE row_value->>'resource_type'
      WHEN 'account' THEN additions:=additions||jsonb_build_array(jsonb_build_array(23,'account',row_value->>'resource_id'));
      WHEN 'project' THEN additions:=additions||jsonb_build_array(jsonb_build_array(1,'project',row_value->>'resource_id'));
      WHEN 'cluster' THEN NULL;
      ELSE RAISE EXCEPTION 'early binding scope cannot be classified' USING ERRCODE='42501';
     END CASE;
    ELSIF k=10 THEN
     IF row_value->>'binding_id' IS DISTINCT FROM identifier THEN
      RAISE EXCEPTION 'early member owner differs' USING ERRCODE='42501';END IF;
     additions:=additions||jsonb_build_array(jsonb_build_array(0,row_value->>'object_type',row_value->>'object_id'));
    ELSIF k=11 THEN
     IF row_value->>'binding_id' IS DISTINCT FROM identifier THEN
      RAISE EXCEPTION 'early ledger owner differs' USING ERRCODE='42501';END IF;
     ref:=row_value->>'object';
     IF coalesce(ref,'')='' OR position(':' IN ref)<=1 OR position(':' IN ref)=length(ref)
      OR position(':' IN substr(ref,position(':' IN ref)+1))>0 THEN
      RAISE EXCEPTION 'early ledger actual output malformed' USING ERRCODE='42501';END IF;
     additions:=additions||jsonb_build_array(jsonb_build_array(0,split_part(ref,':',1),substr(ref,position(':' IN ref)+1)));
     IF coalesce(row_value->>'member_object_type','')<>'' OR coalesce(row_value->>'member_object_id','')<>'' THEN
      additions:=additions||jsonb_build_array(jsonb_build_array(0,row_value->>'member_object_type',row_value->>'member_object_id'));
     END IF;
    ELSIF k IN (21,22,35) THEN
     binding_id:=row_value->>'binding_id';
     additions:=additions||jsonb_build_array(jsonb_build_array(8,'binding',binding_id));
    END IF;
    -- Точные current/retained owning scopes для object/carrier graph.
    account_id:='';project_id:='';
    IF k=1 THEN account_id:=row_value->>'account_id';
    ELSIF k=12 THEN account_id:=row_value->>'account_id';project_id:=row_value->>'project_id';
    ELSIF k=4 THEN account_id:=row_value->>'account_id';project_id:=row_value->>'project_id';
    ELSIF k=2 THEN account_id:=row_value->>'parent_account_id';project_id:=row_value->>'parent_project_id';
    ELSIF k=31 THEN account_id:=row_value->>'account_id';
    ELSIF k=30 THEN
     CASE typ
      WHEN 'iam.account' THEN account_id:=identifier;
      WHEN 'iam.project' THEN account_id:=row_value->>'account_id';project_id:=identifier;
      WHEN 'iam.role' THEN account_id:=row_value->>'account_id';project_id:=row_value->>'project_id';
      WHEN 'iam.group','iam.serviceAccount' THEN account_id:=row_value->>'account_id';
      WHEN 'iam.accessBinding' THEN
       IF row_value->>'resource_type'='account' THEN account_id:=row_value->>'resource_id';
       ELSIF row_value->>'resource_type'='project' THEN project_id:=row_value->>'resource_id';END IF;
      ELSE NULL;
     END CASE;
    END IF;
    IF coalesce(account_id,'')<>'' THEN additions:=additions||jsonb_build_array(jsonb_build_array(23,'account',account_id));END IF;
    IF coalesce(project_id,'')<>'' THEN additions:=additions||jsonb_build_array(jsonb_build_array(1,'project',project_id));END IF;
   END LOOP;
  END IF;
  queue:=queue||additions;
  IF (SELECT count(*) FROM jsonb_object_keys(idx))>4096 OR (SELECT count(*) FROM jsonb_object_keys(outputs))>4096
   OR (SELECT count(*) FROM jsonb_object_keys(guards))>4096 THEN
   RAISE EXCEPTION 'early metadata closure key bound exceeded' USING ERRCODE='54000';END IF;
 END LOOP;
 -- Для пустой проекции требуется доказательство защиты от вставки.
 -- Пока его нет, отклоняем попытку. Повторная сверка подтверждает
 -- существующую проекцию и её область под штатными блокировками.
 FOR source_key IN SELECT jsonb_object_keys(ancestor_keys) LOOP
  work:=work+1;
  IF work>p_work THEN RAISE EXCEPTION 'early ancestor validation work exhausted' USING ERRCODE='54000';END IF;
  IF jsonb_typeof(idx->source_key->'states') IS DISTINCT FROM 'array'
   OR jsonb_array_length(idx->source_key->'states')<>1 THEN
   RAISE EXCEPTION 'early ancestor projection lacks a present owning-scope witness: %',source_key
    USING ERRCODE='42501';END IF;
 END LOOP;
 -- Ранний root/carrier census должен совпасть с физическими чтениями ниже.
 source_key:=jsonb_build_array(30,root_type,root_id,'')::text;
 IF idx->source_key->'states' IS DISTINCT FROM jsonb_build_array(p_packet->'root_state') THEN
  RAISE EXCEPTION 'early metadata root changed during discovery' USING ERRCODE='40001';END IF;
 FOR expected IN SELECT value FROM jsonb_array_elements(p_packet#>'{census,selected}') LOOP
  source_key:=jsonb_build_array(8,'binding',expected#>>'{2,id}','')::text;
  IF idx->source_key->'states' IS DISTINCT FROM jsonb_build_array(jsonb_build_array(expected->0,expected->1,expected->2)) THEN
   RAISE EXCEPTION 'early metadata carrier changed during discovery' USING ERRCODE='40001';END IF;
  source_key:=jsonb_build_array(12,'role',expected#>>'{5,id}','')::text;
  IF idx->source_key->'states' IS DISTINCT FROM jsonb_build_array(jsonb_build_array(expected->3,expected->4,expected->5)) THEN
   RAISE EXCEPTION 'early metadata role changed during discovery' USING ERRCODE='40001';END IF;
  IF expected#>>'{2,resource_type}'='project' THEN
   source_key:=jsonb_build_array(1,'project',expected#>>'{2,resource_id}','')::text;
   IF idx->source_key->'states' IS DISTINCT FROM jsonb_build_array(jsonb_build_array(expected->6,expected->7,expected->8)) THEN
    RAISE EXCEPTION 'early metadata project changed during discovery' USING ERRCODE='40001';END IF;
  END IF;
 END LOOP;
 SELECT coalesce(jsonb_agg(s.value::jsonb ORDER BY s.value COLLATE "C"),'[]'::jsonb) INTO seed_list FROM jsonb_object_keys(seeds) AS s(value);
 walk:=kaname._authority_metadata_access_label_early_walk_v1(seed_list,split_part(root_type,'.',2),root_id,
  p_rows-used_rows,p_reads-used_reads,p_work-work);
 used_rows:=used_rows+(walk->>'rows')::integer;used_reads:=used_reads+(walk->>'reads')::integer;work:=work+(walk->>'work')::integer;
 FOR item IN SELECT * FROM jsonb_each(walk->'source_index') LOOP
  IF idx ? item.key AND idx->item.key IS DISTINCT FROM item.value THEN
   RAISE EXCEPTION 'early metadata overlapping frontier history changed' USING ERRCODE='40001';END IF;
  idx:=idx||jsonb_build_object(item.key,item.value);
 END LOOP;
 -- Аккаунт может обнаружиться только на пути к родителю. Захватываем
 -- его через тот же источник владения, что и аккаунты самих выходов.
 FOR account_id IN
  SELECT a.id FROM (
   SELECT f.value->>'object_id' AS id FROM jsonb_each(walk->'frontiers') f
    WHERE f.value->>'object_type'='account'
   UNION
   SELECT p.value->>1 FROM jsonb_each(walk->'frontiers') f
    CROSS JOIN LATERAL jsonb_array_elements(f.value->'parents') p
    WHERE p.value->>0='account'
   UNION
   SELECT o.value->>'object_id' FROM jsonb_each(outputs) o WHERE o.value->>'model_type'='account'
  ) a ORDER BY a.id COLLATE "C"
 LOOP
  IF coalesce(account_id,'')='' THEN
   RAISE EXCEPTION 'early metadata frontier account identity missing' USING ERRCODE='42501';END IF;
  key:=jsonb_build_array(23,'account',account_id,'')::text;
  IF NOT (idx ? key) THEN
   capture:=kaname._authority_metadata_access_label_early_source_v1(
    23,'account',account_id,p_rows-used_rows,p_reads-used_reads);
   used_rows:=used_rows+(capture->>'rows')::integer;
   used_reads:=used_reads+(capture->>'reads')::integer;
   idx:=idx||jsonb_build_object(key,jsonb_build_object('source',capture->'source','states',capture->'states'));
  END IF;
  work:=work+1;
  IF jsonb_array_length(idx->key->'states') IS DISTINCT FROM 1
   OR idx->key#>>'{states,0,2,id}' IS DISTINCT FROM account_id THEN
   RAISE EXCEPTION 'early metadata frontier account changed during discovery' USING ERRCODE='40001';END IF;
  source_key:=jsonb_build_array(30,'iam.account',account_id,'')::text;
  IF idx ? source_key AND idx->source_key->'states' IS DISTINCT FROM idx->key->'states' THEN
   RAISE EXCEPTION 'early metadata account histories differ' USING ERRCODE='40001';END IF;
 END LOOP;
 -- Роль или привязка на пути родителей требует SOURCE guard даже при
 -- пустом чтении. Независимый replay после ожиданий сравнит и этот предикат.
 FOR item IN SELECT * FROM jsonb_each(idx)
  WHERE value#>>'{source,kind}'='30' AND value#>>'{source,type}' IN ('iam.role','iam.accessBinding')
 LOOP
  key:=CASE item.value#>>'{source,type}' WHEN 'iam.role' THEN 'role:' ELSE 'binding:' END
   ||(item.value#>>'{source,id}');
  IF key IS NULL OR key !~ '^(role|binding):[^:#*[:space:][:cntrl:]]+$' THEN
   RAISE EXCEPTION 'early metadata frontier guard identity invalid' USING ERRCODE='42501';END IF;
  guards:=guards||jsonb_build_object(key,'share');
  work:=work+1;
 END LOOP;
 IF used_rows>p_rows OR used_reads>p_reads OR work>p_work
  OR (SELECT count(*) FROM jsonb_object_keys(idx))>4096
  OR (SELECT count(*) FROM jsonb_object_keys(guards))>4096 THEN
  RAISE EXCEPTION 'early metadata shared closure budget exceeded' USING ERRCODE='54000';END IF;
 RETURN jsonb_build_object('source_index',idx,'outputs',outputs,'carrier_source_guards',guards,
  'frontier',walk,'rows',used_rows,'reads',used_reads,'work',work);
END;
$closure$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_access_label_discovery_fence_v1(p_closure jsonb)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $check$
DECLARE proof jsonb; entry record;state jsonb;account_id text;need_global boolean:=false;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
  OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'full'
  OR current_setting('transaction_isolation')<>'read committed'
  OR coalesce(proof->>'mode','') NOT IN ('accounts','global')
  OR NOT EXISTS(SELECT 1 FROM pg_temp.kaname_authority_consumer WHERE NOT finalized)
  OR jsonb_typeof(p_closure->'source_index') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_closure->'outputs') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_closure#>'{frontier,frontiers}') IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'metadata independent discovery required before finalize' USING ERRCODE='42501';END IF;
 -- Пока RC closure не дополнил account23 для всех frontier endpoints,
 -- отказываем. Нельзя признать account fence полным только по старому списку23.
 FOR account_id IN
  SELECT f.value->>'object_id' FROM jsonb_each(p_closure#>'{frontier,frontiers}') f
   WHERE f.value->>'object_type'='account'
  UNION
  SELECT parent.value->>1 FROM jsonb_each(p_closure#>'{frontier,frontiers}') f
   CROSS JOIN LATERAL jsonb_array_elements(f.value->'parents') parent
   WHERE parent.value->>0='account'
  UNION
  SELECT o.value->>'object_id' FROM jsonb_each(p_closure->'outputs') o
   WHERE o.value->>'model_type'='account'
 LOOP
  IF NOT coalesce((p_closure->'source_index') ? jsonb_build_array(23,'account',account_id,'')::text,false) THEN
   RAISE EXCEPTION 'metadata frontier account lacks complete physical capture' USING ERRCODE='42501';END IF;
 END LOOP;
 FOR entry IN SELECT * FROM jsonb_each(p_closure->'source_index') LOOP
  IF entry.value#>>'{source,kind}'='23' THEN
   account_id:=entry.value#>>'{source,id}';
   IF jsonb_typeof(entry.value->'states') IS DISTINCT FROM 'array'
    OR jsonb_array_length(entry.value->'states') IS DISTINCT FROM 1
    OR entry.value#>>'{states,0,2,id}' IS DISTINCT FROM account_id THEN
    RAISE EXCEPTION 'metadata account source missing' USING ERRCODE='42501';END IF;
   IF proof->>'mode'='accounts' AND NOT coalesce((proof->'accounts') ? account_id,false) THEN
    RAISE EXCEPTION 'metadata footprint exceeds signed accounts; restage required' USING ERRCODE='P1034';END IF;
  ELSIF entry.value#>>'{source,kind}'='8' THEN
   FOR state IN SELECT value FROM jsonb_array_elements(entry.value->'states') LOOP
    need_global:=need_global OR state#>>'{2,resource_type}'='cluster';
   END LOOP;
  END IF;
 END LOOP;
 FOR entry IN SELECT * FROM jsonb_each(p_closure->'outputs') LOOP
  need_global:=need_global OR entry.value->>'model_type'='cluster';
 END LOOP;
 IF need_global AND proof->>'mode'<>'global' THEN
  RAISE EXCEPTION 'metadata cluster footprint requires fresh global entry' USING ERRCODE='P1034';END IF;
END;
$check$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE signature text; recipient record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 FOREACH signature IN ARRAY ARRAY[
  '_authority_metadata_access_label_carrier_census_v1(text,jsonb,jsonb,integer,integer,integer)',
  '_authority_metadata_access_label_prefinal_carriers_v1(text,text,text,jsonb,jsonb,integer,integer,integer)',
  '_authority_metadata_access_label_early_source_v1(integer,text,text,integer,integer)',
  '_authority_metadata_access_label_early_frontier_v1(text,text,integer,integer)',
  '_authority_metadata_access_label_early_walk_v1(jsonb,text,text,integer,integer,integer)',
  '_authority_metadata_access_label_early_closure_v1(jsonb,jsonb,integer,integer,integer)',
  '_authority_metadata_access_label_discovery_fence_v1(jsonb)'
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
DROP FUNCTION kaname._authority_metadata_access_label_discovery_fence_v1(jsonb);
DROP FUNCTION kaname._authority_metadata_access_label_early_closure_v1(jsonb,jsonb,integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_access_label_early_walk_v1(jsonb,text,text,integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_access_label_early_frontier_v1(text,text,integer,integer);
DROP FUNCTION kaname._authority_metadata_access_label_early_source_v1(integer,text,text,integer,integer);
DROP FUNCTION kaname._authority_metadata_access_label_prefinal_carriers_v1(text,text,text,jsonb,jsonb,integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_access_label_carrier_census_v1(text,jsonb,jsonb,integer,integer,integer);
