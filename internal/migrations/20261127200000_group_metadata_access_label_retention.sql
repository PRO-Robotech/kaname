-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Для Group применяются те же правила сохранения выдач, что для нативных
-- ресурсов. Специализация ограничена физическим источником 30 и моделью
-- iam_group. Действующие функции и их отпечатки не меняются.
-- +goose StatementBegin
DO $specialize$
DECLARE
    item record;
    pair jsonb;
    predecessor text;
    body text;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_access_label_member_partition_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer)',
         '_authority_metadata_group_member_partition_v1',
         'p_root_type text,p_root_id text,p_bindings text[],p_index jsonb,p_catalog jsonb,p_frontiers jsonb,p_rows integer,p_work integer',
         '4654a6cb62d92fbdfcc2e0db90b7f2c1fc1580c505a2c03b6c2bbef54ce3a497',
         'a763c093ce4412e52da32a8f19f964efa8fdc86fd4d3c65a8a6b252dd91dd951',
         $changes$[
 [
  "p_root_type IS NULL OR (p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') AND (p_root_type !~ '^[^.:#*[:space:][:cntrl:]]+[.][^.:#*[:space:][:cntrl:]]+$' OR split_part(p_root_type,'.',1)='iam'))",
  "p_root_type IS DISTINCT FROM 'iam.group'"
 ],
 [
  " root_model:=CASE p_root_type WHEN 'iam.account' THEN 'account' WHEN 'iam.project' THEN 'project' WHEN 'iam.serviceAccount' THEN 'iam_service_account' END;\n IF p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN\n  SELECT count(*),min(r->>'ObjectType') INTO count_value,root_model\n  FROM jsonb_array_elements(p_catalog#>'{Live,Resources}') r\n  WHERE (r->>'Module')||'.'||(r->>'Resource')=p_root_type AND r->>'Module'<>'iam';\n  IF count_value<>1 OR coalesce(root_model,'') !~ '^[a-z][a-z0-9_]*$' THEN\n   RAISE EXCEPTION 'external retention root live model unconfirmed' USING ERRCODE='42501';END IF;\n END IF;\n\n IF p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN\n  work:=work+1;\n  IF work>p_work THEN RAISE EXCEPTION 'external retention root mapping budget exhausted' USING ERRCODE='54000';END IF;\n END IF;\n",
  " root_model:='iam_group';\n"
 ]
]$changes$::jsonb),
        ('_authority_access_label_old_facts_v2(text,text,text[],jsonb,jsonb,jsonb,integer,integer)',
         '_authority_metadata_group_old_facts_v1',
         'p_root_type text,p_root_id text,p_bindings text[],p_index jsonb,p_catalog jsonb,p_frontiers jsonb,p_rows integer,p_work integer',
         '2c1f7492f38356a22db5a5dde186fb3b2337e51a27a265be46ca7e2eef4bb723',
         '7e46fcee2161c3899c7f1b27224ae0dc802d43bb2795a312782d9e27292408b7',
         $changes$[
 [
  "p_root_type IS NULL OR (p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') AND (p_root_type !~ '^[^.:#*[:space:][:cntrl:]]+[.][^.:#*[:space:][:cntrl:]]+$' OR split_part(p_root_type,'.',1)='iam'))",
  "p_root_type IS DISTINCT FROM 'iam.group'"
 ],
 [
  "root:=kaname._authority_resource_require_capture_v2(p_index,\n  CASE WHEN p_root_type IN ('iam.account','iam.project','iam.serviceAccount') THEN 30 ELSE 2 END,p_root_type,p_root_id);",
  "root:=kaname._authority_resource_require_capture_v2(p_index,30,p_root_type,p_root_id);"
 ],
 [
  " OR (p_root_type IN ('iam.account','iam.project','iam.serviceAccount') AND row_value->>'id' IS DISTINCT FROM p_root_id)\n OR (p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') AND (row_value->>'object_type' IS DISTINCT FROM p_root_type\n  OR row_value->>'object_id' IS DISTINCT FROM p_root_id))\n",
  " OR row_value->>'id' IS DISTINCT FROM p_root_id\n"
 ],
 [
  "kaname._authority_access_label_member_partition_v1(",
  "kaname._authority_metadata_group_member_partition_v1("
 ]
]$changes$::jsonb),
        ('_authority_metadata_access_label_retention_plan_v1(jsonb,jsonb,jsonb,jsonb,text,jsonb,jsonb,integer)',
         '_authority_metadata_group_retention_plan_v1',
         'p_index jsonb,p_catalog jsonb,p_outputs jsonb,p_old_outputs jsonb,p_root_type text,p_old jsonb,p_new jsonb,p_work integer',
         '683ae6d0a044bc052e330bd1e75ac39b1541bf416ec6438ffce437d1359e4fb7',
         '089322e2575c95a7ba5f440bc9c53ce9855d255cf301cc866c50d94f28352d71',
         $changes$[
 [
  " work integer:=0; root_id text;root_kind integer;root_model text;count_value integer;external_root boolean;\nBEGIN\n external_root:=p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount');\n root_id:=CASE WHEN external_root THEN p_old->>'object_id' ELSE p_old->>'id' END;\n root_kind:=CASE WHEN external_root THEN 2 ELSE 30 END;\n",
  " work integer:=0; root_id text;\nBEGIN\n root_id:=p_old->>'id';\n"
 ],
 [
  "p_root_type IS NULL OR (external_root AND (p_root_type !~ '^[^.:#*[:space:][:cntrl:]]+[.][^.:#*[:space:][:cntrl:]]+$' OR split_part(p_root_type,'.',1)='iam'))",
  "p_root_type IS DISTINCT FROM 'iam.group'"
 ],
 [
  "  OR (NOT external_root AND (p_old-ARRAY['name','description','labels','access_labels']) IS DISTINCT FROM\n     (p_new-ARRAY['name','description','labels','access_labels']))\n  OR (external_root AND (p_old->>'object_type' IS DISTINCT FROM p_root_type\n   OR (p_old-ARRAY['labels','access_labels']) IS DISTINCT FROM (p_new-ARRAY['labels','access_labels'])))\n",
  "  OR (p_old-ARRAY['name','description','labels','access_labels']) IS DISTINCT FROM\n     (p_new-ARRAY['name','description','labels','access_labels'])\n"
 ],
 [
  " IF p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN\n  SELECT count(*),min(r->>'ObjectType') INTO count_value,root_model\n  FROM jsonb_array_elements(p_catalog#>'{Live,Resources}') r\n  WHERE (r->>'Module')||'.'||(r->>'Resource')=p_root_type AND r->>'Module'<>'iam';\n  IF count_value<>1 OR coalesce(root_model,'') !~ '^[a-z][a-z0-9_]*$' THEN\n   RAISE EXCEPTION 'external retention root live model unconfirmed' USING ERRCODE='42501';END IF;\n END IF;\n root_capture:=kaname._authority_resource_require_capture_v2(p_index,root_kind,p_root_type,root_id);\n",
  " root_capture:=kaname._authority_resource_require_capture_v2(p_index,30,p_root_type,root_id);\n"
 ],
 [
  "+CASE WHEN external_root THEN 1 ELSE 0 END",
  ""
 ]
]$changes$::jsonb)
    ) s(signature,name,args,predecessor_digest,body_digest,changes) LOOP
        SELECT prosrc INTO STRICT predecessor FROM pg_catalog.pg_proc
        WHERE oid=to_regprocedure('kaname.'||item.signature)
            AND proowner=current_user::regrole AND NOT prosecdef AND provolatile='i';
        IF encode(sha256(convert_to(predecessor,'UTF8')),'hex') IS DISTINCT FROM item.predecessor_digest THEN
            RAISE EXCEPTION 'group retention predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=predecessor;
        FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
            IF length(pair->>0)=0
                OR (length(body)-length(replace(body,pair->>0,'')))/length(pair->>0)<>1 THEN
                RAISE EXCEPTION 'group retention specialization differs: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,pair->>0,pair->>1);
        END LOOP;
        IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.body_digest THEN
            RAISE EXCEPTION 'group retention body differs: %',item.name USING ERRCODE='55000';
        END IF;
        EXECUTE format('CREATE FUNCTION kaname.%I(%s) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE
            SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS %L',item.name,item.args,body);
    END LOOP;
END;
$specialize$;
-- +goose StatementEnd

-- Вход для расчёта Go выводится из удержанного OLD, нового PATCH и всей
-- выборки носителей. Физический снимок и вопрос v_update остаются у владельца.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_retention_prepare_v1(
    p_patch jsonb,p_rename boolean,p_actor_type text,p_actor_id text,
    p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $prepare_retention$
DECLARE
    session_state jsonb;
    held jsonb;
    replay jsonb;
    census jsonb;
    source_index jsonb;
    physical jsonb;
    root_state jsonb;
    v_group text;
    old_row jsonb;
    new_row jsonb;
    invoker oid;
    bundle record;
    catalog jsonb;
    holders text[];
    frontiers jsonb;
    old_outputs jsonb;
    plan jsonb;
    inputs jsonb;
    packet jsonb;
    used_rows integer;
    used_reads integer;
    used_work integer;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF p_rows IS NULL OR p_rows NOT BETWEEN 4 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 10 AND 4096
        OR p_work IS NULL OR p_work NOT BETWEEN 6 AND 400000 THEN
        RAISE EXCEPTION 'group retention prepare budget invalid' USING ERRCODE='54000';
    END IF;
    session_state:=kaname._authority_metadata_access_label_stashed_v1();
    IF session_state ? 'retention' OR session_state#>>'{root,root_coordinate,0}' IS DISTINCT FROM 'iam.group' THEN
        RAISE EXCEPTION 'group retention is already prepared or root differs' USING ERRCODE='42501';
    END IF;
    invoker:=(session_state#>>'{plan,invoker_oid}')::oid;
    IF has_function_privilege(invoker,'kaname.authority_protocol_read_bundle()','EXECUTE') IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'group retention requires original catalog access' USING ERRCODE='42501';
    END IF;
    SELECT * INTO STRICT bundle FROM kaname.authority_protocol_read_bundle();
    IF to_jsonb(bundle.catalog_id) IS DISTINCT FROM session_state->'catalog_id'
        OR octet_length(bundle.catalog_json) NOT BETWEEN 1 AND 8388608
        OR encode(sha256(bundle.catalog_json),'hex') IS DISTINCT FROM bundle.catalog_id THEN
        RAISE EXCEPTION 'group retention catalog changed' USING ERRCODE='P1034';
    END IF;
    catalog:=convert_from(bundle.catalog_json,'UTF8')::jsonb;
    held:=kaname._authority_metadata_group_hold_and_replay_v1(
        p_patch,p_rename,p_actor_type,p_actor_id,p_rows-2,p_reads-2,p_work-2);
    used_rows:=2+(held->>'rows')::integer;
    used_reads:=2+(held->>'reads')::integer;
    used_work:=2+(held->>'work')::integer;
    replay:=held->'replay';
    census:=replay->'census';
    source_index:=replay->'source_index';
    physical:=held->'root_physical';
    root_state:=session_state#>'{root,root_state}';
    v_group:=session_state#>>'{root,root_coordinate,1}';
    old_row:=root_state->2;
    new_row:=old_row||p_patch;
    IF census->>'root_type' IS DISTINCT FROM 'iam.group'
        OR coalesce(v_group,'')='' OR census->>'root_id' IS DISTINCT FROM v_group
        OR census->'old_root' IS DISTINCT FROM old_row OR old_row->>'id' IS DISTINCT FROM v_group
        OR physical IS DISTINCT FROM jsonb_build_object('table','groups','id',v_group,
            'xmin',root_state->>0,'ctid',root_state->>1)
        OR held->'update_question' IS DISTINCT FROM session_state#>'{root,update_question}'
        OR jsonb_typeof(census->'binding_ids') IS DISTINCT FROM 'array'
        OR jsonb_typeof(replay->'frontier_witnesses') IS DISTINCT FROM 'object'
        OR jsonb_typeof(source_index) IS DISTINCT FROM 'object'
        OR new_row->'access_labels' IS DISTINCT FROM census->'new_labels' THEN
        RAISE EXCEPTION 'group retention held replay incomplete' USING ERRCODE='42501';
    END IF;
    SELECT coalesce(array_agg(b.id ORDER BY b.id COLLATE "C"),ARRAY[]::text[])
    INTO holders FROM jsonb_array_elements_text(census->'binding_ids') b(id);
    SELECT coalesce(jsonb_object_agg(f.key,f.value->'frontier'),'{}'),used_work+count(*)::integer
    INTO frontiers,used_work FROM jsonb_each(replay->'frontier_witnesses') f;
    IF used_work>p_work THEN
        RAISE EXCEPTION 'group retention frontier work exceeded' USING ERRCODE='54000';
    END IF;
    old_outputs:=kaname._authority_metadata_group_old_facts_v1(
        'iam.group',v_group,holders,source_index,catalog,frontiers,p_rows-used_rows,p_work-used_work);
    IF old_outputs->'old_root' IS DISTINCT FROM root_state THEN
        RAISE EXCEPTION 'group retention OLD projection changed' USING ERRCODE='40001';
    END IF;
    used_work:=used_work+(old_outputs->>'work')::integer;
    plan:=kaname._authority_metadata_group_retention_plan_v1(
        source_index,catalog,session_state#>'{discovery,outputs}',old_outputs,'iam.group',old_row,new_row,p_work-used_work);
    used_work:=used_work+(plan->>'work')::integer;
    inputs:=kaname._authority_metadata_access_label_retention_inputs_v1(source_index,plan,p_work-used_work);
    used_work:=used_work+(inputs->>'work')::integer;
    IF used_rows IS NULL OR used_rows NOT BETWEEN 1 AND p_rows OR used_reads IS NULL OR used_reads NOT BETWEEN 1 AND p_reads
        OR used_work IS NULL OR used_work NOT BETWEEN 1 AND p_work THEN
        RAISE EXCEPTION 'group retention prepare budget exceeded' USING ERRCODE='54000';
    END IF;
    packet:=jsonb_build_object(
        'source_index',source_index,'catalog',catalog,'plan',plan,
        'partition_required',old_outputs#>'{partition,required}','candidate_facts',old_outputs->'facts',
        'root_physical',physical,'root_type','iam.group','root_id',v_group,
        'root_source_kind',30,'root_model','iam_group','old_row',old_row,'new_row',new_row,
        'update_question',held->'update_question');
    IF octet_length(packet::text)>67108864 THEN
        RAISE EXCEPTION 'group retention private packet too large' USING ERRCODE='54000';
    END IF;
    UPDATE pg_temp.kaname_authority_metadata_discovery d
    SET prepared=jsonb_set(d.prepared,'{retention}',packet)
    WHERE d.singleton AND d.prepared=session_state AND NOT (d.prepared ? 'retention');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'group retention owner custody changed' USING ERRCODE='42501';
    END IF;
    RETURN inputs||jsonb_build_object('rows',used_rows,'reads',used_reads,'work',used_work);
END;
$prepare_retention$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE
    fn regprocedure;
    grantee record;
BEGIN
    FOREACH fn IN ARRAY ARRAY[
        'kaname._authority_metadata_group_member_partition_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer)'::regprocedure,
        'kaname._authority_metadata_group_old_facts_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer)'::regprocedure,
        'kaname._authority_metadata_group_retention_plan_v1(jsonb,jsonb,jsonb,jsonb,text,jsonb,jsonb,integer)'::regprocedure,
        'kaname._authority_metadata_group_retention_prepare_v1(jsonb,boolean,text,text,integer,integer,integer)'::regprocedure
    ] LOOP
        FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
            WHERE p.oid=fn AND a.grantee<>p.proowner
        LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
                CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE quote_ident(grantee.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_metadata_group_retention_prepare_v1(jsonb,boolean,text,text,integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_group_retention_plan_v1(jsonb,jsonb,jsonb,jsonb,text,jsonb,jsonb,integer);
DROP FUNCTION kaname._authority_metadata_group_old_facts_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer);
DROP FUNCTION kaname._authority_metadata_group_member_partition_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer);
