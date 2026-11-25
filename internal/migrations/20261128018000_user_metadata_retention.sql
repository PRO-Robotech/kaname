-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- User использует тот же расчёт old ledger, secondary Tuple.Object и точных
-- desired-координат. Область iam.user выводится штатной проекцией из K31.
-- +goose StatementBegin
DO $specialize$
DECLARE
    item record;
    pair jsonb;
    predecessor text;
    body text;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_metadata_group_member_partition_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer)',
         '_authority_metadata_user_member_partition_v1',
         'p_root_type text,p_root_id text,p_bindings text[],p_index jsonb,p_catalog jsonb,p_frontiers jsonb,p_rows integer,p_work integer',
         'a763c093ce4412e52da32a8f19f964efa8fdc86fd4d3c65a8a6b252dd91dd951',
         'a399b12146c382fbd910d6529ed8bb9c0ee65038e75b27443b67cc9062c3141f',
         $changes$[
  [
    "'iam.group'",
    "'iam.user'"
  ],
  [
    "root_model:='iam_group'",
    "root_model:='iam_user'"
  ]
]$changes$::jsonb),
        ('_authority_metadata_group_old_facts_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer)',
         '_authority_metadata_user_old_facts_v1',
         'p_root_type text,p_root_id text,p_bindings text[],p_index jsonb,p_catalog jsonb,p_frontiers jsonb,p_rows integer,p_work integer',
         '7e46fcee2161c3899c7f1b27224ae0dc802d43bb2795a312782d9e27292408b7',
         'e9e713adac23233d139105c45e22cb4833abd6aafaa29e9b278f39eb764c8d27',
         $changes$[
  [
    "'iam.group'",
    "'iam.user'"
  ],
  [
    "_authority_metadata_group_member_partition_v1(",
    "_authority_metadata_user_member_partition_v1("
  ]
]$changes$::jsonb),
        ('_authority_metadata_group_retention_plan_v1(jsonb,jsonb,jsonb,jsonb,text,jsonb,jsonb,integer)',
         '_authority_metadata_user_retention_plan_v1',
         'p_index jsonb,p_catalog jsonb,p_outputs jsonb,p_old_outputs jsonb,p_root_type text,p_old jsonb,p_new jsonb,p_work integer',
         '089322e2575c95a7ba5f440bc9c53ce9855d255cf301cc866c50d94f28352d71',
         'bc9ba49c0c0241bc862323d8e2ef13bf60ca9358ec39fd6f6e9b8ee8fe0fefac',
         $changes$[
  [
    "'iam.group'",
    "'iam.user'"
  ],
  [
    "(p_old-ARRAY['name','description','labels','access_labels']) IS DISTINCT FROM\n     (p_new-ARRAY['name','description','labels','access_labels'])",
    "(p_old-ARRAY['labels','access_labels']) IS DISTINCT FROM\n     (p_new-ARRAY['labels','access_labels'])"
  ]
]$changes$::jsonb)
    ) s(signature,name,args,predecessor_digest,body_digest,changes) LOOP
        SELECT prosrc INTO STRICT predecessor FROM pg_catalog.pg_proc
        WHERE oid=to_regprocedure('kaname.'||item.signature)
            AND proowner=current_user::regrole AND NOT prosecdef AND provolatile='i';
        IF encode(sha256(convert_to(predecessor,'UTF8')),'hex') IS DISTINCT FROM item.predecessor_digest THEN
            RAISE EXCEPTION 'user retention predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=predecessor;
        FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
            IF length(pair->>0)=0
                OR (length(body)-length(replace(body,pair->>0,'')))/length(pair->>0)<>1 THEN
                RAISE EXCEPTION 'user retention specialization differs: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,pair->>0,pair->>1);
        END LOOP;
        IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.body_digest THEN
            RAISE EXCEPTION 'user retention body differs: %',item.name USING ERRCODE='55000';
        END IF;
        EXECUTE format('CREATE FUNCTION kaname.%I(%s) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE
            SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS %L',item.name,item.args,body);
    END LOOP;
END;
$specialize$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_retention_prepare_v1(p_rows integer,p_reads integer,p_work integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $prepare$
DECLARE
    saved jsonb;
    images jsonb;
    held jsonb;
    replay jsonb;
    census jsonb;
    idx jsonb;
    uid text;
    root_state jsonb;
    memberships jsonb;
    held_users jsonb;
    held_memberships jsonb;
    projection jsonb;
    required jsonb;
    account_id text;
    bundle record;
    catalog jsonb;
    member_rows jsonb;
    ledger_rows jsonb;
    holders text[];
    frontiers jsonb;
    old_outputs jsonb;
    plan jsonb;
    inputs jsonb;
    packet jsonb;
    used_work integer:=3;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF p_rows IS NULL OR p_rows NOT BETWEEN 3 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 3 AND 4096
        OR p_work IS NULL OR p_work NOT BETWEEN 3 AND 400000 THEN
        RAISE EXCEPTION 'user retention prepare budget invalid' USING ERRCODE='54000';END IF;
    saved:=kaname._authority_metadata_access_label_stashed_v1();
    images:=saved->'user_images'; held:=saved->'user_held'; replay:=held->'replay';
    census:=replay->'census'; idx:=replay->'source_index';
    root_state:=saved#>'{root,root_state}'; uid:=images->>'root_id';
    memberships:=images->'membership_states';
    IF saved ? 'retention' OR coalesce(uid,'') COLLATE "C" !~ '^usr[a-zA-Z0-9_-]{1,61}$'
        OR images->>'root_type' IS DISTINCT FROM 'iam.user' OR images->>'root_model' IS DISTINCT FROM 'iam_user'
        OR images->>'mode' IS DISTINCT FROM 'access_labels' OR images->'root_source_kind' IS DISTINCT FROM '30'::jsonb
        OR images->'nonce' IS DISTINCT FROM saved#>'{plan,nonce}' OR held->'nonce' IS DISTINCT FROM images->'nonce'
        OR replay->'nonce' IS DISTINCT FROM held->'nonce' OR replay->'backend' IS DISTINCT FROM saved#>'{plan,backend}'
        OR replay->'transaction_id' IS DISTINCT FROM saved#>'{plan,transaction_id}'
        OR saved#>'{root,root_coordinate}' IS DISTINCT FROM jsonb_build_array('iam.user',uid)
        OR images->'old_row' IS DISTINCT FROM root_state->2 OR images#>>'{old_row,id}' IS DISTINCT FROM uid
        OR held->'root_physical' IS DISTINCT FROM jsonb_build_object('table','users','id',uid,'xmin',root_state->>0,'ctid',root_state->>1)
        OR images->'root_physical' IS DISTINCT FROM held->'root_physical'
        OR images->'update_question' IS DISTINCT FROM saved#>'{root,update_question}'
        OR held->'update_question' IS DISTINCT FROM images->'update_question'
        OR images#>>'{update_question,relation}' IS DISTINCT FROM 'record_writer'
        OR census IS DISTINCT FROM saved#>'{root,census}' OR census->>'root_id' IS DISTINCT FROM uid
        OR census->>'root_type' IS DISTINCT FROM 'iam.user' OR census->'old_root' IS DISTINCT FROM images->'old_row'
        OR census->'new_labels' IS DISTINCT FROM images#>'{new_row,access_labels}'
        OR census->'new_ordinary_labels' IS DISTINCT FROM images#>'{new_row,labels}'
        OR jsonb_typeof(memberships) IS DISTINCT FROM 'array' OR memberships IS DISTINCT FROM saved#>'{root,membership_states}'
        OR idx#>ARRAY[jsonb_build_array(30,'iam.user',uid,'')::text,'states'] IS DISTINCT FROM jsonb_build_array(root_state)
        OR idx#>ARRAY[jsonb_build_array(31,'iam.user',uid,'')::text,'states'] IS DISTINCT FROM memberships
        OR jsonb_typeof(census->'binding_ids') IS DISTINCT FROM 'array'
        OR jsonb_typeof(replay->'held_rows') IS DISTINCT FROM 'array'
        OR jsonb_typeof(replay->'frontier_witnesses') IS DISTINCT FROM 'object'
        OR jsonb_typeof(saved#>'{discovery,outputs}') IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'user retention evidence differs from held discovery' USING ERRCODE='42501';END IF;
    used_work:=used_work+2*jsonb_array_length(memberships)+jsonb_array_length(replay->'held_rows');
    IF used_work>p_work THEN RAISE EXCEPTION 'user retention membership work exceeded' USING ERRCODE='54000';END IF;
    -- Фронт и source replay могут держать одну физическую строку дважды.
    -- Собираем точные версии один раз, сохраняя и доказанный пустой K31.
    WITH versions AS (
        SELECT DISTINCT h->>'relation' AS rel,jsonb_build_array(h->'xmin',h->'tid',h->'data') AS state
        FROM jsonb_array_elements(replay->'held_rows') h
        WHERE (h->>'relation'=('kaname.users'::regclass)::oid::text AND h#>>'{data,id}'=uid)
           OR (h->>'relation'=('kaname.memberships'::regclass)::oid::text AND h#>>'{data,user_id}'=uid)
    )
    SELECT coalesce(jsonb_agg(state ORDER BY state::text COLLATE "C") FILTER (WHERE rel=('kaname.users'::regclass)::oid::text),'[]'),
           coalesce(jsonb_agg(state ORDER BY state::text COLLATE "C") FILTER (WHERE rel=('kaname.memberships'::regclass)::oid::text),'[]')
        INTO held_users,held_memberships FROM versions;
    IF held_users IS DISTINCT FROM jsonb_build_array(root_state) OR held_memberships IS DISTINCT FROM memberships THEN
        RAISE EXCEPTION 'user retention physical holds differ from K30 or K31' USING ERRCODE='40001';END IF;
    projection:=kaname._authority_resource_projection_v2(idx,'iam.user',uid);
    IF projection->'projection' IS DISTINCT FROM images->'old_row'
        OR projection->'current_accounts' IS DISTINCT FROM census->'account_ids'
        OR projection->>'current_project' IS DISTINCT FROM ''
        OR jsonb_array_length(projection->'current_accounts')<>jsonb_array_length(memberships) THEN
        RAISE EXCEPTION 'user retention membership scope differs' USING ERRCODE='40001';END IF;
    required:=projection->'required';
    FOR account_id IN SELECT jsonb_array_elements_text(projection->'current_accounts') LOOP
        IF idx#>>ARRAY[jsonb_build_array(23,'account',account_id,'')::text,'states','0','2','id'] IS DISTINCT FROM account_id THEN
            RAISE EXCEPTION 'user retention account is absent' USING ERRCODE='40001';END IF;
        required:=required||jsonb_build_object(jsonb_build_array(23,'account',account_id,'')::text,true);
    END LOOP;
    IF has_function_privilege((saved#>>'{plan,invoker_oid}')::oid,'kaname.authority_protocol_read_bundle()','EXECUTE') IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'user retention requires original catalog access' USING ERRCODE='42501';END IF;
    SELECT * INTO STRICT bundle FROM kaname.authority_protocol_read_bundle();
    IF to_jsonb(bundle.catalog_id) IS DISTINCT FROM saved->'catalog_id' OR octet_length(bundle.catalog_json) NOT BETWEEN 1 AND 8388608
        OR encode(sha256(bundle.catalog_json),'hex') IS DISTINCT FROM bundle.catalog_id THEN
        RAISE EXCEPTION 'user retention catalog differs' USING ERRCODE='P1034';END IF;
    catalog:=convert_from(bundle.catalog_json,'UTF8')::jsonb;
    member_rows:=kaname._authority_resource_require_capture_v2(idx,21,'iam.user',uid)->'states';
    ledger_rows:=kaname._authority_resource_require_capture_v2(idx,22,'iam.user',uid)->'states';
    required:=required||jsonb_build_object(jsonb_build_array(21,'iam.user',uid,'')::text,true,
        jsonb_build_array(22,'iam.user',uid,'')::text,true);
    used_work:=used_work+2*(jsonb_array_length(member_rows)+jsonb_array_length(ledger_rows)+jsonb_array_length(census->'binding_ids'));
    IF used_work>p_work THEN RAISE EXCEPTION 'user retention historical holder work exceeded' USING ERRCODE='54000';END IF;
    IF EXISTS(SELECT FROM jsonb_array_elements_text(census->'binding_ids') x(id)
        CROSS JOIN LATERAL (SELECT idx#>ARRAY[jsonb_build_array(8,'binding',x.id,'')::text,'states','0','2'] AS b) s
        WHERE s.b->>'id' IS DISTINCT FROM x.id
            OR (CASE s.b->>'resource_type' WHEN 'cluster' THEN s.b->>'resource_id'='cluster_root'
                WHEN 'account' THEN (projection->'accounts') ? (s.b->>'resource_id') ELSE false END) IS DISTINCT FROM true)
        OR EXISTS(SELECT FROM jsonb_array_elements(member_rows) m WHERE m#>>'{2,object_type}' IS DISTINCT FROM 'iam.user'
            OR m#>>'{2,object_id}' IS DISTINCT FROM uid OR coalesce(m#>>'{2,binding_id}','')='')
        OR EXISTS(SELECT FROM jsonb_array_elements(ledger_rows) m WHERE m#>>'{2,member_object_type}' IS DISTINCT FROM 'iam.user'
            OR m#>>'{2,member_object_id}' IS DISTINCT FROM uid OR coalesce(m#>>'{2,binding_id}','')='') THEN
        RAISE EXCEPTION 'user retention holder coordinate differs' USING ERRCODE='42501';END IF;
    -- K21 и K22 сохраняют историю, даже когда текущая роль уже не отбирает
    -- User. K35 в общем плане проверяет отдельно каждого держателя Tuple.Object.
    SELECT ARRAY(SELECT id FROM (
        SELECT value COLLATE "C" AS id FROM jsonb_array_elements_text(census->'binding_ids')
        UNION SELECT (m#>>'{2,binding_id}') COLLATE "C" FROM jsonb_array_elements(member_rows) m
        UNION SELECT (m#>>'{2,binding_id}') COLLATE "C" FROM jsonb_array_elements(ledger_rows) m
    ) historical ORDER BY id) INTO holders;
    SELECT coalesce(jsonb_object_agg(f.key,f.value->'frontier'),'{}'),used_work+count(*)::integer
        INTO frontiers,used_work FROM jsonb_each(replay->'frontier_witnesses') f;
    IF cardinality(holders)>4096 OR used_work>p_work THEN
        RAISE EXCEPTION 'user retention frontier budget exceeded' USING ERRCODE='54000';END IF;
    old_outputs:=kaname._authority_metadata_user_old_facts_v1('iam.user',uid,holders,idx,catalog,frontiers,p_rows-3,p_work-used_work);
    IF old_outputs->'old_root' IS DISTINCT FROM root_state THEN
        RAISE EXCEPTION 'user retention OLD differs' USING ERRCODE='40001';END IF;
    used_work:=used_work+(old_outputs->>'work')::integer;
    plan:=kaname._authority_metadata_user_retention_plan_v1(idx,catalog,saved#>'{discovery,outputs}',old_outputs,
        'iam.user',images->'old_row',images->'new_row',p_work-used_work);
    used_work:=used_work+(plan->>'work')::integer;
    inputs:=kaname._authority_metadata_access_label_retention_inputs_v1(idx,plan,p_work-used_work);
    used_work:=used_work+(inputs->>'work')::integer;
    IF used_work IS NULL OR used_work>p_work THEN RAISE EXCEPTION 'user retention input work exceeded' USING ERRCODE='54000';END IF;
    packet:=jsonb_build_object('nonce',images->'nonce','root_type','iam.user','root_id',uid,'catalog',catalog,
        'plan',plan,'partition_required',required||(old_outputs#>'{partition,required}'),'candidate_facts',old_outputs->'facts');
    IF octet_length(saved::text)::bigint+octet_length(packet::text)+16>67108864 THEN
        RAISE EXCEPTION 'user retention custody exceeds storage budget' USING ERRCODE='54000';END IF;
    UPDATE pg_temp.kaname_authority_metadata_discovery d SET prepared=d.prepared||jsonb_build_object('retention',packet)
        WHERE d.singleton AND d.prepared=saved AND NOT (d.prepared ? 'retention');
    IF NOT FOUND THEN RAISE EXCEPTION 'user retention owner custody changed' USING ERRCODE='42501';END IF;
    RETURN inputs||jsonb_build_object('rows',3,'reads',3,'work',used_work);
END;
$prepare$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_retention_compile_v1(p_desired jsonb,p_work integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $compile$
DECLARE
    saved jsonb;
    images jsonb;
    packet jsonb;
    idx jsonb;
    uid text;
    certificate jsonb;
    sources jsonb;
    used_work integer;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF p_work IS NULL OR p_work NOT BETWEEN 1 AND 400000 THEN
        RAISE EXCEPTION 'user retention certificate budget invalid' USING ERRCODE='54000';END IF;
    saved:=kaname._authority_metadata_access_label_stashed_v1();
    images:=saved->'user_images'; packet:=saved->'retention'; idx:=saved#>'{user_held,replay,source_index}'; uid:=images->>'root_id';
    IF jsonb_typeof(packet) IS DISTINCT FROM 'object' OR packet->>'root_type' IS DISTINCT FROM 'iam.user'
        OR packet->>'root_id' IS DISTINCT FROM uid OR packet->'nonce' IS DISTINCT FROM saved#>'{plan,nonce}'
        OR images->'nonce' IS DISTINCT FROM packet->'nonce' OR saved#>'{user_held,nonce}' IS DISTINCT FROM packet->'nonce'
        OR images->>'mode' IS DISTINCT FROM 'access_labels' OR saved#>'{root,root_coordinate}' IS DISTINCT FROM jsonb_build_array('iam.user',uid)
        OR idx#>ARRAY[jsonb_build_array(30,'iam.user',uid,'')::text,'states'] IS DISTINCT FROM jsonb_build_array(saved#>'{root,root_state}')
        OR idx#>ARRAY[jsonb_build_array(31,'iam.user',uid,'')::text,'states'] IS DISTINCT FROM images->'membership_states'
        OR jsonb_typeof(packet->'candidate_facts') IS DISTINCT FROM 'array' OR jsonb_typeof(packet->'partition_required') IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'user retention certificate custody differs' USING ERRCODE='42501';END IF;
    certificate:=kaname._authority_metadata_access_label_retention_certify_v1(idx,packet->'catalog',packet->'plan',p_desired,p_work-1);
    sources:=kaname._authority_resource_object_physical_sources_v2(idx,(packet->'partition_required')||(certificate->'required'));
    used_work:=1+(certificate->>'work')::integer+(sources->>'work')::integer;
    IF used_work IS NULL OR used_work>p_work THEN
        RAISE EXCEPTION 'user retention certificate work exceeded' USING ERRCODE='54000';END IF;
    RETURN jsonb_build_object(
        'receipt',jsonb_build_object('root_type','iam.user','root_id',uid,'old_labels',images#>'{old_row,access_labels}',
            'new_labels',images#>'{new_row,access_labels}','facts',packet->'candidate_facts'),
        'retention',jsonb_build_object('certificate',certificate,'sources',sources,
            'physical',jsonb_build_object('members',sources->'members','ledger',sources->'ledger'),
            'folded',jsonb_build_object('facts',sources->'facts')),
        'root_physical',images->'root_physical','old_row',images->'old_row','new_row',images->'new_row',
        'update_question',images->'update_question','rows',1,'reads',1,'work',used_work);
END;
$compile$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE
    fn regprocedure;
    grantee record;
BEGIN
    FOREACH fn IN ARRAY ARRAY[
        'kaname._authority_metadata_user_retention_compile_v1(jsonb,integer)'::regprocedure,
        'kaname._authority_metadata_user_member_partition_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer)'::regprocedure,
        'kaname._authority_metadata_user_old_facts_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer)'::regprocedure,
        'kaname._authority_metadata_user_retention_plan_v1(jsonb,jsonb,jsonb,jsonb,text,jsonb,jsonb,integer)'::regprocedure,
        'kaname._authority_metadata_user_retention_prepare_v1(integer,integer,integer)'::regprocedure
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
DROP FUNCTION kaname._authority_metadata_user_retention_compile_v1(jsonb,integer);
DROP FUNCTION kaname._authority_metadata_user_retention_prepare_v1(integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_user_retention_plan_v1(jsonb,jsonb,jsonb,jsonb,text,jsonb,jsonb,integer);
DROP FUNCTION kaname._authority_metadata_user_old_facts_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer);
DROP FUNCTION kaname._authority_metadata_user_member_partition_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer);
