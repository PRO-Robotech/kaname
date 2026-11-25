-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Та же выборка старых привязок и тот же обход физических источников, что
-- у действующего metadata writer. Отдельные приватные функции позволяют
-- удержать существующий контракт до готовности Group replay и exact DML.
-- +goose StatementBegin
DO $specialize$
DECLARE
    item record;
    original text;
    body text;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_metadata_access_label_carrier_census_v1(text,jsonb,jsonb,integer,integer,integer)',
         '_authority_metadata_group_census_v1',
         'p_root_type text,p_old_root jsonb,p_new_labels jsonb,p_rows integer,p_reads integer,p_work integer',
         'STABLE','3c7583258dda9c9bb1f2448835dca77b676d1a94f9aee2c687e189823b2a52fd',
         'ed8b59bb833d3fd0d5e94ec9d0a18f4ce8f66bf6b2cb6b396e8b8ab489b0fc55'),
        ('_authority_metadata_access_label_early_closure_v1(jsonb,jsonb,integer,integer,integer)',
         '_authority_metadata_group_closure_v1',
         'p_packet jsonb,p_catalog jsonb,p_rows integer,p_reads integer,p_work integer',
         'VOLATILE','037bb846b0aece534088339e9a7cd5d4c17ce4ce7b56a9d9f1bac8de4d0b82ee',
         '58464957fd57b4cdaf730e1eb835c4a08d1e3fee3ce8540c58d148a205a24527')
    ) s(predecessor,name,args,volatility,original_digest,group_digest) LOOP
        SELECT prosrc INTO STRICT original FROM pg_catalog.pg_proc
        WHERE oid=to_regprocedure('kaname.'||item.predecessor) AND proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.original_digest THEN
            RAISE EXCEPTION 'group compiler predecessor differs: %',item.predecessor USING ERRCODE='55000';
        END IF;
        IF item.name='_authority_metadata_group_census_v1' THEN
            body:=replace(original,
                $before$mirror_root:=p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount');$before$,
                $after$IF p_root_type IS DISTINCT FROM 'iam.group' THEN RAISE EXCEPTION 'group census root differs' USING ERRCODE='42501'; END IF;
 mirror_root:=false;$after$);
        ELSE
            body:=replace(original,
                $before$external_root:=root_type NOT IN ('iam.account','iam.project','iam.serviceAccount');$before$,
                $after$IF root_type IS DISTINCT FROM 'iam.group' THEN RAISE EXCEPTION 'group closure root differs' USING ERRCODE='42501'; END IF;
 external_root:=false;$after$);
            body:=replace(body,
                $before$root_model:=CASE root_type WHEN 'iam.serviceAccount' THEN 'iam_service_account' ELSE split_part(root_type,'.',2) END;$before$,
                $after$root_model:='iam_group';$after$);
        END IF;
        IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.group_digest THEN
            RAISE EXCEPTION 'group compiler body differs: %',item.name USING ERRCODE='55000';
        END IF;
        EXECUTE format('CREATE FUNCTION kaname.%I(%s) RETURNS jsonb LANGUAGE plpgsql %s
            SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS %L',item.name,item.args,item.volatility,body);
    END LOOP;
END;
$specialize$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_prepare_v1(
    p_id text,p_xmin text,p_ctid text,p_old jsonb,p_new_access jsonb,p_actor_type text,p_actor_id text,
    p_policy_expected jsonb,p_policy_writes text[],p_rows integer,p_reads integer,p_work integer
) RETURNS TABLE(used_rows integer,used_reads integer,used_work integer)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $prepare$
DECLARE
    proof jsonb;
    invoker oid;
    source_table regclass;
    target jsonb;
    bundle record;
    catalog jsonb;
    census jsonb;
    discovery jsonb;
    output_key text;
    root_account text;
    write_key text;
    policy_count integer;
    policy_keys jsonb;
    binding_keys jsonb;
    source_keys jsonb;
    plan jsonb;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN 2 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 4 AND 4096
        OR p_work IS NULL OR p_work NOT BETWEEN 4 AND 400000 THEN
        RAISE EXCEPTION 'group metadata prepare budget invalid' USING ERRCODE='54000';
    END IF;
    -- Сверяет signed resource/decision/2, режим RC, физический OLD из RR и актора.
    target:=kaname._authority_metadata_group_target_v1(p_id,p_xmin,p_ctid,p_old,p_actor_type,p_actor_id,1,1);
    proof:=kaname.authority_protocol_attestation();
    invoker:=(proof->>'invoker_oid')::oid;
    root_account:=target->>'root_account';
    write_key:='group:'||p_id;
    IF jsonb_typeof(p_policy_expected) IS DISTINCT FROM 'object' OR NOT (p_policy_expected ? '*')
        OR NOT (p_policy_expected ? ('scope:'||root_account)) OR p_policy_writes IS NULL
        OR cardinality(p_policy_writes)>4096
        OR (proof->>'mode'='accounts' AND NOT (write_key=ANY(p_policy_writes)))
        OR (proof->>'mode'='global' AND cardinality(p_policy_writes)<>0)
        OR EXISTS (SELECT FROM unnest(p_policy_writes) w WHERE w IS NULL OR NOT (p_policy_expected ? w)) THEN
        RAISE EXCEPTION 'group metadata policy guards incomplete' USING ERRCODE='42501';
    END IF;
    SELECT count(*) INTO policy_count FROM (SELECT FROM jsonb_object_keys(p_policy_expected) LIMIT 4097) keys;
    IF policy_count>4094 OR policy_count+3>=p_work THEN
        RAISE EXCEPTION 'group metadata policy guards exceed budget' USING ERRCODE='54000';
    END IF;

    -- Вход в census проверяет форму таблиц; проверяем также права исходного LOGIN,
    -- включая предикаты, которые могут вернуть пустой набор.
    FOREACH source_table IN ARRAY ARRAY['kaname.access_bindings'::regclass,'kaname.roles'::regclass,
        'kaname.projects'::regclass,'kaname.authority_semantic_identity'::regclass] LOOP
        IF has_table_privilege(invoker,source_table,'SELECT') IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'group metadata source read denied' USING ERRCODE='42501';
        END IF;
    END LOOP;
    IF has_function_privilege(invoker,'kaname.authority_protocol_read_bundle()','EXECUTE') IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'group metadata admitted bundle read denied' USING ERRCODE='42501';
    END IF;
    SELECT * INTO STRICT bundle FROM kaname.authority_protocol_read_bundle();
    IF bundle.model_id IS DISTINCT FROM proof->>'model_id' OR bundle.catalog_id IS DISTINCT FROM proof->>'catalog_id'
        OR bundle.projector_version IS DISTINCT FROM proof->>'projector_version'
        OR octet_length(bundle.catalog_json) NOT BETWEEN 1 AND 8388608
        OR encode(sha256(bundle.catalog_json),'hex') IS DISTINCT FROM bundle.catalog_id
        OR encode(sha256(convert_to(bundle.model_source,'UTF8')),'hex') IS DISTINCT FROM bundle.model_id THEN
        RAISE EXCEPTION 'group metadata admitted bundle changed' USING ERRCODE='P1034';
    END IF;
    catalog:=convert_from(bundle.catalog_json,'UTF8')::jsonb;
    IF NOT EXISTS (SELECT FROM jsonb_array_elements(catalog#>'{Live,Resources}') r
        WHERE r->>'ObjectType'='iam_group' AND r->>'Module'='iam' AND r->>'Resource'='group') THEN
        RAISE EXCEPTION 'group metadata live catalog identity differs' USING ERRCODE='P1034';
    END IF;
    used_rows:=2;
    used_reads:=2;
    used_work:=2+policy_count;
    census:=kaname._authority_metadata_group_census_v1('iam.group',target#>'{root_state,2}',p_new_access,
        p_rows-used_rows,p_reads-used_reads,p_work-used_work);
    target:=target||jsonb_build_object('census',census,
        'rows',1+(census->>'logical_rows')::integer,'reads',1+(census->>'logical_reads')::integer,
        'work',1+(census->>'work')::integer);
    used_rows:=used_rows+(census->>'logical_rows')::integer;
    used_reads:=used_reads+(census->>'logical_reads')::integer;
    used_work:=used_work+(census->>'work')::integer;
    IF p_reads<=used_reads OR p_work<=used_work THEN
        RAISE EXCEPTION 'group metadata closure budget exhausted' USING ERRCODE='54000';
    END IF;
    discovery:=kaname._authority_metadata_group_closure_v1(target,catalog,p_rows-used_rows,p_reads-used_reads,p_work-used_work);
    used_rows:=used_rows+(discovery->>'rows')::integer;
    used_reads:=used_reads+(discovery->>'reads')::integer;
    used_work:=used_work+(discovery->>'work')::integer;
    output_key:=jsonb_build_array('iam_group',p_id)::text;
    IF discovery#>ARRAY['outputs',output_key] IS DISTINCT FROM
        jsonb_build_object('model_type','iam_group','object_type','iam.group','object_id',p_id)
        OR discovery#>ARRAY['frontier','reaches',output_key] IS DISTINCT FROM 'true'::jsonb THEN
        RAISE EXCEPTION 'group metadata discovery root not confirmed' USING ERRCODE='42501';
    END IF;
    PERFORM kaname._authority_metadata_access_label_discovery_fence_v1(discovery);
    SELECT jsonb_object_agg(key,CASE WHEN key=ANY(p_policy_writes) OR (key='*' AND proof->>'mode'='global')
        THEN 'write' ELSE 'share' END) INTO policy_keys FROM jsonb_object_keys(p_policy_expected) key;
    SELECT jsonb_object_agg(id,CASE WHEN id=root_account THEN 'write' ELSE 'share' END) INTO binding_keys
    FROM (SELECT root_account AS id UNION SELECT e.value#>>'{source,id}' FROM jsonb_each(discovery->'source_index') e
        WHERE e.value#>>'{source,kind}'='23') scopes;
    IF EXISTS (SELECT FROM jsonb_object_keys(binding_keys) k WHERE NOT (policy_keys ? ('scope:'||k))) THEN
        RAISE EXCEPTION 'group metadata discovery needs additional signed scopes' USING ERRCODE='P1034';
    END IF;
    binding_keys:=binding_keys||jsonb_build_object('','share');
    source_keys:=discovery->'carrier_source_guards';
    IF p_work-used_work<2 THEN
        RAISE EXCEPTION 'group metadata source lock budget exhausted' USING ERRCODE='54000';
    END IF;
    used_work:=used_work+kaname._authority_metadata_access_label_source_locks_v1(
        source_keys,policy_keys,binding_keys,least(p_work-used_work,4096),false);
    IF used_rows IS NULL OR used_rows NOT BETWEEN 1 AND p_rows OR used_reads IS NULL OR used_reads NOT BETWEEN 1 AND p_reads
        OR used_work IS NULL OR used_work NOT BETWEEN 1 AND p_work THEN
        RAISE EXCEPTION 'group metadata prepare exceeded budget' USING ERRCODE='54000';
    END IF;
    plan:=jsonb_build_object('backend',proof->'backend','transaction_id',proof->'transaction_id',
        'invoker_oid',proof->'invoker_oid','nonce',proof->'nonce','mode',proof->'mode','accounts',proof->'accounts',
        'source_guards',source_keys,'policy_epochs',policy_keys,'binding_epochs',binding_keys);
    PERFORM kaname._authority_metadata_access_label_stash_v1(jsonb_build_object('root',target,'discovery',discovery,
        'catalog_id',bundle.catalog_id,'plan',plan,'rows',used_rows,'reads',used_reads,'work',used_work));
    RETURN NEXT;
END;
$prepare$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE
    fn regprocedure;
    grantee record;
BEGIN
    FOREACH fn IN ARRAY ARRAY[
        'kaname._authority_metadata_group_census_v1(text,jsonb,jsonb,integer,integer,integer)'::regprocedure,
        'kaname._authority_metadata_group_closure_v1(jsonb,jsonb,integer,integer,integer)'::regprocedure,
        'kaname._authority_metadata_group_prepare_v1(text,text,text,jsonb,jsonb,text,text,jsonb,text[],integer,integer,integer)'::regprocedure
    ] LOOP
        FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
            WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
                CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_metadata_group_prepare_v1(text,text,text,jsonb,jsonb,text,text,jsonb,text[],integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_group_closure_v1(jsonb,jsonb,integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_group_census_v1(text,jsonb,jsonb,integer,integer,integer);
