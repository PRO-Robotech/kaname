-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Исторические носители остаются кандидатами после отзыва/expiry. Положительная
-- выдача рассчитывается позднее по физическим строкам полного графа. При
-- совместной смене карт учитываем селекторы каждой изменившейся карты.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_census_v1(
    p_target jsonb,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $census$
DECLARE
    uid text:=p_target#>>'{root_coordinate,1}';
    old_row jsonb:=p_target#>'{root_state,2}';
    memberships jsonb:=p_target->'membership_states';
    next_row jsonb;
    accounts text[];
    hit record;
    selected jsonb:='[]';
    ids text[]:=ARRAY[]::text[];
    used integer;
    work integer;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF p_target->'root_coordinate' IS DISTINCT FROM jsonb_build_array('iam.user',uid)
        OR coalesce(uid,'') COLLATE "C" !~ '^usr[a-zA-Z0-9_-]{1,61}$' OR old_row->>'id' IS DISTINCT FROM uid
        OR jsonb_typeof(memberships) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'user census identity differs' USING ERRCODE='42501';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN 3 AND 100000 OR jsonb_array_length(memberships)>p_rows-3
        OR p_reads IS NULL OR p_reads NOT BETWEEN 2 AND 4096
        OR p_work IS NULL OR p_work NOT BETWEEN 1 AND 400000 OR jsonb_array_length(memberships)+4>p_work THEN
        RAISE EXCEPTION 'user census exceeds budget' USING ERRCODE='54000';
    END IF;
    IF (SELECT count(*) FROM pg_catalog.pg_class c WHERE c.oid IN
        ('kaname.access_bindings'::regclass,'kaname.roles'::regclass,'kaname.projects'::regclass)
        AND c.relkind='r' AND c.relpersistence='p' AND NOT (c.relrowsecurity OR c.relforcerowsecurity
            OR c.relhasrules OR c.relispartition OR c.relhassubclass)
        AND NOT EXISTS(SELECT FROM pg_catalog.pg_inherits i WHERE i.inhparent=c.oid OR i.inhrelid=c.oid))<>3 THEN
        RAISE EXCEPTION 'user census source shape differs' USING ERRCODE='42501';
    END IF;
    next_row:=kaname._authority_metadata_user_patch_images_v1(old_row,p_target->'patch');
    IF next_row->>'mode' IS DISTINCT FROM 'access_labels' OR p_target->'mode' IS DISTINCT FROM next_row->'mode' THEN
        RAISE EXCEPTION 'user census requires changed protected labels' USING ERRCODE='42501';
    END IF;
    next_row:=next_row->'new_row';
    IF EXISTS(SELECT FROM jsonb_array_elements(memberships) m
        WHERE m#>>'{2,user_id}' IS DISTINCT FROM uid OR coalesce(m#>>'{2,account_id}','') COLLATE "C" !~ '^acc[a-zA-Z0-9_-]{1,61}$') THEN
        RAISE EXCEPTION 'user census membership identity differs' USING ERRCODE='42501';
    END IF;
    accounts:=ARRAY(SELECT DISTINCT (m#>>'{2,account_id}') COLLATE "C" AS id FROM jsonb_array_elements(memberships) m ORDER BY id);
    used:=3+jsonb_array_length(memberships);
    work:=used+1;
    IF cardinality(accounts)<>jsonb_array_length(memberships) THEN
        RAISE EXCEPTION 'user census membership duplicated' USING ERRCODE='42501';
    END IF;
    FOR hit IN
        SELECT b.id,b.resource_type,b.resource_id,r.id AS role,r.rules,p.id AS project,
            jsonb_build_array(b.xmin::text,b.ctid::text,to_jsonb(b),r.xmin::text,r.ctid::text,to_jsonb(r),
                p.xmin::text,p.ctid::text,to_jsonb(p)) AS state
        FROM ONLY kaname.access_bindings b LEFT JOIN ONLY kaname.roles r ON r.id=b.role_id
        LEFT JOIN ONLY kaname.projects p ON b.resource_type='project' AND p.id=b.resource_id
        WHERE b.role_id IS NOT NULL AND (b.resource_type NOT IN ('account','project')
            OR (b.resource_type='account' AND b.resource_id=ANY(accounts)) OR (b.resource_type='project' AND p.id IS NULL))
        AND CASE WHEN r.id IS NULL OR kaname.access_label_rules_valid_v1(r.rules) IS DISTINCT FROM true THEN true
            ELSE EXISTS (SELECT FROM jsonb_array_elements(r.rules) authored(rule)
                CROSS JOIN LATERAL jsonb_array_elements(jsonb_build_array(rule)||coalesce(nullif(rule->'children','null'),'[]')) nodes(node)
                WHERE rule->>'module' IN ('iam','*') AND (node->'resources' ? 'user' OR node->'resources' ? '*')
                AND (((old_row->'access_labels') @> (node->'match_access_labels')) IS DISTINCT FROM
                     ((next_row->'access_labels') @> (node->'match_access_labels'))
                 OR ((old_row->'labels') @> (node->'match_labels')) IS DISTINCT FROM
                     ((next_row->'labels') @> (node->'match_labels')))) END
        LIMIT p_rows-used+1
    LOOP
        used:=used+1+(hit.role IS NOT NULL)::integer+(hit.project IS NOT NULL)::integer;
        work:=work+1;
        IF used>p_rows OR work>p_work OR cardinality(ids)>=4096 THEN
            RAISE EXCEPTION 'user carrier census exceeds budget' USING ERRCODE='54000';
        END IF;
        IF hit.resource_type NOT IN ('account','cluster') OR coalesce(hit.resource_id,'')='' OR hit.role IS NULL
            OR kaname.access_label_rules_valid_v1(hit.rules) IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'user carrier scope or role unconfirmed' USING ERRCODE='42501';
        END IF;
        work:=work+(SELECT count(*) FROM jsonb_array_elements(hit.rules) authored(rule)
            CROSS JOIN LATERAL jsonb_array_elements(jsonb_build_array(rule)||coalesce(nullif(rule->'children','null'),'[]')) nodes);
        IF work>p_work THEN RAISE EXCEPTION 'user census selector budget exhausted' USING ERRCODE='54000';END IF;
        selected:=selected||jsonb_build_array(hit.state);
        ids:=array_append(ids,hit.id);
    END LOOP;
    SELECT coalesce(jsonb_agg(s ORDER BY s::text COLLATE "C"),'[]'::jsonb) INTO selected FROM jsonb_array_elements(selected) s;
    SELECT ARRAY(SELECT id FROM unnest(ids) id ORDER BY id COLLATE "C") INTO ids;
    RETURN jsonb_build_object('root_type','iam.user','root_id',uid,'account_ids',accounts,
        'old_root',old_row,'new_labels',next_row->'access_labels','new_ordinary_labels',next_row->'labels',
        'states',selected,'selected',selected,'binding_ids',ids,'logical_rows',used,'logical_reads',2,'work',work);
END;
$census$;
-- +goose StatementEnd

-- Полный обход и повтор всех предикатов выполняет та же версия алгоритма,
-- что у Group. Каждая специализация создаёт отдельную функцию.
-- +goose StatementBegin
DO $specialize$
DECLARE item record;body text;pair jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_metadata_group_closure_v1(jsonb,jsonb,integer,integer,integer)','_authority_metadata_user_closure_v1',
         'p_packet jsonb,p_catalog jsonb,p_rows integer,p_reads integer,p_work integer',
         '58464957fd57b4cdaf730e1eb835c4a08d1e3fee3ce8540c58d148a205a24527','b96cfa3454348ce44bd1bb4af012f903df53775296927f272ced3ba288838588',
         $edits$[
  [
    "IF root_type IS DISTINCT FROM 'iam.group' THEN RAISE EXCEPTION 'group closure root differs'",
    "IF root_type IS DISTINCT FROM 'iam.user' THEN RAISE EXCEPTION 'user closure root differs'"
  ],
  [
    "root_model:='iam_group';",
    "root_model:='iam_user';"
  ]
]$edits$::jsonb),
        ('_authority_metadata_group_held_replay_v1(integer,integer,integer)','_authority_metadata_user_held_replay_v1',
         'p_rows integer,p_reads integer,p_work integer',
         'f39c0e51902930b6efe63337f2962899c53ca66aecf9a97109e4d50051e55eac','f772c1035bdbffbaae57e10cabbd22af7cf52a5844b49282ef1cbed9f7d73586',
         $edits$[
  [
    "root_type IS DISTINCT FROM 'iam.group' OR proof->>'purpose'",
    "root_type IS DISTINCT FROM 'iam.user' OR proof->>'mode' IS DISTINCT FROM 'global' OR proof->>'purpose'"
  ],
  [
    "'group held replay root or decision differs'",
    "'user held replay root or decision differs'"
  ],
  [
    "expected_census->>'account_id' IS DISTINCT FROM p_packet->>'root_account'",
    "expected_census->'account_ids' IS DISTINCT FROM p_packet->'account_ids'"
  ],
  [
    "coalesce(p_packet->>'root_account','')='' THEN",
    "jsonb_typeof(p_packet->'account_ids') IS DISTINCT FROM 'array' THEN"
  ],
  [
    "p_plan#>>ARRAY['binding_epochs',p_packet->>'root_account'] IS DISTINCT FROM 'write'",
    "p_plan#>>ARRAY['binding_epochs',''] IS DISTINCT FROM 'write'\n  OR p_plan#>>ARRAY['policy_epochs','user:'||root_id] IS DISTINCT FROM 'write'"
  ],
  [
    "census:=kaname._authority_metadata_group_census_v1(root_type,expected_census->'old_root',\n  expected_census->'new_labels',",
    "census:=kaname._authority_metadata_user_census_v1(p_packet,"
  ]
]$edits$::jsonb)
    ) s(predecessor,name,args,prior,installed,edits) LOOP
        SELECT p.prosrc INTO STRICT body FROM pg_catalog.pg_proc p
        WHERE p.oid=to_regprocedure('kaname.'||item.predecessor) AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.prior THEN
            RAISE EXCEPTION 'user carrier predecessor differs: %',item.predecessor USING ERRCODE='55000';
        END IF;
        FOR pair IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            body:=replace(body,pair->>0,pair->>1);
        END LOOP;
        IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'user carrier specialization differs: %',item.name USING ERRCODE='55000';
        END IF;
        EXECUTE format('CREATE FUNCTION kaname.%I(%s) RETURNS jsonb LANGUAGE plpgsql VOLATILE
            SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS %L',item.name,item.args,body);
    END LOOP;
END;
$specialize$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_prepare_v1(
    p_id text,p_xmin text,p_ctid text,p_old jsonb,p_memberships jsonb,p_patch jsonb,
    p_actor_type text,p_actor_id text,p_policy_expected jsonb,p_rows integer,p_reads integer,p_work integer
) RETURNS TABLE(used_rows integer,used_reads integer,used_work integer)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $prepare$
DECLARE
    proof jsonb;
    invoker oid;
    bundle record;
    catalog jsonb;
    target jsonb;
    census jsonb;
    discovery jsonb;
    source_index jsonb;
    output_key text;
    policy_count integer;
    policy_keys jsonb;
    binding_keys jsonb;
    plan jsonb;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN 12 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 5 AND 4096
        OR p_work IS NULL OR p_work NOT BETWEEN 5 AND 400000 THEN
        RAISE EXCEPTION 'user discovery budget invalid' USING ERRCODE='54000';
    END IF;
    target:=kaname._authority_metadata_user_patch_target_v1(p_id,p_xmin,p_ctid,p_old,p_memberships,p_patch,
        p_actor_type,p_actor_id,p_rows-8,p_reads-3);
    proof:=kaname.authority_protocol_attestation();
    invoker:=(proof->>'invoker_oid')::oid;
    IF jsonb_typeof(p_policy_expected) IS DISTINCT FROM 'object'
        OR NOT (p_policy_expected ?& ARRAY['*','user:'||p_id]) THEN
        RAISE EXCEPTION 'user discovery policy epoch set incomplete' USING ERRCODE='P1034';
    END IF;
    SELECT count(*) INTO policy_count FROM (SELECT FROM jsonb_object_keys(p_policy_expected) LIMIT 4097) keys;
    used_rows:=8+(target->>'rows')::integer;
    used_reads:=3+(target->>'reads')::integer;
    used_work:=used_rows+policy_count;
    IF policy_count>4094 OR used_work>=p_work THEN
        RAISE EXCEPTION 'user discovery policy budget exhausted' USING ERRCODE='54000';
    END IF;
    -- Проверяем и право исходного LOGIN прочитать пустой предикат.
    IF EXISTS(SELECT FROM unnest(ARRAY['kaname.users'::regclass,'kaname.memberships'::regclass,
        'kaname.access_bindings'::regclass,'kaname.roles'::regclass,'kaname.projects'::regclass,
        'kaname.accounts'::regclass,'kaname.authority_semantic_identity'::regclass]) rel
        LEFT JOIN pg_catalog.pg_class c ON c.oid=rel WHERE c.oid IS NULL OR c.relkind<>'r' OR c.relpersistence<>'p'
            OR c.relrowsecurity OR c.relforcerowsecurity OR c.relhasrules OR c.relispartition OR c.relhassubclass
            OR has_table_privilege(invoker,rel,'SELECT') IS DISTINCT FROM true)
        OR has_function_privilege(invoker,'kaname.authority_protocol_read_bundle()','EXECUTE') IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'user discovery native source or privilege differs' USING ERRCODE='42501';
    END IF;
    SELECT * INTO STRICT bundle FROM kaname.authority_protocol_read_bundle();
    IF bundle.model_id IS DISTINCT FROM proof->>'model_id' OR bundle.catalog_id IS DISTINCT FROM proof->>'catalog_id'
        OR bundle.projector_version IS DISTINCT FROM proof->>'projector_version'
        OR octet_length(bundle.catalog_json) NOT BETWEEN 1 AND 8388608
        OR encode(sha256(bundle.catalog_json),'hex') IS DISTINCT FROM bundle.catalog_id
        OR encode(sha256(convert_to(bundle.model_source,'UTF8')),'hex') IS DISTINCT FROM bundle.model_id THEN
        RAISE EXCEPTION 'user discovery admitted catalog changed' USING ERRCODE='P1034';
    END IF;
    catalog:=convert_from(bundle.catalog_json,'UTF8')::jsonb;
    IF (SELECT count(*) FROM jsonb_array_elements(catalog#>'{Live,Resources}') r
        WHERE r->>'ObjectType'='iam_user' AND r->>'Module'='iam' AND r->>'Resource'='user')<>1 THEN
        RAISE EXCEPTION 'user discovery catalog identity differs' USING ERRCODE='P1034';
    END IF;
    census:=kaname._authority_metadata_user_census_v1(target,p_rows-used_rows,p_reads-used_reads,p_work-used_work);
    used_rows:=used_rows+(census->>'logical_rows')::integer;
    used_reads:=used_reads+(census->>'logical_reads')::integer;
    used_work:=used_work+(census->>'work')::integer;
    target:=target||jsonb_build_object('census',census,'account_ids',census->'account_ids');
    discovery:=kaname._authority_metadata_user_closure_v1(target,catalog,p_rows-used_rows,p_reads-used_reads,p_work-used_work);
    source_index:=discovery->'source_index';
    used_rows:=used_rows+(discovery->>'rows')::integer;
    used_reads:=used_reads+(discovery->>'reads')::integer;
    used_work:=used_work+(discovery->>'work')::integer+jsonb_array_length(p_memberships);
    output_key:=jsonb_build_array('iam_user',p_id)::text;
    IF discovery#>ARRAY['outputs',output_key] IS DISTINCT FROM
        jsonb_build_object('model_type','iam_user','object_type','iam.user','object_id',p_id)
        OR discovery#>ARRAY['frontier','reaches',output_key] IS DISTINCT FROM 'true'::jsonb
        OR source_index#>ARRAY[jsonb_build_array(30,'iam.user',p_id,'')::text,'states'] IS DISTINCT FROM jsonb_build_array(target->'root_state')
        OR source_index#>ARRAY[jsonb_build_array(31,'iam.user',p_id,'')::text,'states'] IS DISTINCT FROM p_memberships
        OR EXISTS(SELECT FROM jsonb_array_elements_text(census->'account_ids') a
            WHERE source_index#>>ARRAY[jsonb_build_array(23,'account',a,'')::text,'states','0','2','id'] IS DISTINCT FROM a) THEN
        RAISE EXCEPTION 'user discovery root or membership history changed' USING ERRCODE='40001';
    END IF;
    PERFORM kaname._authority_metadata_access_label_discovery_fence_v1(discovery);
    SELECT jsonb_object_agg(k,CASE WHEN k IN ('*','user:'||p_id) THEN 'write' ELSE 'share' END)
        INTO policy_keys FROM jsonb_object_keys(p_policy_expected) k;
    SELECT coalesce(jsonb_object_agg(e.value#>>'{source,id}','share'::text),'{}') INTO binding_keys
        FROM jsonb_each(source_index) e WHERE e.value#>>'{source,kind}'='23';
    IF EXISTS(SELECT FROM jsonb_object_keys(binding_keys) k WHERE NOT (policy_keys ? ('scope:'||k))) THEN
        RAISE EXCEPTION 'user discovery needs additional policy scopes' USING ERRCODE='P1034';
    END IF;
    IF EXISTS(SELECT FROM jsonb_each(source_index) e WHERE e.value#>>'{source,kind}'='31'
        AND NOT (policy_keys ? ('user:'||(e.value#>>'{source,id}')))) THEN
        RAISE EXCEPTION 'user discovery needs membership predicate epochs' USING ERRCODE='P1034';
    END IF;
    binding_keys:=binding_keys||jsonb_build_object('','write');
    IF used_work>p_work-2 THEN RAISE EXCEPTION 'user discovery source budget exhausted' USING ERRCODE='54000'; END IF;
    used_work:=used_work+kaname._authority_metadata_access_label_source_locks_v1(
        discovery->'carrier_source_guards',policy_keys,binding_keys,least(4096,p_work-used_work),false);
    IF used_rows IS NULL OR used_rows>p_rows OR used_reads IS NULL OR used_reads>p_reads OR used_work IS NULL OR used_work>p_work THEN
        RAISE EXCEPTION 'user discovery exceeds shared budget' USING ERRCODE='54000';END IF;
    plan:=jsonb_build_object('backend',proof->'backend','transaction_id',proof->'transaction_id','invoker_oid',proof->'invoker_oid',
        'nonce',proof->'nonce','mode',proof->'mode','accounts',proof->'accounts','source_guards',discovery->'carrier_source_guards',
        'policy_epochs',policy_keys,'binding_epochs',binding_keys);
    PERFORM kaname._authority_metadata_access_label_stash_v1(jsonb_build_object('root',target,'discovery',discovery,
        'catalog_id',bundle.catalog_id,'plan',plan,'rows',used_rows,'reads',used_reads,'work',used_work));
    RETURN NEXT;
END;
$prepare$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_hold_and_replay_v1(
    p_actor_type text,p_actor_id text,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $hold$
DECLARE
    stored jsonb;
    images jsonb;
    frozen jsonb;
    replay jsonb;
    receipt jsonb;
    replacement jsonb;
    state_index jsonb;
    uid text;
    epoch_key text;
    account_id text;
    witness_count integer;
    needs_cluster boolean;
    used_rows integer:=3;
    used_reads integer:=4;
    used_work integer:=4;
    saved_timeout text:=current_setting('lock_timeout');
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN 18 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 15 AND 4096
        OR p_work IS NULL OR p_work NOT BETWEEN 5 AND 400000 THEN
        RAISE EXCEPTION 'user held replay budget invalid' USING ERRCODE='54000';END IF;
    IF saved_timeout::interval=interval '0' OR saved_timeout::interval>interval '2 seconds' THEN
        PERFORM set_config('lock_timeout','2s',true);
    END IF;
    -- freeze получает FOR UPDATE для OLD и общей/персональной эпох, удерживает
    -- существующие K31 и проверяет контракт producer даже при пустом K31.
    frozen:=kaname._authority_metadata_user_freeze_images_v1(p_actor_type,p_actor_id,p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(frozen->>'rows')::integer;
    used_reads:=used_reads+(frozen->>'reads')::integer;
    used_work:=used_work+(frozen->>'rows')::integer;
    stored:=kaname._authority_metadata_access_label_stashed_v1();
    images:=stored->'user_images';
    uid:=images->>'root_id';
    IF stored ? 'user_held' OR images->>'mode' IS DISTINCT FROM 'access_labels'
        OR images#>'{new_row,access_labels}' IS DISTINCT FROM stored#>'{root,census,new_labels}'
        OR images#>'{new_row,labels}' IS DISTINCT FROM stored#>'{root,census,new_ordinary_labels}'
        OR stored#>>ARRAY['plan','binding_epochs',''] IS DISTINCT FROM 'write'
        OR stored#>>ARRAY['plan','policy_epochs','user:'||uid] IS DISTINCT FROM 'write' THEN
        RAISE EXCEPTION 'user held replay lacks changed discovery' USING ERRCODE='42501';END IF;

    -- Отрицательный предикат K31 нужен и для других User в retained-графе.
    -- '*' уже удержана freeze: большая пачка/ TRUNCATE не уйдёт мимо него.
    FOR epoch_key IN SELECT ('user:'||(e.value#>>'{source,id}')) COLLATE "C" AS k FROM jsonb_each(stored#>'{discovery,source_index}') e
        WHERE e.value#>>'{source,kind}'='31' AND e.value#>>'{source,id}'<>uid ORDER BY 1
    LOOP
        IF used_rows>=p_rows OR used_reads>=p_reads OR used_work>=p_work THEN
            RAISE EXCEPTION 'retained user epoch hold exceeds budget' USING ERRCODE='54000';END IF;
        IF stored#>>ARRAY['plan','policy_epochs',epoch_key] IS DISTINCT FROM 'share' THEN
            RAISE EXCEPTION 'retained user membership epoch not prepared' USING ERRCODE='42501';END IF;
        PERFORM FROM ONLY kaname.authority_policy_epoch e WHERE e.key=epoch_key FOR SHARE NOWAIT;
        IF NOT FOUND THEN RAISE EXCEPTION 'retained user membership epoch absent' USING ERRCODE='40001';END IF;
        used_rows:=used_rows+1;used_reads:=used_reads+1;used_work:=used_work+1;
    END LOOP;
    LOCK TABLE ONLY kaname.authority_binding_epoch IN ROW EXCLUSIVE MODE NOWAIT;
    FOR account_id IN SELECT k FROM jsonb_object_keys(stored#>'{plan,binding_epochs}') k ORDER BY k COLLATE "C"
    LOOP
        IF used_rows>=p_rows OR used_reads>=p_reads OR used_work>=p_work THEN
            RAISE EXCEPTION 'user binding epoch hold exceeds budget' USING ERRCODE='54000';END IF;
        IF account_id='' THEN
            PERFORM FROM ONLY kaname.authority_binding_epoch b WHERE b.scope='' FOR UPDATE NOWAIT;
            IF NOT FOUND THEN RAISE EXCEPTION 'user binding epoch absent' USING ERRCODE='40001';END IF;
        ELSE
            IF stored#>>ARRAY['plan','binding_epochs',account_id] IS DISTINCT FROM 'share' THEN
                RAISE EXCEPTION 'user binding epoch mode differs' USING ERRCODE='42501';END IF;
            PERFORM FROM ONLY kaname.authority_binding_epoch b WHERE b.scope=account_id FOR SHARE NOWAIT;
        END IF;
        IF FOUND THEN used_rows:=used_rows+1;END IF;
        used_reads:=used_reads+1;used_work:=used_work+1;
    END LOOP;
    SELECT count(*),bool_or(w.value->'cluster_states'='[]'::jsonb) INTO witness_count,needs_cluster
        FROM jsonb_each(stored#>'{discovery,frontier,witnesses}') w;
    used_work:=used_work+witness_count;
    IF used_rows>=p_rows OR used_reads>=p_reads OR used_work>=p_work THEN
        RAISE EXCEPTION 'user closure replay exceeds remaining budget' USING ERRCODE='54000';END IF;
    IF needs_cluster THEN LOCK TABLE ONLY kaname.clusters IN SHARE MODE NOWAIT;END IF;
    replay:=kaname._authority_metadata_user_held_replay_v1(p_rows-used_rows,p_reads-used_reads,p_work-used_work);
    used_rows:=used_rows+(replay->>'rows')::integer;
    used_reads:=used_reads+(replay->>'reads')::integer;
    used_work:=used_work+(replay->>'work')::integer+jsonb_array_length(images->'membership_states');
    state_index:=replay->'source_index';
    IF replay->'nonce' IS DISTINCT FROM images->'nonce'
        OR state_index#>ARRAY[jsonb_build_array(30,'iam.user',uid,'')::text,'states'] IS DISTINCT FROM jsonb_build_array(stored#>'{root,root_state}')
        OR state_index#>ARRAY[jsonb_build_array(31,'iam.user',uid,'')::text,'states'] IS DISTINCT FROM images->'membership_states'
        OR EXISTS(SELECT FROM jsonb_array_elements_text(replay#>'{census,account_ids}') a
            WHERE state_index#>>ARRAY[jsonb_build_array(23,'account',a,'')::text,'states','0','2','id'] IS DISTINCT FROM a) THEN
        RAISE EXCEPTION 'user held closure differs from frozen root and scopes' USING ERRCODE='40001';
    END IF;
    IF used_rows IS NULL OR used_rows>p_rows OR used_reads IS NULL OR used_reads>p_reads OR used_work IS NULL OR used_work>p_work THEN
        RAISE EXCEPTION 'user held replay exceeds shared budget' USING ERRCODE='54000';END IF;
    receipt:=jsonb_build_object('nonce',images->'nonce','root_physical',images->'root_physical',
        'update_question',images->'update_question','replay',replay);
    replacement:=stored||jsonb_build_object('user_held',receipt);
    IF octet_length(replacement::text)>67108864 THEN RAISE EXCEPTION 'user held packet too large' USING ERRCODE='54000';END IF;
    UPDATE pg_temp.kaname_authority_metadata_discovery d SET prepared=replacement
        WHERE d.singleton AND d.prepared=stored AND NOT (d.prepared ? 'user_held');
    IF NOT FOUND THEN RAISE EXCEPTION 'user held packet custody changed' USING ERRCODE='42501';END IF;
    IF current_setting('lock_timeout') IS DISTINCT FROM saved_timeout THEN PERFORM set_config('lock_timeout',saved_timeout,true);END IF;
    RETURN receipt||jsonb_build_object('rows',used_rows,'reads',used_reads,'work',used_work);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'user held replay busy; restage required' USING ERRCODE='40001';
END;
$hold$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure; grantee record;
BEGIN
    FOREACH fn IN ARRAY ARRAY[
        'kaname._authority_metadata_user_census_v1(jsonb,integer,integer,integer)'::regprocedure,
        'kaname._authority_metadata_user_closure_v1(jsonb,jsonb,integer,integer,integer)'::regprocedure,
        'kaname._authority_metadata_user_held_replay_v1(integer,integer,integer)'::regprocedure,
        'kaname._authority_metadata_user_prepare_v1(text,text,text,jsonb,jsonb,jsonb,text,text,jsonb,integer,integer,integer)'::regprocedure,
        'kaname._authority_metadata_user_hold_and_replay_v1(text,text,integer,integer,integer)'::regprocedure
    ] LOOP
        FOR grantee IN SELECT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
                CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE quote_ident(grantee.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_metadata_user_hold_and_replay_v1(text,text,integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_user_prepare_v1(text,text,text,jsonb,jsonb,jsonb,text,text,jsonb,integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_user_held_replay_v1(integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_user_closure_v1(jsonb,jsonb,integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_user_census_v1(jsonb,integer,integer,integer);
