-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Приватные проверки физического графа и старого правила готовят источник
-- защищённой копии. Подключение к решению о записи требует отдельной сверки
-- выбранных позиций и действующих выдач на финальных часах.
-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Удерживает физические источники вложенного проекта в транзакции роли.
-- Квитанция нужна для проверки старой позиции правила. Она не разрешает запись.
CREATE FUNCTION kaname._authority_role_move_project_copy_graph_hold_v1(
    p_project_id text,p_native jsonb,p_mirror jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $hold$
DECLARE
    proof jsonb;
    item record;
    project_model text;
    account_model text;
    catalog_rows jsonb:='[]'::jsonb;
    catalog_resources jsonb:='[]'::jsonb;
    edge_rows jsonb:='[]'::jsonb;
    native_row jsonb;
    mirror_row jsonb;
    captured jsonb:='{}'::jsonb;
    project_graph jsonb;
    receipt jsonb;
    used_bytes bigint;
    source_row jsonb;
    source_id text;
    parent_project text;
    used_rows integer:=11;
    used_reads integer:=4;
    seen_edges integer:=0;
BEGIN
    proof:=kaname._authority_role_move_attestation_v1();
    IF coalesce(p_project_id,'')='' OR octet_length(p_project_id)>16384
        OR p_project_id ~ '[:#*[:space:][:cntrl:]]'
        OR jsonb_typeof(p_native) IS DISTINCT FROM 'array'
        OR jsonb_typeof(p_mirror) IS DISTINCT FROM 'array'
        OR jsonb_array_length(p_native)<>3 OR jsonb_array_length(p_mirror)<>3 THEN
        RAISE EXCEPTION 'invalid selector move project graph coordinates' USING ERRCODE='42501';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
        OR octet_length(p_native::text)+octet_length(p_mirror::text)>8388608 THEN
        RAISE EXCEPTION 'selector move project graph input exceeds budget' USING ERRCODE='54000';
    END IF;
    -- Порядок совпадает с существующим удержанием переписи потомков роли.
    LOCK TABLE ONLY kaname.catalog_resource, ONLY kaname.resource_mirror, ONLY kaname.resource_parent_edge
        IN SHARE MODE NOWAIT;
    IF EXISTS(SELECT 1 FROM unnest(ARRAY['kaname.catalog_resource'::regclass,'kaname.resource_mirror'::regclass,
        'kaname.resource_parent_edge'::regclass,'kaname.projects'::regclass,'kaname.accounts'::regclass]) AS source(oid)
        WHERE NOT EXISTS(SELECT 1 FROM pg_class c WHERE c.oid=source.oid
            AND c.relowner=current_user::regrole AND c.relkind='r' AND c.relpersistence='p'
            AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relispartition OR c.relhasrules)
            AND NOT EXISTS(SELECT 1 FROM pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid))
            OR NOT has_table_privilege((proof->>'invoker_oid')::oid,source.oid,'SELECT')) THEN
        RAISE EXCEPTION 'selector move project graph source custody differs' USING ERRCODE='42501';
    END IF;
    IF EXISTS(SELECT 1 FROM (VALUES
        ('kaname.catalog_resource'::regclass,ARRAY['dotted','live']),
        ('kaname.resource_mirror'::regclass,ARRAY['object_type','object_id']),
        ('kaname.resource_parent_edge'::regclass,ARRAY['object_type','object_id','depth']),
        ('kaname.projects'::regclass,ARRAY['id']),('kaname.accounts'::regclass,ARRAY['id'])
    ) AS source(rel,cols)
    WHERE NOT EXISTS(SELECT 1 FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid
        JOIN pg_am am ON am.oid=idx.relam
        WHERE i.indrelid=source.rel AND am.amname='btree' AND i.indisready AND i.indisvalid
            AND i.indisunique AND i.indimmediate AND i.indpred IS NULL AND i.indexprs IS NULL
            AND (SELECT array_agg(a.attname::text ORDER BY k.pos)
                FROM unnest(i.indkey::smallint[]) WITH ORDINALITY AS k(attnum,pos)
                JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum
                WHERE k.pos<=i.indnkeyatts)=source.cols)) THEN
        RAISE EXCEPTION 'selector move project graph source keys differ' USING ERRCODE='42501';
    END IF;
    IF p_rows-used_rows<5 OR p_reads-used_reads<3 THEN
        RAISE EXCEPTION 'selector move project graph read budget exhausted' USING ERRCODE='54000';
    END IF;

    SELECT jsonb_build_array(p.xmin::text,p.ctid::text,to_jsonb(p)) INTO native_row
    FROM ONLY kaname.projects p WHERE p.id=p_project_id FOR SHARE OF p NOWAIT;
    SELECT jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) INTO mirror_row
    FROM ONLY kaname.resource_mirror m WHERE m.object_type='iam.project' AND m.object_id=p_project_id;
    IF native_row IS NULL OR native_row IS DISTINCT FROM p_native
        OR mirror_row IS NULL OR mirror_row IS DISTINCT FROM p_mirror THEN
        RAISE EXCEPTION 'selector move physical project graph changed' USING ERRCODE='40001';
    END IF;
    used_bytes:=octet_length(native_row::text)+octet_length(mirror_row::text);
    used_rows:=used_rows+2;
    used_reads:=used_reads+3;
    FOR item IN
        SELECT c.dotted,c.object_type,jsonb_build_array(c.xmin::text,c.ctid::text,to_jsonb(c)) AS image
        FROM ONLY kaname.catalog_resource c WHERE c.live AND c.dotted IN ('iam.account','iam.project') ORDER BY c.dotted COLLATE "C" LIMIT 3
    LOOP
        IF item.object_type='' OR octet_length(item.object_type)>16384
            OR item.object_type ~ '[:#*[:space:][:cntrl:]]'
            OR (item.dotted='iam.project' AND project_model IS NOT NULL)
            OR (item.dotted='iam.account' AND account_model IS NOT NULL) THEN
            RAISE EXCEPTION 'invalid selector move project graph catalog' USING ERRCODE='42501';
        END IF;
        IF item.dotted='iam.project' THEN project_model:=item.object_type;
        ELSE account_model:=item.object_type; END IF;
        used_bytes:=used_bytes+octet_length(item.image::text);
        IF used_bytes>8388608 THEN RAISE EXCEPTION 'selector move project catalog exceeds byte budget' USING ERRCODE='54000'; END IF;
        catalog_rows:=catalog_rows||jsonb_build_array(item.image);
        catalog_resources:=catalog_resources||jsonb_build_array(jsonb_build_object('Module','iam',
            'Resource',substring(item.dotted from 5),'ObjectType',item.object_type));
        used_rows:=used_rows+1;
    END LOOP;
    IF project_model IS NULL OR account_model IS NULL OR project_model=account_model THEN
        RAISE EXCEPTION 'selector move project graph lacks a live catalog type' USING ERRCODE='42501';
    END IF;
    IF used_rows+5>p_rows OR used_reads>=p_reads THEN
        RAISE EXCEPTION 'selector move project edge budget exhausted' USING ERRCODE='54000';
    END IF;
    used_reads:=used_reads+1;
    FOR item IN
        SELECT jsonb_build_array(e.xmin::text,e.ctid::text,to_jsonb(e)) AS image
        FROM ONLY kaname.resource_parent_edge e
        WHERE e.object_type=project_model AND e.object_id=p_project_id ORDER BY e.depth LIMIT 5
    LOOP
        seen_edges:=seen_edges+1;
        IF seen_edges>4 THEN RAISE EXCEPTION 'selector move project edges exceed bound' USING ERRCODE='54000'; END IF;
        used_bytes:=used_bytes+octet_length(item.image::text);
        IF used_bytes>8388608 THEN RAISE EXCEPTION 'selector move project edge exceeds byte budget' USING ERRCODE='54000'; END IF;
        edge_rows:=edge_rows||jsonb_build_array(item.image);
        used_rows:=used_rows+1;
    END LOOP;

    captured:=jsonb_build_object(
        jsonb_build_array(2,'iam.project',p_project_id,'')::text,jsonb_build_object('source','{}'::jsonb,'states',jsonb_build_array(mirror_row)),
        jsonb_build_array(3,project_model,p_project_id,'')::text,jsonb_build_object('source','{}'::jsonb,'states',edge_rows));

    parent_project:=nullif(mirror_row#>>'{2,parent_project_id}','');
    IF parent_project IS NOT NULL THEN
        IF used_rows>=p_rows OR p_reads-used_reads<2 THEN
            RAISE EXCEPTION 'selector move fallback project budget exhausted' USING ERRCODE='54000';
        END IF;
        IF octet_length(parent_project)>16384 OR parent_project ~ '[:#*[:space:][:cntrl:]]' THEN
            RAISE EXCEPTION 'invalid selector move fallback project source' USING ERRCODE='42501';
        END IF;
        -- Общий ключ INSERT/смены PK удерживает в том числе пустое чтение.
        IF NOT pg_try_advisory_xact_lock_shared(1262569303,hashtext(kaname._authority_crud_unique_key_v3(
            'projects',jsonb_build_object('id',parent_project)))) THEN
            RAISE EXCEPTION 'selector move fallback project is changing' USING ERRCODE='40001';
        END IF;
        SELECT jsonb_build_array(p.xmin::text,p.ctid::text,to_jsonb(p)) INTO source_row
        FROM ONLY kaname.projects p WHERE p.id=parent_project FOR SHARE OF p NOWAIT;
        used_reads:=used_reads+2;
        used_bytes:=used_bytes+coalesce(octet_length(source_row::text),0);
        IF used_bytes>8388608 THEN RAISE EXCEPTION 'selector move project source exceeds byte budget' USING ERRCODE='54000'; END IF;
        used_rows:=used_rows+CASE WHEN source_row IS NULL THEN 0 ELSE 1 END;
        captured:=captured||jsonb_build_object(jsonb_build_array(1,'project',parent_project,'')::text,
            jsonb_build_object('source','{}'::jsonb,'states',CASE WHEN source_row IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(source_row) END));
    END IF;
    FOR source_id IN
        SELECT DISTINCT (edge->2->>'parent_id') COLLATE "C"
        FROM jsonb_array_elements(edge_rows) edge
        WHERE edge->2->>'parent_type'=account_model ORDER BY 1
    LOOP
        IF used_rows>=p_rows OR p_reads-used_reads<2 THEN
            RAISE EXCEPTION 'selector move project account budget exhausted' USING ERRCODE='54000';
        END IF;
        IF coalesce(source_id,'')='' OR octet_length(source_id)>16384 OR source_id ~ '[:#*[:space:][:cntrl:]]' THEN
            RAISE EXCEPTION 'invalid selector move project account source' USING ERRCODE='42501';
        END IF;
        IF NOT pg_try_advisory_xact_lock_shared(1262569303,hashtext(kaname._authority_crud_unique_key_v3(
            'accounts',jsonb_build_object('id',source_id)))) THEN
            RAISE EXCEPTION 'selector move account source is changing' USING ERRCODE='40001';
        END IF;
        SELECT jsonb_build_array(a.xmin::text,a.ctid::text,to_jsonb(a)) INTO source_row
        FROM ONLY kaname.accounts a WHERE a.id=source_id FOR SHARE OF a NOWAIT;
        used_reads:=used_reads+2;
        used_bytes:=used_bytes+coalesce(octet_length(source_row::text),0);
        IF used_bytes>8388608 THEN RAISE EXCEPTION 'selector move project source exceeds byte budget' USING ERRCODE='54000'; END IF;
        used_rows:=used_rows+CASE WHEN source_row IS NULL THEN 0 ELSE 1 END;
        captured:=captured||jsonb_build_object(jsonb_build_array(30,'iam.account',source_id,'')::text,
            jsonb_build_object('source','{}'::jsonb,'states',CASE WHEN source_row IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(source_row) END));
    END LOOP;
    project_graph:=kaname._authority_resource_project_graph_v3(captured,
        jsonb_build_object('Live',jsonb_build_object('Resources',catalog_resources)),
        jsonb_build_object('object_type','iam.project','object_id',p_project_id,'present',true,'projection',native_row->2));
    receipt:=jsonb_build_object('nonce',proof->>'nonce','backend_pid',pg_backend_pid(),'txid',pg_current_xact_id()::text,
        'project_id',p_project_id,'native',native_row,'catalog',catalog_rows,'sources',captured,
        'graph',project_graph,'rows',used_rows,'reads',used_reads);
    IF octet_length(receipt::text)>8388608 THEN
        RAISE EXCEPTION 'selector move project graph receipt exceeds byte budget' USING ERRCODE='54000';
    END IF;
    RETURN receipt;
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'selector move project graph is being written' USING ERRCODE='40001';
END;
$hold$;

CREATE FUNCTION kaname._authority_role_move_old_project_match_v1(
    p_rules jsonb,p_rule_index integer,p_child_index integer,p_scope jsonb,p_target jsonb,
    p_account jsonb,p_mirror jsonb,p_project_id text,p_mirror_account_id text
) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $match$
DECLARE
    owner_rule jsonb;child_rule jsonb;branch jsonb;pairs jsonb;selector jsonb;
    names jsonb;labels jsonb;protected_labels jsonb;
    ids jsonb:=coalesce(p_target->'resources','[]'::jsonb);
    account_id text:=p_account->>'id';scope_kind text:=p_scope->>0;scope_id text:=p_scope->>1;
    explicit_account text:=coalesce(p_mirror->>'parent_account_id','');
    parent_project text:=coalesce(p_mirror->>'parent_project_id','');
    mirror_account text:=coalesce(p_mirror_account_id,'');
    -- nativeQuestionToken: управляющие символы, пробелы Unicode и разделители координат.
    forbidden constant text:=U&'[:#*\0001-\0020\007F-\00A0\1680\2000-\200A\2028\2029\202F\205F\3000]';
BEGIN
    -- Правила, позиции переноса и связь ребра с этими строками удерживает вызывающий код.
    -- Сначала проверяем знак: оператор JSONB трактует отрицательную позицию как индекс с конца.
    IF jsonb_typeof(p_rules) IS DISTINCT FROM 'array' OR p_rule_index IS NULL OR p_rule_index NOT BETWEEN 0 AND 63
        OR p_child_index IS NULL OR p_child_index NOT BETWEEN 0 AND 15 THEN
        RAISE EXCEPTION 'invalid held role or requested nested position' USING ERRCODE='42501';
    END IF;
    owner_rule:=p_rules->p_rule_index;
    child_rule:=owner_rule->'children'->p_child_index;
    IF jsonb_array_length(p_rules)>64 OR jsonb_typeof(owner_rule) IS DISTINCT FROM 'object'
        OR jsonb_typeof(owner_rule->'children') IS DISTINCT FROM 'array' OR jsonb_typeof(child_rule) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'selected held nested position missing' USING ERRCODE='42501';
    END IF;
    IF jsonb_array_length(owner_rule->'children')>16 THEN
        RAISE EXCEPTION 'held nested role exceeds child bound' USING ERRCODE='42501';
    END IF;
    -- Обе проверки уже применялись ко всей OLD-роли. Здесь судим конкретную
    -- авторскую ветвь и возможность перенести ВСЮ карту её обычных меток.
    branch:=jsonb_build_array(jsonb_set(owner_rule,'{children}',jsonb_build_array(child_rule)));
    pairs:=child_rule->'match_labels';
    IF kaname.iam_rules_valid(branch) IS DISTINCT FROM true OR kaname.access_label_rules_valid_v1(branch) IS DISTINCT FROM true
        OR child_rule ? 'created_by_subject' OR child_rule ? 'match_access_labels'
        OR kaname.access_labels_valid_v1(pairs) IS DISTINCT FROM true OR pairs='{}'::jsonb
        OR coalesce(nullif(child_rule->'resource_names','null'::jsonb),'[]'::jsonb)<>'[]'::jsonb
        OR child_rule->'verbs' ? '*' THEN
        RAISE EXCEPTION 'invalid held ordinary child selector' USING ERRCODE='42501';
    END IF;
    IF owner_rule->'module' IS DISTINCT FROM '"iam"'::jsonb OR owner_rule->'resources' IS DISTINCT FROM '["account"]'::jsonb
        OR NOT (child_rule->'resources' ? 'project') THEN RETURN NULL;END IF;

    IF jsonb_typeof(p_account) IS DISTINCT FROM 'object' OR jsonb_typeof(p_account->'id') IS DISTINCT FROM 'string'
        OR (p_account ? 'object_type' AND p_account->'object_type' IS DISTINCT FROM '"iam.account"'::jsonb)
        OR (p_account ? 'object_id' AND p_account->'object_id' IS DISTINCT FROM p_account->'id')
        OR jsonb_typeof(p_account->'labels') IS DISTINCT FROM 'object'
        OR kaname.access_labels_valid_v1(p_account->'access_labels') IS DISTINCT FROM true
        OR jsonb_typeof(p_mirror) IS DISTINCT FROM 'object' OR p_mirror->'object_type' IS DISTINCT FROM '"iam.project"'::jsonb
        OR p_project_id IS NULL OR p_mirror->'object_id' IS DISTINCT FROM to_jsonb(p_project_id)
        OR jsonb_typeof(p_mirror->'labels') IS DISTINCT FROM 'object'
        OR NOT (p_mirror ?& ARRAY['parent_account_id','parent_project_id'])
        OR jsonb_typeof(p_mirror->'parent_account_id') NOT IN ('string','null')
        OR jsonb_typeof(p_mirror->'parent_project_id') NOT IN ('string','null')
        OR (explicit_account<>'' AND explicit_account IS DISTINCT FROM mirror_account)
        OR (explicit_account='' AND parent_project='' AND mirror_account<>'') THEN
        RAISE EXCEPTION 'invalid held account or project mirror projection' USING ERRCODE='42501';
    END IF;
    IF jsonb_typeof(p_scope) IS DISTINCT FROM 'array' OR jsonb_typeof(p_scope->0) IS DISTINCT FROM 'string'
        OR jsonb_typeof(p_scope->1) IS DISTINCT FROM 'string' OR scope_kind NOT IN ('account','project','cluster')
        OR (scope_kind='cluster' AND scope_id<>'cluster_root') OR jsonb_typeof(p_target) IS DISTINCT FROM 'object'
        OR p_target-ARRAY['allInScope','resources']<>'{}'::jsonb
        OR (p_target ? 'allInScope' AND jsonb_typeof(p_target->'allInScope') IS DISTINCT FROM 'boolean')
        OR jsonb_typeof(ids) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'invalid held nested scope or finite target' USING ERRCODE='42501';
    END IF;
    IF jsonb_array_length(p_scope)<>2 OR jsonb_array_length(ids)>256 OR (ids<>'[]'::jsonb AND p_target->'allInScope'='true'::jsonb)
        OR EXISTS(SELECT FROM unnest(ARRAY[account_id,p_project_id,scope_id]) id WHERE octet_length(id) NOT BETWEEN 1 AND 16384)
        OR EXISTS(SELECT FROM unnest(ARRAY[account_id,p_project_id,scope_id,mirror_account,parent_project]) id
            WHERE octet_length(id)>16384 OR id COLLATE "C" ~ forbidden)
        OR EXISTS(SELECT FROM jsonb_array_elements(ids) r WHERE jsonb_typeof(r) IS DISTINCT FROM 'object'
            OR jsonb_typeof(r->'type') IS DISTINCT FROM 'string' OR jsonb_typeof(r->'id') IS DISTINCT FROM 'string'
            OR octet_length(r->>'type') NOT BETWEEN 1 AND 16384 OR octet_length(r->>'id') NOT BETWEEN 1 AND 16384
            OR (r->>'id') COLLATE "C" ~ forbidden)
        OR EXISTS(SELECT FROM jsonb_each(p_mirror->'labels') l WHERE jsonb_typeof(l.value)<>'string')
        OR EXISTS(SELECT FROM jsonb_each(p_account->'labels') l WHERE jsonb_typeof(l.value)<>'string') THEN
        RAISE EXCEPTION 'invalid nested source coordinates or labels' USING ERRCODE='42501';
    END IF;
    -- У аккаунта родительский аккаунт — он сам, родительского проекта нет.
    -- Область ребёнка определяется зеркалом, включая удостоверенный родительский проект.
    IF kaname._authority_resource_contained_v2(scope_kind,scope_id,jsonb_build_array(account_id),'') IS DISTINCT FROM true
        OR kaname._authority_resource_contained_v2(scope_kind,scope_id,
            CASE WHEN mirror_account='' THEN '[]'::jsonb ELSE jsonb_build_array(mirror_account) END,parent_project) IS DISTINCT FROM true
        OR kaname._authority_resource_target_contains_v2(p_target,'iam.account',account_id) IS DISTINCT FROM true THEN RETURN NULL;END IF;

    names:=coalesce(nullif(owner_rule->'resource_names','null'::jsonb),'[]'::jsonb);
    labels:=coalesce(nullif(owner_rule->'match_labels','null'::jsonb),'{}'::jsonb);
    protected_labels:=coalesce(owner_rule->'match_access_labels','{}'::jsonb);
    IF kaname.access_labels_valid_v1(labels) IS DISTINCT FROM true
        OR (owner_rule->'verbs' ? '*' AND (names<>'[]'::jsonb OR labels<>'{}'::jsonb OR protected_labels<>'{}'::jsonb))
        OR EXISTS(SELECT FROM jsonb_array_elements_text(names) n WHERE n COLLATE "C" !~ '^[A-Za-z0-9_-]{1,64}$') THEN
        RAISE EXCEPTION 'invalid held account selector' USING ERRCODE='42501';
    END IF;
    selector:=jsonb_build_object('object_types',jsonb_build_array('iam.account'),'resource_names',names,
        'match_labels',labels,'match_access_labels',protected_labels,'arm',CASE WHEN protected_labels<>'{}'::jsonb THEN 'access_labels'
        WHEN names<>'[]'::jsonb THEN 'names' WHEN labels<>'{}'::jsonb THEN 'labels' ELSE 'anchor' END);
    IF kaname._authority_resource_selector_matches_v3(selector,'iam.account',account_id,
            p_account->'labels',p_account->'access_labels') IS DISTINCT FROM true THEN RETURN NULL;END IF;
    IF NOT ((p_mirror->'labels') @> pairs) THEN RETURN NULL;END IF;
    RETURN pairs;
END;
$match$;

DO $private$
DECLARE signature text; grantee record;
BEGIN
    FOREACH signature IN ARRAY ARRAY['kaname._authority_role_move_project_copy_graph_hold_v1(text,jsonb,jsonb,integer,integer)','kaname._authority_role_move_old_project_match_v1(jsonb,integer,integer,jsonb,jsonb,jsonb,jsonb,text,text)'] LOOP
        FOR grantee IN
            SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
            WHERE p.oid=to_regprocedure(signature) AND a.grantee<>p.proowner
        LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',signature,
                CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $scope_install$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('_authority_crud_storage_v3()','3f516c6b0d2fd7f26ab0d89e6da88f61470ba54d9045f9e7ab66aca9350712a0','a3b988f9e0ea9b33843c53062788a37f859bd4a9d5d1c7effbd4488d7cf0b3fe',$changes$[
 [
  " ('_authority_role_move_copy_requirements_hold_v1(jsonb,text,text,integer,integer)','3ad9612a52ef6d3d615c94439e62dfb7a1da6d545cec876867389a718cba4576',false,'v',true,'private'),\n",
  " ('_authority_role_move_copy_requirements_hold_v1(jsonb,text,text,integer,integer)','3ad9612a52ef6d3d615c94439e62dfb7a1da6d545cec876867389a718cba4576',false,'v',true,'private'),\n ('_authority_role_move_project_copy_graph_hold_v1(text,jsonb,jsonb,integer,integer)','e24a5fc109d80b3f27db2f457bdd6541107b1b6597694adb91d072626f762acf',false,'v',true,'private'),\n ('_authority_role_move_old_project_match_v1(jsonb,integer,integer,jsonb,jsonb,jsonb,jsonb,text,text)','7410529c62e5b4fb4e4fe5989ddab8135befa4d16a27b7e8fb38bb981d1969c3',false,'i',true,'private'),\n"
 ],
 [
  "  ('_authority_role_move_copy_requirements_hold_v1(jsonb,text,text,integer,integer)','jsonb',5,ARRAY['p_plan','p_actor_type','p_actor_id','p_rows','p_reads']),\n",
  "  ('_authority_role_move_copy_requirements_hold_v1(jsonb,text,text,integer,integer)','jsonb',5,ARRAY['p_plan','p_actor_type','p_actor_id','p_rows','p_reads']),\n  ('_authority_role_move_project_copy_graph_hold_v1(text,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_project_id','p_native','p_mirror','p_rows','p_reads']),\n  ('_authority_role_move_old_project_match_v1(jsonb,integer,integer,jsonb,jsonb,jsonb,jsonb,text,text)','jsonb',9,ARRAY['p_rules','p_rule_index','p_child_index','p_scope','p_target','p_account','p_mirror','p_project_id','p_mirror_account_id']),\n"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','caad893b04b5e7d7ec6b4e9d8737cc9614c4d194838d5c526a631361bb3d1c94','6887f5816495ae2a898600a48e57ca2d7bcf8c2a94c64daeefda497752365f45',$changes$[
 [
  "3f516c6b0d2fd7f26ab0d89e6da88f61470ba54d9045f9e7ab66aca9350712a0",
  "a3b988f9e0ea9b33843c53062788a37f859bd4a9d5d1c7effbd4488d7cf0b3fe"
 ]
]$changes$::jsonb),
  ('authority_metadata_service_account_access_label_ready_v1()','f70a64f42663e0c2b7ab11ea834f4b54868a56d08b593ef0536281ccad5a0f07','a1bdb56d1e1124945c6463490415027d3524497d6d077589cb44c4e249df4592',$changes$[
 [
  "3f516c6b0d2fd7f26ab0d89e6da88f61470ba54d9045f9e7ab66aca9350712a0",
  "a3b988f9e0ea9b33843c53062788a37f859bd4a9d5d1c7effbd4488d7cf0b3fe"
 ],
 [
  "caad893b04b5e7d7ec6b4e9d8737cc9614c4d194838d5c526a631361bb3d1c94",
  "6887f5816495ae2a898600a48e57ca2d7bcf8c2a94c64daeefda497752365f45"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move project source custody predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move project source custody splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move project source custody body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move project source custody function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move project source custody function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move project source custody custody differs after migration' USING ERRCODE='55000';END IF;
END;
$scope_install$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $scope_install$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('authority_metadata_service_account_access_label_ready_v1()','a1bdb56d1e1124945c6463490415027d3524497d6d077589cb44c4e249df4592','f70a64f42663e0c2b7ab11ea834f4b54868a56d08b593ef0536281ccad5a0f07',$changes$[
 [
  "6887f5816495ae2a898600a48e57ca2d7bcf8c2a94c64daeefda497752365f45",
  "caad893b04b5e7d7ec6b4e9d8737cc9614c4d194838d5c526a631361bb3d1c94"
 ],
 [
  "a3b988f9e0ea9b33843c53062788a37f859bd4a9d5d1c7effbd4488d7cf0b3fe",
  "3f516c6b0d2fd7f26ab0d89e6da88f61470ba54d9045f9e7ab66aca9350712a0"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','6887f5816495ae2a898600a48e57ca2d7bcf8c2a94c64daeefda497752365f45','caad893b04b5e7d7ec6b4e9d8737cc9614c4d194838d5c526a631361bb3d1c94',$changes$[
 [
  "a3b988f9e0ea9b33843c53062788a37f859bd4a9d5d1c7effbd4488d7cf0b3fe",
  "3f516c6b0d2fd7f26ab0d89e6da88f61470ba54d9045f9e7ab66aca9350712a0"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','a3b988f9e0ea9b33843c53062788a37f859bd4a9d5d1c7effbd4488d7cf0b3fe','3f516c6b0d2fd7f26ab0d89e6da88f61470ba54d9045f9e7ab66aca9350712a0',$changes$[
 [
  "  ('_authority_role_move_copy_requirements_hold_v1(jsonb,text,text,integer,integer)','jsonb',5,ARRAY['p_plan','p_actor_type','p_actor_id','p_rows','p_reads']),\n  ('_authority_role_move_project_copy_graph_hold_v1(text,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_project_id','p_native','p_mirror','p_rows','p_reads']),\n  ('_authority_role_move_old_project_match_v1(jsonb,integer,integer,jsonb,jsonb,jsonb,jsonb,text,text)','jsonb',9,ARRAY['p_rules','p_rule_index','p_child_index','p_scope','p_target','p_account','p_mirror','p_project_id','p_mirror_account_id']),\n",
  "  ('_authority_role_move_copy_requirements_hold_v1(jsonb,text,text,integer,integer)','jsonb',5,ARRAY['p_plan','p_actor_type','p_actor_id','p_rows','p_reads']),\n"
 ],
 [
  " ('_authority_role_move_copy_requirements_hold_v1(jsonb,text,text,integer,integer)','3ad9612a52ef6d3d615c94439e62dfb7a1da6d545cec876867389a718cba4576',false,'v',true,'private'),\n ('_authority_role_move_project_copy_graph_hold_v1(text,jsonb,jsonb,integer,integer)','e24a5fc109d80b3f27db2f457bdd6541107b1b6597694adb91d072626f762acf',false,'v',true,'private'),\n ('_authority_role_move_old_project_match_v1(jsonb,integer,integer,jsonb,jsonb,jsonb,jsonb,text,text)','7410529c62e5b4fb4e4fe5989ddab8135befa4d16a27b7e8fb38bb981d1969c3',false,'i',true,'private'),\n",
  " ('_authority_role_move_copy_requirements_hold_v1(jsonb,text,text,integer,integer)','3ad9612a52ef6d3d615c94439e62dfb7a1da6d545cec876867389a718cba4576',false,'v',true,'private'),\n"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move project source custody predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move project source custody splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move project source custody body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move project source custody function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move project source custody function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move project source custody custody differs after migration' USING ERRCODE='55000';END IF;
END;
$scope_install$;
-- +goose StatementEnd
DROP FUNCTION kaname._authority_role_move_old_project_match_v1(jsonb,integer,integer,jsonb,jsonb,jsonb,jsonb,text,text);
DROP FUNCTION kaname._authority_role_move_project_copy_graph_hold_v1(text,jsonb,jsonb,integer,integer);
