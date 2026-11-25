-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Форма будущего чтения выводится из обеих раскладок роли и переписи
-- прямых привязок. Сами объекты, дети и держатели кортежей здесь не читаются.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_selector_versions_v1(
    p_role_id text,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $versions$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    images jsonb;
    n integer;
    cap integer;
BEGIN
    IF coalesce(p_role_id,'')='' THEN RAISE EXCEPTION 'selector role missing' USING ERRCODE='42501'; END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN 2 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 3 AND 4096 THEN
        RAISE EXCEPTION 'selector generation read budget exceeded' USING ERRCODE='54000';
    END IF;
    LOCK TABLE ONLY kaname.role_rule_selectors IN SHARE MODE NOWAIT;
    IF NOT EXISTS(SELECT FROM pg_class c WHERE c.oid='kaname.role_rule_selectors'::regclass
        AND c.relowner=current_user::regrole AND c.relkind='r' AND c.relpersistence='p'
        AND NOT (c.relispartition OR c.relrowsecurity OR c.relforcerowsecurity OR c.relhasrules)
        AND has_table_privilege((proof->>'invoker_oid')::oid,c.oid,'SELECT')
        AND NOT EXISTS(SELECT FROM pg_inherits i WHERE i.inhparent=c.oid OR i.inhrelid=c.oid)) THEN
        RAISE EXCEPTION 'selector generation source custody differs' USING ERRCODE='42501';
    END IF;
    cap:=least(4096,p_rows-2);
    -- Не-SHA историческая строка не выбирает канонический FP. Её поколение
    -- остаётся в переписи, без накопления произвольно длинного текста.
    SELECT count(*),coalesce(jsonb_agg(jsonb_build_array(s.x,s.t,s.fp) ORDER BY s.t COLLATE "C"),'[]')
        INTO n,images FROM (SELECT r.xmin::text x,r.ctid::text t,CASE WHEN octet_length(r.rule_fp)=64 AND r.rule_fp ~ '^[0-9a-f]{64}$' THEN r.rule_fp END fp FROM ONLY kaname.role_rule_selectors r
            WHERE r.role_id=p_role_id LIMIT cap+1) s;
    IF n>cap OR octet_length(images::text)>8388608 THEN
        RAISE EXCEPTION 'selector generation census exceeds budget' USING ERRCODE='54000';
    END IF;
    RETURN jsonb_build_object('versions',images,'rows',2+n,'reads',3);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'selector generation source busy' USING ERRCODE='40001';
END;
$versions$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_predicate_plan_v1(
    p_prepared jsonb,p_holders jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $predicates$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    old_role jsonb:=p_prepared#>'{role,physical,2}';
    new_role jsonb:=p_prepared#>'{role,new_role}';
    role_id text:=p_prepared->>'role_id';
    invoker oid:=(proof->>'invoker_oid')::oid;
    versions jsonb;fps jsonb;bundle record;catalog jsonb;models jsonb;
    side text;role_row jsonb;layout jsonb;compiled jsonb;templates jsonb:='{}';
    old_ordinary_source jsonb;cluster_types jsonb;rule_value jsonb;sel jsonb;node jsonb;types jsonb;object_ids jsonb;
    holder record;target jsonb;targets jsonb;target_ids jsonb;subject_count integer;nonclass boolean;
    nested boolean;effective_node jsonb;object_type text;read_type text;names jsonb;guard text;
    receipt jsonb;items jsonb[]:=ARRAY[]::jsonb[];used_rows integer:=1;used_reads integer:=1;
    bytes integer:=2;first_item integer;counts jsonb;summary jsonb;summaries jsonb[]:=ARRAY[]::jsonb[];
    scope_root jsonb;plan jsonb;catalog_rows integer;
BEGIN
    IF jsonb_typeof(p_holders) IS DISTINCT FROM 'object'
        OR jsonb_typeof(p_prepared->'selector_versions') IS DISTINCT FROM 'array'
        OR old_role->>'id' IS DISTINCT FROM role_id OR new_role->>'id' IS DISTINCT FROM role_id
        OR coalesce(role_id,'')='' OR p_prepared->'nonce' IS DISTINCT FROM proof->'nonce'
        OR p_prepared->'invoker_oid' IS DISTINCT FROM proof->'invoker_oid' THEN
        RAISE EXCEPTION 'selector obligation source identity differs' USING ERRCODE='42501';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN 1 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 1 AND 4096
        OR octet_length(p_holders::text)>8388608 THEN
        RAISE EXCEPTION 'selector obligation input budget exceeded' USING ERRCODE='54000';
    END IF;
    -- Пустой состав получателей выведен из уже перепроверенного OLD.
    -- Отсутствие прямых обязанностей ничего не говорит о копиях без выдач.
    IF p_holders='{}'::jsonb THEN
        RETURN jsonb_build_object('plan',jsonb_build_object('catalog_id',proof->'catalog_id','holders','[]'::jsonb,'items','[]'::jsonb),
            'rows',used_rows,'reads',used_reads);
    END IF;
    versions:=kaname._authority_role_move_selector_versions_v1(role_id,p_rows-used_rows,p_reads-used_reads);
    IF versions->'versions' IS DISTINCT FROM p_prepared->'selector_versions' THEN
        RAISE EXCEPTION 'selector layout changed after preparation' USING ERRCODE='40001';
    END IF;
    used_rows:=used_rows+(versions->>'rows')::integer;
    used_reads:=used_reads+(versions->>'reads')::integer+1;
    IF used_reads>p_reads THEN RAISE EXCEPTION 'selector catalog read budget exceeded' USING ERRCODE='54000';END IF;
    IF NOT coalesce(has_table_privilege(invoker,'kaname.authority_semantic_identity','SELECT'),false)
        OR NOT coalesce(has_function_privilege(invoker,'kaname.authority_protocol_read_bundle()','EXECUTE'),false) THEN
        RAISE EXCEPTION 'selector catalog read denied' USING ERRCODE='42501';
    END IF;
    SELECT b.catalog_json,b.model_id,b.catalog_id,b.projector_version INTO bundle
        FROM ONLY kaname.authority_bundle_handoff b WHERE b.singleton FOR SHARE OF b NOWAIT;
    IF NOT FOUND OR bundle.catalog_id IS DISTINCT FROM proof->>'catalog_id'
        OR bundle.model_id IS DISTINCT FROM proof->>'model_id' OR bundle.projector_version IS DISTINCT FROM proof->>'projector_version'
        OR octet_length(bundle.catalog_json) NOT BETWEEN 1 AND 8388608
        OR encode(sha256(bundle.catalog_json),'hex') IS DISTINCT FROM bundle.catalog_id THEN
        RAISE EXCEPTION 'selector catalog differs from admitted identity' USING ERRCODE='40001';
    END IF;
    catalog:=convert_from(bundle.catalog_json,'UTF8')::jsonb;
    SELECT sum(jsonb_array_length(coalesce(nullif(catalog#>ARRAY[part,field],'null'),'[]'))) INTO catalog_rows
        FROM unnest(ARRAY['Live','Retired']) part CROSS JOIN unnest(ARRAY['Modules','Resources','Verbs']) field;
    used_rows:=used_rows+1+jsonb_array_length(old_role->'rules')+jsonb_array_length(coalesce(nullif(catalog#>'{Live,Resources}','null'),'[]'));
    IF used_rows+6*catalog_rows>p_rows THEN RAISE EXCEPTION 'selector catalog row budget exceeded' USING ERRCODE='54000';END IF;
    SELECT coalesce(jsonb_agg(v->2),'[]') INTO fps FROM jsonb_array_elements(versions->'versions') v WHERE v->2<>'null'::jsonb;
    -- Модели только живых типов. У снятого типа всё равно проверяется предикат:
    -- результат будущего чтения и ветвь REJECTED могут быть непустыми.
    SELECT coalesce(jsonb_object_agg((r->>'Module')||'.'||(r->>'Resource'),r->'ObjectType'),'{}') INTO models
        FROM jsonb_array_elements(coalesce(nullif(catalog#>'{Live,Resources}','null'),'[]')) r;
    -- Старый ABI раскладки предшествует iam.accessLabel.apply. Без сохранённого
    -- отпечатка отдельное правило apply даёт только управляющую возможность.
    -- Неканонические смеси метаправ с защищённым селектором требуют отказа.
    SELECT coalesce(jsonb_agg(r.rule ORDER BY r.ord),'[]') INTO old_ordinary_source
        FROM jsonb_array_elements(old_role->'rules') WITH ORDINALITY r(rule,ord)
        WHERE NOT (r.rule->>'module'='iam' AND r.rule->'resources' ? 'accessLabel'
            AND EXISTS(SELECT FROM jsonb_array_elements_text(r.rule->'verbs') v WHERE lower(v)='apply')
            AND NOT (fps ? kaname._authority_resource_rule_fingerprint_v2(r.rule,false)));
    IF EXISTS(SELECT FROM jsonb_array_elements(old_role->'rules') r WHERE r->>'module'='iam'
        AND (EXISTS(SELECT FROM jsonb_array_elements(coalesce(nullif(r->'children','null'),'[]')) c
            WHERE c->'resources' ? 'accessLabel' AND EXISTS(SELECT FROM jsonb_array_elements_text(c->'verbs') v WHERE lower(v)='apply'))
        OR (r->'resources' ? 'accessLabel' AND EXISTS(SELECT FROM jsonb_array_elements_text(r->'verbs') v WHERE lower(v)='apply')
            AND jsonb_array_length(coalesce(nullif(r->'children','null'),'[]'))>0)
        OR (r->'match_access_labels' IS NOT NULL AND r->'match_access_labels'<>'null'::jsonb
            AND ((r->'resources' ? 'accessBinding' AND EXISTS(SELECT FROM jsonb_array_elements_text(r->'verbs') v WHERE lower(v)='create'))
            OR (r->'resources' ? 'role' AND EXISTS(SELECT FROM jsonb_array_elements_text(r->'verbs') v WHERE lower(v)='bind')))))) THEN
        RAISE EXCEPTION 'unsupported protected selector and grant capability shape' USING ERRCODE='42501';
    END IF;
    FOREACH side IN ARRAY ARRAY['old','new'] LOOP
        role_row:=CASE side WHEN 'old' THEN old_role ELSE new_role END;
        layout:=CASE side WHEN 'old' THEN kaname._authority_resource_rule_layout_v2(jsonb_set(role_row,'{rules}',old_ordinary_source),fps)
            ELSE role_row->'rules' END;
        -- Авторское значение null эквивалентно отсутствующей ветви; именно
        -- такой материализующий образ получает обычный компилятор роли.
        layout:=jsonb_strip_nulls(layout);
        compiled:=kaname._authority_resource_withdrawal_role_projection_v2(role_row,'[]',layout,catalog);
        used_rows:=used_rows+(compiled->>'work')::integer+jsonb_array_length(layout);
        IF used_rows>p_rows THEN RAISE EXCEPTION 'selector layout work budget exceeded' USING ERRCODE='54000';END IF;
        cluster_types:='{}';
        FOR rule_value IN SELECT value FROM jsonb_array_elements(layout) LOOP
            cluster_types:=cluster_types||jsonb_build_object(kaname._authority_resource_rule_fingerprint_v2(rule_value,false),
                kaname._authority_resource_materialized_types_v2(rule_value,1));
        END LOOP;
        templates:=templates||jsonb_build_object(side,jsonb_build_object('selectors',compiled->'selectors','cluster_types',cluster_types));
    END LOOP;

    FOR holder IN SELECT key,value FROM jsonb_each(p_holders) ORDER BY key COLLATE "C" LOOP
        target:=coalesce(holder.value#>'{target,resources}','[]');
        IF jsonb_typeof(holder.value->'target') IS DISTINCT FROM 'object'
            OR ((holder.value->'target') ? 'allInScope' AND jsonb_typeof(holder.value#>'{target,allInScope}') IS DISTINCT FROM 'boolean')
            OR jsonb_typeof(target) IS DISTINCT FROM 'array' OR jsonb_array_length(target)>256 THEN
            RAISE EXCEPTION 'selector target form differs' USING ERRCODE='42501';
        END IF;
        subject_count:=jsonb_array_length(holder.value->'subjects');
        used_rows:=used_rows+1+subject_count+jsonb_array_length(target);
        IF used_rows>p_rows THEN RAISE EXCEPTION 'selector target budget exceeded' USING ERRCODE='54000';END IF;
        SELECT EXISTS(SELECT FROM jsonb_array_elements(holder.value->'subjects') s WHERE s->>0<>'system_class') INTO nonclass;
        IF EXISTS(SELECT FROM jsonb_array_elements(target) r WHERE coalesce(r->>'type','')=''
            OR coalesce(r->>'id','')='' OR jsonb_typeof(r->'type') IS DISTINCT FROM 'string'
            OR jsonb_typeof(r->'id') IS DISTINCT FROM 'string' OR octet_length(r->>'id')>16384
            OR r->>'id' ~ '[:#*[:space:][:cntrl:]]') THEN
            RAISE EXCEPTION 'selector finite target identity invalid' USING ERRCODE='42501';
        END IF;
        SELECT coalesce(jsonb_object_agg(t.typ,t.ids),'{}') INTO targets
          FROM (SELECT d.typ,jsonb_agg(d.id ORDER BY d.id COLLATE "C") AS ids
            FROM (SELECT DISTINCT r->>'type' typ,r->>'id' id FROM jsonb_array_elements(target) r) d GROUP BY d.typ) t;
        -- Чтение самого аккаунта/проекта требуется даже при нуле предикатов.
        scope_root:=CASE WHEN holder.value#>>'{scope,0}' IN ('project','account')
            THEN jsonb_build_array('iam.'||(holder.value#>>'{scope,0}'),holder.value#>'{scope,1}') END;
        counts:='{}';
        FOREACH side IN ARRAY ARRAY['old','new'] LOOP
            first_item:=cardinality(items);
            FOR sel IN SELECT value FROM jsonb_array_elements(templates#>ARRAY[side,'selectors']) LOOP
                used_rows:=used_rows+1;
                IF used_rows>p_rows THEN RAISE EXCEPTION 'selector obligation work budget exceeded' USING ERRCODE='54000';END IF;
                nested:=jsonb_typeof(sel->'Container')='object';
                IF jsonb_array_length(sel->'Verbs')=0 THEN CONTINUE;END IF;
                IF NOT nonclass AND (nested OR NOT EXISTS(SELECT FROM jsonb_array_elements_text(sel->'Verbs') v
                        WHERE lower(btrim(v)) IN ('get','list'))) THEN CONTINUE;END IF;
                node:=CASE WHEN nested THEN sel->'Container' ELSE sel END;
                types:=CASE WHEN NOT nested AND holder.value#>>'{scope,0}'='cluster'
                        THEN templates#>ARRAY[side,'cluster_types',sel->>'RuleFP'] ELSE sel->'ObjectTypes' END;
                types:=coalesce(nullif(types,'null'),'[]');
                -- Даже если у ребёнка нет типов, основной материализатор читает контейнеры.
                IF nested AND types='[]'::jsonb THEN types:='[null]';END IF;
                FOR object_type IN SELECT DISTINCT t COLLATE "C" FROM jsonb_array_elements_text(types) t ORDER BY 1 LOOP
                    used_rows:=used_rows+1;
                    IF used_rows>p_rows THEN RAISE EXCEPTION 'selector typed obligation budget exceeded' USING ERRCODE='54000';END IF;
                    read_type:=CASE WHEN nested THEN node->>'Type' ELSE object_type END;
                    target_ids:=coalesce(targets->read_type,'[]');
                    IF target<>'[]'::jsonb AND target_ids='[]'::jsonb THEN CONTINUE;END IF;
                    effective_node:=node;
                    IF node->>'Arm'='0' AND target_ids<>'[]'::jsonb THEN
                        effective_node:=node||jsonb_build_object('Arm',1,'ResourceNames',target_ids);
                    END IF;
                    names:=coalesce(nullif(node->'ResourceNames','null'),'[]');
                    object_ids:=CASE WHEN target_ids<>'[]'::jsonb THEN target_ids ELSE names END;
                    IF node->>'Arm'='1' AND target_ids<>'[]'::jsonb THEN
                        SELECT coalesce(jsonb_agg(id ORDER BY id COLLATE "C"),'[]') INTO object_ids
                            FROM jsonb_array_elements_text(target_ids) id WHERE names ? id;
                        IF object_ids='[]'::jsonb THEN CONTINUE;END IF;
                    END IF;
                    guard:=CASE WHEN target_ids<>'[]'::jsonb OR node->>'Arm'='1' THEN 'objects'
                        WHEN node->>'Arm' IN ('2','3') OR holder.value#>>'{scope,0}'='cluster' THEN 'whole_type'
                        ELSE 'scope' END;
                    -- Вложенная обязанность именует точную ветвь ребёнка и
                    -- предикат контейнера. Множество родителей и пустые наборы
                    -- их детей предстоит подтвердить отдельным удержанным чтением.
                    receipt:=jsonb_build_object('side',side,'binding_id',holder.key,'scope',holder.value->'scope',
                        'rule_fp',sel->'RuleFP','read_type',read_type,'model',models->read_type,
                        'guard',guard,'object_ids',object_ids,
                        'predicate',effective_node-ARRAY['Grants','Verbs','ObjectTypes','Container'],
                        'target_ids',target_ids);
                    IF nested THEN
                        receipt:=receipt||jsonb_build_object('child_type',object_type,'child_model',models->object_type,
                            'child_predicate',sel-ARRAY['Grants','Verbs','ObjectTypes','Container']);
                    END IF;
                    bytes:=bytes+octet_length(receipt::text)+2;
                    IF bytes>8388608 THEN RAISE EXCEPTION 'selector obligation byte budget exceeded' USING ERRCODE='54000'; END IF;
                    items:=array_append(items,receipt);
                END LOOP;
            END LOOP;
            counts:=counts||jsonb_build_object(side,cardinality(items)-first_item);
        END LOOP;
        summary:=jsonb_build_object('binding_id',holder.key,'scope_root',scope_root,'predicates',counts);
        bytes:=bytes+octet_length(summary::text)+2;
        IF bytes>8388608 THEN RAISE EXCEPTION 'selector obligation summary exceeds budget' USING ERRCODE='54000';END IF;
        summaries:=array_append(summaries,summary);
    END LOOP;
    plan:=jsonb_build_object('catalog_id',bundle.catalog_id,'holders',to_jsonb(summaries),'items',to_jsonb(items));
    IF octet_length(plan::text)>8388608 THEN RAISE EXCEPTION 'selector obligation output exceeds budget' USING ERRCODE='54000';END IF;
    RETURN jsonb_build_object('plan',plan,
        'rows',used_rows,'reads',used_reads);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'selector catalog source busy' USING ERRCODE='40001';
END;
$predicates$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure;grantee record;
BEGIN
    FOREACH fn IN ARRAY ARRAY['kaname._authority_role_move_selector_versions_v1(text,integer,integer)'::regprocedure,
        'kaname._authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)'::regprocedure] LOOP
        FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_proc p
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
                CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $obligations$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','2c19697cdf3f2a8a4874c49c0eae766897c1c27aa4ce112e69dc4d04a659477a','42ae559cb6b9e325501849eab7bb5280c184cc6015a29c6dbd5eff620a132b0f',$changes$[
 [
  "    copies jsonb;",
  "    copies jsonb;\n    selector_versions jsonb:='[]';\n    selector_source jsonb;"
 ],
 [
  "    copies:=kaname._authority_role_move_copy_requirements_hold_v1",
  "    -- Удержанные отзыв и истечение окончательны: финальные часы строго позднее.\n    -- Неопределённая пригодность сохраняет полную проверку поколения селекторов.\n    IF EXISTS(SELECT FROM jsonb_array_elements(carriers#>'{old,bindings}') b\n        WHERE b#>>'{2,role_id}'=p_input->>'role_id'\n          AND (b#>>'{2,status}'='REVOKED' OR b#>>'{2,revoked_at}' IS NOT NULL\n            OR (b#>>'{2,status}' IN ('ACTIVE','PENDING') AND isfinite((proof->>'decision_at')::timestamptz)\n                AND (b#>>'{2,expires_at}')::timestamptz<=(proof->>'decision_at')::timestamptz)) IS NOT TRUE) THEN\n        selector_source:=kaname._authority_role_move_selector_versions_v1(p_input->>'role_id',p_rows-used_rows,p_reads-used_reads);\n        selector_versions:=selector_source->'versions';\n        used_rows:=used_rows+(selector_source->>'rows')::integer;\n        used_reads:=used_reads+(selector_source->>'reads')::integer;\n    END IF;\n    copies:=kaname._authority_role_move_copy_requirements_hold_v1"
 ],
 [
  "'binding_census',carriers->'old'",
  "'binding_census',carriers->'old','selector_versions',selector_versions"
 ]
]$changes$::jsonb),
  ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','8cffc9e80a318ebb283446f57b16c6afa2deb4b06f6f075a91cf6fefcf81b273','971d66d0a1329bb4dca49ea02c9b5fbae050ea5f29ccfb0cd8a15c49689c0218',$changes$[
 [
  "    binding_new jsonb;",
  "    binding_new jsonb;\n    predicates jsonb;"
 ],
 [
  "    result:=kaname._authority_role_move_copy_requirements_require_v1",
  "    predicates:=kaname._authority_role_move_predicate_plan_v1(p_frozen,binding_new->'holders',p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(predicates->>'rows')::integer;\n    used_reads:=used_reads+(predicates->>'reads')::integer;\n    result:=kaname._authority_role_move_copy_requirements_require_v1"
 ],
 [
  "'binding_new',binding_new->'holders','rows',",
  "'binding_new',binding_new->'holders','predicate_plan',predicates->'plan','rows',"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','707327736532ccc1a90362e3dcbccf69e4f0b86c4215fcf41cea66f972331e23','4b39a28dcd1c82882237043711c8da7c61d20d056bfb4e642f252a3ff34037e6',$changes$[
 [
  "2c19697cdf3f2a8a4874c49c0eae766897c1c27aa4ce112e69dc4d04a659477a",
  "42ae559cb6b9e325501849eab7bb5280c184cc6015a29c6dbd5eff620a132b0f"
 ],
 [
  "8cffc9e80a318ebb283446f57b16c6afa2deb4b06f6f075a91cf6fefcf81b273",
  "971d66d0a1329bb4dca49ea02c9b5fbae050ea5f29ccfb0cd8a15c49689c0218"
 ],
 [
  " ('_authority_role_move_binding_new_v1(jsonb,jsonb,integer)','d1bc74c3bd77e3082e27dbf89c536dd595bc98dde1efefa4b3f567d9c1130dbc',false,'i',true,'private'),",
  " ('_authority_role_move_binding_new_v1(jsonb,jsonb,integer)','d1bc74c3bd77e3082e27dbf89c536dd595bc98dde1efefa4b3f567d9c1130dbc',false,'i',true,'private'),\n ('_authority_role_move_selector_versions_v1(text,integer,integer)','ae68e9b78d71233c2ba6ff1b31144549353ef8ac89eeaeb7a615408bc3f90da4',false,'v',true,'private'),\n ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','cb231a595f6dd57a28f293c74b87d2dae78fdfcca5ab9deb538130f1cfc7cab9',false,'v',true,'private'),"
 ],
 [
  "  ('_authority_role_move_binding_new_v1(jsonb,jsonb,integer)','jsonb',3,ARRAY['p_prepared','p_status','p_rows']),",
  "  ('_authority_role_move_binding_new_v1(jsonb,jsonb,integer)','jsonb',3,ARRAY['p_prepared','p_status','p_rows']),\n  ('_authority_role_move_selector_versions_v1(text,integer,integer)','jsonb',3,ARRAY['p_role_id','p_rows','p_reads']),\n  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','3dfc1f4884a02964b029b6b3f242cae32d42ff2e84da42b70376310ac9cd0065','a11f765916935e1750ff37b720a31b11ffa5864a7d3a917a7f5ef4e97d56314d',$changes$[
 [
  "707327736532ccc1a90362e3dcbccf69e4f0b86c4215fcf41cea66f972331e23",
  "4b39a28dcd1c82882237043711c8da7c61d20d056bfb4e642f252a3ff34037e6"
 ]
]$changes$::jsonb),
  ('authority_metadata_service_account_access_label_ready_v1()','f6bf60fab853f55d341b49c02c17d6cc5e3d5102cac46eff79834de1f8886c05','d1b495c4ab94a250bd61d214ec2a228b622acc87ee13f35575c3908aeb131d9c',$changes$[
 [
  "707327736532ccc1a90362e3dcbccf69e4f0b86c4215fcf41cea66f972331e23",
  "4b39a28dcd1c82882237043711c8da7c61d20d056bfb4e642f252a3ff34037e6"
 ],
 [
  "3dfc1f4884a02964b029b6b3f242cae32d42ff2e84da42b70376310ac9cd0065",
  "a11f765916935e1750ff37b720a31b11ffa5864a7d3a917a7f5ef4e97d56314d"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move selector obligations predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move selector obligations splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move selector obligations body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move selector obligations function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move selector obligations function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move selector obligations custody differs after migration' USING ERRCODE='55000';END IF;
END;
$obligations$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $obligations$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('authority_metadata_service_account_access_label_ready_v1()','d1b495c4ab94a250bd61d214ec2a228b622acc87ee13f35575c3908aeb131d9c','f6bf60fab853f55d341b49c02c17d6cc5e3d5102cac46eff79834de1f8886c05',$changes$[
 [
  "a11f765916935e1750ff37b720a31b11ffa5864a7d3a917a7f5ef4e97d56314d",
  "3dfc1f4884a02964b029b6b3f242cae32d42ff2e84da42b70376310ac9cd0065"
 ],
 [
  "4b39a28dcd1c82882237043711c8da7c61d20d056bfb4e642f252a3ff34037e6",
  "707327736532ccc1a90362e3dcbccf69e4f0b86c4215fcf41cea66f972331e23"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','a11f765916935e1750ff37b720a31b11ffa5864a7d3a917a7f5ef4e97d56314d','3dfc1f4884a02964b029b6b3f242cae32d42ff2e84da42b70376310ac9cd0065',$changes$[
 [
  "4b39a28dcd1c82882237043711c8da7c61d20d056bfb4e642f252a3ff34037e6",
  "707327736532ccc1a90362e3dcbccf69e4f0b86c4215fcf41cea66f972331e23"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','4b39a28dcd1c82882237043711c8da7c61d20d056bfb4e642f252a3ff34037e6','707327736532ccc1a90362e3dcbccf69e4f0b86c4215fcf41cea66f972331e23',$changes$[
 [
  "  ('_authority_role_move_binding_new_v1(jsonb,jsonb,integer)','jsonb',3,ARRAY['p_prepared','p_status','p_rows']),\n  ('_authority_role_move_selector_versions_v1(text,integer,integer)','jsonb',3,ARRAY['p_role_id','p_rows','p_reads']),\n  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),",
  "  ('_authority_role_move_binding_new_v1(jsonb,jsonb,integer)','jsonb',3,ARRAY['p_prepared','p_status','p_rows']),"
 ],
 [
  " ('_authority_role_move_binding_new_v1(jsonb,jsonb,integer)','d1bc74c3bd77e3082e27dbf89c536dd595bc98dde1efefa4b3f567d9c1130dbc',false,'i',true,'private'),\n ('_authority_role_move_selector_versions_v1(text,integer,integer)','ae68e9b78d71233c2ba6ff1b31144549353ef8ac89eeaeb7a615408bc3f90da4',false,'v',true,'private'),\n ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','cb231a595f6dd57a28f293c74b87d2dae78fdfcca5ab9deb538130f1cfc7cab9',false,'v',true,'private'),",
  " ('_authority_role_move_binding_new_v1(jsonb,jsonb,integer)','d1bc74c3bd77e3082e27dbf89c536dd595bc98dde1efefa4b3f567d9c1130dbc',false,'i',true,'private'),"
 ],
 [
  "971d66d0a1329bb4dca49ea02c9b5fbae050ea5f29ccfb0cd8a15c49689c0218",
  "8cffc9e80a318ebb283446f57b16c6afa2deb4b06f6f075a91cf6fefcf81b273"
 ],
 [
  "42ae559cb6b9e325501849eab7bb5280c184cc6015a29c6dbd5eff620a132b0f",
  "2c19697cdf3f2a8a4874c49c0eae766897c1c27aa4ce112e69dc4d04a659477a"
 ]
]$changes$::jsonb),
  ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','971d66d0a1329bb4dca49ea02c9b5fbae050ea5f29ccfb0cd8a15c49689c0218','8cffc9e80a318ebb283446f57b16c6afa2deb4b06f6f075a91cf6fefcf81b273',$changes$[
 [
  "'binding_new',binding_new->'holders','predicate_plan',predicates->'plan','rows',",
  "'binding_new',binding_new->'holders','rows',"
 ],
 [
  "    predicates:=kaname._authority_role_move_predicate_plan_v1(p_frozen,binding_new->'holders',p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(predicates->>'rows')::integer;\n    used_reads:=used_reads+(predicates->>'reads')::integer;\n    result:=kaname._authority_role_move_copy_requirements_require_v1",
  "    result:=kaname._authority_role_move_copy_requirements_require_v1"
 ],
 [
  "    binding_new jsonb;\n    predicates jsonb;",
  "    binding_new jsonb;"
 ]
]$changes$::jsonb),
  ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','42ae559cb6b9e325501849eab7bb5280c184cc6015a29c6dbd5eff620a132b0f','2c19697cdf3f2a8a4874c49c0eae766897c1c27aa4ce112e69dc4d04a659477a',$changes$[
 [
  "'binding_census',carriers->'old','selector_versions',selector_versions",
  "'binding_census',carriers->'old'"
 ],
 [
  "    -- Удержанные отзыв и истечение окончательны: финальные часы строго позднее.\n    -- Неопределённая пригодность сохраняет полную проверку поколения селекторов.\n    IF EXISTS(SELECT FROM jsonb_array_elements(carriers#>'{old,bindings}') b\n        WHERE b#>>'{2,role_id}'=p_input->>'role_id'\n          AND (b#>>'{2,status}'='REVOKED' OR b#>>'{2,revoked_at}' IS NOT NULL\n            OR (b#>>'{2,status}' IN ('ACTIVE','PENDING') AND isfinite((proof->>'decision_at')::timestamptz)\n                AND (b#>>'{2,expires_at}')::timestamptz<=(proof->>'decision_at')::timestamptz)) IS NOT TRUE) THEN\n        selector_source:=kaname._authority_role_move_selector_versions_v1(p_input->>'role_id',p_rows-used_rows,p_reads-used_reads);\n        selector_versions:=selector_source->'versions';\n        used_rows:=used_rows+(selector_source->>'rows')::integer;\n        used_reads:=used_reads+(selector_source->>'reads')::integer;\n    END IF;\n    copies:=kaname._authority_role_move_copy_requirements_hold_v1",
  "    copies:=kaname._authority_role_move_copy_requirements_hold_v1"
 ],
 [
  "    copies jsonb;\n    selector_versions jsonb:='[]';\n    selector_source jsonb;",
  "    copies jsonb;"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move selector obligations predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move selector obligations splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move selector obligations body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move selector obligations function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move selector obligations function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move selector obligations custody differs after migration' USING ERRCODE='55000';END IF;
END;
$obligations$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer);
DROP FUNCTION kaname._authority_role_move_selector_versions_v1(text,integer,integer);
