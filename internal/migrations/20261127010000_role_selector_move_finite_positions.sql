-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Физические позиции хранятся отдельно от результата селектора. Поздние
-- копии accessLabels, целый тип, потомки и общие выдачи требуют своих чтений.
-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_finite_positions_v1(
    p_frozen jsonb,p_plan jsonb,p_replay boolean,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $positions$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    expected jsonb:=p_frozen->'finite_positions';
    pos record;rel regclass;row_xmin xid;row_tid tid;row_value jsonb;state jsonb;key_value text;found_row boolean;
    coord_keys text[]:=ARRAY[]::text[];states jsonb[]:=ARRAY[]::jsonb[];positions jsonb;
    used_rows integer;used_reads integer:=0;bytes bigint:=2;n bigint;
BEGIN
    IF p_replay IS NULL OR p_frozen->'nonce' IS DISTINCT FROM proof->'nonce'
        OR p_frozen->'invoker_oid' IS DISTINCT FROM proof->'invoker_oid'
        OR p_frozen#>>'{copies,backend_pid}' IS DISTINCT FROM pg_backend_pid()::text
        OR p_frozen#>>'{copies,txid}' IS DISTINCT FROM pg_current_xact_id()::text
        OR coalesce(p_frozen->>'role_id','')='' OR p_plan->'catalog_id' IS DISTINCT FROM proof->'catalog_id'
        OR p_frozen#>>'{role,physical,2,id}' IS DISTINCT FROM p_frozen->>'role_id'
        OR p_frozen#>>'{role,new_role,id}' IS DISTINCT FROM p_frozen->>'role_id'
        OR jsonb_typeof(p_plan->'items') IS DISTINCT FROM 'array' OR jsonb_typeof(p_plan->'holders') IS DISTINCT FROM 'array'
        OR (p_replay AND jsonb_typeof(expected) IS DISTINCT FROM 'object') THEN
        RAISE EXCEPTION 'finite position owner source differs' USING ERRCODE='42501';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 0 AND 4096
        OR octet_length(p_plan::text)>8388608 OR octet_length(p_frozen::text)>8388608 THEN
        RAISE EXCEPTION 'finite position input budget exceeded' USING ERRCODE='54000';
    END IF;
    used_rows:=jsonb_array_length(p_plan->'items')+jsonb_array_length(p_plan->'holders');
    IF used_rows>p_rows THEN RAISE EXCEPTION 'finite position plan budget exceeded' USING ERRCODE='54000';END IF;
    SELECT coalesce(sum(jsonb_array_length(i->'object_ids')),0) INTO n
        FROM jsonb_array_elements(p_plan->'items') i WHERE i->>'guard'='objects';
    IF n>p_rows-used_rows THEN RAISE EXCEPTION 'finite target expansion budget exceeded' USING ERRCODE='54000';END IF;
    used_rows:=used_rows+n::integer;
    -- Ссылки получателей, сторон и FP остаются в исходном плане. Общая позиция
    -- объединяет только чтение строки, а не ветви правил и не владельцев выдачи.
    FOR pos IN WITH coords AS (
        SELECT h#>>'{scope_root,0}' typ,h#>>'{scope_root,1}' id FROM jsonb_array_elements(p_plan->'holders') h
            WHERE jsonb_typeof(h->'scope_root')='array'
        UNION ALL
        SELECT i->>'read_type',v.id FROM jsonb_array_elements(p_plan->'items') i
            CROSS JOIN LATERAL jsonb_array_elements_text(i->'object_ids') v(id) WHERE i->>'guard'='objects'
    ) SELECT DISTINCT typ COLLATE "C" typ,id COLLATE "C" id FROM coords ORDER BY 1,2 LOOP
        IF coalesce(pos.typ,'')='' OR coalesce(pos.id,'')='' OR pos.id ~ '[:#*[:space:][:cntrl:]]' THEN
            RAISE EXCEPTION 'invalid finite position coordinate' USING ERRCODE='42501';
        END IF;
        key_value:=pos.typ||':'||pos.id;
        IF p_replay AND NOT (expected ? key_value) THEN
            RAISE EXCEPTION 'finite position missing from preparation' USING ERRCODE='40001';
        END IF;
        rel:=CASE pos.typ WHEN 'iam.account' THEN 'kaname.accounts'::regclass
            WHEN 'iam.project' THEN 'kaname.projects'::regclass
            WHEN 'iam.accessBinding' THEN 'kaname.access_bindings'::regclass END;
        row_value:=NULL;
        -- Пустое точечное чтение аккаунта/проекта не удерживает промежуток.
        -- Даже появившуюся позднее строку нельзя принять за подготовленную.
        IF rel IS NULL THEN
            state:=jsonb_build_object('state','pending_source');
        ELSE
            used_rows:=used_rows+3;used_reads:=used_reads+3;
            IF used_rows>p_rows OR used_reads>p_reads THEN
                RAISE EXCEPTION 'finite position source budget exceeded' USING ERRCODE='54000';
            END IF;
            IF NOT p_replay AND pos.typ<>'iam.accessBinding' THEN
                EXECUTE format('LOCK TABLE ONLY %s IN ROW SHARE MODE NOWAIT',rel);
            END IF;
            IF NOT EXISTS(SELECT FROM pg_class c WHERE c.oid=rel AND c.relowner=current_user::regrole
                AND c.relkind='r' AND c.relpersistence='p' AND NOT (c.relispartition OR c.relrowsecurity OR c.relforcerowsecurity OR c.relhasrules)
                AND has_table_privilege((proof->>'invoker_oid')::oid,c.oid,'SELECT')
                AND EXISTS(SELECT FROM pg_index idx JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='id' AND NOT a.attisdropped
                    WHERE idx.indrelid=c.oid AND idx.indisprimary AND idx.indisvalid AND idx.indisready AND idx.indimmediate
                        AND idx.indnkeyatts=1 AND idx.indkey[0]=a.attnum)
                AND NOT EXISTS(SELECT FROM pg_inherits i WHERE i.inhparent=c.oid OR i.inhrelid=c.oid)) THEN
                RAISE EXCEPTION 'finite position source custody differs' USING ERRCODE='42501';
            END IF;
            IF pos.typ='iam.accessBinding' THEN
                -- Перепись владельца уже удерживает и отсутствие по любому id.
                IF NOT EXISTS(SELECT FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='relation'
                    AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
                    AND l.relation=rel AND l.granted AND l.mode='ShareLock') THEN
                    RAISE EXCEPTION 'finite binding position lacks its census lock' USING ERRCODE='42501';
                END IF;
                -- Цель привязки может быть большой и не входит в этот образ.
                SELECT b.xmin,b.ctid,jsonb_build_object('id',b.id,'labels',b.labels,'access_labels',b.access_labels,
                    'resource_type',b.resource_type,'resource_id',b.resource_id) INTO row_xmin,row_tid,row_value
                    FROM ONLY kaname.access_bindings b WHERE b.id=pos.id;
            ELSE
                -- До часов удерживаем строку без ожидания. В обеих фазах читаем одни и те же поля.
                IF NOT p_replay THEN
                    EXECUTE format('SELECT true FROM ONLY %s r WHERE r.id=$1 FOR SHARE OF r NOWAIT',rel)
                        INTO found_row USING pos.id;
                ELSE found_row:=true;END IF;
                IF found_row IS TRUE THEN
                    IF pos.typ='iam.account' THEN
                        SELECT a.xmin,a.ctid,jsonb_build_object('id',a.id,'labels',a.labels,'access_labels',a.access_labels)
                            INTO row_xmin,row_tid,row_value FROM ONLY kaname.accounts a WHERE a.id=pos.id;
                    ELSE
                        SELECT p.xmin,p.ctid,jsonb_build_object('id',p.id,'labels',p.labels,'access_labels',p.access_labels,
                            'account_id',p.account_id) INTO row_xmin,row_tid,row_value FROM ONLY kaname.projects p WHERE p.id=pos.id;
                    END IF;
                    IF NOT p_replay AND row_value IS NULL THEN RAISE EXCEPTION 'finite position row changed' USING ERRCODE='40001';END IF;
                END IF;
            END IF;
            IF row_value IS NULL THEN
                state:=jsonb_build_object('state',CASE WHEN pos.typ='iam.accessBinding' THEN 'absent' ELSE 'pending_absence' END);
            ELSE
                IF row_value->>'id' IS DISTINCT FROM pos.id THEN RAISE EXCEPTION 'finite position row identity differs' USING ERRCODE='42501';END IF;
                -- Сохраняем исходные поля принадлежности. Для привязки в проекте
                -- вывод аккаунта через проект и новые защищённые метки идут отдельно.
                state:=jsonb_build_object('state','present','generation',jsonb_build_array(row_xmin::text,row_tid::text),'row',row_value);
            END IF;
        END IF;
        IF p_replay AND state IS DISTINCT FROM expected->key_value THEN
            RAISE EXCEPTION 'finite position generation differs from held source' USING ERRCODE='40001';
        END IF;
        bytes:=bytes+octet_length(key_value)+octet_length(state::text)+8;
        IF bytes>8388608 THEN RAISE EXCEPTION 'finite position image budget exceeded' USING ERRCODE='54000';END IF;
        coord_keys:=array_append(coord_keys,key_value);states:=array_append(states,state);
    END LOOP;
    SELECT coalesce(jsonb_object_agg(t.key,t.state),'{}') INTO positions FROM unnest(coord_keys,states) t(key,state);
    IF octet_length(positions::text)>8388608 THEN RAISE EXCEPTION 'finite position output exceeds byte budget' USING ERRCODE='54000';END IF;
    RETURN jsonb_build_object('positions',positions,'rows',used_rows,'reads',used_reads);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'finite selector position busy' USING ERRCODE='40001';
END;
$positions$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE grantee record;fn regprocedure:='kaname._authority_role_move_finite_positions_v1(jsonb,jsonb,boolean,integer,integer)'::regprocedure;
BEGIN
    FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_proc p
        CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        LEFT JOIN pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
            CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $positions_install$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('_authority_role_move_binding_census_v1(text,jsonb,integer,integer)','524a999cd7ed2f18bbebf057cd2cfed6252c926dfa7350488cf0287c6092ba1a','da27abe2e2c107a611dc4dda8b736da937a37278bf643b7de64a52d64750b2bf',$changes$[
 [
  "    classes text[]",
  "    binding_status jsonb;\n    classes text[]"
 ],
 [
  "                IF p_expected IS NOT NULL THEN\n                    classes:=array_append(classes,CASE\n                        WHEN physical#>>'{2,status}'='REVOKED' OR physical#>>'{2,revoked_at}' IS NOT NULL THEN 'REVOKED'\n                        WHEN (physical#>>'{2,expires_at}')::timestamptz<=at_time THEN 'EXPIRED'\n                        ELSE physical#>>'{2,status}' END);\n                END IF;\n",
  "                classes:=array_append(classes,CASE\n                    WHEN physical#>>'{2,status}'='REVOKED' OR physical#>>'{2,revoked_at}' IS NOT NULL THEN 'REVOKED'\n                    WHEN (physical#>>'{2,expires_at}')::timestamptz<=at_time THEN 'EXPIRED'\n                    ELSE physical#>>'{2,status}' END);\n"
 ],
 [
  "    IF p_expected IS NULL THEN\n        RETURN jsonb_build_object('old',census,'rows',used_rows,'reads',used_reads);\n    END IF;\n    SELECT coalesce(jsonb_object_agg(b.id,b.class),'{}'::jsonb) INTO census\n    FROM unnest(binding_ids,classes) b(id,class);\n    RETURN jsonb_build_object('binding_status',census,'rows',used_rows,'reads',used_reads);",
  "    SELECT coalesce(jsonb_object_agg(b.id,b.class),'{}'::jsonb) INTO binding_status\n    FROM unnest(binding_ids,classes) b(id,class);\n    IF p_expected IS NULL THEN\n        RETURN jsonb_build_object('old',census,'binding_status',binding_status,'rows',used_rows,'reads',used_reads);\n    END IF;\n    RETURN jsonb_build_object('binding_status',binding_status,'rows',used_rows,'reads',used_reads);"
 ]
]$changes$::jsonb),
  ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','42ae559cb6b9e325501849eab7bb5280c184cc6015a29c6dbd5eff620a132b0f','b1b8fead6e2c7d35721dd071c31e10329e3477b4503a99cf9827f2eb75ad006b',$changes$[
 [
  "    frozen jsonb;",
  "    frozen jsonb;\n    eligible jsonb;\n    predicates jsonb;\n    positions jsonb;"
 ],
 [
  "    IF octet_length(frozen::text)>8388608 THEN",
  "    used_rows:=used_rows+step_rows;\n    used_reads:=used_reads+step_reads;\n    IF selector_source IS NULL THEN\n        frozen:=frozen||jsonb_build_object('finite_positions','{}'::jsonb);\n    ELSE\n        -- Часы подготовки включают всех прямых держателей, которые смогут\n        -- дожить до финальной проверки. Финал снова определит каждого отдельно.\n        eligible:=kaname._authority_role_move_binding_new_v1(frozen,carriers->'binding_status',p_rows-used_rows);\n        used_rows:=used_rows+(eligible->>'rows')::integer;\n        predicates:=kaname._authority_role_move_predicate_plan_v1(frozen,eligible->'holders',p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(predicates->>'rows')::integer;\n        used_reads:=used_reads+(predicates->>'reads')::integer;\n        positions:=kaname._authority_role_move_finite_positions_v1(frozen,predicates->'plan',false,p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(positions->>'rows')::integer;\n        used_reads:=used_reads+(positions->>'reads')::integer;\n        frozen:=frozen||jsonb_build_object('finite_positions',positions->'positions');\n    END IF;\n    IF octet_length(frozen::text)>8388608 THEN"
 ],
 [
  "'frozen',frozen,'rows',used_rows+step_rows,'reads',used_reads+step_reads",
  "'frozen',frozen,'rows',used_rows,'reads',used_reads"
 ]
]$changes$::jsonb),
  ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','971d66d0a1329bb4dca49ea02c9b5fbae050ea5f29ccfb0cd8a15c49689c0218','2d4cc407bb142aaf8fd1fd46b2887e68990919b16a64374bff388f3d68d648c6',$changes$[
 [
  "    predicates jsonb;",
  "    predicates jsonb;\n    positions jsonb;"
 ],
 [
  "    result:=kaname._authority_role_move_copy_requirements_require_v1",
  "    positions:=kaname._authority_role_move_finite_positions_v1(p_frozen,predicates->'plan',true,p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(positions->>'rows')::integer;\n    used_reads:=used_reads+(positions->>'reads')::integer;\n    result:=kaname._authority_role_move_copy_requirements_require_v1"
 ],
 [
  "'predicate_plan',predicates->'plan','rows',",
  "'predicate_plan',predicates->'plan','finite_positions',positions->'positions','rows',"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','4b39a28dcd1c82882237043711c8da7c61d20d056bfb4e642f252a3ff34037e6','b1dd692c923b234c8ae60281ae7c3db2d1abc3b354a8d640af7db8ab51975f61',$changes$[
 [
  "524a999cd7ed2f18bbebf057cd2cfed6252c926dfa7350488cf0287c6092ba1a",
  "da27abe2e2c107a611dc4dda8b736da937a37278bf643b7de64a52d64750b2bf"
 ],
 [
  "42ae559cb6b9e325501849eab7bb5280c184cc6015a29c6dbd5eff620a132b0f",
  "b1b8fead6e2c7d35721dd071c31e10329e3477b4503a99cf9827f2eb75ad006b"
 ],
 [
  "971d66d0a1329bb4dca49ea02c9b5fbae050ea5f29ccfb0cd8a15c49689c0218",
  "2d4cc407bb142aaf8fd1fd46b2887e68990919b16a64374bff388f3d68d648c6"
 ],
 [
  " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','cb231a595f6dd57a28f293c74b87d2dae78fdfcca5ab9deb538130f1cfc7cab9',false,'v',true,'private'),",
  " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','cb231a595f6dd57a28f293c74b87d2dae78fdfcca5ab9deb538130f1cfc7cab9',false,'v',true,'private'),\n ('_authority_role_move_finite_positions_v1(jsonb,jsonb,boolean,integer,integer)','07bb9ed3f7da1fba71472842ad04621feb81e6c742ca8cbc28ee4396f50462cc',false,'v',true,'private'),\n ('_authority_metadata_root_state_v1(text,text,boolean)','3206b57ba4fe7afc579c98df293d07cbb792b0741ac7146aa1c69f1f4c2de350',false,'v',true,'private'),"
 ],
 [
  "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),",
  "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n  ('_authority_role_move_finite_positions_v1(jsonb,jsonb,boolean,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_replay','p_rows','p_reads']),\n  ('_authority_metadata_root_state_v1(text,text,boolean)','jsonb',3,ARRAY['p_dotted','p_id','p_hold']),"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','a11f765916935e1750ff37b720a31b11ffa5864a7d3a917a7f5ef4e97d56314d','777748711c8d301313a1a23d00e30f1c6efd4e691c607353c7239f830be96f5d',$changes$[
 [
  "4b39a28dcd1c82882237043711c8da7c61d20d056bfb4e642f252a3ff34037e6",
  "b1dd692c923b234c8ae60281ae7c3db2d1abc3b354a8d640af7db8ab51975f61"
 ]
]$changes$::jsonb),
  ('authority_metadata_service_account_access_label_ready_v1()','d1b495c4ab94a250bd61d214ec2a228b622acc87ee13f35575c3908aeb131d9c','dbb706e34b0e333882e1ff578ea905ca7df7f072ce88746cec2a0855799e464c',$changes$[
 [
  "4b39a28dcd1c82882237043711c8da7c61d20d056bfb4e642f252a3ff34037e6",
  "b1dd692c923b234c8ae60281ae7c3db2d1abc3b354a8d640af7db8ab51975f61"
 ],
 [
  "a11f765916935e1750ff37b720a31b11ffa5864a7d3a917a7f5ef4e97d56314d",
  "777748711c8d301313a1a23d00e30f1c6efd4e691c607353c7239f830be96f5d"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move finite positions predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move finite positions splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move finite positions body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move finite positions function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move finite positions function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move finite positions custody differs after migration' USING ERRCODE='55000';END IF;
END;
$positions_install$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $positions_install$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('authority_metadata_service_account_access_label_ready_v1()','dbb706e34b0e333882e1ff578ea905ca7df7f072ce88746cec2a0855799e464c','d1b495c4ab94a250bd61d214ec2a228b622acc87ee13f35575c3908aeb131d9c',$changes$[
 [
  "777748711c8d301313a1a23d00e30f1c6efd4e691c607353c7239f830be96f5d",
  "a11f765916935e1750ff37b720a31b11ffa5864a7d3a917a7f5ef4e97d56314d"
 ],
 [
  "b1dd692c923b234c8ae60281ae7c3db2d1abc3b354a8d640af7db8ab51975f61",
  "4b39a28dcd1c82882237043711c8da7c61d20d056bfb4e642f252a3ff34037e6"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','777748711c8d301313a1a23d00e30f1c6efd4e691c607353c7239f830be96f5d','a11f765916935e1750ff37b720a31b11ffa5864a7d3a917a7f5ef4e97d56314d',$changes$[
 [
  "b1dd692c923b234c8ae60281ae7c3db2d1abc3b354a8d640af7db8ab51975f61",
  "4b39a28dcd1c82882237043711c8da7c61d20d056bfb4e642f252a3ff34037e6"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','b1dd692c923b234c8ae60281ae7c3db2d1abc3b354a8d640af7db8ab51975f61','4b39a28dcd1c82882237043711c8da7c61d20d056bfb4e642f252a3ff34037e6',$changes$[
 [
  "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n  ('_authority_role_move_finite_positions_v1(jsonb,jsonb,boolean,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_replay','p_rows','p_reads']),\n  ('_authority_metadata_root_state_v1(text,text,boolean)','jsonb',3,ARRAY['p_dotted','p_id','p_hold']),",
  "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),"
 ],
 [
  " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','cb231a595f6dd57a28f293c74b87d2dae78fdfcca5ab9deb538130f1cfc7cab9',false,'v',true,'private'),\n ('_authority_role_move_finite_positions_v1(jsonb,jsonb,boolean,integer,integer)','07bb9ed3f7da1fba71472842ad04621feb81e6c742ca8cbc28ee4396f50462cc',false,'v',true,'private'),\n ('_authority_metadata_root_state_v1(text,text,boolean)','3206b57ba4fe7afc579c98df293d07cbb792b0741ac7146aa1c69f1f4c2de350',false,'v',true,'private'),",
  " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','cb231a595f6dd57a28f293c74b87d2dae78fdfcca5ab9deb538130f1cfc7cab9',false,'v',true,'private'),"
 ],
 [
  "2d4cc407bb142aaf8fd1fd46b2887e68990919b16a64374bff388f3d68d648c6",
  "971d66d0a1329bb4dca49ea02c9b5fbae050ea5f29ccfb0cd8a15c49689c0218"
 ],
 [
  "b1b8fead6e2c7d35721dd071c31e10329e3477b4503a99cf9827f2eb75ad006b",
  "42ae559cb6b9e325501849eab7bb5280c184cc6015a29c6dbd5eff620a132b0f"
 ],
 [
  "da27abe2e2c107a611dc4dda8b736da937a37278bf643b7de64a52d64750b2bf",
  "524a999cd7ed2f18bbebf057cd2cfed6252c926dfa7350488cf0287c6092ba1a"
 ]
]$changes$::jsonb),
  ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','2d4cc407bb142aaf8fd1fd46b2887e68990919b16a64374bff388f3d68d648c6','971d66d0a1329bb4dca49ea02c9b5fbae050ea5f29ccfb0cd8a15c49689c0218',$changes$[
 [
  "'predicate_plan',predicates->'plan','finite_positions',positions->'positions','rows',",
  "'predicate_plan',predicates->'plan','rows',"
 ],
 [
  "    positions:=kaname._authority_role_move_finite_positions_v1(p_frozen,predicates->'plan',true,p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(positions->>'rows')::integer;\n    used_reads:=used_reads+(positions->>'reads')::integer;\n    result:=kaname._authority_role_move_copy_requirements_require_v1",
  "    result:=kaname._authority_role_move_copy_requirements_require_v1"
 ],
 [
  "    predicates jsonb;\n    positions jsonb;",
  "    predicates jsonb;"
 ]
]$changes$::jsonb),
  ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','b1b8fead6e2c7d35721dd071c31e10329e3477b4503a99cf9827f2eb75ad006b','42ae559cb6b9e325501849eab7bb5280c184cc6015a29c6dbd5eff620a132b0f',$changes$[
 [
  "'frozen',frozen,'rows',used_rows,'reads',used_reads",
  "'frozen',frozen,'rows',used_rows+step_rows,'reads',used_reads+step_reads"
 ],
 [
  "    used_rows:=used_rows+step_rows;\n    used_reads:=used_reads+step_reads;\n    IF selector_source IS NULL THEN\n        frozen:=frozen||jsonb_build_object('finite_positions','{}'::jsonb);\n    ELSE\n        -- Часы подготовки включают всех прямых держателей, которые смогут\n        -- дожить до финальной проверки. Финал снова определит каждого отдельно.\n        eligible:=kaname._authority_role_move_binding_new_v1(frozen,carriers->'binding_status',p_rows-used_rows);\n        used_rows:=used_rows+(eligible->>'rows')::integer;\n        predicates:=kaname._authority_role_move_predicate_plan_v1(frozen,eligible->'holders',p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(predicates->>'rows')::integer;\n        used_reads:=used_reads+(predicates->>'reads')::integer;\n        positions:=kaname._authority_role_move_finite_positions_v1(frozen,predicates->'plan',false,p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(positions->>'rows')::integer;\n        used_reads:=used_reads+(positions->>'reads')::integer;\n        frozen:=frozen||jsonb_build_object('finite_positions',positions->'positions');\n    END IF;\n    IF octet_length(frozen::text)>8388608 THEN",
  "    IF octet_length(frozen::text)>8388608 THEN"
 ],
 [
  "    frozen jsonb;\n    eligible jsonb;\n    predicates jsonb;\n    positions jsonb;",
  "    frozen jsonb;"
 ]
]$changes$::jsonb),
  ('_authority_role_move_binding_census_v1(text,jsonb,integer,integer)','da27abe2e2c107a611dc4dda8b736da937a37278bf643b7de64a52d64750b2bf','524a999cd7ed2f18bbebf057cd2cfed6252c926dfa7350488cf0287c6092ba1a',$changes$[
 [
  "    SELECT coalesce(jsonb_object_agg(b.id,b.class),'{}'::jsonb) INTO binding_status\n    FROM unnest(binding_ids,classes) b(id,class);\n    IF p_expected IS NULL THEN\n        RETURN jsonb_build_object('old',census,'binding_status',binding_status,'rows',used_rows,'reads',used_reads);\n    END IF;\n    RETURN jsonb_build_object('binding_status',binding_status,'rows',used_rows,'reads',used_reads);",
  "    IF p_expected IS NULL THEN\n        RETURN jsonb_build_object('old',census,'rows',used_rows,'reads',used_reads);\n    END IF;\n    SELECT coalesce(jsonb_object_agg(b.id,b.class),'{}'::jsonb) INTO census\n    FROM unnest(binding_ids,classes) b(id,class);\n    RETURN jsonb_build_object('binding_status',census,'rows',used_rows,'reads',used_reads);"
 ],
 [
  "                classes:=array_append(classes,CASE\n                    WHEN physical#>>'{2,status}'='REVOKED' OR physical#>>'{2,revoked_at}' IS NOT NULL THEN 'REVOKED'\n                    WHEN (physical#>>'{2,expires_at}')::timestamptz<=at_time THEN 'EXPIRED'\n                    ELSE physical#>>'{2,status}' END);\n",
  "                IF p_expected IS NOT NULL THEN\n                    classes:=array_append(classes,CASE\n                        WHEN physical#>>'{2,status}'='REVOKED' OR physical#>>'{2,revoked_at}' IS NOT NULL THEN 'REVOKED'\n                        WHEN (physical#>>'{2,expires_at}')::timestamptz<=at_time THEN 'EXPIRED'\n                        ELSE physical#>>'{2,status}' END);\n                END IF;\n"
 ],
 [
  "    binding_status jsonb;\n    classes text[]",
  "    classes text[]"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move finite positions predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move finite positions splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move finite positions body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move finite positions function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move finite positions function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move finite positions custody differs after migration' USING ERRCODE='55000';END IF;
END;
$positions_install$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_role_move_finite_positions_v1(jsonb,jsonb,boolean,integer,integer);
