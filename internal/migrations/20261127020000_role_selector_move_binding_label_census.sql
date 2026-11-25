-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Широкие предикаты меток объекта iam.accessBinding читают всю защищённую
-- перепись. Попадание в кандидаты ещё не определяет область, выдачу или аудит.
-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_binding_label_candidates_v1(
    p_frozen jsonb,p_plan jsonb,p_replay boolean,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $labels$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    expected jsonb:=p_frozen->'binding_label_source';source jsonb;
    digest text;cap integer;used_rows integer;used_reads integer:=0;branches integer;copy_count integer;has_binding_copy boolean;
    bytes bigint:=2;output_bytes bigint:=2;r record;entry record;s jsonb;predicate jsonb;
    image jsonb;images jsonb[]:=ARRAY[]::jsonb[];hits jsonb;result jsonb;items jsonb[]:=ARRAY[]::jsonb[];
BEGIN
    IF p_replay IS NULL OR p_frozen->'nonce' IS DISTINCT FROM proof->'nonce'
        OR p_frozen->'invoker_oid' IS DISTINCT FROM proof->'invoker_oid'
        OR p_frozen#>>'{copies,backend_pid}' IS DISTINCT FROM pg_backend_pid()::text
        OR p_frozen#>>'{copies,txid}' IS DISTINCT FROM pg_current_xact_id()::text
        OR coalesce(p_frozen->>'role_id','')='' OR p_frozen#>>'{role,physical,2,id}' IS DISTINCT FROM p_frozen->>'role_id'
        OR p_frozen#>>'{role,new_role,id}' IS DISTINCT FROM p_frozen->>'role_id'
        OR p_plan->'catalog_id' IS DISTINCT FROM proof->'catalog_id' OR jsonb_typeof(p_plan->'items') IS DISTINCT FROM 'array'
        OR (p_replay AND jsonb_typeof(expected) IS DISTINCT FROM 'object') THEN
        RAISE EXCEPTION 'binding label census requires held role plan' USING ERRCODE='42501';
    END IF;
    used_rows:=jsonb_array_length(p_plan->'items');
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 0 AND 4096
        OR octet_length(p_frozen::text)>8388608 OR octet_length(p_plan::text)>8388608 THEN
        RAISE EXCEPTION 'binding label plan budget exceeded' USING ERRCODE='54000';
    END IF;
    SELECT count(*) INTO branches FROM jsonb_array_elements(p_plan->'items') i
        WHERE i->>'read_type'='iam.accessBinding' AND i->>'guard'='whole_type' AND i#>>'{predicate,Arm}' IN ('2','3');
    IF branches=0 THEN
        RETURN jsonb_build_object('source',jsonb_build_object('state','unused'),'items','[]'::jsonb,
            'other_predicates','pending','rows',used_rows,'reads',0);
    END IF;
    -- Текущий писатель допускает копии в трёх IAM-таблицах и во внешнем
    -- зеркале. При расширении списка NEW потребует наложения выбранных копий.
    SELECT count(*),coalesce(bool_or(starts_with(k,'iam.accessBinding:')),false) INTO copy_count,has_binding_copy
        FROM jsonb_object_keys(p_frozen#>'{copies,roots}') k;
    used_rows:=used_rows+copy_count+CASE WHEN p_replay THEN jsonb_array_length(p_plan->'items') ELSE 0 END;
    IF used_rows>p_rows THEN RAISE EXCEPTION 'binding label copy and selector budget exceeded' USING ERRCODE='54000';END IF;
    IF has_binding_copy THEN
        RAISE EXCEPTION 'binding label census requires copy overlay' USING ERRCODE='42501';
    END IF;
    IF p_replay AND coalesce(expected->>'state','') NOT IN ('held','pending_budget') THEN
        RAISE EXCEPTION 'binding label census missing before decision' USING ERRCODE='40001';
    END IF;
    -- LIMIT стоит до сортировки и сопоставления. Лишняя строка оставляет
    -- весь предикат открытым, а частичный набор никогда не становится пустым.
    cap:=least(4096,p_rows-used_rows-3);
    IF p_replay AND expected->>'state'='held' THEN
        IF jsonb_typeof(expected->'count') IS DISTINCT FROM 'number' OR expected->>'count' !~ '^(0|[1-9][0-9]{0,3})$'
            OR (expected->>'count')::integer>4096 THEN RAISE EXCEPTION 'binding label census count invalid' USING ERRCODE='42501';END IF;
        cap:=least(cap,(expected->>'count')::integer);
    END IF;
    source:=jsonb_build_object('state','pending_budget');
    IF NOT (p_replay AND expected->>'state'='pending_budget') AND cap>=0 AND p_reads>=2 THEN
        used_reads:=2;used_rows:=used_rows+2;
        -- Эту блокировку берёт перепись привязок перед чтением обеих сторон.
        IF NOT EXISTS(SELECT FROM pg_locks l JOIN pg_class c ON c.oid=l.relation
            WHERE l.pid=pg_backend_pid() AND l.locktype='relation' AND l.granted AND l.mode='ShareLock'
            AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
            AND c.oid='kaname.access_bindings'::regclass AND c.relowner=current_user::regrole AND c.relkind='r' AND c.relpersistence='p'
            AND NOT (c.relispartition OR c.relrowsecurity OR c.relforcerowsecurity OR c.relhasrules)
            AND EXISTS(SELECT FROM pg_index idx JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='id' AND NOT a.attisdropped
                WHERE idx.indrelid=c.oid AND idx.indisprimary AND idx.indisvalid AND idx.indisready AND idx.indimmediate
                    AND idx.indnkeyatts=1 AND idx.indkey[0]=a.attnum)
            AND NOT EXISTS(SELECT FROM pg_inherits i WHERE i.inhparent=c.oid OR i.inhrelid=c.oid)
            AND has_table_privilege((proof->>'invoker_oid')::oid,c.oid,'SELECT')) THEN
            RAISE EXCEPTION 'binding label census lacks physical source guard' USING ERRCODE='42501';
        END IF;
        source:=jsonb_build_object('state','held');
        FOR r IN SELECT b.ctid AS tid,b.xmin AS generation,b.id,b.labels,b.access_labels
            FROM ONLY kaname.access_bindings b LIMIT cap+1 LOOP
            used_rows:=used_rows+1;
            IF cardinality(images)>=cap THEN
                IF p_replay AND cap=(expected->>'count')::integer THEN
                    RAISE EXCEPTION 'binding label census grew after preparation' USING ERRCODE='40001';
                END IF;
                source:=jsonb_build_object('state','pending_budget');EXIT;
            END IF;
            IF octet_length(r.id)>16384 THEN source:=jsonb_build_object('state','pending_budget');EXIT;END IF;
            image:=jsonb_build_array(r.generation::text,r.tid::text,r.id,r.labels,r.access_labels);
            bytes:=bytes+octet_length(image::text)+2;
            IF bytes>8388608 THEN source:=jsonb_build_object('state','pending_budget');EXIT;END IF;
            images:=array_append(images,image);
        END LOOP;
        IF source->>'state'='held' THEN
            SELECT encode(sha256(convert_to(coalesce(jsonb_agg(v ORDER BY (v->>1)::tid),'[]')::text,'UTF8')),'hex')
                INTO digest FROM unnest(images) v;
            source:=source||jsonb_build_object('count',cardinality(images),'sha256',digest);
        END IF;
    END IF;
    IF p_replay AND source->>'state'='held' AND source IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'binding label census differs from preparation' USING ERRCODE='40001';
    END IF;
    IF p_replay THEN
        FOR entry IN SELECT i,ordinal FROM jsonb_array_elements(p_plan->'items') WITH ORDINALITY x(i,ordinal)
                WHERE i->>'read_type'='iam.accessBinding' AND i->>'guard'='whole_type' AND i#>>'{predicate,Arm}' IN ('2','3') LOOP
            s:=entry.i;
            result:=jsonb_build_object('plan_item',entry.ordinal,'binding_id',s->'binding_id','side',s->'side','rule_fp',s->'rule_fp');
            IF source->>'state'='held' AND cardinality(images)<=p_rows-used_rows THEN
                used_rows:=used_rows+cardinality(images);
                predicate:=jsonb_build_object('object_types',jsonb_build_array('iam.accessBinding'))||
                    CASE s#>>'{predicate,Arm}' WHEN '2' THEN jsonb_build_object('arm','labels','match_labels',s#>'{predicate,MatchLabels}')
                        ELSE jsonb_build_object('arm','access_labels','match_access_labels',s#>'{predicate,MatchAccessLabels}') END;
                SELECT coalesce(jsonb_agg(v->2 ORDER BY (v->>2) COLLATE "C"),'[]') INTO hits FROM unnest(images) v
                    WHERE kaname._authority_resource_selector_matches_v3(predicate,'iam.accessBinding',v->>2,v->3,v->4);
                IF EXISTS(SELECT FROM jsonb_array_elements_text(hits) id WHERE id='' OR id ~ '[:#*[:space:][:cntrl:]]') THEN
                    RAISE EXCEPTION 'binding label candidate id invalid' USING ERRCODE='42501';
                END IF;
                result:=result||jsonb_build_object('state','complete','candidate_ids',hits);
                IF s ? 'child_predicate' THEN
                    result:=result||jsonb_build_object('children',CASE WHEN hits='[]'::jsonb THEN 'empty' ELSE 'pending' END);
                END IF;
            ELSE result:=result||jsonb_build_object('state','pending_budget');END IF;
            output_bytes:=output_bytes+octet_length(result::text)+2;
            IF output_bytes>8388608 THEN RAISE EXCEPTION 'binding label result byte budget exceeded' USING ERRCODE='54000';END IF;
            items:=array_append(items,result);
        END LOOP;
    END IF;
    RETURN jsonb_build_object('source',source,'items',to_jsonb(items),'other_predicates','pending','rows',used_rows,'reads',used_reads);
END;
$labels$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE grantee record;fn regprocedure:='kaname._authority_role_move_binding_label_candidates_v1(jsonb,jsonb,boolean,integer,integer)'::regprocedure;
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
DO $labels_install$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','b1b8fead6e2c7d35721dd071c31e10329e3477b4503a99cf9827f2eb75ad006b','e5dd08ae64e954d276d540831ab33f540b0427ddf2ea7e2d2f6c82d1c30cd7e9',$changes$[
 [
  "    positions jsonb;",
  "    positions jsonb;\n    binding_labels jsonb;"
 ],
 [
  "jsonb_build_object('finite_positions','{}'::jsonb)",
  "jsonb_build_object('finite_positions','{}'::jsonb,'binding_label_source',jsonb_build_object('state','unused'))"
 ],
 [
  "        frozen:=frozen||jsonb_build_object('finite_positions',positions->'positions');",
  "        binding_labels:=kaname._authority_role_move_binding_label_candidates_v1(frozen,predicates->'plan',false,p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(binding_labels->>'rows')::integer;\n        used_reads:=used_reads+(binding_labels->>'reads')::integer;\n        frozen:=frozen||jsonb_build_object('finite_positions',positions->'positions','binding_label_source',binding_labels->'source');"
 ]
]$changes$::jsonb),
  ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','2d4cc407bb142aaf8fd1fd46b2887e68990919b16a64374bff388f3d68d648c6','4040ee5e25fc3986a261ea16cedcfc2657efb356b9a1729db9df10c1070d8762',$changes$[
 [
  "    positions jsonb;",
  "    positions jsonb;\n    binding_labels jsonb;"
 ],
 [
  "    RETURN jsonb_build_object('role_id',root_id,'actor',actor,'decision_at',at_time,",
  "    used_rows:=used_rows+step_rows;\n    used_reads:=used_reads+step_reads;\n    binding_labels:=kaname._authority_role_move_binding_label_candidates_v1(p_frozen,predicates->'plan',true,p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(binding_labels->>'rows')::integer;\n    used_reads:=used_reads+(binding_labels->>'reads')::integer;\n    RETURN jsonb_build_object('role_id',root_id,'actor',actor,'decision_at',at_time,\n        'binding_label_candidates',binding_labels-ARRAY['rows','reads'],"
 ],
 [
  "'rows',used_rows+step_rows,'reads',used_reads+step_reads",
  "'rows',used_rows,'reads',used_reads"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','b1dd692c923b234c8ae60281ae7c3db2d1abc3b354a8d640af7db8ab51975f61','c9ca3e5c3dd9ab241d3212dd1fd92fc9a71e1fd924081d26685d6d8d4934f9a8',$changes$[
 [
  "b1b8fead6e2c7d35721dd071c31e10329e3477b4503a99cf9827f2eb75ad006b",
  "e5dd08ae64e954d276d540831ab33f540b0427ddf2ea7e2d2f6c82d1c30cd7e9"
 ],
 [
  "2d4cc407bb142aaf8fd1fd46b2887e68990919b16a64374bff388f3d68d648c6",
  "4040ee5e25fc3986a261ea16cedcfc2657efb356b9a1729db9df10c1070d8762"
 ],
 [
  " ('_authority_role_move_finite_positions_v1(jsonb,jsonb,boolean,integer,integer)','07bb9ed3f7da1fba71472842ad04621feb81e6c742ca8cbc28ee4396f50462cc',false,'v',true,'private'),",
  " ('_authority_role_move_finite_positions_v1(jsonb,jsonb,boolean,integer,integer)','07bb9ed3f7da1fba71472842ad04621feb81e6c742ca8cbc28ee4396f50462cc',false,'v',true,'private'),\n ('_authority_role_move_binding_label_candidates_v1(jsonb,jsonb,boolean,integer,integer)','1e54b2d219066b958e4973f98f93e50dc03e6fb520c23e45428a2c55a302f057',false,'v',true,'private'),"
 ],
 [
  "  ('_authority_role_move_finite_positions_v1(jsonb,jsonb,boolean,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_replay','p_rows','p_reads']),",
  "  ('_authority_role_move_finite_positions_v1(jsonb,jsonb,boolean,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_replay','p_rows','p_reads']),\n  ('_authority_role_move_binding_label_candidates_v1(jsonb,jsonb,boolean,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_replay','p_rows','p_reads']),"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','777748711c8d301313a1a23d00e30f1c6efd4e691c607353c7239f830be96f5d','e984071291b9298c9b64feb16d18595bc29f543dc47db64e0606eab07cf27394',$changes$[
 [
  "b1dd692c923b234c8ae60281ae7c3db2d1abc3b354a8d640af7db8ab51975f61",
  "c9ca3e5c3dd9ab241d3212dd1fd92fc9a71e1fd924081d26685d6d8d4934f9a8"
 ]
]$changes$::jsonb),
  ('authority_metadata_service_account_access_label_ready_v1()','dbb706e34b0e333882e1ff578ea905ca7df7f072ce88746cec2a0855799e464c','b05aa0f76adb3f06c3fa14f319853f66c2768c3abd2d0608baab07b0bf9b5473',$changes$[
 [
  "b1dd692c923b234c8ae60281ae7c3db2d1abc3b354a8d640af7db8ab51975f61",
  "c9ca3e5c3dd9ab241d3212dd1fd92fc9a71e1fd924081d26685d6d8d4934f9a8"
 ],
 [
  "777748711c8d301313a1a23d00e30f1c6efd4e691c607353c7239f830be96f5d",
  "e984071291b9298c9b64feb16d18595bc29f543dc47db64e0606eab07cf27394"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move binding label census predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move binding label census splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move binding label census body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move binding label census function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move binding label census function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move binding label census custody differs after migration' USING ERRCODE='55000';END IF;
END;
$labels_install$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $labels_install$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('authority_metadata_service_account_access_label_ready_v1()','b05aa0f76adb3f06c3fa14f319853f66c2768c3abd2d0608baab07b0bf9b5473','dbb706e34b0e333882e1ff578ea905ca7df7f072ce88746cec2a0855799e464c',$changes$[
 [
  "e984071291b9298c9b64feb16d18595bc29f543dc47db64e0606eab07cf27394",
  "777748711c8d301313a1a23d00e30f1c6efd4e691c607353c7239f830be96f5d"
 ],
 [
  "c9ca3e5c3dd9ab241d3212dd1fd92fc9a71e1fd924081d26685d6d8d4934f9a8",
  "b1dd692c923b234c8ae60281ae7c3db2d1abc3b354a8d640af7db8ab51975f61"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','e984071291b9298c9b64feb16d18595bc29f543dc47db64e0606eab07cf27394','777748711c8d301313a1a23d00e30f1c6efd4e691c607353c7239f830be96f5d',$changes$[
 [
  "c9ca3e5c3dd9ab241d3212dd1fd92fc9a71e1fd924081d26685d6d8d4934f9a8",
  "b1dd692c923b234c8ae60281ae7c3db2d1abc3b354a8d640af7db8ab51975f61"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','c9ca3e5c3dd9ab241d3212dd1fd92fc9a71e1fd924081d26685d6d8d4934f9a8','b1dd692c923b234c8ae60281ae7c3db2d1abc3b354a8d640af7db8ab51975f61',$changes$[
 [
  "  ('_authority_role_move_finite_positions_v1(jsonb,jsonb,boolean,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_replay','p_rows','p_reads']),\n  ('_authority_role_move_binding_label_candidates_v1(jsonb,jsonb,boolean,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_replay','p_rows','p_reads']),",
  "  ('_authority_role_move_finite_positions_v1(jsonb,jsonb,boolean,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_replay','p_rows','p_reads']),"
 ],
 [
  " ('_authority_role_move_finite_positions_v1(jsonb,jsonb,boolean,integer,integer)','07bb9ed3f7da1fba71472842ad04621feb81e6c742ca8cbc28ee4396f50462cc',false,'v',true,'private'),\n ('_authority_role_move_binding_label_candidates_v1(jsonb,jsonb,boolean,integer,integer)','1e54b2d219066b958e4973f98f93e50dc03e6fb520c23e45428a2c55a302f057',false,'v',true,'private'),",
  " ('_authority_role_move_finite_positions_v1(jsonb,jsonb,boolean,integer,integer)','07bb9ed3f7da1fba71472842ad04621feb81e6c742ca8cbc28ee4396f50462cc',false,'v',true,'private'),"
 ],
 [
  "4040ee5e25fc3986a261ea16cedcfc2657efb356b9a1729db9df10c1070d8762",
  "2d4cc407bb142aaf8fd1fd46b2887e68990919b16a64374bff388f3d68d648c6"
 ],
 [
  "e5dd08ae64e954d276d540831ab33f540b0427ddf2ea7e2d2f6c82d1c30cd7e9",
  "b1b8fead6e2c7d35721dd071c31e10329e3477b4503a99cf9827f2eb75ad006b"
 ]
]$changes$::jsonb),
  ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','4040ee5e25fc3986a261ea16cedcfc2657efb356b9a1729db9df10c1070d8762','2d4cc407bb142aaf8fd1fd46b2887e68990919b16a64374bff388f3d68d648c6',$changes$[
 [
  "'rows',used_rows,'reads',used_reads",
  "'rows',used_rows+step_rows,'reads',used_reads+step_reads"
 ],
 [
  "    used_rows:=used_rows+step_rows;\n    used_reads:=used_reads+step_reads;\n    binding_labels:=kaname._authority_role_move_binding_label_candidates_v1(p_frozen,predicates->'plan',true,p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(binding_labels->>'rows')::integer;\n    used_reads:=used_reads+(binding_labels->>'reads')::integer;\n    RETURN jsonb_build_object('role_id',root_id,'actor',actor,'decision_at',at_time,\n        'binding_label_candidates',binding_labels-ARRAY['rows','reads'],",
  "    RETURN jsonb_build_object('role_id',root_id,'actor',actor,'decision_at',at_time,"
 ],
 [
  "    positions jsonb;\n    binding_labels jsonb;",
  "    positions jsonb;"
 ]
]$changes$::jsonb),
  ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','e5dd08ae64e954d276d540831ab33f540b0427ddf2ea7e2d2f6c82d1c30cd7e9','b1b8fead6e2c7d35721dd071c31e10329e3477b4503a99cf9827f2eb75ad006b',$changes$[
 [
  "        binding_labels:=kaname._authority_role_move_binding_label_candidates_v1(frozen,predicates->'plan',false,p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(binding_labels->>'rows')::integer;\n        used_reads:=used_reads+(binding_labels->>'reads')::integer;\n        frozen:=frozen||jsonb_build_object('finite_positions',positions->'positions','binding_label_source',binding_labels->'source');",
  "        frozen:=frozen||jsonb_build_object('finite_positions',positions->'positions');"
 ],
 [
  "jsonb_build_object('finite_positions','{}'::jsonb,'binding_label_source',jsonb_build_object('state','unused'))",
  "jsonb_build_object('finite_positions','{}'::jsonb)"
 ],
 [
  "    positions jsonb;\n    binding_labels jsonb;",
  "    positions jsonb;"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move binding label census predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move binding label census splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move binding label census body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move binding label census function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move binding label census function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move binding label census custody differs after migration' USING ERRCODE='55000';END IF;
END;
$labels_install$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_role_move_binding_label_candidates_v1(jsonb,jsonb,boolean,integer,integer);
