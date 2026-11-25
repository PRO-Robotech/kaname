-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Старые строки привязок роли нужны и при отсутствии выбранных копий.
-- Полная перепись не заменяет доказательство нового участника или кортежа.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- Обратная связь участника нужна и для проверки отсутствия строк.
CREATE INDEX access_binding_target_members_role_binding_idx
    ON kaname.access_binding_target_members(role_id,binding_id);

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_binding_census_v1(
    p_role_id text,p_expected jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $census$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    invoker oid:=(proof->>'invoker_oid')::oid;
    at_time timestamptz:=(proof->>'decision_at')::timestamptz;
    source record;
    physical jsonb;
    images jsonb[];
    binding_ids text[]:=ARRAY[]::text[];
    member_binding_ids text[]:=ARRAY[]::text[];
    expected_member_binding_ids text[];
    member_binding_id text;
    classes text[]:=ARRAY[]::text[];
    census jsonb:='{}';
    expected jsonb;
    seen integer;
    cap integer;
    -- Перепроверка оплачивает также два точечных предиката при одобрении и COMMIT.
    used_rows integer:=CASE WHEN p_expected IS NULL THEN 6 ELSE 10 END;
    used_reads integer:=CASE WHEN p_expected IS NULL THEN 8 ELSE 12 END;
    bytes integer:=128;
BEGIN
    IF coalesce(p_role_id,'')='' OR octet_length(p_role_id)>16384 OR p_role_id ~ '[:#*[:space:][:cntrl:]]'
        OR at_time IS NULL OR NOT isfinite(at_time) THEN
        RAISE EXCEPTION 'invalid selector move binding census identity' USING ERRCODE='42501';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
        RAISE EXCEPTION 'selector move binding census budget exhausted' USING ERRCODE='54000';
    END IF;
    IF octet_length(p_expected::text)>8388608 THEN
        RAISE EXCEPTION 'selector move binding receipt exceeds byte budget' USING ERRCODE='54000';
    END IF;
    IF p_expected IS NOT NULL AND (jsonb_typeof(p_expected) IS DISTINCT FROM 'object'
        OR NOT (p_expected ?& ARRAY['bindings','subjects','members','ledger'])
        OR p_expected-ARRAY['bindings','subjects','members','ledger']<>'{}'::jsonb
        OR jsonb_typeof(p_expected->'members') IS DISTINCT FROM 'array') THEN
        RAISE EXCEPTION 'selector move binding census receipt incomplete' USING ERRCODE='42501';
    END IF;

    -- Глобальная строка совпадает с authority_role_stage_epoch_lock(NULL,...).
    -- SHARE удерживает также отсутствие строк и не даёт добавить наследника.
    -- Все четыре предиката защищены до первого чтения, включая повторный вызов.
    PERFORM FROM ONLY kaname.authority_binding_epoch e WHERE e.scope='' FOR UPDATE OF e NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'selector move global binding epoch missing' USING ERRCODE='40001';END IF;
    LOCK TABLE ONLY kaname.access_binding_emitted_tuples, ONLY kaname.access_binding_subjects,
        ONLY kaname.access_binding_target_members, ONLY kaname.access_bindings IN SHARE MODE NOWAIT;
    IF EXISTS(SELECT FROM unnest(ARRAY['kaname.access_bindings'::regclass,'kaname.access_binding_subjects'::regclass,
            'kaname.access_binding_target_members'::regclass,'kaname.access_binding_emitted_tuples'::regclass]) t(relid)
        JOIN pg_class c ON c.oid=t.relid WHERE c.relowner<>current_user::regrole OR c.relkind<>'r' OR c.relpersistence<>'p'
            OR c.relispartition OR c.relrowsecurity OR c.relforcerowsecurity OR c.relhasrules
            OR NOT has_table_privilege(invoker,c.oid,'SELECT')
            OR EXISTS(SELECT FROM pg_inherits i WHERE i.inhparent=c.oid OR i.inhrelid=c.oid)) THEN
        RAISE EXCEPTION 'selector move binding census source custody differs' USING ERRCODE='42501';
    END IF;

    -- Роль участника и роль привязки независимы. Выбираем также родителя
    -- участника со старой несовпадающей ролью, включая всех его субъектов,
    -- участников и журнал. Подсчёт в обратную сторону ограничен до накопления.
    cap:=p_rows-used_rows;
    IF p_expected IS NOT NULL THEN
        SELECT coalesce(array_agg(m.value#>>'{2,binding_id}' ORDER BY m.ord),ARRAY[]::text[]) INTO expected_member_binding_ids
            FROM jsonb_array_elements(p_expected->'members') WITH ORDINALITY m(value,ord)
            WHERE m.value#>>'{2,role_id}'=p_role_id;
        IF cardinality(expected_member_binding_ids)>cap THEN
            RAISE EXCEPTION 'selector move member link replay budget exhausted' USING ERRCODE='54000';
        END IF;
        cap:=cardinality(expected_member_binding_ids);
    END IF;
    seen:=0;
    FOR member_binding_id IN SELECT s.binding_id FROM (
        SELECT m.binding_id,m.ctid FROM ONLY kaname.access_binding_target_members m
        WHERE m.role_id=p_role_id LIMIT cap+1) s ORDER BY s.ctid LOOP
        IF p_expected IS NOT NULL AND (seen>=cap OR member_binding_id IS DISTINCT FROM expected_member_binding_ids[seen+1]) THEN
            RAISE EXCEPTION 'selector move member link changed after preparation' USING ERRCODE='40001';
        END IF;
        IF seen>=cap THEN RAISE EXCEPTION 'selector move member link row budget exhausted' USING ERRCODE='54000';END IF;
        bytes:=bytes+octet_length(member_binding_id)+2;
        IF bytes>8388608 THEN RAISE EXCEPTION 'selector move member links exceed byte budget' USING ERRCODE='54000';END IF;
        member_binding_ids:=array_append(member_binding_ids,member_binding_id);
        seen:=seen+1;
    END LOOP;
    IF p_expected IS NOT NULL AND seen<>cap THEN
        RAISE EXCEPTION 'selector move member link missing after preparation' USING ERRCODE='40001';
    END IF;
    used_rows:=used_rows+seen;

    -- В журнале учитываются binding-wide записи, записи без живого участника
    -- и выходы на другом объекте. Состояние и TTL не сужают ни один предикат.
    FOR source IN SELECT * FROM (VALUES
        (1,'bindings','access_bindings','r.role_id=$1 OR r.id=ANY($2)'),
        (2,'subjects','access_binding_subjects','r.binding_id=ANY($2)'),
        (3,'members','access_binding_target_members','r.binding_id=ANY($2)'),
        (4,'ledger','access_binding_emitted_tuples','r.binding_id=ANY($2)')
    ) t(position,kind,relation_name,predicate) ORDER BY position LOOP
        expected:=p_expected->source.kind;
        cap:=p_rows-used_rows;
        IF p_expected IS NOT NULL THEN
            IF jsonb_typeof(expected) IS DISTINCT FROM 'array' THEN
                RAISE EXCEPTION 'selector move binding census family missing' USING ERRCODE='42501';
            END IF;
            IF jsonb_array_length(expected)>cap THEN
                RAISE EXCEPTION 'selector move binding replay budget exhausted' USING ERRCODE='54000';
            END IF;
            cap:=jsonb_array_length(expected);
        END IF;
        seen:=0;
        images:=ARRAY[]::jsonb[];
        FOR physical IN EXECUTE format(
            'SELECT jsonb_build_array(s.row_xmin,s.row_tid::text,to_jsonb(s.row_value)) FROM (
                SELECT r.xmin::text AS row_xmin,r.ctid AS row_tid,r AS row_value
                FROM ONLY kaname.%I r WHERE %s LIMIT $3) s ORDER BY s.row_tid',
            source.relation_name,source.predicate) USING p_role_id,
            CASE WHEN source.kind='bindings' THEN member_binding_ids ELSE binding_ids END,cap+1 LOOP
            IF p_expected IS NOT NULL AND (seen>=cap OR physical IS DISTINCT FROM expected->seen) THEN
                RAISE EXCEPTION 'selector move % OLD changed after preparation',source.kind USING ERRCODE='40001';
            END IF;
            IF seen>=cap THEN RAISE EXCEPTION 'selector move binding row budget exhausted' USING ERRCODE='54000';END IF;
            seen:=seen+1;
            bytes:=bytes+octet_length(physical::text)+2;
            IF bytes>8388608 THEN RAISE EXCEPTION 'selector move binding census byte budget exhausted' USING ERRCODE='54000';END IF;
            IF p_expected IS NULL THEN images:=array_append(images,physical);END IF;
            IF source.kind='bindings' THEN
                binding_ids:=array_append(binding_ids,physical#>>'{2,id}');
                IF p_expected IS NOT NULL THEN
                    classes:=array_append(classes,CASE
                        WHEN physical#>>'{2,status}'='REVOKED' OR physical#>>'{2,revoked_at}' IS NOT NULL THEN 'REVOKED'
                        WHEN (physical#>>'{2,expires_at}')::timestamptz<=at_time THEN 'EXPIRED'
                        ELSE physical#>>'{2,status}' END);
                END IF;
            END IF;
        END LOOP;
        IF p_expected IS NOT NULL AND seen<>cap THEN
            RAISE EXCEPTION 'selector move % OLD row missing after preparation',source.kind USING ERRCODE='40001';
        END IF;
        IF source.kind='bindings' AND EXISTS(
            SELECT unnest(member_binding_ids) EXCEPT SELECT unnest(binding_ids)) THEN
            RAISE EXCEPTION 'selector move member parent binding absent' USING ERRCODE='42501';
        END IF;
        used_rows:=used_rows+seen;
        IF p_expected IS NULL THEN census:=census||jsonb_build_object(source.kind,to_jsonb(images));END IF;
    END LOOP;
    IF p_expected IS NULL THEN
        RETURN jsonb_build_object('old',census,'rows',used_rows,'reads',used_reads);
    END IF;
    SELECT coalesce(jsonb_object_agg(b.id,b.class),'{}'::jsonb) INTO census
    FROM unnest(binding_ids,classes) b(id,class);
    RETURN jsonb_build_object('binding_status',census,'rows',used_rows,'reads',used_reads);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'selector move binding census source busy' USING ERRCODE='40001';
END;
$census$;
-- +goose StatementEnd

-- Пока полная NEW-проекция и сохранение общих кортежей не сертифицированы,
-- только пустой OLD допускает публикацию. Та же транзакция могла изменить
-- строки после финальной проверки. Повторяем её два определяющих предиката.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_binding_empty_require_v1(p_frozen jsonb)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $gate$
DECLARE
    v_role_id text:=p_frozen#>>'{selector_move,role_id}';
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF coalesce(v_role_id,'')='' OR v_role_id IS DISTINCT FROM p_frozen#>>'{selector_move_decision,role_id}'
        OR p_frozen#>'{selector_move,binding_census}' IS DISTINCT FROM '{"bindings":[],"subjects":[],"members":[],"ledger":[]}'::jsonb
        OR p_frozen#>'{selector_move_decision,binding_status}' IS DISTINCT FROM '{}'::jsonb THEN
        RAISE EXCEPTION 'selector move requires NEW authority for captured binding outputs' USING ERRCODE='42501';
    END IF;
    IF EXISTS(SELECT FROM ONLY kaname.access_bindings b WHERE b.role_id=v_role_id)
        OR EXISTS(SELECT FROM ONLY kaname.access_binding_target_members m WHERE m.role_id=v_role_id) THEN
        RAISE EXCEPTION 'selector move bindings changed after decision' USING ERRCODE='40001';
    END IF;
END;
$gate$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE grantee record;fn regprocedure;
BEGIN
    FOREACH fn IN ARRAY ARRAY[
        'kaname._authority_role_move_binding_census_v1(text,jsonb,integer,integer)'::regprocedure,
        'kaname._authority_role_move_binding_empty_require_v1(jsonb)'::regprocedure
    ] LOOP
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
DO $binding_proof$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','b62b3fed95dfd39408adf6086649d034fa1fdc39bcc6c7c406ea94e278e34804','2c19697cdf3f2a8a4874c49c0eae766897c1c27aa4ce112e69dc4d04a659477a',$changes$[
 [
  "    role_image jsonb;",
  "    role_image jsonb;\n    carriers jsonb;"
 ],
 [
  "    copies:=kaname._authority_role_move_copy_requirements_hold_v1",
  "    carriers:=kaname._authority_role_move_binding_census_v1(p_input->>'role_id',NULL,p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(carriers->>'rows')::integer;\n    used_reads:=used_reads+(carriers->>'reads')::integer;\n    copies:=kaname._authority_role_move_copy_requirements_hold_v1"
 ],
 [
  "'role',role_image-ARRAY['rows','reads'],'copies',copies-ARRAY['rows','reads']",
  "'role',role_image-ARRAY['rows','reads'],'copies',copies-ARRAY['rows','reads'],'binding_census',carriers->'old'"
 ]
]$changes$::jsonb),
  ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','9644399436d2dca53ab8f629522a88abe0aa16f06eb856b616abd79e73a38927','9e7772c3a4950497773c1e4d2dc7a0f747db4a03d08b8ac581747e50fcb43cb2',$changes$[
 [
  "    actual_role_row jsonb;",
  "    actual_role_row jsonb;\n    carriers jsonb;"
 ],
 [
  "    result:=kaname._authority_role_move_copy_requirements_require_v1",
  "    IF jsonb_typeof(p_frozen->'binding_census') IS DISTINCT FROM 'object' THEN\n        RAISE EXCEPTION 'selector move prepared binding census missing' USING ERRCODE='42501';\n    END IF;\n    carriers:=kaname._authority_role_move_binding_census_v1(root_id,p_frozen->'binding_census',p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(carriers->>'rows')::integer;\n    used_reads:=used_reads+(carriers->>'reads')::integer;\n    result:=kaname._authority_role_move_copy_requirements_require_v1"
 ],
 [
  "'commands',result->'commands','rows',used_rows+step_rows",
  "'commands',result->'commands','binding_status',carriers->'binding_status','rows',used_rows+step_rows"
 ]
]$changes$::jsonb),
  ('_authority_role_move_sequence_approve_v1()','68bf1bae5828e05864b7d6b27986abb0a2123d573f534ddc8e938f7045bdcb7c','427e98aeb8679cb18e253760abacff4757905d9dcdcc087cabbd3b4e0dc23cb8',$changes$[
 [
  "    approval:=jsonb_build_object('nonce',proof->'nonce',",
  "    PERFORM kaname._authority_role_move_binding_empty_require_v1(program->'frozen');\n    approval:=jsonb_build_object('nonce',proof->'nonce',"
 ]
]$changes$::jsonb),
  ('_authority_role_move_roots_complete_v1()','f8ab09fd1664a0a1bf70f4708848bd2ac68ab0e2db4a36da668e3f90e686513e','22da8d1aabc4b9a48b3377d8e7f9462a4eb503dd4d6105875dea1a3a671e471b',$changes$[
 [
  "    IF commands='[]'::jsonb THEN RETURN;END IF;",
  "    PERFORM kaname._authority_role_move_binding_empty_require_v1(frozen);\n    IF commands='[]'::jsonb THEN RETURN;END IF;"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','d7d6c9b9157a9e145a7c1fce9b474c77602971d99645ea57fca33e2168f7c83f','5808081c4afa7ccdd6b831731532c1e645aa3c7162c1c8523da497ad68da425e',$changes$[
 [
  "b62b3fed95dfd39408adf6086649d034fa1fdc39bcc6c7c406ea94e278e34804",
  "2c19697cdf3f2a8a4874c49c0eae766897c1c27aa4ce112e69dc4d04a659477a"
 ],
 [
  "9644399436d2dca53ab8f629522a88abe0aa16f06eb856b616abd79e73a38927",
  "9e7772c3a4950497773c1e4d2dc7a0f747db4a03d08b8ac581747e50fcb43cb2"
 ],
 [
  "68bf1bae5828e05864b7d6b27986abb0a2123d573f534ddc8e938f7045bdcb7c",
  "427e98aeb8679cb18e253760abacff4757905d9dcdcc087cabbd3b4e0dc23cb8"
 ],
 [
  "f8ab09fd1664a0a1bf70f4708848bd2ac68ab0e2db4a36da668e3f90e686513e",
  "22da8d1aabc4b9a48b3377d8e7f9462a4eb503dd4d6105875dea1a3a671e471b"
 ],
 [
  " ('_authority_role_move_native_clock_v1(jsonb,jsonb)','e109f864a07dd2cb8814989eb915da415700bf84bf80576e6b6c281d4a5a3a47',false,'s',true,'private'),",
  " ('_authority_role_move_native_clock_v1(jsonb,jsonb)','e109f864a07dd2cb8814989eb915da415700bf84bf80576e6b6c281d4a5a3a47',false,'s',true,'private'),\n ('_authority_role_move_binding_census_v1(text,jsonb,integer,integer)','524a999cd7ed2f18bbebf057cd2cfed6252c926dfa7350488cf0287c6092ba1a',false,'v',true,'private'),\n ('_authority_role_move_binding_empty_require_v1(jsonb)','048b60e9637befdbbca317dba9db6d192bece6b298b1704bbcd306006b63c379',false,'v',true,'private'),"
 ],
 [
  "  ('_authority_role_move_native_clock_v1(jsonb,jsonb)','timestamp with time zone',2,ARRAY['p_proof','p_frozen']),",
  "  ('_authority_role_move_native_clock_v1(jsonb,jsonb)','timestamp with time zone',2,ARRAY['p_proof','p_frozen']),\n  ('_authority_role_move_binding_census_v1(text,jsonb,integer,integer)','jsonb',4,ARRAY['p_role_id','p_expected','p_rows','p_reads']),\n  ('_authority_role_move_binding_empty_require_v1(jsonb)','void',1,ARRAY['p_frozen']),"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','64ed933ee4c9bdd585a3a128b3dec8b47cf24b41f2bb1db23f46836af2ea29fa','6881336c2f6c0d0ab4c1fcfdea74376b7d3ccdebe2155efc49fb70fd7697abfc',$changes$[
 [
  "d7d6c9b9157a9e145a7c1fce9b474c77602971d99645ea57fca33e2168f7c83f",
  "5808081c4afa7ccdd6b831731532c1e645aa3c7162c1c8523da497ad68da425e"
 ]
]$changes$::jsonb),
  ('authority_metadata_service_account_access_label_ready_v1()','03027a7eb8686e4ef8a2c8245db2e2ed21e522808197aa30bc317f5ce55a19ef','7163c0f805715bd7b808993a11276be90a9874cb0306d48232acb6cdd7fad5dc',$changes$[
 [
  "d7d6c9b9157a9e145a7c1fce9b474c77602971d99645ea57fca33e2168f7c83f",
  "5808081c4afa7ccdd6b831731532c1e645aa3c7162c1c8523da497ad68da425e"
 ],
 [
  "64ed933ee4c9bdd585a3a128b3dec8b47cf24b41f2bb1db23f46836af2ea29fa",
  "6881336c2f6c0d0ab4c1fcfdea74376b7d3ccdebe2155efc49fb70fd7697abfc"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move binding census predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move binding census splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move binding census body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move binding census function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move binding census function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move binding census custody differs after migration' USING ERRCODE='55000';END IF;
END;
$binding_proof$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $binding_proof$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('authority_metadata_service_account_access_label_ready_v1()','7163c0f805715bd7b808993a11276be90a9874cb0306d48232acb6cdd7fad5dc','03027a7eb8686e4ef8a2c8245db2e2ed21e522808197aa30bc317f5ce55a19ef',$changes$[
 [
  "6881336c2f6c0d0ab4c1fcfdea74376b7d3ccdebe2155efc49fb70fd7697abfc",
  "64ed933ee4c9bdd585a3a128b3dec8b47cf24b41f2bb1db23f46836af2ea29fa"
 ],
 [
  "5808081c4afa7ccdd6b831731532c1e645aa3c7162c1c8523da497ad68da425e",
  "d7d6c9b9157a9e145a7c1fce9b474c77602971d99645ea57fca33e2168f7c83f"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','6881336c2f6c0d0ab4c1fcfdea74376b7d3ccdebe2155efc49fb70fd7697abfc','64ed933ee4c9bdd585a3a128b3dec8b47cf24b41f2bb1db23f46836af2ea29fa',$changes$[
 [
  "5808081c4afa7ccdd6b831731532c1e645aa3c7162c1c8523da497ad68da425e",
  "d7d6c9b9157a9e145a7c1fce9b474c77602971d99645ea57fca33e2168f7c83f"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','5808081c4afa7ccdd6b831731532c1e645aa3c7162c1c8523da497ad68da425e','d7d6c9b9157a9e145a7c1fce9b474c77602971d99645ea57fca33e2168f7c83f',$changes$[
 [
  "  ('_authority_role_move_native_clock_v1(jsonb,jsonb)','timestamp with time zone',2,ARRAY['p_proof','p_frozen']),\n  ('_authority_role_move_binding_census_v1(text,jsonb,integer,integer)','jsonb',4,ARRAY['p_role_id','p_expected','p_rows','p_reads']),\n  ('_authority_role_move_binding_empty_require_v1(jsonb)','void',1,ARRAY['p_frozen']),",
  "  ('_authority_role_move_native_clock_v1(jsonb,jsonb)','timestamp with time zone',2,ARRAY['p_proof','p_frozen']),"
 ],
 [
  " ('_authority_role_move_native_clock_v1(jsonb,jsonb)','e109f864a07dd2cb8814989eb915da415700bf84bf80576e6b6c281d4a5a3a47',false,'s',true,'private'),\n ('_authority_role_move_binding_census_v1(text,jsonb,integer,integer)','524a999cd7ed2f18bbebf057cd2cfed6252c926dfa7350488cf0287c6092ba1a',false,'v',true,'private'),\n ('_authority_role_move_binding_empty_require_v1(jsonb)','048b60e9637befdbbca317dba9db6d192bece6b298b1704bbcd306006b63c379',false,'v',true,'private'),",
  " ('_authority_role_move_native_clock_v1(jsonb,jsonb)','e109f864a07dd2cb8814989eb915da415700bf84bf80576e6b6c281d4a5a3a47',false,'s',true,'private'),"
 ],
 [
  "22da8d1aabc4b9a48b3377d8e7f9462a4eb503dd4d6105875dea1a3a671e471b",
  "f8ab09fd1664a0a1bf70f4708848bd2ac68ab0e2db4a36da668e3f90e686513e"
 ],
 [
  "427e98aeb8679cb18e253760abacff4757905d9dcdcc087cabbd3b4e0dc23cb8",
  "68bf1bae5828e05864b7d6b27986abb0a2123d573f534ddc8e938f7045bdcb7c"
 ],
 [
  "9e7772c3a4950497773c1e4d2dc7a0f747db4a03d08b8ac581747e50fcb43cb2",
  "9644399436d2dca53ab8f629522a88abe0aa16f06eb856b616abd79e73a38927"
 ],
 [
  "2c19697cdf3f2a8a4874c49c0eae766897c1c27aa4ce112e69dc4d04a659477a",
  "b62b3fed95dfd39408adf6086649d034fa1fdc39bcc6c7c406ea94e278e34804"
 ]
]$changes$::jsonb),
  ('_authority_role_move_roots_complete_v1()','22da8d1aabc4b9a48b3377d8e7f9462a4eb503dd4d6105875dea1a3a671e471b','f8ab09fd1664a0a1bf70f4708848bd2ac68ab0e2db4a36da668e3f90e686513e',$changes$[
 [
  "    PERFORM kaname._authority_role_move_binding_empty_require_v1(frozen);\n    IF commands='[]'::jsonb THEN RETURN;END IF;",
  "    IF commands='[]'::jsonb THEN RETURN;END IF;"
 ]
]$changes$::jsonb),
  ('_authority_role_move_sequence_approve_v1()','427e98aeb8679cb18e253760abacff4757905d9dcdcc087cabbd3b4e0dc23cb8','68bf1bae5828e05864b7d6b27986abb0a2123d573f534ddc8e938f7045bdcb7c',$changes$[
 [
  "    PERFORM kaname._authority_role_move_binding_empty_require_v1(program->'frozen');\n    approval:=jsonb_build_object('nonce',proof->'nonce',",
  "    approval:=jsonb_build_object('nonce',proof->'nonce',"
 ]
]$changes$::jsonb),
  ('_authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)','9e7772c3a4950497773c1e4d2dc7a0f747db4a03d08b8ac581747e50fcb43cb2','9644399436d2dca53ab8f629522a88abe0aa16f06eb856b616abd79e73a38927',$changes$[
 [
  "'commands',result->'commands','binding_status',carriers->'binding_status','rows',used_rows+step_rows",
  "'commands',result->'commands','rows',used_rows+step_rows"
 ],
 [
  "    IF jsonb_typeof(p_frozen->'binding_census') IS DISTINCT FROM 'object' THEN\n        RAISE EXCEPTION 'selector move prepared binding census missing' USING ERRCODE='42501';\n    END IF;\n    carriers:=kaname._authority_role_move_binding_census_v1(root_id,p_frozen->'binding_census',p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(carriers->>'rows')::integer;\n    used_reads:=used_reads+(carriers->>'reads')::integer;\n    result:=kaname._authority_role_move_copy_requirements_require_v1",
  "    result:=kaname._authority_role_move_copy_requirements_require_v1"
 ],
 [
  "    actual_role_row jsonb;\n    carriers jsonb;",
  "    actual_role_row jsonb;"
 ]
]$changes$::jsonb),
  ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','2c19697cdf3f2a8a4874c49c0eae766897c1c27aa4ce112e69dc4d04a659477a','b62b3fed95dfd39408adf6086649d034fa1fdc39bcc6c7c406ea94e278e34804',$changes$[
 [
  "'role',role_image-ARRAY['rows','reads'],'copies',copies-ARRAY['rows','reads'],'binding_census',carriers->'old'",
  "'role',role_image-ARRAY['rows','reads'],'copies',copies-ARRAY['rows','reads']"
 ],
 [
  "    carriers:=kaname._authority_role_move_binding_census_v1(p_input->>'role_id',NULL,p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(carriers->>'rows')::integer;\n    used_reads:=used_reads+(carriers->>'reads')::integer;\n    copies:=kaname._authority_role_move_copy_requirements_hold_v1",
  "    copies:=kaname._authority_role_move_copy_requirements_hold_v1"
 ],
 [
  "    role_image jsonb;\n    carriers jsonb;",
  "    role_image jsonb;"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move binding census predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move binding census splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move binding census body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move binding census function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move binding census function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move binding census custody differs after migration' USING ERRCODE='55000';END IF;
END;
$binding_proof$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_role_move_binding_empty_require_v1(jsonb);
DROP FUNCTION kaname._authority_role_move_binding_census_v1(text,jsonb,integer,integer);
DROP INDEX kaname.access_binding_target_members_role_binding_idx;
