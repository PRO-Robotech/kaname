-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Результаты проверок OLD-источников accessLabels в транзакции роли.

-- +goose Up
SELECT kaname.authority_protocol_drain();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_role_source_store_v1() RETURNS oid
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $store$
DECLARE storage oid;owner_oid oid:=current_user::regrole::oid;grantee record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 storage:=to_regclass('pg_temp.kaname_authority_access_label_role_source');
 IF storage IS NULL THEN
  CREATE TEMP TABLE pg_temp.kaname_authority_access_label_role_source(
   nonce uuid NOT NULL,scope_kind text COLLATE "C" NOT NULL,scope_id text COLLATE "C" NOT NULL,
   definition_id uuid NOT NULL,satisfied boolean NOT NULL,
   PRIMARY KEY(nonce,scope_kind,scope_id,definition_id)
  ) ON COMMIT DELETE ROWS;
  storage:='pg_temp.kaname_authority_access_label_role_source'::regclass;
  REVOKE ALL ON pg_temp.kaname_authority_access_label_role_source FROM PUBLIC;
  FOR grantee IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_class c
   CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) a
   JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE c.oid=storage AND a.grantee<>owner_oid LOOP
   EXECUTE format('REVOKE ALL ON pg_temp.kaname_authority_access_label_role_source FROM %I',grantee.rolname);
  END LOOP;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=storage
    AND c.relnamespace=pg_my_temp_schema() AND c.relowner=owner_oid
    AND c.relpersistence='t' AND c.relkind='r'
    AND NOT (c.relhasrules OR c.relrowsecurity OR c.relhastriggers OR c.relhassubclass)
    AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
       WHERE a.grantee<>owner_oid))
 OR (SELECT array_agg(a.attname::text ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
    WHERE a.attrelid=storage AND a.attnum>0 AND NOT a.attisdropped)
    IS DISTINCT FROM ARRAY['nonce','scope_kind','scope_id','definition_id','satisfied']
 OR (SELECT array_agg(a.atttypid ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
    WHERE a.attrelid=storage AND a.attnum>0 AND NOT a.attisdropped)
    IS DISTINCT FROM ARRAY['uuid'::regtype::oid,'text'::regtype::oid,'text'::regtype::oid,'uuid'::regtype::oid,'boolean'::regtype::oid]
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=storage AND a.attnum>0
    AND (a.attisdropped OR NOT a.attnotnull OR a.atthasdef OR a.attgenerated<>'' OR a.attidentity<>''
     OR (a.attnum IN (2,3) AND a.attcollation IS DISTINCT FROM '"C"'::regcollation::oid)
     OR EXISTS(SELECT 1 FROM pg_catalog.aclexplode(a.attacl) x WHERE x.grantee<>owner_oid)))
 OR (SELECT count(*) FROM pg_catalog.pg_index i WHERE i.indrelid=storage)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
    JOIN pg_catalog.pg_am am ON am.oid=c.relam WHERE i.indrelid=storage
    AND i.indisprimary AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
    AND i.indnatts=4 AND i.indnkeyatts=4 AND i.indkey='1 2 3 4'::int2vector
    AND i.indexprs IS NULL AND i.indpred IS NULL AND am.amname='btree')
 THEN RAISE EXCEPTION 'role access label private source store differs' USING ERRCODE='42501';END IF;
 IF EXISTS(SELECT 1 FROM ONLY pg_temp.kaname_authority_access_label_role_source) THEN
  RAISE EXCEPTION 'role access label private source store is not empty' USING ERRCODE='42501';END IF;
 RETURN storage;
END;
$store$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $role_source_store_private$
DECLARE grantee record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 REVOKE ALL ON FUNCTION kaname._authority_access_label_role_source_store_v1() FROM PUBLIC;
 FOR grantee IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname._authority_access_label_role_source_store_v1()'::regprocedure AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_access_label_role_source_store_v1() FROM %I',grantee.rolname);
 END LOOP;
END
$role_source_store_private$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $access_label_role_source_receipts$
DECLARE
    item record;
    replacement jsonb;
    fn regprocedure;
    old_body text;
    new_body text;
    definition text;
    needle text;
BEGIN
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние перед подготовкой обязательных проверок accessLabels' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','cced8e3de809419c6506a4cca501c99bd5b4f4c465681bdb87261777bdbe4972','bcfedb5314ae275e71f5953dac76111ae65f217b4877e8154b224ccc9fe4b6c4',$patch$[[" scope_maximum bigint;scope_cost bigint;", " scope_maximum bigint;scope_cost bigint;source_store oid;"], ["scope_cost:=2+scope_count::bigint+jsonb_array_length(scope_ids)+2*scope_maximum;", "scope_cost:=5+scope_count::bigint+jsonb_array_length(scope_ids)+3*scope_maximum;"], ["     reads:=reads+1; -- owner finalization of required questions", "     -- Проверка формы private store, пустоты и заполнение точек\n     -- оплачиваются до final clock вместе с вычислением owner questions.\n     reads:=reads+4;\n     IF reads>p_reads THEN\n      RAISE EXCEPTION 'role apply private source store read budget' USING ERRCODE='54000';END IF;\n     source_store:=kaname._authority_access_label_role_source_store_v1();"], ["     access_label_frozen:=access_label_frozen||jsonb_build_object('access_label_scope_census',\n      jsonb_build_object('version',1,'mode','apply'", "     access_label_frozen:=access_label_frozen||jsonb_build_object('access_label_source_store_oid',source_store,\n      'access_label_scope_census',jsonb_build_object('version',1,'mode','apply'"]]$patch$::jsonb),
        ('authority_role_sequence_finalize_v3()','22ea6d68eec1c2e597666316ba4614f4f225f96433561884e412c71476b48146','d560c7a10ef3c64a2ec55f2c8e0733e6d4ebc1f134c1be8313e7cd011c22037f',$patch$[[" required_questions jsonb;required_index jsonb;", " required_questions jsonb;required_index jsonb;source_store oid;inserted integer;"], ["  UPDATE pg_temp.kaname_authority_sequence_program s", "  source_store:=(program#>>'{frozen,access_label_source_store_oid}')::oid;\n  IF source_store IS NULL OR source_store IS DISTINCT FROM to_regclass('pg_temp.kaname_authority_access_label_role_source')::oid THEN\n   RAISE EXCEPTION 'role access label finalized source store differs' USING ERRCODE='42501';END IF;\n  INSERT INTO pg_temp.kaname_authority_access_label_role_source(nonce,scope_kind,scope_id,definition_id,satisfied)\n  SELECT (proof->>'nonce')::uuid,q->>'scope_kind',q->>'scope_id',(q->>'definition_id')::uuid,false\n  FROM jsonb_array_elements(required_questions) q;\n  GET DIAGNOSTICS inserted=ROW_COUNT;\n  IF inserted<>jsonb_array_length(required_questions) THEN\n   RAISE EXCEPTION 'role access label finalized source points differ' USING ERRCODE='42501';END IF;\n  UPDATE pg_temp.kaname_authority_sequence_program s"]]$patch$::jsonb),
        ('authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','4f6d03c973e37e47f69f32e96d0bf7ffc028bb53d3ff54ade7f7b12ea27430c1','77c9967452f5540e08d91d63df53e137afd450c0fb8bfefc9699ea561c207723',$patch$[[" root_untouched boolean;", " root_untouched boolean;source_store oid;program_nonce uuid;"], [" -- + minimum source 8/2. All nested calls share these same remainders.", " -- + minimum source 8/2 + custody и запись private результата 2/2."], ["p_rows NOT BETWEEN 15 AND 100000\n OR p_reads IS NULL OR p_reads NOT BETWEEN 8 AND 4096", "p_rows NOT BETWEEN 17 AND 100000\n OR p_reads IS NULL OR p_reads NOT BETWEEN 10 AND 4096"], [" INTO frozen_role_id,program_clock,current_model,current_projector,root_untouched", "        ,(s.frozen->>'access_label_source_store_oid')::oid,s.nonce\n INTO frozen_role_id,program_clock,current_model,current_projector,root_untouched,source_store,program_nonce"], ["p_binding_id,p_recipient_type,p_recipient_id,p_source_rule_fp,receipt_clock,p_rows-used_rows,", "p_binding_id,p_recipient_type,p_recipient_id,p_source_rule_fp,receipt_clock,p_rows-used_rows-2,"], [" used_rows:=used_rows+(source_check->>'rows')::integer;\n used_reads:=used_reads+(source_check->>'reads')::integer;", " -- Два шага резервируются и для отрицательного ответа. Сам отрицательный\n -- ответ не меняет состояние ни одной точки.\n used_rows:=used_rows+(source_check->>'rows')::integer+2;\n used_reads:=used_reads+(source_check->>'reads')::integer+2;\n IF used_rows>p_rows OR used_reads>p_reads THEN\n  RAISE EXCEPTION 'role access label shared source budget exceeded' USING ERRCODE='54000';END IF;\n IF source_check->'allowed'='true'::jsonb THEN\n  IF source_store IS NULL OR program_nonce IS NULL\n   OR source_store IS DISTINCT FROM to_regclass('pg_temp.kaname_authority_access_label_role_source')::oid\n   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n     WHERE c.oid=source_store AND c.relowner=current_user::regrole::oid\n      AND c.relnamespace=pg_my_temp_schema() AND c.relpersistence='t' AND c.relkind='r') THEN\n   RAISE EXCEPTION 'role access label source receipt custody differs' USING ERRCODE='42501';END IF;\n  -- Записывается только результат проверенного OLD-источника для уже\n  -- существующей точки owner census. Повтор идемпотентен, новых точек нет.\n  UPDATE ONLY pg_temp.kaname_authority_access_label_role_source q SET satisfied=true\n   WHERE q.nonce=program_nonce AND q.scope_kind=p_scope_kind AND q.scope_id=p_scope_id\n    AND q.definition_id=p_definition;\n  IF NOT FOUND THEN\n   RAISE EXCEPTION 'role access label source receipt point absent' USING ERRCODE='42501';END IF;\n END IF;"], [" IF used_rows>p_rows OR used_reads>p_reads THEN\n  RAISE EXCEPTION 'role access label shared source budget exceeded' USING ERRCODE='54000';END IF;\n RETURN jsonb_build_object('allowed',source_check->'allowed'", " RETURN jsonb_build_object('allowed',source_check->'allowed'"]]$patch$::jsonb),
        ('_authority_crud_storage_v3()','75d625c28cacf379521a0c3b9a86394f9b98b1589711627a44fb36bd996816c3','fe12a95aa929e85b3e51eb046e029aad79430110b2adad61554d1f96737fe347',$patch$[[" ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','cced8e3de809419c6506a4cca501c99bd5b4f4c465681bdb87261777bdbe4972',true,'v',true,'export'),", " ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','bcfedb5314ae275e71f5953dac76111ae65f217b4877e8154b224ccc9fe4b6c4',true,'v',true,'export'),"], [" ('authority_role_sequence_finalize_v3()','22ea6d68eec1c2e597666316ba4614f4f225f96433561884e412c71476b48146',true,'v',true,'export'),", " ('authority_role_sequence_finalize_v3()','d560c7a10ef3c64a2ec55f2c8e0733e6d4ebc1f134c1be8313e7cd011c22037f',true,'v',true,'export'),"], [" ('authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','4f6d03c973e37e47f69f32e96d0bf7ffc028bb53d3ff54ade7f7b12ea27430c1',false,'v',true,'private'),", " ('authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','77c9967452f5540e08d91d63df53e137afd450c0fb8bfefc9699ea561c207723',false,'v',true,'private'),"], [" ('authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','77c9967452f5540e08d91d63df53e137afd450c0fb8bfefc9699ea561c207723',false,'v',true,'private'),", " ('authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','77c9967452f5540e08d91d63df53e137afd450c0fb8bfefc9699ea561c207723',false,'v',true,'private'),\n ('_authority_access_label_role_source_store_v1()','76b947688f21e26fb58fef22690dfbcd220bd0586469b6c20836420a5865c17f',false,'v',true,'private'),"]]$patch$::jsonb),
        ('_authority_full_contract_storage_v3()','28ada78675e7cc36bafe0afe436a588abf88f591644243f855c073970674bd80','29532a992ae865977f50793695257c9f93a5397de4b31eb373bce8e5e58b87b9',$patch$[["75d625c28cacf379521a0c3b9a86394f9b98b1589711627a44fb36bd996816c3", "fe12a95aa929e85b3e51eb046e029aad79430110b2adad61554d1f96737fe347"]]$patch$::jsonb)
    ) AS changes(signature, before_sha, after_sha, substitutions) LOOP
        fn := pg_catalog.to_regprocedure('kaname.' || item.signature);
        IF fn IS NULL THEN RAISE EXCEPTION 'функция % для миграции отсутствует', item.signature USING ERRCODE='55000';END IF;
        SELECT p.prosrc INTO STRICT old_body FROM pg_catalog.pg_proc p WHERE p.oid=fn;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(old_body,'UTF8')),'hex') IS DISTINCT FROM item.before_sha THEN
            RAISE EXCEPTION 'исходное тело функции % не соответствует этой миграции', item.signature USING ERRCODE='55000';
        END IF;
        new_body := old_body;
        FOR replacement IN SELECT value FROM pg_catalog.jsonb_array_elements(item.substitutions) LOOP
            needle := replacement->>0;
            IF length(new_body)-length(replace(new_body,needle,'')) IS DISTINCT FROM length(needle) THEN
                RAISE EXCEPTION 'фрагмент тела функции % не уникален', item.signature USING ERRCODE='55000';
            END IF;
            new_body := replace(new_body,needle,replacement->>1);
        END LOOP;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(new_body,'UTF8')),'hex') IS DISTINCT FROM item.after_sha THEN
            RAISE EXCEPTION 'расчётное тело функции % изменилось', item.signature USING ERRCODE='55000';
        END IF;
        -- PostgreSQL восстанавливает сигнатуру и настройки, CREATE OR REPLACE
        -- сохраняет owner/ACL. Меняется ровно одно полное тело с известным SHA.
        definition := pg_catalog.pg_get_functiondef(fn);
        IF length(definition)-length(replace(definition,old_body,'')) IS DISTINCT FROM length(old_body) THEN
            RAISE EXCEPTION 'определение функции % не содержит единственного исходного тела', item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,old_body,new_body);
        IF (SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex')
            FROM pg_catalog.pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.after_sha THEN
            RAISE EXCEPTION 'установленное тело функции % не совпадает с расчётным', item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние после фиксации проверенных источников accessLabels' USING ERRCODE='55000';
    END IF;
END
$access_label_role_source_receipts$;
-- +goose StatementEnd



-- +goose Down
SELECT kaname.authority_protocol_drain();

-- +goose StatementBegin
DO $access_label_role_source_receipts$
DECLARE
    item record;
    replacement jsonb;
    fn regprocedure;
    old_body text;
    new_body text;
    definition text;
    needle text;
BEGIN
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние перед подготовкой обязательных проверок accessLabels' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        ('_authority_full_contract_storage_v3()','29532a992ae865977f50793695257c9f93a5397de4b31eb373bce8e5e58b87b9','28ada78675e7cc36bafe0afe436a588abf88f591644243f855c073970674bd80',$patch$[["fe12a95aa929e85b3e51eb046e029aad79430110b2adad61554d1f96737fe347", "75d625c28cacf379521a0c3b9a86394f9b98b1589711627a44fb36bd996816c3"]]$patch$::jsonb),
        ('_authority_crud_storage_v3()','fe12a95aa929e85b3e51eb046e029aad79430110b2adad61554d1f96737fe347','75d625c28cacf379521a0c3b9a86394f9b98b1589711627a44fb36bd996816c3',$patch$[[" ('authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','77c9967452f5540e08d91d63df53e137afd450c0fb8bfefc9699ea561c207723',false,'v',true,'private'),\n ('_authority_access_label_role_source_store_v1()','76b947688f21e26fb58fef22690dfbcd220bd0586469b6c20836420a5865c17f',false,'v',true,'private'),", " ('authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','77c9967452f5540e08d91d63df53e137afd450c0fb8bfefc9699ea561c207723',false,'v',true,'private'),"], [" ('authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','77c9967452f5540e08d91d63df53e137afd450c0fb8bfefc9699ea561c207723',false,'v',true,'private'),", " ('authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','4f6d03c973e37e47f69f32e96d0bf7ffc028bb53d3ff54ade7f7b12ea27430c1',false,'v',true,'private'),"], [" ('authority_role_sequence_finalize_v3()','d560c7a10ef3c64a2ec55f2c8e0733e6d4ebc1f134c1be8313e7cd011c22037f',true,'v',true,'export'),", " ('authority_role_sequence_finalize_v3()','22ea6d68eec1c2e597666316ba4614f4f225f96433561884e412c71476b48146',true,'v',true,'export'),"], [" ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','bcfedb5314ae275e71f5953dac76111ae65f217b4877e8154b224ccc9fe4b6c4',true,'v',true,'export'),", " ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','cced8e3de809419c6506a4cca501c99bd5b4f4c465681bdb87261777bdbe4972',true,'v',true,'export'),"]]$patch$::jsonb),
        ('authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','77c9967452f5540e08d91d63df53e137afd450c0fb8bfefc9699ea561c207723','4f6d03c973e37e47f69f32e96d0bf7ffc028bb53d3ff54ade7f7b12ea27430c1',$patch$[[" RETURN jsonb_build_object('allowed',source_check->'allowed'", " IF used_rows>p_rows OR used_reads>p_reads THEN\n  RAISE EXCEPTION 'role access label shared source budget exceeded' USING ERRCODE='54000';END IF;\n RETURN jsonb_build_object('allowed',source_check->'allowed'"], [" -- Два шага резервируются и для отрицательного ответа. Сам отрицательный\n -- ответ не меняет состояние ни одной точки.\n used_rows:=used_rows+(source_check->>'rows')::integer+2;\n used_reads:=used_reads+(source_check->>'reads')::integer+2;\n IF used_rows>p_rows OR used_reads>p_reads THEN\n  RAISE EXCEPTION 'role access label shared source budget exceeded' USING ERRCODE='54000';END IF;\n IF source_check->'allowed'='true'::jsonb THEN\n  IF source_store IS NULL OR program_nonce IS NULL\n   OR source_store IS DISTINCT FROM to_regclass('pg_temp.kaname_authority_access_label_role_source')::oid\n   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n     WHERE c.oid=source_store AND c.relowner=current_user::regrole::oid\n      AND c.relnamespace=pg_my_temp_schema() AND c.relpersistence='t' AND c.relkind='r') THEN\n   RAISE EXCEPTION 'role access label source receipt custody differs' USING ERRCODE='42501';END IF;\n  -- Записывается только результат проверенного OLD-источника для уже\n  -- существующей точки owner census. Повтор идемпотентен, новых точек нет.\n  UPDATE ONLY pg_temp.kaname_authority_access_label_role_source q SET satisfied=true\n   WHERE q.nonce=program_nonce AND q.scope_kind=p_scope_kind AND q.scope_id=p_scope_id\n    AND q.definition_id=p_definition;\n  IF NOT FOUND THEN\n   RAISE EXCEPTION 'role access label source receipt point absent' USING ERRCODE='42501';END IF;\n END IF;", " used_rows:=used_rows+(source_check->>'rows')::integer;\n used_reads:=used_reads+(source_check->>'reads')::integer;"], ["p_binding_id,p_recipient_type,p_recipient_id,p_source_rule_fp,receipt_clock,p_rows-used_rows-2,", "p_binding_id,p_recipient_type,p_recipient_id,p_source_rule_fp,receipt_clock,p_rows-used_rows,"], ["        ,(s.frozen->>'access_label_source_store_oid')::oid,s.nonce\n INTO frozen_role_id,program_clock,current_model,current_projector,root_untouched,source_store,program_nonce", " INTO frozen_role_id,program_clock,current_model,current_projector,root_untouched"], ["p_rows NOT BETWEEN 17 AND 100000\n OR p_reads IS NULL OR p_reads NOT BETWEEN 10 AND 4096", "p_rows NOT BETWEEN 15 AND 100000\n OR p_reads IS NULL OR p_reads NOT BETWEEN 8 AND 4096"], [" -- + minimum source 8/2 + custody и запись private результата 2/2.", " -- + minimum source 8/2. All nested calls share these same remainders."], [" root_untouched boolean;source_store oid;program_nonce uuid;", " root_untouched boolean;"]]$patch$::jsonb),
        ('authority_role_sequence_finalize_v3()','d560c7a10ef3c64a2ec55f2c8e0733e6d4ebc1f134c1be8313e7cd011c22037f','22ea6d68eec1c2e597666316ba4614f4f225f96433561884e412c71476b48146',$patch$[["  source_store:=(program#>>'{frozen,access_label_source_store_oid}')::oid;\n  IF source_store IS NULL OR source_store IS DISTINCT FROM to_regclass('pg_temp.kaname_authority_access_label_role_source')::oid THEN\n   RAISE EXCEPTION 'role access label finalized source store differs' USING ERRCODE='42501';END IF;\n  INSERT INTO pg_temp.kaname_authority_access_label_role_source(nonce,scope_kind,scope_id,definition_id,satisfied)\n  SELECT (proof->>'nonce')::uuid,q->>'scope_kind',q->>'scope_id',(q->>'definition_id')::uuid,false\n  FROM jsonb_array_elements(required_questions) q;\n  GET DIAGNOSTICS inserted=ROW_COUNT;\n  IF inserted<>jsonb_array_length(required_questions) THEN\n   RAISE EXCEPTION 'role access label finalized source points differ' USING ERRCODE='42501';END IF;\n  UPDATE pg_temp.kaname_authority_sequence_program s", "  UPDATE pg_temp.kaname_authority_sequence_program s"], [" required_questions jsonb;required_index jsonb;source_store oid;inserted integer;", " required_questions jsonb;required_index jsonb;"]]$patch$::jsonb),
        ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','bcfedb5314ae275e71f5953dac76111ae65f217b4877e8154b224ccc9fe4b6c4','cced8e3de809419c6506a4cca501c99bd5b4f4c465681bdb87261777bdbe4972',$patch$[["     access_label_frozen:=access_label_frozen||jsonb_build_object('access_label_source_store_oid',source_store,\n      'access_label_scope_census',jsonb_build_object('version',1,'mode','apply'", "     access_label_frozen:=access_label_frozen||jsonb_build_object('access_label_scope_census',\n      jsonb_build_object('version',1,'mode','apply'"], ["     -- Проверка формы private store, пустоты и заполнение точек\n     -- оплачиваются до final clock вместе с вычислением owner questions.\n     reads:=reads+4;\n     IF reads>p_reads THEN\n      RAISE EXCEPTION 'role apply private source store read budget' USING ERRCODE='54000';END IF;\n     source_store:=kaname._authority_access_label_role_source_store_v1();", "     reads:=reads+1; -- owner finalization of required questions"], ["scope_cost:=5+scope_count::bigint+jsonb_array_length(scope_ids)+3*scope_maximum;", "scope_cost:=2+scope_count::bigint+jsonb_array_length(scope_ids)+2*scope_maximum;"], [" scope_maximum bigint;scope_cost bigint;source_store oid;", " scope_maximum bigint;scope_cost bigint;"]]$patch$::jsonb)
    ) AS changes(signature, before_sha, after_sha, substitutions) LOOP
        fn := pg_catalog.to_regprocedure('kaname.' || item.signature);
        IF fn IS NULL THEN RAISE EXCEPTION 'функция % для миграции отсутствует', item.signature USING ERRCODE='55000';END IF;
        SELECT p.prosrc INTO STRICT old_body FROM pg_catalog.pg_proc p WHERE p.oid=fn;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(old_body,'UTF8')),'hex') IS DISTINCT FROM item.before_sha THEN
            RAISE EXCEPTION 'исходное тело функции % не соответствует этой миграции', item.signature USING ERRCODE='55000';
        END IF;
        new_body := old_body;
        FOR replacement IN SELECT value FROM pg_catalog.jsonb_array_elements(item.substitutions) LOOP
            needle := replacement->>0;
            IF length(new_body)-length(replace(new_body,needle,'')) IS DISTINCT FROM length(needle) THEN
                RAISE EXCEPTION 'фрагмент тела функции % не уникален', item.signature USING ERRCODE='55000';
            END IF;
            new_body := replace(new_body,needle,replacement->>1);
        END LOOP;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(new_body,'UTF8')),'hex') IS DISTINCT FROM item.after_sha THEN
            RAISE EXCEPTION 'расчётное тело функции % изменилось', item.signature USING ERRCODE='55000';
        END IF;
        -- PostgreSQL восстанавливает сигнатуру и настройки, CREATE OR REPLACE
        -- сохраняет owner/ACL. Меняется ровно одно полное тело с известным SHA.
        definition := pg_catalog.pg_get_functiondef(fn);
        IF length(definition)-length(replace(definition,old_body,'')) IS DISTINCT FROM length(old_body) THEN
            RAISE EXCEPTION 'определение функции % не содержит единственного исходного тела', item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,old_body,new_body);
        IF (SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex')
            FROM pg_catalog.pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.after_sha THEN
            RAISE EXCEPTION 'установленное тело функции % не совпадает с расчётным', item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние после фиксации проверенных источников accessLabels' USING ERRCODE='55000';
    END IF;
END
$access_label_role_source_receipts$;
-- +goose StatementEnd



DROP FUNCTION kaname._authority_access_label_role_source_store_v1();
