-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Узкое чтение равенства проекции в том же снимке, что и версия роли.

-- +goose Up
SELECT kaname.authority_protocol_drain();

-- Вызов STABLE использует тот же снимок, что читает версию роли.
-- Наружу возвращаются только равенство проекции и ограниченная стоимость.
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_access_label_role_checkpoint_read_v1(
    p_role_id text,p_xmin text,p_ctid text,p_rows integer
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE invoker oid; result jsonb; actual_xmin text; actual_ctid text;
BEGIN
    -- Проверяется роль вызывающего, у которой уже есть доступ к строке роли.
    SELECT oid INTO STRICT invoker FROM pg_roles
        WHERE rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
    IF NOT has_table_privilege(invoker,'kaname.roles'::regclass,'SELECT')
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid='kaname.roles'::regclass AND c.relrowsecurity) THEN
        RAISE EXCEPTION 'role checkpoint requires existing role read privilege' USING ERRCODE='42501';
    END IF;
    IF coalesce(p_role_id,'')='' OR p_xmin IS NULL OR p_ctid IS NULL THEN
        RAISE EXCEPTION 'role checkpoint requires exact visible role identity' USING ERRCODE='23514';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN 2 AND 4096 THEN
        RAISE EXCEPTION 'role checkpoint remaining budget exhausted' USING ERRCODE='54000';
    END IF;
    SELECT r.xmin::text,r.ctid::text INTO actual_xmin,actual_ctid
        FROM kaname.roles r WHERE r.id=p_role_id AND r.live;
    IF actual_xmin IS DISTINCT FROM p_xmin OR actual_ctid IS DISTINCT FROM p_ctid THEN
        RETURN jsonb_build_object('matches',false,'rows',1,'reads',1);
    END IF;
    result:=kaname.authority_access_label_role_projection_matches_v1(p_role_id,p_rows-1);
    RETURN result||jsonb_build_object('rows',(result->>'rows')::integer+1,
        'reads',(result->>'reads')::integer+1);
END;
$$;
-- +goose StatementEnd

-- Предоставляем EXECUTE только получателям действующего типизированного входа.
-- +goose StatementBegin
DO $$
DECLARE g record;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    FOR g IN SELECT DISTINCT a.grantee,r.rolname FROM pg_proc p
        CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        LEFT JOIN pg_roles r ON r.oid=a.grantee
        WHERE p.oid='kaname.authority_access_label_role_checkpoint_read_v1(text,text,text,integer)'::regprocedure
          AND a.grantee<>p.proowner
    LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION kaname.authority_access_label_role_checkpoint_read_v1(text,text,text,integer) FROM %s',
            CASE WHEN g.grantee=0 THEN 'PUBLIC' ELSE format('%I',g.rolname) END);
    END LOOP;
    -- Сначала сняты в том числе права из настроек по умолчанию.
    FOR g IN SELECT DISTINCT r.rolname FROM pg_proc p
        CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_roles r ON r.oid=a.grantee
        WHERE p.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure
          AND a.grantee<>p.proowner AND a.privilege_type='EXECUTE' AND NOT a.is_grantable
    LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.authority_access_label_role_checkpoint_read_v1(text,text,text,integer) TO %I',g.rolname);
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $access_label_checkpoint_read$
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
        RAISE EXCEPTION 'несогласованное состояние перед изменением проверки снимка роли' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
            (
            'authority_protocol_grant_runtime(regrole)',
            '0d293355335c3d8c60e4fce5b91b335f8dd7dea3fab9dc737e8fcb67d1b266a3',
            '60f3a58150a1d88b43b2a92976e56f01f9db17a63be857a8230a2cde1dfd1de6',
            $patch$[
  [
    "  'authority_crud_storage_v3()',",
    "  'authority_access_label_role_checkpoint_read_v1(text,text,text,integer)',\n  'authority_crud_storage_v3()',"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            '7b35d2f4b1997ffca2b4fe6f89988a1d163e750c5ee7fa3fa505aeeffbce8139',
            '0d1d1e686f9c5601c614bd335edf7b11b823635d98c4a8e4caeed70393bf862d',
            $patch$[
  [
    " ('authority_protocol_grant_runtime(regrole)','0d293355335c3d8c60e4fce5b91b335f8dd7dea3fab9dc737e8fcb67d1b266a3',false,'v',true,'preserve'),",
    " ('authority_protocol_grant_runtime(regrole)','60f3a58150a1d88b43b2a92976e56f01f9db17a63be857a8230a2cde1dfd1de6',false,'v',true,'preserve'),"
  ],
  [
    " ('authority_access_label_role_projection_matches_v1(text,integer)','044de8f3215cefde7b41313278c3e2726142d50bd078cd3b86f423b3f1a71fa3',false,'s',true,'private'),",
    " ('authority_access_label_role_projection_matches_v1(text,integer)','044de8f3215cefde7b41313278c3e2726142d50bd078cd3b86f423b3f1a71fa3',false,'s',true,'private'),\n ('authority_access_label_role_checkpoint_read_v1(text,text,text,integer)','7985c8756c9440f3608e310bd3e8922dafc9ee5752491f93bfaef9f28d4342b0',true,'s',true,'export'),"
  ],
  [
    "  ('authority_native_delete_stamp_v4(uuid,bigint,jsonb)','timestamptz',3,ARRAY['p_nonce','p_id','p_payload'])",
    "  ('authority_native_delete_stamp_v4(uuid,bigint,jsonb)','timestamptz',3,ARRAY['p_nonce','p_id','p_payload']),\n  ('authority_access_label_role_checkpoint_read_v1(text,text,text,integer)','jsonb',4,ARRAY['p_role_id','p_xmin','p_ctid','p_rows'])"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_full_contract_storage_v3()',
            '192ff1f85511ffa1f6dadd37da3106a595e4024252e04051a06ab481584cd0f2',
            '107fec4447089dbff6f1c52cd0bb3de66e95a32db2dde85b8698d53f986bdf2b',
            $patch$[
  [
    "7b35d2f4b1997ffca2b4fe6f89988a1d163e750c5ee7fa3fa505aeeffbce8139",
    "0d1d1e686f9c5601c614bd335edf7b11b823635d98c4a8e4caeed70393bf862d"
  ]
]$patch$::jsonb
        ) ) AS changes(signature, before_sha, after_sha, substitutions) LOOP
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
        RAISE EXCEPTION 'несогласованное состояние после обновления образов доступа' USING ERRCODE='55000';
    END IF;
END
$access_label_checkpoint_read$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();

-- +goose StatementBegin
DO $access_label_checkpoint_read$
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
        RAISE EXCEPTION 'несогласованное состояние перед изменением проверки снимка роли' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
            (
            '_authority_full_contract_storage_v3()',
            '107fec4447089dbff6f1c52cd0bb3de66e95a32db2dde85b8698d53f986bdf2b',
            '192ff1f85511ffa1f6dadd37da3106a595e4024252e04051a06ab481584cd0f2',
            $patch$[
  [
    "0d1d1e686f9c5601c614bd335edf7b11b823635d98c4a8e4caeed70393bf862d",
    "7b35d2f4b1997ffca2b4fe6f89988a1d163e750c5ee7fa3fa505aeeffbce8139"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            '0d1d1e686f9c5601c614bd335edf7b11b823635d98c4a8e4caeed70393bf862d',
            '7b35d2f4b1997ffca2b4fe6f89988a1d163e750c5ee7fa3fa505aeeffbce8139',
            $patch$[
  [
    "  ('authority_native_delete_stamp_v4(uuid,bigint,jsonb)','timestamptz',3,ARRAY['p_nonce','p_id','p_payload']),\n  ('authority_access_label_role_checkpoint_read_v1(text,text,text,integer)','jsonb',4,ARRAY['p_role_id','p_xmin','p_ctid','p_rows'])",
    "  ('authority_native_delete_stamp_v4(uuid,bigint,jsonb)','timestamptz',3,ARRAY['p_nonce','p_id','p_payload'])"
  ],
  [
    " ('authority_access_label_role_projection_matches_v1(text,integer)','044de8f3215cefde7b41313278c3e2726142d50bd078cd3b86f423b3f1a71fa3',false,'s',true,'private'),\n ('authority_access_label_role_checkpoint_read_v1(text,text,text,integer)','7985c8756c9440f3608e310bd3e8922dafc9ee5752491f93bfaef9f28d4342b0',true,'s',true,'export'),",
    " ('authority_access_label_role_projection_matches_v1(text,integer)','044de8f3215cefde7b41313278c3e2726142d50bd078cd3b86f423b3f1a71fa3',false,'s',true,'private'),"
  ],
  [
    " ('authority_protocol_grant_runtime(regrole)','60f3a58150a1d88b43b2a92976e56f01f9db17a63be857a8230a2cde1dfd1de6',false,'v',true,'preserve'),",
    " ('authority_protocol_grant_runtime(regrole)','0d293355335c3d8c60e4fce5b91b335f8dd7dea3fab9dc737e8fcb67d1b266a3',false,'v',true,'preserve'),"
  ]
]$patch$::jsonb
        ),
        (
            'authority_protocol_grant_runtime(regrole)',
            '60f3a58150a1d88b43b2a92976e56f01f9db17a63be857a8230a2cde1dfd1de6',
            '0d293355335c3d8c60e4fce5b91b335f8dd7dea3fab9dc737e8fcb67d1b266a3',
            $patch$[
  [
    "  'authority_access_label_role_checkpoint_read_v1(text,text,text,integer)',\n  'authority_crud_storage_v3()',",
    "  'authority_crud_storage_v3()',"
  ]
]$patch$::jsonb
        ) ) AS changes(signature, before_sha, after_sha, substitutions) LOOP
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
        RAISE EXCEPTION 'несогласованное состояние после обновления образов доступа' USING ERRCODE='55000';
    END IF;
END
$access_label_checkpoint_read$;
-- +goose StatementEnd

DROP FUNCTION kaname.authority_access_label_role_checkpoint_read_v1(text,text,text,integer);
