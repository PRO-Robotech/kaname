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
            '46b22a5305737064ac149d7e5b19e0105ea690b43263c306570d4e2115112821',
            '7b7eb7e1be4e26d2d06be16c95aba9682ef77bd1e1d8b95537b4759b5ae3ec28',
            $patch$[
  [
    "  'authority_crud_storage_v3()',",
    "  'authority_access_label_role_checkpoint_read_v1(text,text,text,integer)',\n  'authority_crud_storage_v3()',"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            '387861a0643db293462bd5e63b37bd6e6201fbb4cd199a4bc925f9d1e21bd793',
            'd7a587c9368995c8bfe073f46c2ca5799dadac165aba3611c039a315767d6909',
            $patch$[
  [
    " ('authority_protocol_grant_runtime(regrole)','46b22a5305737064ac149d7e5b19e0105ea690b43263c306570d4e2115112821',false,'v',true,'preserve'),",
    " ('authority_protocol_grant_runtime(regrole)','7b7eb7e1be4e26d2d06be16c95aba9682ef77bd1e1d8b95537b4759b5ae3ec28',false,'v',true,'preserve'),"
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
            'a7064627b35552764a2c33d4c47a5badf53b689be57bd4685c677f04cec0f2b2',
            '76fb8fa429c80592f2f87d6bf8297ee48ffd2221f7b61914eed91bfa1fbb6ca1',
            $patch$[
  [
    "387861a0643db293462bd5e63b37bd6e6201fbb4cd199a4bc925f9d1e21bd793",
    "d7a587c9368995c8bfe073f46c2ca5799dadac165aba3611c039a315767d6909"
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
            '76fb8fa429c80592f2f87d6bf8297ee48ffd2221f7b61914eed91bfa1fbb6ca1',
            'a7064627b35552764a2c33d4c47a5badf53b689be57bd4685c677f04cec0f2b2',
            $patch$[
  [
    "d7a587c9368995c8bfe073f46c2ca5799dadac165aba3611c039a315767d6909",
    "387861a0643db293462bd5e63b37bd6e6201fbb4cd199a4bc925f9d1e21bd793"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            'd7a587c9368995c8bfe073f46c2ca5799dadac165aba3611c039a315767d6909',
            '387861a0643db293462bd5e63b37bd6e6201fbb4cd199a4bc925f9d1e21bd793',
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
    " ('authority_protocol_grant_runtime(regrole)','7b7eb7e1be4e26d2d06be16c95aba9682ef77bd1e1d8b95537b4759b5ae3ec28',false,'v',true,'preserve'),",
    " ('authority_protocol_grant_runtime(regrole)','46b22a5305737064ac149d7e5b19e0105ea690b43263c306570d4e2115112821',false,'v',true,'preserve'),"
  ]
]$patch$::jsonb
        ),
        (
            'authority_protocol_grant_runtime(regrole)',
            '7b7eb7e1be4e26d2d06be16c95aba9682ef77bd1e1d8b95537b4759b5ae3ec28',
            '46b22a5305737064ac149d7e5b19e0105ea690b43263c306570d4e2115112821',
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
