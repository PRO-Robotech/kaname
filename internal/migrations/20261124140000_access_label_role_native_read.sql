-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Типизированный вход к проверке apply в подписанной операции роли.

-- +goose Up
SELECT kaname.authority_protocol_drain();

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_role_access_label_source_read_v1(
 p_mutation_role_id text,p_actor_type text,p_actor_id text,p_decision_at timestamptz,
 p_binding_id text,p_binding_xmin text,p_binding_ctid text,
 p_source_role_id text,p_source_role_xmin text,p_source_role_ctid text,
 p_recipient_type text,p_recipient_id text,p_scope_kind text,p_scope_id text,
 p_definition uuid,p_source_rule_fp text,p_checkpoint jsonb,p_rows integer,p_reads integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $native_source_read$
BEGIN
 RETURN kaname.authority_role_access_label_source_check_v1(
  p_mutation_role_id, p_actor_type, p_actor_id, p_decision_at,
  p_binding_id, p_binding_xmin, p_binding_ctid, p_source_role_id,
  p_source_role_xmin, p_source_role_ctid, p_recipient_type, p_recipient_id,
  p_scope_kind, p_scope_id, p_definition, p_source_rule_fp,
  p_checkpoint, p_rows, p_reads);
END;
$native_source_read$;
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
        WHERE p.oid='kaname.authority_role_access_label_source_read_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)'::regprocedure
          AND a.grantee<>p.proowner
    LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION kaname.authority_role_access_label_source_read_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer) FROM %s',
            CASE WHEN g.grantee=0 THEN 'PUBLIC' ELSE format('%I',g.rolname) END);
    END LOOP;
    -- Сначала сняты в том числе права из настроек по умолчанию.
    FOR g IN SELECT DISTINCT r.rolname FROM pg_proc p
        CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_roles r ON r.oid=a.grantee
        WHERE p.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure
          AND a.grantee<>p.proowner AND a.privilege_type='EXECUTE' AND NOT a.is_grantable
    LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.authority_role_access_label_source_read_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer) TO %I',g.rolname);
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $access_label_role_native_runtime$
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
        RAISE EXCEPTION 'несогласованное состояние перед изменением типизированного чтения источника accessLabels' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        (
            'authority_protocol_grant_runtime(regrole)',
            '7b7eb7e1be4e26d2d06be16c95aba9682ef77bd1e1d8b95537b4759b5ae3ec28',
            '2bd4434aa60b0d76eeb9d6eac0475cbbeecf859aa0092f44ea7bf2bf1ace1892',
            $patch$[
  [
    "  'authority_access_label_role_checkpoint_read_v1(text,text,text,integer)',",
    "  'authority_access_label_role_checkpoint_read_v1(text,text,text,integer)',\n  'authority_role_access_label_source_read_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)',"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            '825b20705b0f28d20fd7a74a219f4e66b5a9a8a23f4b7030457eeefb323bca51',
            'fbfa3a661ed99588248fbe8a4915bfc33561cb6088aa59ada2aa57c19c5fe7c2',
            $patch$[
  [
    " ('authority_protocol_grant_runtime(regrole)','7b7eb7e1be4e26d2d06be16c95aba9682ef77bd1e1d8b95537b4759b5ae3ec28',false,'v',true,'preserve'),",
    " ('authority_protocol_grant_runtime(regrole)','2bd4434aa60b0d76eeb9d6eac0475cbbeecf859aa0092f44ea7bf2bf1ace1892',false,'v',true,'preserve'),"
  ],
  [
    " ('authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','4f6d03c973e37e47f69f32e96d0bf7ffc028bb53d3ff54ade7f7b12ea27430c1',false,'v',true,'private'),",
    " ('authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','4f6d03c973e37e47f69f32e96d0bf7ffc028bb53d3ff54ade7f7b12ea27430c1',false,'v',true,'private'),\n ('authority_role_access_label_source_read_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','eeeecfa11f0aba381064f3857f930a849f840f646e994db288370c085d5835d8',true,'v',true,'export'),"
  ],
  [
    "  ('authority_access_label_role_checkpoint_read_v1(text,text,text,integer)','jsonb',4,ARRAY['p_role_id','p_xmin','p_ctid','p_rows'])",
    "  ('authority_access_label_role_checkpoint_read_v1(text,text,text,integer)','jsonb',4,ARRAY['p_role_id','p_xmin','p_ctid','p_rows']),\n  ('authority_role_access_label_source_read_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','jsonb',19,ARRAY['p_mutation_role_id','p_actor_type','p_actor_id','p_decision_at','p_binding_id','p_binding_xmin','p_binding_ctid','p_source_role_id','p_source_role_xmin','p_source_role_ctid','p_recipient_type','p_recipient_id','p_scope_kind','p_scope_id','p_definition','p_source_rule_fp','p_checkpoint','p_rows','p_reads'])"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_full_contract_storage_v3()',
            '3a8caf84c8c844ece83680e34b6bcf22c0ecfa86a7ea1166199a6357cc09f520',
            'cdc3716469a20f6dcb0f23eec48dbbe3a80220ec0863ddce866caf253c022728',
            $patch$[
  [
    "825b20705b0f28d20fd7a74a219f4e66b5a9a8a23f4b7030457eeefb323bca51",
    "fbfa3a661ed99588248fbe8a4915bfc33561cb6088aa59ada2aa57c19c5fe7c2"
  ]
]$patch$::jsonb
        )
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
        RAISE EXCEPTION 'несогласованное состояние после обновления образов доступа' USING ERRCODE='55000';
    END IF;
END
$access_label_role_native_runtime$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();

-- +goose StatementBegin
DO $access_label_role_native_runtime$
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
        RAISE EXCEPTION 'несогласованное состояние перед изменением типизированного чтения источника accessLabels' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        (
            '_authority_full_contract_storage_v3()',
            'cdc3716469a20f6dcb0f23eec48dbbe3a80220ec0863ddce866caf253c022728',
            '3a8caf84c8c844ece83680e34b6bcf22c0ecfa86a7ea1166199a6357cc09f520',
            $patch$[
  [
    "fbfa3a661ed99588248fbe8a4915bfc33561cb6088aa59ada2aa57c19c5fe7c2",
    "825b20705b0f28d20fd7a74a219f4e66b5a9a8a23f4b7030457eeefb323bca51"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            'fbfa3a661ed99588248fbe8a4915bfc33561cb6088aa59ada2aa57c19c5fe7c2',
            '825b20705b0f28d20fd7a74a219f4e66b5a9a8a23f4b7030457eeefb323bca51',
            $patch$[
  [
    "  ('authority_access_label_role_checkpoint_read_v1(text,text,text,integer)','jsonb',4,ARRAY['p_role_id','p_xmin','p_ctid','p_rows']),\n  ('authority_role_access_label_source_read_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','jsonb',19,ARRAY['p_mutation_role_id','p_actor_type','p_actor_id','p_decision_at','p_binding_id','p_binding_xmin','p_binding_ctid','p_source_role_id','p_source_role_xmin','p_source_role_ctid','p_recipient_type','p_recipient_id','p_scope_kind','p_scope_id','p_definition','p_source_rule_fp','p_checkpoint','p_rows','p_reads'])",
    "  ('authority_access_label_role_checkpoint_read_v1(text,text,text,integer)','jsonb',4,ARRAY['p_role_id','p_xmin','p_ctid','p_rows'])"
  ],
  [
    " ('authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','4f6d03c973e37e47f69f32e96d0bf7ffc028bb53d3ff54ade7f7b12ea27430c1',false,'v',true,'private'),\n ('authority_role_access_label_source_read_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','eeeecfa11f0aba381064f3857f930a849f840f646e994db288370c085d5835d8',true,'v',true,'export'),",
    " ('authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','4f6d03c973e37e47f69f32e96d0bf7ffc028bb53d3ff54ade7f7b12ea27430c1',false,'v',true,'private'),"
  ],
  [
    " ('authority_protocol_grant_runtime(regrole)','2bd4434aa60b0d76eeb9d6eac0475cbbeecf859aa0092f44ea7bf2bf1ace1892',false,'v',true,'preserve'),",
    " ('authority_protocol_grant_runtime(regrole)','7b7eb7e1be4e26d2d06be16c95aba9682ef77bd1e1d8b95537b4759b5ae3ec28',false,'v',true,'preserve'),"
  ]
]$patch$::jsonb
        ),
        (
            'authority_protocol_grant_runtime(regrole)',
            '2bd4434aa60b0d76eeb9d6eac0475cbbeecf859aa0092f44ea7bf2bf1ace1892',
            '7b7eb7e1be4e26d2d06be16c95aba9682ef77bd1e1d8b95537b4759b5ae3ec28',
            $patch$[
  [
    "  'authority_access_label_role_checkpoint_read_v1(text,text,text,integer)',\n  'authority_role_access_label_source_read_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)',",
    "  'authority_access_label_role_checkpoint_read_v1(text,text,text,integer)',"
  ]
]$patch$::jsonb
        )
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
        RAISE EXCEPTION 'несогласованное состояние после обновления образов доступа' USING ERRCODE='55000';
    END IF;
END
$access_label_role_native_runtime$;
-- +goose StatementEnd

DROP FUNCTION kaname.authority_role_access_label_source_read_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer);
