-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Подготовка роли сохраняет удержанную версию определения до решения.

-- +goose Up
SELECT kaname.authority_protocol_drain();

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_access_label_prepared_definition_v1(
    p_scope_kind text, p_scope_id text, p_definition uuid, p_rows integer, p_reads integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    proof jsonb;
    program jsonb;
    witness jsonb;
    selected_at timestamptz;
    prepared_at timestamptz;
    matches boolean;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF current_setting('transaction_isolation')<>'read committed'
       OR p_scope_kind IS NULL OR p_scope_kind NOT IN ('cluster','account','project')
       OR coalesce(p_scope_id,'')='' OR p_definition IS NULL THEN
        RAISE EXCEPTION 'access label definition requires exact scope' USING ERRCODE='23514';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN 2 AND 100000
       OR p_reads IS NULL OR p_reads NOT BETWEEN 3 AND 4096 THEN
        RAISE EXCEPTION 'access label prepared definition budget is absent' USING ERRCODE='54000';
    END IF;
    SELECT q.proof,q.header INTO STRICT proof,program FROM kaname._authority_sequence_probe_v3() q;
    IF proof->>'writer_contract' IS DISTINCT FROM '2'
       OR proof->>'kind' IS DISTINCT FROM 'role' OR proof->>'purpose' IS DISTINCT FROM 'decision'
       OR program->>'family' IS DISTINCT FROM 'role'
       OR program#>>'{frozen,mode}' IS DISTINCT FROM 'access_label_transition'
       OR jsonb_typeof(program->'selected') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'access label definition requires a finalized role program' USING ERRCODE='42501';
    END IF;
    SELECT s.frozen#>ARRAY['access_label_transition','definition_witnesses',p_definition::text],
           s.decision_at,s.staged_decision_at
    INTO witness,selected_at,prepared_at
    FROM pg_temp.kaname_authority_sequence_program s
    WHERE s.singleton AND s.nonce=(program->>'nonce')::uuid
      AND s.family='role' AND s.frozen->>'kind'='role.mutation'
      AND NOT (s.frozen ? 'access_label_transition_applied');
    IF NOT FOUND OR selected_at IS NULL OR prepared_at IS NULL OR selected_at<=prepared_at
       OR selected_at IS DISTINCT FROM (proof->>'decision_at')::timestamptz THEN
        RAISE EXCEPTION 'access label definition clock differs from finalized decision' USING ERRCODE='42501';
    END IF;
    IF witness IS NULL OR witness->>'scope_kind' IS DISTINCT FROM p_scope_kind
       OR witness->>'scope_id' IS DISTINCT FROM p_scope_id THEN
        RETURN jsonb_build_object('matched',false,'rows',1,'reads',2);
    END IF;
    -- Владелец удержал этот образ до clock. После clock только читаем
    -- и сверяем его: новая блокировка или новая версия не принимаются.
    SELECT EXISTS (
        SELECT 1 FROM kaname.authority_access_label_definition d
        WHERE d.id=p_definition AND d.scope_kind=p_scope_kind AND d.scope_id=p_scope_id
          AND d.module=witness->>'module' AND d.resource=witness->>'resource'
          AND d.label_key=witness->>'label_key' AND d.revision=(witness->>'revision')::bigint
          AND d.xmin::text=witness->>'row_xmin' AND d.ctid::text=witness->>'row_ctid'
    ) INTO matches;
    RETURN jsonb_build_object('matched',matches,'rows',2,'reads',3,
        'decision_at',CASE WHEN matches THEN selected_at END);
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
DECLARE
    signature constant text := 'kaname.authority_access_label_prepared_definition_v1(text,text,uuid,integer,integer)';
    grantee record;
BEGIN
    FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
        WHERE p.oid=to_regprocedure(signature) AND a.grantee<>p.proowner
    LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',signature,
            CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $access_label_definition_custody$
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
        RAISE EXCEPTION 'несогласованное состояние перед изменением удержания определений accessLabels' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        (
            'authority_access_label_role_transition_prepare_v1(jsonb,jsonb,integer,integer)',
            'b52c1fd273d1b169ae22aa313237fc573b28c11b3b0a16e72a6ede67f31e37a3',
            '2e0e88f7ea3231c88e746c80edc82ca4101a19ff6472011ebbb8b34aa7102608',
            $patch$[
  [
    "    definition record;",
    "    definition record;\n    held_definitions jsonb[] := ARRAY[]::jsonb[];\n    witnesses jsonb;"
  ],
  [
    "        used_reads:=used_reads+2;",
    "        held_definitions:=array_append(held_definitions,to_jsonb(definition));\n        used_reads:=used_reads+2;"
  ],
  [
    "    RETURN jsonb_build_object('role_id'",
    "    SELECT coalesce(jsonb_object_agg(held->>'id',held),'{}'::jsonb)\n    INTO witnesses FROM unnest(held_definitions) held;\n    RETURN jsonb_build_object('role_id'"
  ],
  [
    "        'rows',used_rows,'reads',used_reads);",
    "        'definition_witnesses',witnesses,'rows',used_rows,'reads',used_reads);"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            'd7a587c9368995c8bfe073f46c2ca5799dadac165aba3611c039a315767d6909',
            '972bbab30b47edc04eca5e7a04583874178608ad752be84357a0cd5e086b8f85',
            $patch$[
  [
    " ('authority_access_label_role_transition_prepare_v1(jsonb,jsonb,integer,integer)','b52c1fd273d1b169ae22aa313237fc573b28c11b3b0a16e72a6ede67f31e37a3',false,'v',true,'private'),",
    " ('authority_access_label_role_transition_prepare_v1(jsonb,jsonb,integer,integer)','2e0e88f7ea3231c88e746c80edc82ca4101a19ff6472011ebbb8b34aa7102608',false,'v',true,'private'),\n ('authority_access_label_prepared_definition_v1(text,text,uuid,integer,integer)','a2bcc1f0193fe47bfcd7bcb0c4727cffbc892ee049826b28cbf78e418afe71ba',false,'v',true,'private'),"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_full_contract_storage_v3()',
            '76fb8fa429c80592f2f87d6bf8297ee48ffd2221f7b61914eed91bfa1fbb6ca1',
            'c2f71f6ada22503f37fb76c065b8af7847957b74f7c9489f486e434d79f880e8',
            $patch$[
  [
    "d7a587c9368995c8bfe073f46c2ca5799dadac165aba3611c039a315767d6909",
    "972bbab30b47edc04eca5e7a04583874178608ad752be84357a0cd5e086b8f85"
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
$access_label_definition_custody$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();

-- +goose StatementBegin
DO $access_label_definition_custody$
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
        RAISE EXCEPTION 'несогласованное состояние перед изменением удержания определений accessLabels' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        (
            '_authority_full_contract_storage_v3()',
            'c2f71f6ada22503f37fb76c065b8af7847957b74f7c9489f486e434d79f880e8',
            '76fb8fa429c80592f2f87d6bf8297ee48ffd2221f7b61914eed91bfa1fbb6ca1',
            $patch$[
  [
    "972bbab30b47edc04eca5e7a04583874178608ad752be84357a0cd5e086b8f85",
    "d7a587c9368995c8bfe073f46c2ca5799dadac165aba3611c039a315767d6909"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            '972bbab30b47edc04eca5e7a04583874178608ad752be84357a0cd5e086b8f85',
            'd7a587c9368995c8bfe073f46c2ca5799dadac165aba3611c039a315767d6909',
            $patch$[
  [
    " ('authority_access_label_role_transition_prepare_v1(jsonb,jsonb,integer,integer)','2e0e88f7ea3231c88e746c80edc82ca4101a19ff6472011ebbb8b34aa7102608',false,'v',true,'private'),\n ('authority_access_label_prepared_definition_v1(text,text,uuid,integer,integer)','a2bcc1f0193fe47bfcd7bcb0c4727cffbc892ee049826b28cbf78e418afe71ba',false,'v',true,'private'),",
    " ('authority_access_label_role_transition_prepare_v1(jsonb,jsonb,integer,integer)','b52c1fd273d1b169ae22aa313237fc573b28c11b3b0a16e72a6ede67f31e37a3',false,'v',true,'private'),"
  ]
]$patch$::jsonb
        ),
        (
            'authority_access_label_role_transition_prepare_v1(jsonb,jsonb,integer,integer)',
            '2e0e88f7ea3231c88e746c80edc82ca4101a19ff6472011ebbb8b34aa7102608',
            'b52c1fd273d1b169ae22aa313237fc573b28c11b3b0a16e72a6ede67f31e37a3',
            $patch$[
  [
    "        'definition_witnesses',witnesses,'rows',used_rows,'reads',used_reads);",
    "        'rows',used_rows,'reads',used_reads);"
  ],
  [
    "    SELECT coalesce(jsonb_object_agg(held->>'id',held),'{}'::jsonb)\n    INTO witnesses FROM unnest(held_definitions) held;\n    RETURN jsonb_build_object('role_id'",
    "    RETURN jsonb_build_object('role_id'"
  ],
  [
    "        held_definitions:=array_append(held_definitions,to_jsonb(definition));\n        used_reads:=used_reads+2;",
    "        used_reads:=used_reads+2;"
  ],
  [
    "    definition record;\n    held_definitions jsonb[] := ARRAY[]::jsonb[];\n    witnesses jsonb;",
    "    definition record;"
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
$access_label_definition_custody$;
-- +goose StatementEnd

DROP FUNCTION kaname.authority_access_label_prepared_definition_v1(text,text,uuid,integer,integer);
