-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Подготовка привязки удерживает полную версию определений из сохранённой роли.

-- +goose Up
SELECT kaname.authority_protocol_drain();

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_access_label_binding_definitions_prepare_v1(
    p_role jsonb, p_role_xmin text, p_role_ctid text,
    p_scope_kind text, p_scope_id text, p_rows integer, p_reads integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    projection jsonb;
    definition_ids uuid[];
    wanted_count integer;
    captured_count integer;
    definition jsonb;
    witnesses jsonb;
    questions jsonb;
    used_rows integer;
    used_reads integer;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'binding definition preparation requires READ COMMITTED'
            USING ERRCODE='25001';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000
       OR p_reads IS NULL OR p_reads NOT BETWEEN 0 AND 4096 THEN
        RAISE EXCEPTION 'binding definition preparation budget is absent'
            USING ERRCODE='54000';
    END IF;
    IF jsonb_typeof(p_role) IS DISTINCT FROM 'object'
       OR coalesce(p_role->>'id','')='' THEN
        RAISE EXCEPTION 'binding definition preparation requires an actual role'
            USING ERRCODE='23514';
    END IF;
    IF octet_length(p_role::text)>33554432 THEN
        RAISE EXCEPTION 'binding definition preparation role bound exceeded'
            USING ERRCODE='54000';
    END IF;

    -- Только вычисление из уже прочитанной owner-строки, без нового source
    -- scan. Нулевой cap допускает лишь пустое множество actual apply.
    SELECT coalesce(jsonb_agg(jsonb_build_array(c.rule_fp,c.definition_id)
        ORDER BY c.rule_fp COLLATE "C",c.definition_id),'[]'::jsonb)
    INTO projection
    FROM kaname.authority_access_label_role_compile_v1(p_role->'rules') c;
    IF projection='[]'::jsonb THEN
        RETURN jsonb_build_object('projection',projection,'definitions','[]'::jsonb,
            'questions','[]'::jsonb,'rows',0,'reads',0);
    END IF;
    IF p_role->'live' IS DISTINCT FROM 'true'::jsonb
       OR coalesce(p_role_xmin,'')='' OR coalesce(p_role_ctid,'')=''
       OR p_scope_kind IS NULL OR p_scope_kind NOT IN ('cluster','account','project')
       OR coalesce(p_scope_id,'')='' THEN
        RAISE EXCEPTION 'binding definition preparation lacks locked role or exact scope'
            USING ERRCODE='23514';
    END IF;

    SELECT array_agg(id ORDER BY id) INTO definition_ids FROM (
        SELECT DISTINCT (value->>1)::uuid AS id
        FROM jsonb_array_elements(projection) ORDER BY 1 LIMIT 2049
    ) distinct_ids;
    wanted_count:=cardinality(definition_ids);
    -- Compile, один batch capture, затем D exact holds. Новый scan роли
    -- отсутствует: p_role/stamps получены outer SELECT под FOR SHARE.
    used_rows:=jsonb_array_length(projection)+2*wanted_count;
    used_reads:=2+wanted_count;
    IF jsonb_array_length(projection)>16384 OR wanted_count>2048
       OR used_rows>p_rows OR used_reads>p_reads THEN
        RAISE EXCEPTION 'binding definition preparation prepaid budget exceeded'
            USING ERRCODE='54000';
    END IF;

    -- Первичное удержание всех строк идёт в UUID-порядке, до final clock.
    -- Один batch и одна агрегация вместо пересборки двух растущих JSON arrays
    -- на каждом определении. FOR SHARE находится внутри materialized capture;
    -- внешняя агрегация не меняет порядок row locking.
    WITH captured AS MATERIALIZED (
        SELECT d.id,d.scope_kind,d.scope_id,d.module,d.resource,d.label_key,
            d.revision,d.xmin::text AS row_xmin,d.ctid::text AS row_ctid,
            d.scope_kind=p_scope_kind AND d.scope_id=p_scope_id AS applicable
        FROM kaname.authority_access_label_definition d
        WHERE d.id=ANY(definition_ids) ORDER BY d.id FOR SHARE OF d
    )
    SELECT count(*)::integer,
        coalesce(jsonb_agg(jsonb_build_object(
            'id',d.id,'scope_kind',d.scope_kind,'scope_id',d.scope_id,
            'module',d.module,'resource',d.resource,'label_key',d.label_key,
            'revision',d.revision,'xmin',d.row_xmin,'ctid',d.row_ctid,
            'applicable',d.applicable) ORDER BY d.id),'[]'::jsonb),
        coalesce(jsonb_agg(jsonb_build_object(
            'scope_kind',p_scope_kind,'scope_id',p_scope_id,'definition_id',d.id)
            ORDER BY d.id) FILTER (WHERE d.applicable),'[]'::jsonb)
    INTO captured_count,witnesses,questions FROM captured d;
    IF captured_count<>wanted_count THEN
        RAISE EXCEPTION 'binding definition preparation definition is absent'
            USING ERRCODE='23503';
    END IF;

    -- Reuse exact revision verifier: он повторяет координаты уже held rows,
    -- не вводит второй порядок или новые waits после batch FOR SHARE.
    FOR definition IN SELECT value FROM jsonb_array_elements(witnesses)
        ORDER BY (value->>'id')::uuid LOOP
        IF NOT kaname.authority_access_label_definition_hold_v1(
            definition->>'scope_kind',definition->>'scope_id',definition->>'module',
            definition->>'resource',definition->>'label_key',(definition->>'id')::uuid,
            (definition->>'revision')::bigint,definition->>'xmin',definition->>'ctid',NULL) THEN
            RAISE EXCEPTION 'binding definition preparation definition revision changed'
                USING ERRCODE='40001';
        END IF;
    END LOOP;
    RETURN jsonb_build_object('role_id',p_role->>'id',
        'role_digest',encode(sha256(convert_to(p_role::text,'UTF8')),'hex'),
        'role_xmin',p_role_xmin,'role_ctid',p_role_ctid,
        'scope_kind',p_scope_kind,'scope_id',p_scope_id,
        'projection',projection,'definitions',witnesses,'questions',questions,
        'rows',used_rows,'reads',used_reads);
END;
$$;

-- +goose StatementEnd

-- +goose StatementBegin
DO $$
DECLARE grantee record;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    REVOKE ALL ON FUNCTION kaname.authority_access_label_binding_definitions_prepare_v1(jsonb,text,text,text,text,integer,integer) FROM PUBLIC;
    FOR grantee IN SELECT DISTINCT r.rolname FROM pg_proc p
        CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        JOIN pg_roles r ON r.oid=a.grantee
        WHERE p.oid='kaname.authority_access_label_binding_definitions_prepare_v1(jsonb,text,text,text,text,integer,integer)'::regprocedure
          AND a.grantee<>p.proowner
    LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION kaname.authority_access_label_binding_definitions_prepare_v1(jsonb,text,text,text,text,integer,integer) FROM %I',grantee.rolname);
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $access_label_binding_definitions$
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
        RAISE EXCEPTION 'несогласованное состояние перед изменением удержания определений в привязках' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        (
            'authority_binding_sequence_prepare_v3(text,jsonb)',
            'a0290994e32a6eb0a8c753b3be6bff865afcb3a40d4a6f9dafcef0aa1c7beb3c',
            '3ab5bed30a3f8e9fdc27503a03d621dcb37e1437e7663d09ca7c07f322499e47',
            $patch$[
  [
    " ordinal integer:=0;i integer:=0;cost integer;created timestamptz:=transaction_timestamp();scope_value integer;\n",
    " ordinal integer:=0;i integer:=0;cost integer;created timestamptz:=transaction_timestamp();scope_value integer;\n role_xmin text;role_ctid text;prepaid jsonb;prepaid_rows integer:=0;prepaid_reads integer:=0;definition_holds jsonb;frozen jsonb;\n"
  ],
  [
    " ELSE\n",
    " ELSE\n  -- Только create принимает отдельный budget envelope. Он не становится\n  -- полем access_bindings и не ослабляет прежнюю закрытую mutation mask.\n  IF p_input ? '_access_label_prepaid' THEN\n   prepaid:=p_input->'_access_label_prepaid';\n   IF jsonb_typeof(prepaid) IS DISTINCT FROM 'object'\n    OR prepaid-ARRAY['rows','reads']<>'{}'::jsonb\n    OR jsonb_typeof(prepaid->'rows') IS DISTINCT FROM 'number'\n    OR jsonb_typeof(prepaid->'reads') IS DISTINCT FROM 'number' THEN\n    RAISE EXCEPTION 'binding access label budget envelope is not closed' USING ERRCODE='23514';END IF;\n   prepaid_rows:=(prepaid->>'rows')::integer;prepaid_reads:=(prepaid->>'reads')::integer;\n   IF prepaid_rows NOT BETWEEN 0 AND 100000 OR prepaid_reads NOT BETWEEN 0 AND 4096 THEN\n    RAISE EXCEPTION 'binding access label prepaid cap exceeded' USING ERRCODE='54000';END IF;\n   p_input:=p_input-'_access_label_prepaid';\n  END IF;\n"
  ],
  [
    "  SELECT to_jsonb(r) INTO STRICT role_row FROM kaname.roles r WHERE r.id=parent->>'role_id' FOR SHARE;\n",
    "  SELECT to_jsonb(r),r.xmin::text,r.ctid::text INTO STRICT role_row,role_xmin,role_ctid\n   FROM kaname.roles r WHERE r.id=parent->>'role_id' FOR SHARE;\n  definition_holds:=kaname.authority_access_label_binding_definitions_prepare_v1(\n   role_row,role_xmin,role_ctid,parent->>'resource_type',parent->>'resource_id',prepaid_rows,prepaid_reads);\n  IF (definition_holds->>'rows')::integer>prepaid_rows\n   OR (definition_holds->>'reads')::integer>prepaid_reads THEN\n   RAISE EXCEPTION 'binding access label work exceeded prepaid cap' USING ERRCODE='54000';END IF;\n"
  ],
  [
    " PERFORM kaname._authority_sequence_freeze_v3(jsonb_build_object('kind','binding.decision','mode',p_mode,'id',p_input->>'id','created_at',created));\n",
    " frozen:=jsonb_build_object('kind','binding.decision','mode',p_mode,'id',p_input->>'id','created_at',created);\n IF definition_holds->'definitions'<>'[]'::jsonb THEN\n  frozen:=frozen||jsonb_build_object('access_label_definition_holds',definition_holds);\n END IF;\n PERFORM kaname._authority_sequence_freeze_v3(frozen);\n"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            '972bbab30b47edc04eca5e7a04583874178608ad752be84357a0cd5e086b8f85',
            '9d18cd51bf9b55f68028c426540b5ef19f410ea5fc026859776fe41fc48282f1',
            $patch$[
  [
    " ('authority_binding_sequence_prepare_v3(text,jsonb)','a0290994e32a6eb0a8c753b3be6bff865afcb3a40d4a6f9dafcef0aa1c7beb3c',true,'v',true,'export'),",
    " ('authority_binding_sequence_prepare_v3(text,jsonb)','3ab5bed30a3f8e9fdc27503a03d621dcb37e1437e7663d09ca7c07f322499e47',true,'v',true,'export'),"
  ],
  [
    " ('authority_access_label_prepared_definition_v1(text,text,uuid,integer,integer)','a2bcc1f0193fe47bfcd7bcb0c4727cffbc892ee049826b28cbf78e418afe71ba',false,'v',true,'private'),",
    " ('authority_access_label_prepared_definition_v1(text,text,uuid,integer,integer)','a2bcc1f0193fe47bfcd7bcb0c4727cffbc892ee049826b28cbf78e418afe71ba',false,'v',true,'private'),\n ('authority_access_label_binding_definitions_prepare_v1(jsonb,text,text,text,text,integer,integer)','8127b1758d4ce9f8bfda917bb4bcc0bc292972aede72c22d7ba137289ec2b972',false,'v',true,'private'),"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_full_contract_storage_v3()',
            'c2f71f6ada22503f37fb76c065b8af7847957b74f7c9489f486e434d79f880e8',
            '1cb1ab228cacbe657b021f31131131833e3a2482f2d3d831cebf8a770151a23b',
            $patch$[
  [
    "972bbab30b47edc04eca5e7a04583874178608ad752be84357a0cd5e086b8f85",
    "9d18cd51bf9b55f68028c426540b5ef19f410ea5fc026859776fe41fc48282f1"
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
$access_label_binding_definitions$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();

-- +goose StatementBegin
DO $access_label_binding_definitions$
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
        RAISE EXCEPTION 'несогласованное состояние перед изменением удержания определений в привязках' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        (
            '_authority_full_contract_storage_v3()',
            '1cb1ab228cacbe657b021f31131131833e3a2482f2d3d831cebf8a770151a23b',
            'c2f71f6ada22503f37fb76c065b8af7847957b74f7c9489f486e434d79f880e8',
            $patch$[
  [
    "9d18cd51bf9b55f68028c426540b5ef19f410ea5fc026859776fe41fc48282f1",
    "972bbab30b47edc04eca5e7a04583874178608ad752be84357a0cd5e086b8f85"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            '9d18cd51bf9b55f68028c426540b5ef19f410ea5fc026859776fe41fc48282f1',
            '972bbab30b47edc04eca5e7a04583874178608ad752be84357a0cd5e086b8f85',
            $patch$[
  [
    " ('authority_access_label_prepared_definition_v1(text,text,uuid,integer,integer)','a2bcc1f0193fe47bfcd7bcb0c4727cffbc892ee049826b28cbf78e418afe71ba',false,'v',true,'private'),\n ('authority_access_label_binding_definitions_prepare_v1(jsonb,text,text,text,text,integer,integer)','8127b1758d4ce9f8bfda917bb4bcc0bc292972aede72c22d7ba137289ec2b972',false,'v',true,'private'),",
    " ('authority_access_label_prepared_definition_v1(text,text,uuid,integer,integer)','a2bcc1f0193fe47bfcd7bcb0c4727cffbc892ee049826b28cbf78e418afe71ba',false,'v',true,'private'),"
  ],
  [
    " ('authority_binding_sequence_prepare_v3(text,jsonb)','3ab5bed30a3f8e9fdc27503a03d621dcb37e1437e7663d09ca7c07f322499e47',true,'v',true,'export'),",
    " ('authority_binding_sequence_prepare_v3(text,jsonb)','a0290994e32a6eb0a8c753b3be6bff865afcb3a40d4a6f9dafcef0aa1c7beb3c',true,'v',true,'export'),"
  ]
]$patch$::jsonb
        ),
        (
            'authority_binding_sequence_prepare_v3(text,jsonb)',
            '3ab5bed30a3f8e9fdc27503a03d621dcb37e1437e7663d09ca7c07f322499e47',
            'a0290994e32a6eb0a8c753b3be6bff865afcb3a40d4a6f9dafcef0aa1c7beb3c',
            $patch$[
  [
    " frozen:=jsonb_build_object('kind','binding.decision','mode',p_mode,'id',p_input->>'id','created_at',created);\n IF definition_holds->'definitions'<>'[]'::jsonb THEN\n  frozen:=frozen||jsonb_build_object('access_label_definition_holds',definition_holds);\n END IF;\n PERFORM kaname._authority_sequence_freeze_v3(frozen);\n",
    " PERFORM kaname._authority_sequence_freeze_v3(jsonb_build_object('kind','binding.decision','mode',p_mode,'id',p_input->>'id','created_at',created));\n"
  ],
  [
    "  SELECT to_jsonb(r),r.xmin::text,r.ctid::text INTO STRICT role_row,role_xmin,role_ctid\n   FROM kaname.roles r WHERE r.id=parent->>'role_id' FOR SHARE;\n  definition_holds:=kaname.authority_access_label_binding_definitions_prepare_v1(\n   role_row,role_xmin,role_ctid,parent->>'resource_type',parent->>'resource_id',prepaid_rows,prepaid_reads);\n  IF (definition_holds->>'rows')::integer>prepaid_rows\n   OR (definition_holds->>'reads')::integer>prepaid_reads THEN\n   RAISE EXCEPTION 'binding access label work exceeded prepaid cap' USING ERRCODE='54000';END IF;\n",
    "  SELECT to_jsonb(r) INTO STRICT role_row FROM kaname.roles r WHERE r.id=parent->>'role_id' FOR SHARE;\n"
  ],
  [
    " ELSE\n  -- Только create принимает отдельный budget envelope. Он не становится\n  -- полем access_bindings и не ослабляет прежнюю закрытую mutation mask.\n  IF p_input ? '_access_label_prepaid' THEN\n   prepaid:=p_input->'_access_label_prepaid';\n   IF jsonb_typeof(prepaid) IS DISTINCT FROM 'object'\n    OR prepaid-ARRAY['rows','reads']<>'{}'::jsonb\n    OR jsonb_typeof(prepaid->'rows') IS DISTINCT FROM 'number'\n    OR jsonb_typeof(prepaid->'reads') IS DISTINCT FROM 'number' THEN\n    RAISE EXCEPTION 'binding access label budget envelope is not closed' USING ERRCODE='23514';END IF;\n   prepaid_rows:=(prepaid->>'rows')::integer;prepaid_reads:=(prepaid->>'reads')::integer;\n   IF prepaid_rows NOT BETWEEN 0 AND 100000 OR prepaid_reads NOT BETWEEN 0 AND 4096 THEN\n    RAISE EXCEPTION 'binding access label prepaid cap exceeded' USING ERRCODE='54000';END IF;\n   p_input:=p_input-'_access_label_prepaid';\n  END IF;\n",
    " ELSE\n"
  ],
  [
    " ordinal integer:=0;i integer:=0;cost integer;created timestamptz:=transaction_timestamp();scope_value integer;\n role_xmin text;role_ctid text;prepaid jsonb;prepaid_rows integer:=0;prepaid_reads integer:=0;definition_holds jsonb;frozen jsonb;\n",
    " ordinal integer:=0;i integer:=0;cost integer;created timestamptz:=transaction_timestamp();scope_value integer;\n"
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
$access_label_binding_definitions$;
-- +goose StatementEnd

DROP FUNCTION kaname.authority_access_label_binding_definitions_prepare_v1(jsonb,text,text,text,text,integer,integer);
