-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Получает остаток для переписи 15:20 и возвращает квитанцию отдельно от расхода.
CREATE FUNCTION kaname._authority_role_move_content_replay_cost_v1(p_source_rows integer,p_source_reads integer) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $replay_cost$
DECLARE
    proof jsonb;program jsonb;frozen jsonb;source_receipt jsonb;
    result_image jsonb; chosen jsonb; discarded jsonb; reserved jsonb;
    published boolean;replay_rows integer;replay_reads integer;fixed_work integer;
BEGIN
    IF p_source_rows IS NULL OR p_source_rows NOT BETWEEN 1 AND 100000
        OR p_source_reads IS NULL OR p_source_reads NOT BETWEEN 1 AND 4096 THEN
        RAISE EXCEPTION 'role content replay allowance missing' USING ERRCODE='54000';END IF;
    proof:=kaname._authority_role_move_attestation_v1();program:=kaname._authority_sequence_store_v3();
    frozen:=program->'frozen';source_receipt:=frozen->'selector_move_pending_sources';reserved:=program#>'{maximum,0}';
    published:=jsonb_typeof(program->'selected')='array';
    -- Два чтения служебного состояния. До публикации проверяется ещё строка журнала.
    fixed_work:=CASE WHEN published THEN 2 ELSE 3 END;
    IF jsonb_typeof(source_receipt) IS DISTINCT FROM 'object'
        OR program->>'family' IS DISTINCT FROM 'role' OR frozen->>'mode' IS DISTINCT FROM 'selector_move'
        OR program->'nonce' IS DISTINCT FROM proof->'nonce'
        OR program->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid'
        OR program->>'backend' IS DISTINCT FROM pg_backend_pid()::text
        OR program->>'transaction_id' IS DISTINCT FROM pg_current_xact_id()::text
        OR program->>'maximum_count' IS DISTINCT FROM '1' THEN
        RAISE EXCEPTION 'role content requires a sealed pending decision' USING ERRCODE='42501';END IF;
    result_image:=kaname._authority_role_move_pending_sources_v1(NULL,p_source_rows,p_source_reads);
    replay_rows:=(result_image->>'rows')::integer;replay_reads:=(result_image->>'reads')::integer;
    IF replay_rows IS NULL OR replay_rows NOT BETWEEN 1 AND p_source_rows
        OR replay_reads IS NULL OR replay_reads NOT BETWEEN 1 AND p_source_reads THEN
        RAISE EXCEPTION 'role content replay cost unconfirmed' USING ERRCODE='54000';END IF;
    IF published THEN
        chosen:=program->'selected';discarded:=program->'unselected';
    ELSE
        chosen:=frozen#>'{selector_move_pending,selected}';discarded:=frozen#>'{selector_move_pending,unselected}';
        IF program->'decision_at' IS DISTINCT FROM 'null'::jsonb
            OR frozen ?| ARRAY['selector_move_active','selector_move_written','selector_move_roots_completed']
            OR NOT EXISTS(SELECT FROM ONLY pg_temp.kaname_authority_sequence_effects e
                WHERE e.nonce=(proof->>'nonce')::uuid AND e.ordinal=1 AND e.table_name='resource_journal'
                AND e.reserved_id=(reserved->>'reserved_id')::bigint AND e.origin=reserved->'origin'
                AND e.row_value=reserved->'row' AND NOT (e.selected OR e.registered OR e.claimed OR e.consumed)) THEN
            RAISE EXCEPTION 'role content requires untouched reserved journal' USING ERRCODE='42501';END IF;
    END IF;
    IF jsonb_array_length(chosen) IS DISTINCT FROM 1 OR discarded IS DISTINCT FROM '[]'::jsonb
        OR chosen#>'{0,origin}' IS DISTINCT FROM reserved->'origin'
        OR chosen#>'{0,table}' IS DISTINCT FROM reserved->'table' OR chosen#>>'{0,ordinal}' IS DISTINCT FROM '1'
        OR chosen#>'{0,reserved_id}' IS DISTINCT FROM reserved->'reserved_id'
        OR coalesce(result_image->>'sha256','') !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'role content requires exact selected role journal' USING ERRCODE='42501';END IF;
    RETURN jsonb_build_object('rows',fixed_work+replay_rows,'reads',fixed_work+replay_reads,'receipt',jsonb_build_object('contract','RequireRole/v1+v_update+RequireSelectorMoveGrants/v1','operation','role.update',
        'actor',source_receipt->'actor','role_id',source_receipt->'role_id','role_generation',source_receipt->'role_generation',
        'binding_id',source_receipt->'binding_id','decision_at',source_receipt->'decision_at','nonce',proof->'nonce',
        'invoker_oid',proof->'invoker_oid','backend',program->'backend','transaction_id',program->'transaction_id',
        'source_sha256',result_image->'sha256','selected_sha256',encode(sha256(convert_to(chosen::text,'UTF8')),'hex')));
END;
$replay_cost$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Записывает только квитанцию. Расход зависит от фазы и не входит в её хеш.
CREATE FUNCTION kaname._authority_role_move_content_record_cost_v1(p_source_rows integer,p_source_reads integer) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $record_cost$
DECLARE
    proof jsonb;program jsonb;prior_frozen jsonb;receipt jsonb;measured jsonb;receipt_rows integer;receipt_reads integer;
BEGIN
    IF p_source_rows IS NULL OR p_source_rows NOT BETWEEN 1 AND 100000
        OR p_source_reads IS NULL OR p_source_reads NOT BETWEEN 1 AND 4096 THEN
        RAISE EXCEPTION 'role content record allowance missing' USING ERRCODE='54000';END IF;
    proof:=kaname._authority_role_move_attestation_v1();program:=kaname._authority_sequence_store_v3();prior_frozen:=program->'frozen';
    IF program->'selected' IS DISTINCT FROM 'null'::jsonb OR program->'decision_at' IS DISTINCT FROM 'null'::jsonb
        OR prior_frozen ?| ARRAY['selector_move_content_approval','selector_move_approved_content_sha256','selector_move_approved'] THEN
        RAISE EXCEPTION 'role content approval already recorded or published' USING ERRCODE='42501';END IF;
    measured:=kaname._authority_role_move_content_replay_cost_v1(p_source_rows,p_source_reads);
    receipt:=measured->'receipt';receipt_rows:=(measured->>'rows')::integer;receipt_reads:=(measured->>'reads')::integer;
    -- В открытой программе replay оплачивает аттестацию, программу и свободный слот.
    -- Следующее изменение требует подтверждённой цены всех предшествующих чтений.
    IF jsonb_typeof(receipt) IS DISTINCT FROM 'object' OR receipt_rows IS NULL OR receipt_reads IS NULL
        OR receipt_rows NOT BETWEEN 4 AND p_source_rows+3 OR receipt_reads NOT BETWEEN 4 AND p_source_reads+3 THEN
        RAISE EXCEPTION 'role content record cost unconfirmed' USING ERRCODE='54000';END IF;
    IF octet_length(prior_frozen::text)+octet_length(receipt::text)+256>8388608 THEN
        RAISE EXCEPTION 'role content approval exceeds byte budget' USING ERRCODE='54000';END IF;
    UPDATE pg_temp.kaname_authority_sequence_program s
        SET frozen=s.frozen||jsonb_build_object('selector_move_content_approval',receipt)
        WHERE s.singleton AND s.nonce=(proof->>'nonce')::uuid AND s.family='role' AND s.selected IS NULL
          AND s.decision_at IS NULL AND s.frozen=prior_frozen;
    IF NOT FOUND THEN RAISE EXCEPTION 'role content approval program changed' USING ERRCODE='40001';END IF;
    -- Два чтения writer и одна адресная запись программы.
    RETURN jsonb_build_object('rows',3+receipt_rows,'reads',3+receipt_reads,
        'content_sha256',encode(sha256(convert_to(receipt::text,'UTF8')),'hex'));
END;
$record_cost$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Вход для будущего owner-финализатора с единым бюджетом до первой DML.
CREATE FUNCTION kaname._authority_role_move_content_approve_budget_v1(p_rows integer,p_reads integer) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $approve_budget$
BEGIN
    -- Весь остаток принадлежит вызывающему owner. Шесть строк и шесть чтений
    -- обслуживают запись подтверждения и проверку единственного свободного слота.
    IF p_rows IS NULL OR p_rows NOT BETWEEN 7 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 7 AND 4096 THEN
        RAISE EXCEPTION 'role content approval budget exhausted' USING ERRCODE='54000';END IF;
    RETURN kaname._authority_role_move_content_record_cost_v1(p_rows-6,p_reads-6);
END;
$approve_budget$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure;grantee record;
BEGIN
    FOREACH fn IN ARRAY ARRAY['kaname._authority_role_move_content_replay_cost_v1(integer,integer)'::regprocedure,
        'kaname._authority_role_move_content_record_cost_v1(integer,integer)'::regprocedure,
        'kaname._authority_role_move_content_approve_budget_v1(integer,integer)'::regprocedure] LOOP
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
DO $cost_guard$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_role_move_content_receipt_v1()','7f7cbc8fbe00d908d99f5e7b8f33793f41f0fa201b46d506e5c7e71e4d959120','3d726ef33b327bb1b234eddd598edc5f554a998e4111964e9bdcfff9f96bdddf',$changes$[
  [
    "\nDECLARE\n    proof jsonb:=kaname._authority_role_move_attestation_v1();\n    program jsonb:=kaname._authority_sequence_store_v3();\n    frozen jsonb:=program->'frozen'; source_receipt jsonb:=frozen->'selector_move_pending_sources';\n    result_image jsonb; chosen jsonb; discarded jsonb; reserved jsonb:=program#>'{maximum,0}';\n    published boolean:=jsonb_typeof(program->'selected')='array';\nBEGIN\n    IF jsonb_typeof(source_receipt) IS DISTINCT FROM 'object'\n        OR program->>'family' IS DISTINCT FROM 'role' OR frozen->>'mode' IS DISTINCT FROM 'selector_move'\n        OR program->'nonce' IS DISTINCT FROM proof->'nonce'\n        OR program->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid'\n        OR program->>'backend' IS DISTINCT FROM pg_backend_pid()::text\n        OR program->>'transaction_id' IS DISTINCT FROM pg_current_xact_id()::text\n        OR program->>'maximum_count' IS DISTINCT FROM '1' THEN\n        RAISE EXCEPTION 'role content requires a sealed pending decision' USING ERRCODE='42501';END IF;\n    result_image:=kaname._authority_role_move_pending_sources_v1(NULL,100000,4096);\n    IF published THEN\n        chosen:=program->'selected';discarded:=program->'unselected';\n    ELSE\n        chosen:=frozen#>'{selector_move_pending,selected}';discarded:=frozen#>'{selector_move_pending,unselected}';\n        IF program->'decision_at' IS DISTINCT FROM 'null'::jsonb\n            OR frozen ?| ARRAY['selector_move_active','selector_move_written','selector_move_roots_completed']\n            OR NOT EXISTS(SELECT FROM ONLY pg_temp.kaname_authority_sequence_effects e\n                WHERE e.nonce=(proof->>'nonce')::uuid AND e.ordinal=1 AND e.table_name='resource_journal'\n                AND e.reserved_id=(reserved->>'reserved_id')::bigint AND e.origin=reserved->'origin'\n                AND e.row_value=reserved->'row' AND NOT (e.selected OR e.registered OR e.claimed OR e.consumed)) THEN\n            RAISE EXCEPTION 'role content requires untouched reserved journal' USING ERRCODE='42501';END IF;\n    END IF;\n    IF jsonb_array_length(chosen) IS DISTINCT FROM 1 OR discarded IS DISTINCT FROM '[]'::jsonb\n        OR chosen#>'{0,origin}' IS DISTINCT FROM reserved->'origin'\n        OR chosen#>'{0,table}' IS DISTINCT FROM reserved->'table' OR chosen#>>'{0,ordinal}' IS DISTINCT FROM '1'\n        OR chosen#>'{0,reserved_id}' IS DISTINCT FROM reserved->'reserved_id'\n        OR coalesce(result_image->>'sha256','') !~ '^[0-9a-f]{64}$' THEN\n        RAISE EXCEPTION 'role content requires exact selected role journal' USING ERRCODE='42501';END IF;\n    RETURN jsonb_build_object('contract','RequireRole/v1+v_update+RequireSelectorMoveGrants/v1','operation','role.update',\n        'actor',source_receipt->'actor','role_id',source_receipt->'role_id','role_generation',source_receipt->'role_generation',\n        'binding_id',source_receipt->'binding_id','decision_at',source_receipt->'decision_at','nonce',proof->'nonce',\n        'invoker_oid',proof->'invoker_oid','backend',program->'backend','transaction_id',program->'transaction_id',\n        'source_sha256',result_image->'sha256','selected_sha256',encode(sha256(convert_to(chosen::text,'UTF8')),'hex'));\nEND;\n",
    "\nBEGIN\n    RETURN kaname._authority_role_move_content_replay_cost_v1(100000,4096)->'receipt';\nEND;\n"
  ]
]$changes$::jsonb),
        ('authority_role_move_content_approved_v1()','d8d5892cbcb116d7540fa3c70c59d9bbaadf16eda1541df4f209b795e2bf28bb','05385db704de7ce4a669727381d923acf2cad2729c35455fd1fe54335aa79114',$changes$[
  [
    "\nDECLARE\n    proof jsonb:=kaname._authority_role_move_attestation_v1();\n    program jsonb:=kaname._authority_sequence_store_v3(); prior_frozen jsonb:=program->'frozen'; receipt jsonb;\nBEGIN\n    IF program->'selected' IS DISTINCT FROM 'null'::jsonb OR program->'decision_at' IS DISTINCT FROM 'null'::jsonb\n        OR prior_frozen ?| ARRAY['selector_move_content_approval','selector_move_approved_content_sha256','selector_move_approved'] THEN\n        RAISE EXCEPTION 'role content approval already recorded or published' USING ERRCODE='42501';END IF;\n    receipt:=kaname._authority_role_move_content_receipt_v1();\n    IF octet_length(prior_frozen::text)+octet_length(receipt::text)+256>8388608 THEN\n        RAISE EXCEPTION 'role content approval exceeds byte budget' USING ERRCODE='54000';END IF;\n    UPDATE pg_temp.kaname_authority_sequence_program s\n        SET frozen=s.frozen||jsonb_build_object('selector_move_content_approval',receipt)\n        WHERE s.singleton AND s.nonce=(proof->>'nonce')::uuid AND s.family='role' AND s.selected IS NULL\n          AND s.decision_at IS NULL AND s.frozen=prior_frozen;\n    IF NOT FOUND THEN RAISE EXCEPTION 'role content approval program changed' USING ERRCODE='40001';END IF;\nEND;\n",
    "\nBEGIN\n    PERFORM kaname._authority_role_move_content_record_cost_v1(100000,4096);\nEND;\n"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','e3f6f6eb43363509486c6a7549c93c2d2c5cb2eb0a2ca2e877f7e0a7e42e5342','71028e5d9d6344c2275929d53d7a990c13c676b721dc546b5f31c57e2d41b58a',$changes$[
  [
    "7f7cbc8fbe00d908d99f5e7b8f33793f41f0fa201b46d506e5c7e71e4d959120",
    "3d726ef33b327bb1b234eddd598edc5f554a998e4111964e9bdcfff9f96bdddf"
  ],
  [
    "d8d5892cbcb116d7540fa3c70c59d9bbaadf16eda1541df4f209b795e2bf28bb",
    "05385db704de7ce4a669727381d923acf2cad2729c35455fd1fe54335aa79114"
  ],
  [
    " ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n",
    " ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n ('_authority_role_move_content_replay_cost_v1(integer,integer)','1d0fe75ae5acedcb86ba5493f2cb0457acf64f0295c7772ff289b6f59b46df12',false,'v',true,'private'),\n ('_authority_role_move_content_record_cost_v1(integer,integer)','9dc6cd67f823cae9f15a812943a8e58e626e13b0744789a2464f8f0a184736b5',false,'v',true,'private'),\n ('_authority_role_move_content_approve_budget_v1(integer,integer)','28f486152f2e94097d60830f35f37f1e0d4974143bedac665005bea94706c5b4',false,'v',true,'private'),\n"
  ],
  [
    "  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n",
    "  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n  ('_authority_role_move_content_replay_cost_v1(integer,integer)','jsonb',2,ARRAY['p_source_rows','p_source_reads']),\n  ('_authority_role_move_content_record_cost_v1(integer,integer)','jsonb',2,ARRAY['p_source_rows','p_source_reads']),\n  ('_authority_role_move_content_approve_budget_v1(integer,integer)','jsonb',2,ARRAY['p_rows','p_reads']),\n"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','c066d23477d174f67d7e773fa3d8555a98ed5126415878bf5852830672d5d3dd','6e1088992add4c8176799d902a4cb1299eff8c8354561d9cb486f21b0fafddf3',$changes$[
  [
    "e3f6f6eb43363509486c6a7549c93c2d2c5cb2eb0a2ca2e877f7e0a7e42e5342",
    "71028e5d9d6344c2275929d53d7a990c13c676b721dc546b5f31c57e2d41b58a"
  ]
]$changes$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','4d1b40444db98ce2a16c0874ca5bebc4ab3ed78a9ee092ebfc600d61966dbcee','8c5e43c65d160987b078a5933dd2e394d62c85826dd45b2bb857f54ccdc17315',$changes$[
  [
    "e3f6f6eb43363509486c6a7549c93c2d2c5cb2eb0a2ca2e877f7e0a7e42e5342",
    "71028e5d9d6344c2275929d53d7a990c13c676b721dc546b5f31c57e2d41b58a"
  ],
  [
    "c066d23477d174f67d7e773fa3d8555a98ed5126415878bf5852830672d5d3dd",
    "6e1088992add4c8176799d902a4cb1299eff8c8354561d9cb486f21b0fafddf3"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'selector move content budget predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'selector move content budget replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move content budget body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move content budget installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector move content budget storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$cost_guard$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $cost_guard$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('authority_metadata_service_account_access_label_ready_v1()','8c5e43c65d160987b078a5933dd2e394d62c85826dd45b2bb857f54ccdc17315','4d1b40444db98ce2a16c0874ca5bebc4ab3ed78a9ee092ebfc600d61966dbcee',$changes$[
  [
    "6e1088992add4c8176799d902a4cb1299eff8c8354561d9cb486f21b0fafddf3",
    "c066d23477d174f67d7e773fa3d8555a98ed5126415878bf5852830672d5d3dd"
  ],
  [
    "71028e5d9d6344c2275929d53d7a990c13c676b721dc546b5f31c57e2d41b58a",
    "e3f6f6eb43363509486c6a7549c93c2d2c5cb2eb0a2ca2e877f7e0a7e42e5342"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','6e1088992add4c8176799d902a4cb1299eff8c8354561d9cb486f21b0fafddf3','c066d23477d174f67d7e773fa3d8555a98ed5126415878bf5852830672d5d3dd',$changes$[
  [
    "71028e5d9d6344c2275929d53d7a990c13c676b721dc546b5f31c57e2d41b58a",
    "e3f6f6eb43363509486c6a7549c93c2d2c5cb2eb0a2ca2e877f7e0a7e42e5342"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','71028e5d9d6344c2275929d53d7a990c13c676b721dc546b5f31c57e2d41b58a','e3f6f6eb43363509486c6a7549c93c2d2c5cb2eb0a2ca2e877f7e0a7e42e5342',$changes$[
  [
    "  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n  ('_authority_role_move_content_replay_cost_v1(integer,integer)','jsonb',2,ARRAY['p_source_rows','p_source_reads']),\n  ('_authority_role_move_content_record_cost_v1(integer,integer)','jsonb',2,ARRAY['p_source_rows','p_source_reads']),\n  ('_authority_role_move_content_approve_budget_v1(integer,integer)','jsonb',2,ARRAY['p_rows','p_reads']),\n",
    "  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n"
  ],
  [
    " ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n ('_authority_role_move_content_replay_cost_v1(integer,integer)','1d0fe75ae5acedcb86ba5493f2cb0457acf64f0295c7772ff289b6f59b46df12',false,'v',true,'private'),\n ('_authority_role_move_content_record_cost_v1(integer,integer)','9dc6cd67f823cae9f15a812943a8e58e626e13b0744789a2464f8f0a184736b5',false,'v',true,'private'),\n ('_authority_role_move_content_approve_budget_v1(integer,integer)','28f486152f2e94097d60830f35f37f1e0d4974143bedac665005bea94706c5b4',false,'v',true,'private'),\n",
    " ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n"
  ],
  [
    "05385db704de7ce4a669727381d923acf2cad2729c35455fd1fe54335aa79114",
    "d8d5892cbcb116d7540fa3c70c59d9bbaadf16eda1541df4f209b795e2bf28bb"
  ],
  [
    "3d726ef33b327bb1b234eddd598edc5f554a998e4111964e9bdcfff9f96bdddf",
    "7f7cbc8fbe00d908d99f5e7b8f33793f41f0fa201b46d506e5c7e71e4d959120"
  ]
]$changes$::jsonb),
        ('authority_role_move_content_approved_v1()','05385db704de7ce4a669727381d923acf2cad2729c35455fd1fe54335aa79114','d8d5892cbcb116d7540fa3c70c59d9bbaadf16eda1541df4f209b795e2bf28bb',$changes$[
  [
    "\nBEGIN\n    PERFORM kaname._authority_role_move_content_record_cost_v1(100000,4096);\nEND;\n",
    "\nDECLARE\n    proof jsonb:=kaname._authority_role_move_attestation_v1();\n    program jsonb:=kaname._authority_sequence_store_v3(); prior_frozen jsonb:=program->'frozen'; receipt jsonb;\nBEGIN\n    IF program->'selected' IS DISTINCT FROM 'null'::jsonb OR program->'decision_at' IS DISTINCT FROM 'null'::jsonb\n        OR prior_frozen ?| ARRAY['selector_move_content_approval','selector_move_approved_content_sha256','selector_move_approved'] THEN\n        RAISE EXCEPTION 'role content approval already recorded or published' USING ERRCODE='42501';END IF;\n    receipt:=kaname._authority_role_move_content_receipt_v1();\n    IF octet_length(prior_frozen::text)+octet_length(receipt::text)+256>8388608 THEN\n        RAISE EXCEPTION 'role content approval exceeds byte budget' USING ERRCODE='54000';END IF;\n    UPDATE pg_temp.kaname_authority_sequence_program s\n        SET frozen=s.frozen||jsonb_build_object('selector_move_content_approval',receipt)\n        WHERE s.singleton AND s.nonce=(proof->>'nonce')::uuid AND s.family='role' AND s.selected IS NULL\n          AND s.decision_at IS NULL AND s.frozen=prior_frozen;\n    IF NOT FOUND THEN RAISE EXCEPTION 'role content approval program changed' USING ERRCODE='40001';END IF;\nEND;\n"
  ]
]$changes$::jsonb),
        ('_authority_role_move_content_receipt_v1()','3d726ef33b327bb1b234eddd598edc5f554a998e4111964e9bdcfff9f96bdddf','7f7cbc8fbe00d908d99f5e7b8f33793f41f0fa201b46d506e5c7e71e4d959120',$changes$[
  [
    "\nBEGIN\n    RETURN kaname._authority_role_move_content_replay_cost_v1(100000,4096)->'receipt';\nEND;\n",
    "\nDECLARE\n    proof jsonb:=kaname._authority_role_move_attestation_v1();\n    program jsonb:=kaname._authority_sequence_store_v3();\n    frozen jsonb:=program->'frozen'; source_receipt jsonb:=frozen->'selector_move_pending_sources';\n    result_image jsonb; chosen jsonb; discarded jsonb; reserved jsonb:=program#>'{maximum,0}';\n    published boolean:=jsonb_typeof(program->'selected')='array';\nBEGIN\n    IF jsonb_typeof(source_receipt) IS DISTINCT FROM 'object'\n        OR program->>'family' IS DISTINCT FROM 'role' OR frozen->>'mode' IS DISTINCT FROM 'selector_move'\n        OR program->'nonce' IS DISTINCT FROM proof->'nonce'\n        OR program->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid'\n        OR program->>'backend' IS DISTINCT FROM pg_backend_pid()::text\n        OR program->>'transaction_id' IS DISTINCT FROM pg_current_xact_id()::text\n        OR program->>'maximum_count' IS DISTINCT FROM '1' THEN\n        RAISE EXCEPTION 'role content requires a sealed pending decision' USING ERRCODE='42501';END IF;\n    result_image:=kaname._authority_role_move_pending_sources_v1(NULL,100000,4096);\n    IF published THEN\n        chosen:=program->'selected';discarded:=program->'unselected';\n    ELSE\n        chosen:=frozen#>'{selector_move_pending,selected}';discarded:=frozen#>'{selector_move_pending,unselected}';\n        IF program->'decision_at' IS DISTINCT FROM 'null'::jsonb\n            OR frozen ?| ARRAY['selector_move_active','selector_move_written','selector_move_roots_completed']\n            OR NOT EXISTS(SELECT FROM ONLY pg_temp.kaname_authority_sequence_effects e\n                WHERE e.nonce=(proof->>'nonce')::uuid AND e.ordinal=1 AND e.table_name='resource_journal'\n                AND e.reserved_id=(reserved->>'reserved_id')::bigint AND e.origin=reserved->'origin'\n                AND e.row_value=reserved->'row' AND NOT (e.selected OR e.registered OR e.claimed OR e.consumed)) THEN\n            RAISE EXCEPTION 'role content requires untouched reserved journal' USING ERRCODE='42501';END IF;\n    END IF;\n    IF jsonb_array_length(chosen) IS DISTINCT FROM 1 OR discarded IS DISTINCT FROM '[]'::jsonb\n        OR chosen#>'{0,origin}' IS DISTINCT FROM reserved->'origin'\n        OR chosen#>'{0,table}' IS DISTINCT FROM reserved->'table' OR chosen#>>'{0,ordinal}' IS DISTINCT FROM '1'\n        OR chosen#>'{0,reserved_id}' IS DISTINCT FROM reserved->'reserved_id'\n        OR coalesce(result_image->>'sha256','') !~ '^[0-9a-f]{64}$' THEN\n        RAISE EXCEPTION 'role content requires exact selected role journal' USING ERRCODE='42501';END IF;\n    RETURN jsonb_build_object('contract','RequireRole/v1+v_update+RequireSelectorMoveGrants/v1','operation','role.update',\n        'actor',source_receipt->'actor','role_id',source_receipt->'role_id','role_generation',source_receipt->'role_generation',\n        'binding_id',source_receipt->'binding_id','decision_at',source_receipt->'decision_at','nonce',proof->'nonce',\n        'invoker_oid',proof->'invoker_oid','backend',program->'backend','transaction_id',program->'transaction_id',\n        'source_sha256',result_image->'sha256','selected_sha256',encode(sha256(convert_to(chosen::text,'UTF8')),'hex'));\nEND;\n"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'selector move content budget predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'selector move content budget replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move content budget body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move content budget installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector move content budget storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$cost_guard$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_role_move_content_approve_budget_v1(integer,integer);
DROP FUNCTION kaname._authority_role_move_content_record_cost_v1(integer,integer);
DROP FUNCTION kaname._authority_role_move_content_replay_cost_v1(integer,integer);
