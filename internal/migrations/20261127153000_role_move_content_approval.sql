-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Источник и выбор единственного слота проверяются на окончательных часах.
-- До публикации слот обязан быть свободен, при COMMIT его потребляет запись роли.
CREATE FUNCTION kaname._authority_role_move_content_receipt_v1() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $receipt$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    program jsonb:=kaname._authority_sequence_store_v3();
    frozen jsonb:=program->'frozen'; source_receipt jsonb:=frozen->'selector_move_pending_sources';
    result_image jsonb; chosen jsonb; discarded jsonb; reserved jsonb:=program#>'{maximum,0}';
    published boolean:=jsonb_typeof(program->'selected')='array';
BEGIN
    IF jsonb_typeof(source_receipt) IS DISTINCT FROM 'object'
        OR program->>'family' IS DISTINCT FROM 'role' OR frozen->>'mode' IS DISTINCT FROM 'selector_move'
        OR program->'nonce' IS DISTINCT FROM proof->'nonce'
        OR program->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid'
        OR program->>'backend' IS DISTINCT FROM pg_backend_pid()::text
        OR program->>'transaction_id' IS DISTINCT FROM pg_current_xact_id()::text
        OR program->>'maximum_count' IS DISTINCT FROM '1' THEN
        RAISE EXCEPTION 'role content requires a sealed pending decision' USING ERRCODE='42501';END IF;
    result_image:=kaname._authority_role_move_pending_sources_v1(NULL,100000,4096);
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
    RETURN jsonb_build_object('contract','RequireRole/v1+v_update+RequireSelectorMoveGrants/v1','operation','role.update',
        'actor',source_receipt->'actor','role_id',source_receipt->'role_id','role_generation',source_receipt->'role_generation',
        'binding_id',source_receipt->'binding_id','decision_at',source_receipt->'decision_at','nonce',proof->'nonce',
        'invoker_oid',proof->'invoker_oid','backend',program->'backend','transaction_id',program->'transaction_id',
        'source_sha256',result_image->'sha256','selected_sha256',encode(sha256(convert_to(chosen::text,'UTF8')),'hex'));
END;
$receipt$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Как у подтверждения apply/revoke, автором вызова служит выделенный процесс
-- Kaname после полного RequireRole, проверки v_update и prospective Grant.
-- Право EXECUTE остаётся у владельца до подключения этих проверок в Go.
CREATE FUNCTION kaname.authority_role_move_content_approved_v1() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $approve_content$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    program jsonb:=kaname._authority_sequence_store_v3(); prior_frozen jsonb:=program->'frozen'; receipt jsonb;
BEGIN
    IF program->'selected' IS DISTINCT FROM 'null'::jsonb OR program->'decision_at' IS DISTINCT FROM 'null'::jsonb
        OR prior_frozen ?| ARRAY['selector_move_content_approval','selector_move_approved_content_sha256','selector_move_approved'] THEN
        RAISE EXCEPTION 'role content approval already recorded or published' USING ERRCODE='42501';END IF;
    receipt:=kaname._authority_role_move_content_receipt_v1();
    IF octet_length(prior_frozen::text)+octet_length(receipt::text)+256>8388608 THEN
        RAISE EXCEPTION 'role content approval exceeds byte budget' USING ERRCODE='54000';END IF;
    UPDATE pg_temp.kaname_authority_sequence_program s
        SET frozen=s.frozen||jsonb_build_object('selector_move_content_approval',receipt)
        WHERE s.singleton AND s.nonce=(proof->>'nonce')::uuid AND s.family='role' AND s.selected IS NULL
          AND s.decision_at IS NULL AND s.frozen=prior_frozen;
    IF NOT FOUND THEN RAISE EXCEPTION 'role content approval program changed' USING ERRCODE='40001';END IF;
END;
$approve_content$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure;grantee record;
BEGIN
    FOREACH fn IN ARRAY ARRAY['kaname._authority_role_move_content_receipt_v1()'::regprocedure,
        'kaname.authority_role_move_content_approved_v1()'::regprocedure] LOOP
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
DO $content_guard$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_role_move_binding_empty_require_v1(jsonb)','7260da43b7c40f9b9021c57de81450fb4a46437cda5928844175229a8cf062d7','73d299f024c0f8015f6a228dfb9306ffe9f2263e2aece6999b723fc8b6ae93f0',$changes$[
  [
    "    IF p_frozen ? 'selector_move_pending_sources' THEN\n        IF p_frozen IS DISTINCT FROM (kaname._authority_sequence_store_v3()->'frozen') THEN\n            RAISE EXCEPTION 'pending member source outside owner program' USING ERRCODE='42501';END IF;\n        PERFORM kaname._authority_role_move_pending_sources_v1(NULL,100000,4096);\n        -- Собранные источники не являются правом актёра. Предикат метода и\n        -- prospective Grant ещё не подтверждены владельцем для этого решения.\n        RAISE EXCEPTION 'pending member sources require owner method and grant authority' USING ERRCODE='42501';\n    END IF;\n",
    "    IF p_frozen ?| ARRAY['selector_move_pending_sources','selector_move_content_approval','selector_move_approved_content_sha256'] THEN\n        IF p_frozen IS DISTINCT FROM (kaname._authority_sequence_store_v3()->'frozen') THEN\n            RAISE EXCEPTION 'pending member source outside owner program' USING ERRCODE='42501';END IF;\n        IF jsonb_typeof(p_frozen->'selector_move_content_approval') IS DISTINCT FROM 'object' THEN\n            PERFORM kaname._authority_role_move_pending_sources_v1(NULL,100000,4096);\n            RAISE EXCEPTION 'pending member sources require owner method and grant authority' USING ERRCODE='42501';END IF;\n        IF p_frozen->'selector_move_content_approval' IS DISTINCT FROM kaname._authority_role_move_content_receipt_v1()\n            OR ((p_frozen ? 'selector_move_approved') IS DISTINCT FROM (p_frozen ? 'selector_move_approved_content_sha256'))\n            OR ((p_frozen ? 'selector_move_approved') AND p_frozen->>'selector_move_approved_content_sha256' IS DISTINCT FROM\n                encode(sha256(convert_to((p_frozen->'selector_move_content_approval')::text,'UTF8')),'hex')) THEN\n            RAISE EXCEPTION 'pending role content approval changed' USING ERRCODE='42501';END IF;\n        RETURN;\n    END IF;\n"
  ]
]$changes$::jsonb),
        ('_authority_role_move_sequence_approve_v1()','bf68e469d6ad37c6eb627640a9b992f2bf233f30cb99092f6e111f6898c4f16e','21661aeae6a43fd14316b73d2b71a8994ef87b7a154c2d55623376df9f7b3d3a',$changes$[
  [
    "jsonb_build_object('selector_move_pending_sources_approved',encode(sha256(convert_to((s.frozen->'selector_move_pending_sources')::text,'UTF8')),'hex'))",
    "jsonb_build_object('selector_move_pending_sources_approved',encode(sha256(convert_to((s.frozen->'selector_move_pending_sources')::text,'UTF8')),'hex'),\n                    'selector_move_approved_content_sha256',encode(sha256(convert_to((s.frozen->'selector_move_content_approval')::text,'UTF8')),'hex'))"
  ]
]$changes$::jsonb),
        ('_authority_role_move_roots_complete_v1()','22da8d1aabc4b9a48b3377d8e7f9462a4eb503dd4d6105875dea1a3a671e471b','cf50ce308de57a7afb3cb6451b268e566d5d84d105da533181835db32967c87c',$changes$[
  [
    "    PERFORM kaname._authority_role_move_binding_empty_require_v1(frozen);",
    "    IF frozen ? 'selector_move_content_approval' AND jsonb_typeof(program->'selected') IS DISTINCT FROM 'array' THEN\n        RAISE EXCEPTION 'pending role content approval was not published' USING ERRCODE='42501';END IF;\n    PERFORM kaname._authority_role_move_binding_empty_require_v1(frozen);"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','012ff77b4f259e4156b26a5e3eafc1ea22f3556bce46d90b5d6284f783a5f8e9','5eb15d5158db9625cde91f603451bd8603f0bc7c95406021fa1c90292eb8a232',$changes$[
  [
    "7260da43b7c40f9b9021c57de81450fb4a46437cda5928844175229a8cf062d7",
    "73d299f024c0f8015f6a228dfb9306ffe9f2263e2aece6999b723fc8b6ae93f0"
  ],
  [
    "bf68e469d6ad37c6eb627640a9b992f2bf233f30cb99092f6e111f6898c4f16e",
    "21661aeae6a43fd14316b73d2b71a8994ef87b7a154c2d55623376df9f7b3d3a"
  ],
  [
    "22da8d1aabc4b9a48b3377d8e7f9462a4eb503dd4d6105875dea1a3a671e471b",
    "cf50ce308de57a7afb3cb6451b268e566d5d84d105da533181835db32967c87c"
  ],
  [
    " ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n",
    " ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n ('_authority_role_move_content_receipt_v1()','7f7cbc8fbe00d908d99f5e7b8f33793f41f0fa201b46d506e5c7e71e4d959120',false,'v',true,'private'),\n ('authority_role_move_content_approved_v1()','d8d5892cbcb116d7540fa3c70c59d9bbaadf16eda1541df4f209b795e2bf28bb',true,'v',true,'private'),\n"
  ],
  [
    "  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n",
    "  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n  ('_authority_role_move_content_receipt_v1()','jsonb',0,NULL::text[]),\n  ('authority_role_move_content_approved_v1()','void',0,NULL::text[]),\n"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','873236f5cb33c0e147fcfaa2534e50d9f0c54296825df3981fa4797850ada0a7','c4a9c31fb668f4cc5b0984f8fdf06765b785b36c88aa40f5ef2b8fd95d95e9c3',$changes$[
  [
    "012ff77b4f259e4156b26a5e3eafc1ea22f3556bce46d90b5d6284f783a5f8e9",
    "5eb15d5158db9625cde91f603451bd8603f0bc7c95406021fa1c90292eb8a232"
  ]
]$changes$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','4c07b6a922eb38ce74e84a05e7750b2a73de1ef7a97f646c0e025f41637d76c9','e10ce9918c92df0877a8469d3a287e7f13d087f1d4a1d0a8f50edab1d597b01e',$changes$[
  [
    "012ff77b4f259e4156b26a5e3eafc1ea22f3556bce46d90b5d6284f783a5f8e9",
    "5eb15d5158db9625cde91f603451bd8603f0bc7c95406021fa1c90292eb8a232"
  ],
  [
    "873236f5cb33c0e147fcfaa2534e50d9f0c54296825df3981fa4797850ada0a7",
    "c4a9c31fb668f4cc5b0984f8fdf06765b785b36c88aa40f5ef2b8fd95d95e9c3"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'selector move content approval predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'selector move content approval replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move content approval body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move content approval installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector move content approval storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$content_guard$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $content_guard$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('authority_metadata_service_account_access_label_ready_v1()','e10ce9918c92df0877a8469d3a287e7f13d087f1d4a1d0a8f50edab1d597b01e','4c07b6a922eb38ce74e84a05e7750b2a73de1ef7a97f646c0e025f41637d76c9',$changes$[
  [
    "c4a9c31fb668f4cc5b0984f8fdf06765b785b36c88aa40f5ef2b8fd95d95e9c3",
    "873236f5cb33c0e147fcfaa2534e50d9f0c54296825df3981fa4797850ada0a7"
  ],
  [
    "5eb15d5158db9625cde91f603451bd8603f0bc7c95406021fa1c90292eb8a232",
    "012ff77b4f259e4156b26a5e3eafc1ea22f3556bce46d90b5d6284f783a5f8e9"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','c4a9c31fb668f4cc5b0984f8fdf06765b785b36c88aa40f5ef2b8fd95d95e9c3','873236f5cb33c0e147fcfaa2534e50d9f0c54296825df3981fa4797850ada0a7',$changes$[
  [
    "5eb15d5158db9625cde91f603451bd8603f0bc7c95406021fa1c90292eb8a232",
    "012ff77b4f259e4156b26a5e3eafc1ea22f3556bce46d90b5d6284f783a5f8e9"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','5eb15d5158db9625cde91f603451bd8603f0bc7c95406021fa1c90292eb8a232','012ff77b4f259e4156b26a5e3eafc1ea22f3556bce46d90b5d6284f783a5f8e9',$changes$[
  [
    "  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n  ('_authority_role_move_content_receipt_v1()','jsonb',0,NULL::text[]),\n  ('authority_role_move_content_approved_v1()','void',0,NULL::text[]),\n",
    "  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n"
  ],
  [
    " ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n ('_authority_role_move_content_receipt_v1()','7f7cbc8fbe00d908d99f5e7b8f33793f41f0fa201b46d506e5c7e71e4d959120',false,'v',true,'private'),\n ('authority_role_move_content_approved_v1()','d8d5892cbcb116d7540fa3c70c59d9bbaadf16eda1541df4f209b795e2bf28bb',true,'v',true,'private'),\n",
    " ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n"
  ],
  [
    "cf50ce308de57a7afb3cb6451b268e566d5d84d105da533181835db32967c87c",
    "22da8d1aabc4b9a48b3377d8e7f9462a4eb503dd4d6105875dea1a3a671e471b"
  ],
  [
    "21661aeae6a43fd14316b73d2b71a8994ef87b7a154c2d55623376df9f7b3d3a",
    "bf68e469d6ad37c6eb627640a9b992f2bf233f30cb99092f6e111f6898c4f16e"
  ],
  [
    "73d299f024c0f8015f6a228dfb9306ffe9f2263e2aece6999b723fc8b6ae93f0",
    "7260da43b7c40f9b9021c57de81450fb4a46437cda5928844175229a8cf062d7"
  ]
]$changes$::jsonb),
        ('_authority_role_move_roots_complete_v1()','cf50ce308de57a7afb3cb6451b268e566d5d84d105da533181835db32967c87c','22da8d1aabc4b9a48b3377d8e7f9462a4eb503dd4d6105875dea1a3a671e471b',$changes$[
  [
    "    IF frozen ? 'selector_move_content_approval' AND jsonb_typeof(program->'selected') IS DISTINCT FROM 'array' THEN\n        RAISE EXCEPTION 'pending role content approval was not published' USING ERRCODE='42501';END IF;\n    PERFORM kaname._authority_role_move_binding_empty_require_v1(frozen);",
    "    PERFORM kaname._authority_role_move_binding_empty_require_v1(frozen);"
  ]
]$changes$::jsonb),
        ('_authority_role_move_sequence_approve_v1()','21661aeae6a43fd14316b73d2b71a8994ef87b7a154c2d55623376df9f7b3d3a','bf68e469d6ad37c6eb627640a9b992f2bf233f30cb99092f6e111f6898c4f16e',$changes$[
  [
    "jsonb_build_object('selector_move_pending_sources_approved',encode(sha256(convert_to((s.frozen->'selector_move_pending_sources')::text,'UTF8')),'hex'),\n                    'selector_move_approved_content_sha256',encode(sha256(convert_to((s.frozen->'selector_move_content_approval')::text,'UTF8')),'hex'))",
    "jsonb_build_object('selector_move_pending_sources_approved',encode(sha256(convert_to((s.frozen->'selector_move_pending_sources')::text,'UTF8')),'hex'))"
  ]
]$changes$::jsonb),
        ('_authority_role_move_binding_empty_require_v1(jsonb)','73d299f024c0f8015f6a228dfb9306ffe9f2263e2aece6999b723fc8b6ae93f0','7260da43b7c40f9b9021c57de81450fb4a46437cda5928844175229a8cf062d7',$changes$[
  [
    "    IF p_frozen ?| ARRAY['selector_move_pending_sources','selector_move_content_approval','selector_move_approved_content_sha256'] THEN\n        IF p_frozen IS DISTINCT FROM (kaname._authority_sequence_store_v3()->'frozen') THEN\n            RAISE EXCEPTION 'pending member source outside owner program' USING ERRCODE='42501';END IF;\n        IF jsonb_typeof(p_frozen->'selector_move_content_approval') IS DISTINCT FROM 'object' THEN\n            PERFORM kaname._authority_role_move_pending_sources_v1(NULL,100000,4096);\n            RAISE EXCEPTION 'pending member sources require owner method and grant authority' USING ERRCODE='42501';END IF;\n        IF p_frozen->'selector_move_content_approval' IS DISTINCT FROM kaname._authority_role_move_content_receipt_v1()\n            OR ((p_frozen ? 'selector_move_approved') IS DISTINCT FROM (p_frozen ? 'selector_move_approved_content_sha256'))\n            OR ((p_frozen ? 'selector_move_approved') AND p_frozen->>'selector_move_approved_content_sha256' IS DISTINCT FROM\n                encode(sha256(convert_to((p_frozen->'selector_move_content_approval')::text,'UTF8')),'hex')) THEN\n            RAISE EXCEPTION 'pending role content approval changed' USING ERRCODE='42501';END IF;\n        RETURN;\n    END IF;\n",
    "    IF p_frozen ? 'selector_move_pending_sources' THEN\n        IF p_frozen IS DISTINCT FROM (kaname._authority_sequence_store_v3()->'frozen') THEN\n            RAISE EXCEPTION 'pending member source outside owner program' USING ERRCODE='42501';END IF;\n        PERFORM kaname._authority_role_move_pending_sources_v1(NULL,100000,4096);\n        -- Собранные источники не являются правом актёра. Предикат метода и\n        -- prospective Grant ещё не подтверждены владельцем для этого решения.\n        RAISE EXCEPTION 'pending member sources require owner method and grant authority' USING ERRCODE='42501';\n    END IF;\n"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'selector move content approval predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'selector move content approval replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move content approval body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move content approval installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector move content approval storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$content_guard$;
-- +goose StatementEnd

DROP FUNCTION kaname.authority_role_move_content_approved_v1();
DROP FUNCTION kaname._authority_role_move_content_receipt_v1();
