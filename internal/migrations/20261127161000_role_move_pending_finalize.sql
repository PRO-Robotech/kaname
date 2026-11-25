-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Доверенный writer вызывает этот вход после своих проверок метода и Grant.
-- Все четыре owner-фазы выполняются одним SQL-вызовом. Ошибка откатывает
-- также предшествующие изменения временной программы этого backend.
CREATE FUNCTION kaname.authority_role_move_pending_finalize_v1(p_sets jsonb,p_rows integer,p_reads integer) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $finish$
DECLARE
    -- Аттестация и чтение программы до начала, readback после выбора.
    -- Native finalize отдельно читает программу и proof до вызова своего
    -- publisher: его move_cost учитывает только работу самого publisher.
    fixed_work constant integer:=5;
    proof jsonb;program jsonb;held jsonb;prepared jsonb;source_receipt jsonb;content_receipt jsonb;credit jsonb;
    binding_key text;source_hash text;content_hash text;step jsonb;
    rows_left integer;reads_left integer;step_rows integer;step_reads integer;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN fixed_work+1 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN fixed_work+1 AND 4096
        OR octet_length(p_sets::text)>65536 THEN RAISE EXCEPTION 'pending role finish exceeds budget' USING ERRCODE='54000';END IF;
    proof:=kaname._authority_role_move_attestation_v1();program:=kaname._authority_sequence_store_v3();
    held:=program->'frozen';prepared:=held->'selector_move';binding_key:=prepared#>>'{binding_census,bindings,0,2,id}';
    IF program->>'family' IS DISTINCT FROM 'role' OR held->>'kind' IS DISTINCT FROM 'role.mutation'
        OR held->>'mode' IS DISTINCT FROM 'selector_move' OR held->>'selector_move_transport' IS DISTINCT FROM 'pending_no_copy_v1'
        OR program->'nonce' IS DISTINCT FROM proof->'nonce' OR prepared->'nonce' IS DISTINCT FROM proof->'nonce'
        OR prepared->'invoker_oid' IS DISTINCT FROM proof->'invoker_oid' OR program->>'backend' IS DISTINCT FROM pg_backend_pid()::text
        OR program->>'transaction_id' IS DISTINCT FROM pg_current_xact_id()::text OR prepared->>'role_id' IS DISTINCT FROM held->>'id'
        OR ((proof->>'decision_at')::timestamptz>(prepared->>'prepared_at')::timestamptz) IS DISTINCT FROM true
        OR program->'selected' IS DISTINCT FROM 'null'::jsonb OR program->'decision_at' IS DISTINCT FROM 'null'::jsonb
        OR program->>'maximum_count' IS DISTINCT FROM '1' OR prepared#>'{copies,roots}' IS DISTINCT FROM '{}'::jsonb
        OR held ?| ARRAY['selector_move_decision','selector_move_pending','selector_move_pending_sources','selector_move_content_approval',
            'selector_move_approved','selector_move_pending_sources_approved','selector_move_approved_content_sha256','selector_move_publication_budget']
        OR coalesce(binding_key,'')='' OR jsonb_typeof(p_sets) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'pending role finish requires fresh transport and final clock' USING ERRCODE='42501';END IF;
    IF p_sets-binding_key IS DISTINCT FROM '{}'::jsonb OR jsonb_typeof(p_sets->binding_key) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'pending role finish coordinate binding differs' USING ERRCODE='42501';END IF;
    IF jsonb_array_length(p_sets->binding_key) IS DISTINCT FROM 2 THEN
        RAISE EXCEPTION 'pending role finish coordinate pair missing' USING ERRCODE='42501';END IF;
    rows_left:=p_rows-fixed_work;reads_left:=p_reads-fixed_work;
    FOR stage_number IN 1..4 LOOP
        CASE stage_number
            WHEN 1 THEN step:=kaname._authority_role_move_sequence_finalize_v1('[]'::jsonb,rows_left,reads_left);
            WHEN 2 THEN step:=kaname._authority_role_move_pending_sources_v1(p_sets,rows_left,reads_left);
            WHEN 3 THEN step:=kaname._authority_role_move_content_approve_budget_v1(rows_left,reads_left);
            WHEN 4 THEN step:=kaname._authority_role_move_sequence_approve_budget_v1(rows_left,reads_left);
        END CASE;
        IF jsonb_typeof(step->'rows') IS DISTINCT FROM 'number' OR jsonb_typeof(step->'reads') IS DISTINCT FROM 'number'
            OR coalesce(step->>'rows','') !~ '^[0-9]{1,6}$' OR coalesce(step->>'reads','') !~ '^[0-9]{1,4}$' THEN
            RAISE EXCEPTION 'pending role finish cost missing at phase %',stage_number USING ERRCODE='54000';END IF;
        step_rows:=(step->>'rows')::integer;step_reads:=(step->>'reads')::integer;
        IF step_rows NOT BETWEEN 1 AND rows_left OR step_reads NOT BETWEEN 1 AND reads_left THEN
            RAISE EXCEPTION 'pending role finish cost exceeded at phase %',stage_number USING ERRCODE='54000';END IF;
        rows_left:=rows_left-step_rows;reads_left:=reads_left-step_reads;
        IF stage_number=2 THEN
            source_hash:=step->>'sha256';
            IF coalesce(source_hash,'') !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'pending role source hash missing' USING ERRCODE='42501';END IF;
        ELSIF stage_number=3 THEN
            content_hash:=step->>'content_sha256';
            IF coalesce(content_hash,'') !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'pending role content hash missing' USING ERRCODE='42501';END IF;
        END IF;
    END LOOP;
    program:=kaname._authority_sequence_store_v3();held:=program->'frozen';
    source_receipt:=held->'selector_move_pending_sources';content_receipt:=held->'selector_move_content_approval';credit:=held->'selector_move_publication_budget';
    IF jsonb_typeof(program->'selected') IS DISTINCT FROM 'array' OR program->>'selected_count' IS DISTINCT FROM '1'
        OR program->'nonce' IS DISTINCT FROM proof->'nonce' OR program->'decision_at' IS DISTINCT FROM proof->'decision_at'
        OR held->>'selector_move_transport' IS DISTINCT FROM 'pending_no_copy_v1' OR held ? 'selector_move_pending'
        OR held#>'{selector_move_approved,nonce}' IS DISTINCT FROM proof->'nonce' OR held#>'{selector_move_approved,actor}' IS DISTINCT FROM prepared->'actor'
        OR held#>'{selector_move_approved,role_id}' IS DISTINCT FROM prepared->'role_id' OR held#>'{selector_move_approved,decision_at}' IS DISTINCT FROM proof->'decision_at'
        OR source_receipt->'sets' IS DISTINCT FROM p_sets OR source_receipt->>'binding_id' IS DISTINCT FROM binding_key
        OR source_receipt->'actor' IS DISTINCT FROM prepared->'actor' OR source_receipt->'nonce' IS DISTINCT FROM proof->'nonce'
        OR source_receipt->'decision_at' IS DISTINCT FROM proof->'decision_at' OR source_receipt->'invoker_oid' IS DISTINCT FROM proof->'invoker_oid'
        OR source_receipt->'backend' IS DISTINCT FROM program->'backend' OR source_receipt->>'xid' IS DISTINCT FROM program->>'transaction_id'
        OR source_receipt->'role_generation' IS DISTINCT FROM jsonb_build_array(prepared#>'{role,physical,0}',prepared#>'{role,physical,1}')
        OR content_receipt->'role_generation' IS DISTINCT FROM source_receipt->'role_generation'
        OR content_receipt->>'source_sha256' IS DISTINCT FROM source_hash OR held->>'selector_move_pending_sources_approved' IS DISTINCT FROM source_hash
        OR held->>'selector_move_approved_content_sha256' IS DISTINCT FROM content_hash OR credit->>'content_sha256' IS DISTINCT FROM content_hash
        OR credit->'nonce' IS DISTINCT FROM proof->'nonce' OR credit->>'phase' IS DISTINCT FROM 'deferred'
        OR credit->'rows' IS DISTINCT FROM to_jsonb(rows_left) OR credit->'reads' IS DISTINCT FROM to_jsonb(reads_left)
        OR step->'deferred_rows' IS DISTINCT FROM credit->'rows' OR step->'deferred_reads' IS DISTINCT FROM credit->'reads' THEN
        RAISE EXCEPTION 'pending role finish readback differs' USING ERRCODE='40001';END IF;
    RETURN jsonb_build_object('selector_move_transport','pending_no_copy_v1','phase','selected','rows',p_rows-rows_left,'reads',p_reads-reads_left,
        'deferred_rows',rows_left,'deferred_reads',reads_left,'source_sha256',source_hash,'content_sha256',content_hash);
END;
$finish$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure;grantee record;
BEGIN
    FOREACH fn IN ARRAY ARRAY['kaname.authority_role_move_pending_finalize_v1(jsonb,integer,integer)'::regprocedure] LOOP
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
DO $finish_contract$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_crud_storage_v3()','2a509037bf6728e1e469a5fb67ac1a7249d5f2e37c568326e23576ef39d08568','d02583f4fbcf55384579586a637b5f0716b2d858e913995c67460bb74cf6e423',$changes$[
  [
    " ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n",
    " ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n ('authority_role_move_pending_finalize_v1(jsonb,integer,integer)','51ca09bef15de6ed427d20d43c358288d7623e69aa04956e79f5696be483342e',true,'v',true,'private'),\n"
  ],
  [
    "  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n",
    "  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n  ('authority_role_move_pending_finalize_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','f23becc78d46cd3ef4e83ea6575347f879dc816c2b563871074bfb7a5e272481','50feff7af5b0a74d93cae738ba5c55efaab0ac312efb9edc13f75e0729e5ff15',$changes$[
  [
    "2a509037bf6728e1e469a5fb67ac1a7249d5f2e37c568326e23576ef39d08568",
    "d02583f4fbcf55384579586a637b5f0716b2d858e913995c67460bb74cf6e423"
  ]
]$changes$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','21d31121d7a86aabf55e648312b32deeca0dec64e64b8ea1538c44a8c9944ef2','53e3127bdc930b9c3b5d51b5344f47b1cdac3b668f3c222ebdff4fe2c85da732',$changes$[
  [
    "2a509037bf6728e1e469a5fb67ac1a7249d5f2e37c568326e23576ef39d08568",
    "d02583f4fbcf55384579586a637b5f0716b2d858e913995c67460bb74cf6e423"
  ],
  [
    "f23becc78d46cd3ef4e83ea6575347f879dc816c2b563871074bfb7a5e272481",
    "50feff7af5b0a74d93cae738ba5c55efaab0ac312efb9edc13f75e0729e5ff15"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'pending role finish contract predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'pending role finish contract replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'pending role finish contract body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'pending role finish contract installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'pending role finish contract storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$finish_contract$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $finish_contract$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('authority_metadata_service_account_access_label_ready_v1()','53e3127bdc930b9c3b5d51b5344f47b1cdac3b668f3c222ebdff4fe2c85da732','21d31121d7a86aabf55e648312b32deeca0dec64e64b8ea1538c44a8c9944ef2',$changes$[
  [
    "50feff7af5b0a74d93cae738ba5c55efaab0ac312efb9edc13f75e0729e5ff15",
    "f23becc78d46cd3ef4e83ea6575347f879dc816c2b563871074bfb7a5e272481"
  ],
  [
    "d02583f4fbcf55384579586a637b5f0716b2d858e913995c67460bb74cf6e423",
    "2a509037bf6728e1e469a5fb67ac1a7249d5f2e37c568326e23576ef39d08568"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','50feff7af5b0a74d93cae738ba5c55efaab0ac312efb9edc13f75e0729e5ff15','f23becc78d46cd3ef4e83ea6575347f879dc816c2b563871074bfb7a5e272481',$changes$[
  [
    "d02583f4fbcf55384579586a637b5f0716b2d858e913995c67460bb74cf6e423",
    "2a509037bf6728e1e469a5fb67ac1a7249d5f2e37c568326e23576ef39d08568"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','d02583f4fbcf55384579586a637b5f0716b2d858e913995c67460bb74cf6e423','2a509037bf6728e1e469a5fb67ac1a7249d5f2e37c568326e23576ef39d08568',$changes$[
  [
    "  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n  ('authority_role_move_pending_finalize_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n",
    "  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n"
  ],
  [
    " ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n ('authority_role_move_pending_finalize_v1(jsonb,integer,integer)','51ca09bef15de6ed427d20d43c358288d7623e69aa04956e79f5696be483342e',true,'v',true,'private'),\n",
    " ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'pending role finish contract predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'pending role finish contract replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'pending role finish contract body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'pending role finish contract installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'pending role finish contract storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$finish_contract$;
-- +goose StatementEnd

DROP FUNCTION kaname.authority_role_move_pending_finalize_v1(jsonb,integer,integer);
