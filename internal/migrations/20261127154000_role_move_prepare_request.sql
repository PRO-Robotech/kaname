-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Только отдельный LOGIN процесса Kaname удерживает OLD перед окончательными часами.
-- Actor уже входит в обычный запрос этого writer. Пакет переноса содержит только
-- физический образ, позиции и предложенные правила. Публикация проверяется отдельно.
CREATE FUNCTION kaname._authority_role_move_prepare_request_v1(p_input jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $prepare_request$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    req jsonb; hold_image jsonb; authority_input jsonb; returned jsonb; program jsonb; held jsonb; prepared jsonb;
    census jsonb; binding_image jsonb; target_project text; old_rule jsonb; new_rule jsonb;
    row_cost integer:=4;read_cost integer:=4;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN row_cost+1 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN read_cost+1 AND 4096
        OR octet_length(p_input::text)>8388608 THEN
        RAISE EXCEPTION 'role selector move transport exceeds budget' USING ERRCODE='54000';END IF;
    IF jsonb_typeof(p_input) IS DISTINCT FROM 'object' OR p_input->'_selector_move' IS DISTINCT FROM '"pending_no_copy_v1"'::jsonb
        OR p_input-ARRAY['_selector_move','request','hold'] IS DISTINCT FROM '{}'::jsonb
        OR jsonb_typeof(p_input->'request') IS DISTINCT FROM 'object' OR jsonb_typeof(p_input->'hold') IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'invalid role selector move envelope' USING ERRCODE='42501';END IF;
    req:=p_input->'request';hold_image:=p_input->'hold';authority_input:=req->'_access_label_authority';
    IF req-ARRAY['create','rules','retier','role','mask','version','_access_label_authority'] IS DISTINCT FROM '{}'::jsonb
        OR req->'create' IS DISTINCT FROM 'false'::jsonb OR req->'rules' IS DISTINCT FROM 'true'::jsonb
        OR req->'retier' IS DISTINCT FROM 'true'::jsonb OR req->'mask' IS DISTINCT FROM '["rules"]'::jsonb
        OR jsonb_typeof(authority_input) IS DISTINCT FROM 'object' OR authority_input-ARRAY['actor','questions'] IS DISTINCT FROM '{}'::jsonb
        OR authority_input->'questions' IS DISTINCT FROM '[]'::jsonb OR jsonb_typeof(authority_input->'actor') IS DISTINCT FROM 'object'
        OR hold_image->'copy_candidates' IS DISTINCT FROM '[]'::jsonb
        OR hold_image->'moves' IS DISTINCT FROM '[{"rule_index":0,"child_index":-1}]'::jsonb
        OR req#>'{role,rules}' IS DISTINCT FROM hold_image->'proposed_rules'
        OR req#>'{role,id}' IS DISTINCT FROM hold_image->'role_id' OR req->'version' IS DISTINCT FROM hold_image->'version' THEN
        RAISE EXCEPTION 'role selector move transport differs from typed request' USING ERRCODE='42501';END IF;
    returned:=kaname._authority_role_move_sequence_prepare_v1(req,hold_image,authority_input->'actor',p_rows-row_cost,p_reads-read_cost);
    program:=kaname._authority_sequence_store_v3();held:=program->'frozen';prepared:=held->'selector_move';
    census:=prepared->'binding_census';binding_image:=census#>'{bindings,0,2}';target_project:=binding_image#>>'{target,resources,0,id}';
    old_rule:=prepared#>'{role,physical,2,rules,0}';new_rule:=prepared#>'{role,new_role,rules,0}';
    IF returned->>'access_label_mode' IS DISTINCT FROM 'ordinary' OR program->>'family' IS DISTINCT FROM 'role'
        OR program->'selected' IS DISTINCT FROM 'null'::jsonb OR program->'decision_at' IS DISTINCT FROM 'null'::jsonb
        OR program->'nonce' IS DISTINCT FROM proof->'nonce' OR held->>'kind' IS DISTINCT FROM 'role.mutation'
        OR held->>'mode' IS DISTINCT FROM 'selector_move' OR held->>'selector_move_fixed' IS DISTINCT FROM '1'
        OR program->>'maximum_count' IS DISTINCT FROM '1' OR held ?| ARRAY['selector_move_transport','selector_move_decision',
            'selector_move_pending','selector_move_approved','selector_move_content_approval','selector_move_pending_sources']
        OR prepared->'actor' IS DISTINCT FROM authority_input->'actor' OR prepared->'nonce' IS DISTINCT FROM proof->'nonce'
        OR prepared->'invoker_oid' IS DISTINCT FROM proof->'invoker_oid' OR prepared->'prepared_at' IS DISTINCT FROM proof->'decision_at'
        OR prepared#>'{copies,roots}' IS DISTINCT FROM '{}'::jsonb
        OR jsonb_array_length(prepared#>'{role,physical,2,rules}') IS DISTINCT FROM 1
        OR jsonb_array_length(prepared#>'{role,new_role,rules}') IS DISTINCT FROM 1
        OR old_rule-ARRAY['module','resources','verbs','match_labels'] IS DISTINCT FROM '{}'::jsonb
        OR new_rule-ARRAY['module','resources','verbs','match_access_labels'] IS DISTINCT FROM '{}'::jsonb
        OR old_rule->>'module' IS DISTINCT FROM 'iam' OR old_rule->'resources' IS DISTINCT FROM '["project"]'::jsonb
        OR old_rule->'verbs' IS DISTINCT FROM '["get"]'::jsonb OR old_rule-'match_labels' IS DISTINCT FROM new_rule-'match_access_labels'
        OR old_rule->'match_labels' IS DISTINCT FROM new_rule->'match_access_labels'
        OR jsonb_array_length(census->'bindings') IS DISTINCT FROM 1 OR jsonb_array_length(census->'subjects') IS DISTINCT FROM 1
        OR binding_image->>'role_id' IS DISTINCT FROM prepared->>'role_id' OR binding_image->>'status' IS DISTINCT FROM 'PENDING'
        OR binding_image->>'revoked_at' IS NOT NULL OR binding_image->>'expires_at' IS NOT NULL
        OR binding_image->>'resource_type' IS DISTINCT FROM 'account' OR coalesce(target_project,'')=''
        OR binding_image->'target' IS DISTINCT FROM jsonb_build_object('resources',jsonb_build_array(jsonb_build_object('type','iam.project','id',target_project)))
        OR census->'members' IS DISTINCT FROM '[]'::jsonb OR jsonb_array_length(census->'ledger') IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'role selector move exceeds pending source coverage' USING ERRCODE='42501';END IF;
    IF octet_length(held::text)+64>8388608 THEN RAISE EXCEPTION 'role selector move transport exceeds frozen budget' USING ERRCODE='54000';END IF;
    UPDATE pg_temp.kaname_authority_sequence_program s SET frozen=s.frozen||jsonb_build_object('selector_move_transport','pending_no_copy_v1')
        WHERE s.singleton AND s.family='role' AND s.nonce=(proof->>'nonce')::uuid AND s.selected IS NULL AND s.frozen=held;
    IF NOT FOUND THEN RAISE EXCEPTION 'role selector move transport reservation changed' USING ERRCODE='40001';END IF;
    RETURN returned||jsonb_build_object('rows',(returned->>'rows')::integer+row_cost,'reads',(returned->>'reads')::integer+read_cost,
        'selector_move_transport','pending_no_copy_v1');
END;
$prepare_request$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure;grantee record;
BEGIN
    FOREACH fn IN ARRAY ARRAY['kaname._authority_role_move_prepare_request_v1(jsonb,integer,integer)'::regprocedure] LOOP
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
DO $prepare_guard$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','a2f5785344e6e53ce74cc1eafb3fcc8e234956b90837e010d70803d9f146061e','766d0f081364aaf517a37b28dfd8a6f1c9fd06f47c9a14d5ddb2b316b15686c3',$changes$[
  [
    " RETURN kaname._authority_role_move_sequence_prepare_v1(p_input,NULL,NULL,p_rows,p_reads);",
    " IF p_input ? '_selector_move' THEN\n  RETURN kaname._authority_role_move_prepare_request_v1(p_input,p_rows,p_reads);\n END IF;\n RETURN kaname._authority_role_move_sequence_prepare_v1(p_input,NULL,NULL,p_rows,p_reads);"
  ]
]$changes$::jsonb),
        ('_authority_role_move_binding_empty_require_v1(jsonb)','73d299f024c0f8015f6a228dfb9306ffe9f2263e2aece6999b723fc8b6ae93f0','0fc1d70bbda251fbfac9d47d31b16cd47f23c45a8491c6d5d5040dec094c491d',$changes$[
  [
    "    IF p_frozen ?| ARRAY['selector_move_pending_sources','selector_move_content_approval','selector_move_approved_content_sha256'] THEN",
    "    -- Публичный prepare фиксирует этот режим только после физического OLD.\n    -- Закрытый finalize не может превратить отсутствие выдач в разрешение.\n    IF p_frozen ? 'selector_move_transport' AND (\n        p_frozen->>'selector_move_transport' IS DISTINCT FROM 'pending_no_copy_v1'\n        OR jsonb_typeof(p_frozen->'selector_move_pending_sources') IS DISTINCT FROM 'object'\n        OR jsonb_typeof(p_frozen->'selector_move_content_approval') IS DISTINCT FROM 'object') THEN\n        RAISE EXCEPTION 'role selector move transport requires its source and content approval' USING ERRCODE='42501';END IF;\n    IF p_frozen ?| ARRAY['selector_move_pending_sources','selector_move_content_approval','selector_move_approved_content_sha256'] THEN"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','5eb15d5158db9625cde91f603451bd8603f0bc7c95406021fa1c90292eb8a232','e3f6f6eb43363509486c6a7549c93c2d2c5cb2eb0a2ca2e877f7e0a7e42e5342',$changes$[
  [
    "a2f5785344e6e53ce74cc1eafb3fcc8e234956b90837e010d70803d9f146061e",
    "766d0f081364aaf517a37b28dfd8a6f1c9fd06f47c9a14d5ddb2b316b15686c3"
  ],
  [
    "73d299f024c0f8015f6a228dfb9306ffe9f2263e2aece6999b723fc8b6ae93f0",
    "0fc1d70bbda251fbfac9d47d31b16cd47f23c45a8491c6d5d5040dec094c491d"
  ],
  [
    " ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n",
    " ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n ('_authority_role_move_prepare_request_v1(jsonb,integer,integer)','32d277a02b227a7966b8339fc9aebe5ac4139fb71b95cf2a8535d390a46bd1c1',false,'v',true,'private'),\n"
  ],
  [
    "  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n",
    "  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n  ('_authority_role_move_prepare_request_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_input','p_rows','p_reads']),\n"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','c4a9c31fb668f4cc5b0984f8fdf06765b785b36c88aa40f5ef2b8fd95d95e9c3','c066d23477d174f67d7e773fa3d8555a98ed5126415878bf5852830672d5d3dd',$changes$[
  [
    "5eb15d5158db9625cde91f603451bd8603f0bc7c95406021fa1c90292eb8a232",
    "e3f6f6eb43363509486c6a7549c93c2d2c5cb2eb0a2ca2e877f7e0a7e42e5342"
  ]
]$changes$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','e10ce9918c92df0877a8469d3a287e7f13d087f1d4a1d0a8f50edab1d597b01e','4d1b40444db98ce2a16c0874ca5bebc4ab3ed78a9ee092ebfc600d61966dbcee',$changes$[
  [
    "5eb15d5158db9625cde91f603451bd8603f0bc7c95406021fa1c90292eb8a232",
    "e3f6f6eb43363509486c6a7549c93c2d2c5cb2eb0a2ca2e877f7e0a7e42e5342"
  ],
  [
    "c4a9c31fb668f4cc5b0984f8fdf06765b785b36c88aa40f5ef2b8fd95d95e9c3",
    "c066d23477d174f67d7e773fa3d8555a98ed5126415878bf5852830672d5d3dd"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'selector move prepare envelope predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'selector move prepare envelope replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move prepare envelope body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move prepare envelope installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector move prepare envelope storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$prepare_guard$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $prepare_guard$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('authority_metadata_service_account_access_label_ready_v1()','4d1b40444db98ce2a16c0874ca5bebc4ab3ed78a9ee092ebfc600d61966dbcee','e10ce9918c92df0877a8469d3a287e7f13d087f1d4a1d0a8f50edab1d597b01e',$changes$[
  [
    "c066d23477d174f67d7e773fa3d8555a98ed5126415878bf5852830672d5d3dd",
    "c4a9c31fb668f4cc5b0984f8fdf06765b785b36c88aa40f5ef2b8fd95d95e9c3"
  ],
  [
    "e3f6f6eb43363509486c6a7549c93c2d2c5cb2eb0a2ca2e877f7e0a7e42e5342",
    "5eb15d5158db9625cde91f603451bd8603f0bc7c95406021fa1c90292eb8a232"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','c066d23477d174f67d7e773fa3d8555a98ed5126415878bf5852830672d5d3dd','c4a9c31fb668f4cc5b0984f8fdf06765b785b36c88aa40f5ef2b8fd95d95e9c3',$changes$[
  [
    "e3f6f6eb43363509486c6a7549c93c2d2c5cb2eb0a2ca2e877f7e0a7e42e5342",
    "5eb15d5158db9625cde91f603451bd8603f0bc7c95406021fa1c90292eb8a232"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','e3f6f6eb43363509486c6a7549c93c2d2c5cb2eb0a2ca2e877f7e0a7e42e5342','5eb15d5158db9625cde91f603451bd8603f0bc7c95406021fa1c90292eb8a232',$changes$[
  [
    "  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n  ('_authority_role_move_prepare_request_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_input','p_rows','p_reads']),\n",
    "  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n"
  ],
  [
    " ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n ('_authority_role_move_prepare_request_v1(jsonb,integer,integer)','32d277a02b227a7966b8339fc9aebe5ac4139fb71b95cf2a8535d390a46bd1c1',false,'v',true,'private'),\n",
    " ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n"
  ],
  [
    "0fc1d70bbda251fbfac9d47d31b16cd47f23c45a8491c6d5d5040dec094c491d",
    "73d299f024c0f8015f6a228dfb9306ffe9f2263e2aece6999b723fc8b6ae93f0"
  ],
  [
    "766d0f081364aaf517a37b28dfd8a6f1c9fd06f47c9a14d5ddb2b316b15686c3",
    "a2f5785344e6e53ce74cc1eafb3fcc8e234956b90837e010d70803d9f146061e"
  ]
]$changes$::jsonb),
        ('_authority_role_move_binding_empty_require_v1(jsonb)','0fc1d70bbda251fbfac9d47d31b16cd47f23c45a8491c6d5d5040dec094c491d','73d299f024c0f8015f6a228dfb9306ffe9f2263e2aece6999b723fc8b6ae93f0',$changes$[
  [
    "    -- Публичный prepare фиксирует этот режим только после физического OLD.\n    -- Закрытый finalize не может превратить отсутствие выдач в разрешение.\n    IF p_frozen ? 'selector_move_transport' AND (\n        p_frozen->>'selector_move_transport' IS DISTINCT FROM 'pending_no_copy_v1'\n        OR jsonb_typeof(p_frozen->'selector_move_pending_sources') IS DISTINCT FROM 'object'\n        OR jsonb_typeof(p_frozen->'selector_move_content_approval') IS DISTINCT FROM 'object') THEN\n        RAISE EXCEPTION 'role selector move transport requires its source and content approval' USING ERRCODE='42501';END IF;\n    IF p_frozen ?| ARRAY['selector_move_pending_sources','selector_move_content_approval','selector_move_approved_content_sha256'] THEN",
    "    IF p_frozen ?| ARRAY['selector_move_pending_sources','selector_move_content_approval','selector_move_approved_content_sha256'] THEN"
  ]
]$changes$::jsonb),
        ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','766d0f081364aaf517a37b28dfd8a6f1c9fd06f47c9a14d5ddb2b316b15686c3','a2f5785344e6e53ce74cc1eafb3fcc8e234956b90837e010d70803d9f146061e',$changes$[
  [
    " IF p_input ? '_selector_move' THEN\n  RETURN kaname._authority_role_move_prepare_request_v1(p_input,p_rows,p_reads);\n END IF;\n RETURN kaname._authority_role_move_sequence_prepare_v1(p_input,NULL,NULL,p_rows,p_reads);",
    " RETURN kaname._authority_role_move_sequence_prepare_v1(p_input,NULL,NULL,p_rows,p_reads);"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'selector move prepare envelope predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'selector move prepare envelope replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move prepare envelope body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move prepare envelope installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector move prepare envelope storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$prepare_guard$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_role_move_prepare_request_v1(jsonb,integer,integer);
