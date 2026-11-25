-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- До выбора слота проверяем OLD, после его потребления — NEW. Каждый вызов
-- списывает собственное чтение в той же программе, включая повторные проверки.
CREATE FUNCTION kaname._authority_role_move_publication_replay_v1(p_frozen jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $replay$
DECLARE
    credit jsonb:=p_frozen->'selector_move_publication_budget';
    approved jsonb:=p_frozen->'selector_move_content_approval';
    published boolean:=p_frozen ? 'selector_move_approved';
    available_rows integer;available_reads integer;reserve_rows integer:=0;reserve_reads integer:=0;
    used_rows integer;used_reads integer;fixed_work integer;measured jsonb;
BEGIN
    IF p_frozen->>'selector_move_transport' IS DISTINCT FROM 'pending_no_copy_v1'
        OR jsonb_typeof(credit) IS DISTINCT FROM 'object' OR credit-ARRAY['phase','nonce','content_sha256','rows','reads'] IS DISTINCT FROM '{}'::jsonb
        OR credit->>'phase' IS DISTINCT FROM (CASE WHEN published THEN 'deferred' ELSE 'approval' END)
        OR jsonb_typeof(credit->'rows') IS DISTINCT FROM 'number' OR jsonb_typeof(credit->'reads') IS DISTINCT FROM 'number'
        OR coalesce(credit->>'rows','') !~ '^[0-9]{1,6}$' OR coalesce(credit->>'reads','') !~ '^[0-9]{1,4}$'
        OR credit->'nonce' IS DISTINCT FROM p_frozen#>'{selector_move_pending_sources,nonce}'
        OR credit->'nonce' IS DISTINCT FROM approved->'nonce'
        OR credit->>'content_sha256' IS DISTINCT FROM encode(sha256(convert_to(approved::text,'UTF8')),'hex') THEN
        RAISE EXCEPTION 'role publication budget is not bound to content' USING ERRCODE='42501';END IF;
    available_rows:=(credit->>'rows')::integer;available_reads:=(credit->>'reads')::integer;
    IF published THEN
        -- roots_complete читает программу, общий guard сверяет frozen, ниже CAS списывает расход.
        fixed_work:=3;
    ELSE
        -- Общий guard сверяет frozen, ниже выполняется CAS. Оставляем минимум
        -- 15:20 (16/5), два чтения 15:50 и три действия deferred. Реальную цену
        -- NEW узнаём после DML; исчерпание остатка откатывает всю транзакцию.
        fixed_work:=2;reserve_rows:=21;reserve_reads:=10;
    END IF;
    -- Внутри 15:50 дополнительные два чтения после DML или три до DML.
    IF available_rows NOT BETWEEN fixed_work+reserve_rows+(CASE WHEN published THEN 2 ELSE 3 END)+1 AND 100000
        OR available_reads NOT BETWEEN fixed_work+reserve_reads+(CASE WHEN published THEN 2 ELSE 3 END)+1 AND 4096 THEN
        RAISE EXCEPTION 'role publication replay budget exhausted' USING ERRCODE='54000';END IF;
    measured:=kaname._authority_role_move_content_replay_cost_v1(
        available_rows-fixed_work-reserve_rows-(CASE WHEN published THEN 2 ELSE 3 END),
        available_reads-fixed_work-reserve_reads-(CASE WHEN published THEN 2 ELSE 3 END));
    used_rows:=(measured->>'rows')::integer+fixed_work;used_reads:=(measured->>'reads')::integer+fixed_work;
    IF used_rows IS NULL OR used_rows NOT BETWEEN 1 AND available_rows-reserve_rows
        OR used_reads IS NULL OR used_reads NOT BETWEEN 1 AND available_reads-reserve_reads THEN
        RAISE EXCEPTION 'role publication replay cost unconfirmed' USING ERRCODE='54000';END IF;
    IF measured->'receipt' IS DISTINCT FROM approved THEN RAISE EXCEPTION 'role publication content changed' USING ERRCODE='42501';END IF;
    UPDATE pg_temp.kaname_authority_sequence_program s
        SET frozen=jsonb_set(s.frozen,'{selector_move_publication_budget}',credit||jsonb_build_object(
            'phase','deferred','rows',available_rows-used_rows,'reads',available_reads-used_reads),false)
        WHERE s.singleton AND s.family='role' AND s.nonce=(credit->>'nonce')::uuid AND s.frozen=p_frozen
            AND (s.selected IS NOT NULL)=published;
    IF NOT FOUND THEN RAISE EXCEPTION 'role publication budget changed' USING ERRCODE='40001';END IF;
    RETURN measured->'receipt';
END;
$replay$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Только владелец передаёт неизрасходованную часть бюджета предыдущих фаз.
-- Возвращённый остаток принадлежит deferred до конца транзакции. Вызывающий
-- writer передаёт всю сумму один раз и не расходует этот остаток повторно.
CREATE FUNCTION kaname._authority_role_move_sequence_approve_budget_v1(p_rows integer,p_reads integer) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $budget$
DECLARE
    -- Четыре действия этого адаптера (аттестация, программа, CAS, readback).
    -- Семь действий approve для одного журнала: та же аттестация и программа,
    -- header, проверка состояния, count, выбор слота и публикация программы.
    fixed_work constant integer:=11;
    proof jsonb;program jsonb;original jsonb;approval jsonb;credit jsonb;afterward jsonb;
    remaining_rows integer;remaining_reads integer;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN fixed_work+1 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN fixed_work+1 AND 4096 THEN
        RAISE EXCEPTION 'role publication budget exhausted' USING ERRCODE='54000';END IF;
    proof:=kaname._authority_role_move_attestation_v1();program:=kaname._authority_sequence_store_v3();original:=program->'frozen';
    approval:=original->'selector_move_content_approval';
    IF program->>'family' IS DISTINCT FROM 'role' OR original->>'selector_move_transport' IS DISTINCT FROM 'pending_no_copy_v1'
        OR original->>'mode' IS DISTINCT FROM 'selector_move' OR program->'nonce' IS DISTINCT FROM proof->'nonce'
        OR program->'selected' IS DISTINCT FROM 'null'::jsonb OR program->>'maximum_count' IS DISTINCT FROM '1'
        OR jsonb_typeof(original->'selector_move_pending_sources') IS DISTINCT FROM 'object'
        OR jsonb_typeof(approval) IS DISTINCT FROM 'object' OR approval->'nonce' IS DISTINCT FROM proof->'nonce'
        OR approval->'decision_at' IS DISTINCT FROM proof->'decision_at'
        OR original ?| ARRAY['selector_move_publication_budget','selector_move_approved','selector_move_approved_content_sha256'] THEN
        RAISE EXCEPTION 'role publication requires open content approval' USING ERRCODE='42501';END IF;
    credit:=jsonb_build_object('phase','approval','nonce',proof->'nonce','content_sha256',encode(sha256(convert_to(approval::text,'UTF8')),'hex'),
        'rows',p_rows-fixed_work,'reads',p_reads-fixed_work);
    IF octet_length(original::text)+octet_length(credit::text)+512>8388608 THEN
        RAISE EXCEPTION 'role publication budget receipt exceeds byte limit' USING ERRCODE='54000';END IF;
    UPDATE pg_temp.kaname_authority_sequence_program s SET frozen=s.frozen||jsonb_build_object('selector_move_publication_budget',credit)
        WHERE s.singleton AND s.family='role' AND s.nonce=(proof->>'nonce')::uuid AND s.selected IS NULL AND s.frozen=original;
    IF NOT FOUND THEN RAISE EXCEPTION 'role publication budget repeated' USING ERRCODE='40001';END IF;
    PERFORM kaname._authority_role_move_sequence_approve_v1();
    program:=kaname._authority_sequence_store_v3();afterward:=program#>'{frozen,selector_move_publication_budget}';
    IF jsonb_typeof(program->'selected') IS DISTINCT FROM 'array' OR afterward->>'phase' IS DISTINCT FROM 'deferred'
        OR afterward-ARRAY['rows','reads','phase'] IS DISTINCT FROM credit-ARRAY['rows','reads','phase']
        OR program#>'{frozen,selector_move_approved_content_sha256}' IS DISTINCT FROM credit->'content_sha256' THEN
        RAISE EXCEPTION 'role publication budget readback differs' USING ERRCODE='40001';END IF;
    remaining_rows:=(afterward->>'rows')::integer;remaining_reads:=(afterward->>'reads')::integer;
    IF remaining_rows IS NULL OR remaining_rows NOT BETWEEN 21 AND p_rows-fixed_work
        OR remaining_reads IS NULL OR remaining_reads NOT BETWEEN 10 AND p_reads-fixed_work THEN
        RAISE EXCEPTION 'role publication did not reserve deferred work' USING ERRCODE='54000';END IF;
    RETURN jsonb_build_object('rows',p_rows-remaining_rows,'reads',p_reads-remaining_reads,
        'deferred_rows',remaining_rows,'deferred_reads',remaining_reads);
END;
$budget$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure;grantee record;
BEGIN
    FOREACH fn IN ARRAY ARRAY['kaname._authority_role_move_publication_replay_v1(jsonb)'::regprocedure,
        'kaname._authority_role_move_sequence_approve_budget_v1(integer,integer)'::regprocedure] LOOP
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
DO $publication_budget$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_role_move_binding_empty_require_v1(jsonb)','0fc1d70bbda251fbfac9d47d31b16cd47f23c45a8491c6d5d5040dec094c491d','b846e2025d6246d9b9431667f828b05abd86594bbb142bee38e46ad9d44ef004',$changes$[
  [
    "    IF p_frozen ? 'selector_move_transport' AND (",
    "    IF p_frozen ? 'selector_move_publication_budget' AND NOT (p_frozen ? 'selector_move_transport') THEN\n        RAISE EXCEPTION 'role publication budget outside transport' USING ERRCODE='42501';END IF;\n    IF p_frozen ? 'selector_move_transport' AND ("
  ],
  [
    "IF p_frozen->'selector_move_content_approval' IS DISTINCT FROM kaname._authority_role_move_content_receipt_v1()",
    "IF p_frozen->'selector_move_content_approval' IS DISTINCT FROM\n            (CASE WHEN p_frozen ? 'selector_move_transport' THEN kaname._authority_role_move_publication_replay_v1(p_frozen)\n             ELSE kaname._authority_role_move_content_receipt_v1() END)"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','71028e5d9d6344c2275929d53d7a990c13c676b721dc546b5f31c57e2d41b58a','2a509037bf6728e1e469a5fb67ac1a7249d5f2e37c568326e23576ef39d08568',$changes$[
  [
    "0fc1d70bbda251fbfac9d47d31b16cd47f23c45a8491c6d5d5040dec094c491d",
    "b846e2025d6246d9b9431667f828b05abd86594bbb142bee38e46ad9d44ef004"
  ],
  [
    " ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n",
    " ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n ('_authority_role_move_publication_replay_v1(jsonb)','4f336128b2f07ed0c2c7c8298862dcec8f40a451f194cd52d3be72c5e4ac45d0',false,'v',true,'private'),\n ('_authority_role_move_sequence_approve_budget_v1(integer,integer)','41fc02a3449305dc84e3cc4588c8663ef1b1be641b22b9290e94fc3094ae4e65',false,'v',true,'private'),\n"
  ],
  [
    "  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n",
    "  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n  ('_authority_role_move_publication_replay_v1(jsonb)','jsonb',1,ARRAY['p_frozen']),\n  ('_authority_role_move_sequence_approve_budget_v1(integer,integer)','jsonb',2,ARRAY['p_rows','p_reads']),\n"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','6e1088992add4c8176799d902a4cb1299eff8c8354561d9cb486f21b0fafddf3','f23becc78d46cd3ef4e83ea6575347f879dc816c2b563871074bfb7a5e272481',$changes$[
  [
    "71028e5d9d6344c2275929d53d7a990c13c676b721dc546b5f31c57e2d41b58a",
    "2a509037bf6728e1e469a5fb67ac1a7249d5f2e37c568326e23576ef39d08568"
  ]
]$changes$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','8c5e43c65d160987b078a5933dd2e394d62c85826dd45b2bb857f54ccdc17315','21d31121d7a86aabf55e648312b32deeca0dec64e64b8ea1538c44a8c9944ef2',$changes$[
  [
    "71028e5d9d6344c2275929d53d7a990c13c676b721dc546b5f31c57e2d41b58a",
    "2a509037bf6728e1e469a5fb67ac1a7249d5f2e37c568326e23576ef39d08568"
  ],
  [
    "6e1088992add4c8176799d902a4cb1299eff8c8354561d9cb486f21b0fafddf3",
    "f23becc78d46cd3ef4e83ea6575347f879dc816c2b563871074bfb7a5e272481"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'selector move publication budget predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'selector move publication budget replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move publication budget body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move publication budget installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector move publication budget storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$publication_budget$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $publication_budget$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('authority_metadata_service_account_access_label_ready_v1()','21d31121d7a86aabf55e648312b32deeca0dec64e64b8ea1538c44a8c9944ef2','8c5e43c65d160987b078a5933dd2e394d62c85826dd45b2bb857f54ccdc17315',$changes$[
  [
    "f23becc78d46cd3ef4e83ea6575347f879dc816c2b563871074bfb7a5e272481",
    "6e1088992add4c8176799d902a4cb1299eff8c8354561d9cb486f21b0fafddf3"
  ],
  [
    "2a509037bf6728e1e469a5fb67ac1a7249d5f2e37c568326e23576ef39d08568",
    "71028e5d9d6344c2275929d53d7a990c13c676b721dc546b5f31c57e2d41b58a"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','f23becc78d46cd3ef4e83ea6575347f879dc816c2b563871074bfb7a5e272481','6e1088992add4c8176799d902a4cb1299eff8c8354561d9cb486f21b0fafddf3',$changes$[
  [
    "2a509037bf6728e1e469a5fb67ac1a7249d5f2e37c568326e23576ef39d08568",
    "71028e5d9d6344c2275929d53d7a990c13c676b721dc546b5f31c57e2d41b58a"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','2a509037bf6728e1e469a5fb67ac1a7249d5f2e37c568326e23576ef39d08568','71028e5d9d6344c2275929d53d7a990c13c676b721dc546b5f31c57e2d41b58a',$changes$[
  [
    "  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n  ('_authority_role_move_publication_replay_v1(jsonb)','jsonb',1,ARRAY['p_frozen']),\n  ('_authority_role_move_sequence_approve_budget_v1(integer,integer)','jsonb',2,ARRAY['p_rows','p_reads']),\n",
    "  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n"
  ],
  [
    " ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n ('_authority_role_move_publication_replay_v1(jsonb)','4f336128b2f07ed0c2c7c8298862dcec8f40a451f194cd52d3be72c5e4ac45d0',false,'v',true,'private'),\n ('_authority_role_move_sequence_approve_budget_v1(integer,integer)','41fc02a3449305dc84e3cc4588c8663ef1b1be641b22b9290e94fc3094ae4e65',false,'v',true,'private'),\n",
    " ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n"
  ],
  [
    "b846e2025d6246d9b9431667f828b05abd86594bbb142bee38e46ad9d44ef004",
    "0fc1d70bbda251fbfac9d47d31b16cd47f23c45a8491c6d5d5040dec094c491d"
  ]
]$changes$::jsonb),
        ('_authority_role_move_binding_empty_require_v1(jsonb)','b846e2025d6246d9b9431667f828b05abd86594bbb142bee38e46ad9d44ef004','0fc1d70bbda251fbfac9d47d31b16cd47f23c45a8491c6d5d5040dec094c491d',$changes$[
  [
    "IF p_frozen->'selector_move_content_approval' IS DISTINCT FROM\n            (CASE WHEN p_frozen ? 'selector_move_transport' THEN kaname._authority_role_move_publication_replay_v1(p_frozen)\n             ELSE kaname._authority_role_move_content_receipt_v1() END)",
    "IF p_frozen->'selector_move_content_approval' IS DISTINCT FROM kaname._authority_role_move_content_receipt_v1()"
  ],
  [
    "    IF p_frozen ? 'selector_move_publication_budget' AND NOT (p_frozen ? 'selector_move_transport') THEN\n        RAISE EXCEPTION 'role publication budget outside transport' USING ERRCODE='42501';END IF;\n    IF p_frozen ? 'selector_move_transport' AND (",
    "    IF p_frozen ? 'selector_move_transport' AND ("
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'selector move publication budget predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'selector move publication budget replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move publication budget body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move publication budget installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector move publication budget storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$publication_budget$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_role_move_sequence_approve_budget_v1(integer,integer);
DROP FUNCTION kaname._authority_role_move_publication_replay_v1(jsonb);
