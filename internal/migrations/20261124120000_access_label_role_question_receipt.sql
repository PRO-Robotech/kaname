-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Фиксирует вызывающего и объявленные вопросы accessLabels в программе роли.

-- +goose Up
SELECT kaname.authority_protocol_drain();

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_access_label_role_questions_prepare_v1(
 p_transition jsonb,p_authority jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE actor jsonb;question jsonb;definition_id uuid;declared jsonb;
 questions jsonb;new_ids jsonb;declared_count integer;retained_count integer;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_rows IS NULL OR p_rows NOT BETWEEN 1 AND 100000
 OR p_reads IS NULL OR p_reads NOT BETWEEN 1 AND 4096 THEN
  RAISE EXCEPTION 'role access label question budget absent' USING ERRCODE='54000';END IF;
 IF jsonb_typeof(p_authority) IS DISTINCT FROM 'object'
 OR p_authority-ARRAY['actor','questions']<>'{}'::jsonb
 OR jsonb_typeof(p_authority->'actor') IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_authority->'questions') IS DISTINCT FROM 'array'
 OR jsonb_array_length(p_authority->'questions')>4096
 OR octet_length(p_authority::text)>8388608 THEN
  RAISE EXCEPTION 'role access label declared authority is absent or unbounded' USING ERRCODE='42501';END IF;
 actor:=p_authority->'actor';declared:=p_authority->'questions';
 declared_count:=jsonb_array_length(declared);
 IF 1+declared_count>p_rows THEN
  RAISE EXCEPTION 'role access label declared question budget exceeded' USING ERRCODE='54000';END IF;
 IF actor-ARRAY['type','id']<>'{}'::jsonb
 OR actor->>'type' IS NULL OR actor->>'type' NOT IN ('user','service_account')
 OR jsonb_typeof(actor->'id') IS DISTINCT FROM 'string'
 OR coalesce(actor->>'id','')='' OR length(actor->>'id')>16384
 OR (actor->>'id')~'[:#*[:space:][:cntrl:]]' THEN
  RAISE EXCEPTION 'role access label actor is not canonical' USING ERRCODE='23514';END IF;
 IF jsonb_typeof(p_transition->'new_projection') IS DISTINCT FROM 'array'
 OR jsonb_typeof(p_transition->'definition_witnesses') IS DISTINCT FROM 'object'
 OR coalesce(p_transition->>'role_id','')='' OR coalesce(p_transition->>'new_digest','')='' THEN
  RAISE EXCEPTION 'role access label question lacks owner transition' USING ERRCODE='42501';END IF;
 SELECT coalesce(jsonb_object_agg(e->>1,true),'{}'::jsonb) INTO new_ids
 FROM jsonb_array_elements(p_transition->'new_projection') e;
 FOR question IN SELECT value FROM jsonb_array_elements(declared) LOOP
  IF jsonb_typeof(question) IS DISTINCT FROM 'object'
  OR question-ARRAY['scope_kind','scope_id','definition_id']<>'{}'::jsonb
  OR question->>'scope_kind' IS NULL OR question->>'scope_kind' NOT IN ('cluster','account','project')
  OR jsonb_typeof(question->'scope_id') IS DISTINCT FROM 'string'
  OR coalesce(question->>'scope_id','')='' OR length(question->>'scope_id')>4096
  OR (question->>'scope_id')~'[:#*[:space:][:cntrl:]]'
  OR jsonb_typeof(question->'definition_id') IS DISTINCT FROM 'string' THEN
   RAISE EXCEPTION 'role access label question is not canonical' USING ERRCODE='23514';END IF;
  definition_id:=(question->>'definition_id')::uuid;
  IF question->>'definition_id' IS DISTINCT FROM definition_id::text
  OR NOT (new_ids ? definition_id::text)
  OR NOT ((p_transition->'definition_witnesses') ? definition_id::text) THEN
   RAISE EXCEPTION 'role access label question is outside NEW definitions' USING ERRCODE='42501';END IF;
 END LOOP;
 IF (SELECT count(DISTINCT value) FROM jsonb_array_elements(declared))<>declared_count THEN
  RAISE EXCEPTION 'role access label question is repeated' USING ERRCODE='23514';END IF;
 -- Discovery может объявить scope-superset для нескольких carriers. Только
 -- совпадение с held scope определения становится допустимым read question.
 -- Foreign scope остаётся непригодным для запроса, но не запрещает mixed role.
 SELECT coalesce(jsonb_object_agg(jsonb_build_array(q->>'scope_kind',q->>'scope_id',q->>'definition_id')::text,true),'{}'::jsonb),count(*)::integer
 INTO questions,retained_count FROM jsonb_array_elements(declared) q
 WHERE p_transition#>>ARRAY['definition_witnesses',q->>'definition_id','scope_kind']=q->>'scope_kind'
 AND p_transition#>>ARRAY['definition_witnesses',q->>'definition_id','scope_id']=q->>'scope_id';
 IF 1+declared_count+retained_count>p_rows THEN
  RAISE EXCEPTION 'role access label question row budget exceeded' USING ERRCODE='54000';END IF;
 RETURN jsonb_build_object('actor',actor,'questions',questions,
  'role_id',p_transition->>'role_id','new_digest',p_transition->>'new_digest',
  'rows',1+declared_count+retained_count,'reads',1);
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Root-owned same-snapshot SOURCE wrapper must invoke this before source allow.
-- No locks and no accepting fresh definitions after the final decision clock.
CREATE FUNCTION kaname.authority_access_label_role_question_require_v1(
 p_actor_type text,p_actor_id text,p_scope_kind text,p_scope_id text,p_definition uuid,
 p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;header jsonb;receipt jsonb;selected_at timestamptz;prepared_at timestamptz;
 mutation_id text;new_digest text;own_role_written boolean;question_key text;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_rows IS NULL OR p_rows NOT BETWEEN 2 AND 100000
 OR p_reads IS NULL OR p_reads NOT BETWEEN 2 AND 4096 THEN
  RAISE EXCEPTION 'role access label question read budget absent' USING ERRCODE='54000';END IF;
 SELECT q.proof,q.header INTO STRICT proof,header FROM kaname._authority_sequence_probe_v3() q;
 IF proof->>'writer_contract' IS DISTINCT FROM '2'
 OR proof->>'kind' IS DISTINCT FROM 'role' OR proof->>'purpose' IS DISTINCT FROM 'decision'
 OR header->>'family' IS DISTINCT FROM 'role'
 OR header#>>'{frozen,mode}' IS DISTINCT FROM 'access_label_transition'
 OR jsonb_typeof(header->'selected') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'role access label question requires finalized program' USING ERRCODE='42501';END IF;
 SELECT s.frozen->'access_label_authority',s.decision_at,s.staged_decision_at,
  s.frozen#>>'{access_label_transition,role_id}',s.frozen#>>'{access_label_transition,new_digest}',
  EXISTS(SELECT 1 FROM pg_temp.kaname_authority_sequence_effects e
   WHERE e.ordinal=1 AND e.nonce=s.nonce AND e.selected AND e.registered
    AND e.table_name='resource_journal' AND e.origin->>'table'='roles')
 INTO receipt,selected_at,prepared_at,mutation_id,new_digest,own_role_written
 FROM pg_temp.kaname_authority_sequence_program s
 WHERE s.singleton AND s.nonce=(header->>'nonce')::uuid AND s.family='role'
  AND s.frozen->>'kind'='role.mutation'
  AND NOT (s.frozen ? 'access_label_transition_applied');
 IF NOT FOUND OR selected_at IS NULL OR prepared_at IS NULL OR selected_at<=prepared_at
 OR selected_at IS DISTINCT FROM (proof->>'decision_at')::timestamptz
 OR own_role_written OR jsonb_typeof(receipt) IS DISTINCT FROM 'object'
 OR coalesce(mutation_id,'')='' OR coalesce(new_digest,'')=''
 OR receipt->>'role_id' IS DISTINCT FROM mutation_id
 OR receipt->>'new_digest' IS DISTINCT FROM new_digest
 OR receipt->'actor' IS DISTINCT FROM jsonb_build_object('type',p_actor_type,'id',p_actor_id) THEN
  RAISE EXCEPTION 'role access label actor receipt is absent or consumed' USING ERRCODE='42501';END IF;
 question_key:=jsonb_build_array(p_scope_kind,p_scope_id,p_definition)::text;
 IF (receipt->'questions')->question_key IS DISTINCT FROM 'true'::jsonb THEN
  RAISE EXCEPTION 'role access label question was not prepared' USING ERRCODE='42501';END IF;
 RETURN jsonb_build_object('decision_at',selected_at,'rows',2,'reads',2);
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
DECLARE signature text;grantee record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 FOREACH signature IN ARRAY ARRAY[
  'authority_access_label_role_questions_prepare_v1(jsonb,jsonb,integer,integer)',
  'authority_access_label_role_question_require_v1(text,text,text,text,uuid,integer,integer)'
 ] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',signature);
  FOR grantee IN SELECT DISTINCT r.rolname FROM pg_proc p
   CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   JOIN pg_roles r ON r.oid=a.grantee
   WHERE p.oid=to_regprocedure('kaname.'||signature) AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM %I',signature,grantee.rolname);
  END LOOP;
 END LOOP;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $access_label_role_question_receipt$
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
        RAISE EXCEPTION 'несогласованное состояние перед изменением фиксации вопросов accessLabels' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        (
            'authority_role_sequence_prepare_v3(jsonb,integer,integer)',
            '15e6d0b5ff8dd88de51c684e4a7a1df23e460ed3a4c36a7781fd444be5f68550',
            '1fee16aa90e9b764520158013479315184116fc5e17991573dac4f509f1fa0dc',
            $patch$[
  [
    " access_label_transition jsonb;access_label_frozen jsonb:='{}';access_label_needed boolean;\n",
    " access_label_transition jsonb;access_label_frozen jsonb:='{}';access_label_needed boolean;\n access_label_authority_input jsonb;access_label_authority jsonb;\n"
  ],
  [
    " OR p_input-ARRAY['create','rules','retier','role','mask','version']<>'{}' THEN\n",
    " OR p_input-ARRAY['create','rules','retier','role','mask','version','_access_label_authority']<>'{}' THEN\n"
  ],
  [
    "  RAISE EXCEPTION 'role sequence input is not a closed request' USING ERRCODE='42501';END IF;\n",
    "  RAISE EXCEPTION 'role sequence input is not a closed request' USING ERRCODE='42501';END IF;\n access_label_authority_input:=p_input->'_access_label_authority';\n p_input:=p_input-'_access_label_authority';\n"
  ],
  [
    "   reads:=reads+(access_label_transition->>'reads')::integer;\n",
    "   reads:=reads+(access_label_transition->>'reads')::integer;\n   IF access_label_transition->'new_projection'<>'[]'::jsonb THEN\n    access_label_authority:=kaname.authority_access_label_role_questions_prepare_v1(\n     access_label_transition,access_label_authority_input,p_rows-scanned,p_reads-reads);\n    scanned:=scanned+(access_label_authority->>'rows')::integer;\n    reads:=reads+(access_label_authority->>'reads')::integer;\n   END IF;\n"
  ],
  [
    "     'access_label_transition',access_label_transition);\n",
    "     'access_label_transition',access_label_transition);\n    IF access_label_authority IS NOT NULL THEN\n     access_label_frozen:=access_label_frozen||jsonb_build_object('access_label_authority',access_label_authority);\n    END IF;\n"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            'f640484ea8c9afa1e0c83d4a40907e0ef42b1dca81fadc7eb558b406a1757f13',
            '093014807621e110f3f3e3da382992686f03739d0723480a5d16592d47e1ce5d',
            $patch$[
  [
    " ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','15e6d0b5ff8dd88de51c684e4a7a1df23e460ed3a4c36a7781fd444be5f68550',true,'v',true,'export'),",
    " ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','1fee16aa90e9b764520158013479315184116fc5e17991573dac4f509f1fa0dc',true,'v',true,'export'),"
  ],
  [
    " ('authority_access_label_binding_definitions_prepare_v1(jsonb,text,text,text,text,integer,integer)','8127b1758d4ce9f8bfda917bb4bcc0bc292972aede72c22d7ba137289ec2b972',false,'v',true,'private'),",
    " ('authority_access_label_binding_definitions_prepare_v1(jsonb,text,text,text,text,integer,integer)','8127b1758d4ce9f8bfda917bb4bcc0bc292972aede72c22d7ba137289ec2b972',false,'v',true,'private'),\n ('authority_access_label_role_questions_prepare_v1(jsonb,jsonb,integer,integer)','62863d6265ce430d137b1d66d7214adf26d51aaf1846eb1b0e1afa48231fed38',false,'v',true,'private'),\n ('authority_access_label_role_question_require_v1(text,text,text,text,uuid,integer,integer)','a5b7081e9cd8901c88132ba503e9006923c21fca16d366913de540bb8e11cd3c',false,'v',true,'private'),"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_full_contract_storage_v3()',
            '278ffcfbd0b872e311014247a7d000ae5e99818ed88510936537af11bec8f16e',
            '8268ab7fff7f48f31ffeb6211b709f65289428fd4653fc523605236783406547',
            $patch$[
  [
    "f640484ea8c9afa1e0c83d4a40907e0ef42b1dca81fadc7eb558b406a1757f13",
    "093014807621e110f3f3e3da382992686f03739d0723480a5d16592d47e1ce5d"
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
$access_label_role_question_receipt$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();

-- +goose StatementBegin
DO $access_label_role_question_receipt$
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
        RAISE EXCEPTION 'несогласованное состояние перед изменением фиксации вопросов accessLabels' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        (
            '_authority_full_contract_storage_v3()',
            '8268ab7fff7f48f31ffeb6211b709f65289428fd4653fc523605236783406547',
            '278ffcfbd0b872e311014247a7d000ae5e99818ed88510936537af11bec8f16e',
            $patch$[
  [
    "093014807621e110f3f3e3da382992686f03739d0723480a5d16592d47e1ce5d",
    "f640484ea8c9afa1e0c83d4a40907e0ef42b1dca81fadc7eb558b406a1757f13"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            '093014807621e110f3f3e3da382992686f03739d0723480a5d16592d47e1ce5d',
            'f640484ea8c9afa1e0c83d4a40907e0ef42b1dca81fadc7eb558b406a1757f13',
            $patch$[
  [
    " ('authority_access_label_binding_definitions_prepare_v1(jsonb,text,text,text,text,integer,integer)','8127b1758d4ce9f8bfda917bb4bcc0bc292972aede72c22d7ba137289ec2b972',false,'v',true,'private'),\n ('authority_access_label_role_questions_prepare_v1(jsonb,jsonb,integer,integer)','62863d6265ce430d137b1d66d7214adf26d51aaf1846eb1b0e1afa48231fed38',false,'v',true,'private'),\n ('authority_access_label_role_question_require_v1(text,text,text,text,uuid,integer,integer)','a5b7081e9cd8901c88132ba503e9006923c21fca16d366913de540bb8e11cd3c',false,'v',true,'private'),",
    " ('authority_access_label_binding_definitions_prepare_v1(jsonb,text,text,text,text,integer,integer)','8127b1758d4ce9f8bfda917bb4bcc0bc292972aede72c22d7ba137289ec2b972',false,'v',true,'private'),"
  ],
  [
    " ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','1fee16aa90e9b764520158013479315184116fc5e17991573dac4f509f1fa0dc',true,'v',true,'export'),",
    " ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','15e6d0b5ff8dd88de51c684e4a7a1df23e460ed3a4c36a7781fd444be5f68550',true,'v',true,'export'),"
  ]
]$patch$::jsonb
        ),
        (
            'authority_role_sequence_prepare_v3(jsonb,integer,integer)',
            '1fee16aa90e9b764520158013479315184116fc5e17991573dac4f509f1fa0dc',
            '15e6d0b5ff8dd88de51c684e4a7a1df23e460ed3a4c36a7781fd444be5f68550',
            $patch$[
  [
    "     'access_label_transition',access_label_transition);\n    IF access_label_authority IS NOT NULL THEN\n     access_label_frozen:=access_label_frozen||jsonb_build_object('access_label_authority',access_label_authority);\n    END IF;\n",
    "     'access_label_transition',access_label_transition);\n"
  ],
  [
    "   reads:=reads+(access_label_transition->>'reads')::integer;\n   IF access_label_transition->'new_projection'<>'[]'::jsonb THEN\n    access_label_authority:=kaname.authority_access_label_role_questions_prepare_v1(\n     access_label_transition,access_label_authority_input,p_rows-scanned,p_reads-reads);\n    scanned:=scanned+(access_label_authority->>'rows')::integer;\n    reads:=reads+(access_label_authority->>'reads')::integer;\n   END IF;\n",
    "   reads:=reads+(access_label_transition->>'reads')::integer;\n"
  ],
  [
    "  RAISE EXCEPTION 'role sequence input is not a closed request' USING ERRCODE='42501';END IF;\n access_label_authority_input:=p_input->'_access_label_authority';\n p_input:=p_input-'_access_label_authority';\n",
    "  RAISE EXCEPTION 'role sequence input is not a closed request' USING ERRCODE='42501';END IF;\n"
  ],
  [
    " OR p_input-ARRAY['create','rules','retier','role','mask','version','_access_label_authority']<>'{}' THEN\n",
    " OR p_input-ARRAY['create','rules','retier','role','mask','version']<>'{}' THEN\n"
  ],
  [
    " access_label_transition jsonb;access_label_frozen jsonb:='{}';access_label_needed boolean;\n access_label_authority_input jsonb;access_label_authority jsonb;\n",
    " access_label_transition jsonb;access_label_frozen jsonb:='{}';access_label_needed boolean;\n"
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
$access_label_role_question_receipt$;
-- +goose StatementEnd

DROP FUNCTION kaname.authority_access_label_role_question_require_v1(text,text,text,text,uuid,integer,integer);
DROP FUNCTION kaname.authority_access_label_role_questions_prepare_v1(jsonb,jsonb,integer,integer);
