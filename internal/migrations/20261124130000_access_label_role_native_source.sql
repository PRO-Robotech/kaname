-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Сверяет версию источника apply и точный вопрос до первой записи роли.

-- +goose Up
SELECT kaname.authority_protocol_drain();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_source_check_v2(
    p_actor_type text, p_actor_id text,
    p_scope_kind text, p_scope_id text, p_definition uuid,
    p_binding_id text, p_recipient_type text, p_recipient_id text,
    p_rule_fp text, p_decision_at timestamptz, p_rows integer,
    p_source_role_id text,p_binding_xmin text,p_binding_ctid text,p_role_xmin text,p_role_ctid text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    source_found boolean;
    stamps_current boolean;
    strict_stamps boolean := num_nonnulls(p_source_role_id,p_binding_xmin,p_binding_ctid,p_role_xmin,p_role_ctid)>0;
    rules_bytes integer;
    compiled_count integer;
    origin_current boolean;
    -- По точным ключам: actor, definition, binding, subject, role, origin,
    -- membership и group. Для прямого получателя это безопасный overcharge.
    source_rows constant integer := 8;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF current_setting('transaction_isolation')<>'read committed' THEN
        RAISE EXCEPTION 'native access label source requires READ COMMITTED'
            USING ERRCODE='25001';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN source_rows AND 100000 THEN
        RAISE EXCEPTION 'native access label source row budget is absent'
            USING ERRCODE='54000';
    END IF;
    IF p_actor_type IS NULL OR p_actor_type NOT IN ('user','service_account')
       OR coalesce(p_actor_id,'')='' OR p_actor_id ~ '[*#:]'
       OR p_recipient_type IS NULL OR p_recipient_type NOT IN ('user','service_account','group')
       OR coalesce(p_recipient_id,'')='' OR p_recipient_id ~ '[*#:]'
       OR coalesce(p_binding_id,'')='' OR p_decision_at IS NULL OR NOT isfinite(p_decision_at)
       OR p_definition IS NULL OR p_definition='00000000-0000-0000-0000-000000000000'::uuid
       OR p_rule_fp IS NULL OR p_rule_fp COLLATE "C" !~ '^[0-9a-f]{64}$'
       OR p_scope_kind IS NULL OR p_scope_kind NOT IN ('cluster','account','project')
       OR coalesce(p_scope_id,'')='' THEN
        RAISE EXCEPTION 'invalid exact access label source question'
            USING ERRCODE='23514';
    END IF;

    IF strict_stamps AND (
       num_nonnulls(p_source_role_id,p_binding_xmin,p_binding_ctid,p_role_xmin,p_role_ctid)<>5
       OR coalesce(p_source_role_id,'')='' OR p_source_role_id ~ '[:#*[:space:][:cntrl:]]'
       OR p_binding_xmin !~ '^[1-9][0-9]{0,9}$' OR p_role_xmin !~ '^[1-9][0-9]{0,9}$'
       OR p_binding_ctid !~ '^\([0-9]+,[1-9][0-9]*\)$' OR p_role_ctid !~ '^\([0-9]+,[1-9][0-9]*\)$'
    ) THEN RAISE EXCEPTION 'exact access label source stamps are incomplete' USING ERRCODE='23514';END IF;

    -- Вся положительная цепочка и сверка authored origin читаются одним
    -- оператором. Нет relation_fact, admin, wildcard или наследования scope.
    WITH source_identity AS MATERIALIZED (
        SELECT b.id,b.resource_type,b.resource_id,b.status,b.revoked_at,
               b.grant_capability_version,b.expires_at,b.target,
               r.id AS role_id,r.live,r.rules,
               (NOT strict_stamps OR (r.id=p_source_role_id
                AND b.xmin::text=p_binding_xmin AND b.ctid::text=p_binding_ctid
                AND r.xmin::text=p_role_xmin AND r.ctid::text=p_role_ctid)) AS stamps_match
        FROM kaname.access_bindings b JOIN kaname.roles r ON r.id=b.role_id
        WHERE b.id=p_binding_id
    ), source AS MATERIALIZED (
        SELECT b.rules,octet_length(b.rules::text) AS bytes
        FROM source_identity b
        JOIN kaname.access_binding_subjects s ON s.binding_id=b.id
            AND s.subject_type=p_recipient_type AND s.subject_id=p_recipient_id
            AND s.resource_type=p_scope_kind AND s.resource_id=p_scope_id
        JOIN kaname.authority_role_access_label_rule a ON a.role_id=b.role_id
            AND a.rule_fp=p_rule_fp AND a.definition_id=p_definition
        JOIN kaname.authority_access_label_definition d ON d.id=a.definition_id
            AND d.scope_kind=p_scope_kind AND d.scope_id=p_scope_id
        WHERE b.live AND b.stamps_match AND b.resource_type=p_scope_kind AND b.resource_id=p_scope_id
            AND b.status='ACTIVE' AND b.revoked_at IS NULL AND b.grant_capability_version=1
            AND (b.expires_at IS NULL OR b.expires_at>p_decision_at)
            AND ((jsonb_typeof(b.target)='object' AND NOT (b.target ? 'resources'))
                OR b.target->'resources'='[]'::jsonb)
            AND ((p_actor_type='user' AND EXISTS(SELECT 1 FROM kaname.users u WHERE u.id=p_actor_id AND u.email_verified_at IS NOT NULL))
                OR (p_actor_type='service_account' AND EXISTS(
                    SELECT 1 FROM kaname.service_accounts u WHERE u.id=p_actor_id AND u.enabled)))
            AND ((p_recipient_type=p_actor_type AND p_recipient_id=p_actor_id)
                OR (p_recipient_type='group' AND EXISTS(
                    SELECT 1 FROM kaname.group_members m JOIN kaname.groups g ON g.id=m.group_id
                    WHERE m.group_id=p_recipient_id AND m.member_type=p_actor_type AND m.member_id=p_actor_id)))
    ), compiled AS MATERIALIZED (
        -- Compiler сам ограничивает 64 rules * 256 origins и 1024 permissions.
        -- Сверх оставшегося бюджета читается sentinel; положительный origin
        -- в усечённом наборе никогда не даёт true.
        SELECT c.rule_fp,c.definition_id FROM source s
        CROSS JOIN LATERAL kaname.authority_access_label_role_compile_v1(
            CASE WHEN s.bytes<=8388608 THEN s.rules ELSE '[]'::jsonb END) c
        LIMIT least(16384,p_rows-source_rows)+1
    )
    SELECT EXISTS(SELECT 1 FROM source),
        coalesce((SELECT s.bytes FROM source s),0),
        (SELECT count(*)::integer FROM compiled),
        EXISTS(SELECT 1 FROM compiled c WHERE c.rule_fp=p_rule_fp AND c.definition_id=p_definition),
        coalesce((SELECT b.stamps_match FROM source_identity b),true)
    INTO source_found,rules_bytes,compiled_count,origin_current,stamps_current;

    IF NOT stamps_current THEN
        RAISE EXCEPTION 'exact access label source physical generation changed' USING ERRCODE='40001';
    END IF;

    IF rules_bytes>8388608 OR compiled_count>16384 OR source_rows+compiled_count>p_rows THEN
        RAISE EXCEPTION 'native access label source bound exceeded' USING ERRCODE='54000';
    END IF;
    IF source_found AND NOT origin_current THEN
        RAISE EXCEPTION 'native access label stored origin differs from current role'
            USING ERRCODE='40001';
    END IF;
    RETURN jsonb_build_object('allowed',source_found AND origin_current,
        'rows',source_rows+compiled_count,'reads',2);
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_role_access_label_source_check_v1(
 p_mutation_role_id text,p_actor_type text,p_actor_id text,p_decision_at timestamptz,
 p_binding_id text,p_binding_xmin text,p_binding_ctid text,
 p_source_role_id text,p_source_role_xmin text,p_source_role_ctid text,
 p_recipient_type text,p_recipient_id text,p_scope_kind text,p_scope_id text,
 p_definition uuid,p_source_rule_fp text,p_checkpoint jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 question jsonb;
 definition_check jsonb;
 source_check jsonb;
 used_rows integer:=0;
 used_reads integer:=0;
 receipt_clock timestamptz;
 frozen_role_id text;
 current_model text;
 current_projector text;
 program_clock timestamptz;
 root_untouched boolean;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'role access label source requires READ COMMITTED' USING ERRCODE='25001';END IF;
 -- question 2/2 + private header/attestation/root 3/1 + definition 2/3
 -- + minimum source 8/2. All nested calls share these same remainders.
 IF p_rows IS NULL OR p_rows NOT BETWEEN 15 AND 100000
 OR p_reads IS NULL OR p_reads NOT BETWEEN 8 AND 4096 THEN
  RAISE EXCEPTION 'role access label source budget absent' USING ERRCODE='54000';END IF;
 IF p_decision_at IS NULL OR NOT isfinite(p_decision_at)
 OR coalesce(p_mutation_role_id,'')='' OR p_mutation_role_id ~ '[:#*[:space:][:cntrl:]]'
 OR coalesce(p_source_role_id,'')='' OR p_source_role_id ~ '[:#*[:space:][:cntrl:]]'
 OR coalesce(p_binding_id,'')='' OR p_binding_id ~ '[:#*[:space:][:cntrl:]]'
 OR num_nonnulls(p_binding_xmin,p_binding_ctid,p_source_role_xmin,p_source_role_ctid)<>4 THEN
  RAISE EXCEPTION 'role access label source input incomplete' USING ERRCODE='23514';END IF;
 IF jsonb_typeof(p_checkpoint) IS DISTINCT FROM 'object'
 OR p_checkpoint-ARRAY['AuthoredID','RelevantCatalogID','ProjectionID','ModelID','ProjectorVersion']<>'{}'::jsonb
 OR jsonb_typeof(p_checkpoint->'AuthoredID') IS DISTINCT FROM 'string'
 OR jsonb_typeof(p_checkpoint->'RelevantCatalogID') IS DISTINCT FROM 'string'
 OR jsonb_typeof(p_checkpoint->'ProjectionID') IS DISTINCT FROM 'string'
 OR jsonb_typeof(p_checkpoint->'ModelID') IS DISTINCT FROM 'string'
 OR jsonb_typeof(p_checkpoint->'ProjectorVersion') IS DISTINCT FROM 'string'
 OR (p_checkpoint->>'AuthoredID') COLLATE "C" !~ '^[0-9a-f]{64}$'
 OR (p_checkpoint->>'RelevantCatalogID') COLLATE "C" !~ '^[0-9a-f]{64}$'
 OR (p_checkpoint->>'ProjectionID') COLLATE "C" !~ '^[0-9a-f]{64}$'
 OR octet_length(p_checkpoint::text)>4096 THEN
  RAISE EXCEPTION 'role access label checkpoint shape invalid' USING ERRCODE='23514';END IF;

 question:=kaname.authority_access_label_role_question_require_v1(
  p_actor_type,p_actor_id,p_scope_kind,p_scope_id,p_definition,p_rows,p_reads);
 used_rows:=(question->>'rows')::integer;used_reads:=(question->>'reads')::integer;
 receipt_clock:=(question->>'decision_at')::timestamptz;
 IF receipt_clock IS DISTINCT FROM p_decision_at OR used_rows IS DISTINCT FROM 2 OR used_reads IS DISTINCT FROM 2 THEN
  RAISE EXCEPTION 'role access label final clock differs' USING ERRCODE='42501';END IF;

 -- question_require already attests ownership/nonce/ABI of these temp tables.
 -- First role DML is the closed role-program ordinal 1; require all state bits
 -- untouched, not merely the absence of an applied projection marker.
 SELECT s.frozen#>>'{access_label_transition,role_id}',s.decision_at,
        a.model_id,a.projector_version,
        e.selected AND NOT e.registered AND NOT e.claimed AND NOT e.consumed
         AND e.table_name='resource_journal' AND e.origin->>'table'='roles'
 INTO frozen_role_id,program_clock,current_model,current_projector,root_untouched
 FROM pg_temp.kaname_authority_sequence_program s
 JOIN pg_temp.kaname_authority_attestation a ON a.singleton AND a.nonce=s.nonce
 LEFT JOIN pg_temp.kaname_authority_sequence_effects e ON e.ordinal=1 AND e.nonce=s.nonce
 WHERE s.singleton AND s.family='role' AND s.frozen->>'kind'='role.mutation'
  AND NOT (s.frozen ? 'access_label_transition_applied');
 used_rows:=used_rows+3;used_reads:=used_reads+1;
 IF NOT FOUND OR frozen_role_id IS DISTINCT FROM p_mutation_role_id
 OR program_clock IS DISTINCT FROM receipt_clock OR root_untouched IS DISTINCT FROM true
 OR p_checkpoint->>'ModelID' IS DISTINCT FROM current_model
 OR p_checkpoint->>'ProjectorVersion' IS DISTINCT FROM current_projector THEN
  RAISE EXCEPTION 'role access label program identity or pre-DML state differs' USING ERRCODE='42501';END IF;

 definition_check:=kaname.authority_access_label_prepared_definition_v1(
  p_scope_kind,p_scope_id,p_definition,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+(definition_check->>'rows')::integer;
 used_reads:=used_reads+(definition_check->>'reads')::integer;
 IF definition_check->'matched' IS DISTINCT FROM 'true'::jsonb
 OR (definition_check->>'decision_at')::timestamptz IS DISTINCT FROM receipt_clock THEN
  RAISE EXCEPTION 'role access label held definition changed' USING ERRCODE='40001';END IF;
 IF used_rows IS DISTINCT FROM 7 OR used_reads IS DISTINCT FROM 6 THEN
  RAISE EXCEPTION 'role access label nested definition cost differs' USING ERRCODE='54000';END IF;

 -- Checkpoint hashes are computational evidence checked by the Go source reader;
 -- they are NOT caller-provided authority. SQL independently checks the exact
 -- current authored origin and physical source generations in one statement.
 source_check:=kaname._authority_access_label_source_check_v2(
  p_actor_type,p_actor_id,p_scope_kind,p_scope_id,p_definition,
  p_binding_id,p_recipient_type,p_recipient_id,p_source_rule_fp,receipt_clock,p_rows-used_rows,
  p_source_role_id,p_binding_xmin,p_binding_ctid,p_source_role_xmin,p_source_role_ctid);
 IF jsonb_typeof(source_check->'allowed') IS DISTINCT FROM 'boolean'
 OR coalesce((source_check->>'rows')::integer,-1)<8
 OR (source_check->>'reads')::integer IS DISTINCT FROM 2 THEN
  RAISE EXCEPTION 'role access label source cost invalid' USING ERRCODE='54000';END IF;
 used_rows:=used_rows+(source_check->>'rows')::integer;
 used_reads:=used_reads+(source_check->>'reads')::integer;
 IF used_rows>p_rows OR used_reads>p_reads THEN
  RAISE EXCEPTION 'role access label shared source budget exceeded' USING ERRCODE='54000';END IF;
 RETURN jsonb_build_object('allowed',source_check->'allowed','rows',used_rows,'reads',used_reads);
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
DECLARE signature text;grantee record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 FOREACH signature IN ARRAY ARRAY[
  '_authority_access_label_source_check_v2(text,text,text,text,uuid,text,text,text,text,timestamptz,integer,text,text,text,text,text)',
  'authority_access_label_source_check_v1(text,text,text,text,uuid,text,text,text,text,timestamptz,integer)',
  'authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)'
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
DO $access_label_role_native_source$
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
        RAISE EXCEPTION 'несогласованное состояние перед изменением проверки исходной привязки accessLabels' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        (
            'authority_access_label_source_check_v1(text,text,text,text,uuid,text,text,text,text,timestamptz,integer)',
            '282382e8b48680378f219ab1ae787d36125d4a4f8f8b69c08fbc003940e65639',
            '76cbe736802a28435837932b5d851a8c45987bfafac29910b58a420ebc005369',
            $patch$[
  [
    "\nDECLARE\n    source_found boolean;\n    rules_bytes integer;\n    compiled_count integer;\n    origin_current boolean;\n    -- По точным ключам: actor, definition, binding, subject, role, origin,\n    -- membership и group. Для прямого получателя это безопасный overcharge.\n    source_rows constant integer := 8;\nBEGIN\n    PERFORM kaname.authority_protocol_require_owner();\n    IF current_setting('transaction_isolation')<>'read committed' THEN\n        RAISE EXCEPTION 'native access label source requires READ COMMITTED'\n            USING ERRCODE='25001';\n    END IF;\n    IF p_rows IS NULL OR p_rows NOT BETWEEN source_rows AND 100000 THEN\n        RAISE EXCEPTION 'native access label source row budget is absent'\n            USING ERRCODE='54000';\n    END IF;\n    IF p_actor_type IS NULL OR p_actor_type NOT IN ('user','service_account')\n       OR coalesce(p_actor_id,'')='' OR p_actor_id ~ '[*#:]'\n       OR p_recipient_type IS NULL OR p_recipient_type NOT IN ('user','service_account','group')\n       OR coalesce(p_recipient_id,'')='' OR p_recipient_id ~ '[*#:]'\n       OR coalesce(p_binding_id,'')='' OR p_decision_at IS NULL OR NOT isfinite(p_decision_at)\n       OR p_definition IS NULL OR p_definition='00000000-0000-0000-0000-000000000000'::uuid\n       OR p_rule_fp IS NULL OR p_rule_fp COLLATE \"C\" !~ '^[0-9a-f]{64}$'\n       OR p_scope_kind IS NULL OR p_scope_kind NOT IN ('cluster','account','project')\n       OR coalesce(p_scope_id,'')='' THEN\n        RAISE EXCEPTION 'invalid exact access label source question'\n            USING ERRCODE='23514';\n    END IF;\n\n    -- Вся положительная цепочка и сверка authored origin читаются одним\n    -- оператором. Нет relation_fact, admin, wildcard или наследования scope.\n    WITH source AS MATERIALIZED (\n        SELECT r.rules,octet_length(r.rules::text) AS bytes\n        FROM kaname.access_bindings b\n        JOIN kaname.access_binding_subjects s ON s.binding_id=b.id\n            AND s.subject_type=p_recipient_type AND s.subject_id=p_recipient_id\n            AND s.resource_type=p_scope_kind AND s.resource_id=p_scope_id\n        JOIN kaname.roles r ON r.id=b.role_id AND r.live\n        JOIN kaname.authority_role_access_label_rule a ON a.role_id=r.id\n            AND a.rule_fp=p_rule_fp AND a.definition_id=p_definition\n        JOIN kaname.authority_access_label_definition d ON d.id=a.definition_id\n            AND d.scope_kind=p_scope_kind AND d.scope_id=p_scope_id\n        WHERE b.id=p_binding_id AND b.resource_type=p_scope_kind AND b.resource_id=p_scope_id\n            AND b.status='ACTIVE' AND b.revoked_at IS NULL AND b.grant_capability_version=1\n            AND (b.expires_at IS NULL OR b.expires_at>p_decision_at)\n            AND ((jsonb_typeof(b.target)='object' AND NOT (b.target ? 'resources'))\n                OR b.target->'resources'='[]'::jsonb)\n            AND ((p_actor_type='user' AND EXISTS(SELECT 1 FROM kaname.users u WHERE u.id=p_actor_id AND u.email_verified_at IS NOT NULL))\n                OR (p_actor_type='service_account' AND EXISTS(\n                    SELECT 1 FROM kaname.service_accounts u WHERE u.id=p_actor_id AND u.enabled)))\n            AND ((p_recipient_type=p_actor_type AND p_recipient_id=p_actor_id)\n                OR (p_recipient_type='group' AND EXISTS(\n                    SELECT 1 FROM kaname.group_members m JOIN kaname.groups g ON g.id=m.group_id\n                    WHERE m.group_id=p_recipient_id AND m.member_type=p_actor_type AND m.member_id=p_actor_id)))\n    ), compiled AS MATERIALIZED (\n        -- Compiler сам ограничивает 64 rules * 256 origins и 1024 permissions.\n        -- Сверх оставшегося бюджета читается sentinel; положительный origin\n        -- в усечённом наборе никогда не даёт true.\n        SELECT c.rule_fp,c.definition_id FROM source s\n        CROSS JOIN LATERAL kaname.authority_access_label_role_compile_v1(\n            CASE WHEN s.bytes<=8388608 THEN s.rules ELSE '[]'::jsonb END) c\n        LIMIT least(16384,p_rows-source_rows)+1\n    )\n    SELECT EXISTS(SELECT 1 FROM source),\n        coalesce((SELECT s.bytes FROM source s),0),\n        (SELECT count(*)::integer FROM compiled),\n        EXISTS(SELECT 1 FROM compiled c WHERE c.rule_fp=p_rule_fp AND c.definition_id=p_definition)\n    INTO source_found,rules_bytes,compiled_count,origin_current;\n\n    IF rules_bytes>8388608 OR compiled_count>16384 OR source_rows+compiled_count>p_rows THEN\n        RAISE EXCEPTION 'native access label source bound exceeded' USING ERRCODE='54000';\n    END IF;\n    IF source_found AND NOT origin_current THEN\n        RAISE EXCEPTION 'native access label stored origin differs from current role'\n            USING ERRCODE='40001';\n    END IF;\n    RETURN jsonb_build_object('allowed',source_found AND origin_current,\n        'rows',source_rows+compiled_count,'reads',2);\nEND;\n",
    "\nBEGIN\n RETURN kaname._authority_access_label_source_check_v2(\n  p_actor_type,p_actor_id,p_scope_kind,p_scope_id,p_definition,\n  p_binding_id,p_recipient_type,p_recipient_id,p_rule_fp,p_decision_at,p_rows,\n  NULL,NULL,NULL,NULL,NULL);\nEND;\n"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            '093014807621e110f3f3e3da382992686f03739d0723480a5d16592d47e1ce5d',
            '77b29d98128a5eaa20f2ea2667f30b3e38c591f985a42375377834850db08d65',
            $patch$[
  [
    " ('authority_access_label_source_check_v1(text,text,text,text,uuid,text,text,text,text,timestamptz,integer)','282382e8b48680378f219ab1ae787d36125d4a4f8f8b69c08fbc003940e65639',false,'v',true,'private'),",
    " ('authority_access_label_source_check_v1(text,text,text,text,uuid,text,text,text,text,timestamptz,integer)','76cbe736802a28435837932b5d851a8c45987bfafac29910b58a420ebc005369',false,'v',true,'private'),"
  ],
  [
    " ('authority_access_label_role_question_require_v1(text,text,text,text,uuid,integer,integer)','a5b7081e9cd8901c88132ba503e9006923c21fca16d366913de540bb8e11cd3c',false,'v',true,'private'),",
    " ('authority_access_label_role_question_require_v1(text,text,text,text,uuid,integer,integer)','a5b7081e9cd8901c88132ba503e9006923c21fca16d366913de540bb8e11cd3c',false,'v',true,'private'),\n ('_authority_access_label_source_check_v2(text,text,text,text,uuid,text,text,text,text,timestamptz,integer,text,text,text,text,text)','7dfb81c8f43cba03edb3de4d6d60280912063063e51b2d57cb24a5ae2629548c',false,'v',true,'private'),\n ('authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','4f6d03c973e37e47f69f32e96d0bf7ffc028bb53d3ff54ade7f7b12ea27430c1',false,'v',true,'private'),"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_full_contract_storage_v3()',
            '8268ab7fff7f48f31ffeb6211b709f65289428fd4653fc523605236783406547',
            'eb0f1c8bd66d618d83f6a9125ccbab22038e6c47c91bd1bcbf806e768006a7e8',
            $patch$[
  [
    "093014807621e110f3f3e3da382992686f03739d0723480a5d16592d47e1ce5d",
    "77b29d98128a5eaa20f2ea2667f30b3e38c591f985a42375377834850db08d65"
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
$access_label_role_native_source$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();

-- +goose StatementBegin
DO $access_label_role_native_source$
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
        RAISE EXCEPTION 'несогласованное состояние перед изменением проверки исходной привязки accessLabels' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        (
            '_authority_full_contract_storage_v3()',
            'eb0f1c8bd66d618d83f6a9125ccbab22038e6c47c91bd1bcbf806e768006a7e8',
            '8268ab7fff7f48f31ffeb6211b709f65289428fd4653fc523605236783406547',
            $patch$[
  [
    "77b29d98128a5eaa20f2ea2667f30b3e38c591f985a42375377834850db08d65",
    "093014807621e110f3f3e3da382992686f03739d0723480a5d16592d47e1ce5d"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            '77b29d98128a5eaa20f2ea2667f30b3e38c591f985a42375377834850db08d65',
            '093014807621e110f3f3e3da382992686f03739d0723480a5d16592d47e1ce5d',
            $patch$[
  [
    " ('authority_access_label_role_question_require_v1(text,text,text,text,uuid,integer,integer)','a5b7081e9cd8901c88132ba503e9006923c21fca16d366913de540bb8e11cd3c',false,'v',true,'private'),\n ('_authority_access_label_source_check_v2(text,text,text,text,uuid,text,text,text,text,timestamptz,integer,text,text,text,text,text)','7dfb81c8f43cba03edb3de4d6d60280912063063e51b2d57cb24a5ae2629548c',false,'v',true,'private'),\n ('authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','4f6d03c973e37e47f69f32e96d0bf7ffc028bb53d3ff54ade7f7b12ea27430c1',false,'v',true,'private'),",
    " ('authority_access_label_role_question_require_v1(text,text,text,text,uuid,integer,integer)','a5b7081e9cd8901c88132ba503e9006923c21fca16d366913de540bb8e11cd3c',false,'v',true,'private'),"
  ],
  [
    " ('authority_access_label_source_check_v1(text,text,text,text,uuid,text,text,text,text,timestamptz,integer)','76cbe736802a28435837932b5d851a8c45987bfafac29910b58a420ebc005369',false,'v',true,'private'),",
    " ('authority_access_label_source_check_v1(text,text,text,text,uuid,text,text,text,text,timestamptz,integer)','282382e8b48680378f219ab1ae787d36125d4a4f8f8b69c08fbc003940e65639',false,'v',true,'private'),"
  ]
]$patch$::jsonb
        ),
        (
            'authority_access_label_source_check_v1(text,text,text,text,uuid,text,text,text,text,timestamptz,integer)',
            '76cbe736802a28435837932b5d851a8c45987bfafac29910b58a420ebc005369',
            '282382e8b48680378f219ab1ae787d36125d4a4f8f8b69c08fbc003940e65639',
            $patch$[
  [
    "\nBEGIN\n RETURN kaname._authority_access_label_source_check_v2(\n  p_actor_type,p_actor_id,p_scope_kind,p_scope_id,p_definition,\n  p_binding_id,p_recipient_type,p_recipient_id,p_rule_fp,p_decision_at,p_rows,\n  NULL,NULL,NULL,NULL,NULL);\nEND;\n",
    "\nDECLARE\n    source_found boolean;\n    rules_bytes integer;\n    compiled_count integer;\n    origin_current boolean;\n    -- По точным ключам: actor, definition, binding, subject, role, origin,\n    -- membership и group. Для прямого получателя это безопасный overcharge.\n    source_rows constant integer := 8;\nBEGIN\n    PERFORM kaname.authority_protocol_require_owner();\n    IF current_setting('transaction_isolation')<>'read committed' THEN\n        RAISE EXCEPTION 'native access label source requires READ COMMITTED'\n            USING ERRCODE='25001';\n    END IF;\n    IF p_rows IS NULL OR p_rows NOT BETWEEN source_rows AND 100000 THEN\n        RAISE EXCEPTION 'native access label source row budget is absent'\n            USING ERRCODE='54000';\n    END IF;\n    IF p_actor_type IS NULL OR p_actor_type NOT IN ('user','service_account')\n       OR coalesce(p_actor_id,'')='' OR p_actor_id ~ '[*#:]'\n       OR p_recipient_type IS NULL OR p_recipient_type NOT IN ('user','service_account','group')\n       OR coalesce(p_recipient_id,'')='' OR p_recipient_id ~ '[*#:]'\n       OR coalesce(p_binding_id,'')='' OR p_decision_at IS NULL OR NOT isfinite(p_decision_at)\n       OR p_definition IS NULL OR p_definition='00000000-0000-0000-0000-000000000000'::uuid\n       OR p_rule_fp IS NULL OR p_rule_fp COLLATE \"C\" !~ '^[0-9a-f]{64}$'\n       OR p_scope_kind IS NULL OR p_scope_kind NOT IN ('cluster','account','project')\n       OR coalesce(p_scope_id,'')='' THEN\n        RAISE EXCEPTION 'invalid exact access label source question'\n            USING ERRCODE='23514';\n    END IF;\n\n    -- Вся положительная цепочка и сверка authored origin читаются одним\n    -- оператором. Нет relation_fact, admin, wildcard или наследования scope.\n    WITH source AS MATERIALIZED (\n        SELECT r.rules,octet_length(r.rules::text) AS bytes\n        FROM kaname.access_bindings b\n        JOIN kaname.access_binding_subjects s ON s.binding_id=b.id\n            AND s.subject_type=p_recipient_type AND s.subject_id=p_recipient_id\n            AND s.resource_type=p_scope_kind AND s.resource_id=p_scope_id\n        JOIN kaname.roles r ON r.id=b.role_id AND r.live\n        JOIN kaname.authority_role_access_label_rule a ON a.role_id=r.id\n            AND a.rule_fp=p_rule_fp AND a.definition_id=p_definition\n        JOIN kaname.authority_access_label_definition d ON d.id=a.definition_id\n            AND d.scope_kind=p_scope_kind AND d.scope_id=p_scope_id\n        WHERE b.id=p_binding_id AND b.resource_type=p_scope_kind AND b.resource_id=p_scope_id\n            AND b.status='ACTIVE' AND b.revoked_at IS NULL AND b.grant_capability_version=1\n            AND (b.expires_at IS NULL OR b.expires_at>p_decision_at)\n            AND ((jsonb_typeof(b.target)='object' AND NOT (b.target ? 'resources'))\n                OR b.target->'resources'='[]'::jsonb)\n            AND ((p_actor_type='user' AND EXISTS(SELECT 1 FROM kaname.users u WHERE u.id=p_actor_id AND u.email_verified_at IS NOT NULL))\n                OR (p_actor_type='service_account' AND EXISTS(\n                    SELECT 1 FROM kaname.service_accounts u WHERE u.id=p_actor_id AND u.enabled)))\n            AND ((p_recipient_type=p_actor_type AND p_recipient_id=p_actor_id)\n                OR (p_recipient_type='group' AND EXISTS(\n                    SELECT 1 FROM kaname.group_members m JOIN kaname.groups g ON g.id=m.group_id\n                    WHERE m.group_id=p_recipient_id AND m.member_type=p_actor_type AND m.member_id=p_actor_id)))\n    ), compiled AS MATERIALIZED (\n        -- Compiler сам ограничивает 64 rules * 256 origins и 1024 permissions.\n        -- Сверх оставшегося бюджета читается sentinel; положительный origin\n        -- в усечённом наборе никогда не даёт true.\n        SELECT c.rule_fp,c.definition_id FROM source s\n        CROSS JOIN LATERAL kaname.authority_access_label_role_compile_v1(\n            CASE WHEN s.bytes<=8388608 THEN s.rules ELSE '[]'::jsonb END) c\n        LIMIT least(16384,p_rows-source_rows)+1\n    )\n    SELECT EXISTS(SELECT 1 FROM source),\n        coalesce((SELECT s.bytes FROM source s),0),\n        (SELECT count(*)::integer FROM compiled),\n        EXISTS(SELECT 1 FROM compiled c WHERE c.rule_fp=p_rule_fp AND c.definition_id=p_definition)\n    INTO source_found,rules_bytes,compiled_count,origin_current;\n\n    IF rules_bytes>8388608 OR compiled_count>16384 OR source_rows+compiled_count>p_rows THEN\n        RAISE EXCEPTION 'native access label source bound exceeded' USING ERRCODE='54000';\n    END IF;\n    IF source_found AND NOT origin_current THEN\n        RAISE EXCEPTION 'native access label stored origin differs from current role'\n            USING ERRCODE='40001';\n    END IF;\n    RETURN jsonb_build_object('allowed',source_found AND origin_current,\n        'rows',source_rows+compiled_count,'reads',2);\nEND;\n"
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
$access_label_role_native_source$;
-- +goose StatementEnd

DROP FUNCTION kaname.authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer);
DROP FUNCTION kaname._authority_access_label_source_check_v2(text,text,text,text,uuid,text,text,text,text,timestamptz,integer,text,text,text,text,text);
