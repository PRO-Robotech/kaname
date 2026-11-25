-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_attestation_v1() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $attestation$
DECLARE
    proof jsonb;
    identity jsonb;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    proof:=kaname.authority_protocol_attestation();
    identity:=kaname._authority_role_actor_login_current_v1();
    IF current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
        OR identity IS NULL OR identity->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid'
        OR proof->>'kind' IS DISTINCT FROM 'role' OR proof->>'purpose' IS DISTINCT FROM 'decision'
        OR proof->>'writer_contract' IS DISTINCT FROM '2' OR proof->>'mode' IS DISTINCT FROM 'global'
        OR coalesce(proof->>'nonce','')='' OR proof->>'decision_at' IS NULL THEN
        RAISE EXCEPTION 'selector move requires the signed role writer' USING ERRCODE='42501';
    END IF;
    RETURN proof;
END;
$attestation$;
-- +goose StatementEnd

-- Результат помещается в единственную программу записи роли. Судить
-- полномочия и писать строки по возвращённому образу пока нельзя.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_prepare_checks_v1(
    p_input jsonb,p_actor jsonb,p_rows integer,p_reads integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $prepare$
DECLARE
    proof jsonb;
    role_image jsonb;
    copies jsonb;
    frozen jsonb;
    used_rows integer:=1;
    used_reads integer:=2;
    step_rows integer;
    step_reads integer;
BEGIN
    proof:=kaname._authority_role_move_attestation_v1();
    IF octet_length(p_input::text)>8388608 THEN
        RAISE EXCEPTION 'selector move preparation input exceeds byte budget' USING ERRCODE='54000';
    END IF;
    IF jsonb_typeof(p_input) IS DISTINCT FROM 'object'
        OR p_input-ARRAY['role_id','version','physical','moves','proposed_rules','copy_candidates'] <> '{}'::jsonb
        OR jsonb_typeof(p_input->'role_id') IS DISTINCT FROM 'string'
        OR jsonb_typeof(p_input->'version') IS DISTINCT FROM 'string'
        OR jsonb_typeof(p_actor) IS DISTINCT FROM 'object'
        OR p_actor-ARRAY['type','id'] <> '{}'::jsonb
        OR jsonb_typeof(p_actor->'type') IS DISTINCT FROM 'string'
        OR jsonb_typeof(p_actor->'id') IS DISTINCT FROM 'string' THEN
        RAISE EXCEPTION 'invalid selector move preparation request' USING ERRCODE='42501';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
        RAISE EXCEPTION 'selector move preparation budget exhausted' USING ERRCODE='54000';
    END IF;
    role_image:=kaname._authority_role_move_role_image_hold_v1(p_input->>'role_id',p_input->>'version',
        p_input->'physical',p_input->'moves',p_input->'proposed_rules',p_rows-used_rows,p_reads-used_reads);
    step_rows:=(role_image->>'rows')::integer;
    step_reads:=(role_image->>'reads')::integer;
    IF step_rows IS NULL OR step_rows NOT BETWEEN 1 AND p_rows-used_rows
        OR step_reads IS NULL OR step_reads NOT BETWEEN 1 AND p_reads-used_reads THEN
        RAISE EXCEPTION 'selector move role image budget exhausted' USING ERRCODE='54000';
    END IF;
    used_rows:=used_rows+step_rows;
    used_reads:=used_reads+step_reads;
    copies:=kaname._authority_role_move_copy_requirements_hold_v1(p_input->'copy_candidates',
        p_actor->>'type',p_actor->>'id',p_rows-used_rows,p_reads-used_reads);
    step_rows:=(copies->>'rows')::integer;
    step_reads:=(copies->>'reads')::integer;
    IF step_rows IS NULL OR step_rows NOT BETWEEN 0 AND p_rows-used_rows
        OR step_reads IS NULL OR step_reads NOT BETWEEN 1 AND p_reads-used_reads THEN
        RAISE EXCEPTION 'selector move copy preparation budget exhausted' USING ERRCODE='54000';
    END IF;
    frozen:=jsonb_build_object('role_id',p_input->>'role_id','actor',p_actor,
        'nonce',proof->>'nonce','invoker_oid',proof->>'invoker_oid','prepared_at',proof->>'decision_at',
        'role',role_image-ARRAY['rows','reads'],'copies',copies-ARRAY['rows','reads']);
    IF octet_length(frozen::text)>8388608 THEN
        RAISE EXCEPTION 'prepared selector move exceeds byte budget' USING ERRCODE='54000';
    END IF;
    RETURN jsonb_build_object('frozen',frozen,'rows',used_rows+step_rows,'reads',used_reads+step_reads);
END;
$prepare$;
-- +goose StatementEnd

-- Вызывается владельцем зафиксированной программы после проверки Go и
-- обновления часов. Тот же writer проверяет исходный образ и apply каждого
-- оставшегося ключа. Первый UPDATE допустим только после этого решения.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_require_checks_v1(
    p_frozen jsonb,p_copies jsonb,p_rows integer,p_reads integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $require$
DECLARE
    proof jsonb;
    at_time timestamptz;
    prepared_at timestamptz;
    actual_role_row jsonb;
    root_id text;
    actor jsonb;
    result jsonb;
    used_rows integer:=1;
    used_reads integer:=3;
    step_rows integer;
    step_reads integer;
BEGIN
    proof:=kaname._authority_role_move_attestation_v1();
    IF octet_length(p_frozen::text)>8388608 OR octet_length(p_copies::text)>8388608 THEN
        RAISE EXCEPTION 'selector move decision input exceeds byte budget' USING ERRCODE='54000';
    END IF;
    IF jsonb_typeof(p_frozen) IS DISTINCT FROM 'object'
        OR jsonb_typeof(p_frozen->'prepared_at') IS DISTINCT FROM 'string'
        OR jsonb_typeof(p_frozen->'actor') IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'invalid prepared selector move' USING ERRCODE='42501';
    END IF;
    root_id:=p_frozen->>'role_id';
    actor:=p_frozen->'actor';
    at_time:=(proof->>'decision_at')::timestamptz;
    prepared_at:=(p_frozen->>'prepared_at')::timestamptz;
    IF p_frozen->>'nonce' IS DISTINCT FROM proof->>'nonce'
        OR p_frozen->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid'
        OR (isfinite(prepared_at) AND isfinite(at_time) AND at_time>prepared_at) IS DISTINCT FROM true
        OR coalesce(root_id,'')='' OR jsonb_typeof(p_frozen#>'{role,physical}') IS DISTINCT FROM 'array'
        OR p_frozen#>>'{role,physical,2,id}' IS DISTINCT FROM root_id
        OR p_frozen#>>'{role,new_role,id}' IS DISTINCT FROM root_id
        OR actor IS DISTINCT FROM p_frozen#>'{copies,actor}' THEN
        RAISE EXCEPTION 'selector move decision is outside its prepared transaction' USING ERRCODE='42501';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
        RAISE EXCEPTION 'selector move final check budget exhausted' USING ERRCODE='54000';
    END IF;
    SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r)) INTO actual_role_row
        FROM ONLY kaname.roles r WHERE r.id=root_id;
    IF actual_role_row IS DISTINCT FROM p_frozen#>'{role,physical}' THEN
        RAISE EXCEPTION 'selector move role OLD changed after holding' USING ERRCODE='40001';
    END IF;
    result:=kaname._authority_role_move_copy_requirements_require_v1(p_frozen->'copies',p_copies,
        actor->>'type',actor->>'id',at_time,p_rows-used_rows,p_reads-used_reads);
    IF jsonb_typeof(result->'commands') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'selector move decision omitted write commands' USING ERRCODE='42501';
    END IF;
    IF jsonb_array_length(result->'commands')<>jsonb_array_length(p_copies) THEN
        RAISE EXCEPTION 'selector move commands differ from selected roots' USING ERRCODE='42501';
    END IF;
    step_rows:=(result->>'rows')::integer;
    step_reads:=(result->>'reads')::integer;
    IF step_rows IS NULL OR step_rows NOT BETWEEN 0 AND p_rows-used_rows
        OR step_reads IS NULL OR step_reads NOT BETWEEN 1 AND p_reads-used_reads THEN
        RAISE EXCEPTION 'selector move final key check budget exhausted' USING ERRCODE='54000';
    END IF;
    RETURN jsonb_build_object('role_id',root_id,'actor',actor,'decision_at',at_time,
        'commands',result->'commands','rows',used_rows+step_rows,'reads',used_reads+step_reads);
END;
$require$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE
    signature text;
    grantee record;
BEGIN
    FOREACH signature IN ARRAY ARRAY[
        'kaname._authority_role_move_attestation_v1()',
        'kaname._authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)',
        'kaname._authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer)'
    ] LOOP
        FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
            WHERE p.oid=to_regprocedure(signature) AND a.grantee<>p.proowner
        LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',signature,
                CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_role_move_require_checks_v1(jsonb,jsonb,integer,integer);
DROP FUNCTION kaname._authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer);
DROP FUNCTION kaname._authority_role_move_attestation_v1();
