-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Подготовка под одним владельцем и в общем бюджете. Копии из RR остаются
-- предложением: каждый физический root и определение подтверждает сервер.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_copy_requirements_hold_v1(
    p_plan jsonb,p_actor_type text,p_actor_id text,p_rows integer,p_reads integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $hold$
DECLARE
    root jsonb;
    held jsonb;
    root_keys text[]:=ARRAY[]::text[];
    root_receipts jsonb[]:=ARRAY[]::jsonb[];
    roots jsonb;
    receipt jsonb;
    prior_coordinate text;
    used_bytes integer:=0;
    root_type text;
    root_id text;
    coordinate text;
    step_rows integer;
    step_reads integer;
    used_rows integer;
    used_reads integer:=1;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
        OR jsonb_typeof(p_plan) IS DISTINCT FROM 'array'
        OR octet_length(p_plan::text)>8388608
        OR p_actor_type IS NULL OR p_actor_type NOT IN ('user','service_account')
        OR coalesce(p_actor_id,'')='' OR octet_length(p_actor_id)>16384
        OR p_actor_id ~ '[:#*[:space:][:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid selector move copy proposal' USING ERRCODE='42501';
    END IF;
    used_rows:=jsonb_array_length(p_plan);
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
        RAISE EXCEPTION 'selector move copy capture budget exhausted' USING ERRCODE='54000';
    END IF;

    FOR root IN SELECT x.value FROM jsonb_array_elements(p_plan) x
        ORDER BY (x.value->>'root_type') COLLATE "C",(x.value->>'root_id') COLLATE "C"
    LOOP
        root_type:=root->>'root_type';
        root_id:=root->>'root_id';
        IF jsonb_typeof(root) IS DISTINCT FROM 'object'
            OR root-ARRAY['root_type','root_id','physical','new_access_labels'] <> '{}'::jsonb
            OR coalesce(root_type,'')='' OR root_type ~ '[:#*[:space:][:cntrl:]]'
            OR coalesce(root_id,'')='' OR root_id ~ '[:#*[:space:][:cntrl:]]' THEN
            RAISE EXCEPTION 'invalid selector move copy coordinate' USING ERRCODE='42501';
        END IF;
        coordinate:=root_type||':'||root_id;
        IF coordinate=prior_coordinate THEN
            RAISE EXCEPTION 'duplicate selector move copy coordinate' USING ERRCODE='42501';
        END IF;
        IF root_type IN ('iam.account','iam.project','iam.serviceAccount') THEN
            held:=kaname._authority_role_move_iam_copy_sources_hold_v1(root_type,root_id,
                root->'physical',root->'new_access_labels',p_actor_type,p_actor_id,p_rows-used_rows,p_reads-used_reads);
        ELSE
            held:=kaname._authority_role_move_external_copy_sources_hold_v1(root_type,root_id,
                root->'physical',root->'new_access_labels',p_actor_type,p_actor_id,p_rows-used_rows,p_reads-used_reads);
        END IF;
        step_rows:=(held->>'rows')::integer;
        step_reads:=(held->>'reads')::integer;
        IF step_rows IS NULL OR step_rows NOT BETWEEN 1 AND p_rows-used_rows
            OR step_reads IS NULL OR step_reads NOT BETWEEN 1 AND p_reads-used_reads THEN
            RAISE EXCEPTION 'selector move copy capture budget exhausted' USING ERRCODE='54000';
        END IF;
        used_rows:=used_rows+step_rows;
        used_reads:=used_reads+step_reads;
        -- Буфер растёт линейно. Повторная сборка jsonb-карты на каждый
        -- объект делала бы полную перепись квадратичной.
        used_bytes:=used_bytes+octet_length(held::text)+octet_length(coordinate)+8;
        IF used_bytes>8388608 THEN
            RAISE EXCEPTION 'selector move copy receipt exceeds byte budget' USING ERRCODE='54000';
        END IF;
        prior_coordinate:=coordinate;
        root_keys:=array_append(root_keys,coordinate);
        root_receipts:=array_append(root_receipts,held);
    END LOOP;
    SELECT coalesce(jsonb_object_agg(t.key,t.receipt),'{}'::jsonb) INTO roots
    FROM unnest(root_keys,root_receipts) AS t(key,receipt);
    receipt:=jsonb_build_object('actor',jsonb_build_object('type',p_actor_type,'id',p_actor_id),
        'backend_pid',pg_backend_pid(),'txid',pg_current_xact_id()::text,'held_at',clock_timestamp(),
        'roots',roots,'rows',used_rows,'reads',used_reads);
    IF octet_length(receipt::text)>8388608 THEN
        RAISE EXCEPTION 'selector move copy receipt exceeds byte budget' USING ERRCODE='54000';
    END IF;
    RETURN receipt;
END;
$hold$;
-- +goose StatementEnd

-- Вызывается закрытой программой роли с её зафиксированной квитанцией и
-- пересчитанными по финальным часам копиями. Истёкшая выдача может только
-- убрать объект или ключ из ожидаемой записи. Проверяются оставшиеся ключи.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_copy_requirements_require_v1(
    p_held jsonb,p_copies jsonb,p_actor_type text,p_actor_id text,p_at timestamptz,p_rows integer,p_reads integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $require$
DECLARE
    root jsonb;
    expected jsonb;
    old_labels jsonb;
    next_labels jsonb;
    needed jsonb;
    cost jsonb;
    coordinate text;
    root_type text;
    root_id text;
    prior_coordinate text;
    step_rows integer;
    step_reads integer;
    used_rows integer;
    used_reads integer:=1;
    command jsonb;
    commands jsonb[]:=ARRAY[]::jsonb[];
    used_bytes bigint:=2;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
        OR p_at IS NULL OR NOT isfinite(p_at)
        OR p_actor_type IS NULL OR p_actor_type NOT IN ('user','service_account')
        OR coalesce(p_actor_id,'')='' OR octet_length(p_actor_id)>16384
        OR p_actor_id ~ '[:#*[:space:][:cntrl:]]'
        OR p_held->'actor' IS DISTINCT FROM jsonb_build_object('type',p_actor_type,'id',p_actor_id)
        OR p_held->'backend_pid' IS DISTINCT FROM to_jsonb(pg_backend_pid())
        OR pg_current_xact_id_if_assigned() IS NULL
        OR p_held->>'txid' IS DISTINCT FROM pg_current_xact_id_if_assigned()::text
        OR jsonb_typeof(p_held->'held_at') IS DISTINCT FROM 'string'
        OR p_at<(p_held->>'held_at')::timestamptz OR p_at>clock_timestamp()
        OR jsonb_typeof(p_held->'roots') IS DISTINCT FROM 'object'
        OR jsonb_typeof(p_copies) IS DISTINCT FROM 'array'
        OR octet_length(p_copies::text)>8388608 THEN
        RAISE EXCEPTION 'invalid selector move copy receipt' USING ERRCODE='42501';
    END IF;
    used_rows:=jsonb_array_length(p_copies);
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
        RAISE EXCEPTION 'selector move copy decision budget exhausted' USING ERRCODE='54000';
    END IF;

    FOR root IN SELECT x.value FROM jsonb_array_elements(p_copies) x
        ORDER BY (x.value->>'root_type') COLLATE "C",(x.value->>'root_id') COLLATE "C"
    LOOP
        root_type:=root->>'root_type';
        root_id:=root->>'root_id';
        coordinate:=root_type||':'||root_id;
        expected:=p_held->'roots'->coordinate;
        next_labels:=root->'new_access_labels';
        old_labels:=expected#>'{physical,2,access_labels}';
        IF jsonb_typeof(root) IS DISTINCT FROM 'object'
            OR root-ARRAY['root_type','root_id','new_access_labels'] <> '{}'::jsonb
            OR coordinate IS NULL OR coordinate=prior_coordinate
            OR expected->>'root_type' IS DISTINCT FROM root_type
            OR expected->>'root_id' IS DISTINCT FROM root_id
            OR expected#>'{authority,actor}' IS DISTINCT FROM p_held->'actor'
            OR jsonb_typeof(expected->'requirements') IS DISTINCT FROM 'array'
            OR kaname.access_labels_valid_v1(old_labels) IS DISTINCT FROM true
            OR kaname.access_labels_valid_v1(next_labels) IS DISTINCT FROM true
            OR next_labels=old_labels OR NOT (next_labels @> old_labels)
            OR (expected->'new_access_labels' @> next_labels) IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'selector move copy exceeds held requirements' USING ERRCODE='42501';
        END IF;
        prior_coordinate:=coordinate;
        step_rows:=jsonb_array_length(expected->'requirements')+(SELECT count(*) FROM jsonb_object_keys(next_labels));
        IF step_rows>p_rows-used_rows OR used_reads>=p_reads THEN
            RAISE EXCEPTION 'selector move copy decision budget exhausted' USING ERRCODE='54000';
        END IF;
        used_rows:=used_rows+step_rows;
        used_reads:=used_reads+1;
        -- Отбираем точные ключи и значения, подтверждённые до часов.
        -- Квитанция authority остаётся той же даже у сузившейся записи.
        SELECT coalesce(jsonb_agg(q.value ORDER BY q.value->>'key'),'[]'::jsonb) INTO needed
        FROM jsonb_array_elements(expected->'requirements') q
        WHERE next_labels ? (q.value->>'key') AND NOT (old_labels ? (q.value->>'key'))
            AND next_labels->(q.value->>'key') = q.value->'new_value';
        IF jsonb_array_length(needed)<>(SELECT count(*) FROM jsonb_each(next_labels) k WHERE NOT (old_labels ? k.key))
            OR jsonb_array_length(needed)<>(SELECT count(DISTINCT k.value->>'key') FROM jsonb_array_elements(needed) k) THEN
            RAISE EXCEPTION 'selector move copy key has no exact held requirement' USING ERRCODE='42501';
        END IF;
        cost:=kaname._authority_resource_access_label_sources_require_v1(
            expected->'authority',needed,p_at,p_rows-used_rows,p_reads-used_reads);
        step_rows:=(cost->>'rows')::integer;
        step_reads:=(cost->>'reads')::integer;
        IF step_rows IS NULL OR step_rows NOT BETWEEN 1 AND p_rows-used_rows
            OR step_reads IS NULL OR step_reads NOT BETWEEN 1 AND p_reads-used_reads THEN
            RAISE EXCEPTION 'selector move copy decision budget exhausted' USING ERRCODE='54000';
        END IF;
        used_rows:=used_rows+step_rows;
        used_reads:=used_reads+step_reads;
        -- Физический OLD получен и удержан до принятия решения. Запись
        -- может менять только access_labels в этой строке по этому ключу.
        command:=jsonb_build_object('root_type',root_type,'root_id',root_id,
            'table',CASE root_type WHEN 'iam.account' THEN 'accounts' WHEN 'iam.project' THEN 'projects'
                WHEN 'iam.serviceAccount' THEN 'service_accounts' ELSE 'resource_mirror' END,
            'physical',expected->'physical','access_labels',next_labels);
        used_bytes:=used_bytes+octet_length(command::text)+2;
        IF used_bytes>8388608 THEN
            RAISE EXCEPTION 'selector move write commands exceed byte budget' USING ERRCODE='54000';
        END IF;
        commands:=array_append(commands,command);
    END LOOP;
    RETURN jsonb_build_object('rows',used_rows,'reads',used_reads,'commands',to_jsonb(commands));
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
        'kaname._authority_role_move_copy_requirements_hold_v1(jsonb,text,text,integer,integer)',
        'kaname._authority_role_move_copy_requirements_require_v1(jsonb,jsonb,text,text,timestamptz,integer,integer)'
    ] LOOP
        FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=to_regprocedure(signature) AND a.grantee<>p.proowner
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
DROP FUNCTION kaname._authority_role_move_copy_requirements_require_v1(jsonb,jsonb,text,text,timestamptz,integer,integer);
DROP FUNCTION kaname._authority_role_move_copy_requirements_hold_v1(jsonb,text,text,integer,integer);
