-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Повторяем тот же полный обход источников, включая пустые предикаты.
-- Его аргументы остаются за владельцем; точные входы берутся из stash.
-- +goose StatementBegin
DO $specialize$
DECLARE
    body text;
BEGIN
    SELECT prosrc INTO STRICT body FROM pg_catalog.pg_proc
    WHERE oid='kaname._authority_metadata_access_label_held_replay_v1(jsonb,jsonb,jsonb,integer,integer,integer)'::regprocedure
        AND proowner=current_user::regrole;
    IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM
        '586423c5c0965e9cf8ab408894127527eb66edbfc1a454a0a056e9fb064a4749' THEN
        RAISE EXCEPTION 'group replay predecessor differs' USING ERRCODE='55000';
    END IF;
    body:=replace(body,'DECLARE proof jsonb;',
        'DECLARE owner_state jsonb;p_packet jsonb;p_closure jsonb;p_plan jsonb;proof jsonb;');
    body:=replace(body,' PERFORM kaname.authority_protocol_require_owner();',
        $stash$ owner_state:=kaname._authority_metadata_access_label_stashed_v1();
 p_packet:=owner_state->'root';p_closure:=owner_state->'discovery';p_plan:=owner_state->'plan';$stash$);
    body:=replace(body,
        $old$external_root:=root_type NOT IN ('iam.account','iam.project','iam.serviceAccount');$old$,
        $new$IF root_type IS DISTINCT FROM 'iam.group' OR proof->>'purpose' IS DISTINCT FROM 'decision'
    OR proof->>'writer_contract' IS DISTINCT FROM '2' THEN
   RAISE EXCEPTION 'group held replay root or decision differs' USING ERRCODE='42501';END IF;
 external_root:=false;$new$);
    body:=replace(body,'kaname._authority_metadata_access_label_carrier_census_v1(root_type,',
        'kaname._authority_metadata_group_census_v1(root_type,');
    IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM
        'f39c0e51902930b6efe63337f2962899c53ca66aecf9a97109e4d50051e55eac' THEN
        RAISE EXCEPTION 'group held replay specialization differs' USING ERRCODE='55000';
    END IF;
    EXECUTE format('CREATE FUNCTION kaname._authority_metadata_group_held_replay_v1(
        p_rows integer,p_reads integer,p_work integer)
        RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS %L',body);
END;
$specialize$;
-- +goose StatementEnd

-- Удержание физической группы, эпох и отрицательного предиката singleton
-- предшествует повторному чтению всех источников. Контракт результата совпадает
-- с native retention; вопрос обновления возвращается для следующей стадии.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_hold_and_replay_v1(
    p_patch jsonb,p_rename boolean,p_actor_type text,p_actor_id text,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $hold$
DECLARE
    prepared jsonb;
    target jsonb;
    old_state jsonb;
    witnesses jsonb;
    witness_count integer;
    needs_cluster boolean;
    epoch record;
    epoch_scope text;
    replay jsonb;
    -- Три чтения stash (здесь, в target_hold и в полном replay) и
    -- захват таблицы эпох. Строки самой группы и ключи считаются по receipt.
    used_rows integer:=3;
    used_reads integer:=4;
    used_work integer:=4;
    timeout_before text:=current_setting('lock_timeout');
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN 5 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 6 AND 4096
        OR p_work IS NULL OR p_work NOT BETWEEN 5 AND 400000 THEN
        RAISE EXCEPTION 'group hold budget invalid' USING ERRCODE='54000';
    END IF;
    prepared:=kaname._authority_metadata_access_label_stashed_v1();
    old_state:=prepared#>'{root,root_state}';
    IF jsonb_typeof(p_patch) IS DISTINCT FROM 'object'
        OR p_patch-ARRAY['name','description','labels','access_labels']<>'{}'::jsonb
        OR (p_patch ? 'name' AND jsonb_typeof(p_patch->'name') IS DISTINCT FROM 'string')
        OR (p_patch ? 'description' AND jsonb_typeof(p_patch->'description') IS DISTINCT FROM 'string')
        OR (p_patch ? 'labels' AND jsonb_typeof(p_patch->'labels') IS DISTINCT FROM 'object')
        OR kaname.access_labels_valid_v1(p_patch->'access_labels') IS DISTINCT FROM true
        OR p_patch->'access_labels' IS DISTINCT FROM prepared#>'{root,census,new_labels}'
        OR p_rename IS DISTINCT FROM (p_patch ? 'name' AND p_patch->'name' IS DISTINCT FROM old_state#>'{2,name}') THEN
        RAISE EXCEPTION 'group held patch differs' USING ERRCODE='42501';
    END IF;
    -- Общий обход делает FOR SHARE до финального времени решения. Ограничиваем
    -- ожидание конфликта, сохраняя более короткий таймаут вызывающей транзакции.
    IF timeout_before::interval=interval '0' OR timeout_before::interval>interval '2 seconds' THEN
        PERFORM set_config('lock_timeout','2s',true);
    END IF;
    target:=kaname._authority_metadata_group_target_hold_v1(p_actor_type,p_actor_id,
        least(p_reads-used_reads-1,p_work-used_work,4096),1,1);
    used_rows:=used_rows+(target->>'rows')::integer;
    used_reads:=used_reads+(target->>'reads')::integer+(target->>'lock_keys')::integer;
    used_work:=used_work+(target->>'lock_keys')::integer;
    LOCK TABLE ONLY kaname.authority_binding_epoch IN ROW EXCLUSIVE MODE NOWAIT;
    FOR epoch IN SELECT e.key,e.value FROM jsonb_each_text(prepared#>'{plan,binding_epochs}') e ORDER BY e.key COLLATE "C" LOOP
        IF used_rows>=p_rows OR used_reads>=p_reads OR used_work>=p_work THEN
            RAISE EXCEPTION 'group binding epoch hold exceeds budget' USING ERRCODE='54000';
        END IF;
        IF epoch.value='write' THEN
            SELECT e.scope INTO epoch_scope FROM ONLY kaname.authority_binding_epoch e
            WHERE e.scope=epoch.key FOR UPDATE OF e NOWAIT;
        ELSIF epoch.value='share' THEN
            SELECT e.scope INTO epoch_scope FROM ONLY kaname.authority_binding_epoch e
            WHERE e.scope=epoch.key FOR SHARE OF e NOWAIT;
        ELSE
            RAISE EXCEPTION 'group binding epoch hold mode differs' USING ERRCODE='42501';
        END IF;
        IF epoch_scope IS NOT NULL THEN
            used_rows:=used_rows+1;
        ELSIF epoch.key IN ('',target->>'root_account') THEN
            RAISE EXCEPTION 'group binding epoch disappeared' USING ERRCODE='P1034';
        END IF;
        used_reads:=used_reads+1;
        used_work:=used_work+1;
    END LOOP;
    witnesses:=prepared#>'{discovery,frontier,witnesses}';
    SELECT count(*),bool_or(w.value->'cluster_states'='[]'::jsonb) INTO witness_count,needs_cluster
    FROM jsonb_each(witnesses) w;
    used_work:=used_work+witness_count;
    IF used_rows>=p_rows OR used_reads>=p_reads OR used_work>=p_work THEN
        RAISE EXCEPTION 'group held replay exceeds remaining budget' USING ERRCODE='54000';
    END IF;
    IF needs_cluster THEN LOCK TABLE ONLY kaname.clusters IN SHARE MODE NOWAIT; END IF;
    replay:=kaname._authority_metadata_group_held_replay_v1(p_rows-used_rows,p_reads-used_reads,p_work-used_work);
    used_rows:=used_rows+(replay->>'rows')::integer;
    used_reads:=used_reads+(replay->>'reads')::integer;
    used_work:=used_work+(replay->>'work')::integer;
    IF used_rows IS NULL OR used_rows NOT BETWEEN 1 AND p_rows OR used_reads IS NULL OR used_reads NOT BETWEEN 1 AND p_reads
        OR used_work IS NULL OR used_work NOT BETWEEN 1 AND p_work THEN
        RAISE EXCEPTION 'group held replay receipt exceeds budget' USING ERRCODE='54000';
    END IF;
    IF current_setting('lock_timeout') IS DISTINCT FROM timeout_before THEN
        PERFORM set_config('lock_timeout',timeout_before,true);
    END IF;
    RETURN jsonb_build_object('replay',replay,'update_question',target->'update_question',
        'root_physical',jsonb_build_object('table','groups','id',target#>>'{root_coordinate,1}',
            'xmin',old_state->>0,'ctid',old_state->>1),'rows',used_rows,'reads',used_reads,'work',used_work);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'group metadata replay busy; restage required' USING ERRCODE='40001';
END;
$hold$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE
    fn regprocedure;
    grantee record;
BEGIN
    FOREACH fn IN ARRAY ARRAY[
        'kaname._authority_metadata_group_held_replay_v1(integer,integer,integer)'::regprocedure,
        'kaname._authority_metadata_group_hold_and_replay_v1(jsonb,boolean,text,text,integer,integer,integer)'::regprocedure
    ] LOOP
        FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
            WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
                CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_metadata_group_hold_and_replay_v1(jsonb,boolean,text,text,integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_group_held_replay_v1(integer,integer,integer);
