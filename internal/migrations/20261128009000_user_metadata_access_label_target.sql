-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- OLD и полный, отсортированный набор физических версий членств приходят из
-- одного RR-снимка. Область человека определяется всеми строками memberships.
-- Состояние членства и устаревшее users.account_id не фильтруют этот набор.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_target_v1(
    p_id text,p_xmin text,p_ctid text,p_old jsonb,p_memberships jsonb,
    p_actor_type text,p_actor_id text,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $target$
DECLARE
    proof jsonb;
    root jsonb;
    members jsonb;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    proof:=kaname.authority_protocol_attestation();
    IF proof->>'mode' IS DISTINCT FROM 'global' OR proof->>'kind' IS DISTINCT FROM 'resource'
        OR proof->>'writer_contract' IS DISTINCT FROM '2' OR proof->>'purpose' IS DISTINCT FROM 'decision'
        OR proof->>'consumer_finalized' IS DISTINCT FROM 'false'
        OR coalesce(p_id,'') COLLATE "C" !~ '^usr[a-zA-Z0-9_-]{1,61}$'
        OR coalesce(p_xmin,'')='' OR coalesce(p_ctid,'')=''
        OR jsonb_typeof(p_old) IS DISTINCT FROM 'object' OR p_old->>'id' IS DISTINCT FROM p_id
        OR jsonb_typeof(p_memberships) IS DISTINCT FROM 'array'
        OR coalesce(p_actor_type,'') NOT IN ('user','service_account')
        OR coalesce(octet_length(p_actor_id),0) NOT BETWEEN 1 AND 64
        OR p_actor_id ~ '[:#*[:space:][:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid user metadata target' USING ERRCODE='42501';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN 1 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 2 AND 4096
        OR jsonb_array_length(p_memberships)>p_rows-1
        OR octet_length(p_memberships::text)::bigint+octet_length(p_old::text)>8388608 THEN
        RAISE EXCEPTION 'user metadata target exceeds budget' USING ERRCODE='54000';
    END IF;
    root:=kaname._authority_metadata_access_label_early_source_v1(30,'iam.user',p_id,1,1);
    members:=kaname._authority_metadata_access_label_early_source_v1(31,'iam.user',p_id,p_rows-1,1);
    IF root->'states' IS DISTINCT FROM jsonb_build_array(jsonb_build_array(p_xmin,p_ctid,p_old))
        OR members->'states' IS DISTINCT FROM p_memberships THEN
        RAISE EXCEPTION 'user or memberships changed after discovery' USING ERRCODE='40001';
    END IF;
    IF EXISTS(SELECT FROM jsonb_array_elements(p_memberships) m
        WHERE m#>>'{2,user_id}' IS DISTINCT FROM p_id
           OR coalesce(m#>>'{2,account_id}','') COLLATE "C" !~ '^acc[a-zA-Z0-9_-]{1,61}$') THEN
        RAISE EXCEPTION 'user membership has an invalid scope' USING ERRCODE='42501';
    END IF;
    RETURN jsonb_build_object('root_coordinate',jsonb_build_array('iam.user',p_id),
        'root_state',root#>'{states,0}','membership_states',members->'states',
        'update_question',jsonb_build_object('subject',p_actor_type||':'||p_actor_id,
            'relation','record_writer','object_type','iam_user','object_id',p_id),
        'rows',1+jsonb_array_length(p_memberships),'reads',2);
END;
$target$;
-- +goose StatementEnd

-- Вызывается после первой protectPolicyPlan и до окончательного decision_at.
-- Владелец извлекает target из своего stash этой попытки. Эпохи для обычной
-- записи в memberships и для больших statement-пакетов удерживаются до commit.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_target_hold_v1(
    p_actor_type text,p_actor_id text,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $hold$
DECLARE
    proof jsonb;
    target jsonb;
    uid text;
    question jsonb;
    physical jsonb;
    members jsonb;
    n integer;
    -- Две формы таблиц, четыре триггера, две функции, две эпохи и строка users.
    fixed_rows constant integer:=11;
    fixed_reads constant integer:=6;
    invoker oid;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    target:=kaname._authority_metadata_access_label_stashed_v1()->'root';
    proof:=kaname.authority_protocol_attestation();
    uid:=target#>>'{root_coordinate,1}';
    question:=jsonb_build_object('subject',p_actor_type||':'||p_actor_id,
        'relation','record_writer','object_type','iam_user','object_id',uid);
    IF proof->>'mode' IS DISTINCT FROM 'global' OR proof->>'kind' IS DISTINCT FROM 'resource'
        OR proof->>'writer_contract' IS DISTINCT FROM '2'
        OR proof->>'purpose' IS DISTINCT FROM 'decision' OR proof->>'consumer_finalized' IS DISTINCT FROM 'true'
        OR coalesce(uid,'') COLLATE "C" !~ '^usr[a-zA-Z0-9_-]{1,61}$'
        OR target->'root_coordinate' IS DISTINCT FROM jsonb_build_array('iam.user',uid)
        OR target#>>'{root_state,2,id}' IS DISTINCT FROM uid
        OR jsonb_typeof(target->'membership_states') IS DISTINCT FROM 'array'
        OR coalesce(p_actor_type,'') NOT IN ('user','service_account')
        OR coalesce(octet_length(p_actor_id),0) NOT BETWEEN 1 AND 64
        OR p_actor_id ~ '[:#*[:space:][:cntrl:]]'
        OR target->'update_question' IS DISTINCT FROM question THEN
        RAISE EXCEPTION 'user metadata target differs from prepared question' USING ERRCODE='42501';
    END IF;
    n:=jsonb_array_length(target->'membership_states');
    IF p_rows IS NULL OR p_rows NOT BETWEEN fixed_rows AND 100000 OR n>(p_rows-fixed_rows)/2
        OR p_reads IS NULL OR p_reads NOT BETWEEN fixed_reads+2 AND 4096 THEN
        RAISE EXCEPTION 'user metadata replay exceeds budget' USING ERRCODE='54000';
    END IF;
    -- ROW EXCLUSIVE совместим с обычными INSERT/UPDATE/DELETE. Он защищает
    -- shape от ALTER TABLE DISABLE TRIGGER, а не предикат от вставки.
    LOCK TABLE ONLY kaname.users, ONLY kaname.memberships IN ROW EXCLUSIVE MODE NOWAIT;
    invoker:=(proof->>'invoker_oid')::oid;
    IF current_setting('session_replication_role') NOT IN ('origin','local')
        OR (SELECT count(*) FROM pg_catalog.pg_class c WHERE c.oid IN ('kaname.users'::regclass,'kaname.memberships'::regclass)
            AND c.relkind='r' AND c.relpersistence='p' AND NOT (c.relrowsecurity OR c.relforcerowsecurity
                OR c.relispartition OR c.relhassubclass OR c.relhasrules)
            AND NOT EXISTS(SELECT FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid)
            AND has_table_privilege(invoker,c.oid,'SELECT'))<>2
        OR has_column_privilege(invoker,'kaname.users','labels','UPDATE') IS DISTINCT FROM true
        OR has_column_privilege(invoker,'kaname.users','access_labels','UPDATE') IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'user metadata source shape or privilege differs' USING ERRCODE='42501';
    END IF;
    IF EXISTS(SELECT FROM (VALUES
        ('policy_epoch_insert',4,NULL,'new_policy_rows'),('policy_epoch_update',16,'old_policy_rows','new_policy_rows'),
        ('policy_epoch_delete',8,'old_policy_rows',NULL),('policy_epoch_truncate',32,NULL,NULL)
    ) expected(name,kind,olds,news) WHERE NOT EXISTS(
        SELECT FROM pg_catalog.pg_trigger t WHERE t.tgrelid='kaname.memberships'::regclass
        AND t.tgname=expected.name AND t.tgfoid='kaname.authority_policy_changed()'::regprocedure
        AND t.tgtype=expected.kind AND t.tgenabled IN ('A','O') AND NOT t.tgisinternal
        AND t.tgconstraint=0 AND NOT t.tgdeferrable AND NOT t.tginitdeferred
        AND t.tgnargs=0 AND t.tgattr::text='' AND t.tgqual IS NULL
        AND t.tgoldtable::text IS NOT DISTINCT FROM expected.olds AND t.tgnewtable::text IS NOT DISTINCT FROM expected.news
    )) OR EXISTS(SELECT FROM (VALUES
        ('kaname.authority_policy_changed()','46a479262309d1ab8cd6efd41ea519921eb57c13ca7b5054ce6550aba366371d'),
        ('kaname.authority_policy_keys(text,jsonb)','5bed24d2efa4e9dd3eadd3224d06031b5eeebf6785e7461ece8a4830adb46e86')
    ) expected(signature,digest) WHERE NOT EXISTS(
        SELECT FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure(expected.signature)
        AND p.proowner=current_user::regrole AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
        AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=expected.digest
    )) THEN
        RAISE EXCEPTION 'user membership policy epoch producer differs' USING ERRCODE='42501';
    END IF;
    -- Большой batch и TRUNCATE повышают *, остальные изменения повышают
    -- user:<id> для OLD и NEW. Порядок совпадает с policy_epoch_lock_full_v2.
    PERFORM e.key FROM ONLY kaname.authority_policy_epoch e WHERE e.key='*' FOR UPDATE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'global policy epoch absent' USING ERRCODE='40001'; END IF;
    PERFORM e.key FROM ONLY kaname.authority_policy_epoch e WHERE e.key=('user:'||uid) FOR UPDATE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'user policy epoch absent' USING ERRCODE='40001'; END IF;
    SELECT jsonb_build_array(u.xmin::text,u.ctid::text,to_jsonb(u)) INTO physical
        FROM ONLY kaname.users u WHERE u.id=uid FOR UPDATE OF u NOWAIT;
    IF physical IS DISTINCT FROM target->'root_state' THEN
        RAISE EXCEPTION 'held user row changed' USING ERRCODE='40001';
    END IF;
    -- Писатель мог взять строку до своего AFTER STATEMENT. NOWAIT оставляет
    -- ему возможность завершиться, после чего вся попытка повторится.
    PERFORM m.id FROM ONLY kaname.memberships m WHERE m.user_id=uid LIMIT n+1 FOR SHARE OF m NOWAIT;
    GET DIAGNOSTICS n=ROW_COUNT;
    IF n<>jsonb_array_length(target->'membership_states') THEN
        RAISE EXCEPTION 'held membership count changed' USING ERRCODE='40001';
    END IF;
    members:=kaname._authority_metadata_access_label_held_source_v1(31,'iam.user',uid,n,1);
    IF members->'states' IS DISTINCT FROM target->'membership_states' THEN
        RAISE EXCEPTION 'held user memberships changed' USING ERRCODE='40001';
    END IF;
    RETURN jsonb_build_object('root_coordinate',target->'root_coordinate','root_state',physical,
        'membership_states',members->'states','update_question',question,'rows',fixed_rows+2*n,'reads',fixed_reads+2);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'user metadata target busy' USING ERRCODE='40001';
END;
$hold$;
-- +goose StatementEnd
-- Учитываем EXECUTE, который мог быть выдан существующим ALTER DEFAULT PRIVILEGES.
-- +goose StatementBegin
DO $private$
DECLARE
    fn regprocedure;
    grantee record;
BEGIN
    FOREACH fn IN ARRAY ARRAY[
        'kaname._authority_metadata_user_target_v1(text,text,text,jsonb,jsonb,text,text,integer,integer)'::regprocedure,
        'kaname._authority_metadata_user_target_hold_v1(text,text,integer,integer)'::regprocedure
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
DROP FUNCTION kaname._authority_metadata_user_target_hold_v1(text,text,integer,integer);
DROP FUNCTION kaname._authority_metadata_user_target_v1(text,text,text,jsonb,jsonb,text,text,integer,integer);
