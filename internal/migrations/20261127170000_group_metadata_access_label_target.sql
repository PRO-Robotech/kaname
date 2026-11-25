-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- В RC владелец повторно проверяет физическую строку из снимка RR.
-- Из подтверждённой строки выводит один вопрос для актора и одну область группы.
-- Участие в группе, владелец аккаунта и сведения из PATCH здесь не нужны.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_target_v1(
    p_id text, p_xmin text, p_ctid text, p_old jsonb, p_actor_type text, p_actor_id text,
    p_rows integer, p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $target$
DECLARE
    proof jsonb;
    capture jsonb;
    physical jsonb;
    v_account text;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    proof:=kaname.authority_protocol_attestation();
    IF proof->>'kind' IS DISTINCT FROM 'resource'
        OR proof->>'purpose' IS DISTINCT FROM 'decision'
        OR proof->>'writer_contract' IS DISTINCT FROM '2'
        OR proof->>'consumer_finalized' IS DISTINCT FROM 'false'
        OR coalesce(p_id,'') COLLATE "C" !~ '^grp[a-zA-Z0-9_-]{1,61}$'
        OR coalesce(p_xmin,'')=''
        OR jsonb_typeof(p_old) IS DISTINCT FROM 'object'
        OR p_old->>'id' IS DISTINCT FROM p_id
        OR coalesce(p_actor_type,'') NOT IN ('user','service_account')
        OR coalesce(p_actor_id,'')='' OR octet_length(p_actor_id)>16384
        OR p_actor_id ~ '[:#*[:space:][:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid group metadata discovery' USING ERRCODE='42501';
    END IF;

    IF p_rows IS NULL OR p_rows NOT BETWEEN 1 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 1 AND 4096 THEN
        RAISE EXCEPTION 'group metadata discovery exceeds read budget' USING ERRCODE='54000';
    END IF;
    -- Вид 30 даёт снимок ONLY groups и проверяет право чтения исходного LOGIN.
    capture:=kaname._authority_metadata_access_label_early_source_v1(30,'iam.group',p_id,1,1);
    physical:=capture#>'{states,0}';
    IF capture->>'rows' IS DISTINCT FROM '1' OR capture->>'reads' IS DISTINCT FROM '1'
        OR physical->>0 IS DISTINCT FROM p_xmin OR physical->>1 IS DISTINCT FROM p_ctid
        OR physical->2 IS DISTINCT FROM p_old THEN
        RAISE EXCEPTION 'group metadata discovery snapshot changed' USING ERRCODE='40001';
    END IF;
    v_account:=physical#>>'{2,account_id}';
    IF coalesce(v_account,'') COLLATE "C" !~ '^acc[a-zA-Z0-9_-]{1,61}$'
        OR coalesce(proof->>'mode','') NOT IN ('accounts','global')
        OR (proof->>'mode'='accounts' AND (proof->'accounts' ? v_account) IS DISTINCT FROM true) THEN
        RAISE EXCEPTION 'group metadata outside signed account scope' USING ERRCODE='42501';
    END IF;
    RETURN jsonb_build_object('root_coordinate',jsonb_build_array('iam.group',p_id),
        'root_account',v_account,'root_state',physical,'rows',1,'reads',1,
        'update_question',jsonb_build_object('subject',p_actor_type||':'||p_actor_id,
            'relation','v_update','object_type','iam_group','object_id',p_id));
END;
$target$;
-- +goose StatementEnd

-- Вызывается после формирования полного плана и до изменения группы.
-- Проверка самой политики и прав на отдельные ключи остаётся за писателем.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_target_hold_v1(
    p_actor_type text,p_actor_id text,p_key_budget integer,p_rows integer,p_reads integer
)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $hold$
DECLARE
    prepared jsonb;
    proof jsonb;
    target jsonb;
    plan jsonb;
    v_group text;
    v_account text;
    physical jsonb;
    question jsonb;
    column_name text;
    invoker oid;
    key_count integer;
BEGIN
    -- Stash сверяет владельца/ACL временной таблицы и подписанные backend, xid,
    -- nonce и catalog_id. Аргументы раннего плана от клиента здесь не принимаются.
    prepared:=kaname._authority_metadata_access_label_stashed_v1();
    proof:=kaname.authority_protocol_attestation();
    target:=prepared->'root';
    plan:=prepared->'plan';
    v_group:=target#>>'{root_coordinate,1}';
    v_account:=target#>>'{root_state,2,account_id}';
    question:=jsonb_build_object('subject',p_actor_type||':'||p_actor_id,
        'relation','v_update','object_type','iam_group','object_id',v_group);
    IF proof->>'writer_contract' IS DISTINCT FROM '2' OR proof->>'purpose' IS DISTINCT FROM 'decision'
        OR coalesce(p_actor_type,'') NOT IN ('user','service_account') OR coalesce(p_actor_id,'')=''
        OR octet_length(p_actor_id)>16384 OR p_actor_id ~ '[:#*[:space:][:cntrl:]]'
        OR coalesce(v_group,'') COLLATE "C" !~ '^grp[a-zA-Z0-9_-]{1,61}$'
        OR coalesce(v_account,'') COLLATE "C" !~ '^acc[a-zA-Z0-9_-]{1,61}$'
        OR target->'root_coordinate' IS DISTINCT FROM jsonb_build_array('iam.group',v_group)
        OR target#>>'{root_state,2,id}' IS DISTINCT FROM v_group
        OR target->>'root_account' IS DISTINCT FROM v_account
        OR target->'update_question' IS DISTINCT FROM question
        OR coalesce(proof->>'mode','') NOT IN ('accounts','global')
        OR (proof->>'mode'='accounts' AND (proof->'accounts' ? v_account) IS DISTINCT FROM true)
        OR plan#>>ARRAY['binding_epochs',v_account] IS DISTINCT FROM 'write'
        OR plan#>>ARRAY['binding_epochs',''] IS DISTINCT FROM 'share'
        OR coalesce(plan#>>ARRAY['policy_epochs','scope:'||v_account],'') NOT IN ('share','write')
        -- Триггер UPDATE пишет group:<id>. В режиме accounts ключ должен
        -- быть удержан на запись, в режиме global его держит корневой fence.
        OR (proof->>'mode'='accounts'
            AND plan#>>ARRAY['policy_epochs','group:'||v_group] IS DISTINCT FROM 'write') THEN
        RAISE EXCEPTION 'group metadata held plan differs' USING ERRCODE='42501';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN 1 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 1 AND 4096 THEN
        RAISE EXCEPTION 'group metadata replay exceeds read budget' USING ERRCODE='54000';
    END IF;
    key_count:=kaname._authority_metadata_access_label_source_locks_v1(
        plan->'source_guards',plan->'policy_epochs',plan->'binding_epochs',p_key_budget,true);

    invoker:=(proof->>'invoker_oid')::oid;
    LOCK TABLE ONLY kaname.groups IN ROW EXCLUSIVE MODE NOWAIT;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_class c WHERE c.oid='kaname.groups'::regclass
        AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
        AND NOT c.relhasrules AND NOT c.relispartition AND NOT EXISTS (
            SELECT FROM pg_catalog.pg_inherits i WHERE i.inhparent=c.oid OR i.inhrelid=c.oid))
        OR has_table_privilege(invoker,'kaname.groups','SELECT') IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'group metadata source unavailable to original login' USING ERRCODE='42501';
    END IF;
    FOREACH column_name IN ARRAY ARRAY['name','description','labels','access_labels'] LOOP
        IF has_column_privilege(invoker,'kaname.groups',column_name,'UPDATE') IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'group metadata write privilege missing' USING ERRCODE='42501';
        END IF;
    END LOOP;
    SELECT jsonb_build_array(g.xmin::text,g.ctid::text,to_jsonb(g)) INTO physical
    FROM ONLY kaname.groups g WHERE g.id=v_group AND g.account_id=v_account FOR UPDATE OF g NOWAIT;
    IF physical IS NULL OR physical IS DISTINCT FROM target->'root_state' THEN
        RAISE EXCEPTION 'group metadata root changed during replay' USING ERRCODE='40001';
    END IF;
    RETURN jsonb_build_object('root_coordinate',target->'root_coordinate','root_account',v_account,
        'root_state',physical,'update_question',question,'rows',1,'reads',1,'lock_keys',key_count);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'group metadata root busy' USING ERRCODE='40001';
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
        'kaname._authority_metadata_group_target_v1(text,text,text,jsonb,text,text,integer,integer)'::regprocedure,
        'kaname._authority_metadata_group_target_hold_v1(text,text,integer,integer,integer)'::regprocedure
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
DROP FUNCTION kaname._authority_metadata_group_target_hold_v1(text,text,integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_group_target_v1(text,text,text,jsonb,text,text,integer,integer);
