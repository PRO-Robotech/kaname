-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Реестр определений и значений читается каноническим helper без ONLY.
-- Сверяем форму обеих таблиц и удерживаем её до финального решения.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_copy_registry_hold_v1() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $registry$
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    LOCK TABLE ONLY kaname.authority_access_label_definition, ONLY kaname.authority_access_label_value IN SHARE MODE NOWAIT;
    IF EXISTS (SELECT FROM pg_catalog.pg_class c
        WHERE c.oid IN ('kaname.authority_access_label_definition'::regclass,'kaname.authority_access_label_value'::regclass)
        AND (c.relkind<>'r' OR c.relpersistence<>'p' OR c.relispartition OR c.relhasrules
            OR c.relrowsecurity OR c.relforcerowsecurity OR EXISTS (
                SELECT FROM pg_catalog.pg_inherits i WHERE i.inhparent=c.oid OR i.inhrelid=c.oid))) THEN
        RAISE EXCEPTION 'selector move key registry shape differs' USING ERRCODE='42501';
    END IF;
END;
$registry$;
-- +goose StatementEnd

-- Закрытый шаг до финальных часов писателя роли. Владелец передаёт
-- физическую версию из RR и выведенную для этой цели полную карту копии.
-- Он отдельно подтверждает выбор объекта и ключей правилами роли.
-- Квитанцию надо заморозить в программе этой же транзакции и проверить
-- sources_require_v1 на её decision_at до изменения роли и меток.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_iam_copy_sources_hold_v1(
    p_root_type text, p_root_id text, p_expected jsonb, p_access_labels jsonb,
    p_actor_type text, p_actor_id text, p_rows integer, p_reads integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    table_name text;
    resource_kind text;
    physical jsonb;
    old_row jsonb;
    old_access jsonb;
    definitions jsonb;
    sources jsonb;
    used_rows integer:=1;
    used_reads integer:=1;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF current_setting('transaction_isolation') IS DISTINCT FROM 'read committed' THEN
        RAISE EXCEPTION 'copy source capture requires READ COMMITTED' USING ERRCODE='25001';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
        RAISE EXCEPTION 'copy source capture budget exhausted' USING ERRCODE='54000';
    END IF;
    SELECT t.rel,t.kind INTO table_name,resource_kind FROM (VALUES
        ('iam.account','accounts','account'),
        ('iam.project','projects','project'),
        ('iam.serviceAccount','service_accounts','service_account')
    ) t(dotted,rel,kind) WHERE t.dotted=p_root_type;
    IF table_name IS NULL OR coalesce(p_root_id,'')=''
        OR jsonb_typeof(p_expected) IS DISTINCT FROM 'array'
        OR kaname.access_labels_valid_v1(p_access_labels) IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'invalid IAM copy root or proposed access labels' USING ERRCODE='42501';
    END IF;

    EXECUTE format('SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r))
        FROM ONLY kaname.%I r WHERE r.id=$1 FOR UPDATE OF r NOWAIT',table_name)
        INTO physical USING p_root_id;
    IF physical IS NULL OR physical IS DISTINCT FROM p_expected THEN
        RAISE EXCEPTION 'IAM copy root changed before capture' USING ERRCODE='40001';
    END IF;
    old_row:=physical->2;
    old_access:=old_row->'access_labels';
    IF kaname.access_labels_valid_v1(old_access) IS DISTINCT FROM true
        OR jsonb_typeof(old_row->'labels') IS DISTINCT FROM 'object'
        OR NOT (p_access_labels @> old_access) OR p_access_labels=old_access THEN
        RAISE EXCEPTION 'IAM selector move must only add protected copies' USING ERRCODE='42501';
    END IF;
    used_rows:=used_rows+(SELECT count(*) FROM jsonb_object_keys(p_access_labels));
    IF used_rows>p_rows THEN
        RAISE EXCEPTION 'copy source capture budget exhausted' USING ERRCODE='54000';
    END IF;
    IF EXISTS (SELECT FROM jsonb_each(p_access_labels) n
        WHERE NOT (old_access ? n.key) AND n.value IS DISTINCT FROM (old_row->'labels'->n.key)) THEN
        RAISE EXCEPTION 'protected copy differs from the physical ordinary label' USING ERRCODE='42501';
    END IF;

    used_rows:=used_rows+2;
    used_reads:=used_reads+2;
    IF used_rows>p_rows OR used_reads>p_reads THEN
        RAISE EXCEPTION 'copy source capture budget exhausted' USING ERRCODE='54000';
    END IF;
    PERFORM kaname._authority_role_move_copy_registry_hold_v1();
    definitions:=kaname._authority_resource_access_label_requirements_v1(resource_kind,
        old_row,jsonb_set(old_row,'{access_labels}',p_access_labels),p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(definitions->>'rows')::integer;
    used_reads:=used_reads+(definitions->>'reads')::integer;
    sources:=kaname._authority_resource_access_label_sources_hold_v1(p_actor_type,p_actor_id,
        definitions->'requirements',p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(sources->>'rows')::integer;
    used_reads:=used_reads+(sources->>'reads')::integer;
    IF used_rows IS NULL OR used_rows>p_rows OR used_reads IS NULL OR used_reads>p_reads THEN
        RAISE EXCEPTION 'copy source capture budget exhausted' USING ERRCODE='54000';
    END IF;
    RETURN jsonb_build_object('root_type',p_root_type,'root_id',p_root_id,'physical',physical,
        'new_access_labels',p_access_labels,'requirements',definitions->'requirements','authority',sources,
        'rows',used_rows,'reads',used_reads);
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE
    signature text;
    grantee record;
BEGIN
    FOREACH signature IN ARRAY ARRAY[
        'kaname._authority_role_move_copy_registry_hold_v1()',
        'kaname._authority_role_move_iam_copy_sources_hold_v1(text,text,jsonb,jsonb,text,text,integer,integer)'
    ] LOOP
        FOR grantee IN
            SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
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
DROP FUNCTION kaname._authority_role_move_iam_copy_sources_hold_v1(text,text,jsonb,jsonb,text,text,integer,integer);
DROP FUNCTION kaname._authority_role_move_copy_registry_hold_v1();
