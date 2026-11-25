-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Области определений группы выводим из удержанного физического OLD.
-- Для проверки права на каждый ключ следующая стадия получает точную редакцию.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_access_label_requirements_v1(
    p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $requirements$
DECLARE
    prepared jsonb;
    packet jsonb;
    root_state jsonb;
    old_row jsonb;
    new_row jsonb;
    v_group text;
    v_account text;
    old_labels jsonb;
    new_labels jsonb;
    delta record;
    held record;
    candidates integer;
    requirements jsonb:='[]';
    -- Одна строка stash, одно чтение stash и один шаг разбора дельты.
    used_rows integer:=1;
    used_reads integer:=2;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF current_setting('transaction_isolation') IS DISTINCT FROM 'read committed' THEN
        RAISE EXCEPTION 'group access label definitions require READ COMMITTED' USING ERRCODE='25001';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
        RAISE EXCEPTION 'group access label definition budget exhausted' USING ERRCODE='54000';
    END IF;
    prepared:=kaname._authority_metadata_access_label_stashed_v1();
    packet:=prepared->'retention';
    root_state:=prepared#>'{root,root_state}';
    old_row:=packet->'old_row';
    new_row:=packet->'new_row';
    v_group:=old_row->>'id';
    v_account:=old_row->>'account_id';
    IF packet->>'root_type' IS DISTINCT FROM 'iam.group' OR packet->>'root_model' IS DISTINCT FROM 'iam_group'
        OR packet->'root_source_kind' IS DISTINCT FROM '30'::jsonb
        OR coalesce(v_group,'') COLLATE "C" !~ '^grp[a-zA-Z0-9_-]{1,61}$'
        OR coalesce(v_account,'') COLLATE "C" !~ '^acc[a-zA-Z0-9_-]{1,61}$'
        OR packet->>'root_id' IS DISTINCT FROM v_group
        OR prepared#>'{root,root_coordinate}' IS DISTINCT FROM jsonb_build_array('iam.group',v_group)
        OR prepared#>>'{root,root_account}' IS DISTINCT FROM v_account
        OR old_row IS DISTINCT FROM root_state->2
        OR coalesce(root_state->>0,'')='' OR coalesce(root_state->>1,'')=''
        OR packet->'root_physical' IS DISTINCT FROM jsonb_build_object(
            'table','groups','id',v_group,'xmin',root_state->>0,'ctid',root_state->>1)
        OR jsonb_typeof(new_row) IS DISTINCT FROM 'object'
        OR old_row-ARRAY['name','description','labels','access_labels'] IS DISTINCT FROM
           new_row-ARRAY['name','description','labels','access_labels'] THEN
        RAISE EXCEPTION 'group access label held identity differs' USING ERRCODE='42501';
    END IF;
    old_labels:=old_row->'access_labels';
    new_labels:=new_row->'access_labels';
    IF kaname.access_labels_valid_v1(old_labels) IS DISTINCT FROM true
        OR kaname.access_labels_valid_v1(new_labels) IS DISTINCT FROM true
        OR new_labels IS DISTINCT FROM prepared#>'{root,census,new_labels}' THEN
        RAISE EXCEPTION 'group access label held images differ' USING ERRCODE='42501';
    END IF;
    used_rows:=used_rows+(SELECT count(*) FROM jsonb_object_keys(old_labels))
        +(SELECT count(*) FROM jsonb_object_keys(new_labels));
    IF used_rows>p_rows THEN
        RAISE EXCEPTION 'group access label definition budget exhausted' USING ERRCODE='54000';
    END IF;
    IF old_labels=new_labels THEN
        RETURN jsonb_build_object('requirements',requirements,'rows',used_rows,'reads',used_reads);
    END IF;

    -- SHARE удерживает также отсутствие конкурирующей политики в другой области.
    LOCK TABLE kaname.authority_access_label_definition IN SHARE MODE;
    FOR delta IN SELECT coalesce(o.key,n.key) AS changed_key,o.value AS old_value,n.value AS new_value
        FROM jsonb_each_text(old_labels) o FULL JOIN jsonb_each_text(new_labels) n ON n.key=o.key
        WHERE o.value COLLATE "C" IS DISTINCT FROM n.value COLLATE "C"
        ORDER BY coalesce(o.key,n.key) COLLATE "C"
    LOOP
        -- Две возможные области, удержание определения и проверка значения.
        used_rows:=used_rows+4;
        used_reads:=used_reads+3;
        IF used_rows>p_rows OR used_reads>p_reads THEN
            RAISE EXCEPTION 'group access label definition budget exhausted' USING ERRCODE='54000';
        END IF;
        candidates:=0;
        FOR held IN SELECT d.id,d.scope_kind,d.scope_id,d.revision,d.xmin::text AS row_xmin,d.ctid::text AS row_ctid
            FROM (VALUES ('cluster','cluster_root'),('account',v_account)) s(kind,id)
            JOIN kaname.authority_access_label_definition d ON d.scope_kind=s.kind AND d.scope_id=s.id
                AND d.module='iam' AND d.resource='group' AND d.label_key=delta.changed_key
            ORDER BY d.id LIMIT 2
        LOOP
            candidates:=candidates+1;
            IF candidates<>1 THEN
                RAISE EXCEPTION 'group access label definition is ambiguous' USING ERRCODE='42501';
            END IF;
            IF kaname.authority_access_label_definition_hold_v1(held.scope_kind,held.scope_id,'iam','group',
                delta.changed_key,held.id,held.revision,held.row_xmin,held.row_ctid,delta.new_value) IS DISTINCT FROM true THEN
                RAISE EXCEPTION 'group access label value or generation is not allowed' USING ERRCODE='42501';
            END IF;
            requirements:=requirements||jsonb_build_array(jsonb_build_object('key',delta.changed_key,
                'old_value',delta.old_value,'new_value',delta.new_value,'definition_id',held.id,
                'scope_kind',held.scope_kind,'scope_id',held.scope_id,
                'revision',held.revision,'row_xmin',held.row_xmin,'row_ctid',held.row_ctid));
        END LOOP;
        IF candidates<>1 THEN
            RAISE EXCEPTION 'group access label has no applicable definition' USING ERRCODE='42501';
        END IF;
    END LOOP;
    RETURN jsonb_build_object('requirements',requirements,'rows',used_rows,'reads',used_reads);
END;
$requirements$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE
    fn regprocedure:='kaname._authority_metadata_group_access_label_requirements_v1(integer,integer)'::regprocedure;
    grantee record;
BEGIN
    FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
        WHERE p.oid=fn AND a.grantee<>p.proowner
    LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
            CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE quote_ident(grantee.rolname) END);
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_metadata_group_access_label_requirements_v1(integer,integer);
