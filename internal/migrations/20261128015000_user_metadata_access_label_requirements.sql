-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Для глобального пользователя применимость определяется полным удержанным
-- набором memberships. На каждый изменившийся ключ нужна однозначная
-- политика в каждой области, а при отсутствии членств нужна политика кластера.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_access_label_requirements_v1(p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $requirements$
DECLARE
    prepared jsonb;
    images jsonb;
    old_labels jsonb;
    new_labels jsonb;
    memberships jsonb;
    account_ids text[];
    account_count integer;
    delta record;
    definition record;
    cluster_found boolean;
    account_found integer;
    requirements jsonb:='[]';
    used_rows integer:=1;
    used_reads integer:=2;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
        RAISE EXCEPTION 'user access label definition budget exhausted' USING ERRCODE='54000';
    END IF;
    prepared:=kaname._authority_metadata_access_label_stashed_v1();
    images:=prepared->'user_images';
    old_labels:=images#>'{old_row,access_labels}';
    new_labels:=images#>'{new_row,access_labels}';
    memberships:=images->'membership_states';
    IF images->>'root_type' IS DISTINCT FROM 'iam.user' OR images->>'root_model' IS DISTINCT FROM 'iam_user'
        OR images->'root_source_kind' IS DISTINCT FROM '30'::jsonb
        OR images->>'mode' IS DISTINCT FROM 'access_labels'
        OR images->'nonce' IS DISTINCT FROM prepared#>'{plan,nonce}'
        OR jsonb_typeof(memberships) IS DISTINCT FROM 'array'
        OR kaname.access_labels_valid_v1(old_labels) IS DISTINCT FROM true
        OR kaname.access_labels_valid_v1(new_labels) IS DISTINCT FROM true
        OR new_labels=old_labels THEN
        RAISE EXCEPTION 'user access label requirements need held changed images' USING ERRCODE='42501';
    END IF;

    used_rows:=used_rows+jsonb_array_length(memberships)
        +(SELECT count(*) FROM jsonb_object_keys(old_labels))+(SELECT count(*) FROM jsonb_object_keys(new_labels));
    IF used_rows>p_rows THEN
        RAISE EXCEPTION 'user access label definition budget exhausted' USING ERRCODE='54000';
    END IF;
    SELECT ARRAY(SELECT DISTINCT (m.value#>>'{2,account_id}') COLLATE "C" AS account_id
        FROM jsonb_array_elements(memberships) m ORDER BY account_id) INTO account_ids;
    account_count:=cardinality(account_ids);

    -- Удерживаем как найденное определение, так и отсутствие конкурирующих
    -- определений до фиксации. Используем тот же порядок, что для Group.
    LOCK TABLE kaname.authority_access_label_definition IN SHARE MODE;
    FOR delta IN SELECT coalesce(o.key,n.key) AS changed_key,o.value AS old_value,n.value AS new_value
        FROM jsonb_each_text(old_labels) o FULL JOIN jsonb_each_text(new_labels) n ON n.key=o.key
        WHERE o.value COLLATE "C" IS DISTINCT FROM n.value COLLATE "C"
        ORDER BY coalesce(o.key,n.key) COLLATE "C"
    LOOP
        used_rows:=used_rows+account_count+1;
        used_reads:=used_reads+1;
        IF used_rows>p_rows OR used_reads>p_reads THEN
            RAISE EXCEPTION 'user access label definition budget exhausted' USING ERRCODE='54000';
        END IF;
        cluster_found:=false;
        account_found:=0;
        FOR definition IN
            SELECT d.id,d.scope_kind,d.scope_id,d.revision,d.xmin::text AS row_xmin,d.ctid::text AS row_ctid
            FROM kaname.authority_access_label_definition d
            WHERE d.module='iam' AND d.resource='user' AND d.label_key=delta.changed_key
              AND ((d.scope_kind='cluster' AND d.scope_id='cluster_root')
                   OR (d.scope_kind='account' AND d.scope_id=ANY(account_ids)))
            ORDER BY d.scope_kind DESC,d.scope_id COLLATE "C"
        LOOP
            IF definition.scope_kind='cluster' THEN
                cluster_found:=true;
            ELSE
                account_found:=account_found+1;
            END IF;
            IF cluster_found AND account_found>0 THEN
                RAISE EXCEPTION 'user access label definition is ambiguous' USING ERRCODE='42501';
            END IF;
            used_rows:=used_rows+2;
            used_reads:=used_reads+2;
            IF jsonb_array_length(requirements)>=128 OR used_rows>p_rows OR used_reads>p_reads THEN
                RAISE EXCEPTION 'user access label definition budget exhausted' USING ERRCODE='54000';
            END IF;
            IF kaname.authority_access_label_definition_hold_v1(definition.scope_kind,definition.scope_id,
                'iam','user',delta.changed_key,definition.id,definition.revision,
                definition.row_xmin,definition.row_ctid,delta.new_value) IS DISTINCT FROM true THEN
                RAISE EXCEPTION 'user access label value or revision is not allowed' USING ERRCODE='42501';
            END IF;
            requirements:=requirements||jsonb_build_array(jsonb_build_object('key',delta.changed_key,
                'old_value',delta.old_value,'new_value',delta.new_value,'definition_id',definition.id,
                'scope_kind',definition.scope_kind,'scope_id',definition.scope_id,
                'revision',definition.revision,'row_xmin',definition.row_xmin,'row_ctid',definition.row_ctid));
        END LOOP;
        IF NOT cluster_found AND (account_count=0 OR account_found<>account_count) THEN
            RAISE EXCEPTION 'user access label has no definition in every applicable scope' USING ERRCODE='42501';
        END IF;
    END LOOP;
    RETURN jsonb_build_object('requirements',requirements,'rows',used_rows,'reads',used_reads);
END;
$requirements$;
-- +goose StatementEnd

-- Источники выдачи удерживаются для актора из замороженного образа.
-- Окончательный precommit передаёт эти же требования и источники в
-- _authority_resource_access_label_sources_require_v1 на decision_at.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_apply_sources_v1(p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $sources$
DECLARE
    actor jsonb;
    definitions jsonb;
    held jsonb;
    used_rows integer:=1;
    used_reads integer:=1;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF p_rows IS NULL OR p_rows NOT BETWEEN 3 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 3 AND 4096 THEN
        RAISE EXCEPTION 'user access label source budget exhausted' USING ERRCODE='54000';
    END IF;
    actor:=kaname._authority_metadata_access_label_stashed_v1()#>'{user_images,actor}';
    definitions:=kaname._authority_metadata_user_access_label_requirements_v1(p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(definitions->>'rows')::integer;
    used_reads:=used_reads+(definitions->>'reads')::integer;
    held:=kaname._authority_resource_access_label_sources_hold_v1(actor->>'type',actor->>'id',
        definitions->'requirements',p_rows-used_rows,p_reads-used_reads);
    RETURN jsonb_build_object('requirements',definitions->'requirements','authority',held,
        'rows',used_rows+(held->>'rows')::integer,'reads',used_reads+(held->>'reads')::integer);
END;
$sources$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE
    fn regprocedure;
    grantee record;
BEGIN
    FOREACH fn IN ARRAY ARRAY[
        'kaname._authority_metadata_user_access_label_requirements_v1(integer,integer)'::regprocedure,
        'kaname._authority_metadata_user_apply_sources_v1(integer,integer)'::regprocedure
    ] LOOP
        FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
            WHERE p.oid=fn AND a.grantee<>p.proowner
        LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
                CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE quote_ident(grantee.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_metadata_user_apply_sources_v1(integer,integer);
DROP FUNCTION kaname._authority_metadata_user_access_label_requirements_v1(integer,integer);
