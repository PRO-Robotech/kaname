-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Удерживаем источники apply для того же актора, группы и изменённых ключей.
-- Возвращённые свидетельства используются на окончательном decision_at.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_compile_sources_v1(
    p_desired jsonb,p_actor_type text,p_actor_id text,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $sources$
DECLARE
    compiled jsonb;
    definitions jsonb;
    required jsonb;
    held jsonb;
    v_group text;
    used_rows integer:=1;
    used_reads integer:=1;
    used_work integer:=1;
    changed_count integer;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF p_rows IS NULL OR p_rows NOT BETWEEN 3 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 3 AND 4096
        OR p_work IS NULL OR p_work NOT BETWEEN 3 AND 400000 THEN
        RAISE EXCEPTION 'group apply compile budget invalid' USING ERRCODE='54000';
    END IF;
    IF coalesce(p_actor_type,'') NOT IN ('user','service_account')
        OR coalesce(p_actor_id,'')='' OR octet_length(p_actor_id)>16384
        OR p_actor_id ~ '[:#*[:space:][:cntrl:]]'
        OR kaname._authority_sequence_store_v3() IS NOT NULL THEN
        RAISE EXCEPTION 'group apply compile actor or stage invalid' USING ERRCODE='42501';
    END IF;
    compiled:=kaname._authority_metadata_group_retention_compile_v1(p_desired,p_work-used_work);
    v_group:=compiled#>>'{receipt,root_id}';
    IF compiled->'update_question' IS DISTINCT FROM jsonb_build_object(
        'subject',p_actor_type||':'||p_actor_id,'relation','v_update','object_type','iam_group','object_id',v_group) THEN
        RAISE EXCEPTION 'group apply actor differs from held update question' USING ERRCODE='42501';
    END IF;
    used_rows:=used_rows+(compiled->>'rows')::integer;
    used_reads:=used_reads+(compiled->>'reads')::integer;
    used_work:=used_work+(compiled->>'work')::integer;

    definitions:=kaname._authority_metadata_group_access_label_requirements_v1(p_rows-used_rows,p_reads-used_reads);
    required:=definitions->'requirements';
    IF jsonb_typeof(required) IS DISTINCT FROM 'array' OR jsonb_array_length(required) NOT BETWEEN 1 AND 128 THEN
        RAISE EXCEPTION 'group apply has no changed protected keys' USING ERRCODE='42501';
    END IF;
    changed_count:=jsonb_array_length(required);
    used_rows:=used_rows+(definitions->>'rows')::integer;
    used_reads:=used_reads+(definitions->>'reads')::integer;
    used_work:=used_work+changed_count;
    IF used_work>p_work THEN
        RAISE EXCEPTION 'group apply source compile budget exceeded' USING ERRCODE='54000';
    END IF;
    held:=kaname._authority_resource_access_label_sources_hold_v1(
        p_actor_type,p_actor_id,required,p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(held->>'rows')::integer;
    used_reads:=used_reads+(held->>'reads')::integer;
    used_work:=used_work+(held->>'source_count')::integer;
    IF used_rows IS NULL OR used_rows NOT BETWEEN 1 AND p_rows OR used_reads IS NULL OR used_reads NOT BETWEEN 1 AND p_reads
        OR used_work IS NULL OR used_work NOT BETWEEN 1 AND p_work THEN
        RAISE EXCEPTION 'group apply source compile budget exceeded' USING ERRCODE='54000';
    END IF;
    RETURN jsonb_build_object('compiled',compiled,'requirements',required,'authority',held,
        'rows',used_rows,'reads',used_reads,'work',used_work);
END;
$sources$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE
    fn regprocedure:='kaname._authority_metadata_group_compile_sources_v1(jsonb,text,text,integer,integer,integer)'::regprocedure;
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
DROP FUNCTION kaname._authority_metadata_group_compile_sources_v1(jsonb,text,text,integer,integer,integer);
