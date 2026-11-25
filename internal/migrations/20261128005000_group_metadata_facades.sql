-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Эти фасады принимают только входы текущего подписанного writer. Право
-- выполнения выдаётся после проверки полной установленной цепочки.
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_metadata_group_prepare_v1(
    p_id text,p_xmin text,p_ctid text,p_old jsonb,p_access_labels jsonb,p_actor_type text,p_actor_id text,
    p_policy jsonb,p_writes text[],p_rows integer,p_reads integer,p_work integer
) RETURNS TABLE(used_rows integer,used_reads integer,used_work integer)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $prepare$
    SELECT * FROM kaname._authority_metadata_group_prepare_v1(
        p_id,p_xmin,p_ctid,p_old,p_access_labels,p_actor_type,p_actor_id,p_policy,p_writes,p_rows,p_reads,p_work);
$prepare$;

CREATE FUNCTION kaname.authority_metadata_group_retention_inputs_v1(
    p_patch jsonb,p_rename boolean,p_actor_type text,p_actor_id text,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $retention$
    SELECT kaname._authority_metadata_group_retention_prepare_v1(
        p_patch,p_rename,p_actor_type,p_actor_id,p_rows,p_reads,p_work);
$retention$;

CREATE FUNCTION kaname.authority_metadata_group_reserve_v1(
    p_desired jsonb,p_audit text,p_actor_type text,p_actor_id text,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $reserve$
    SELECT kaname._authority_metadata_group_compile_reserve_v1(
        p_desired,p_audit,p_actor_type,p_actor_id,p_rows,p_reads,p_work);
$reserve$;

CREATE FUNCTION kaname.authority_metadata_group_accept_v1(
    p_actor_type text,p_actor_id text,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $accept$
    SELECT kaname._authority_metadata_group_accept_v1(p_actor_type,p_actor_id,p_rows,p_reads,p_work);
$accept$;

CREATE FUNCTION kaname.authority_metadata_group_write_v1(p_id text)
RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $write$
    SELECT kaname._authority_metadata_group_write_v1(p_id);
$write$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE
    signature text;
    fn regprocedure;
    grantee record;
BEGIN
    FOREACH signature IN ARRAY ARRAY[
        'authority_metadata_group_prepare_v1(text,text,text,jsonb,jsonb,text,text,jsonb,text[],integer,integer,integer)',
        'authority_metadata_group_retention_inputs_v1(jsonb,boolean,text,text,integer,integer,integer)',
        'authority_metadata_group_reserve_v1(jsonb,text,text,text,integer,integer,integer)',
        'authority_metadata_group_accept_v1(text,text,integer,integer,integer)',
        'authority_metadata_group_write_v1(text)'
    ] LOOP
        fn:=to_regprocedure('kaname.'||signature);
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
DROP FUNCTION kaname.authority_metadata_group_write_v1(text);
DROP FUNCTION kaname.authority_metadata_group_accept_v1(text,text,integer,integer,integer);
DROP FUNCTION kaname.authority_metadata_group_reserve_v1(jsonb,text,text,text,integer,integer,integer);
DROP FUNCTION kaname.authority_metadata_group_retention_inputs_v1(jsonb,boolean,text,text,integer,integer,integer);
DROP FUNCTION kaname.authority_metadata_group_prepare_v1(text,text,text,jsonb,jsonb,text,text,jsonb,text[],integer,integer,integer);
