-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_metadata_group_ordinary_reserve_v1(
    p_id text,p_xmin text,p_ctid text,p_old jsonb,p_patch jsonb,p_actor_type text,p_actor_id text,
    p_audit text,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $ordinary$
    SELECT kaname._authority_metadata_group_ordinary_reserve_v1(
        p_id,p_xmin,p_ctid,p_old,p_patch,p_actor_type,p_actor_id,p_audit,p_rows,p_reads,p_work);
$ordinary$;

-- Режим выбирает закрытая программа той же транзакции. Аргумент клиента
-- не может переключить обычную запись в запись защищённых меток.
CREATE OR REPLACE FUNCTION kaname.authority_metadata_group_accept_v1(
    p_actor_type text,p_actor_id text,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $accept$
DECLARE
    mode text:=kaname._authority_sequence_header_v3()#>>'{frozen,mode}';
BEGIN
    IF mode IN ('group_ordinary','group_noop') THEN
        RETURN kaname._authority_metadata_group_ordinary_accept_v1(p_actor_type,p_actor_id,p_rows,p_reads,p_work);
    END IF;
    RETURN kaname._authority_metadata_group_accept_v1(p_actor_type,p_actor_id,p_rows,p_reads,p_work);
END;
$accept$;

CREATE OR REPLACE FUNCTION kaname.authority_metadata_group_write_v1(p_id text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $write$
DECLARE
    mode text:=kaname._authority_sequence_header_v3()#>>'{frozen,mode}';
BEGIN
    IF mode IN ('group_ordinary','group_noop') THEN
        RETURN kaname._authority_metadata_group_ordinary_write_v1(p_id);
    END IF;
    RETURN kaname._authority_metadata_group_write_v1(p_id);
END;
$write$;

DO $private$
DECLARE
    fn regprocedure:='kaname.authority_metadata_group_ordinary_reserve_v1(text,text,text,jsonb,jsonb,text,text,text,integer,integer,integer)'::regprocedure;
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

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_metadata_group_accept_v1(
    p_actor_type text,p_actor_id text,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $accept$
    SELECT kaname._authority_metadata_group_accept_v1(p_actor_type,p_actor_id,p_rows,p_reads,p_work);
$accept$;

CREATE OR REPLACE FUNCTION kaname.authority_metadata_group_write_v1(p_id text)
RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $write$
    SELECT kaname._authority_metadata_group_write_v1(p_id);
$write$;
-- +goose StatementEnd

DROP FUNCTION kaname.authority_metadata_group_ordinary_reserve_v1(text,text,text,jsonb,jsonb,text,text,text,integer,integer,integer);
