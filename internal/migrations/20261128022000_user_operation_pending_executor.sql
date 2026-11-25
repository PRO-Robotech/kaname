-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $enrollment$
DECLARE
    fn regprocedure:='kaname.authority_user_access_labels_operation_create_v1(text,timestamptz,text,text,bytea,text,text,text)'::regprocedure;
    src text;
BEGIN
    IF NOT EXISTS(SELECT FROM pg_catalog.pg_proc p
        WHERE p.oid='kaname.authority_role_actor_pair_ready_v1(oid,text)'::regprocedure
          AND p.proowner=current_user::regrole AND p.prosecdef AND p.provolatile='s'
          AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='f505be6caecf533c3bb32d76e640ef84be9288e25714ee696ccc43bb0aa1ec79') THEN
        RAISE EXCEPTION 'user operation enrollment prerequisite differs' USING ERRCODE='55000';
    END IF;
    SELECT p.prosrc INTO STRICT src FROM pg_catalog.pg_proc p
    WHERE p.oid=fn AND p.proowner=current_user::regrole AND p.prosecdef AND p.provolatile='v'
      AND NOT EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner);
    IF encode(sha256(convert_to(src,'UTF8')),'hex') IS DISTINCT FROM '4fea0a7ed4317ef17b1b45ad75c3f021bc2a5acbdf29178384811852fb38ff1e' THEN
        RAISE EXCEPTION 'user operation create predecessor differs' USING ERRCODE='55000';
    END IF;
    src:=replace(src,$before$DECLARE invoker oid;
BEGIN
    SELECT r.oid INTO STRICT invoker FROM pg_catalog.pg_roles r
    WHERE r.rolname=coalesce(nullif(current_setting('role'),'none'),session_user);$before$,$after$DECLARE invoker oid; runtime_name_before name;
BEGIN
    SELECT e.runtime_oid,e.runtime_name INTO invoker,runtime_name_before
    FROM ONLY kaname.authority_role_actor_login e WHERE e.singleton AND e.role_name=session_user;
    IF NOT FOUND OR kaname.authority_role_actor_pair_ready_v1(invoker,runtime_name_before::text) IS DISTINCT FROM true
        OR has_schema_privilege(invoker,'kaname','USAGE') IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'user operation requires the enrolled application LOGIN' USING ERRCODE='42501';
    END IF;$after$);
    src:=replace(src,$before$        p_id,p_created_at,p_user_id,p_account_id,p_metadata,p_actor_type,p_actor_id,p_display_name);$before$,$after$        p_id,p_created_at,p_user_id,p_account_id,p_metadata,p_actor_type,p_actor_id,p_display_name);
    -- configure берёт блокировки таблиц до enrollment. Удерживаем ту же пару
    -- после INSERT в этом же порядке; несовпадение откатывает pending.
    PERFORM FROM ONLY kaname.authority_role_actor_login e
    WHERE e.singleton AND e.runtime_oid=invoker AND e.runtime_name=runtime_name_before
        AND e.role_oid=to_regrole(quote_ident(session_user))::oid AND e.role_name=session_user FOR SHARE NOWAIT;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'user operation enrollment changed' USING ERRCODE='40001';
    END IF;$after$);
    IF encode(sha256(convert_to(src,'UTF8')),'hex') IS DISTINCT FROM 'c807513b9d0bdf5230781bc44a5be84d3a48b5569c4ce8bf8754d70ac9c2bfef' THEN
        RAISE EXCEPTION 'user operation create enrollment transition differs' USING ERRCODE='55000';
    END IF;
    EXECUTE format('CREATE OR REPLACE FUNCTION kaname.authority_user_access_labels_operation_create_v1(
        p_id text,p_created_at timestamptz,p_user_id text,p_account_id text,p_metadata bytea,
        p_actor_type text,p_actor_id text,p_display_name text) RETURNS void LANGUAGE plpgsql VOLATILE
        SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS %L',src);
END;
$enrollment$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $enrollment$
DECLARE
    fn regprocedure:='kaname.authority_user_access_labels_operation_create_v1(text,timestamptz,text,text,bytea,text,text,text)'::regprocedure;
    src text;
BEGIN
    SELECT p.prosrc INTO STRICT src FROM pg_catalog.pg_proc p
    WHERE p.oid=fn AND p.proowner=current_user::regrole AND p.prosecdef AND p.provolatile='v'
      AND NOT EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner);
    IF encode(sha256(convert_to(src,'UTF8')),'hex') IS DISTINCT FROM 'c807513b9d0bdf5230781bc44a5be84d3a48b5569c4ce8bf8754d70ac9c2bfef' THEN
        RAISE EXCEPTION 'user operation create predecessor differs' USING ERRCODE='55000';
    END IF;
    src:=replace(src,$before$DECLARE invoker oid; runtime_name_before name;
BEGIN
    SELECT e.runtime_oid,e.runtime_name INTO invoker,runtime_name_before
    FROM ONLY kaname.authority_role_actor_login e WHERE e.singleton AND e.role_name=session_user;
    IF NOT FOUND OR kaname.authority_role_actor_pair_ready_v1(invoker,runtime_name_before::text) IS DISTINCT FROM true
        OR has_schema_privilege(invoker,'kaname','USAGE') IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'user operation requires the enrolled application LOGIN' USING ERRCODE='42501';
    END IF;$before$,$after$DECLARE invoker oid;
BEGIN
    SELECT r.oid INTO STRICT invoker FROM pg_catalog.pg_roles r
    WHERE r.rolname=coalesce(nullif(current_setting('role'),'none'),session_user);$after$);
    src:=replace(src,$before$        p_id,p_created_at,p_user_id,p_account_id,p_metadata,p_actor_type,p_actor_id,p_display_name);
    -- configure берёт блокировки таблиц до enrollment. Удерживаем ту же пару
    -- после INSERT в этом же порядке; несовпадение откатывает pending.
    PERFORM FROM ONLY kaname.authority_role_actor_login e
    WHERE e.singleton AND e.runtime_oid=invoker AND e.runtime_name=runtime_name_before
        AND e.role_oid=to_regrole(quote_ident(session_user))::oid AND e.role_name=session_user FOR SHARE NOWAIT;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'user operation enrollment changed' USING ERRCODE='40001';
    END IF;$before$,$after$        p_id,p_created_at,p_user_id,p_account_id,p_metadata,p_actor_type,p_actor_id,p_display_name);$after$);
    IF encode(sha256(convert_to(src,'UTF8')),'hex') IS DISTINCT FROM '4fea0a7ed4317ef17b1b45ad75c3f021bc2a5acbdf29178384811852fb38ff1e' THEN
        RAISE EXCEPTION 'user operation create enrollment transition differs' USING ERRCODE='55000';
    END IF;
    EXECUTE format('CREATE OR REPLACE FUNCTION kaname.authority_user_access_labels_operation_create_v1(
        p_id text,p_created_at timestamptz,p_user_id text,p_account_id text,p_metadata bytea,
        p_actor_type text,p_actor_id text,p_display_name text) RETURNS void LANGUAGE plpgsql VOLATILE
        SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS %L',src);
END;
$enrollment$;
-- +goose StatementEnd
