-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Пишем только согласованный физический переход. Журнал создаёт штатный
-- триггер группы, а аудит и пересчёт используют зарезервированные строки.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_write_v1(p_group text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $write$
DECLARE
    command jsonb;
    desired jsonb;
    previous jsonb;
    physical jsonb;
    actual jsonb;
    version jsonb;
    audit kaname.audit_outbox;
    reconcile kaname.resource_reconcile_outbox;
    invoker oid;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    command:=kaname._authority_metadata_group_command_v1();
    IF p_group IS DISTINCT FROM command->>'id'
        OR command->>'phase' IS DISTINCT FROM 'pending'
        OR command->'journal_consumed' IS DISTINCT FROM 'false'::jsonb
        OR command->'freshness_installed' IS DISTINCT FROM 'false'::jsonb THEN
        RAISE EXCEPTION 'group metadata command is not pending' USING ERRCODE='42501';
    END IF;

    invoker:=(kaname.authority_protocol_attestation()->>'invoker_oid')::oid;
    IF NOT coalesce(has_table_privilege(invoker,'kaname.groups','SELECT')
        AND has_column_privilege(invoker,'kaname.groups','name','UPDATE')
        AND has_column_privilege(invoker,'kaname.groups','description','UPDATE')
        AND has_column_privilege(invoker,'kaname.groups','labels','UPDATE')
        AND has_column_privilege(invoker,'kaname.groups','access_labels','UPDATE')
        AND has_table_privilege(invoker,'kaname.audit_outbox','INSERT')
        AND has_table_privilege(invoker,'kaname.resource_reconcile_outbox','INSERT'),false) THEN
        RAISE EXCEPTION 'group metadata write lacks original relation privileges' USING ERRCODE='42501';
    END IF;

    desired:=command->'new';
    previous:=command->'old';
    physical:=command->'physical';
    UPDATE ONLY kaname.groups AS g
    SET name=desired->>'name',description=desired->>'description',
        labels=desired->'labels',access_labels=desired->'access_labels'
    WHERE g.id=p_group AND g.account_id=command->>'account_id'
        AND g.xmin::text=physical->>'xmin' AND g.ctid::text=physical->>'ctid'
        AND to_jsonb(g)=previous
    RETURNING to_jsonb(g),jsonb_build_array(g.xmin::text,g.ctid::text) INTO actual,version;
    IF NOT FOUND OR actual IS DISTINCT FROM desired THEN
        RAISE EXCEPTION 'group metadata physical UPDATE changed' USING ERRCODE='40001';
    END IF;

    audit:=jsonb_populate_record(NULL::kaname.audit_outbox,command->'audit_row');
    INSERT INTO kaname.audit_outbox(id,event_type,tenant_account_id,event_payload,status,attempts,
        created_at,next_attempt_at,sent_at,last_error)
    VALUES(audit.id,audit.event_type,audit.tenant_account_id,audit.event_payload,audit.status,audit.attempts,
        audit.created_at,audit.next_attempt_at,audit.sent_at,audit.last_error);

    reconcile:=jsonb_populate_record(NULL::kaname.resource_reconcile_outbox,command->'reconcile_row');
    INSERT INTO kaname.resource_reconcile_outbox(id,object_type,object_id,event_type,created_at,
        sent_at,last_error,attempt_count)
    OVERRIDING SYSTEM VALUE VALUES(reconcile.id,reconcile.object_type,reconcile.object_id,reconcile.event_type,
        reconcile.created_at,reconcile.sent_at,reconcile.last_error,reconcile.attempt_count);

    PERFORM kaname._authority_metadata_group_consume_v1(version);
    RETURN actual;
END;
$write$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE
    fn regprocedure:='kaname._authority_metadata_group_write_v1(text)'::regprocedure;
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
DROP FUNCTION kaname._authority_metadata_group_write_v1(text);
