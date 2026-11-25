-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Временная отсрочка успешного частичного пересчёта. Запись события и форма
-- программ, которые его создают, остаются прежними. Удаление события очищает
-- и его отметку об отсрочке.

-- +goose Up
SELECT kaname.authority_protocol_require_owner();
CREATE TABLE kaname.resource_reconcile_event_defer (
 event_id bigint PRIMARY KEY REFERENCES kaname.resource_reconcile_outbox(id) ON DELETE CASCADE,
 ready_at timestamptz NOT NULL
);
-- +goose StatementBegin
CREATE FUNCTION kaname.resource_reconcile_is_due_v1(p_event_id bigint) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $due$
DECLARE invoker oid;
BEGIN
 SELECT r.oid INTO STRICT invoker FROM pg_catalog.pg_roles r
 WHERE r.rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 IF NOT has_table_privilege(invoker,'kaname.resource_reconcile_outbox'::regclass,'SELECT') THEN
  RAISE EXCEPTION 'reconcile event reader required' USING ERRCODE='42501';END IF;
 RETURN NOT EXISTS(SELECT 1 FROM kaname.resource_reconcile_event_defer d
  WHERE d.event_id=p_event_id AND d.ready_at>statement_timestamp());
END;
$due$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.resource_reconcile_defer_pending_v1(p_event_id bigint) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $defer$
DECLARE invoker oid;
BEGIN
 SELECT r.oid INTO STRICT invoker FROM pg_catalog.pg_roles r
 WHERE r.rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 IF NOT has_table_privilege(invoker,'kaname.resource_reconcile_outbox'::regclass,'SELECT')
  OR NOT has_table_privilege(invoker,'kaname.resource_reconcile_outbox'::regclass,'UPDATE') THEN
  RAISE EXCEPTION 'reconcile event worker required' USING ERRCODE='42501';END IF;
 -- Закрытое или удалённое другой репликой событие повторно не ставится.
 PERFORM q.id FROM kaname.resource_reconcile_outbox q WHERE q.id=p_event_id AND q.sent_at IS NULL FOR UPDATE;
 IF NOT FOUND THEN RETURN;END IF;
 INSERT INTO kaname.resource_reconcile_event_defer(event_id,ready_at)
 VALUES(p_event_id,statement_timestamp()+interval '5 seconds')
 ON CONFLICT(event_id) DO UPDATE SET ready_at=greatest(resource_reconcile_event_defer.ready_at,excluded.ready_at);
END;
$defer$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $acl$
DECLARE item record;
BEGIN
 REVOKE ALL ON kaname.resource_reconcile_event_defer FROM PUBLIC;
 FOR item IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_class c
  CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE c.oid='kaname.resource_reconcile_event_defer'::regclass AND a.grantee<>c.relowner LOOP
  EXECUTE format('REVOKE ALL ON TABLE kaname.resource_reconcile_event_defer FROM %I',item.rolname);
 END LOOP;
 FOR item IN SELECT DISTINCT p.oid::regprocedure AS signature,r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid IN ('kaname.resource_reconcile_is_due_v1(bigint)'::regprocedure,
                  'kaname.resource_reconcile_defer_pending_v1(bigint)'::regprocedure) AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',item.signature,item.rolname);
 END LOOP;
END;
$acl$;
-- +goose StatementEnd
-- Функции проверяют прежние права на очередь для каждой штатной runtime-роли.
GRANT EXECUTE ON FUNCTION kaname.resource_reconcile_is_due_v1(bigint),kaname.resource_reconcile_defer_pending_v1(bigint) TO PUBLIC;

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname.resource_reconcile_defer_pending_v1(bigint);
DROP FUNCTION kaname.resource_reconcile_is_due_v1(bigint);
DROP TABLE kaname.resource_reconcile_event_defer;
