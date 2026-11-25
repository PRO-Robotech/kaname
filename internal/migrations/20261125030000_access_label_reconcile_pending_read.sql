-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Узкое наблюдение для работника очереди в исходном снимке объекта.
-- Версии строк, получатели и значения меток остаются внутри программы владельца.
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_resource_reconcile_pending_v1(
 p_model text,p_id text,p_rows integer,p_reads integer
) RETURNS TABLE(pending boolean,logical_rows integer,logical_reads integer)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $pending$
DECLARE invoker oid;direct_type text;
BEGIN
 IF current_setting('transaction_isolation')<>'repeatable read'
  OR current_setting('transaction_read_only')<>'on' THEN
  RAISE EXCEPTION 'reconcile observation requires read-only repeatable read' USING ERRCODE='42501';
 END IF;
 SELECT r.oid INTO STRICT invoker FROM pg_catalog.pg_roles r
  WHERE r.rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 IF NOT has_function_privilege(invoker,'kaname.authority_resource_enter_v2(text,text[],jsonb,text,text,text)'::regprocedure,'EXECUTE')
  OR NOT has_table_privilege(invoker,'kaname.resource_reconcile_outbox'::regclass,'SELECT')
  OR NOT has_table_privilege(invoker,'kaname.relation_fact'::regclass,'SELECT')
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.relrowsecurity
   AND c.oid IN ('kaname.resource_reconcile_outbox'::regclass,'kaname.relation_fact'::regclass)) THEN
  RAISE EXCEPTION 'reconcile observation requires existing worker access' USING ERRCODE='42501';
 END IF;
 IF coalesce(p_model,'')='' OR p_model LIKE '%.%' OR coalesce(p_id,'')=''
  OR octet_length(p_model)>16384 OR octet_length(p_id)>16384
  OR p_model ~ '[:#*[:space:][:cntrl:]]' OR p_id ~ '[:#*[:space:][:cntrl:]]' THEN
  RAISE EXCEPTION 'reconcile observation coordinate invalid' USING ERRCODE='42501';
 END IF;
 IF p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000
  OR p_reads IS NULL OR p_reads NOT BETWEEN 1 AND 4096 THEN
  RAISE EXCEPTION 'reconcile observation budget invalid' USING ERRCODE='54000';
 END IF;

 -- Работник может обнаружить большое открытое поколение с постоянным
 -- бюджетом: ждём завершения поколения без чтения полного списка фактов.
 logical_reads:=1;
 direct_type:=CASE p_model WHEN 'account' THEN 'iam.account' WHEN 'project' THEN 'iam.project' END;
 IF direct_type IS NOT NULL THEN
  SELECT EXISTS(SELECT 1 FROM kaname.authority_access_label_dirty_root r
   WHERE r.root_type=direct_type AND r.root_id=p_id) INTO pending;
  IF NOT pending THEN
   logical_reads:=2;
  END IF;
 END IF;
 IF logical_reads>p_reads THEN
  RAISE EXCEPTION 'reconcile observation read budget exhausted' USING ERRCODE='54000';
 END IF;
 IF pending IS DISTINCT FROM true THEN
  SELECT EXISTS(SELECT 1 FROM kaname.authority_access_label_dirty_fact d
   WHERE d.object_type=p_model AND d.object_id=p_id) INTO pending;
 END IF;
 logical_rows:=CASE WHEN pending THEN 1 ELSE 0 END;
 IF logical_rows>p_rows THEN
  RAISE EXCEPTION 'reconcile observation row budget exhausted' USING ERRCODE='54000';
 END IF;
 RETURN NEXT;
END;
$pending$;
-- +goose StatementEnd

-- Сам вызов проверяет текущие права рабочего LOGIN, в том числе после их отзыва.
-- Явно убираем независимые назначения из default privileges.
-- +goose StatementBegin
DO $acl$
DECLARE recipient record;
BEGIN
 REVOKE ALL ON FUNCTION kaname.authority_resource_reconcile_pending_v1(text,text,integer,integer) FROM PUBLIC;
 FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname.authority_resource_reconcile_pending_v1(text,text,integer,integer)'::regprocedure
   AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.authority_resource_reconcile_pending_v1(text,text,integer,integer) FROM %I',recipient.rolname);
 END LOOP;
 GRANT EXECUTE ON FUNCTION kaname.authority_resource_reconcile_pending_v1(text,text,integer,integer) TO PUBLIC;
END;
$acl$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname.authority_resource_reconcile_pending_v1(text,text,integer,integer);
