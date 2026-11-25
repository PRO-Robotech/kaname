-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Внутренняя передача координат поколения. Полное свидетельство повторно
-- вычисляет и хранит SQL-компилятор владельца после захвата удержаний.
CREATE FUNCTION kaname.authority_resource_generation_observe_v1(
 p_model text,p_id text,p_rows integer,p_reads integer
) RETURNS TABLE(fingerprint text,roots jsonb,outputs jsonb,logical_rows integer,logical_reads integer)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $observe$
DECLARE invoker oid;probe record;captured jsonb;
BEGIN
 -- Проекция доступна рабочему LOGIN, который уже обслуживает очередь.
 -- Остальные полномочия и isolation проверяет короткая проверка pending.
 SELECT r.oid INTO STRICT invoker FROM pg_catalog.pg_roles r
  WHERE r.rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 IF NOT has_table_privilege(invoker,'kaname.resource_reconcile_outbox'::regclass,'UPDATE') THEN
  RAISE EXCEPTION 'generation observation requires existing worker update access' USING ERRCODE='42501';
 END IF;
 SELECT * INTO STRICT probe FROM kaname.authority_resource_reconcile_pending_v1(p_model,p_id,p_rows,p_reads);
 logical_rows:=probe.logical_rows;logical_reads:=probe.logical_reads;
 roots:='[]'::jsonb;outputs:='[]'::jsonb;
 IF NOT probe.pending THEN
  -- Пустой предикат тоже повторно проверяет компилятор RC.
  fingerprint:=NULL;
  RETURN NEXT;
  RETURN;
 END IF;
 captured:=kaname._authority_access_label_object_generation_capture_v1(
  p_model,p_id,p_rows-logical_rows,p_reads-logical_reads);
 IF jsonb_array_length(captured->'roots')=0 THEN
  RAISE EXCEPTION 'generation observation disagrees in one snapshot' USING ERRCODE='40001';
 END IF;
 logical_rows:=logical_rows+(captured->>'rows')::integer;
 logical_reads:=logical_reads+(captured->>'reads')::integer;
 -- Скрываем полезную нагрузку. Хеш содержит версии строк и все координаты
 -- вместе с получателями, но сами получатели и метки остаются у владельца.
 fingerprint:=pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(captured::text,'UTF8')),'hex');
 SELECT coalesce(jsonb_agg(jsonb_build_array(r#>>'{state,2,root_type}',r#>>'{state,2,root_id}')
   ORDER BY r#>>'{state,2,root_type}' COLLATE "C",r#>>'{state,2,root_id}' COLLATE "C"),'[]'::jsonb)
  INTO roots FROM jsonb_array_elements(captured->'roots') r;
 SELECT coalesce(jsonb_agg(jsonb_build_array(c.object_type,c.object_id)
   ORDER BY c.object_type COLLATE "C",c.object_id COLLATE "C"),'[]'::jsonb)
  INTO outputs FROM (
   SELECT DISTINCT f->>'object_type' COLLATE "C" object_type,f->>'object_id' COLLATE "C" object_id
   FROM jsonb_array_elements(captured->'roots') r
   CROSS JOIN LATERAL jsonb_array_elements(r->'facts') f
  ) c;
 RETURN NEXT;
END;
$observe$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $acl$
DECLARE recipient record;
BEGIN
 REVOKE ALL ON FUNCTION kaname.authority_resource_generation_observe_v1(text,text,integer,integer) FROM PUBLIC;
 FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname.authority_resource_generation_observe_v1(text,text,integer,integer)'::regprocedure
   AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.authority_resource_generation_observe_v1(text,text,integer,integer) FROM %I',recipient.rolname);
 END LOOP;
 -- Здесь доступны только координаты для планирования. Доступ к приватным
 -- таблицам и окончательное решение остаются под владельцем SQL-компилятора.
 GRANT EXECUTE ON FUNCTION kaname.authority_resource_generation_observe_v1(text,text,integer,integer) TO PUBLIC;
END;
$acl$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname.authority_resource_generation_observe_v1(text,text,integer,integer);
