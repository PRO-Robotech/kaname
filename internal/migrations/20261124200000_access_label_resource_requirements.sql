-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Владелец программы записи передаёт удержанный OLD и построенный NEW.
-- Из этих образов функция выводит координаты ключей и удерживает определения
-- до конца транзакции. Проверка права применить каждый ключ выполняется отдельно.

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_resource_access_label_requirements_v1(
 p_resource text,p_old jsonb,p_new jsonb,p_rows integer,p_reads integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $requirements$
DECLARE
 resource_id text;
 account_id text;
 old_labels jsonb;
 new_labels jsonb;
 delta record;
 held record;
 candidates integer;
 used_rows integer;
 used_reads integer;
 result jsonb:='[]'::jsonb;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'access label definitions require a locked decision transaction' USING ERRCODE='25001';
 END IF;
 IF p_resource IS NULL OR p_resource NOT IN ('account','project')
  OR jsonb_typeof(p_old) IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_new) IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_old->'id') IS DISTINCT FROM 'string'
  OR p_old->'id' IS DISTINCT FROM p_new->'id'
  OR (p_resource='project' AND (
   jsonb_typeof(p_old->'account_id') IS DISTINCT FROM 'string'
   OR p_old->'account_id' IS DISTINCT FROM p_new->'account_id')) THEN
  RAISE EXCEPTION 'invalid resource access label identity' USING ERRCODE='42501';
 END IF;
 resource_id:=p_old->>'id';
 account_id:=CASE WHEN p_resource='account' THEN resource_id ELSE p_old->>'account_id' END;
 old_labels:=p_old->'access_labels';
 new_labels:=p_new->'access_labels';
 IF account_id COLLATE "C" !~ '^acc[a-zA-Z0-9_-]{1,61}$'
  OR (p_resource='project' AND resource_id COLLATE "C" !~ '^prj[a-zA-Z0-9_-]{1,61}$')
  OR kaname.access_labels_valid_v1(old_labels) IS DISTINCT FROM true
  OR kaname.access_labels_valid_v1(new_labels) IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'invalid resource access label images' USING ERRCODE='42501';
 END IF;
 -- Начисляем разбор обеих ограниченных карт и общий шаг дельты, включая
 -- удалённые ключи. У равных карт нет обращений к реестру определений.
 used_rows:=(SELECT count(*) FROM jsonb_object_keys(old_labels))
           +(SELECT count(*) FROM jsonb_object_keys(new_labels));
 used_reads:=1;
 IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
  OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
  RAISE EXCEPTION 'resource access label definition budget exhausted' USING ERRCODE='54000';
 END IF;
 IF old_labels=new_labels THEN
  RETURN jsonb_build_object('requirements',result,'rows',used_rows,'reads',used_reads);
 END IF;
 -- Для ключа должна существовать ровно одна применимая политика. Защищаем
 -- и существующие строки, и отсутствие второго определения в области.
 -- SHARE совместим с другими проверками ресурса. Правка реестра ждёт commit.
 LOCK TABLE kaname.authority_access_label_definition IN SHARE MODE;
 FOR delta IN SELECT coalesce(o.key,n.key) AS changed_key,o.value AS old_value,n.value AS new_value
  FROM jsonb_each_text(old_labels) o FULL JOIN jsonb_each_text(new_labels) n ON n.key=o.key
  WHERE o.value COLLATE "C" IS DISTINCT FROM n.value COLLATE "C"
  ORDER BY coalesce(o.key,n.key) COLLATE "C"
 LOOP
  -- Три точечных ключа, удержание определения и проверка допустимого
  -- значения. Запас начисляется и на отсутствующие строки.
  used_rows:=used_rows+CASE WHEN p_resource='project' THEN 3 ELSE 2 END+2;
  used_reads:=used_reads+3;
  IF used_rows>p_rows OR used_reads>p_reads THEN
   RAISE EXCEPTION 'resource access label definition budget exhausted' USING ERRCODE='54000';
  END IF;
  candidates:=0;
  FOR held IN SELECT d.id,d.scope_kind,d.scope_id,d.revision,d.xmin::text AS row_xmin,d.ctid::text AS row_ctid
   FROM (VALUES ('cluster','cluster_root'),('account',account_id),
    ('project',CASE WHEN p_resource='project' THEN resource_id END)) s(kind,id)
   JOIN kaname.authority_access_label_definition d ON d.scope_kind=s.kind AND d.scope_id=s.id
    AND d.module='iam' AND d.resource=p_resource AND d.label_key=delta.changed_key
   ORDER BY d.id LIMIT 2
  LOOP
   candidates:=candidates+1;
   IF candidates<>1 THEN
    RAISE EXCEPTION 'resource access label definition is ambiguous' USING ERRCODE='42501';
   END IF;
   IF kaname.authority_access_label_definition_hold_v1(held.scope_kind,held.scope_id,'iam',
       p_resource,delta.changed_key,held.id,held.revision,held.row_xmin,held.row_ctid,delta.new_value) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'resource access label value or generation is not allowed' USING ERRCODE='42501';
   END IF;
   result:=result||jsonb_build_array(jsonb_build_object('key',delta.changed_key,
    'old_value',delta.old_value,'new_value',delta.new_value,'definition_id',held.id,
    'scope_kind',held.scope_kind,'scope_id',held.scope_id,
    'revision',held.revision,'row_xmin',held.row_xmin,'row_ctid',held.row_ctid));
  END LOOP;
  IF candidates<>1 THEN
   RAISE EXCEPTION 'resource access label has no applicable definition' USING ERRCODE='42501';
  END IF;
 END LOOP;
 RETURN jsonb_build_object('requirements',result,'rows',used_rows,'reads',used_reads);
END;
$requirements$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION kaname._authority_resource_access_label_requirements_v1(text,jsonb,jsonb,integer,integer) FROM PUBLIC;
-- +goose StatementBegin
DO $private$
DECLARE item record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 FOR item IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a
  JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname._authority_resource_access_label_requirements_v1(text,jsonb,jsonb,integer,integer)'::regprocedure
    AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_resource_access_label_requirements_v1(text,jsonb,jsonb,integer,integer) FROM %I',item.rolname);
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_resource_access_label_requirements_v1(text,jsonb,jsonb,integer,integer);
