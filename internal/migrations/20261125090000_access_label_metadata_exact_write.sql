-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Закрытая запись по точному образу ресурса, удержанному до решения.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_metadata_access_label_write_v1(p_kind text,p_id text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $write$
DECLARE
 table_name text; command jsonb; program jsonb; program_nonce uuid;
 old_row jsonb; new_row jsonb; physical jsonb; actual jsonb;
 installed jsonb; affected bigint; invoker oid; field_name text;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_kind IS NULL OR p_kind NOT IN ('account','project')
  OR coalesce(p_id,'')='' OR octet_length(p_id)>16384
  OR p_id ~ '[:#*[:space:][:cntrl:]]' THEN
  RAISE EXCEPTION 'protected metadata write coordinate invalid' USING ERRCODE='42501';END IF;
 table_name:=CASE p_kind WHEN 'account' THEN 'accounts' ELSE 'projects' END;
 -- Команда уже привязана к окончательному времени решения и одной записи журнала.
 command:=kaname._authority_metadata_access_label_origin_v1(table_name,p_id);
 program:=kaname._authority_sequence_store_v3();
 program_nonce:=(program->>'nonce')::uuid;
 old_row:=command->'old';new_row:=command->'new';
 physical:=program#>'{frozen,access_label_root_physical}';
 IF program_nonce IS NULL OR jsonb_typeof(old_row) IS DISTINCT FROM 'object'
  OR jsonb_typeof(new_row) IS DISTINCT FROM 'object'
  OR old_row->>'id' IS DISTINCT FROM p_id OR new_row->>'id' IS DISTINCT FROM p_id
  OR (old_row-ARRAY['name','description','labels','access_labels']) IS DISTINCT FROM
     (new_row-ARRAY['name','description','labels','access_labels'])
  OR jsonb_typeof(new_row->'name') IS DISTINCT FROM 'string'
  OR jsonb_typeof(new_row->'description') IS DISTINCT FROM 'string'
  OR jsonb_typeof(new_row->'labels') IS DISTINCT FROM 'object'
  OR kaname.access_labels_valid_v1(new_row->'access_labels') IS DISTINCT FROM true
  OR old_row->'access_labels' IS NOT DISTINCT FROM new_row->'access_labels'
  OR jsonb_typeof(physical) IS DISTINCT FROM 'object'
  OR physical->>'table' IS DISTINCT FROM table_name OR physical->>'id' IS DISTINCT FROM p_id
  OR jsonb_typeof(physical->'xmin') IS DISTINCT FROM 'string'
  OR coalesce(physical->>'xmin','')=''
  OR jsonb_typeof(physical->'ctid') IS DISTINCT FROM 'string'
  OR coalesce(physical->>'ctid','')=''
  OR (program->'frozen') ? 'access_label_freshness_installed' THEN
  RAISE EXCEPTION 'protected metadata exact physical command missing' USING ERRCODE='42501';END IF;
 -- Права владельца функции не заменяют исходные права подключения.
 invoker:=(program->>'invoker_oid')::oid;
 IF invoker IS NULL OR NOT has_table_privilege(invoker,to_regclass('kaname.'||table_name),'SELECT')
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c
   WHERE c.oid=to_regclass('kaname.'||table_name) AND (c.relrowsecurity OR c.relforcerowsecurity)) THEN
  RAISE EXCEPTION 'protected metadata existing row read privilege required' USING ERRCODE='42501';END IF;
 FOREACH field_name IN ARRAY ARRAY['name','description','labels','access_labels'] LOOP
  IF NOT has_column_privilege(invoker,to_regclass('kaname.'||table_name),field_name,'UPDATE') THEN
   RAISE EXCEPTION 'protected metadata existing field write privilege required' USING ERRCODE='42501';END IF;
 END LOOP;
 -- Подготовка удерживает строку. xmin и ctid также различают повторную запись с тем же значением.
 EXECUTE format('UPDATE ONLY kaname.%I AS target
  SET name=$1::jsonb->>''name'',description=$1::jsonb->>''description'',
      labels=$1::jsonb->''labels'',access_labels=$1::jsonb->''access_labels''
  WHERE target.id=$2 AND target.xmin::text=$3 AND target.ctid::text=$4
    AND to_jsonb(target)=$5::jsonb RETURNING to_jsonb(target)',table_name)
 INTO actual USING new_row,p_id,physical->>'xmin',physical->>'ctid',old_row;
 GET DIAGNOSTICS affected=ROW_COUNT;
 IF affected<>1 OR actual IS DISTINCT FROM new_row THEN
  RAISE EXCEPTION 'protected metadata physical root changed before write' USING ERRCODE='40001';END IF;
 -- Запись и поколение отзыва фиксируются только вместе.
 SELECT p.frozen->'access_label_freshness_installed' INTO installed
 FROM pg_temp.kaname_authority_sequence_program p
 WHERE p.singleton AND p.nonce=program_nonce AND p.family='metadata';
 IF installed IS DISTINCT FROM to_jsonb(program_nonce) THEN
  RAISE EXCEPTION 'protected metadata freshness was not installed atomically' USING ERRCODE='42501';END IF;
 RETURN actual;
END;
$write$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE recipient record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 REVOKE ALL ON FUNCTION kaname.authority_metadata_access_label_write_v1(text,text) FROM PUBLIC;
 FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a
  JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname.authority_metadata_access_label_write_v1(text,text)'::regprocedure
   AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.authority_metadata_access_label_write_v1(text,text) FROM %I',recipient.rolname);
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname.authority_metadata_access_label_write_v1(text,text);
