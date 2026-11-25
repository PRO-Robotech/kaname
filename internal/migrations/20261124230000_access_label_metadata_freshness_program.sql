-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Закрытый переход между поколениями отзыва. Подключается к записи только
-- после удержания полного набора фактов и проверки итоговых полномочий.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_access_label_origin_v1(
 p_table text,p_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $origin$
DECLARE
 proof jsonb;
 header jsonb;
 program jsonb;
 command jsonb;
 freshness jsonb;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_table IS NULL OR p_table NOT IN ('accounts','projects') OR coalesce(p_id,'')='' THEN
  RAISE EXCEPTION 'protected metadata resource coordinate is invalid' USING ERRCODE='42501';END IF;
 SELECT x.proof,x.header INTO STRICT proof,header FROM kaname._authority_sequence_probe_v3() x;
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
  OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'full'
  OR NOT coalesce((proof->>'writer_contract'='2' AND proof->>'purpose'='decision')
    OR (proof->>'writer_contract'='1' AND proof->>'purpose'='participant'),false)
  OR header->>'family' IS DISTINCT FROM 'metadata'
  OR jsonb_typeof(header->'selected') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'protected metadata has no final signed command' USING ERRCODE='42501';END IF;
 program:=kaname._authority_sequence_store_v3();
 freshness:=program#>'{frozen,access_label_freshness}';
 IF program#>>'{frozen,kind}' IS DISTINCT FROM 'metadata.access_labels'
  OR (program#>>'{frozen,access_label_approved_at}')::timestamptz IS DISTINCT FROM (program->>'decision_at')::timestamptz
  OR (program->>'decision_at')::timestamptz IS DISTINCT FROM (proof->>'decision_at')::timestamptz
  OR (program->>'decision_at')::timestamptz IS NULL
  OR (program->>'selected_count')::integer IS DISTINCT FROM 1
  OR jsonb_typeof(freshness) IS DISTINCT FROM 'object'
  OR jsonb_typeof(freshness->'facts') IS DISTINCT FROM 'array'
  OR freshness->>'root_id' IS DISTINCT FROM p_id
  OR freshness->>'root_type' IS DISTINCT FROM (CASE p_table WHEN 'accounts' THEN 'iam.account' ELSE 'iam.project' END) THEN
  RAISE EXCEPTION 'protected metadata apply or freshness receipt is missing' USING ERRCODE='42501';END IF;
 SELECT e.origin INTO command FROM pg_temp.kaname_authority_sequence_effects e
 WHERE e.nonce=(header->>'nonce')::uuid AND e.ordinal=1 AND e.table_name='resource_journal' AND e.selected
  AND NOT (e.registered OR e.claimed OR e.consumed)
  AND e.origin->>'table'=p_table AND e.origin->>'operation'='UPDATE' AND e.origin->>'when'='AFTER'
  AND e.origin#>>'{old,id}'=p_id AND e.origin#>>'{new,id}'=p_id
  AND e.origin#>'{old,access_labels}'=freshness->'old_labels'
  AND e.origin#>'{new,access_labels}'=freshness->'new_labels';
 IF NOT FOUND THEN
  RAISE EXCEPTION 'protected metadata selected command is absent or already used' USING ERRCODE='42501';END IF;
 RETURN command;
END;
$origin$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_access_label_carry_v1(
 p_root_type text,p_root_id text,p_old_labels jsonb,p_rows integer,p_reads integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $carry$
DECLARE previous_generation uuid;previous_labels jsonb;facts jsonb;n integer;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF coalesce(p_root_type,'') NOT IN ('iam.account','iam.project') OR coalesce(p_root_id,'')=''
  OR kaname.access_labels_valid_v1(p_old_labels) IS DISTINCT FROM true
  OR p_rows IS NULL OR p_rows NOT BETWEEN 1 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 1 AND 4096 THEN
  RAISE EXCEPTION 'invalid access label freshness carry' USING ERRCODE='42501';END IF;
 -- Сначала удерживается строка ресурса. Подготавливаем запись в обе
 -- таблицы до финального решения, чтобы не ждать DDL после него.
 LOCK TABLE kaname.authority_access_label_dirty_root,kaname.authority_access_label_dirty_fact IN ROW EXCLUSIVE MODE;
 -- Писатель и обработчик отзыва берут строку поколения после ресурса.
 -- Обработчик повторно читает поколение под этой блокировкой.
 SELECT r.generation,r.new_labels INTO previous_generation,previous_labels
 FROM kaname.authority_access_label_dirty_root r WHERE r.root_type=p_root_type AND r.root_id=p_root_id FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('prior_generation',NULL,'prior_facts','[]'::jsonb,'rows',1,'reads',1);END IF;
 IF previous_labels IS DISTINCT FROM p_old_labels THEN
  RAISE EXCEPTION 'prior access label generation differs from current root' USING ERRCODE='40001';END IF;
 IF p_reads<2 THEN RAISE EXCEPTION 'access label freshness carry budget exhausted' USING ERRCODE='54000';END IF;
 SELECT count(*)::integer,coalesce(jsonb_agg(to_jsonb(f) ORDER BY f.object_type COLLATE "C",f.object_id COLLATE "C",
  f.relation COLLATE "C",f.subject COLLATE "C"),'[]'::jsonb) INTO n,facts
 FROM (SELECT d.object_type,d.object_id,d.relation,d.subject FROM kaname.authority_access_label_dirty_fact d
  WHERE d.root_type=p_root_type AND d.root_id=p_root_id AND d.generation=previous_generation
  LIMIT p_rows FOR UPDATE OF d) f;
 IF n>=p_rows THEN RAISE EXCEPTION 'access label freshness carry budget exhausted' USING ERRCODE='54000';END IF;
 RETURN jsonb_build_object('prior_generation',previous_generation,'prior_facts',facts,'rows',1+n,'reads',2);
END;
$carry$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_access_label_freshness_v1() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $freshness$
DECLARE
 command jsonb;
 store jsonb;
 receipt jsonb;
 v_root_type text;
 v_root_id text;
 v_generation uuid;
 previous_generation uuid;
 previous_labels jsonb;
 facts jsonb;
 expected integer;
 affected integer;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME NOT IN ('accounts','projects')
  OR TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'UPDATE'
  OR NEW.access_labels IS NOT DISTINCT FROM OLD.access_labels THEN
  RAISE EXCEPTION 'invalid access label freshness trigger context' USING ERRCODE='42501';END IF;
 command:=kaname._authority_metadata_access_label_origin_v1(TG_TABLE_NAME,OLD.id);
 IF command->'old' IS DISTINCT FROM to_jsonb(OLD) OR command->'new' IS DISTINCT FROM to_jsonb(NEW) THEN
  RAISE EXCEPTION 'access label freshness row differs from approved write' USING ERRCODE='42501';END IF;
 store:=kaname._authority_sequence_store_v3();
 receipt:=store#>'{frozen,access_label_freshness}';
 v_root_type:=receipt->>'root_type';
 v_root_id:=receipt->>'root_id';
 v_generation:=(store->>'nonce')::uuid;
 facts:=receipt->'facts';
 IF v_generation IS NULL OR NOT (receipt ? 'prior_generation')
  OR (store->'frozen') ? 'access_label_freshness_installed'
  OR jsonb_typeof(facts) IS DISTINCT FROM 'array' OR jsonb_array_length(facts)>100000 THEN
  RAISE EXCEPTION 'invalid access label freshness receipt' USING ERRCODE='42501';END IF;
 expected:=jsonb_array_length(facts);
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(facts) f
  WHERE jsonb_typeof(f) IS DISTINCT FROM 'object'
  OR f-ARRAY['object_type','object_id','relation','subject']<>'{}'::jsonb
  OR jsonb_typeof(f->'object_type') IS DISTINCT FROM 'string' OR coalesce(f->>'object_type','')='' OR f->>'object_type' LIKE '%.%'
  OR jsonb_typeof(f->'object_id') IS DISTINCT FROM 'string' OR coalesce(f->>'object_id','')=''
  OR jsonb_typeof(f->'relation') IS DISTINCT FROM 'string' OR coalesce(f->>'relation','')=''
  OR jsonb_typeof(f->'subject') IS DISTINCT FROM 'string' OR coalesce(f->>'subject','')='') THEN
  RAISE EXCEPTION 'invalid coordinate in access label freshness receipt' USING ERRCODE='42501';END IF;
 SELECT r.generation,r.new_labels INTO previous_generation,previous_labels
 FROM kaname.authority_access_label_dirty_root r WHERE r.root_type=v_root_type AND r.root_id=v_root_id FOR UPDATE;
 IF previous_generation IS DISTINCT FROM (receipt->>'prior_generation')::uuid
  OR (previous_generation IS NOT NULL AND previous_labels IS DISTINCT FROM OLD.access_labels) THEN
  RAISE EXCEPTION 'access label freshness generation changed after reservation' USING ERRCODE='40001';END IF;
 IF previous_generation IS NOT NULL THEN
  IF EXISTS(SELECT d.object_type,d.object_id,d.relation,d.subject FROM kaname.authority_access_label_dirty_fact d
   WHERE d.root_type=v_root_type AND d.root_id=v_root_id AND d.generation=previous_generation
   EXCEPT SELECT f.object_type,f.object_id,f.relation,f.subject
   FROM jsonb_to_recordset(facts) f(object_type text,object_id text,relation text,subject text)) THEN
   RAISE EXCEPTION 'access label freshness receipt lost a previously pending fact' USING ERRCODE='42501';END IF;
  DELETE FROM kaname.authority_access_label_dirty_root r
  WHERE r.root_type=v_root_type AND r.root_id=v_root_id AND r.generation=previous_generation;
  GET DIAGNOSTICS affected=ROW_COUNT;
  IF affected<>1 THEN RAISE EXCEPTION 'prior access label freshness root disappeared' USING ERRCODE='40001';END IF;
 END IF;
 IF expected<>0 THEN
  INSERT INTO kaname.authority_access_label_dirty_root(root_type,root_id,generation,new_labels)
  VALUES(v_root_type,v_root_id,v_generation,NEW.access_labels);
  INSERT INTO kaname.authority_access_label_dirty_fact(root_type,root_id,generation,object_type,object_id,relation,subject)
  SELECT v_root_type,v_root_id,v_generation,f.object_type,f.object_id,f.relation,f.subject
  FROM jsonb_to_recordset(facts) f(object_type text,object_id text,relation text,subject text);
  GET DIAGNOSTICS affected=ROW_COUNT;
  IF affected<>expected THEN RAISE EXCEPTION 'access label freshness receipt write incomplete' USING ERRCODE='42501';END IF;
 END IF;
 UPDATE pg_temp.kaname_authority_sequence_program p
 SET frozen=p.frozen||jsonb_build_object('access_label_freshness_installed',v_generation)
 WHERE p.singleton AND p.nonce=v_generation AND p.family='metadata' AND p.frozen=store->'frozen';
 GET DIAGNOSTICS affected=ROW_COUNT;
 IF affected<>1 THEN RAISE EXCEPTION 'access label freshness install could not be recorded' USING ERRCODE='42501';END IF;
 RETURN NULL;
END;
$freshness$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE target text;grantee record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 FOREACH target IN ARRAY ARRAY[
  '_authority_metadata_access_label_origin_v1(text,text)',
  '_authority_metadata_access_label_carry_v1(text,text,jsonb,integer,integer)',
  '_authority_metadata_access_label_freshness_v1()'
 ] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',target);
  FOR grantee IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE p.oid=to_regprocedure('kaname.'||target) AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM %I',target,grantee.rolname);
  END LOOP;
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_metadata_access_label_freshness_v1();
DROP FUNCTION kaname._authority_metadata_access_label_carry_v1(text,text,jsonb,integer,integer);
DROP FUNCTION kaname._authority_metadata_access_label_origin_v1(text,text);
