-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Блокировка постоянной привязки подтверждается только текущей owner-транзакцией.
-- Путь записи внешнего ресурса пока не вызывает новый захват.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_registration_binding_holds_v1(p_budget integer)
RETURNS integer LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $hold$
DECLARE prepared jsonb; root_key text; source_index jsonb; root_catalog jsonb;
 source_entry record; model_type text; object_id text;
 logical_keys text[]:=ARRAY[]::text[]; lock_entry record; claims jsonb; affected integer;
BEGIN
 -- Stash проверяет подписанную попытку, её backend/xid/nonce и ACL таблицы.
 -- Внешний caller приходит сюда после строк эпох и до ожидания mirror root.
 prepared:=kaname._authority_metadata_access_label_stashed_v1();
 source_index:=prepared#>'{discovery,source_index}';
 root_catalog:=prepared#>'{root,census,root_scope_states,catalog,2}';
 IF p_budget IS NULL OR p_budget NOT BETWEEN 1 AND 4096
  OR prepared ? 'registration_binding_holds'
  OR jsonb_typeof(source_index) IS DISTINCT FROM 'object'
  OR root_catalog->>'live' IS DISTINCT FROM 'true'
  OR root_catalog->>'dotted' IS DISTINCT FROM prepared#>>'{root,root_coordinate,0}'
  OR coalesce(root_catalog->>'module','') IN ('','iam')
  OR coalesce(root_catalog->>'object_type','')=''
  OR coalesce(prepared#>>'{root,root_coordinate,1}','')='' THEN
  RAISE EXCEPTION 'metadata registration binding hold input invalid' USING ERRCODE='42501';END IF;
 root_key:=jsonb_build_array(root_catalog->>'object_type',prepared#>>'{root,root_coordinate,1}')::text;
 FOR source_entry IN SELECT e.key,e.value->'source' AS source FROM jsonb_each(source_index) e
  WHERE e.value#>>'{source,kind}'='5' LIMIT p_budget+1 LOOP
  model_type:=source_entry.source->>'type';object_id:=source_entry.source->>'id';
  IF coalesce(model_type,'')='' OR coalesce(object_id,'')=''
   OR octet_length(model_type)>16384 OR octet_length(object_id)>16384
   OR model_type ~ '[.:#*[:space:][:cntrl:]]' OR object_id ~ '[:#*[:space:][:cntrl:]]'
   OR source_entry.source->>'projection' IS DISTINCT FROM ''
   OR source_entry.key IS DISTINCT FROM jsonb_build_array(5,model_type,object_id,'')::text THEN
   RAISE EXCEPTION 'metadata registration binding source coordinate invalid' USING ERRCODE='42501';END IF;
  IF cardinality(logical_keys)>=p_budget THEN
   RAISE EXCEPTION 'metadata registration binding hold budget exceeded' USING ERRCODE='54000';END IF;
  logical_keys:=array_append(logical_keys,jsonb_build_array(model_type,object_id)::text);
 END LOOP;
 IF NOT (root_key=ANY(logical_keys)) THEN
  RAISE EXCEPTION 'metadata registration binding root source absent' USING ERRCODE='42501';END IF;
 -- Берём тот же ключ, что регистрация. Не ждём его или строку привязки:
 -- legacy-писатель мог войти с уже удержанным tuple lock. Конфликт повторяет попытку.
 BEGIN
  LOCK TABLE ONLY kaname.object_project_binding IN ROW SHARE MODE NOWAIT;
  IF NOT coalesce(has_table_privilege((prepared#>>'{plan,invoker_oid}')::oid,
        'kaname.object_project_binding','SELECT'),false)
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid='kaname.object_project_binding'::regclass
    AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
    AND NOT c.relispartition AND NOT c.relhassubclass AND NOT c.relhasrules) THEN
   RAISE EXCEPTION 'metadata registration binding SELECT or table shape invalid' USING ERRCODE='42501';END IF;
  FOR lock_entry IN SELECT DISTINCT hashtext(k) AS hashed FROM unnest(logical_keys) k ORDER BY hashed LOOP
   IF NOT pg_try_advisory_xact_lock_shared(1262569300,lock_entry.hashed) THEN
    RAISE EXCEPTION 'metadata registration binding advisory conflict' USING ERRCODE='40001';END IF;
  END LOOP;
  FOR lock_entry IN SELECT k::jsonb AS coordinate FROM unnest(logical_keys) k ORDER BY k COLLATE "C" LOOP
   PERFORM 1 FROM ONLY kaname.object_project_binding b
   WHERE b.object_type=lock_entry.coordinate->>0 AND b.object_id=lock_entry.coordinate->>1
   FOR SHARE OF b NOWAIT;
  END LOOP;
 EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'metadata registration binding row or relation conflict' USING ERRCODE='40001';
 END;

 -- Запись существует только в транзакции-владельце и появляется после взятия
 -- xact locks. Оставшийся session lock не может создать эту запись.
 claims:=jsonb_build_object('keys',to_jsonb(logical_keys),
  'transaction_id',prepared#>'{plan,transaction_id}','nonce',prepared#>'{plan,nonce}');
 UPDATE pg_temp.kaname_authority_metadata_discovery d
 SET prepared=d.prepared||jsonb_build_object('registration_binding_holds',claims)
 WHERE d.singleton AND NOT (d.prepared ? 'registration_binding_holds');
 GET DIAGNOSTICS affected=ROW_COUNT;
 IF affected<>1 THEN RAISE EXCEPTION 'metadata registration binding receipt unavailable' USING ERRCODE='42501';END IF;
 RETURN cardinality(logical_keys);
END;
$hold$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_registration_binding_check_v1(p_model text,p_id text)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $check$
DECLARE prepared jsonb; claims jsonb; logical_key text;
BEGIN
 prepared:=kaname._authority_metadata_access_label_stashed_v1();
 claims:=prepared->'registration_binding_holds';
 logical_key:=jsonb_build_array(p_model,p_id)::text;
 IF jsonb_typeof(claims->'keys') IS DISTINCT FROM 'array'
  OR NOT ((claims->'keys') ? logical_key)
  OR claims->'transaction_id' IS DISTINCT FROM prepared#>'{plan,transaction_id}'
  OR claims->'nonce' IS DISTINCT FROM prepared#>'{plan,nonce}' THEN
  RAISE EXCEPTION 'metadata registration binding receipt absent for coordinate' USING ERRCODE='42501';END IF;
 PERFORM kaname._authority_resource_preheld_key_v2(1262569300,logical_key,false);
END;
$check$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE target regprocedure;recipient record;
BEGIN
 FOREACH target IN ARRAY ARRAY[
  'kaname._authority_metadata_registration_binding_holds_v1(integer)'::regprocedure,
  'kaname._authority_metadata_registration_binding_check_v1(text,text)'::regprocedure] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',target);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
   JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE p.oid=target AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',target,recipient.rolname);
  END LOOP;
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('_authority_metadata_access_label_held_source_v1(integer,text,text,integer,integer)','581fe110a541b51ea8e678008906987660a541d2c2f4219bbf11a1feb7bbedbd','0b04bffacc953161b564752d675e9e60656348aa98c3bd13666dee621609e88a',
  $changes$[
 [
  " WHEN 4 THEN table_name:='resource_registration_scope';predicate:='r.object_type=$1 AND r.object_id=$2';",
  " WHEN 4 THEN table_name:='resource_registration_scope';predicate:='r.object_type=$1 AND r.object_id=$2';\n WHEN 5 THEN\n  PERFORM kaname._authority_metadata_registration_binding_check_v1(p_type,p_id);\n  table_name:='object_project_binding';predicate:='r.object_type=$1 AND r.object_id=$2';"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_stash_v1(jsonb)','3e37f89e0c84ddaf757331eeabe31f351b2d3e7493c131a03c716f60083a5909','cda82ea89f04138b43d02b4082d1f44493a330f8807178eb1a5d07faa5cc16b9',
  $changes$[
 [
  "  OR jsonb_typeof(p_prepared->'root') IS DISTINCT FROM 'object'",
  "  OR p_prepared ? 'registration_binding_holds'\n  OR jsonb_typeof(p_prepared->'root') IS DISTINCT FROM 'object'"
 ]
]$changes$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','c0d015f355dc1dae5fe3e10e7f5a51630c922f6405cc89ada7e809e4e4f931eb','73cf60bf7d003e3a694303cc14b0db89eae7d179ba04e72c5556f0e78b6fb236',
  $changes$[
 [
  "581fe110a541b51ea8e678008906987660a541d2c2f4219bbf11a1feb7bbedbd",
  "0b04bffacc953161b564752d675e9e60656348aa98c3bd13666dee621609e88a"
 ],
 [
  "3e37f89e0c84ddaf757331eeabe31f351b2d3e7493c131a03c716f60083a5909",
  "cda82ea89f04138b43d02b4082d1f44493a330f8807178eb1a5d07faa5cc16b9"
 ],
 [
  " manifest jsonb:=$manifest$\n[\n",
  " manifest jsonb:=$manifest$\n[\n  {\n    \"signature\": \"_authority_metadata_registration_binding_holds_v1(integer)\",\n    \"digest\": \"861ddeac15c398add39958a4ef7af725aa93e1eca48948a1b2c751f0995d8f87\",\n    \"definer\": false,\n    \"volatility\": \"v\",\n    \"exported\": false,\n    \"result_type\": \"integer\",\n    \"result_set\": false,\n    \"language\": \"plpgsql\",\n    \"argnames\": [\n      \"p_budget\"\n    ],\n    \"argmodes\": null,\n    \"allargtypes\": null\n  },\n  {\n    \"signature\": \"_authority_metadata_registration_binding_check_v1(text,text)\",\n    \"digest\": \"de2458e1b5001b7f3a6390b8429168ea38f6184f34ae16723cba136a97ba26d9\",\n    \"definer\": false,\n    \"volatility\": \"v\",\n    \"exported\": false,\n    \"result_type\": \"void\",\n    \"result_set\": false,\n    \"language\": \"plpgsql\",\n    \"argnames\": [\n      \"p_model\",\n      \"p_id\"\n    ],\n    \"argmodes\": null,\n    \"allargtypes\": null\n  },\n"
 ]
]$changes$::jsonb),
 ('authority_metadata_service_account_access_label_ready_v1()','1e42612e22a7539b9d0fb112e457b385f194332060cd5e2bfaffa49ed2f99ff4','05f62d50bedc50db0d0eb12875f5bd06d835376b14a50c12b0d0ab6913c542d0',
  $changes$[
 [
  "c0d015f355dc1dae5fe3e10e7f5a51630c922f6405cc89ada7e809e4e4f931eb",
  "73cf60bf7d003e3a694303cc14b0db89eae7d179ba04e72c5556f0e78b6fb236"
 ]
]$changes$::jsonb)
 ) AS expected(signature,old_digest,new_digest,changes) LOOP
  found_oid:=pg_catalog.to_regprocedure('kaname.'||step.signature);
  SELECT pg_catalog.pg_get_functiondef(p.oid),p.prosrc INTO STRICT definition,original
  FROM pg_catalog.pg_proc p WHERE p.oid=found_oid;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM step.old_digest THEN
   RAISE EXCEPTION 'metadata carrier predecessor differs: %',step.signature;END IF;
  FOR pair IN SELECT value FROM jsonb_array_elements(step.changes) LOOP
   IF octet_length(original)-octet_length(replace(original,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'metadata carrier patch does not match once: %',step.signature;END IF;
   original:=replace(original,pair->>0,pair->>1);
   definition:=replace(definition,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM step.new_digest THEN
   RAISE EXCEPTION 'metadata carrier expected body differs: %',step.signature;END IF;
  EXECUTE definition;
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=found_oid)
   IS DISTINCT FROM step.new_digest THEN
   RAISE EXCEPTION 'metadata carrier installed body differs: %',step.signature;END IF;
 END LOOP;
END;
$install$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('authority_metadata_service_account_access_label_ready_v1()','05f62d50bedc50db0d0eb12875f5bd06d835376b14a50c12b0d0ab6913c542d0','1e42612e22a7539b9d0fb112e457b385f194332060cd5e2bfaffa49ed2f99ff4',
  $changes$[
 [
  "73cf60bf7d003e3a694303cc14b0db89eae7d179ba04e72c5556f0e78b6fb236",
  "c0d015f355dc1dae5fe3e10e7f5a51630c922f6405cc89ada7e809e4e4f931eb"
 ]
]$changes$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','73cf60bf7d003e3a694303cc14b0db89eae7d179ba04e72c5556f0e78b6fb236','c0d015f355dc1dae5fe3e10e7f5a51630c922f6405cc89ada7e809e4e4f931eb',
  $changes$[
 [
  " manifest jsonb:=$manifest$\n[\n  {\n    \"signature\": \"_authority_metadata_registration_binding_holds_v1(integer)\",\n    \"digest\": \"861ddeac15c398add39958a4ef7af725aa93e1eca48948a1b2c751f0995d8f87\",\n    \"definer\": false,\n    \"volatility\": \"v\",\n    \"exported\": false,\n    \"result_type\": \"integer\",\n    \"result_set\": false,\n    \"language\": \"plpgsql\",\n    \"argnames\": [\n      \"p_budget\"\n    ],\n    \"argmodes\": null,\n    \"allargtypes\": null\n  },\n  {\n    \"signature\": \"_authority_metadata_registration_binding_check_v1(text,text)\",\n    \"digest\": \"de2458e1b5001b7f3a6390b8429168ea38f6184f34ae16723cba136a97ba26d9\",\n    \"definer\": false,\n    \"volatility\": \"v\",\n    \"exported\": false,\n    \"result_type\": \"void\",\n    \"result_set\": false,\n    \"language\": \"plpgsql\",\n    \"argnames\": [\n      \"p_model\",\n      \"p_id\"\n    ],\n    \"argmodes\": null,\n    \"allargtypes\": null\n  },\n",
  " manifest jsonb:=$manifest$\n[\n"
 ],
 [
  "cda82ea89f04138b43d02b4082d1f44493a330f8807178eb1a5d07faa5cc16b9",
  "3e37f89e0c84ddaf757331eeabe31f351b2d3e7493c131a03c716f60083a5909"
 ],
 [
  "0b04bffacc953161b564752d675e9e60656348aa98c3bd13666dee621609e88a",
  "581fe110a541b51ea8e678008906987660a541d2c2f4219bbf11a1feb7bbedbd"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_stash_v1(jsonb)','cda82ea89f04138b43d02b4082d1f44493a330f8807178eb1a5d07faa5cc16b9','3e37f89e0c84ddaf757331eeabe31f351b2d3e7493c131a03c716f60083a5909',
  $changes$[
 [
  "  OR p_prepared ? 'registration_binding_holds'\n  OR jsonb_typeof(p_prepared->'root') IS DISTINCT FROM 'object'",
  "  OR jsonb_typeof(p_prepared->'root') IS DISTINCT FROM 'object'"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_held_source_v1(integer,text,text,integer,integer)','0b04bffacc953161b564752d675e9e60656348aa98c3bd13666dee621609e88a','581fe110a541b51ea8e678008906987660a541d2c2f4219bbf11a1feb7bbedbd',
  $changes$[
 [
  " WHEN 4 THEN table_name:='resource_registration_scope';predicate:='r.object_type=$1 AND r.object_id=$2';\n WHEN 5 THEN\n  PERFORM kaname._authority_metadata_registration_binding_check_v1(p_type,p_id);\n  table_name:='object_project_binding';predicate:='r.object_type=$1 AND r.object_id=$2';",
  " WHEN 4 THEN table_name:='resource_registration_scope';predicate:='r.object_type=$1 AND r.object_id=$2';"
 ]
]$changes$::jsonb)
 ) AS expected(signature,old_digest,new_digest,changes) LOOP
  found_oid:=pg_catalog.to_regprocedure('kaname.'||step.signature);
  SELECT pg_catalog.pg_get_functiondef(p.oid),p.prosrc INTO STRICT definition,original
  FROM pg_catalog.pg_proc p WHERE p.oid=found_oid;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM step.old_digest THEN
   RAISE EXCEPTION 'metadata carrier predecessor differs: %',step.signature;END IF;
  FOR pair IN SELECT value FROM jsonb_array_elements(step.changes) LOOP
   IF octet_length(original)-octet_length(replace(original,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'metadata carrier patch does not match once: %',step.signature;END IF;
   original:=replace(original,pair->>0,pair->>1);
   definition:=replace(definition,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM step.new_digest THEN
   RAISE EXCEPTION 'metadata carrier expected body differs: %',step.signature;END IF;
  EXECUTE definition;
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=found_oid)
   IS DISTINCT FROM step.new_digest THEN
   RAISE EXCEPTION 'metadata carrier installed body differs: %',step.signature;END IF;
 END LOOP;
END;
$install$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_metadata_registration_binding_check_v1(text,text);
DROP FUNCTION kaname._authority_metadata_registration_binding_holds_v1(integer);
