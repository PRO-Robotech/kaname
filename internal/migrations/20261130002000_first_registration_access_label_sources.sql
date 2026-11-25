-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Компонент закрытого prewait для первой регистрации через project.
-- certificate создаёт _authority_resource_registration_intent_certificate_v2
-- из удержанного каталога. p_index содержит обычные RR-предикаты; RR receipt
-- по dotted координате передаётся отдельно от legacy capture index.
-- Результат свидетельствует только об отсутствии OLD и поколения. Перед
-- записью нужны полный census NEW, held Apply/Grant и подписанный manifest.
CREATE FUNCTION kaname._authority_resource_first_registration_absence_v1(
 p_certificate jsonb,p_index jsonb,p_receipt jsonb,p_rows integer,p_reads integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $first$
DECLARE
 proof jsonb; command jsonb; model text; dotted text; identifier text; module_name text;
 project_id text; account_id text; version_at timestamptz;
 coordinate text; project_key text; project_capture jsonb; capture_type text; source_kind integer; capture jsonb;
 required jsonb:='{}'::jsonb; checked record;
BEGIN
 -- Та же owner-private ограда, что исключает открытие новых поколений
 -- во время object reconciliation. Сначала проверяем её и signed RC frame.
 proof:=kaname._authority_access_label_generation_latch_require_v1(false);
 IF p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000
  OR p_reads IS NULL OR p_reads NOT BETWEEN 16 AND 4096 THEN
  RAISE EXCEPTION 'first registration absence budget invalid' USING ERRCODE='54000';
 END IF;
 IF jsonb_typeof(p_certificate) IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_index) IS DISTINCT FROM 'object'
  OR octet_length(p_certificate::text)::bigint+octet_length(p_index::text)::bigint>67108864
  OR p_certificate->>'action' IS DISTINCT FROM '1'
  OR p_certificate->'versionless' IS DISTINCT FROM 'false'::jsonb
  OR p_certificate->'binding_refuses' IS DISTINCT FROM 'false'::jsonb
  OR p_certificate->'old_scopes' IS DISTINCT FROM '[]'::jsonb THEN
  RAISE EXCEPTION 'first registration certificate is incomplete' USING ERRCODE='42501';
 END IF;
 command:=p_certificate->'command';
 model:=p_certificate->>'model_type'; dotted:=p_certificate->>'object_type';
 identifier:=p_certificate->>'object_id'; module_name:=p_certificate->>'module';
 project_id:=command->>'parent_project_id'; account_id:=command->>'parent_account_id';
 version_at:=(command->>'source_version')::timestamptz;
 IF coalesce(model,'')='' OR model ~ '[.[:space:][:cntrl:]:#*]'
  OR coalesce(identifier,'')='' OR identifier ~ '[[:space:][:cntrl:]:#*]'
  OR coalesce(module_name,'') IN ('','iam') OR coalesce(dotted,'')=''
  OR left(dotted,length(module_name)+1) IS DISTINCT FROM module_name||'.'
  OR project_id IS NULL OR project_id NOT LIKE 'prj%' OR project_id ~ '[[:space:][:cntrl:]:#*]'
  OR account_id IS NULL OR account_id NOT LIKE 'acc%' OR account_id ~ '[[:space:][:cntrl:]:#*]'
  OR version_at IS NULL OR NOT isfinite(version_at)
  OR version_at IS DISTINCT FROM kaname._authority_resource_registration_version_v2(p_certificate->>'source_version_text')
  OR command->>'dotted_type' IS DISTINCT FROM dotted
  OR command->>'object_id' IS DISTINCT FROM identifier
  OR command->'parent_chain' IS DISTINCT FROM jsonb_build_array('project:'||project_id,'account:'||account_id)
  OR p_certificate->'new_scopes' IS DISTINCT FROM
    jsonb_build_array(jsonb_build_object('Registered',true,'ProjectID',project_id,'AccountID',account_id))
  OR p_certificate->'registration_accounts' IS DISTINCT FROM jsonb_build_object(account_id,true)
  OR p_certificate#>>'{tuple,User}' IS DISTINCT FROM 'project:'||project_id
  OR p_certificate#>>'{tuple,Relation}' IS DISTINCT FROM 'project'
  OR p_certificate#>>'{tuple,Object}' IS DISTINCT FROM model||':'||identifier
  OR p_certificate#>>'{catalog,module}' IS DISTINCT FROM module_name
  OR p_certificate#>>'{catalog,dotted}' IS DISTINCT FROM dotted
  OR p_certificate#>>'{catalog,object_type}' IS DISTINCT FROM model
  OR p_certificate#>'{catalog,live}' IS DISTINCT FROM 'true'::jsonb THEN
  RAISE EXCEPTION 'first registration canonical identity differs' USING ERRCODE='42501';
 END IF;
 PERFORM kaname._authority_resource_module_identity_v2(
  p_certificate->>'service',p_certificate->>'actor',module_name);
 IF proof->>'mode' IS DISTINCT FROM 'global'
  AND NOT coalesce(proof->'accounts' ? account_id,false) THEN
  RAISE EXCEPTION 'first registration account not held' USING ERRCODE='42501';
 END IF;
 -- Ключи идентичны registration maximum. Проверяем фактические удержания,
 -- а не флаг от вызывающего кода. Повторное чтение идёт до final clock.
 PERFORM kaname._authority_resource_preheld_key_v2(1262569296,'object:'||jsonb_build_array(dotted,identifier)::text,true);
 PERFORM kaname._authority_resource_preheld_key_v2(1262569296,'scope:project:'||project_id,true);
 PERFORM kaname._authority_resource_preheld_key_v2(1262569296,'scope:account:'||account_id,true);
 IF p_receipt IS DISTINCT FROM jsonb_build_object('kind',42,'type',dotted,'id',identifier,'projection','','states','[]'::jsonb) THEN
  RAISE EXCEPTION 'first registration receipt absence not captured' USING ERRCODE='42501';
 END IF;
 -- Перечень выводится из канонической координаты, а не списка клиента.
 -- Каждый известный RR-ключ обязан присутствовать с пустым ответом.
 FOREACH source_kind IN ARRAY ARRAY[2,3,4,5,6,7,21,22,25,26,27,28,35] LOOP
  capture_type:=CASE WHEN source_kind IN (2,21,22) THEN dotted ELSE model END;
  capture:=kaname._authority_resource_require_capture_v2(p_index,source_kind,capture_type,identifier);
  IF capture->'states' IS DISTINCT FROM '[]'::jsonb THEN
   RAISE EXCEPTION 'first registration OLD is present' USING ERRCODE='P1034';
  END IF;
  IF capture->'source' IS DISTINCT FROM jsonb_build_object(
   'kind',source_kind,'type',capture_type,'id',identifier,'projection','','states','[]'::jsonb) THEN
   RAISE EXCEPTION 'first registration absence predicate differs' USING ERRCODE='42501';
  END IF;
  coordinate:=jsonb_build_array(source_kind,capture_type,identifier,'')::text;
  required:=required||jsonb_build_object(coordinate,true);
 END LOOP;
 project_capture:=kaname._authority_resource_require_capture_v2(p_index,1,'project',project_id);
 IF project_capture#>>'{source,kind}' IS DISTINCT FROM '1'
  OR project_capture#>>'{source,type}' IS DISTINCT FROM 'project'
  OR project_capture#>>'{source,id}' IS DISTINCT FROM project_id
  OR project_capture#>>'{source,projection}' IS DISTINCT FROM ''
  OR jsonb_array_length(project_capture->'states') IS DISTINCT FROM 1 THEN
  RAISE EXCEPTION 'first registration owning project predicate differs' USING ERRCODE='42501';
 END IF;
 project_key:=jsonb_build_array(1,'project',project_id,'')::text;
 required:=required||jsonb_build_object(project_key,true);
 SELECT * INTO STRICT checked FROM kaname._authority_resource_required_reread_v2(
  p_index,required,'{}'::jsonb,p_rows,p_reads-2);
 IF checked.held_rows->project_key->0->'data'->>'account_id' IS DISTINCT FROM account_id THEN
  RAISE EXCEPTION 'first registration owning account changed' USING ERRCODE='P1034';
 END IF;
 -- Обе проверки индексированы по точной координате. Один совпавший ряд
 -- прекращает попытку, никаких live-перечней и работы после clock.
 IF EXISTS(SELECT 1 FROM ONLY kaname.producer_source_receipt r WHERE r.catalog_type=dotted AND r.object_id=identifier)
  OR EXISTS(SELECT 1 FROM ONLY kaname.authority_access_label_dirty_fact d WHERE d.object_type=model AND d.object_id=identifier) THEN
  RAISE EXCEPTION 'first registration prior receipt or pending generation' USING ERRCODE='P1034';
 END IF;
 RETURN jsonb_build_object('backend',proof->'backend','transaction_id',proof->'transaction_id','nonce',proof->'nonce',
  'model_id',proof->'model_id','catalog_id',proof->'catalog_id','projector_version',proof->'projector_version',
  'object_type',dotted,'object_id',identifier,'model_type',model,'module',module_name,'actor',p_certificate->'actor',
  'project_id',project_id,'account_id',account_id,'source_version',version_at,
  'logical_rows',checked.logical_rows,'logical_reads',checked.logical_reads+2);
END;
$first$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE grantee record;
BEGIN
 REVOKE ALL ON FUNCTION kaname._authority_resource_first_registration_absence_v1(jsonb,jsonb,jsonb,integer,integer) FROM PUBLIC;
 FOR grantee IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname._authority_resource_first_registration_absence_v1(jsonb,jsonb,jsonb,integer,integer)'::regprocedure
   AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_resource_first_registration_absence_v1(jsonb,jsonb,jsonb,integer,integer) FROM %I',grantee.rolname);
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_resource_first_registration_absence_v1(jsonb,jsonb,jsonb,integer,integer);
