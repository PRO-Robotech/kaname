-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1045: сверка источников регистрации потомка после ожиданий.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd

-- Верхняя граница синтаксических операций для нового объекта. Общий
-- компилятор использует только типы операций и граф источников. Версию,
-- строки и решение о записи определяет финальная программа.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_child_registration_maximum_v1(
 p_index jsonb,p_certificate jsonb,p_sources jsonb)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_certificate->>'action' IS DISTINCT FROM '1'
  OR p_certificate#>>'{tuple,Relation}' IS DISTINCT FROM 'parent'
  OR p_sources#>'{before,mirror}' IS DISTINCT FROM 'null'::jsonb THEN
  RAISE EXCEPTION 'child registration maximum requires an unoccupied key' USING ERRCODE='42501';
 END IF;
 -- Invalidate выполняет UPDATE даже при отсутствии квитанций. Audit
 -- обязателен и когда точный parent tuple уже остался в истории.
 RETURN kaname._authority_resource_registration_maximum_v2(p_index,p_certificate,p_sources,
  '{"physical_applied":true,"projection_replaced":true,"journal_required":true,"audit_required":true,
    "steps":[{"kind":"mirror","images":[{"table":"resource_mirror","operation":"INSERT"}]},
             {"kind":"scope_clear"},{"kind":"scope_insert"},
             {"kind":"receipt_invalidate","operations":{"producer_source_receipt":["UPDATE"]}},
             {"kind":"registration_reconcile"}]}'::jsonb,'[]'::jsonb);
END $$;
-- +goose StatementEnd

-- Координату родителя определяет удержанный каталог. Снимок квот и
-- квитанций читается после проверки областей и точных источников RR.
-- Возвращённый пакет остаётся у владельца и не разрешает запись.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_child_registration_hold_v1(p_envelope jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(prepared jsonb,logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 proof jsonb; intent jsonb; guards jsonb; epochs jsonb; policy_guards jsonb; checked_epochs jsonb; predicates jsonb;
 epoch_result record; bundle_result record; catalog_result record; current_result record; captured record;
 binding_result record; audit_result record; reconcile_result record; relations_result record;
 source_index jsonb; parent_row jsonb; child_row jsonb; parent_scope jsonb; child_scope jsonb;
 parent_state jsonb; child_state jsonb; required jsonb; scope jsonb; candidates jsonb; maximum jsonb;
 covered_accounts jsonb:='{}'::jsonb; parent_witness jsonb; held_source_index jsonb;
 binding_plan jsonb; reservations jsonb:='{}'::jsonb; held_relations jsonb:='[]'::jsonb; held_advisory jsonb;
 parent_type text; parent_model text; parent_id text; child_type text; child_model text; child_id text;
 parts text[]; segments integer; kind integer; mirror_key text;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'writer_contract' IS DISTINCT FROM '2'
  OR proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'purpose' IS DISTINCT FROM 'participant'
  OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_source_pending'
  OR proof->>'consumer_finalized' IS DISTINCT FROM 'false' OR current_setting('transaction_isolation')<>'read committed'
  OR to_regclass('pg_temp.kaname_authority_resource_manifest') IS NOT NULL THEN
  RAISE EXCEPTION 'child registration hold requires fresh pending RC source admission' USING ERRCODE='42501';
 END IF;
 IF p_rows IS NULL OR p_rows NOT BETWEEN 1 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 1 AND 4096
  OR jsonb_typeof(p_envelope) IS DISTINCT FROM 'object' OR octet_length(p_envelope::text)>67108864 THEN
  RAISE EXCEPTION 'child registration hold budget exceeded' USING ERRCODE='54000';
 END IF;
 intent:=p_envelope->'intent';
 child_type:=intent->>'resource_type';
 child_id:=intent->>'resource_id';
 IF p_envelope->>'abi' IS DISTINCT FROM '2' OR jsonb_typeof(intent) IS DISTINCT FROM 'object'
  OR intent->>'kind' IS DISTINCT FROM 'child_registration'
  OR intent-ARRAY['kind','resource_type','resource_id','actor','audit_id']<>'{}'::jsonb
  OR jsonb_typeof(intent->'resource_type') IS DISTINCT FROM 'string' OR octet_length(child_type)>512
  OR jsonb_typeof(intent->'resource_id') IS DISTINCT FROM 'string' OR octet_length(child_id)>512
  OR child_id COLLATE "C" !~ '^[a-z0-9]([a-z0-9._-]*[a-z0-9])?(/[a-z0-9]([a-z0-9._-]*[a-z0-9])?)+$'
  OR jsonb_typeof(intent->'actor') IS DISTINCT FROM 'string' OR coalesce(intent->>'actor','')=''
  OR octet_length(intent->>'actor')>512 OR intent->>'actor' ~ '[[:space:][:cntrl:]:#*]'
  OR intent->>'actor' IS DISTINCT FROM p_envelope->>'actor'
  OR jsonb_typeof(intent->'audit_id') IS DISTINCT FROM 'string'
  OR intent->>'audit_id' !~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$'
  OR coalesce(p_envelope->>'service','')<>'' OR p_envelope ?| ARRAY['object_effects','registration_effects','refusal_effects']
  OR coalesce(nullif(p_envelope->'installation','null'::jsonb),'[]'::jsonb)<>'[]'::jsonb
  OR coalesce(nullif(p_envelope->'source_effects','null'::jsonb),'[]'::jsonb)<>'[]'::jsonb THEN
  RAISE EXCEPTION 'invalid child registration hold intent' USING ERRCODE='42501';
 END IF;

 guards:=p_envelope->'native_guards';
 epochs:=p_envelope->'native_epochs';
 IF jsonb_typeof(guards) IS DISTINCT FROM 'array' OR jsonb_typeof(epochs) IS DISTINCT FROM 'object'
  OR jsonb_array_length(guards)>4095 OR NOT guards ? '*' THEN
  RAISE EXCEPTION 'child registration native epoch guards unavailable' USING ERRCODE='42501';
 END IF;
 IF EXISTS(SELECT FROM jsonb_array_elements(guards) guard
  WHERE jsonb_typeof(guard)<>'string' OR coalesce(guard#>>'{}','')='' OR octet_length(guard#>>'{}')>16384) THEN
  RAISE EXCEPTION 'invalid child registration native epoch guard' USING ERRCODE='42501';
 END IF;
 SELECT jsonb_object_agg(key,'share') INTO policy_guards FROM jsonb_array_elements_text(guards) key;
 IF (SELECT count(*) FROM jsonb_object_keys(policy_guards))<>jsonb_array_length(guards)
  OR EXISTS(SELECT FROM jsonb_object_keys(epochs) key WHERE NOT policy_guards ? key) THEN
  RAISE EXCEPTION 'child registration native epoch guard set differs' USING ERRCODE='42501';
 END IF;
 SELECT * INTO STRICT bundle_result FROM kaname._authority_resource_bundle_catalog_v2(p_rows,p_reads);
 logical_rows:=bundle_result.logical_rows;
 logical_reads:=bundle_result.logical_reads;
 SELECT * INTO STRICT catalog_result FROM kaname._authority_resource_catalog_wait_v2(
  p_envelope->'catalogs',p_rows-logical_rows,p_reads-logical_reads);
 logical_rows:=logical_rows+catalog_result.logical_rows;
 logical_reads:=logical_reads+catalog_result.logical_reads;

 SELECT (item->>'state')::jsonb->2 INTO child_row FROM jsonb_array_elements(catalog_result.catalog_rows) item
 WHERE item->>'dotted'=child_type AND ((item->>'state')::jsonb #>'{2,live}')='true'::jsonb;
 child_model:=child_row->>'object_type';
 segments:=(child_row#>>'{child_registration,ParentSegments}')::integer;
 parent_model:=child_row->'parent_types'->>((SELECT ord::integer-1
  FROM jsonb_array_elements_text(child_row->'parent_names') WITH ORDINALITY parents(name,ord) WHERE name='parent'));
 parts:=string_to_array(child_id,'/');
 parent_id:=array_to_string(parts[1:segments],'/');
 SELECT (item->>'state')::jsonb->2 INTO parent_row FROM jsonb_array_elements(catalog_result.catalog_rows) item
 WHERE item->>'object_type'=parent_model AND item->>'module'=child_row->>'module'
  AND ((item->>'state')::jsonb #>'{2,live}')='true'::jsonb;
 parent_type:=parent_row->>'dotted';
 IF child_model IS NULL OR parent_type IS NULL OR segments IS NULL OR segments<1 OR cardinality(parts)<=segments
  OR octet_length(parent_model)+1+octet_length(parent_id)>512 OR octet_length(child_model)+1+octet_length(child_id)>512 THEN
  RAISE EXCEPTION 'child registration held catalog coordinates unavailable' USING ERRCODE='42501';
 END IF;

 source_index:=kaname._authority_resource_capture_index_v2(p_envelope->'sources',100000);
 parent_state:=kaname._authority_resource_require_capture_v2(source_index,2,parent_type,parent_id)->'states';
 child_state:=kaname._authority_resource_require_capture_v2(source_index,2,child_type,child_id)->'states';
 IF jsonb_array_length(parent_state)<>1 OR jsonb_array_length(child_state)>1 THEN
  RAISE EXCEPTION 'child registration mirror census differs' USING ERRCODE='P1034';
 END IF;
 parent_scope:=kaname._authority_resource_registration_saved_scopes_v2(source_index,bundle_result.catalog,parent_model,parent_id);
 child_scope:=kaname._authority_resource_registration_saved_scopes_v2(source_index,bundle_result.catalog,child_model,child_id);
 IF jsonb_array_length(parent_scope->'scopes')=0
  OR (jsonb_array_length(child_state)=1 AND jsonb_array_length(child_scope->'scopes')=0) THEN
  RAISE EXCEPTION 'child registration scope census unavailable' USING ERRCODE='42501';
 END IF;
 FOR scope IN SELECT value FROM jsonb_array_elements((parent_scope->'scopes')||(child_scope->'scopes')) LOOP
  IF coalesce(scope->>'AccountID','')=''
   OR (proof->>'mode'='accounts' AND NOT coalesce(proof->'accounts' ? (scope->>'AccountID'),false)) THEN
   RAISE EXCEPTION 'child registration owner fence missing' USING ERRCODE='42501';
  END IF;
  covered_accounts:=covered_accounts||jsonb_build_object(scope->>'AccountID',true);
 END LOOP;
 mirror_key:=jsonb_build_array(2,parent_type,parent_id,'')::text;
 required:=(parent_scope->'required')||(child_scope->'required')||jsonb_build_object(
  mirror_key,true,jsonb_build_array(2,child_type,child_id,'')::text,true);
 FOREACH kind IN ARRAY ARRAY[3,4,5,6,25,26,28] LOOP
  required:=required||jsonb_build_object(jsonb_build_array(kind,child_model,child_id,'')::text,true);
 END LOOP;

 -- RR предполагает возможность создания только при отсутствующем зеркале.
 -- Граф записи определён до блокировки epochs. Квоты и состояние закрытия
 -- родителя пока неизвестны. Эти поля могут только исключить создание.
 IF jsonb_array_length(child_state)=0 THEN
  parent_witness:=jsonb_build_object('child_type',child_type,'child_model',child_model,'child_id',child_id,
   'parent_model',parent_model,'parent_id',parent_id,'parent_version',parent_state#>'{0,2,source_version}',
   'policy',child_row->'child_registration');
  candidates:=kaname._authority_child_registration_sources_v1(
   parent_witness,source_index,bundle_result.catalog,catalog_result.catalog_rows);
  maximum:=kaname._authority_child_registration_maximum_v1(source_index,candidates->'certificate',candidates->'sources');
 ELSE
  -- Занятый ключ допускает только точный повтор или отказ. Его источники
  -- удерживаются в SHARE, пока сверяем зеркало и квитанцию текущей версии.
  maximum:='{"required":{},"accounts":{},"policy_epochs":{},"binding_epochs":{"":"share"},
    "source_guards":{},"write_sources":{},"operations":{},"global":false}'::jsonb;
 END IF;
 required:=required||(maximum->'required');
 covered_accounts:=covered_accounts||(maximum->'accounts');
 predicates:=kaname._authority_resource_predicate_maximum_v2(source_index,required);
 IF proof->>'mode'='accounts' AND ((maximum->>'global')::boolean OR (predicates->>'global')::boolean
  OR EXISTS(SELECT FROM jsonb_object_keys(covered_accounts) account WHERE NOT proof->'accounts' ? account)) THEN
  RAISE EXCEPTION 'child registration complete source fence changed' USING ERRCODE='P1034';
 END IF;
 -- При пересечении WRITE из плана записи сохраняет приоритет. В native
 -- witness сравниваются только переданные ключи и состояние до записи.
 policy_guards:=policy_guards||(predicates->'policy_epochs')||jsonb_build_object(
  'object:'||jsonb_build_array(parent_type,parent_id)::text,'share',
  'object:'||jsonb_build_array(child_type,child_id)::text,'share')||(maximum->'policy_epochs');
 maximum:=maximum||jsonb_build_object('required',required,'accounts',covered_accounts,'policy_epochs',policy_guards);
 SELECT * INTO STRICT epoch_result FROM kaname._authority_resource_epoch_wait_v2(
  maximum->'source_guards',policy_guards,maximum->'binding_epochs',p_rows-logical_rows,p_reads-logical_reads);
 logical_rows:=logical_rows+epoch_result.logical_rows;
 logical_reads:=logical_reads+epoch_result.logical_reads;
 SELECT jsonb_object_agg(key,epoch_result.lock_witness->'policy_before'->key) INTO checked_epochs
 FROM jsonb_array_elements_text(guards) key;
 IF checked_epochs IS DISTINCT FROM epochs THEN
  RAISE EXCEPTION 'child registration native epochs changed' USING ERRCODE='P1034';
 END IF;
 held_advisory:=epoch_result.lock_witness->'held_advisory';
 IF candidates IS NOT NULL THEN
  -- Уникальный ключ project binding резервируется перед reread kind 5.
  binding_plan:='{"steps":[]}'::jsonb;
  IF maximum->'operations' ? 'object_project_binding' THEN
   binding_plan:='{"steps":[{"images":[{"table":"object_project_binding","operation":"INSERT"}]}]}'::jsonb;
  END IF;
  SELECT * INTO STRICT binding_result FROM kaname._authority_resource_registration_binding_wait_v2(
   candidates->'certificate',binding_plan,p_reads-logical_reads);
  logical_reads:=logical_reads+binding_result.logical_reads;
  held_relations:=binding_result.held_relations;
  held_advisory:=held_advisory||binding_result.held_advisory;
 END IF;
 SELECT * INTO STRICT current_result FROM kaname._authority_resource_required_reread_v2(
  source_index,required,maximum->'write_sources',p_rows-logical_rows,p_reads-logical_reads);
 logical_rows:=logical_rows+current_result.logical_rows;
 logical_reads:=logical_reads+current_result.logical_reads;
 IF current_result.predicate_protections IS DISTINCT FROM predicates->'protections' THEN
  RAISE EXCEPTION 'child registration held predicate protection changed' USING ERRCODE='P1034';
 END IF;
 SELECT * INTO STRICT captured FROM kaname._authority_child_registration_capture_v1(
  child_type,child_id,p_rows-logical_rows,p_reads-logical_reads);
 IF captured.witness->>'parent_type' IS DISTINCT FROM parent_type
  OR captured.witness->>'parent_id' IS DISTINCT FROM parent_id
  OR captured.witness->>'parent_model' IS DISTINCT FROM parent_model
  OR captured.witness->>'child_model' IS DISTINCT FROM child_model
  OR (captured.witness->>'parent_version')::timestamptz IS DISTINCT FROM (parent_state#>>'{0,2,source_version}')::timestamptz
  OR (captured.witness->>'closed_at' IS NULL AND (captured.witness->>'child_version')::timestamptz
   IS DISTINCT FROM (child_state#>>'{0,2,source_version}')::timestamptz) THEN
  RAISE EXCEPTION 'child registration held witness changed' USING ERRCODE='P1034';
 END IF;
 logical_rows:=logical_rows+captured.logical_rows;
 logical_reads:=logical_reads+captured.logical_reads;
 IF candidates IS NOT NULL AND captured.witness->>'closed_at' IS NULL THEN
  -- Канонические helpers удерживают audit ID, очередь пересчёта и отношения
  -- до выбора версии. Слот outbox получает точный payload после выбора версии.
  SELECT * INTO STRICT audit_result FROM kaname._authority_resource_audit_wait_v2(
   jsonb_build_object(intent->>'audit_id',true),p_rows-logical_rows,p_reads-logical_reads);
  logical_rows:=logical_rows+audit_result.logical_rows;
  logical_reads:=logical_reads+audit_result.logical_reads;
  SELECT * INTO STRICT reconcile_result FROM kaname._authority_resource_reconcile_wait_v2(1,p_reads-logical_reads);
  logical_reads:=logical_reads+reconcile_result.logical_reads;
  SELECT * INTO STRICT relations_result FROM kaname._authority_resource_physical_relations_wait_v2(
   (maximum->'operations')-'object_project_binding'-'resource_reconcile_outbox',p_reads-logical_reads);
  logical_reads:=logical_reads+relations_result.logical_reads;
  IF logical_reads+2>p_reads THEN
   RAISE EXCEPTION 'child registration private relation budget exceeded' USING ERRCODE='54000';
  END IF;
  -- Таблицы не выданы runtime. Их запись остаётся закрытым шагом владельца.
  LOCK TABLE ONLY kaname.authority_child_parent_state IN ROW EXCLUSIVE MODE;
  LOCK TABLE ONLY kaname.authority_child_creation IN ROW EXCLUSIVE MODE;
  logical_reads:=logical_reads+2;
  held_relations:=held_relations||relations_result.lock_witness||reconcile_result.held_relations||jsonb_build_array(
   jsonb_build_object('oid','kaname.authority_child_parent_state'::regclass::oid,'mode','RowExclusiveLock'),
   jsonb_build_object('oid','kaname.authority_child_creation'::regclass::oid,'mode','RowExclusiveLock'));
  held_advisory:=held_advisory||audit_result.lock_witness||reconcile_result.held_advisory;
  logical_reads:=logical_reads+kaname._authority_sequence_reserve_v3('resource',
   jsonb_build_array(jsonb_build_object('table','fga_outbox','ordinal',1,
    'origin',jsonb_build_object('family','resource.registration','ordinal',1),
    'row','{}'::jsonb,'stamp','transaction')),p_reads-logical_reads);
  PERFORM kaname._authority_sequence_freeze_v3(jsonb_build_object('kind','child_registration',
   'intent',intent,'tuple',candidates#>'{certificate,tuple}'));
  reservations:=jsonb_build_object('audit_id',intent->'audit_id',
   'reconcile_ids',reconcile_result.reserved_ids,'fga_slot',1);
 END IF;
 SELECT jsonb_object_agg(key,source_index->key) INTO held_source_index FROM jsonb_object_keys(required) key;
 prepared:=jsonb_build_object('intent',intent,'witness',captured.witness,'native_epochs',checked_epochs,
  'backend',proof->'backend','transaction_id',proof->'transaction_id','nonce',proof->'nonce',
  'maximum',maximum,'epoch_witness',epoch_result.lock_witness,'required',required,
  'source_index',held_source_index,'catalog',bundle_result.catalog,'catalog_rows',catalog_result.catalog_rows,
  'held_advisory',held_advisory,'held_relations',held_relations,'reservations',reservations);
 RETURN NEXT;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$ DECLARE helper record; principal record; BEGIN
 FOR helper IN SELECT oid,oid::regprocedure AS signature,proowner FROM pg_catalog.pg_proc
 WHERE oid IN ('kaname._authority_child_registration_maximum_v1(jsonb,jsonb,jsonb)'::regprocedure,
  'kaname._authority_child_registration_hold_v1(jsonb,integer,integer)'::regprocedure)
 LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',helper.signature);
  FOR principal IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
   JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=helper.oid AND a.grantee<>helper.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',helper.signature,principal.rolname);
  END LOOP;
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION kaname._authority_child_registration_hold_v1(jsonb,integer,integer);
DROP FUNCTION kaname._authority_child_registration_maximum_v1(jsonb,jsonb,jsonb);
