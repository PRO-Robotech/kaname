-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1045: сверка источников регистрации потомка после ожиданий.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd

-- Координату родителя определяет удержанный каталог. Снимок квот и
-- квитанций читается после проверки областей и точных источников RR.
-- Возвращённый пакет остаётся у владельца и не разрешает запись.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_child_registration_hold_v1(p_envelope jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(prepared jsonb,logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 proof jsonb; intent jsonb; guards jsonb; epochs jsonb; policy_guards jsonb; checked_epochs jsonb;
 epoch_result record; bundle_result record; catalog_result record; current_result record; captured record;
 source_index jsonb; parent_row jsonb; child_row jsonb; parent_scope jsonb; child_scope jsonb;
 parent_state jsonb; child_state jsonb; required jsonb; scope jsonb;
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
  OR coalesce(nullif(p_envelope->'source_effects','null'::jsonb),'[]'::jsonb)<>'[]'::jsonb
  OR coalesce(nullif(p_envelope->'predicate_guards','null'::jsonb),'[]'::jsonb)<>'[]'::jsonb THEN
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
 SELECT * INTO STRICT epoch_result FROM kaname._authority_resource_epoch_wait_v2(
  '{}'::jsonb,policy_guards,'{"":"share"}'::jsonb,p_rows,p_reads);
 checked_epochs:=epoch_result.lock_witness->'policy_before';
 IF checked_epochs IS DISTINCT FROM epochs THEN
  RAISE EXCEPTION 'child registration native epochs changed' USING ERRCODE='P1034';
 END IF;
 logical_rows:=epoch_result.logical_rows;
 logical_reads:=epoch_result.logical_reads;
 SELECT * INTO STRICT bundle_result FROM kaname._authority_resource_bundle_catalog_v2(
  p_rows-logical_rows,p_reads-logical_reads);
 logical_rows:=logical_rows+bundle_result.logical_rows;
 logical_reads:=logical_reads+bundle_result.logical_reads;
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
 END LOOP;
 mirror_key:=jsonb_build_array(2,parent_type,parent_id,'')::text;
 required:=(parent_scope->'required')||(child_scope->'required')||jsonb_build_object(
  mirror_key,true,jsonb_build_array(2,child_type,child_id,'')::text,true);
 FOREACH kind IN ARRAY ARRAY[3,4,5,6,25,26,28] LOOP
  required:=required||jsonb_build_object(jsonb_build_array(kind,child_model,child_id,'')::text,true);
 END LOOP;
 SELECT * INTO STRICT current_result FROM kaname._authority_resource_required_reread_v2(
  source_index,required,'{}'::jsonb,p_rows-logical_rows,p_reads-logical_reads);
 logical_rows:=logical_rows+current_result.logical_rows;
 logical_reads:=logical_reads+current_result.logical_reads;
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
 prepared:=jsonb_build_object('intent',intent,'witness',captured.witness,'native_epochs',checked_epochs,
  'backend',proof->'backend','transaction_id',proof->'transaction_id','nonce',proof->'nonce');
 RETURN NEXT;
END $$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION kaname._authority_child_registration_hold_v1(jsonb,integer,integer) FROM PUBLIC;
-- +goose StatementBegin
DO $$ DECLARE principal record; BEGIN
 FOR principal IN SELECT r.rolname FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
  JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname._authority_child_registration_hold_v1(jsonb,integer,integer)'::regprocedure AND a.grantee<>p.proowner
 LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_child_registration_hold_v1(jsonb,integer,integer) FROM %I',principal.rolname);
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION kaname._authority_child_registration_hold_v1(jsonb,integer,integer);
