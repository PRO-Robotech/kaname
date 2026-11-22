-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1045: программа записи потомка из подтверждённых источников.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd

-- Закрытый компилятор получает удержанные источники и время решения от
-- владельца транзакции. Полномочия пользователя проверяет вызывающий код.
-- Компилятор не читает состояние заново, не берёт блокировки и не пишет.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_child_registration_program_v1(
 p_witness jsonb,p_index jsonb,p_catalog jsonb,p_catalog_rows jsonb,
 p_user_id text,p_audit_id text,p_decision_at timestamptz,p_transaction_at timestamptz,p_reserved_incarnation uuid DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 result record; child_type text; child_model text; child_id text; parent_ref text;
 catalog_item jsonb; child_catalog jsonb; catalog_state jsonb; structural jsonb; project_held boolean:=false;
 scope_info jsonb; hierarchy jsonb; sources jsonb; certificate jsonb; command jsonb;
 tuple_value jsonb; program jsonb; parent_write jsonb; parent_fact jsonb; retired_parent jsonb;
 source_version_text text; incarnation uuid; parent_state jsonb; receipt jsonb; audit jsonb;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 SELECT * INTO STRICT result FROM kaname._authority_child_registration_outcome_v1(p_witness,p_decision_at);
 IF result.outcome<>'create' THEN
  RETURN jsonb_build_object('outcome',result.outcome,'source_version',result.source_version);
 END IF;

 IF coalesce(p_user_id,'')='' OR octet_length(p_user_id)>512 OR p_user_id ~ '[[:space:][:cntrl:]:#*]'
  OR coalesce(p_audit_id,'') !~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$'
  OR p_transaction_at IS NULL OR NOT isfinite(p_transaction_at)
  OR jsonb_typeof(p_catalog_rows) IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'invalid child registration write inputs' USING ERRCODE='42501';
 END IF;
 IF jsonb_array_length(p_catalog_rows)>8192 OR octet_length(p_catalog_rows::text)>8388608
  OR octet_length(p_catalog::text)>8388608 THEN
  RAISE EXCEPTION 'child registration write catalog exceeded' USING ERRCODE='54000';
 END IF;
 child_type:=p_witness->>'child_type';
 child_model:=p_witness->>'child_model';
 child_id:=p_witness->>'child_id';
 parent_ref:=(p_witness->>'parent_model')||':'||(p_witness->>'parent_id');
 SELECT value INTO STRICT structural FROM jsonb_array_elements(p_catalog#>'{Live,Resources}')
  WHERE (value->>'Module')||'.'||(value->>'Resource')=child_type AND value->>'ObjectType'=child_model;
 IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(structural->'ParentNames') WITH ORDINALITY n(name,i)
  WHERE n.name='parent' AND structural->'ParentTypes'->>((n.i-1)::integer)=p_witness->>'parent_model')
  OR structural->'ChildRegistration' IS DISTINCT FROM p_witness->'policy' THEN
  RAISE EXCEPTION 'child registration signed catalog mismatch' USING ERRCODE='42501';
 END IF;
 FOR catalog_item IN SELECT value FROM jsonb_array_elements(p_catalog_rows) LOOP
  catalog_state:=((catalog_item->>'state')::jsonb)->2;
  IF catalog_state->>'object_type' IS DISTINCT FROM child_model THEN CONTINUE;END IF;
  project_held:=project_held OR catalog_state->'permanent_project' IS NOT DISTINCT FROM 'true'::jsonb
   OR catalog_state->'project_bindings_held' IS NOT DISTINCT FROM 'true'::jsonb;
  IF catalog_state->>'dotted'=child_type AND catalog_state->'live'='true'::jsonb THEN
   IF child_catalog IS NOT NULL AND child_catalog IS DISTINCT FROM catalog_state THEN
    RAISE EXCEPTION 'ambiguous child registration catalog' USING ERRCODE='42501';
   END IF;
   child_catalog:=catalog_state;
  END IF;
 END LOOP;
 IF child_catalog IS NULL OR child_catalog->'child_registration' IS DISTINCT FROM p_witness->'policy'
  OR child_catalog->'permanent_project' IS DISTINCT FROM structural->'PermanentProject'
  OR child_catalog->'parent_names' IS DISTINCT FROM structural->'ParentNames'
  OR child_catalog->'parent_types' IS DISTINCT FROM structural->'ParentTypes' THEN
  RAISE EXCEPTION 'child registration current catalog mismatch' USING ERRCODE='42501';
 END IF;
 child_catalog:=child_catalog||jsonb_build_object('project_bindings_held',project_held);

 scope_info:=kaname._authority_resource_registration_scope_certificate_v2(p_index,p_catalog,
  child_model,child_id,'parent',parent_ref,jsonb_build_object('ProjectID','','AccountID','','Chain','[]'::jsonb),true);
 hierarchy:=scope_info->'hierarchies'->0;
 IF hierarchy->'Links'->>0 IS DISTINCT FROM parent_ref
  OR (child_catalog->'permanent_project'='true'::jsonb AND hierarchy->>'ProjectID'='') THEN
  RAISE EXCEPTION 'child registration parent scope unavailable' USING ERRCODE='42501';
 END IF;
 tuple_value:=jsonb_build_object('User',parent_ref,'Relation','parent','Object',child_model||':'||child_id);
 command:=jsonb_build_object('dotted_type',child_type,'object_id',child_id,'parent_project_id',hierarchy->>'ProjectID',
  'parent_account_id',hierarchy->>'AccountID','labels','{}'::jsonb,'source_version',result.source_version,'parent_chain',hierarchy->'Links');
 certificate:=jsonb_build_object('action',1,'model_type',child_model,'object_type',child_type,'object_id',child_id,
  'module',structural->>'Module','tuple',tuple_value,'versionless',false,'command',command,'catalog',child_catalog,
  'old_scopes',scope_info->'old_scopes','new_scopes',scope_info->'new_scopes','hierarchies',scope_info->'hierarchies',
  'registration_accounts',scope_info->'accounts','required',scope_info->'required');
 sources:=kaname._authority_resource_registration_direct_sources_v2(p_index,certificate);
 IF sources#>'{before,mirror}' IS DISTINCT FROM 'null'::jsonb THEN
  RAISE EXCEPTION 'child registration program requires a new object' USING ERRCODE='42501';
 END IF;
 program:=kaname._authority_resource_registration_direct_program_v2(certificate,sources->'before',p_transaction_at);
 IF program->'physical_applied' IS DISTINCT FROM 'true'::jsonb OR program->'journal_required' IS DISTINCT FROM 'true'::jsonb THEN
  RAISE EXCEPTION 'child registration program did not create the object' USING ERRCODE='42501';
 END IF;
 SELECT value INTO parent_fact FROM jsonb_array_elements(sources#>'{before,facts}')
  WHERE value->>'relation'='parent' AND value->>'subject'=parent_ref;
 SELECT value INTO retired_parent FROM jsonb_array_elements(sources#>'{before,retirements}')
  WHERE value->>'relation'='parent' AND value->>'subject'=parent_ref;
 IF (retired_parent->>'delete_through')::timestamptz>=result.source_version THEN
  RAISE EXCEPTION 'child registration version precedes the parent relation retirement' USING ERRCODE='42501';
 END IF;
 parent_write:=kaname._authority_resource_registration_write_images_v2(tuple_value,result.source_version,
  parent_fact,retired_parent,p_transaction_at);
 IF nullif(parent_write#>>'{fact,source_version}','')::timestamptz IS DISTINCT FROM result.source_version THEN
  RAISE EXCEPTION 'child registration parent fact version did not advance' USING ERRCODE='42501';
 END IF;
 incarnation:=(p_witness->>'parent_incarnation')::uuid;
 IF (incarnation IS NULL)=(p_reserved_incarnation IS NULL) THEN
  RAISE EXCEPTION 'child registration incarnation reservation mismatch' USING ERRCODE='42501';
 END IF;
 IF incarnation IS NULL THEN
  incarnation:=p_reserved_incarnation;
  parent_state:=jsonb_build_object('object_type',p_witness->>'parent_type','object_id',p_witness->>'parent_id',
   'incarnation',incarnation,'closed_at',NULL);
 END IF;
 receipt:=jsonb_build_object('child_type',child_type,'child_id',child_id,'source_version',result.source_version,
  'parent_incarnation',incarnation,'created_at',p_decision_at,'user_id',p_user_id);
 source_version_text:=rtrim(rtrim(to_char(result.source_version AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'0'),'.')||'Z';
 audit:=jsonb_build_object('id',p_audit_id,'event_type','iam.resource_registration.registered',
  'tenant_account_id',nullif(hierarchy->>'AccountID',''),
  'event_payload',jsonb_build_object('actor','user:'||p_user_id,'module',structural->>'Module',
   'object',jsonb_build_object('type',child_type,'id',child_id),'relation','parent','subject',parent_ref,'outcome','registered',
   'parent_chain',hierarchy->'Links','parent',jsonb_build_object('type',p_witness->>'parent_model','id',p_witness->>'parent_id'),
   'source_version',source_version_text),
  'status','pending','attempts',0,'created_at',p_transaction_at,'next_attempt_at',p_transaction_at,'sent_at',NULL,'last_error',NULL);
 RETURN jsonb_build_object('outcome',result.outcome,'source_version',result.source_version,'certificate',certificate,
  'sources',sources,'program',program,'parent_write',parent_write,'parent_state',parent_state,'receipt',receipt,'audit',audit);
END $$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION kaname._authority_child_registration_program_v1(jsonb,jsonb,jsonb,jsonb,text,text,timestamptz,timestamptz,uuid) FROM PUBLIC;
-- +goose StatementBegin
DO $$ DECLARE principal record; BEGIN
 FOR principal IN SELECT r.rolname FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
  JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname._authority_child_registration_program_v1(jsonb,jsonb,jsonb,jsonb,text,text,timestamptz,timestamptz,uuid)'::regprocedure
   AND a.grantee<>p.proowner
 LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_child_registration_program_v1(jsonb,jsonb,jsonb,jsonb,text,text,timestamptz,timestamptz,uuid) FROM %I',principal.rolname);
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION kaname._authority_child_registration_program_v1(jsonb,jsonb,jsonb,jsonb,text,text,timestamptz,timestamptz,uuid);
