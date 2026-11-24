-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1142. Подстановки в owner proof читают уже закреплённый каталог.
-- Приёмка: docs/engineering/acceptance/live-business-catalog-publication.md

-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_resource_materialized_types_v2(p_rule jsonb,p_scope integer,p_catalog jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE legacy jsonb;module_name text;resources jsonb;verbs jsonb;types jsonb;
BEGIN
 -- Общие правила формы и поимённые типы остаются у проекции прежнего ABI.
 legacy:=kaname._authority_resource_materialized_types_v2(p_rule,p_scope);
 module_name:=p_rule->>'module';
 IF p_scope NOT IN (2,3) OR (module_name<>'*' AND NOT (p_rule->'resources' ? '*')) THEN
  RETURN legacy;
 END IF;
 resources:=p_catalog#>'{Live,Resources}';
 verbs:=p_catalog#>'{Live,Verbs}';
 IF jsonb_typeof(resources) IS DISTINCT FROM 'array' OR jsonb_typeof(verbs) IS DISTINCT FROM 'array'
 OR jsonb_array_length(resources)=0 OR jsonb_array_length(verbs)=0 THEN
  RAISE EXCEPTION 'materialized types require canonical live catalog' USING ERRCODE='42501';
 END IF;
 IF jsonb_array_length(resources)>100000 OR jsonb_array_length(verbs)>100000 THEN
  RAISE EXCEPTION 'materialized catalog overbound' USING ERRCODE='54000';
 END IF;
 -- Паритет catalog.Facts.buildMaterializableTypes: встроенный материализуемый
 -- тип требует живой строки. Новый тип требует собственного пообъектного
 -- глагола. Снятые имена и встроенный нематериализуемый тип остаются вне охвата.
 WITH per_object_types AS (
  SELECT DISTINCT v->>'Module' AS module_name,v->>'Resource' AS resource_name
  FROM jsonb_array_elements(verbs) v
  WHERE v->'PerObject'='true'::jsonb
 ), live_types AS (
  SELECT DISTINCT ((r->>'Module')||'.'||(r->>'Resource')) COLLATE "C" AS dotted
  FROM jsonb_array_elements(resources) r
  WHERE (module_name='*' OR r->>'Module'=module_name)
  AND ((r->>'Module')||'.'||(r->>'Resource')) <> ALL(ARRAY[
   'compute.disk','compute.image','compute.snapshot','vpc.addressPool']::text[])
  AND (((r->>'Module')||'.'||(r->>'Resource'))=ANY(kaname._authority_resource_materializable_types_v2())
   OR EXISTS(SELECT 1 FROM per_object_types v
    WHERE v.module_name=r->>'Module' AND v.resource_name=r->>'Resource'))
 )
 SELECT coalesce(jsonb_agg(dotted ORDER BY dotted),'[]'::jsonb) INTO types
 FROM (SELECT dotted FROM live_types ORDER BY dotted LIMIT 4097) bounded;
 IF jsonb_array_length(types)>4096 THEN
  RAISE EXCEPTION 'materialized type proof overbound' USING ERRCODE='54000';
 END IF;
 RETURN types;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_binding_census_projection_v3(p_role jsonb,p_stored_fps jsonb,p_scope integer,p_catalog jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE layout jsonb;types jsonb;has_nonanchor boolean;
BEGIN
 IF jsonb_typeof(p_role->'live') IS DISTINCT FROM 'boolean' THEN
  RAISE EXCEPTION 'binding census role lifecycle absent' USING ERRCODE='42501';
 END IF;
 IF p_role->'live'='false'::jsonb THEN
  RETURN jsonb_build_object('types','[]'::jsonb,'has_selectors',false,'has_nonanchor',false);
 END IF;
 layout:=kaname._authority_resource_rule_layout_v2(p_role,p_stored_fps);
 -- Stored FP's только выбирают историческую форму authored rules. Типы и
 -- необходимость глобального прохода выводятся из самих правил этой формы.
 WITH roots AS (
  SELECT value AS rule,
   CASE WHEN jsonb_array_length(value->'resources')=1 AND value->>'module' NOT IN ('','*')
         AND value->'resources'->>0<>'*'
    THEN coalesce(nullif(value->'children','null'::jsonb),'[]'::jsonb) ELSE '[]'::jsonb END AS children
  FROM jsonb_array_elements(layout)
 ), selectors AS (
  SELECT rule AS authored,p_scope AS scope FROM roots
  UNION ALL
  SELECT c.value||jsonb_build_object('module',r.rule->>'module'),1
  FROM roots r CROSS JOIN LATERAL jsonb_array_elements(r.children) c
 ), distinct_types AS (
  SELECT DISTINCT t.value COLLATE "C" AS dotted
  FROM selectors s CROSS JOIN LATERAL jsonb_array_elements_text(
   kaname._authority_resource_materialized_types_v2(s.authored,s.scope,p_catalog)) t
 )
 SELECT
  (SELECT coalesce(jsonb_agg(dotted ORDER BY dotted),'[]'::jsonb)
   FROM (SELECT dotted FROM distinct_types ORDER BY dotted LIMIT 4097) bounded),
  EXISTS(SELECT 1 FROM roots WHERE children<>'[]'::jsonb
   OR coalesce(nullif(rule->'resource_names','null'::jsonb),'[]'::jsonb)<>'[]'::jsonb
   OR coalesce(nullif(rule->'match_labels','null'::jsonb),'{}'::jsonb)<>'{}'::jsonb)
 INTO types,has_nonanchor;
 IF jsonb_array_length(types)>4096 THEN
  RAISE EXCEPTION 'binding census projection overbound' USING ERRCODE='54000';
 END IF;
 RETURN jsonb_build_object('types',types,'has_selectors',layout<>'[]'::jsonb,'has_nonanchor',has_nonanchor);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
DECLARE entry record;grantee record;
BEGIN
 FOR entry IN SELECT p.oid,p.oid::regprocedure AS signature,p.proowner
  FROM pg_catalog.pg_proc p WHERE p.oid IN (
   'kaname._authority_resource_materialized_types_v2(jsonb,integer,jsonb)'::regprocedure,
   'kaname._authority_binding_census_projection_v3(jsonb,jsonb,integer,jsonb)'::regprocedure
  )
 LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',entry.signature);
  FOR grantee IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE p.oid=entry.oid AND a.grantee<>entry.proowner
  LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',entry.signature,grantee.rolname);
  END LOOP;
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Изменения применяются только к точным телам предыдущей версии. В
-- отпечатках ниже закреплены обе стороны замены, включая оба owner verifier.
-- Исходные OID, owner, параметры и ACL сохраняет CREATE OR REPLACE из pg_proc.
DO $$
DECLARE patch record;src text;updated text;definition text;edit text[];
BEGIN
 FOR patch IN SELECT * FROM (VALUES
 ('kaname._authority_resource_binding_candidates_v2(jsonb,jsonb,text,text,text,boolean)'::regprocedure,
  '0dd211dcb360329fa856f8c14692b50169668f73e2c03fd90aea3d3a0d7737b0','827602df4b6c9590bdd3cbf94087a2ccbdb412f95736be0c3eda05e6cfba18ac',
  ARRAY[
   ARRAY[$edit$kaname._authority_resource_materialized_types_v2(authored,(binding->>'scope')::integer)$edit$,$edit$kaname._authority_resource_materialized_types_v2(authored,(binding->>'scope')::integer,p_catalog)$edit$]
  ]),
 ('kaname._authority_resource_ordinary_member_v2(jsonb,jsonb,text,jsonb,jsonb)'::regprocedure,
  'e22a387229f36c3ff81806752df50a0a0b5e03f2d8a66df1f0482180e17b5305','12f63b57af5fb53abdaaf7695491a13443f4a709a38d2124a8cfd707c6ce573c',
  ARRAY[
   ARRAY[$edit$authored jsonb; rule_proof jsonb;$edit$,$edit$authored jsonb; materialized_types jsonb; rule_proof jsonb;$edit$],
   ARRAY[$edit$ IF NOT (kaname._authority_resource_materialized_types_v2(authored,(binding->>'scope')::integer) ? dotted) THEN$edit$,$edit$ materialized_types:=kaname._authority_resource_materialized_types_v2(authored,(binding->>'scope')::integer,p_catalog);
 IF NOT (materialized_types ? dotted) THEN$edit$],
   ARRAY[$edit$ selector:=selector||jsonb_build_object('verbs',authored->'verbs',$edit$,$edit$ -- Индекс подтверждает fingerprint и форму сохранённой проекции. Состав типов
 -- определяет то же authored правило и снимок каталога, что и в census.
 IF jsonb_typeof(selector->'object_types') IS DISTINCT FROM 'array'
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(selector->'object_types') v WHERE jsonb_typeof(v)<>'string') THEN
  RAISE EXCEPTION 'invalid captured selector proof' USING ERRCODE='22023';
 END IF;
 selector:=selector||jsonb_build_object('object_types',materialized_types,'verbs',authored->'verbs',$edit$]
  ]),
 ('kaname._authority_resource_special_member_core_v2(jsonb,jsonb,text,jsonb,jsonb,jsonb)'::regprocedure,
  'a7009eb3fc759ba72f73579f72a23b6078174b556fbcbbcadc91b2e95bb4013c','2b2757872642bb61bb18ab2f6dc58e300a9d356c68490303fc7ce2562802826b',
  ARRAY[
   ARRAY[$edit$    -- Типы выводит общий exact static-registry port C, а не все live строки
    -- каталога и не сохранённая selector-проекция. Concrete names сохраняются.
    materialized_types:=kaname._authority_resource_materialized_types_v2(authored,(binding->>'scope')::integer);$edit$,$edit$    -- Типы выводятся из authored правила и закреплённого снимка каталога.
    materialized_types:=kaname._authority_resource_materialized_types_v2(authored,(binding->>'scope')::integer,p_catalog);$edit$]
  ]),
 ('kaname._authority_resource_withdrawal_role_projection_v2(jsonb,jsonb,jsonb,jsonb)'::regprocedure,
  '89c1b44eb9a74c42c2be80f3f395e05216636481893f47ac85b6696704689ab6','1a003c807a251a32fc1c07ab25f386c692ff8ff0104934684e515d343844ac57',
  ARRAY[
   ARRAY[$edit$     types:=kaname._authority_resource_materialized_types_v2(rule,1);
    ELSE types:=kaname._authority_resource_materialized_types_v2(node,2); END IF;$edit$,$edit$     types:=kaname._authority_resource_materialized_types_v2(rule,1,p_catalog);
    ELSE types:=kaname._authority_resource_materialized_types_v2(node,2,p_catalog); END IF;$edit$]
  ]),
 ('kaname.authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)'::regprocedure,
  'de942f0c6c21834ac9ecb177f4dce25e5c66c83101aaaf78bd23805ab04952a6','e61e4cb14a0cbe97eaae4466df38f79e9996e0eff1eb8ed79421835733dc19f6',
  ARRAY[
   ARRAY[$edit$ binding jsonb;selectors jsonb;members jsonb;ledger jsonb;$edit$,$edit$ binding jsonb;role_capture jsonb;stored_fps jsonb;role_projection jsonb;members jsonb;ledger jsonb;$edit$],
   ARRAY[$edit$ used_reads:=used_reads+1;used_rows:=used_rows+1;
 IF used_reads>p_reads OR used_rows>p_rows THEN RAISE EXCEPTION 'binding bundle budget exceeded' USING ERRCODE='54000';END IF;
 SELECT b.* INTO STRICT bundle FROM kaname.authority_bundle_handoff b WHERE singleton;
 IF encode(sha256(bundle.catalog_json),'hex') IS DISTINCT FROM bundle.catalog_id
 OR encode(sha256(convert_to(bundle.model_source,'UTF8')),'hex') IS DISTINCT FROM bundle.model_id THEN
  RAISE EXCEPTION 'binding canonical bundle corrupt' USING ERRCODE='42501';END IF;
 catalog:=convert_from(bundle.catalog_json,'UTF8')::jsonb;
$edit$,$edit$ -- Каталог прочитан до независимого подсчёта координат.
$edit$],
   ARRAY[$edit$ selectors:='[]'::jsonb;
 IF nullif(binding->>'role_id','') IS NOT NULL THEN
  SELECT coalesce(jsonb_agg(value->2),'[]'::jsonb) INTO selectors FROM jsonb_array_elements(kaname._authority_resource_require_capture_v2(source_index,13,'role',binding->>'role_id')->'states');
 END IF;
 SELECT coalesce(array_agg(DISTINCT value),'{}'::text[]) INTO types FROM (
  SELECT jsonb_array_elements_text(coalesce(nullif(s->'object_types','null'::jsonb),'[]'::jsonb)) value FROM jsonb_array_elements(selectors) s
  UNION SELECT value->2->>'object_type' FROM jsonb_array_elements(members->'states')
  UNION SELECT 'iam.'||(binding->>'resource_type') WHERE jsonb_array_length(selectors)>0) q;
 narrow:=binding->>'resource_type'='account' AND jsonb_array_length(coalesce(nullif(binding#>'{target,resources}','null'::jsonb),'[]'::jsonb))=0
  AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(selectors) s WHERE s->>'arm'<>'anchor' OR s->>'container_type' IS NOT NULL);
$edit$,$edit$ used_reads:=used_reads+1;used_rows:=used_rows+1;
 IF used_reads>p_reads OR used_rows>p_rows THEN RAISE EXCEPTION 'binding bundle budget exceeded' USING ERRCODE='54000';END IF;
 SELECT b.* INTO STRICT bundle FROM kaname.authority_bundle_handoff b WHERE singleton;
 IF encode(sha256(bundle.catalog_json),'hex') IS DISTINCT FROM bundle.catalog_id
 OR encode(sha256(convert_to(bundle.model_source,'UTF8')),'hex') IS DISTINCT FROM bundle.model_id THEN
  RAISE EXCEPTION 'binding canonical bundle corrupt' USING ERRCODE='42501';END IF;
 catalog:=convert_from(bundle.catalog_json,'UTF8')::jsonb;
 role_projection:=jsonb_build_object('types','[]'::jsonb,'has_selectors',false,'has_nonanchor',false);
 IF nullif(binding->>'role_id','') IS NOT NULL THEN
  role_capture:=kaname._authority_resource_require_capture_v2(source_index,12,'role',binding->>'role_id');
  IF jsonb_array_length(role_capture->'states')<>1
  OR role_capture->'states'->0->2->>'id' IS DISTINCT FROM binding->>'role_id' THEN
   RAISE EXCEPTION 'binding census canonical role absent' USING ERRCODE='42501';END IF;
  SELECT coalesce(jsonb_agg(value->2->'rule_fp'),'[]'::jsonb) INTO stored_fps
  FROM jsonb_array_elements(kaname._authority_resource_require_capture_v2(source_index,13,'role',binding->>'role_id')->'states');
  role_projection:=kaname._authority_binding_census_projection_v3(
   role_capture->'states'->0->2,stored_fps,(binding->>'scope')::integer,catalog);
 END IF;
 SELECT coalesce(array_agg(DISTINCT value),'{}'::text[]) INTO types FROM (
  SELECT jsonb_array_elements_text(role_projection->'types') value
  UNION SELECT value->2->>'object_type' FROM jsonb_array_elements(members->'states')
  UNION SELECT 'iam.'||(binding->>'resource_type') WHERE role_projection->'has_selectors'='true'::jsonb) q;
 narrow:=binding->>'resource_type'='account' AND jsonb_array_length(coalesce(nullif(binding#>'{target,resources}','null'::jsonb),'[]'::jsonb))=0
  AND role_projection->'has_nonanchor'='false'::jsonb;
$edit$]
  ]),
 ('kaname._authority_crud_storage_v3()'::regprocedure,
  '36bd005f8ee097ce2f71fb396bed20e968aa1c3f9f0baab4554e932e251a9a64','6b39ee6bf886b1ae0746093127e5b89264d32b88f01b3e3ff8bb79ebed51f259',
  ARRAY[
   ARRAY[$edit$('_authority_resource_binding_candidates_v2(jsonb,jsonb,text,text,text,boolean)','0dd211dcb360329fa856f8c14692b50169668f73e2c03fd90aea3d3a0d7737b0'$edit$,$edit$('_authority_resource_binding_candidates_v2(jsonb,jsonb,text,text,text,boolean)','827602df4b6c9590bdd3cbf94087a2ccbdb412f95736be0c3eda05e6cfba18ac'$edit$],
   ARRAY[$edit$('_authority_resource_ordinary_member_v2(jsonb,jsonb,text,jsonb,jsonb)','e22a387229f36c3ff81806752df50a0a0b5e03f2d8a66df1f0482180e17b5305'$edit$,$edit$('_authority_resource_ordinary_member_v2(jsonb,jsonb,text,jsonb,jsonb)','12f63b57af5fb53abdaaf7695491a13443f4a709a38d2124a8cfd707c6ce573c'$edit$],
   ARRAY[$edit$('_authority_resource_special_member_core_v2(jsonb,jsonb,text,jsonb,jsonb,jsonb)','a7009eb3fc759ba72f73579f72a23b6078174b556fbcbbcadc91b2e95bb4013c'$edit$,$edit$('_authority_resource_special_member_core_v2(jsonb,jsonb,text,jsonb,jsonb,jsonb)','2b2757872642bb61bb18ab2f6dc58e300a9d356c68490303fc7ce2562802826b'$edit$],
   ARRAY[$edit$('_authority_resource_withdrawal_role_projection_v2(jsonb,jsonb,jsonb,jsonb)','89c1b44eb9a74c42c2be80f3f395e05216636481893f47ac85b6696704689ab6'$edit$,$edit$('_authority_resource_withdrawal_role_projection_v2(jsonb,jsonb,jsonb,jsonb)','1a003c807a251a32fc1c07ab25f386c692ff8ff0104934684e515d343844ac57'$edit$],
   ARRAY[$edit$('authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)','de942f0c6c21834ac9ecb177f4dce25e5c66c83101aaaf78bd23805ab04952a6'$edit$,$edit$('authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)','e61e4cb14a0cbe97eaae4466df38f79e9996e0eff1eb8ed79421835733dc19f6'$edit$],
   ARRAY[$edit$ ('_authority_resource_materialized_types_v2(jsonb,integer)','a1b18cbee25c6da9fa6cbd017b0dbcd69eaa5c692065d0856d6b65cadaad4bac',true,'i',true,'preserve'),$edit$,$edit$ ('_authority_resource_materialized_types_v2(jsonb,integer)','a1b18cbee25c6da9fa6cbd017b0dbcd69eaa5c692065d0856d6b65cadaad4bac',true,'i',true,'preserve'),
 ('_authority_resource_materialized_types_v2(jsonb,integer,jsonb)','c48f643efc4c37a7de9bc99b59feeae1c7c631c005ff8fc8fc2cc56ec83a4861',true,'i',true,'private'),
 ('_authority_binding_census_projection_v3(jsonb,jsonb,integer,jsonb)','36963e0529cbc6e5264d76b1d8aa88eea1f19839bfec61684821fac060f59478',true,'i',true,'private'),$edit$]
  ]),
 ('kaname._authority_full_contract_storage_v3()'::regprocedure,
  '2aba8bcc57e9cb4b4d6bbe1241813c92b3e0cb70876d71e388401f6b8de11606','79b1e75ea5775a140b6debfe835833c4794284a6c1e9e0861fd04594da96d122',
  ARRAY[
   ARRAY[$edit$36bd005f8ee097ce2f71fb396bed20e968aa1c3f9f0baab4554e932e251a9a64$edit$,$edit$6b39ee6bf886b1ae0746093127e5b89264d32b88f01b3e3ff8bb79ebed51f259$edit$]
  ])
 ) AS replacements(signature,old_digest,new_digest,edits)
 LOOP
  SELECT p.prosrc INTO STRICT src FROM pg_catalog.pg_proc p WHERE p.oid=patch.signature;
  IF encode(sha256(convert_to(src,'UTF8')),'hex') IS DISTINCT FROM patch.old_digest THEN
   RAISE EXCEPTION 'catalog wildcard predecessor differs: %',patch.signature USING ERRCODE='55000';
  END IF;
  updated:=src;
  FOREACH edit SLICE 1 IN ARRAY patch.edits LOOP
   updated:=replace(updated,edit[1],edit[2]);
  END LOOP;
  IF encode(sha256(convert_to(updated,'UTF8')),'hex') IS DISTINCT FROM patch.new_digest THEN
   RAISE EXCEPTION 'catalog wildcard replacement differs: %',patch.signature USING ERRCODE='55000';
  END IF;
  definition:=pg_catalog.pg_get_functiondef(patch.signature);
  EXECUTE replace(definition,src,updated);
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p
      WHERE p.oid=patch.signature) IS DISTINCT FROM patch.new_digest THEN
   RAISE EXCEPTION 'catalog wildcard deployment differs: %',patch.signature USING ERRCODE='55000';
  END IF;
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
BEGIN
 IF kaname._authority_full_contract_storage_v3() IS NOT TRUE THEN
  RAISE EXCEPTION 'catalog wildcard owner closure incomplete' USING ERRCODE='55000';
 END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
 PERFORM kaname.authority_protocol_drain();
 IF EXISTS(SELECT 1 FROM kaname.authority_writer_contract WHERE required_contract=2) THEN
  RAISE EXCEPTION 'cannot remove live catalog wildcard proof in FULL' USING ERRCODE='P1036';
 END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Изменения применяются только к точным телам предыдущей версии. В
-- отпечатках ниже закреплены обе стороны замены, включая оба owner verifier.
-- Исходные OID, owner, параметры и ACL сохраняет CREATE OR REPLACE из pg_proc.
DO $$
DECLARE patch record;src text;updated text;definition text;edit text[];
BEGIN
 FOR patch IN SELECT * FROM (VALUES
 ('kaname._authority_full_contract_storage_v3()'::regprocedure,
  '79b1e75ea5775a140b6debfe835833c4794284a6c1e9e0861fd04594da96d122','2aba8bcc57e9cb4b4d6bbe1241813c92b3e0cb70876d71e388401f6b8de11606',
  ARRAY[
   ARRAY[$edit$6b39ee6bf886b1ae0746093127e5b89264d32b88f01b3e3ff8bb79ebed51f259$edit$,$edit$36bd005f8ee097ce2f71fb396bed20e968aa1c3f9f0baab4554e932e251a9a64$edit$]
  ]),
 ('kaname._authority_crud_storage_v3()'::regprocedure,
  '6b39ee6bf886b1ae0746093127e5b89264d32b88f01b3e3ff8bb79ebed51f259','36bd005f8ee097ce2f71fb396bed20e968aa1c3f9f0baab4554e932e251a9a64',
  ARRAY[
   ARRAY[$edit$ ('_authority_resource_materialized_types_v2(jsonb,integer)','a1b18cbee25c6da9fa6cbd017b0dbcd69eaa5c692065d0856d6b65cadaad4bac',true,'i',true,'preserve'),
 ('_authority_resource_materialized_types_v2(jsonb,integer,jsonb)','c48f643efc4c37a7de9bc99b59feeae1c7c631c005ff8fc8fc2cc56ec83a4861',true,'i',true,'private'),
 ('_authority_binding_census_projection_v3(jsonb,jsonb,integer,jsonb)','36963e0529cbc6e5264d76b1d8aa88eea1f19839bfec61684821fac060f59478',true,'i',true,'private'),$edit$,$edit$ ('_authority_resource_materialized_types_v2(jsonb,integer)','a1b18cbee25c6da9fa6cbd017b0dbcd69eaa5c692065d0856d6b65cadaad4bac',true,'i',true,'preserve'),$edit$],
   ARRAY[$edit$('authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)','e61e4cb14a0cbe97eaae4466df38f79e9996e0eff1eb8ed79421835733dc19f6'$edit$,$edit$('authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)','de942f0c6c21834ac9ecb177f4dce25e5c66c83101aaaf78bd23805ab04952a6'$edit$],
   ARRAY[$edit$('_authority_resource_withdrawal_role_projection_v2(jsonb,jsonb,jsonb,jsonb)','1a003c807a251a32fc1c07ab25f386c692ff8ff0104934684e515d343844ac57'$edit$,$edit$('_authority_resource_withdrawal_role_projection_v2(jsonb,jsonb,jsonb,jsonb)','89c1b44eb9a74c42c2be80f3f395e05216636481893f47ac85b6696704689ab6'$edit$],
   ARRAY[$edit$('_authority_resource_special_member_core_v2(jsonb,jsonb,text,jsonb,jsonb,jsonb)','2b2757872642bb61bb18ab2f6dc58e300a9d356c68490303fc7ce2562802826b'$edit$,$edit$('_authority_resource_special_member_core_v2(jsonb,jsonb,text,jsonb,jsonb,jsonb)','a7009eb3fc759ba72f73579f72a23b6078174b556fbcbbcadc91b2e95bb4013c'$edit$],
   ARRAY[$edit$('_authority_resource_ordinary_member_v2(jsonb,jsonb,text,jsonb,jsonb)','12f63b57af5fb53abdaaf7695491a13443f4a709a38d2124a8cfd707c6ce573c'$edit$,$edit$('_authority_resource_ordinary_member_v2(jsonb,jsonb,text,jsonb,jsonb)','e22a387229f36c3ff81806752df50a0a0b5e03f2d8a66df1f0482180e17b5305'$edit$],
   ARRAY[$edit$('_authority_resource_binding_candidates_v2(jsonb,jsonb,text,text,text,boolean)','827602df4b6c9590bdd3cbf94087a2ccbdb412f95736be0c3eda05e6cfba18ac'$edit$,$edit$('_authority_resource_binding_candidates_v2(jsonb,jsonb,text,text,text,boolean)','0dd211dcb360329fa856f8c14692b50169668f73e2c03fd90aea3d3a0d7737b0'$edit$]
  ]),
 ('kaname.authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)'::regprocedure,
  'e61e4cb14a0cbe97eaae4466df38f79e9996e0eff1eb8ed79421835733dc19f6','de942f0c6c21834ac9ecb177f4dce25e5c66c83101aaaf78bd23805ab04952a6',
  ARRAY[
   ARRAY[$edit$ used_reads:=used_reads+1;used_rows:=used_rows+1;
 IF used_reads>p_reads OR used_rows>p_rows THEN RAISE EXCEPTION 'binding bundle budget exceeded' USING ERRCODE='54000';END IF;
 SELECT b.* INTO STRICT bundle FROM kaname.authority_bundle_handoff b WHERE singleton;
 IF encode(sha256(bundle.catalog_json),'hex') IS DISTINCT FROM bundle.catalog_id
 OR encode(sha256(convert_to(bundle.model_source,'UTF8')),'hex') IS DISTINCT FROM bundle.model_id THEN
  RAISE EXCEPTION 'binding canonical bundle corrupt' USING ERRCODE='42501';END IF;
 catalog:=convert_from(bundle.catalog_json,'UTF8')::jsonb;
 role_projection:=jsonb_build_object('types','[]'::jsonb,'has_selectors',false,'has_nonanchor',false);
 IF nullif(binding->>'role_id','') IS NOT NULL THEN
  role_capture:=kaname._authority_resource_require_capture_v2(source_index,12,'role',binding->>'role_id');
  IF jsonb_array_length(role_capture->'states')<>1
  OR role_capture->'states'->0->2->>'id' IS DISTINCT FROM binding->>'role_id' THEN
   RAISE EXCEPTION 'binding census canonical role absent' USING ERRCODE='42501';END IF;
  SELECT coalesce(jsonb_agg(value->2->'rule_fp'),'[]'::jsonb) INTO stored_fps
  FROM jsonb_array_elements(kaname._authority_resource_require_capture_v2(source_index,13,'role',binding->>'role_id')->'states');
  role_projection:=kaname._authority_binding_census_projection_v3(
   role_capture->'states'->0->2,stored_fps,(binding->>'scope')::integer,catalog);
 END IF;
 SELECT coalesce(array_agg(DISTINCT value),'{}'::text[]) INTO types FROM (
  SELECT jsonb_array_elements_text(role_projection->'types') value
  UNION SELECT value->2->>'object_type' FROM jsonb_array_elements(members->'states')
  UNION SELECT 'iam.'||(binding->>'resource_type') WHERE role_projection->'has_selectors'='true'::jsonb) q;
 narrow:=binding->>'resource_type'='account' AND jsonb_array_length(coalesce(nullif(binding#>'{target,resources}','null'::jsonb),'[]'::jsonb))=0
  AND role_projection->'has_nonanchor'='false'::jsonb;
$edit$,$edit$ selectors:='[]'::jsonb;
 IF nullif(binding->>'role_id','') IS NOT NULL THEN
  SELECT coalesce(jsonb_agg(value->2),'[]'::jsonb) INTO selectors FROM jsonb_array_elements(kaname._authority_resource_require_capture_v2(source_index,13,'role',binding->>'role_id')->'states');
 END IF;
 SELECT coalesce(array_agg(DISTINCT value),'{}'::text[]) INTO types FROM (
  SELECT jsonb_array_elements_text(coalesce(nullif(s->'object_types','null'::jsonb),'[]'::jsonb)) value FROM jsonb_array_elements(selectors) s
  UNION SELECT value->2->>'object_type' FROM jsonb_array_elements(members->'states')
  UNION SELECT 'iam.'||(binding->>'resource_type') WHERE jsonb_array_length(selectors)>0) q;
 narrow:=binding->>'resource_type'='account' AND jsonb_array_length(coalesce(nullif(binding#>'{target,resources}','null'::jsonb),'[]'::jsonb))=0
  AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(selectors) s WHERE s->>'arm'<>'anchor' OR s->>'container_type' IS NOT NULL);
$edit$],
   ARRAY[$edit$ -- Каталог прочитан до независимого подсчёта координат.
$edit$,$edit$ used_reads:=used_reads+1;used_rows:=used_rows+1;
 IF used_reads>p_reads OR used_rows>p_rows THEN RAISE EXCEPTION 'binding bundle budget exceeded' USING ERRCODE='54000';END IF;
 SELECT b.* INTO STRICT bundle FROM kaname.authority_bundle_handoff b WHERE singleton;
 IF encode(sha256(bundle.catalog_json),'hex') IS DISTINCT FROM bundle.catalog_id
 OR encode(sha256(convert_to(bundle.model_source,'UTF8')),'hex') IS DISTINCT FROM bundle.model_id THEN
  RAISE EXCEPTION 'binding canonical bundle corrupt' USING ERRCODE='42501';END IF;
 catalog:=convert_from(bundle.catalog_json,'UTF8')::jsonb;
$edit$],
   ARRAY[$edit$ binding jsonb;role_capture jsonb;stored_fps jsonb;role_projection jsonb;members jsonb;ledger jsonb;$edit$,$edit$ binding jsonb;selectors jsonb;members jsonb;ledger jsonb;$edit$]
  ]),
 ('kaname._authority_resource_withdrawal_role_projection_v2(jsonb,jsonb,jsonb,jsonb)'::regprocedure,
  '1a003c807a251a32fc1c07ab25f386c692ff8ff0104934684e515d343844ac57','89c1b44eb9a74c42c2be80f3f395e05216636481893f47ac85b6696704689ab6',
  ARRAY[
   ARRAY[$edit$     types:=kaname._authority_resource_materialized_types_v2(rule,1,p_catalog);
    ELSE types:=kaname._authority_resource_materialized_types_v2(node,2,p_catalog); END IF;$edit$,$edit$     types:=kaname._authority_resource_materialized_types_v2(rule,1);
    ELSE types:=kaname._authority_resource_materialized_types_v2(node,2); END IF;$edit$]
  ]),
 ('kaname._authority_resource_special_member_core_v2(jsonb,jsonb,text,jsonb,jsonb,jsonb)'::regprocedure,
  '2b2757872642bb61bb18ab2f6dc58e300a9d356c68490303fc7ce2562802826b','a7009eb3fc759ba72f73579f72a23b6078174b556fbcbbcadc91b2e95bb4013c',
  ARRAY[
   ARRAY[$edit$    -- Типы выводятся из authored правила и закреплённого снимка каталога.
    materialized_types:=kaname._authority_resource_materialized_types_v2(authored,(binding->>'scope')::integer,p_catalog);$edit$,$edit$    -- Типы выводит общий exact static-registry port C, а не все live строки
    -- каталога и не сохранённая selector-проекция. Concrete names сохраняются.
    materialized_types:=kaname._authority_resource_materialized_types_v2(authored,(binding->>'scope')::integer);$edit$]
  ]),
 ('kaname._authority_resource_ordinary_member_v2(jsonb,jsonb,text,jsonb,jsonb)'::regprocedure,
  '12f63b57af5fb53abdaaf7695491a13443f4a709a38d2124a8cfd707c6ce573c','e22a387229f36c3ff81806752df50a0a0b5e03f2d8a66df1f0482180e17b5305',
  ARRAY[
   ARRAY[$edit$ -- Индекс подтверждает fingerprint и форму сохранённой проекции. Состав типов
 -- определяет то же authored правило и снимок каталога, что и в census.
 IF jsonb_typeof(selector->'object_types') IS DISTINCT FROM 'array'
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(selector->'object_types') v WHERE jsonb_typeof(v)<>'string') THEN
  RAISE EXCEPTION 'invalid captured selector proof' USING ERRCODE='22023';
 END IF;
 selector:=selector||jsonb_build_object('object_types',materialized_types,'verbs',authored->'verbs',$edit$,$edit$ selector:=selector||jsonb_build_object('verbs',authored->'verbs',$edit$],
   ARRAY[$edit$ materialized_types:=kaname._authority_resource_materialized_types_v2(authored,(binding->>'scope')::integer,p_catalog);
 IF NOT (materialized_types ? dotted) THEN$edit$,$edit$ IF NOT (kaname._authority_resource_materialized_types_v2(authored,(binding->>'scope')::integer) ? dotted) THEN$edit$],
   ARRAY[$edit$authored jsonb; materialized_types jsonb; rule_proof jsonb;$edit$,$edit$authored jsonb; rule_proof jsonb;$edit$]
  ]),
 ('kaname._authority_resource_binding_candidates_v2(jsonb,jsonb,text,text,text,boolean)'::regprocedure,
  '827602df4b6c9590bdd3cbf94087a2ccbdb412f95736be0c3eda05e6cfba18ac','0dd211dcb360329fa856f8c14692b50169668f73e2c03fd90aea3d3a0d7737b0',
  ARRAY[
   ARRAY[$edit$kaname._authority_resource_materialized_types_v2(authored,(binding->>'scope')::integer,p_catalog)$edit$,$edit$kaname._authority_resource_materialized_types_v2(authored,(binding->>'scope')::integer)$edit$]
  ])
 ) AS replacements(signature,old_digest,new_digest,edits)
 LOOP
  SELECT p.prosrc INTO STRICT src FROM pg_catalog.pg_proc p WHERE p.oid=patch.signature;
  IF encode(sha256(convert_to(src,'UTF8')),'hex') IS DISTINCT FROM patch.old_digest THEN
   RAISE EXCEPTION 'catalog wildcard predecessor differs: %',patch.signature USING ERRCODE='55000';
  END IF;
  updated:=src;
  FOREACH edit SLICE 1 IN ARRAY patch.edits LOOP
   updated:=replace(updated,edit[1],edit[2]);
  END LOOP;
  IF encode(sha256(convert_to(updated,'UTF8')),'hex') IS DISTINCT FROM patch.new_digest THEN
   RAISE EXCEPTION 'catalog wildcard replacement differs: %',patch.signature USING ERRCODE='55000';
  END IF;
  definition:=pg_catalog.pg_get_functiondef(patch.signature);
  EXECUTE replace(definition,src,updated);
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p
      WHERE p.oid=patch.signature) IS DISTINCT FROM patch.new_digest THEN
   RAISE EXCEPTION 'catalog wildcard deployment differs: %',patch.signature USING ERRCODE='55000';
  END IF;
 END LOOP;
END $$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_binding_census_projection_v3(jsonb,jsonb,integer,jsonb);
DROP FUNCTION kaname._authority_resource_materialized_types_v2(jsonb,integer,jsonb);

-- +goose StatementBegin
DO $$
BEGIN
 IF kaname._authority_full_contract_storage_v3() IS NOT TRUE THEN
  RAISE EXCEPTION 'catalog wildcard owner closure incomplete' USING ERRCODE='55000';
 END IF;
END $$;
-- +goose StatementEnd
