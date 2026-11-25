-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Вложенная выдача проекта доказывает отдельный удержанный снимок графа.
-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Вложенная проекция проекта берётся из удержанного зеркала и рёбер.
-- Метки доступа берутся из собственной строки, как при прямом правиле.
CREATE FUNCTION kaname._authority_resource_project_graph_v3(p_index jsonb,p_catalog jsonb,p_native jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 resources jsonb; captured jsonb; mirror_row jsonb; row_value jsonb; state jsonb;
 model_value jsonb; project_model text; account_model text; parent jsonb;
 identifier text; project_id text; account_id text; parent_id text; parent_model text;
 depth_value integer; previous_depth integer:=0; mappings integer; codepoint integer;
 forbidden text:=':#*'; seen_accounts jsonb:='{}'; ancestors jsonb:='[]'; required jsonb:='{}';
BEGIN
 resources:=p_catalog#>'{Live,Resources}';
 IF jsonb_typeof(p_index) IS DISTINCT FROM 'object' OR jsonb_typeof(p_native) IS DISTINCT FROM 'object'
 OR p_native->'object_type' IS DISTINCT FROM '"iam.project"'::jsonb
 OR p_native->'present' IS DISTINCT FROM 'true'::jsonb
 OR jsonb_typeof(p_native->'object_id') IS DISTINCT FROM 'string'
 OR jsonb_typeof(p_native->'projection') IS DISTINCT FROM 'object'
 OR p_native#>'{projection,id}' IS DISTINCT FROM p_native->'object_id'
 OR kaname.access_labels_valid_v1(p_native#>'{projection,access_labels}') IS DISTINCT FROM true
 OR resources IS NULL OR jsonb_typeof(resources) NOT IN ('array','null') THEN
  RAISE EXCEPTION 'invalid native source for retained project graph' USING ERRCODE='42501';
 END IF;
 resources:=coalesce(nullif(resources,'null'::jsonb),'[]'::jsonb);
 -- Допустимые символы координат совпадают с nativeQuestionToken.
 FOR codepoint IN 1..31 LOOP forbidden:=forbidden||chr(codepoint);END LOOP;
 FOR codepoint IN 127..159 LOOP forbidden:=forbidden||chr(codepoint);END LOOP;
 FOREACH codepoint IN ARRAY ARRAY[32,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288] LOOP
  forbidden:=forbidden||chr(codepoint);
 END LOOP;
 identifier:=p_native->>'object_id';
 IF octet_length(identifier) NOT BETWEEN 1 AND 16384 OR translate(identifier,forbidden,'')<>identifier THEN
  RAISE EXCEPTION 'invalid retained project graph identity' USING ERRCODE='42501';
 END IF;

 captured:=kaname._authority_resource_require_capture_v2(p_index,2,'iam.project',identifier);
 required:=jsonb_build_object(jsonb_build_array(2,'iam.project',identifier,'')::text,true);
 IF captured->'states'='[]'::jsonb THEN
  RETURN jsonb_build_object('present',false,'projection',NULL,'current_accounts','[]'::jsonb,
   'current_project','','ancestors',ancestors,'required',required);
 END IF;
 mirror_row:=captured#>'{states,0,2}';
 IF jsonb_array_length(captured->'states')<>1
 OR jsonb_typeof(mirror_row) IS DISTINCT FROM 'object'
 OR mirror_row->'object_type' IS DISTINCT FROM '"iam.project"'::jsonb
 OR mirror_row->'object_id' IS DISTINCT FROM to_jsonb(identifier)
 OR jsonb_typeof(mirror_row->'labels') IS DISTINCT FROM 'object'
 OR coalesce(jsonb_typeof(mirror_row->'parent_account_id'),'null') NOT IN ('string','null')
 OR coalesce(jsonb_typeof(mirror_row->'parent_project_id'),'null') NOT IN ('string','null') THEN
  RAISE EXCEPTION 'invalid retained project mirror identity or image' USING ERRCODE='42501';
 END IF;
 mirror_row:=jsonb_set(mirror_row,'{access_labels}',p_native#>'{projection,access_labels}');
 account_id:=coalesce(mirror_row->>'parent_account_id','');
 project_id:=coalesce(mirror_row->>'parent_project_id','');
 IF octet_length(account_id)>16384 OR translate(account_id,forbidden,'')<>account_id
 OR octet_length(project_id)>16384 OR translate(project_id,forbidden,'')<>project_id THEN
  RAISE EXCEPTION 'invalid retained project mirror scope' USING ERRCODE='42501';
 END IF;
 -- Фиксируем необязательный проект даже при указанном в зеркале аккаунте.
 IF project_id<>'' THEN
  captured:=kaname._authority_resource_require_capture_v2(p_index,1,'project',project_id);
  required:=required||jsonb_build_object(jsonb_build_array(1,'project',project_id,'')::text,true);
  IF jsonb_array_length(captured->'states')>1 THEN
   RAISE EXCEPTION 'duplicate retained owning project' USING ERRCODE='42501';
  END IF;
  IF captured->'states'<>'[]'::jsonb THEN
   row_value:=captured#>'{states,0,2}';
   parent_id:=row_value->>'account_id';
   IF row_value->'id' IS DISTINCT FROM to_jsonb(project_id)
   OR jsonb_typeof(row_value->'account_id') IS DISTINCT FROM 'string'
   OR octet_length(parent_id) NOT BETWEEN 1 AND 16384 OR translate(parent_id,forbidden,'')<>parent_id THEN
    RAISE EXCEPTION 'invalid retained owning project identity or account' USING ERRCODE='42501';
   END IF;
   IF account_id='' THEN account_id:=parent_id;END IF;
  END IF;
 END IF;

 SELECT count(*),jsonb_agg(r)->0->'ObjectType' INTO mappings,model_value
 FROM jsonb_array_elements(resources) r WHERE r->'Module'='"iam"'::jsonb AND r->'Resource'='"project"'::jsonb;
 IF mappings>0 THEN
  project_model:=model_value #>> '{}';
  IF mappings<>1 OR jsonb_typeof(model_value) IS DISTINCT FROM 'string'
  OR octet_length(project_model) NOT BETWEEN 1 AND 16384 OR translate(project_model,forbidden,'')<>project_model THEN
   RAISE EXCEPTION 'invalid live project model mapping' USING ERRCODE='42501';
  END IF;
  captured:=kaname._authority_resource_require_capture_v2(p_index,3,project_model,identifier);
  required:=required||jsonb_build_object(jsonb_build_array(3,project_model,identifier,'')::text,true);
  IF jsonb_array_length(captured->'states')>4 THEN
   RAISE EXCEPTION 'stored project ancestor graph overbound' USING ERRCODE='54000';
  END IF;
  IF captured->'states'<>'[]'::jsonb THEN
   SELECT count(*),jsonb_agg(r)->0->'ObjectType' INTO mappings,model_value
   FROM jsonb_array_elements(resources) r WHERE r->'Module'='"iam"'::jsonb AND r->'Resource'='"account"'::jsonb;
   IF mappings>0 THEN
    account_model:=model_value #>> '{}';
    IF mappings<>1 OR jsonb_typeof(model_value) IS DISTINCT FROM 'string'
    OR octet_length(account_model) NOT BETWEEN 1 AND 16384 OR translate(account_model,forbidden,'')<>account_model THEN
     RAISE EXCEPTION 'invalid live account model mapping' USING ERRCODE='42501';
    END IF;
   END IF;
  END IF;
  -- Сохраняем все физические рёбра, включая повторы аккаунта
  -- и рёбра типов вне расчёта прав проекта.
  FOR state IN SELECT value FROM jsonb_array_elements(captured->'states') ORDER BY value->2->'depth' LOOP
   row_value:=state->2;
   parent_model:=row_value->>'parent_type';
   parent_id:=row_value->>'parent_id';
   IF row_value->'object_type' IS DISTINCT FROM to_jsonb(project_model)
   OR row_value->'object_id' IS DISTINCT FROM to_jsonb(identifier)
   OR jsonb_typeof(row_value->'parent_type') IS DISTINCT FROM 'string'
   OR jsonb_typeof(row_value->'parent_id') IS DISTINCT FROM 'string'
   OR jsonb_typeof(row_value->'depth') IS DISTINCT FROM 'number'
   OR row_value->>'depth' !~ '^[1-4]$'
   OR octet_length(parent_model) NOT BETWEEN 1 AND 16384 OR translate(parent_model,forbidden,'')<>parent_model
   OR octet_length(parent_id) NOT BETWEEN 1 AND 16384 OR translate(parent_id,forbidden,'')<>parent_id THEN
    RAISE EXCEPTION 'invalid stored project ancestor edge' USING ERRCODE='42501';
   END IF;
   depth_value:=(row_value->>'depth')::integer;
   IF depth_value<=previous_depth THEN
    RAISE EXCEPTION 'duplicate stored project ancestor depth' USING ERRCODE='42501';
   END IF;
   previous_depth:=depth_value;
   IF parent_model IS DISTINCT FROM account_model OR seen_accounts ? parent_id THEN CONTINUE;END IF;
   seen_accounts:=seen_accounts||jsonb_build_object(parent_id,true);
   parent:=kaname._authority_resource_projection_v2(p_index,'iam.account',parent_id);
   required:=required||(parent->'required');
   IF parent->'present'='true'::jsonb THEN
    IF parent#>'{projection,id}' IS DISTINCT FROM to_jsonb(parent_id)
    OR jsonb_typeof(parent#>'{projection,labels}') IS DISTINCT FROM 'object'
    OR kaname.access_labels_valid_v1(parent#>'{projection,access_labels}') IS DISTINCT FROM true THEN
     RAISE EXCEPTION 'invalid native account ancestor image' USING ERRCODE='42501';
    END IF;
    ancestors:=ancestors||jsonb_build_array(parent);
   END IF;
  END LOOP;
 END IF;
 RETURN jsonb_build_object('present',true,'projection',mirror_row,
  'current_accounts',CASE WHEN account_id='' THEN '[]'::jsonb ELSE jsonb_build_array(account_id) END,
  'current_project',project_id,'ancestors',ancestors,'required',required);
END $$;
REVOKE ALL ON FUNCTION kaname._authority_resource_project_graph_v3(jsonb,jsonb,jsonb) FROM PUBLIC;
DO $$ DECLARE recipient record; BEGIN
 FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
 CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) acl
 JOIN pg_catalog.pg_roles r ON r.oid=acl.grantee
 WHERE p.oid='kaname._authority_resource_project_graph_v3(jsonb,jsonb,jsonb)'::regprocedure AND acl.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_resource_project_graph_v3(jsonb,jsonb,jsonb) FROM %I',recipient.rolname);
 END LOOP;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $scope_install$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('_authority_resource_binding_certificate_v2(jsonb,jsonb,text,text,text,boolean,jsonb)','ec4d5deaf2df7982eba06a3350b0ae874c7179af6b41912fae3ed4d93e5c9386','f6827385f78036ea744d9d070e155d53b583fc2ef4e3461a3f5052bd6e78a833',$changes$[
 [
  " projection jsonb;ancestry jsonb;certificate jsonb;members jsonb;ledger jsonb;",
  " projection jsonb;ancestry jsonb;certificate jsonb;members jsonb;ledger jsonb;\n project_graph_sources jsonb:='{}'::jsonb;"
 ],
 [
  " RETURN jsonb_build_object('required',required,'coordinates',coordinates,'whole',census->'whole','desired',verified,'work',work,",
  " RETURN jsonb_build_object('required',required,'coordinates',coordinates,'whole',census->'whole','desired',verified,'work',work,\n  'project_graph_sources',project_graph_sources,"
 ],
 [
  "  ancestry:=kaname._authority_resource_ancestor_graph_v2(p_index,p_catalog,projection);\n  required:=required||(projection->'required')||(ancestry->'required');\n  projection:=projection||jsonb_build_object('ancestors',ancestry->'ancestors');",
  "  IF typ='iam.project' AND (projection->>'present')::boolean THEN\n   ancestry:=kaname._authority_resource_project_graph_v3(p_index,p_catalog,projection);\n   project_graph_sources:=project_graph_sources||(ancestry->'required');\n   required:=required||(projection->'required')||(ancestry->'required');\n   projection:=projection||jsonb_build_object('ancestors','[]'::jsonb,'nested_project',ancestry-'required');\n   work:=work+jsonb_array_length(ancestry->'ancestors');\n  ELSE\n   ancestry:=kaname._authority_resource_ancestor_graph_v2(p_index,p_catalog,projection);\n   required:=required||(projection->'required')||(ancestry->'required');\n   projection:=projection||jsonb_build_object('ancestors',ancestry->'ancestors');\n  END IF;"
 ]
]$changes$::jsonb),
  ('_authority_resource_object_certificate_v2(jsonb,jsonb,jsonb,jsonb)','9d0b5419a24502e9abfa42b50fed23be08ed5d349af73c6eb79896b17712c8e3','2fee3ca4c295f09234e4713d849675d966df8f7492260338c9e41d75f0587a83',$changes$[
 [
  "DECLARE root_graph jsonb;candidate jsonb;certificate jsonb;output_graph jsonb;carrier jsonb;carrier_scopes jsonb;",
  "DECLARE root_graph jsonb;candidate jsonb;certificate jsonb;output_graph jsonb;carrier jsonb;carrier_scopes jsonb;\n project_graph jsonb; project_graph_sources jsonb:='{}'::jsonb;"
 ],
 [
  " RETURN jsonb_build_object('required',required,'graphs',graphs,'accounts',accounts,'projects',projects,",
  " RETURN jsonb_build_object('required',required,'graphs',graphs,'accounts',accounts,'projects',projects,\n  'project_graph_sources',project_graph_sources,"
 ],
 [
  "  required:=required||(certificate->'required');coordinates:=coordinates||(certificate->'coordinates');",
  "  required:=required||(certificate->'required');coordinates:=coordinates||(certificate->'coordinates');\n  project_graph_sources:=project_graph_sources||(certificate->'project_graph_sources');"
 ],
 [
  " required:=(root_graph->'required')||(candidate->'required');",
  " required:=(root_graph->'required')||(candidate->'required');\n IF root_type='iam.project' AND (root_graph->>'present')::boolean THEN\n  -- Пустой отбор не отменяет удержание графа, от которого он зависел.\n  project_graph:=kaname._authority_resource_project_graph_v3(p_index,p_catalog,\n   kaname._authority_resource_projection_v2(p_index,root_type,root_id));\n  project_graph_sources:=project_graph->'required';\n  required:=required||project_graph_sources;\n END IF;"
 ]
]$changes$::jsonb),
  ('_authority_resource_special_member_core_v2(jsonb,jsonb,text,jsonb,jsonb,jsonb)','e68d120733a18f27fd72243f379bbba18de38cfaea1329da4ea8b758b42e256d','01136a2459e0e7d64fc3eb529967de9cebbbb50fc9497cbd96f73283e1d6ca60',$changes$[
 [
  " ancestors jsonb; ancestor jsonb; projection jsonb; root_catalog jsonb; resource jsonb;",
  " ancestors jsonb; ancestor jsonb; projection jsonb; root_catalog jsonb; resource jsonb;\n nested_graph jsonb;"
 ],
 [
  "   IF nested THEN\n    IF NOT has_nonclass THEN EXIT branch_proof; END IF;\n    owner_rule:=proof->'owner';",
  "   IF nested THEN\n    IF NOT has_nonclass THEN EXIT branch_proof; END IF;\n    nested_graph:=p_graph;\n    IF dotted='iam.project' AND p_graph ? 'nested_project' THEN\n     -- Проекция приготовлена внутри закрытого сертификата, отдельно от\n     -- собственной строки проекта, используемой остальными ветвями.\n     nested_graph:=p_graph->'nested_project';\n     IF jsonb_typeof(nested_graph) IS DISTINCT FROM 'object'\n      OR jsonb_typeof(nested_graph->'present') IS DISTINCT FROM 'boolean'\n      OR jsonb_typeof(nested_graph->'ancestors') IS DISTINCT FROM 'array'\n      OR jsonb_typeof(nested_graph->'current_accounts') IS DISTINCT FROM 'array'\n      OR jsonb_typeof(nested_graph->'current_project') IS DISTINCT FROM 'string'\n      OR jsonb_array_length(nested_graph->'ancestors')>4 THEN\n      RAISE EXCEPTION 'invalid certified nested project graph' USING ERRCODE='42501';\n     END IF;\n     IF NOT (nested_graph->>'present')::boolean THEN EXIT branch_proof; END IF;\n     projection:=nested_graph->'projection';\n     ancestors:=nested_graph->'ancestors';\n    END IF;\n    owner_rule:=proof->'owner';"
 ],
 [
  "    IF NOT kaname._authority_resource_contained_v2(scope_type,scope_id,p_graph->'current_accounts',p_graph->>'current_project') THEN\n     exists_member:=true;expected_status:='REJECTED';EXIT branch_proof;\n    END IF;\n    IF model_type IS NULL THEN EXIT branch_proof;END IF;",
  "    IF NOT kaname._authority_resource_contained_v2(scope_type,scope_id,nested_graph->'current_accounts',nested_graph->>'current_project') THEN\n     exists_member:=true;expected_status:='REJECTED';EXIT branch_proof;\n    END IF;\n    IF model_type IS NULL THEN EXIT branch_proof;END IF;"
 ]
]$changes$::jsonb),
  ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','aed0564d7394c2b2880c24f2176e706bc430f81c746c856c5d5c570ac8586446','8c85dff180706093bf3253d7c1a049bd17cb353fe8ed8b1a81dea069cdde6296',$changes$[
 [
  " held_advisory jsonb;compiled jsonb;entry record;global_required boolean;used_rows integer:=0;used_reads integer:=0;",
  " held_advisory jsonb;compiled jsonb;entry record;global_required boolean;used_rows integer:=0;used_reads integer:=0;\n project_sources jsonb; catalog_type text; gap_lock text;"
 ],
 [
  " SELECT * INTO STRICT current_result FROM kaname._authority_resource_required_reread_v2(source_index,required-binding_keys,\n  sources->'write_keys',p_rows-used_rows,p_reads-used_reads);",
  " project_sources:=certificate->'project_graph_sources';\n IF project_sources<>'{}'::jsonb THEN\n  -- Удерживаем точные чтения каталога, в том числе пустой ответ по типу аккаунта.\n  FOR catalog_type IN\n   SELECT 'iam.project'::text\n   UNION ALL SELECT 'iam.account' WHERE EXISTS(\n    SELECT 1 FROM jsonb_object_keys(project_sources) AS s(key)\n    WHERE source_index->s.key->'source'->>'kind'='3'\n    AND source_index->s.key->'source'->'states'<>'[]'::jsonb\n   )\n  LOOP\n   IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p_envelope->'catalogs') c WHERE c->>'input'=catalog_type) THEN\n    RAISE EXCEPTION 'project graph catalog capture omitted' USING ERRCODE='42501';\n   END IF;\n   IF ARRAY(SELECT r->>'ObjectType' FROM jsonb_array_elements(\n      coalesce(nullif(catalog#>'{Live,Resources}','null'::jsonb),'[]'::jsonb)) r\n      WHERE (r->>'Module')||'.'||(r->>'Resource')=catalog_type ORDER BY 1)\n    IS DISTINCT FROM ARRAY(SELECT DISTINCT c->>'object_type' FROM jsonb_array_elements(catalog_result.catalog_rows) c\n      WHERE c->>'dotted'=catalog_type AND c->'live'='true'::jsonb ORDER BY 1) THEN\n    RAISE EXCEPTION 'project graph live catalog changed' USING ERRCODE='P1034';\n   END IF;\n  END LOOP;\n  -- У пустой строки нет tuple lock. Берём SHARE той же координаты, на\n  -- которой INSERT и смена PK требуют EXCLUSIVE. До перечтения, без ожидания.\n  FOR gap_lock IN\n   SELECT kaname._authority_crud_unique_key_v3(\n    CASE source->>'kind' WHEN '1' THEN 'projects' ELSE 'accounts' END,\n    jsonb_build_object('id',source->>'id')) COLLATE \"C\" AS key\n   FROM (\n    SELECT source_index->s.key->'source' AS source\n    FROM jsonb_object_keys(project_sources) AS s(key)\n   ) graph_source\n   WHERE source->'states'='[]'::jsonb\n    AND ((source->>'kind'='1' AND source->>'type'='project')\n     OR (source->>'kind'='30' AND source->>'type'='iam.account'))\n   ORDER BY 1\n  LOOP\n   IF used_reads>=p_reads THEN\n    RAISE EXCEPTION 'project graph gap guard budget exceeded' USING ERRCODE='54000';\n   END IF;\n   used_reads:=used_reads+1;\n   IF NOT pg_try_advisory_xact_lock_shared(1262569303,hashtext(gap_lock)) THEN\n    RAISE EXCEPTION 'project graph source insertion in progress' USING ERRCODE='P1034';\n   END IF;\n  END LOOP;\n END IF;\n SELECT * INTO STRICT current_result FROM kaname._authority_resource_required_reread_v2(source_index,required-binding_keys,\n  sources->'write_keys',p_rows-used_rows,p_reads-used_reads);"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','4ac1f34dbb751749be55fe8f86bf03472e74addb1a06f5d428eb87741bc6ed3f','3f516c6b0d2fd7f26ab0d89e6da88f61470ba54d9045f9e7ab66aca9350712a0',$changes$[
 [
  " ('_authority_resource_binding_certificate_v2(jsonb,jsonb,text,text,text,boolean,jsonb)','ec4d5deaf2df7982eba06a3350b0ae874c7179af6b41912fae3ed4d93e5c9386',true,'i',true,'preserve'),\n",
  " ('_authority_resource_binding_certificate_v2(jsonb,jsonb,text,text,text,boolean,jsonb)','ec4d5deaf2df7982eba06a3350b0ae874c7179af6b41912fae3ed4d93e5c9386',true,'i',true,'preserve'),\n ('_authority_resource_project_graph_v3(jsonb,jsonb,jsonb)','555da7c8947f469b49da0d621c34e775acbe2289db84f30b6358a6404b590151',true,'i',true,'private'),\n"
 ],
 [
  "  ('_authority_role_move_raw_project_children_v1(jsonb,jsonb,boolean,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_replay','p_rows','p_reads']),\n",
  "  ('_authority_role_move_raw_project_children_v1(jsonb,jsonb,boolean,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_replay','p_rows','p_reads']),\n  ('_authority_resource_project_graph_v3(jsonb,jsonb,jsonb)','jsonb',3,ARRAY['p_index','p_catalog','p_native']),\n"
 ],
 [
  "ec4d5deaf2df7982eba06a3350b0ae874c7179af6b41912fae3ed4d93e5c9386",
  "f6827385f78036ea744d9d070e155d53b583fc2ef4e3461a3f5052bd6e78a833"
 ],
 [
  "9d0b5419a24502e9abfa42b50fed23be08ed5d349af73c6eb79896b17712c8e3",
  "2fee3ca4c295f09234e4713d849675d966df8f7492260338c9e41d75f0587a83"
 ],
 [
  "e68d120733a18f27fd72243f379bbba18de38cfaea1329da4ea8b758b42e256d",
  "01136a2459e0e7d64fc3eb529967de9cebbbb50fc9497cbd96f73283e1d6ca60"
 ],
 [
  "aed0564d7394c2b2880c24f2176e706bc430f81c746c856c5d5c570ac8586446",
  "8c85dff180706093bf3253d7c1a049bd17cb353fe8ed8b1a81dea069cdde6296"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','5a0fbdfa186b8ce67133769aab2e0844af997fab15dab6c4d6eb285de25642de','caad893b04b5e7d7ec6b4e9d8737cc9614c4d194838d5c526a631361bb3d1c94',$changes$[
 [
  "4ac1f34dbb751749be55fe8f86bf03472e74addb1a06f5d428eb87741bc6ed3f",
  "3f516c6b0d2fd7f26ab0d89e6da88f61470ba54d9045f9e7ab66aca9350712a0"
 ]
]$changes$::jsonb),
  ('authority_metadata_service_account_access_label_ready_v1()','87ed8dc13f1b393377d6850c1666fb4e6b2cccdf0be1bc60d5bea074bc33a6b5','f70a64f42663e0c2b7ab11ea834f4b54868a56d08b593ef0536281ccad5a0f07',$changes$[
 [
  "4ac1f34dbb751749be55fe8f86bf03472e74addb1a06f5d428eb87741bc6ed3f",
  "3f516c6b0d2fd7f26ab0d89e6da88f61470ba54d9045f9e7ab66aca9350712a0"
 ],
 [
  "5a0fbdfa186b8ce67133769aab2e0844af997fab15dab6c4d6eb285de25642de",
  "caad893b04b5e7d7ec6b4e9d8737cc9614c4d194838d5c526a631361bb3d1c94"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'object project graph custody predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'object project graph custody splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'object project graph custody body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'object project graph custody function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed object project graph custody function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'object project graph custody custody differs after migration' USING ERRCODE='55000';END IF;
END;
$scope_install$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $scope_install$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('authority_metadata_service_account_access_label_ready_v1()','f70a64f42663e0c2b7ab11ea834f4b54868a56d08b593ef0536281ccad5a0f07','87ed8dc13f1b393377d6850c1666fb4e6b2cccdf0be1bc60d5bea074bc33a6b5',$changes$[
 [
  "caad893b04b5e7d7ec6b4e9d8737cc9614c4d194838d5c526a631361bb3d1c94",
  "5a0fbdfa186b8ce67133769aab2e0844af997fab15dab6c4d6eb285de25642de"
 ],
 [
  "3f516c6b0d2fd7f26ab0d89e6da88f61470ba54d9045f9e7ab66aca9350712a0",
  "4ac1f34dbb751749be55fe8f86bf03472e74addb1a06f5d428eb87741bc6ed3f"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','caad893b04b5e7d7ec6b4e9d8737cc9614c4d194838d5c526a631361bb3d1c94','5a0fbdfa186b8ce67133769aab2e0844af997fab15dab6c4d6eb285de25642de',$changes$[
 [
  "3f516c6b0d2fd7f26ab0d89e6da88f61470ba54d9045f9e7ab66aca9350712a0",
  "4ac1f34dbb751749be55fe8f86bf03472e74addb1a06f5d428eb87741bc6ed3f"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','3f516c6b0d2fd7f26ab0d89e6da88f61470ba54d9045f9e7ab66aca9350712a0','4ac1f34dbb751749be55fe8f86bf03472e74addb1a06f5d428eb87741bc6ed3f',$changes$[
 [
  "8c85dff180706093bf3253d7c1a049bd17cb353fe8ed8b1a81dea069cdde6296",
  "aed0564d7394c2b2880c24f2176e706bc430f81c746c856c5d5c570ac8586446"
 ],
 [
  "01136a2459e0e7d64fc3eb529967de9cebbbb50fc9497cbd96f73283e1d6ca60",
  "e68d120733a18f27fd72243f379bbba18de38cfaea1329da4ea8b758b42e256d"
 ],
 [
  "2fee3ca4c295f09234e4713d849675d966df8f7492260338c9e41d75f0587a83",
  "9d0b5419a24502e9abfa42b50fed23be08ed5d349af73c6eb79896b17712c8e3"
 ],
 [
  "f6827385f78036ea744d9d070e155d53b583fc2ef4e3461a3f5052bd6e78a833",
  "ec4d5deaf2df7982eba06a3350b0ae874c7179af6b41912fae3ed4d93e5c9386"
 ],
 [
  "  ('_authority_role_move_raw_project_children_v1(jsonb,jsonb,boolean,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_replay','p_rows','p_reads']),\n  ('_authority_resource_project_graph_v3(jsonb,jsonb,jsonb)','jsonb',3,ARRAY['p_index','p_catalog','p_native']),\n",
  "  ('_authority_role_move_raw_project_children_v1(jsonb,jsonb,boolean,integer,integer)','jsonb',5,ARRAY['p_frozen','p_plan','p_replay','p_rows','p_reads']),\n"
 ],
 [
  " ('_authority_resource_binding_certificate_v2(jsonb,jsonb,text,text,text,boolean,jsonb)','ec4d5deaf2df7982eba06a3350b0ae874c7179af6b41912fae3ed4d93e5c9386',true,'i',true,'preserve'),\n ('_authority_resource_project_graph_v3(jsonb,jsonb,jsonb)','555da7c8947f469b49da0d621c34e775acbe2289db84f30b6358a6404b590151',true,'i',true,'private'),\n",
  " ('_authority_resource_binding_certificate_v2(jsonb,jsonb,text,text,text,boolean,jsonb)','ec4d5deaf2df7982eba06a3350b0ae874c7179af6b41912fae3ed4d93e5c9386',true,'i',true,'preserve'),\n"
 ]
]$changes$::jsonb),
  ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','8c85dff180706093bf3253d7c1a049bd17cb353fe8ed8b1a81dea069cdde6296','aed0564d7394c2b2880c24f2176e706bc430f81c746c856c5d5c570ac8586446',$changes$[
 [
  " project_sources:=certificate->'project_graph_sources';\n IF project_sources<>'{}'::jsonb THEN\n  -- Удерживаем точные чтения каталога, в том числе пустой ответ по типу аккаунта.\n  FOR catalog_type IN\n   SELECT 'iam.project'::text\n   UNION ALL SELECT 'iam.account' WHERE EXISTS(\n    SELECT 1 FROM jsonb_object_keys(project_sources) AS s(key)\n    WHERE source_index->s.key->'source'->>'kind'='3'\n    AND source_index->s.key->'source'->'states'<>'[]'::jsonb\n   )\n  LOOP\n   IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p_envelope->'catalogs') c WHERE c->>'input'=catalog_type) THEN\n    RAISE EXCEPTION 'project graph catalog capture omitted' USING ERRCODE='42501';\n   END IF;\n   IF ARRAY(SELECT r->>'ObjectType' FROM jsonb_array_elements(\n      coalesce(nullif(catalog#>'{Live,Resources}','null'::jsonb),'[]'::jsonb)) r\n      WHERE (r->>'Module')||'.'||(r->>'Resource')=catalog_type ORDER BY 1)\n    IS DISTINCT FROM ARRAY(SELECT DISTINCT c->>'object_type' FROM jsonb_array_elements(catalog_result.catalog_rows) c\n      WHERE c->>'dotted'=catalog_type AND c->'live'='true'::jsonb ORDER BY 1) THEN\n    RAISE EXCEPTION 'project graph live catalog changed' USING ERRCODE='P1034';\n   END IF;\n  END LOOP;\n  -- У пустой строки нет tuple lock. Берём SHARE той же координаты, на\n  -- которой INSERT и смена PK требуют EXCLUSIVE. До перечтения, без ожидания.\n  FOR gap_lock IN\n   SELECT kaname._authority_crud_unique_key_v3(\n    CASE source->>'kind' WHEN '1' THEN 'projects' ELSE 'accounts' END,\n    jsonb_build_object('id',source->>'id')) COLLATE \"C\" AS key\n   FROM (\n    SELECT source_index->s.key->'source' AS source\n    FROM jsonb_object_keys(project_sources) AS s(key)\n   ) graph_source\n   WHERE source->'states'='[]'::jsonb\n    AND ((source->>'kind'='1' AND source->>'type'='project')\n     OR (source->>'kind'='30' AND source->>'type'='iam.account'))\n   ORDER BY 1\n  LOOP\n   IF used_reads>=p_reads THEN\n    RAISE EXCEPTION 'project graph gap guard budget exceeded' USING ERRCODE='54000';\n   END IF;\n   used_reads:=used_reads+1;\n   IF NOT pg_try_advisory_xact_lock_shared(1262569303,hashtext(gap_lock)) THEN\n    RAISE EXCEPTION 'project graph source insertion in progress' USING ERRCODE='P1034';\n   END IF;\n  END LOOP;\n END IF;\n SELECT * INTO STRICT current_result FROM kaname._authority_resource_required_reread_v2(source_index,required-binding_keys,\n  sources->'write_keys',p_rows-used_rows,p_reads-used_reads);",
  " SELECT * INTO STRICT current_result FROM kaname._authority_resource_required_reread_v2(source_index,required-binding_keys,\n  sources->'write_keys',p_rows-used_rows,p_reads-used_reads);"
 ],
 [
  " held_advisory jsonb;compiled jsonb;entry record;global_required boolean;used_rows integer:=0;used_reads integer:=0;\n project_sources jsonb; catalog_type text; gap_lock text;",
  " held_advisory jsonb;compiled jsonb;entry record;global_required boolean;used_rows integer:=0;used_reads integer:=0;"
 ]
]$changes$::jsonb),
  ('_authority_resource_special_member_core_v2(jsonb,jsonb,text,jsonb,jsonb,jsonb)','01136a2459e0e7d64fc3eb529967de9cebbbb50fc9497cbd96f73283e1d6ca60','e68d120733a18f27fd72243f379bbba18de38cfaea1329da4ea8b758b42e256d',$changes$[
 [
  "    IF NOT kaname._authority_resource_contained_v2(scope_type,scope_id,nested_graph->'current_accounts',nested_graph->>'current_project') THEN\n     exists_member:=true;expected_status:='REJECTED';EXIT branch_proof;\n    END IF;\n    IF model_type IS NULL THEN EXIT branch_proof;END IF;",
  "    IF NOT kaname._authority_resource_contained_v2(scope_type,scope_id,p_graph->'current_accounts',p_graph->>'current_project') THEN\n     exists_member:=true;expected_status:='REJECTED';EXIT branch_proof;\n    END IF;\n    IF model_type IS NULL THEN EXIT branch_proof;END IF;"
 ],
 [
  "   IF nested THEN\n    IF NOT has_nonclass THEN EXIT branch_proof; END IF;\n    nested_graph:=p_graph;\n    IF dotted='iam.project' AND p_graph ? 'nested_project' THEN\n     -- Проекция приготовлена внутри закрытого сертификата, отдельно от\n     -- собственной строки проекта, используемой остальными ветвями.\n     nested_graph:=p_graph->'nested_project';\n     IF jsonb_typeof(nested_graph) IS DISTINCT FROM 'object'\n      OR jsonb_typeof(nested_graph->'present') IS DISTINCT FROM 'boolean'\n      OR jsonb_typeof(nested_graph->'ancestors') IS DISTINCT FROM 'array'\n      OR jsonb_typeof(nested_graph->'current_accounts') IS DISTINCT FROM 'array'\n      OR jsonb_typeof(nested_graph->'current_project') IS DISTINCT FROM 'string'\n      OR jsonb_array_length(nested_graph->'ancestors')>4 THEN\n      RAISE EXCEPTION 'invalid certified nested project graph' USING ERRCODE='42501';\n     END IF;\n     IF NOT (nested_graph->>'present')::boolean THEN EXIT branch_proof; END IF;\n     projection:=nested_graph->'projection';\n     ancestors:=nested_graph->'ancestors';\n    END IF;\n    owner_rule:=proof->'owner';",
  "   IF nested THEN\n    IF NOT has_nonclass THEN EXIT branch_proof; END IF;\n    owner_rule:=proof->'owner';"
 ],
 [
  " ancestors jsonb; ancestor jsonb; projection jsonb; root_catalog jsonb; resource jsonb;\n nested_graph jsonb;",
  " ancestors jsonb; ancestor jsonb; projection jsonb; root_catalog jsonb; resource jsonb;"
 ]
]$changes$::jsonb),
  ('_authority_resource_object_certificate_v2(jsonb,jsonb,jsonb,jsonb)','2fee3ca4c295f09234e4713d849675d966df8f7492260338c9e41d75f0587a83','9d0b5419a24502e9abfa42b50fed23be08ed5d349af73c6eb79896b17712c8e3',$changes$[
 [
  " required:=(root_graph->'required')||(candidate->'required');\n IF root_type='iam.project' AND (root_graph->>'present')::boolean THEN\n  -- Пустой отбор не отменяет удержание графа, от которого он зависел.\n  project_graph:=kaname._authority_resource_project_graph_v3(p_index,p_catalog,\n   kaname._authority_resource_projection_v2(p_index,root_type,root_id));\n  project_graph_sources:=project_graph->'required';\n  required:=required||project_graph_sources;\n END IF;",
  " required:=(root_graph->'required')||(candidate->'required');"
 ],
 [
  "  required:=required||(certificate->'required');coordinates:=coordinates||(certificate->'coordinates');\n  project_graph_sources:=project_graph_sources||(certificate->'project_graph_sources');",
  "  required:=required||(certificate->'required');coordinates:=coordinates||(certificate->'coordinates');"
 ],
 [
  " RETURN jsonb_build_object('required',required,'graphs',graphs,'accounts',accounts,'projects',projects,\n  'project_graph_sources',project_graph_sources,",
  " RETURN jsonb_build_object('required',required,'graphs',graphs,'accounts',accounts,'projects',projects,"
 ],
 [
  "DECLARE root_graph jsonb;candidate jsonb;certificate jsonb;output_graph jsonb;carrier jsonb;carrier_scopes jsonb;\n project_graph jsonb; project_graph_sources jsonb:='{}'::jsonb;",
  "DECLARE root_graph jsonb;candidate jsonb;certificate jsonb;output_graph jsonb;carrier jsonb;carrier_scopes jsonb;"
 ]
]$changes$::jsonb),
  ('_authority_resource_binding_certificate_v2(jsonb,jsonb,text,text,text,boolean,jsonb)','f6827385f78036ea744d9d070e155d53b583fc2ef4e3461a3f5052bd6e78a833','ec4d5deaf2df7982eba06a3350b0ae874c7179af6b41912fae3ed4d93e5c9386',$changes$[
 [
  "  IF typ='iam.project' AND (projection->>'present')::boolean THEN\n   ancestry:=kaname._authority_resource_project_graph_v3(p_index,p_catalog,projection);\n   project_graph_sources:=project_graph_sources||(ancestry->'required');\n   required:=required||(projection->'required')||(ancestry->'required');\n   projection:=projection||jsonb_build_object('ancestors','[]'::jsonb,'nested_project',ancestry-'required');\n   work:=work+jsonb_array_length(ancestry->'ancestors');\n  ELSE\n   ancestry:=kaname._authority_resource_ancestor_graph_v2(p_index,p_catalog,projection);\n   required:=required||(projection->'required')||(ancestry->'required');\n   projection:=projection||jsonb_build_object('ancestors',ancestry->'ancestors');\n  END IF;",
  "  ancestry:=kaname._authority_resource_ancestor_graph_v2(p_index,p_catalog,projection);\n  required:=required||(projection->'required')||(ancestry->'required');\n  projection:=projection||jsonb_build_object('ancestors',ancestry->'ancestors');"
 ],
 [
  " RETURN jsonb_build_object('required',required,'coordinates',coordinates,'whole',census->'whole','desired',verified,'work',work,\n  'project_graph_sources',project_graph_sources,",
  " RETURN jsonb_build_object('required',required,'coordinates',coordinates,'whole',census->'whole','desired',verified,'work',work,"
 ],
 [
  " projection jsonb;ancestry jsonb;certificate jsonb;members jsonb;ledger jsonb;\n project_graph_sources jsonb:='{}'::jsonb;",
  " projection jsonb;ancestry jsonb;certificate jsonb;members jsonb;ledger jsonb;"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'object project graph custody predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'object project graph custody splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'object project graph custody body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'object project graph custody function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed object project graph custody function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'object project graph custody custody differs after migration' USING ERRCODE='55000';END IF;
END;
$scope_install$;
-- +goose StatementEnd
DROP FUNCTION kaname._authority_resource_project_graph_v3(jsonb,jsonb,jsonb);
