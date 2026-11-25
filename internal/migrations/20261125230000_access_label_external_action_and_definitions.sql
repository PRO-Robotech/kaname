-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Удерживаем объектный update из каталога и определения изменяемых меток.
-- Требования к каждому ключу сохраняются с точной внешней координатой.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('_authority_metadata_access_label_prefinal_carriers_v1(text,text,text,jsonb,jsonb,integer,integer,integer)','fb40b186a84a3f7303195ae6edb0829043ac43a7c2514bbdf0d1d1b2185027e0','eb3eee9e9760725cb689b3d05808d6f66e65a53c40284e2a8f950aa40d177348',
  $changes$[
 [
  "catalog_state jsonb;target_tables text[];",
  "catalog_state jsonb;verb_state jsonb;target_tables text[];"
 ],
 [
  "ARRAY[table_name,'catalog_resource','accounts','access_bindings','roles','projects']",
  "ARRAY[table_name,'catalog_resource','catalog_verb','accounts','access_bindings','roles','projects']"
 ],
 [
  "IF p_rows<=1 OR p_reads<=2 OR p_work<=1 THEN",
  "IF p_rows<=2 OR p_reads<=3 OR p_work<=2 THEN"
 ],
 [
  "   WHERE c.dotted=root_dotted AND c.live AND c.module<>'iam' FOR SHARE OF c NOWAIT;",
  "   WHERE c.dotted=root_dotted AND c.live AND c.module<>'iam' FOR SHARE OF c NOWAIT;\n   IF catalog_state IS NULL THEN\n    RAISE EXCEPTION 'external metadata live catalog type absent' USING ERRCODE='P1034';END IF;\n   -- Действие удерживается вместе с типом до общих блокировок.\n   LOCK TABLE ONLY kaname.catalog_verb IN ROW SHARE MODE NOWAIT;\n   IF NOT coalesce(has_table_privilege(invoker,'kaname.catalog_verb','SELECT'),false)\n    OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n     WHERE c.oid='kaname.catalog_verb'::regclass AND c.relkind='r' AND c.relpersistence='p'\n     AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND NOT c.relispartition\n     AND NOT c.relhassubclass AND NOT c.relhasrules) THEN\n    RAISE EXCEPTION 'external metadata action catalog privilege or shape differs' USING ERRCODE='42501';END IF;\n   SELECT jsonb_build_array(v.xmin::text,v.ctid::text,to_jsonb(v)) INTO verb_state\n   FROM ONLY kaname.catalog_verb v\n   WHERE v.module=catalog_state#>>'{2,module}' AND v.resource=catalog_state#>>'{2,resource}'\n    AND v.verb='update' AND v.live AND v.per_object FOR SHARE OF v NOWAIT;\n   IF verb_state IS NULL THEN\n    RAISE EXCEPTION 'external metadata object action is not admitted' USING ERRCODE='42501';END IF;"
 ],
 [
  "  IF catalog_state IS NULL THEN\n   RAISE EXCEPTION 'external metadata live catalog type absent' USING ERRCODE='P1034';END IF;\n  prepare_rows:=prepare_rows+1;prepare_reads:=prepare_reads+1;prepare_work:=prepare_work+1;",
  "  prepare_rows:=prepare_rows+2;prepare_reads:=prepare_reads+2;prepare_work:=prepare_work+2;"
 ],
 [
  "  'rows',used_rows,'reads',used_reads,'work',work);",
  "  'rows',used_rows,'reads',used_reads,'work',work)\n  ||CASE WHEN external_root THEN jsonb_build_object('root_update_verb',verb_state) ELSE '{}'::jsonb END;"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_hold_and_replay_v1(jsonb,boolean,integer,integer,integer)','6d037d13ca41c8277dccbe6a79d4105751a8fa2bfb5dc058ed11e81085c0843a','ace3b272dcd98248cde6deffeb01770ea9a815764412eec828c7fdc25535f703',
  $changes$[
 [
  "external_root boolean;catalog_state jsonb;catalog_expected jsonb;",
  "external_root boolean;catalog_state jsonb;catalog_expected jsonb;verb_state jsonb;verb_expected jsonb;"
 ],
 [
  "  catalog_expected:=prepared#>'{root,census,root_scope_states,catalog}';",
  "  catalog_expected:=prepared#>'{root,census,root_scope_states,catalog}';\n  verb_expected:=prepared#>'{root,root_update_verb}';"
 ],
 [
  "   OR coalesce(catalog_expected#>>'{2,object_type}','')=''",
  "   OR coalesce(catalog_expected#>>'{2,object_type}','')=''\n   OR jsonb_typeof(verb_expected) IS DISTINCT FROM 'array'\n   OR verb_expected#>>'{2,verb}' IS DISTINCT FROM 'update'\n   OR verb_expected#>>'{2,live}' IS DISTINCT FROM 'true'\n   OR verb_expected#>>'{2,per_object}' IS DISTINCT FROM 'true'"
 ],
 [
  "registration_work:=2*source_count+2*registration_count+2;",
  "registration_work:=2*source_count+2*registration_count+3;"
 ],
 [
  "p_rows-rows_used<registration_count+1\n   OR p_reads-reads_used<=registration_count+2",
  "p_rows-rows_used<registration_count+2\n   OR p_reads-reads_used<=registration_count+3"
 ],
 [
  "rows_used:=rows_used+registration_count+1;\n  reads_used:=reads_used+registration_count+2;",
  "rows_used:=rows_used+registration_count+2;\n  reads_used:=reads_used+registration_count+3;"
 ],
 [
  "   IF kaname._authority_metadata_registration_binding_holds_v1(registration_count)",
  "   LOCK TABLE ONLY kaname.catalog_verb IN ROW SHARE MODE NOWAIT;\n   IF NOT coalesce(has_table_privilege(invoker,'kaname.catalog_verb','SELECT'),false)\n    OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n     WHERE c.oid='kaname.catalog_verb'::regclass AND c.relkind='r' AND c.relpersistence='p'\n     AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND NOT c.relispartition\n     AND NOT c.relhassubclass AND NOT c.relhasrules) THEN\n    RAISE EXCEPTION 'external metadata held action catalog privilege or shape differs' USING ERRCODE='42501';END IF;\n   SELECT jsonb_build_array(v.xmin::text,v.ctid::text,to_jsonb(v)) INTO verb_state\n   FROM ONLY kaname.catalog_verb v\n   WHERE v.module=catalog_state#>>'{2,module}' AND v.resource=catalog_state#>>'{2,resource}'\n    AND v.verb='update' AND v.live AND v.per_object FOR SHARE OF v NOWAIT;\n   IF verb_state IS DISTINCT FROM verb_expected THEN\n    RAISE EXCEPTION 'external metadata object action changed before replay' USING ERRCODE='40001';END IF;\n   IF kaname._authority_metadata_registration_binding_holds_v1(registration_count)"
 ]
]$changes$::jsonb),
 ('_authority_resource_access_label_requirements_v1(text,jsonb,jsonb,integer,integer)','978758f5cd292059a16258ec393df4768aa3fc5bb0e26fffd5d6b0248e4134db','38c56887f8c63dcd7f16477a4cf33542da9ee3449cf1b41ab9f70496dda873eb',
  $changes$[
 [
  " account_id text;",
  " account_id text;\n project_id text; target_module text:='iam';\n prepared jsonb; scopes jsonb; catalog_row jsonb; external_root boolean;"
 ],
 [
  " IF p_resource IS NULL OR p_resource NOT IN ('account','project','service_account')\n  OR jsonb_typeof(p_old) IS DISTINCT FROM 'object'\n  OR jsonb_typeof(p_new) IS DISTINCT FROM 'object'\n  OR jsonb_typeof(p_old->'id') IS DISTINCT FROM 'string'\n  OR p_old->'id' IS DISTINCT FROM p_new->'id'\n  OR (p_resource IN ('project','service_account') AND (\n   jsonb_typeof(p_old->'account_id') IS DISTINCT FROM 'string'\n   OR p_old->'account_id' IS DISTINCT FROM p_new->'account_id')) THEN\n  RAISE EXCEPTION 'invalid resource access label identity' USING ERRCODE='42501';\n END IF;\n resource_id:=p_old->>'id';\n resource_name:=CASE p_resource WHEN 'service_account' THEN 'serviceAccount' ELSE p_resource END;\n account_id:=CASE WHEN p_resource='account' THEN resource_id ELSE p_old->>'account_id' END;",
  " IF p_resource IS NULL OR jsonb_typeof(p_old) IS DISTINCT FROM 'object'\n  OR jsonb_typeof(p_new) IS DISTINCT FROM 'object' THEN\n  RAISE EXCEPTION 'invalid resource access label identity' USING ERRCODE='42501';END IF;\n external_root:=p_resource NOT IN ('account','project','service_account');\n IF external_root THEN\n  IF p_rows IS NULL OR p_rows<2 OR p_reads IS NULL OR p_reads<3 THEN\n   RAISE EXCEPTION 'external access label definition budget exhausted' USING ERRCODE='54000';END IF;\n  -- Область приходит только из удержанного owner-пакета этой транзакции.\n  prepared:=kaname._authority_metadata_access_label_stashed_v1();\n  scopes:=prepared#>'{root,census,root_scope_states}';\n  catalog_row:=scopes#>'{catalog,2}';\n  target_module:=catalog_row->>'module';\n  resource_name:=catalog_row->>'resource';\n  resource_id:=p_old->>'object_id';\n  account_id:=scopes#>>'{account,2,id}';\n  project_id:=scopes#>>'{project,2,id}';\n  IF coalesce(target_module,'') IN ('','iam') OR coalesce(resource_name,'')=''\n   OR target_module||'.'||resource_name IS DISTINCT FROM p_resource\n   OR catalog_row->>'dotted' IS DISTINCT FROM p_resource OR catalog_row->>'live' IS DISTINCT FROM 'true'\n   OR p_old->>'object_type' IS DISTINCT FROM p_resource OR coalesce(resource_id,'')=''\n   OR prepared#>'{root,root_coordinate}' IS DISTINCT FROM jsonb_build_array(p_resource,resource_id)\n   OR prepared#>'{root,census,old_root}' IS DISTINCT FROM p_old\n   OR prepared#>'{root,census,new_labels}' IS DISTINCT FROM p_new->'access_labels'\n   OR (p_old-ARRAY['labels','access_labels']) IS DISTINCT FROM (p_new-ARRAY['labels','access_labels'])\n   OR nullif(p_old->>'parent_project_id','') IS DISTINCT FROM project_id\n   OR account_id IS DISTINCT FROM prepared#>>'{root,root_account}'\n   OR (project_id IS NOT NULL AND scopes#>>'{project,2,account_id}' IS DISTINCT FROM account_id) THEN\n   RAISE EXCEPTION 'external resource access label scope is not held' USING ERRCODE='42501';END IF;\n  PERFORM kaname._authority_metadata_registration_binding_check_v1(catalog_row->>'object_type',resource_id);\n ELSE\n  IF jsonb_typeof(p_old->'id') IS DISTINCT FROM 'string'\n   OR p_old->'id' IS DISTINCT FROM p_new->'id'\n   OR (p_resource IN ('project','service_account') AND (\n    jsonb_typeof(p_old->'account_id') IS DISTINCT FROM 'string'\n    OR p_old->'account_id' IS DISTINCT FROM p_new->'account_id')) THEN\n   RAISE EXCEPTION 'invalid resource access label identity' USING ERRCODE='42501';END IF;\n  resource_id:=p_old->>'id';\n  account_id:=CASE WHEN p_resource='account' THEN resource_id ELSE p_old->>'account_id' END;\n  project_id:=CASE WHEN p_resource='project' THEN resource_id END;\n  resource_name:=CASE p_resource WHEN 'service_account' THEN 'serviceAccount' ELSE p_resource END;\n END IF;"
 ],
 [
  " IF account_id COLLATE \"C\" !~ '^acc[a-zA-Z0-9_-]{1,61}$'\n  OR (p_resource='project' AND resource_id COLLATE \"C\" !~ '^prj[a-zA-Z0-9_-]{1,61}$')",
  " IF (external_root AND account_id IS NULL) OR account_id COLLATE \"C\" !~ '^acc[a-zA-Z0-9_-]{1,61}$'\n  OR (project_id IS NOT NULL AND project_id COLLATE \"C\" !~ '^prj[a-zA-Z0-9_-]{1,61}$')"
 ],
 [
  " used_reads:=1;",
  " used_reads:=1;\n IF external_root THEN used_rows:=used_rows+2;used_reads:=used_reads+2;END IF;"
 ],
 [
  " LOCK TABLE kaname.authority_access_label_definition IN SHARE MODE;",
  " IF external_root THEN\n  BEGIN\n   LOCK TABLE ONLY kaname.authority_access_label_definition IN SHARE MODE NOWAIT;\n  EXCEPTION WHEN lock_not_available THEN\n   RAISE EXCEPTION 'external access label definition is being changed' USING ERRCODE='40001';\n  END;\n ELSE\n  LOCK TABLE kaname.authority_access_label_definition IN SHARE MODE;\n END IF;"
 ],
 [
  "CASE WHEN p_resource='project' THEN 3 ELSE 2 END",
  "CASE WHEN project_id IS NOT NULL THEN 3 ELSE 2 END"
 ],
 [
  "('project',CASE WHEN p_resource='project' THEN resource_id END))",
  "('project',project_id))"
 ],
 [
  "AND d.module='iam' AND d.resource=resource_name",
  "AND d.module=target_module AND d.resource=resource_name"
 ],
 [
  "kaname.authority_access_label_definition_hold_v1(held.scope_kind,held.scope_id,'iam',\n       resource_name,",
  "kaname.authority_access_label_definition_hold_v1(held.scope_kind,held.scope_id,target_module,\n       resource_name,"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_retention_prepare_v1(jsonb,boolean,integer,integer,integer)','314631d2ffa09e89cf5240cfc47a028f3ac3d73ea07e8394cbae339727e637dc','9aed38b30ad7d502182b60f4614b19b116b46d0f510c4ae1fb58cc2ed60391be',
  $changes$[
 [
  "external_root boolean;session_after jsonb;root_kind integer;root_model text;root_physical jsonb;",
  "external_root boolean;session_after jsonb;root_kind integer;root_model text;root_physical jsonb;\n definitions jsonb;"
 ],
 [
  "  root_physical:=root_physical||jsonb_build_object('object_type',root_type);",
  "  root_physical:=root_physical||jsonb_build_object('object_type',root_type);\n  definitions:=kaname._authority_resource_access_label_requirements_v1(\n   root_type,old_row,new_row,p_rows-used_rows,p_reads-used_reads);\n  IF jsonb_typeof(definitions->'requirements') IS DISTINCT FROM 'array'\n   OR jsonb_array_length(definitions->'requirements') NOT BETWEEN 1 AND 128 THEN\n   RAISE EXCEPTION 'external access label requirements are missing' USING ERRCODE='42501';END IF;\n  used_rows:=used_rows+(definitions->>'rows')::integer;\n  used_reads:=used_reads+(definitions->>'reads')::integer;\n  used_work:=used_work+jsonb_array_length(definitions->'requirements');"
 ],
 [
  "  'old_row',old_row,'new_row',new_row);",
  "  'old_row',old_row,'new_row',new_row)\n  ||CASE WHEN external_root THEN jsonb_build_object('resource_requirements',definitions->'requirements')\n    ELSE '{}'::jsonb END;"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_retention_compile_v1(jsonb,integer)','487d87c466857c875ec06e6c26d27f4c8dd15aef19522d2b11b52cbc6c9043b1','f88d0478318a6cef3fbd861a3717f2b042aa95e159e414b47066a52c5d2dec2d',
  $changes$[
 [
  "  PERFORM kaname._authority_metadata_registration_binding_check_v1(packet->>'root_model',packet->>'root_id');",
  "  PERFORM kaname._authority_metadata_registration_binding_check_v1(packet->>'root_model',packet->>'root_id');\n  IF jsonb_typeof(packet->'resource_requirements') IS DISTINCT FROM 'array'\n   OR jsonb_array_length(packet->'resource_requirements') NOT BETWEEN 1 AND 128 THEN\n   RAISE EXCEPTION 'external retention requires a held definition for each changed key' USING ERRCODE='42501';END IF;"
 ],
 [
  "  'rows',1+receipt_cost,'reads',1+receipt_cost,'work',used_work);",
  "  'rows',1+receipt_cost,'reads',1+receipt_cost,'work',used_work)\n  ||CASE WHEN root_kind=2 THEN jsonb_build_object('resource_requirements',packet->'resource_requirements')\n    ELSE '{}'::jsonb END;"
 ]
]$changes$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','1a797d8c04e211d3e078b22128d2f5018b853a91792f4fa21a37a1679be6945a','e40c32117191982841cdd3197aa9f09889caf673edcb995a9c0896b0e66242d3',
  $changes$[
 [
  "fb40b186a84a3f7303195ae6edb0829043ac43a7c2514bbdf0d1d1b2185027e0",
  "eb3eee9e9760725cb689b3d05808d6f66e65a53c40284e2a8f950aa40d177348"
 ],
 [
  "6d037d13ca41c8277dccbe6a79d4105751a8fa2bfb5dc058ed11e81085c0843a",
  "ace3b272dcd98248cde6deffeb01770ea9a815764412eec828c7fdc25535f703"
 ],
 [
  "314631d2ffa09e89cf5240cfc47a028f3ac3d73ea07e8394cbae339727e637dc",
  "9aed38b30ad7d502182b60f4614b19b116b46d0f510c4ae1fb58cc2ed60391be"
 ],
 [
  "487d87c466857c875ec06e6c26d27f4c8dd15aef19522d2b11b52cbc6c9043b1",
  "f88d0478318a6cef3fbd861a3717f2b042aa95e159e414b47066a52c5d2dec2d"
 ],
 [
  " manifest jsonb:=$manifest$\n[\n",
  " manifest jsonb:=$manifest$\n[\n  {\n    \"signature\": \"_authority_resource_access_label_requirements_v1(text,jsonb,jsonb,integer,integer)\",\n    \"digest\": \"38c56887f8c63dcd7f16477a4cf33542da9ee3449cf1b41ab9f70496dda873eb\",\n    \"definer\": false,\n    \"volatility\": \"v\",\n    \"exported\": false,\n    \"result_type\": \"jsonb\",\n    \"result_set\": false,\n    \"language\": \"plpgsql\",\n    \"argnames\": [\n      \"p_resource\",\n      \"p_old\",\n      \"p_new\",\n      \"p_rows\",\n      \"p_reads\"\n    ],\n    \"argmodes\": null,\n    \"allargtypes\": null\n  },\n"
 ]
]$changes$::jsonb),
 ('authority_metadata_service_account_access_label_ready_v1()','bbee2b2d3b3aaf8dd45fa0ec16a518d032e3360a6fec5a4ddd08fe899e6d55a1','3f15fa266924e9bfd02cd0f7595342ffb1f907b504f57dd474bec10216cb7be1',
  $changes$[
 [
  "fb40b186a84a3f7303195ae6edb0829043ac43a7c2514bbdf0d1d1b2185027e0",
  "eb3eee9e9760725cb689b3d05808d6f66e65a53c40284e2a8f950aa40d177348"
 ],
 [
  "6d037d13ca41c8277dccbe6a79d4105751a8fa2bfb5dc058ed11e81085c0843a",
  "ace3b272dcd98248cde6deffeb01770ea9a815764412eec828c7fdc25535f703"
 ],
 [
  "978758f5cd292059a16258ec393df4768aa3fc5bb0e26fffd5d6b0248e4134db",
  "38c56887f8c63dcd7f16477a4cf33542da9ee3449cf1b41ab9f70496dda873eb"
 ],
 [
  "1a797d8c04e211d3e078b22128d2f5018b853a91792f4fa21a37a1679be6945a",
  "e40c32117191982841cdd3197aa9f09889caf673edcb995a9c0896b0e66242d3"
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
 ('authority_metadata_service_account_access_label_ready_v1()','3f15fa266924e9bfd02cd0f7595342ffb1f907b504f57dd474bec10216cb7be1','bbee2b2d3b3aaf8dd45fa0ec16a518d032e3360a6fec5a4ddd08fe899e6d55a1',
  $changes$[
 [
  "e40c32117191982841cdd3197aa9f09889caf673edcb995a9c0896b0e66242d3",
  "1a797d8c04e211d3e078b22128d2f5018b853a91792f4fa21a37a1679be6945a"
 ],
 [
  "38c56887f8c63dcd7f16477a4cf33542da9ee3449cf1b41ab9f70496dda873eb",
  "978758f5cd292059a16258ec393df4768aa3fc5bb0e26fffd5d6b0248e4134db"
 ],
 [
  "ace3b272dcd98248cde6deffeb01770ea9a815764412eec828c7fdc25535f703",
  "6d037d13ca41c8277dccbe6a79d4105751a8fa2bfb5dc058ed11e81085c0843a"
 ],
 [
  "eb3eee9e9760725cb689b3d05808d6f66e65a53c40284e2a8f950aa40d177348",
  "fb40b186a84a3f7303195ae6edb0829043ac43a7c2514bbdf0d1d1b2185027e0"
 ]
]$changes$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','e40c32117191982841cdd3197aa9f09889caf673edcb995a9c0896b0e66242d3','1a797d8c04e211d3e078b22128d2f5018b853a91792f4fa21a37a1679be6945a',
  $changes$[
 [
  " manifest jsonb:=$manifest$\n[\n  {\n    \"signature\": \"_authority_resource_access_label_requirements_v1(text,jsonb,jsonb,integer,integer)\",\n    \"digest\": \"38c56887f8c63dcd7f16477a4cf33542da9ee3449cf1b41ab9f70496dda873eb\",\n    \"definer\": false,\n    \"volatility\": \"v\",\n    \"exported\": false,\n    \"result_type\": \"jsonb\",\n    \"result_set\": false,\n    \"language\": \"plpgsql\",\n    \"argnames\": [\n      \"p_resource\",\n      \"p_old\",\n      \"p_new\",\n      \"p_rows\",\n      \"p_reads\"\n    ],\n    \"argmodes\": null,\n    \"allargtypes\": null\n  },\n",
  " manifest jsonb:=$manifest$\n[\n"
 ],
 [
  "f88d0478318a6cef3fbd861a3717f2b042aa95e159e414b47066a52c5d2dec2d",
  "487d87c466857c875ec06e6c26d27f4c8dd15aef19522d2b11b52cbc6c9043b1"
 ],
 [
  "9aed38b30ad7d502182b60f4614b19b116b46d0f510c4ae1fb58cc2ed60391be",
  "314631d2ffa09e89cf5240cfc47a028f3ac3d73ea07e8394cbae339727e637dc"
 ],
 [
  "ace3b272dcd98248cde6deffeb01770ea9a815764412eec828c7fdc25535f703",
  "6d037d13ca41c8277dccbe6a79d4105751a8fa2bfb5dc058ed11e81085c0843a"
 ],
 [
  "eb3eee9e9760725cb689b3d05808d6f66e65a53c40284e2a8f950aa40d177348",
  "fb40b186a84a3f7303195ae6edb0829043ac43a7c2514bbdf0d1d1b2185027e0"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_retention_compile_v1(jsonb,integer)','f88d0478318a6cef3fbd861a3717f2b042aa95e159e414b47066a52c5d2dec2d','487d87c466857c875ec06e6c26d27f4c8dd15aef19522d2b11b52cbc6c9043b1',
  $changes$[
 [
  "  'rows',1+receipt_cost,'reads',1+receipt_cost,'work',used_work)\n  ||CASE WHEN root_kind=2 THEN jsonb_build_object('resource_requirements',packet->'resource_requirements')\n    ELSE '{}'::jsonb END;",
  "  'rows',1+receipt_cost,'reads',1+receipt_cost,'work',used_work);"
 ],
 [
  "  PERFORM kaname._authority_metadata_registration_binding_check_v1(packet->>'root_model',packet->>'root_id');\n  IF jsonb_typeof(packet->'resource_requirements') IS DISTINCT FROM 'array'\n   OR jsonb_array_length(packet->'resource_requirements') NOT BETWEEN 1 AND 128 THEN\n   RAISE EXCEPTION 'external retention requires a held definition for each changed key' USING ERRCODE='42501';END IF;",
  "  PERFORM kaname._authority_metadata_registration_binding_check_v1(packet->>'root_model',packet->>'root_id');"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_retention_prepare_v1(jsonb,boolean,integer,integer,integer)','9aed38b30ad7d502182b60f4614b19b116b46d0f510c4ae1fb58cc2ed60391be','314631d2ffa09e89cf5240cfc47a028f3ac3d73ea07e8394cbae339727e637dc',
  $changes$[
 [
  "  'old_row',old_row,'new_row',new_row)\n  ||CASE WHEN external_root THEN jsonb_build_object('resource_requirements',definitions->'requirements')\n    ELSE '{}'::jsonb END;",
  "  'old_row',old_row,'new_row',new_row);"
 ],
 [
  "  root_physical:=root_physical||jsonb_build_object('object_type',root_type);\n  definitions:=kaname._authority_resource_access_label_requirements_v1(\n   root_type,old_row,new_row,p_rows-used_rows,p_reads-used_reads);\n  IF jsonb_typeof(definitions->'requirements') IS DISTINCT FROM 'array'\n   OR jsonb_array_length(definitions->'requirements') NOT BETWEEN 1 AND 128 THEN\n   RAISE EXCEPTION 'external access label requirements are missing' USING ERRCODE='42501';END IF;\n  used_rows:=used_rows+(definitions->>'rows')::integer;\n  used_reads:=used_reads+(definitions->>'reads')::integer;\n  used_work:=used_work+jsonb_array_length(definitions->'requirements');",
  "  root_physical:=root_physical||jsonb_build_object('object_type',root_type);"
 ],
 [
  "external_root boolean;session_after jsonb;root_kind integer;root_model text;root_physical jsonb;\n definitions jsonb;",
  "external_root boolean;session_after jsonb;root_kind integer;root_model text;root_physical jsonb;"
 ]
]$changes$::jsonb),
 ('_authority_resource_access_label_requirements_v1(text,jsonb,jsonb,integer,integer)','38c56887f8c63dcd7f16477a4cf33542da9ee3449cf1b41ab9f70496dda873eb','978758f5cd292059a16258ec393df4768aa3fc5bb0e26fffd5d6b0248e4134db',
  $changes$[
 [
  "kaname.authority_access_label_definition_hold_v1(held.scope_kind,held.scope_id,target_module,\n       resource_name,",
  "kaname.authority_access_label_definition_hold_v1(held.scope_kind,held.scope_id,'iam',\n       resource_name,"
 ],
 [
  "AND d.module=target_module AND d.resource=resource_name",
  "AND d.module='iam' AND d.resource=resource_name"
 ],
 [
  "('project',project_id))",
  "('project',CASE WHEN p_resource='project' THEN resource_id END))"
 ],
 [
  "CASE WHEN project_id IS NOT NULL THEN 3 ELSE 2 END",
  "CASE WHEN p_resource='project' THEN 3 ELSE 2 END"
 ],
 [
  " IF external_root THEN\n  BEGIN\n   LOCK TABLE ONLY kaname.authority_access_label_definition IN SHARE MODE NOWAIT;\n  EXCEPTION WHEN lock_not_available THEN\n   RAISE EXCEPTION 'external access label definition is being changed' USING ERRCODE='40001';\n  END;\n ELSE\n  LOCK TABLE kaname.authority_access_label_definition IN SHARE MODE;\n END IF;",
  " LOCK TABLE kaname.authority_access_label_definition IN SHARE MODE;"
 ],
 [
  " used_reads:=1;\n IF external_root THEN used_rows:=used_rows+2;used_reads:=used_reads+2;END IF;",
  " used_reads:=1;"
 ],
 [
  " IF (external_root AND account_id IS NULL) OR account_id COLLATE \"C\" !~ '^acc[a-zA-Z0-9_-]{1,61}$'\n  OR (project_id IS NOT NULL AND project_id COLLATE \"C\" !~ '^prj[a-zA-Z0-9_-]{1,61}$')",
  " IF account_id COLLATE \"C\" !~ '^acc[a-zA-Z0-9_-]{1,61}$'\n  OR (p_resource='project' AND resource_id COLLATE \"C\" !~ '^prj[a-zA-Z0-9_-]{1,61}$')"
 ],
 [
  " IF p_resource IS NULL OR jsonb_typeof(p_old) IS DISTINCT FROM 'object'\n  OR jsonb_typeof(p_new) IS DISTINCT FROM 'object' THEN\n  RAISE EXCEPTION 'invalid resource access label identity' USING ERRCODE='42501';END IF;\n external_root:=p_resource NOT IN ('account','project','service_account');\n IF external_root THEN\n  IF p_rows IS NULL OR p_rows<2 OR p_reads IS NULL OR p_reads<3 THEN\n   RAISE EXCEPTION 'external access label definition budget exhausted' USING ERRCODE='54000';END IF;\n  -- Область приходит только из удержанного owner-пакета этой транзакции.\n  prepared:=kaname._authority_metadata_access_label_stashed_v1();\n  scopes:=prepared#>'{root,census,root_scope_states}';\n  catalog_row:=scopes#>'{catalog,2}';\n  target_module:=catalog_row->>'module';\n  resource_name:=catalog_row->>'resource';\n  resource_id:=p_old->>'object_id';\n  account_id:=scopes#>>'{account,2,id}';\n  project_id:=scopes#>>'{project,2,id}';\n  IF coalesce(target_module,'') IN ('','iam') OR coalesce(resource_name,'')=''\n   OR target_module||'.'||resource_name IS DISTINCT FROM p_resource\n   OR catalog_row->>'dotted' IS DISTINCT FROM p_resource OR catalog_row->>'live' IS DISTINCT FROM 'true'\n   OR p_old->>'object_type' IS DISTINCT FROM p_resource OR coalesce(resource_id,'')=''\n   OR prepared#>'{root,root_coordinate}' IS DISTINCT FROM jsonb_build_array(p_resource,resource_id)\n   OR prepared#>'{root,census,old_root}' IS DISTINCT FROM p_old\n   OR prepared#>'{root,census,new_labels}' IS DISTINCT FROM p_new->'access_labels'\n   OR (p_old-ARRAY['labels','access_labels']) IS DISTINCT FROM (p_new-ARRAY['labels','access_labels'])\n   OR nullif(p_old->>'parent_project_id','') IS DISTINCT FROM project_id\n   OR account_id IS DISTINCT FROM prepared#>>'{root,root_account}'\n   OR (project_id IS NOT NULL AND scopes#>>'{project,2,account_id}' IS DISTINCT FROM account_id) THEN\n   RAISE EXCEPTION 'external resource access label scope is not held' USING ERRCODE='42501';END IF;\n  PERFORM kaname._authority_metadata_registration_binding_check_v1(catalog_row->>'object_type',resource_id);\n ELSE\n  IF jsonb_typeof(p_old->'id') IS DISTINCT FROM 'string'\n   OR p_old->'id' IS DISTINCT FROM p_new->'id'\n   OR (p_resource IN ('project','service_account') AND (\n    jsonb_typeof(p_old->'account_id') IS DISTINCT FROM 'string'\n    OR p_old->'account_id' IS DISTINCT FROM p_new->'account_id')) THEN\n   RAISE EXCEPTION 'invalid resource access label identity' USING ERRCODE='42501';END IF;\n  resource_id:=p_old->>'id';\n  account_id:=CASE WHEN p_resource='account' THEN resource_id ELSE p_old->>'account_id' END;\n  project_id:=CASE WHEN p_resource='project' THEN resource_id END;\n  resource_name:=CASE p_resource WHEN 'service_account' THEN 'serviceAccount' ELSE p_resource END;\n END IF;",
  " IF p_resource IS NULL OR p_resource NOT IN ('account','project','service_account')\n  OR jsonb_typeof(p_old) IS DISTINCT FROM 'object'\n  OR jsonb_typeof(p_new) IS DISTINCT FROM 'object'\n  OR jsonb_typeof(p_old->'id') IS DISTINCT FROM 'string'\n  OR p_old->'id' IS DISTINCT FROM p_new->'id'\n  OR (p_resource IN ('project','service_account') AND (\n   jsonb_typeof(p_old->'account_id') IS DISTINCT FROM 'string'\n   OR p_old->'account_id' IS DISTINCT FROM p_new->'account_id')) THEN\n  RAISE EXCEPTION 'invalid resource access label identity' USING ERRCODE='42501';\n END IF;\n resource_id:=p_old->>'id';\n resource_name:=CASE p_resource WHEN 'service_account' THEN 'serviceAccount' ELSE p_resource END;\n account_id:=CASE WHEN p_resource='account' THEN resource_id ELSE p_old->>'account_id' END;"
 ],
 [
  " account_id text;\n project_id text; target_module text:='iam';\n prepared jsonb; scopes jsonb; catalog_row jsonb; external_root boolean;",
  " account_id text;"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_hold_and_replay_v1(jsonb,boolean,integer,integer,integer)','ace3b272dcd98248cde6deffeb01770ea9a815764412eec828c7fdc25535f703','6d037d13ca41c8277dccbe6a79d4105751a8fa2bfb5dc058ed11e81085c0843a',
  $changes$[
 [
  "   LOCK TABLE ONLY kaname.catalog_verb IN ROW SHARE MODE NOWAIT;\n   IF NOT coalesce(has_table_privilege(invoker,'kaname.catalog_verb','SELECT'),false)\n    OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n     WHERE c.oid='kaname.catalog_verb'::regclass AND c.relkind='r' AND c.relpersistence='p'\n     AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND NOT c.relispartition\n     AND NOT c.relhassubclass AND NOT c.relhasrules) THEN\n    RAISE EXCEPTION 'external metadata held action catalog privilege or shape differs' USING ERRCODE='42501';END IF;\n   SELECT jsonb_build_array(v.xmin::text,v.ctid::text,to_jsonb(v)) INTO verb_state\n   FROM ONLY kaname.catalog_verb v\n   WHERE v.module=catalog_state#>>'{2,module}' AND v.resource=catalog_state#>>'{2,resource}'\n    AND v.verb='update' AND v.live AND v.per_object FOR SHARE OF v NOWAIT;\n   IF verb_state IS DISTINCT FROM verb_expected THEN\n    RAISE EXCEPTION 'external metadata object action changed before replay' USING ERRCODE='40001';END IF;\n   IF kaname._authority_metadata_registration_binding_holds_v1(registration_count)",
  "   IF kaname._authority_metadata_registration_binding_holds_v1(registration_count)"
 ],
 [
  "rows_used:=rows_used+registration_count+2;\n  reads_used:=reads_used+registration_count+3;",
  "rows_used:=rows_used+registration_count+1;\n  reads_used:=reads_used+registration_count+2;"
 ],
 [
  "p_rows-rows_used<registration_count+2\n   OR p_reads-reads_used<=registration_count+3",
  "p_rows-rows_used<registration_count+1\n   OR p_reads-reads_used<=registration_count+2"
 ],
 [
  "registration_work:=2*source_count+2*registration_count+3;",
  "registration_work:=2*source_count+2*registration_count+2;"
 ],
 [
  "   OR coalesce(catalog_expected#>>'{2,object_type}','')=''\n   OR jsonb_typeof(verb_expected) IS DISTINCT FROM 'array'\n   OR verb_expected#>>'{2,verb}' IS DISTINCT FROM 'update'\n   OR verb_expected#>>'{2,live}' IS DISTINCT FROM 'true'\n   OR verb_expected#>>'{2,per_object}' IS DISTINCT FROM 'true'",
  "   OR coalesce(catalog_expected#>>'{2,object_type}','')=''"
 ],
 [
  "  catalog_expected:=prepared#>'{root,census,root_scope_states,catalog}';\n  verb_expected:=prepared#>'{root,root_update_verb}';",
  "  catalog_expected:=prepared#>'{root,census,root_scope_states,catalog}';"
 ],
 [
  "external_root boolean;catalog_state jsonb;catalog_expected jsonb;verb_state jsonb;verb_expected jsonb;",
  "external_root boolean;catalog_state jsonb;catalog_expected jsonb;"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_prefinal_carriers_v1(text,text,text,jsonb,jsonb,integer,integer,integer)','eb3eee9e9760725cb689b3d05808d6f66e65a53c40284e2a8f950aa40d177348','fb40b186a84a3f7303195ae6edb0829043ac43a7c2514bbdf0d1d1b2185027e0',
  $changes$[
 [
  "  'rows',used_rows,'reads',used_reads,'work',work)\n  ||CASE WHEN external_root THEN jsonb_build_object('root_update_verb',verb_state) ELSE '{}'::jsonb END;",
  "  'rows',used_rows,'reads',used_reads,'work',work);"
 ],
 [
  "  prepare_rows:=prepare_rows+2;prepare_reads:=prepare_reads+2;prepare_work:=prepare_work+2;",
  "  IF catalog_state IS NULL THEN\n   RAISE EXCEPTION 'external metadata live catalog type absent' USING ERRCODE='P1034';END IF;\n  prepare_rows:=prepare_rows+1;prepare_reads:=prepare_reads+1;prepare_work:=prepare_work+1;"
 ],
 [
  "   WHERE c.dotted=root_dotted AND c.live AND c.module<>'iam' FOR SHARE OF c NOWAIT;\n   IF catalog_state IS NULL THEN\n    RAISE EXCEPTION 'external metadata live catalog type absent' USING ERRCODE='P1034';END IF;\n   -- Действие удерживается вместе с типом до общих блокировок.\n   LOCK TABLE ONLY kaname.catalog_verb IN ROW SHARE MODE NOWAIT;\n   IF NOT coalesce(has_table_privilege(invoker,'kaname.catalog_verb','SELECT'),false)\n    OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n     WHERE c.oid='kaname.catalog_verb'::regclass AND c.relkind='r' AND c.relpersistence='p'\n     AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND NOT c.relispartition\n     AND NOT c.relhassubclass AND NOT c.relhasrules) THEN\n    RAISE EXCEPTION 'external metadata action catalog privilege or shape differs' USING ERRCODE='42501';END IF;\n   SELECT jsonb_build_array(v.xmin::text,v.ctid::text,to_jsonb(v)) INTO verb_state\n   FROM ONLY kaname.catalog_verb v\n   WHERE v.module=catalog_state#>>'{2,module}' AND v.resource=catalog_state#>>'{2,resource}'\n    AND v.verb='update' AND v.live AND v.per_object FOR SHARE OF v NOWAIT;\n   IF verb_state IS NULL THEN\n    RAISE EXCEPTION 'external metadata object action is not admitted' USING ERRCODE='42501';END IF;",
  "   WHERE c.dotted=root_dotted AND c.live AND c.module<>'iam' FOR SHARE OF c NOWAIT;"
 ],
 [
  "IF p_rows<=2 OR p_reads<=3 OR p_work<=2 THEN",
  "IF p_rows<=1 OR p_reads<=2 OR p_work<=1 THEN"
 ],
 [
  "ARRAY[table_name,'catalog_resource','catalog_verb','accounts','access_bindings','roles','projects']",
  "ARRAY[table_name,'catalog_resource','accounts','access_bindings','roles','projects']"
 ],
 [
  "catalog_state jsonb;verb_state jsonb;target_tables text[];",
  "catalog_state jsonb;target_tables text[];"
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
