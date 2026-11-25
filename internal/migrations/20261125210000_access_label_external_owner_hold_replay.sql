-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Повторная сверка внешнего корня после точных блокировок регистрации и зеркала.
-- Открывающий запись обработчик и изменение схемы прав здесь не добавляются.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('_authority_metadata_access_label_early_closure_v1(jsonb,jsonb,integer,integer,integer)','01ef36668b4499a8d9384c6887fab29393ce1cac455f307c68710c2e9e3bb479','037bb846b0aece534088339e9a7cd5d4c17ce4ce7b56a9d9f1bac8de4d0b82ee',
  $changes$[
 [
  "  source_key:=jsonb_build_array(5,root_model,root_id,'')::text;",
  "\n  source_key:=jsonb_build_array(4,root_model,root_id,'')::text;\n  IF jsonb_typeof(idx->source_key->'states') IS DISTINCT FROM 'array' THEN\n   RAISE EXCEPTION 'external metadata registration scope witness absent' USING ERRCODE='P1034';END IF;\n  IF EXISTS(SELECT 1 FROM jsonb_array_elements(idx->source_key->'states') s\n   WHERE s#>>'{2,account_id}' IS DISTINCT FROM p_packet->>'root_account'\n    OR s#>>'{2,project_id}' IS DISTINCT FROM coalesce(root_project,'')) THEN\n   RAISE EXCEPTION 'external metadata registration scope differs from owning scope' USING ERRCODE='P1034';END IF;\n  source_key:=jsonb_build_array(5,root_model,root_id,'')::text;"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_hold_and_replay_v1(jsonb,boolean,integer,integer,integer)','790f98119e777889a0b92abf51fe480875da4e504e9853a763627048aba0da6c','6d037d13ca41c8277dccbe6a79d4105751a8fa2bfb5dc058ed11e81085c0843a',
  $changes$[
 [
  " rows_used integer:=2;",
  " external_root boolean;catalog_state jsonb;catalog_expected jsonb;\n registration_count integer;source_count integer;registration_work integer:=0;\n rows_used integer:=2;"
 ],
 [
  " IF table_name IS NULL OR coalesce(resource_id,'')='' OR coalesce(root_account,'')=''",
  " external_root:=table_name IS NULL;\n IF external_root THEN\n  catalog_expected:=prepared#>'{root,census,root_scope_states,catalog}';\n  IF catalog_expected#>>'{2,dotted}' IS DISTINCT FROM root_coordinate->>0\n   OR catalog_expected#>>'{2,live}' IS DISTINCT FROM 'true'\n   OR coalesce(catalog_expected#>>'{2,module}','') IN ('','iam')\n   OR coalesce(catalog_expected#>>'{2,object_type}','')=''\n   OR prepared#>'{root,census,root_scope_states,root}' IS DISTINCT FROM old_state THEN\n   RAISE EXCEPTION 'metadata external root catalog or state missing' USING ERRCODE='42501';END IF;\n  table_name:='resource_mirror';\n END IF;\n IF table_name IS NULL OR coalesce(resource_id,'')='' OR coalesce(root_account,'')=''"
 ],
 [
  "  OR old_state#>>'{2,id}' IS DISTINCT FROM resource_id",
  "  OR (NOT external_root AND old_state#>>'{2,id}' IS DISTINCT FROM resource_id)\n  OR (external_root AND (old_state#>>'{2,object_type}' IS DISTINCT FROM root_coordinate->>0\n   OR old_state#>>'{2,object_id}' IS DISTINCT FROM resource_id\n   OR p_patch-ARRAY['labels','access_labels']<>'{}'::jsonb\n   OR p_rename IS DISTINCT FROM false))"
 ],
 [
  " FOREACH field_name IN ARRAY ARRAY['name','description','labels','access_labels'] LOOP",
  " FOREACH field_name IN ARRAY CASE WHEN NOT external_root THEN ARRAY['name','description','labels','access_labels']\n  WHEN p_patch ? 'labels' THEN ARRAY['labels','access_labels'] ELSE ARRAY['access_labels'] END LOOP"
 ],
 [
  " IF p_rename AND table_name='accounts' THEN\n  LOCK TABLE kaname.accounts IN SHARE ROW EXCLUSIVE MODE;\n ELSE\n  EXECUTE format('LOCK TABLE kaname.%I IN ROW EXCLUSIVE MODE',table_name);\n END IF;\n LOCK TABLE kaname.authority_binding_epoch IN ROW EXCLUSIVE MODE;\n physical_state:=kaname._authority_metadata_root_state_v1(root_coordinate->>0,resource_id,true);\n IF physical_state IS DISTINCT FROM old_state THEN\n  RAISE EXCEPTION 'metadata root changed during physical wait' USING ERRCODE='40001';END IF;",
  " IF NOT external_root THEN\n  IF p_rename AND table_name='accounts' THEN\n   LOCK TABLE kaname.accounts IN SHARE ROW EXCLUSIVE MODE;\n  ELSE\n   EXECUTE format('LOCK TABLE kaname.%I IN ROW EXCLUSIVE MODE',table_name);\n  END IF;\n  LOCK TABLE kaname.authority_binding_epoch IN ROW EXCLUSIVE MODE;\n  physical_state:=kaname._authority_metadata_root_state_v1(root_coordinate->>0,resource_id,true);\n  IF physical_state IS DISTINCT FROM old_state THEN\n   RAISE EXCEPTION 'metadata root changed during physical wait' USING ERRCODE='40001';END IF;\n ELSE\n  -- Строки эпох политики уже удержаны первым protectPolicyPlan.\n  LOCK TABLE ONLY kaname.authority_binding_epoch IN ROW EXCLUSIVE MODE NOWAIT;\n END IF;"
 ],
 [
  "  IF scope_record.value='write' THEN\n   SELECT e.scope INTO locked_scope FROM ONLY kaname.authority_binding_epoch e\n   WHERE e.scope=scope_record.key FOR UPDATE OF e;\n  ELSIF scope_record.value='share' THEN\n   SELECT e.scope INTO locked_scope FROM ONLY kaname.authority_binding_epoch e\n   WHERE e.scope=scope_record.key FOR SHARE OF e;\n  ELSE\n   RAISE EXCEPTION 'metadata binding epoch lock mode differs' USING ERRCODE='42501';\n  END IF;",
  "  IF external_root THEN\n   BEGIN\n    IF scope_record.value='write' THEN\n     SELECT e.scope INTO locked_scope FROM ONLY kaname.authority_binding_epoch e\n     WHERE e.scope=scope_record.key FOR UPDATE OF e NOWAIT;\n    ELSIF scope_record.value='share' THEN\n     SELECT e.scope INTO locked_scope FROM ONLY kaname.authority_binding_epoch e\n     WHERE e.scope=scope_record.key FOR SHARE OF e NOWAIT;\n    ELSE\n     RAISE EXCEPTION 'metadata binding epoch lock mode differs' USING ERRCODE='42501';\n    END IF;\n   EXCEPTION WHEN lock_not_available THEN\n    RAISE EXCEPTION 'external metadata binding epoch row conflict' USING ERRCODE='40001';\n   END;\n  ELSIF scope_record.value='write' THEN\n   SELECT e.scope INTO locked_scope FROM ONLY kaname.authority_binding_epoch e\n   WHERE e.scope=scope_record.key FOR UPDATE OF e;\n  ELSIF scope_record.value='share' THEN\n   SELECT e.scope INTO locked_scope FROM ONLY kaname.authority_binding_epoch e\n   WHERE e.scope=scope_record.key FOR SHARE OF e;\n  ELSE\n   RAISE EXCEPTION 'metadata binding epoch lock mode differs' USING ERRCODE='42501';\n  END IF;"
 ],
 [
  " frontier_witnesses:=prepared#>'{discovery,frontier,witnesses}';",
  "\n IF external_root THEN\n  SELECT count(*)::integer,count(*) FILTER (WHERE kind='5') INTO source_count,registration_count FROM (\n   SELECT e.value#>>'{source,kind}' AS kind FROM jsonb_each(prepared#>'{discovery,source_index}') e LIMIT 4097\n  ) bounded;\n  IF registration_count=0 THEN\n   RAISE EXCEPTION 'external metadata registration key set absent' USING ERRCODE='42501';END IF;\n  registration_work:=2*source_count+2*registration_count+2;\n  IF source_count>4096 OR p_rows-rows_used<registration_count+1\n   OR p_reads-reads_used<=registration_count+2 OR p_work<=registration_work THEN\n   RAISE EXCEPTION 'external metadata registration hold budget exhausted' USING ERRCODE='54000';END IF;\n  -- Чтения и строки для первого удержания учитываются отдельно от replay.\n  rows_used:=rows_used+registration_count+1;\n  reads_used:=reads_used+registration_count+2;\n  BEGIN\n   -- Каталожный тип брали до общих ключей. Теперь вновь подтверждаем ту же\n   -- версию без ожидания, затем удерживаем привязку и только потом зеркало.\n   LOCK TABLE ONLY kaname.catalog_resource IN ROW SHARE MODE NOWAIT;\n   IF NOT coalesce(has_table_privilege(invoker,'kaname.catalog_resource','SELECT'),false)\n    OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n     WHERE c.oid='kaname.catalog_resource'::regclass AND c.relkind='r' AND c.relpersistence='p'\n     AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND NOT c.relispartition\n     AND NOT c.relhassubclass AND NOT c.relhasrules) THEN\n    RAISE EXCEPTION 'external metadata catalog privilege or shape differs' USING ERRCODE='42501';END IF;\n   SELECT jsonb_build_array(c.xmin::text,c.ctid::text,to_jsonb(c)) INTO catalog_state\n   FROM ONLY kaname.catalog_resource c\n   WHERE c.dotted=root_coordinate->>0 AND c.live AND c.module<>'iam' FOR SHARE OF c NOWAIT;\n   IF catalog_state IS DISTINCT FROM catalog_expected THEN\n    RAISE EXCEPTION 'external metadata catalog changed before replay' USING ERRCODE='40001';END IF;\n   IF kaname._authority_metadata_registration_binding_holds_v1(registration_count) IS DISTINCT FROM registration_count THEN\n    RAISE EXCEPTION 'external metadata registration key count differs' USING ERRCODE='42501';END IF;\n   LOCK TABLE ONLY kaname.resource_mirror IN ROW EXCLUSIVE MODE NOWAIT;\n   IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n    WHERE c.oid=relation_id AND c.oid='kaname.resource_mirror'::regclass AND c.relkind='r' AND c.relpersistence='p'\n     AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND NOT c.relispartition\n     AND NOT c.relhassubclass AND NOT c.relhasrules) THEN\n    RAISE EXCEPTION 'external metadata mirror shape differs' USING ERRCODE='42501';END IF;\n   SELECT jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) INTO physical_state\n   FROM ONLY kaname.resource_mirror m\n   WHERE m.object_type=root_coordinate->>0 AND m.object_id=resource_id FOR UPDATE OF m NOWAIT;\n   IF physical_state IS DISTINCT FROM old_state THEN\n    RAISE EXCEPTION 'external metadata root changed before replay' USING ERRCODE='40001';END IF;\n  EXCEPTION WHEN lock_not_available THEN\n   RAISE EXCEPTION 'external metadata registration or mirror lock conflict' USING ERRCODE='40001';\n  END;\n END IF;\n\n frontier_witnesses:=prepared#>'{discovery,frontier,witnesses}';"
 ],
 [
  " SELECT count(*)::integer INTO work_used FROM jsonb_object_keys(frontier_witnesses);",
  " SELECT registration_work+count(*)::integer INTO work_used FROM jsonb_object_keys(frontier_witnesses);"
 ],
 [
  "  'root_physical',jsonb_build_object('table',table_name,'id',resource_id,'xmin',physical_state->>0,'ctid',physical_state->>1),",
  "  'root_physical',jsonb_build_object('table',table_name,'id',resource_id,'xmin',physical_state->>0,'ctid',physical_state->>1)\n   ||CASE WHEN external_root THEN jsonb_build_object('object_type',root_coordinate->>0) ELSE '{}'::jsonb END,"
 ],
 [
  "  LOCK TABLE ONLY kaname.authority_binding_epoch IN ROW EXCLUSIVE MODE NOWAIT;",
  "  BEGIN\n   LOCK TABLE ONLY kaname.authority_binding_epoch IN ROW EXCLUSIVE MODE NOWAIT;\n  EXCEPTION WHEN lock_not_available THEN\n   RAISE EXCEPTION 'external metadata binding epoch relation conflict' USING ERRCODE='40001';\n  END;"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_held_replay_v1(jsonb,jsonb,jsonb,integer,integer,integer)','711c129d2eb1f9e60d9cefc2136a58b9487e3926649f47ed85087fa423e34f31','586423c5c0965e9cf8ab408894127527eb66edbfc1a454a0a056e9fb064a4749',
  $changes$[
 [
  " needs_global boolean:=false;",
  " external_root boolean;root_source_kind integer;root_catalog jsonb;root_model text;census_tables text[];\n needs_global boolean:=false;"
 ],
 [
  " IF jsonb_typeof(expected_census) IS DISTINCT FROM 'object'",
  "\n external_root:=root_type NOT IN ('iam.account','iam.project','iam.serviceAccount');\n root_source_kind:=CASE WHEN external_root THEN 2 ELSE 30 END;\n IF external_root THEN\n  root_catalog:=expected_census#>'{root_scope_states,catalog,2}';\n  root_model:=root_catalog->>'object_type';\n  IF root_catalog->>'dotted' IS DISTINCT FROM root_type\n   OR root_catalog->>'live' IS DISTINCT FROM 'true'\n   OR coalesce(root_catalog->>'module','') IN ('','iam')\n   OR coalesce(root_model,'') !~ '^[a-z][a-z0-9_]*$'\n   OR expected_census#>'{root_scope_states,root}' IS DISTINCT FROM p_packet->'root_state' THEN\n   RAISE EXCEPTION 'metadata external held root scope invalid' USING ERRCODE='42501';END IF;\n END IF;\n IF jsonb_typeof(expected_census) IS DISTINCT FROM 'object'"
 ],
 [
  "  OR coalesce(root_type,'') NOT IN ('iam.account','iam.project','iam.serviceAccount') OR coalesce(root_id,'')=''",
  "  OR coalesce(root_type,'')='' OR coalesce(root_id,'')=''"
 ],
 [
  "  OR expected_census->>'root_id' IS DISTINCT FROM p_packet#>>'{root_state,2,id}'",
  "  OR (NOT external_root AND root_id IS DISTINCT FROM p_packet#>>'{root_state,2,id}')\n  OR (external_root AND (root_id IS DISTINCT FROM p_packet#>>'{root_state,2,object_id}'\n   OR root_type IS DISTINCT FROM p_packet#>>'{root_state,2,object_type}'))"
 ],
 [
  "  IF source_kind NOT IN (1,2,3,4,6,8,9,10,11,12,13,14,15,21,22,23,25,26,27,28,30,31,35,36,37)",
  "  IF source_kind NOT IN (1,2,3,4,5,6,8,9,10,11,12,13,14,15,21,22,23,25,26,27,28,30,31,35,36,37)\n   OR (source_kind=5 AND (NOT external_root OR source->>'type' !~ '^[a-z][a-z0-9_]*$'\n    OR jsonb_array_length(expected_entry->'states')>1))"
 ],
 [
  "jsonb_build_array(30,root_type,root_id,'')",
  "jsonb_build_array(root_source_kind,root_type,root_id,'')"
 ],
 [
  " FOR entry IN SELECT e.key,e.value FROM jsonb_each(p_closure#>'{frontier,source_index}') e LOOP",
  "\n IF external_root AND NOT (p_closure->'source_index') ? jsonb_build_array(5,root_model,root_id,'')::text THEN\n  RAISE EXCEPTION 'metadata held registration binding witness absent' USING ERRCODE='42501';END IF;\n FOR entry IN SELECT e.key,e.value FROM jsonb_each(p_closure#>'{frontier,source_index}') e LOOP"
 ],
 [
  " FOREACH field_name IN ARRAY ARRAY['access_bindings','roles','projects'] LOOP",
  " census_tables:=ARRAY['access_bindings','roles','projects'];\n IF external_root THEN census_tables:=census_tables||ARRAY['resource_mirror','catalog_resource','accounts'];END IF;\n FOREACH field_name IN ARRAY census_tables LOOP"
 ]
]$changes$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','8eb750b502dadc4295a50cc5fdde4e63c9224e6454c4e340be074c7a5f94544a','7eb9e29bfec2e5c9fc457bf0818b2489f7d0faaa25838f74324bc4e04608432a',
  $changes$[
 [
  "01ef36668b4499a8d9384c6887fab29393ce1cac455f307c68710c2e9e3bb479",
  "037bb846b0aece534088339e9a7cd5d4c17ce4ce7b56a9d9f1bac8de4d0b82ee"
 ],
 [
  "790f98119e777889a0b92abf51fe480875da4e504e9853a763627048aba0da6c",
  "6d037d13ca41c8277dccbe6a79d4105751a8fa2bfb5dc058ed11e81085c0843a"
 ],
 [
  "711c129d2eb1f9e60d9cefc2136a58b9487e3926649f47ed85087fa423e34f31",
  "586423c5c0965e9cf8ab408894127527eb66edbfc1a454a0a056e9fb064a4749"
 ]
]$changes$::jsonb),
 ('authority_metadata_service_account_access_label_ready_v1()','43aed234949d072a3d7d26e01b45eb2ea5f244c832f92da78b6a217315a37d75','d52e5eaea50e84d85a750ac5f81c0162cf5e50f186be99b673f6c940e7e470ca',
  $changes$[
 [
  "01ef36668b4499a8d9384c6887fab29393ce1cac455f307c68710c2e9e3bb479",
  "037bb846b0aece534088339e9a7cd5d4c17ce4ce7b56a9d9f1bac8de4d0b82ee"
 ],
 [
  "790f98119e777889a0b92abf51fe480875da4e504e9853a763627048aba0da6c",
  "6d037d13ca41c8277dccbe6a79d4105751a8fa2bfb5dc058ed11e81085c0843a"
 ],
 [
  "711c129d2eb1f9e60d9cefc2136a58b9487e3926649f47ed85087fa423e34f31",
  "586423c5c0965e9cf8ab408894127527eb66edbfc1a454a0a056e9fb064a4749"
 ],
 [
  "8eb750b502dadc4295a50cc5fdde4e63c9224e6454c4e340be074c7a5f94544a",
  "7eb9e29bfec2e5c9fc457bf0818b2489f7d0faaa25838f74324bc4e04608432a"
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
 ('authority_metadata_service_account_access_label_ready_v1()','d52e5eaea50e84d85a750ac5f81c0162cf5e50f186be99b673f6c940e7e470ca','43aed234949d072a3d7d26e01b45eb2ea5f244c832f92da78b6a217315a37d75',
  $changes$[
 [
  "7eb9e29bfec2e5c9fc457bf0818b2489f7d0faaa25838f74324bc4e04608432a",
  "8eb750b502dadc4295a50cc5fdde4e63c9224e6454c4e340be074c7a5f94544a"
 ],
 [
  "586423c5c0965e9cf8ab408894127527eb66edbfc1a454a0a056e9fb064a4749",
  "711c129d2eb1f9e60d9cefc2136a58b9487e3926649f47ed85087fa423e34f31"
 ],
 [
  "6d037d13ca41c8277dccbe6a79d4105751a8fa2bfb5dc058ed11e81085c0843a",
  "790f98119e777889a0b92abf51fe480875da4e504e9853a763627048aba0da6c"
 ],
 [
  "037bb846b0aece534088339e9a7cd5d4c17ce4ce7b56a9d9f1bac8de4d0b82ee",
  "01ef36668b4499a8d9384c6887fab29393ce1cac455f307c68710c2e9e3bb479"
 ]
]$changes$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','7eb9e29bfec2e5c9fc457bf0818b2489f7d0faaa25838f74324bc4e04608432a','8eb750b502dadc4295a50cc5fdde4e63c9224e6454c4e340be074c7a5f94544a',
  $changes$[
 [
  "586423c5c0965e9cf8ab408894127527eb66edbfc1a454a0a056e9fb064a4749",
  "711c129d2eb1f9e60d9cefc2136a58b9487e3926649f47ed85087fa423e34f31"
 ],
 [
  "6d037d13ca41c8277dccbe6a79d4105751a8fa2bfb5dc058ed11e81085c0843a",
  "790f98119e777889a0b92abf51fe480875da4e504e9853a763627048aba0da6c"
 ],
 [
  "037bb846b0aece534088339e9a7cd5d4c17ce4ce7b56a9d9f1bac8de4d0b82ee",
  "01ef36668b4499a8d9384c6887fab29393ce1cac455f307c68710c2e9e3bb479"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_held_replay_v1(jsonb,jsonb,jsonb,integer,integer,integer)','586423c5c0965e9cf8ab408894127527eb66edbfc1a454a0a056e9fb064a4749','711c129d2eb1f9e60d9cefc2136a58b9487e3926649f47ed85087fa423e34f31',
  $changes$[
 [
  " census_tables:=ARRAY['access_bindings','roles','projects'];\n IF external_root THEN census_tables:=census_tables||ARRAY['resource_mirror','catalog_resource','accounts'];END IF;\n FOREACH field_name IN ARRAY census_tables LOOP",
  " FOREACH field_name IN ARRAY ARRAY['access_bindings','roles','projects'] LOOP"
 ],
 [
  "\n IF external_root AND NOT (p_closure->'source_index') ? jsonb_build_array(5,root_model,root_id,'')::text THEN\n  RAISE EXCEPTION 'metadata held registration binding witness absent' USING ERRCODE='42501';END IF;\n FOR entry IN SELECT e.key,e.value FROM jsonb_each(p_closure#>'{frontier,source_index}') e LOOP",
  " FOR entry IN SELECT e.key,e.value FROM jsonb_each(p_closure#>'{frontier,source_index}') e LOOP"
 ],
 [
  "jsonb_build_array(root_source_kind,root_type,root_id,'')",
  "jsonb_build_array(30,root_type,root_id,'')"
 ],
 [
  "  IF source_kind NOT IN (1,2,3,4,5,6,8,9,10,11,12,13,14,15,21,22,23,25,26,27,28,30,31,35,36,37)\n   OR (source_kind=5 AND (NOT external_root OR source->>'type' !~ '^[a-z][a-z0-9_]*$'\n    OR jsonb_array_length(expected_entry->'states')>1))",
  "  IF source_kind NOT IN (1,2,3,4,6,8,9,10,11,12,13,14,15,21,22,23,25,26,27,28,30,31,35,36,37)"
 ],
 [
  "  OR (NOT external_root AND root_id IS DISTINCT FROM p_packet#>>'{root_state,2,id}')\n  OR (external_root AND (root_id IS DISTINCT FROM p_packet#>>'{root_state,2,object_id}'\n   OR root_type IS DISTINCT FROM p_packet#>>'{root_state,2,object_type}'))",
  "  OR expected_census->>'root_id' IS DISTINCT FROM p_packet#>>'{root_state,2,id}'"
 ],
 [
  "  OR coalesce(root_type,'')='' OR coalesce(root_id,'')=''",
  "  OR coalesce(root_type,'') NOT IN ('iam.account','iam.project','iam.serviceAccount') OR coalesce(root_id,'')=''"
 ],
 [
  "\n external_root:=root_type NOT IN ('iam.account','iam.project','iam.serviceAccount');\n root_source_kind:=CASE WHEN external_root THEN 2 ELSE 30 END;\n IF external_root THEN\n  root_catalog:=expected_census#>'{root_scope_states,catalog,2}';\n  root_model:=root_catalog->>'object_type';\n  IF root_catalog->>'dotted' IS DISTINCT FROM root_type\n   OR root_catalog->>'live' IS DISTINCT FROM 'true'\n   OR coalesce(root_catalog->>'module','') IN ('','iam')\n   OR coalesce(root_model,'') !~ '^[a-z][a-z0-9_]*$'\n   OR expected_census#>'{root_scope_states,root}' IS DISTINCT FROM p_packet->'root_state' THEN\n   RAISE EXCEPTION 'metadata external held root scope invalid' USING ERRCODE='42501';END IF;\n END IF;\n IF jsonb_typeof(expected_census) IS DISTINCT FROM 'object'",
  " IF jsonb_typeof(expected_census) IS DISTINCT FROM 'object'"
 ],
 [
  " external_root boolean;root_source_kind integer;root_catalog jsonb;root_model text;census_tables text[];\n needs_global boolean:=false;",
  " needs_global boolean:=false;"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_hold_and_replay_v1(jsonb,boolean,integer,integer,integer)','6d037d13ca41c8277dccbe6a79d4105751a8fa2bfb5dc058ed11e81085c0843a','790f98119e777889a0b92abf51fe480875da4e504e9853a763627048aba0da6c',
  $changes$[
 [
  "  BEGIN\n   LOCK TABLE ONLY kaname.authority_binding_epoch IN ROW EXCLUSIVE MODE NOWAIT;\n  EXCEPTION WHEN lock_not_available THEN\n   RAISE EXCEPTION 'external metadata binding epoch relation conflict' USING ERRCODE='40001';\n  END;",
  "  LOCK TABLE ONLY kaname.authority_binding_epoch IN ROW EXCLUSIVE MODE NOWAIT;"
 ],
 [
  "  'root_physical',jsonb_build_object('table',table_name,'id',resource_id,'xmin',physical_state->>0,'ctid',physical_state->>1)\n   ||CASE WHEN external_root THEN jsonb_build_object('object_type',root_coordinate->>0) ELSE '{}'::jsonb END,",
  "  'root_physical',jsonb_build_object('table',table_name,'id',resource_id,'xmin',physical_state->>0,'ctid',physical_state->>1),"
 ],
 [
  " SELECT registration_work+count(*)::integer INTO work_used FROM jsonb_object_keys(frontier_witnesses);",
  " SELECT count(*)::integer INTO work_used FROM jsonb_object_keys(frontier_witnesses);"
 ],
 [
  "\n IF external_root THEN\n  SELECT count(*)::integer,count(*) FILTER (WHERE kind='5') INTO source_count,registration_count FROM (\n   SELECT e.value#>>'{source,kind}' AS kind FROM jsonb_each(prepared#>'{discovery,source_index}') e LIMIT 4097\n  ) bounded;\n  IF registration_count=0 THEN\n   RAISE EXCEPTION 'external metadata registration key set absent' USING ERRCODE='42501';END IF;\n  registration_work:=2*source_count+2*registration_count+2;\n  IF source_count>4096 OR p_rows-rows_used<registration_count+1\n   OR p_reads-reads_used<=registration_count+2 OR p_work<=registration_work THEN\n   RAISE EXCEPTION 'external metadata registration hold budget exhausted' USING ERRCODE='54000';END IF;\n  -- Чтения и строки для первого удержания учитываются отдельно от replay.\n  rows_used:=rows_used+registration_count+1;\n  reads_used:=reads_used+registration_count+2;\n  BEGIN\n   -- Каталожный тип брали до общих ключей. Теперь вновь подтверждаем ту же\n   -- версию без ожидания, затем удерживаем привязку и только потом зеркало.\n   LOCK TABLE ONLY kaname.catalog_resource IN ROW SHARE MODE NOWAIT;\n   IF NOT coalesce(has_table_privilege(invoker,'kaname.catalog_resource','SELECT'),false)\n    OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n     WHERE c.oid='kaname.catalog_resource'::regclass AND c.relkind='r' AND c.relpersistence='p'\n     AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND NOT c.relispartition\n     AND NOT c.relhassubclass AND NOT c.relhasrules) THEN\n    RAISE EXCEPTION 'external metadata catalog privilege or shape differs' USING ERRCODE='42501';END IF;\n   SELECT jsonb_build_array(c.xmin::text,c.ctid::text,to_jsonb(c)) INTO catalog_state\n   FROM ONLY kaname.catalog_resource c\n   WHERE c.dotted=root_coordinate->>0 AND c.live AND c.module<>'iam' FOR SHARE OF c NOWAIT;\n   IF catalog_state IS DISTINCT FROM catalog_expected THEN\n    RAISE EXCEPTION 'external metadata catalog changed before replay' USING ERRCODE='40001';END IF;\n   IF kaname._authority_metadata_registration_binding_holds_v1(registration_count) IS DISTINCT FROM registration_count THEN\n    RAISE EXCEPTION 'external metadata registration key count differs' USING ERRCODE='42501';END IF;\n   LOCK TABLE ONLY kaname.resource_mirror IN ROW EXCLUSIVE MODE NOWAIT;\n   IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n    WHERE c.oid=relation_id AND c.oid='kaname.resource_mirror'::regclass AND c.relkind='r' AND c.relpersistence='p'\n     AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND NOT c.relispartition\n     AND NOT c.relhassubclass AND NOT c.relhasrules) THEN\n    RAISE EXCEPTION 'external metadata mirror shape differs' USING ERRCODE='42501';END IF;\n   SELECT jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) INTO physical_state\n   FROM ONLY kaname.resource_mirror m\n   WHERE m.object_type=root_coordinate->>0 AND m.object_id=resource_id FOR UPDATE OF m NOWAIT;\n   IF physical_state IS DISTINCT FROM old_state THEN\n    RAISE EXCEPTION 'external metadata root changed before replay' USING ERRCODE='40001';END IF;\n  EXCEPTION WHEN lock_not_available THEN\n   RAISE EXCEPTION 'external metadata registration or mirror lock conflict' USING ERRCODE='40001';\n  END;\n END IF;\n\n frontier_witnesses:=prepared#>'{discovery,frontier,witnesses}';",
  " frontier_witnesses:=prepared#>'{discovery,frontier,witnesses}';"
 ],
 [
  "  IF external_root THEN\n   BEGIN\n    IF scope_record.value='write' THEN\n     SELECT e.scope INTO locked_scope FROM ONLY kaname.authority_binding_epoch e\n     WHERE e.scope=scope_record.key FOR UPDATE OF e NOWAIT;\n    ELSIF scope_record.value='share' THEN\n     SELECT e.scope INTO locked_scope FROM ONLY kaname.authority_binding_epoch e\n     WHERE e.scope=scope_record.key FOR SHARE OF e NOWAIT;\n    ELSE\n     RAISE EXCEPTION 'metadata binding epoch lock mode differs' USING ERRCODE='42501';\n    END IF;\n   EXCEPTION WHEN lock_not_available THEN\n    RAISE EXCEPTION 'external metadata binding epoch row conflict' USING ERRCODE='40001';\n   END;\n  ELSIF scope_record.value='write' THEN\n   SELECT e.scope INTO locked_scope FROM ONLY kaname.authority_binding_epoch e\n   WHERE e.scope=scope_record.key FOR UPDATE OF e;\n  ELSIF scope_record.value='share' THEN\n   SELECT e.scope INTO locked_scope FROM ONLY kaname.authority_binding_epoch e\n   WHERE e.scope=scope_record.key FOR SHARE OF e;\n  ELSE\n   RAISE EXCEPTION 'metadata binding epoch lock mode differs' USING ERRCODE='42501';\n  END IF;",
  "  IF scope_record.value='write' THEN\n   SELECT e.scope INTO locked_scope FROM ONLY kaname.authority_binding_epoch e\n   WHERE e.scope=scope_record.key FOR UPDATE OF e;\n  ELSIF scope_record.value='share' THEN\n   SELECT e.scope INTO locked_scope FROM ONLY kaname.authority_binding_epoch e\n   WHERE e.scope=scope_record.key FOR SHARE OF e;\n  ELSE\n   RAISE EXCEPTION 'metadata binding epoch lock mode differs' USING ERRCODE='42501';\n  END IF;"
 ],
 [
  " IF NOT external_root THEN\n  IF p_rename AND table_name='accounts' THEN\n   LOCK TABLE kaname.accounts IN SHARE ROW EXCLUSIVE MODE;\n  ELSE\n   EXECUTE format('LOCK TABLE kaname.%I IN ROW EXCLUSIVE MODE',table_name);\n  END IF;\n  LOCK TABLE kaname.authority_binding_epoch IN ROW EXCLUSIVE MODE;\n  physical_state:=kaname._authority_metadata_root_state_v1(root_coordinate->>0,resource_id,true);\n  IF physical_state IS DISTINCT FROM old_state THEN\n   RAISE EXCEPTION 'metadata root changed during physical wait' USING ERRCODE='40001';END IF;\n ELSE\n  -- Строки эпох политики уже удержаны первым protectPolicyPlan.\n  LOCK TABLE ONLY kaname.authority_binding_epoch IN ROW EXCLUSIVE MODE NOWAIT;\n END IF;",
  " IF p_rename AND table_name='accounts' THEN\n  LOCK TABLE kaname.accounts IN SHARE ROW EXCLUSIVE MODE;\n ELSE\n  EXECUTE format('LOCK TABLE kaname.%I IN ROW EXCLUSIVE MODE',table_name);\n END IF;\n LOCK TABLE kaname.authority_binding_epoch IN ROW EXCLUSIVE MODE;\n physical_state:=kaname._authority_metadata_root_state_v1(root_coordinate->>0,resource_id,true);\n IF physical_state IS DISTINCT FROM old_state THEN\n  RAISE EXCEPTION 'metadata root changed during physical wait' USING ERRCODE='40001';END IF;"
 ],
 [
  " FOREACH field_name IN ARRAY CASE WHEN NOT external_root THEN ARRAY['name','description','labels','access_labels']\n  WHEN p_patch ? 'labels' THEN ARRAY['labels','access_labels'] ELSE ARRAY['access_labels'] END LOOP",
  " FOREACH field_name IN ARRAY ARRAY['name','description','labels','access_labels'] LOOP"
 ],
 [
  "  OR (NOT external_root AND old_state#>>'{2,id}' IS DISTINCT FROM resource_id)\n  OR (external_root AND (old_state#>>'{2,object_type}' IS DISTINCT FROM root_coordinate->>0\n   OR old_state#>>'{2,object_id}' IS DISTINCT FROM resource_id\n   OR p_patch-ARRAY['labels','access_labels']<>'{}'::jsonb\n   OR p_rename IS DISTINCT FROM false))",
  "  OR old_state#>>'{2,id}' IS DISTINCT FROM resource_id"
 ],
 [
  " external_root:=table_name IS NULL;\n IF external_root THEN\n  catalog_expected:=prepared#>'{root,census,root_scope_states,catalog}';\n  IF catalog_expected#>>'{2,dotted}' IS DISTINCT FROM root_coordinate->>0\n   OR catalog_expected#>>'{2,live}' IS DISTINCT FROM 'true'\n   OR coalesce(catalog_expected#>>'{2,module}','') IN ('','iam')\n   OR coalesce(catalog_expected#>>'{2,object_type}','')=''\n   OR prepared#>'{root,census,root_scope_states,root}' IS DISTINCT FROM old_state THEN\n   RAISE EXCEPTION 'metadata external root catalog or state missing' USING ERRCODE='42501';END IF;\n  table_name:='resource_mirror';\n END IF;\n IF table_name IS NULL OR coalesce(resource_id,'')='' OR coalesce(root_account,'')=''",
  " IF table_name IS NULL OR coalesce(resource_id,'')='' OR coalesce(root_account,'')=''"
 ],
 [
  " external_root boolean;catalog_state jsonb;catalog_expected jsonb;\n registration_count integer;source_count integer;registration_work integer:=0;\n rows_used integer:=2;",
  " rows_used integer:=2;"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_early_closure_v1(jsonb,jsonb,integer,integer,integer)','037bb846b0aece534088339e9a7cd5d4c17ce4ce7b56a9d9f1bac8de4d0b82ee','01ef36668b4499a8d9384c6887fab29393ce1cac455f307c68710c2e9e3bb479',
  $changes$[
 [
  "\n  source_key:=jsonb_build_array(4,root_model,root_id,'')::text;\n  IF jsonb_typeof(idx->source_key->'states') IS DISTINCT FROM 'array' THEN\n   RAISE EXCEPTION 'external metadata registration scope witness absent' USING ERRCODE='P1034';END IF;\n  IF EXISTS(SELECT 1 FROM jsonb_array_elements(idx->source_key->'states') s\n   WHERE s#>>'{2,account_id}' IS DISTINCT FROM p_packet->>'root_account'\n    OR s#>>'{2,project_id}' IS DISTINCT FROM coalesce(root_project,'')) THEN\n   RAISE EXCEPTION 'external metadata registration scope differs from owning scope' USING ERRCODE='P1034';END IF;\n  source_key:=jsonb_build_array(5,root_model,root_id,'')::text;",
  "  source_key:=jsonb_build_array(5,root_model,root_id,'')::text;"
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
