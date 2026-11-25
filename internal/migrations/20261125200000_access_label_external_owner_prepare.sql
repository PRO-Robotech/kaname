-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- До общих блокировок подтверждаем активный тип и версию внешнего ресурса.
-- Подготовка закрыта фазой signed full consumer. Публичной записи нет.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('_authority_metadata_access_label_prefinal_carriers_v1(text,text,text,jsonb,jsonb,integer,integer,integer)','6f6abd4b8133c2bde6d037a7d30b591cefd32c5e1079d05979cc72144aeabe0f','fb40b186a84a3f7303195ae6edb0829043ac43a7c2514bbdf0d1d1b2185027e0',
  $changes$[
 [
  " selected jsonb;binding jsonb;",
  " root_dotted text;external_root boolean;catalog_state jsonb;target_tables text[];\n prepare_rows integer:=1;prepare_reads integer:=1;prepare_work integer:=1;\n selected jsonb;binding jsonb;"
 ],
 [
  " IF p_kind IS NULL OR p_kind NOT IN ('account','project','service_account') OR coalesce(p_id,'')=''",
  " external_root:=p_kind NOT IN ('account','project','service_account');\n root_dotted:=CASE WHEN external_root THEN p_kind ELSE CASE p_kind WHEN 'service_account' THEN 'iam.serviceAccount' ELSE 'iam.'||p_kind END END;\n IF p_kind IS NULL OR coalesce(p_id,'')=''\n  OR (external_root AND (octet_length(p_kind)>16384\n   OR p_kind !~ '^[^.:#*[:space:][:cntrl:]]+[.][^.:#*[:space:][:cntrl:]]+$'\n   OR split_part(p_kind,'.',1)='iam'))"
 ],
 [
  "  OR p_old->>'id' IS DISTINCT FROM p_id",
  "  OR (NOT external_root AND p_old->>'id' IS DISTINCT FROM p_id)\n  OR (external_root AND (p_old->>'object_type' IS DISTINCT FROM root_dotted\n   OR p_old->>'object_id' IS DISTINCT FROM p_id))"
 ],
 [
  " table_name:=CASE p_kind WHEN 'account' THEN 'accounts' WHEN 'project' THEN 'projects' WHEN 'service_account' THEN 'service_accounts' END;",
  " table_name:=CASE p_kind WHEN 'account' THEN 'accounts' WHEN 'project' THEN 'projects' WHEN 'service_account' THEN 'service_accounts' END;\n target_tables:=ARRAY[table_name,'access_bindings','roles','projects'];\n IF external_root THEN\n  table_name:='resource_mirror';\n  target_tables:=ARRAY[table_name,'catalog_resource','accounts','access_bindings','roles','projects'];\n END IF;"
 ],
 [
  " FOREACH target IN ARRAY ARRAY[table_name,'access_bindings','roles','projects'] LOOP",
  " FOREACH target IN ARRAY target_tables LOOP"
 ],
 [
  " -- Не берём tuple/advisory locks частичного графа: полный максимум должен\n -- быть выведен до первого acquisition. Здесь только наблюдение для discovery.",
  " -- Блокировки графа берём после discovery. Здесь удерживаем только\n -- каталожный тип внешнего корня, как в протоколе регистрации."
 ],
 [
  " root_state:=kaname._authority_metadata_root_state_v1(",
  "\n IF external_root THEN\n  -- Тот же порядок, что у регистрации. Закрепляем активный тип до\n  -- общего набора advisory и строк эпох. При конфликте начинаем заново.\n  IF p_rows<=1 OR p_reads<=2 OR p_work<=1 THEN\n   RAISE EXCEPTION 'external metadata catalog budget exhausted' USING ERRCODE='54000';END IF;\n  BEGIN\n   LOCK TABLE ONLY kaname.catalog_resource IN ROW SHARE MODE NOWAIT;\n   IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n    WHERE c.oid='kaname.catalog_resource'::regclass\n    AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity\n    AND NOT c.relispartition AND NOT c.relhassubclass AND NOT c.relhasrules)\n    OR NOT coalesce(has_table_privilege(invoker,'kaname.catalog_resource','SELECT'),false) THEN\n    RAISE EXCEPTION 'external metadata catalog table shape differs' USING ERRCODE='42501';END IF;\n   SELECT jsonb_build_array(c.xmin::text,c.ctid::text,to_jsonb(c)) INTO catalog_state\n   FROM ONLY kaname.catalog_resource c\n   WHERE c.dotted=root_dotted AND c.live AND c.module<>'iam' FOR SHARE OF c NOWAIT;\n  EXCEPTION WHEN lock_not_available THEN\n   RAISE EXCEPTION 'external metadata catalog changed during prepare' USING ERRCODE='40001';\n  END;\n  IF catalog_state IS NULL THEN\n   RAISE EXCEPTION 'external metadata live catalog type absent' USING ERRCODE='P1034';END IF;\n  prepare_rows:=prepare_rows+1;prepare_reads:=prepare_reads+1;prepare_work:=prepare_work+1;\n END IF;\n root_state:=kaname._authority_metadata_root_state_v1("
 ],
 [
  " root_state:=kaname._authority_metadata_root_state_v1(\n  CASE p_kind WHEN 'service_account' THEN 'iam.serviceAccount' ELSE 'iam.'||p_kind END,p_id,false);",
  " root_state:=kaname._authority_metadata_root_state_v1(root_dotted,p_id,false);"
 ],
 [
  " account_id:=CASE p_kind WHEN 'account' THEN p_id ELSE p_old->>'account_id' END;\n",
  " IF external_root THEN\n  account_id:=nullif(p_old->>'parent_account_id','');\n  IF account_id IS NULL THEN\n   IF p_rows<=prepare_rows OR p_reads<=prepare_reads+1 OR p_work<=prepare_work THEN\n    RAISE EXCEPTION 'external metadata owning project budget exhausted' USING ERRCODE='54000';END IF;\n   SELECT p.account_id INTO account_id FROM ONLY kaname.projects p WHERE p.id=nullif(p_old->>'parent_project_id','');\n   prepare_reads:=prepare_reads+1;prepare_work:=prepare_work+1;\n   IF FOUND THEN prepare_rows:=prepare_rows+1;END IF;\n  END IF;\n ELSE\n  account_id:=CASE p_kind WHEN 'account' THEN p_id ELSE p_old->>'account_id' END;\n END IF;\n"
 ],
 [
  " census:=kaname._authority_metadata_access_label_carrier_census_v1(\n  (CASE p_kind WHEN 'service_account' THEN 'iam.serviceAccount' ELSE 'iam.'||p_kind END),root_state->2,p_new_access,p_rows-1,p_reads-1,p_work-1);\n",
  " census:=kaname._authority_metadata_access_label_carrier_census_v1(\n  root_dotted,root_state->2,p_new_access,p_rows-prepare_rows,p_reads-prepare_reads,p_work-prepare_work);\n IF external_root AND (census#>'{root_scope_states,catalog}' IS DISTINCT FROM catalog_state\n  OR census#>'{root_scope_states,root}' IS DISTINCT FROM root_state\n  OR census->>'account_id' IS DISTINCT FROM account_id) THEN\n  RAISE EXCEPTION 'external metadata scope changed during discovery' USING ERRCODE='40001';END IF;\n"
 ],
 [
  "  OR census->>'root_type' IS DISTINCT FROM (CASE p_kind WHEN 'service_account' THEN 'iam.serviceAccount' ELSE 'iam.'||p_kind END)",
  "  OR census->>'root_type' IS DISTINCT FROM root_dotted"
 ],
 [
  " used_rows:=1+(census->>'logical_rows')::integer;\n used_reads:=1+(census->>'logical_reads')::integer;work:=1+(census->>'work')::integer;",
  " used_rows:=prepare_rows+(census->>'logical_rows')::integer;\n used_reads:=prepare_reads+(census->>'logical_reads')::integer;\n work:=prepare_work+(census->>'work')::integer;"
 ],
 [
  " root_ref:=jsonb_build_array((CASE p_kind WHEN 'service_account' THEN 'iam.serviceAccount' ELSE 'iam.'||p_kind END),p_id);",
  " root_ref:=jsonb_build_array(root_dotted,p_id);"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_early_closure_v1(jsonb,jsonb,integer,integer,integer)','aa7e8d053574b69892a5f61f54099f9c6c8718554f47a97eee838d5670ffafeb','01ef36668b4499a8d9384c6887fab29393ce1cac455f307c68710c2e9e3bb479',
  $changes$[
 [
  " ancestor_keys jsonb",
  " external_root boolean;root_model text;root_source_kind integer;root_scope jsonb;root_project text;\n ancestor_keys jsonb"
 ],
 [
  " IF coalesce(root_type,'') NOT IN ('iam.account','iam.project','iam.serviceAccount') OR coalesce(root_id,'')='' THEN",
  " external_root:=root_type NOT IN ('iam.account','iam.project','iam.serviceAccount');\n IF coalesce(root_type,'')='' OR coalesce(root_id,'')='' THEN"
 ],
 [
  " queue:=jsonb_build_array(jsonb_build_array(0,root_type,root_id));",
  "\n IF external_root THEN\n  root_scope:=p_packet#>'{census,root_scope_states}';\n  root_model:=root_scope#>>'{catalog,2,object_type}';\n  root_project:=root_scope#>>'{project,2,id}';\n  root_source_kind:=2;\n  IF NOT coalesce((root_scope#>'{catalog,2,live}')='true'::jsonb,false)\n   OR root_scope#>>'{catalog,2,dotted}' IS DISTINCT FROM root_type\n   OR coalesce(root_model,'')=''\n   OR root_scope#>>'{account,2,id}' IS DISTINCT FROM p_packet->>'root_account'\n   OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p_catalog#>'{Live,Resources}') r\n    WHERE r->>'ObjectType'=root_model AND (r->>'Module')||'.'||(r->>'Resource')=root_type\n     AND r->>'Module'<>'iam') THEN\n   RAISE EXCEPTION 'external metadata canonical catalog or scope changed' USING ERRCODE='P1034';END IF;\n ELSE\n  root_source_kind:=30;\n  root_model:=CASE root_type WHEN 'iam.serviceAccount' THEN 'iam_service_account' ELSE split_part(root_type,'.',2) END;\n END IF;\n queue:=jsonb_build_array(jsonb_build_array(0,root_type,root_id));"
 ],
 [
  "    additions:=additions||jsonb_build_array(jsonb_build_array(4,model,identifier));",
  "    additions:=additions||jsonb_build_array(jsonb_build_array(4,model,identifier));\n    IF external_root THEN\n     additions:=additions||jsonb_build_array(jsonb_build_array(5,model,identifier));\n    END IF;"
 ],
 [
  "    OR (k IN (2,27,30) AND jsonb_array_length(capture->'states')>1)",
  "    OR (k IN (2,5,27,30) AND jsonb_array_length(capture->'states')>1)"
 ],
 [
  " source_key:=jsonb_build_array(30,root_type,root_id,'')::text;",
  " source_key:=jsonb_build_array(root_source_kind,root_type,root_id,'')::text;"
 ],
 [
  " FOR expected IN SELECT value FROM jsonb_array_elements(p_packet#>'{census,selected}') LOOP",
  "\n IF external_root THEN\n  -- Сверяем физическую историю владельцев и постоянную привязку к проекту.\n  -- Пустую привязку явно сохраняем для последующего удержания предиката.\n  source_key:=jsonb_build_array(23,'account',p_packet->>'root_account','')::text;\n  IF idx->source_key->'states' IS DISTINCT FROM jsonb_build_array(root_scope->'account') THEN\n   RAISE EXCEPTION 'external metadata account changed during discovery' USING ERRCODE='40001';END IF;\n  IF root_project IS NOT NULL THEN\n   source_key:=jsonb_build_array(1,'project',root_project,'')::text;\n   IF idx->source_key->'states' IS DISTINCT FROM jsonb_build_array(root_scope->'project') THEN\n    RAISE EXCEPTION 'external metadata project changed during discovery' USING ERRCODE='40001';END IF;\n  END IF;\n  source_key:=jsonb_build_array(5,root_model,root_id,'')::text;\n  IF jsonb_typeof(idx->source_key->'states') IS DISTINCT FROM 'array'\n   OR (jsonb_array_length(idx->source_key->'states')=1\n    AND idx->source_key#>>'{states,0,2,project_id}' IS DISTINCT FROM root_project) THEN\n   RAISE EXCEPTION 'external metadata permanent scope not confirmed' USING ERRCODE='P1034';END IF;\n END IF;\n FOR expected IN SELECT value FROM jsonb_array_elements(p_packet#>'{census,selected}') LOOP"
 ],
 [
  " walk:=kaname._authority_metadata_access_label_early_walk_v1(seed_list,CASE root_type WHEN 'iam.serviceAccount' THEN 'iam_service_account' ELSE split_part(root_type,'.',2) END,root_id,",
  " walk:=kaname._authority_metadata_access_label_early_walk_v1(seed_list,root_model,root_id,"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_early_walk_v1(jsonb,text,text,integer,integer,integer)','b6874b32493ddb7bf8bfe4e70afa10ebb0acb2c8ebf0792419c77969a40d6475','a0b704f14d050e84c4c712a6fa9d6d1c4b152434ceba409f721d6544a0f887b4',
  $changes$[
 [
  "  OR coalesce(p_root_model,'') NOT IN ('account','project','iam_service_account') OR coalesce(p_root_id,'')=''",
  "  OR coalesce(p_root_model,'') !~ '^[a-z][a-z0-9_]*$' OR coalesce(p_root_id,'')=''\n  OR (p_root_model NOT IN ('account','project','iam_service_account')\n   AND NOT coalesce(p_seeds @> jsonb_build_array(jsonb_build_array(p_root_model,p_root_id)),false))"
 ]
]$changes$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','73cf60bf7d003e3a694303cc14b0db89eae7d179ba04e72c5556f0e78b6fb236','8eb750b502dadc4295a50cc5fdde4e63c9224e6454c4e340be074c7a5f94544a',
  $changes$[
 [
  "6f6abd4b8133c2bde6d037a7d30b591cefd32c5e1079d05979cc72144aeabe0f",
  "fb40b186a84a3f7303195ae6edb0829043ac43a7c2514bbdf0d1d1b2185027e0"
 ],
 [
  "aa7e8d053574b69892a5f61f54099f9c6c8718554f47a97eee838d5670ffafeb",
  "01ef36668b4499a8d9384c6887fab29393ce1cac455f307c68710c2e9e3bb479"
 ],
 [
  "b6874b32493ddb7bf8bfe4e70afa10ebb0acb2c8ebf0792419c77969a40d6475",
  "a0b704f14d050e84c4c712a6fa9d6d1c4b152434ceba409f721d6544a0f887b4"
 ]
]$changes$::jsonb),
 ('authority_metadata_service_account_access_label_ready_v1()','05f62d50bedc50db0d0eb12875f5bd06d835376b14a50c12b0d0ab6913c542d0','ce2555cc19aa07d16a15ea1e5e1e58a69ffe677b411ae36ea2c5e7300913fe51',
  $changes$[
 [
  "6f6abd4b8133c2bde6d037a7d30b591cefd32c5e1079d05979cc72144aeabe0f",
  "fb40b186a84a3f7303195ae6edb0829043ac43a7c2514bbdf0d1d1b2185027e0"
 ],
 [
  "aa7e8d053574b69892a5f61f54099f9c6c8718554f47a97eee838d5670ffafeb",
  "01ef36668b4499a8d9384c6887fab29393ce1cac455f307c68710c2e9e3bb479"
 ],
 [
  "b6874b32493ddb7bf8bfe4e70afa10ebb0acb2c8ebf0792419c77969a40d6475",
  "a0b704f14d050e84c4c712a6fa9d6d1c4b152434ceba409f721d6544a0f887b4"
 ],
 [
  "73cf60bf7d003e3a694303cc14b0db89eae7d179ba04e72c5556f0e78b6fb236",
  "8eb750b502dadc4295a50cc5fdde4e63c9224e6454c4e340be074c7a5f94544a"
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
 ('authority_metadata_service_account_access_label_ready_v1()','ce2555cc19aa07d16a15ea1e5e1e58a69ffe677b411ae36ea2c5e7300913fe51','05f62d50bedc50db0d0eb12875f5bd06d835376b14a50c12b0d0ab6913c542d0',
  $changes$[
 [
  "8eb750b502dadc4295a50cc5fdde4e63c9224e6454c4e340be074c7a5f94544a",
  "73cf60bf7d003e3a694303cc14b0db89eae7d179ba04e72c5556f0e78b6fb236"
 ],
 [
  "a0b704f14d050e84c4c712a6fa9d6d1c4b152434ceba409f721d6544a0f887b4",
  "b6874b32493ddb7bf8bfe4e70afa10ebb0acb2c8ebf0792419c77969a40d6475"
 ],
 [
  "01ef36668b4499a8d9384c6887fab29393ce1cac455f307c68710c2e9e3bb479",
  "aa7e8d053574b69892a5f61f54099f9c6c8718554f47a97eee838d5670ffafeb"
 ],
 [
  "fb40b186a84a3f7303195ae6edb0829043ac43a7c2514bbdf0d1d1b2185027e0",
  "6f6abd4b8133c2bde6d037a7d30b591cefd32c5e1079d05979cc72144aeabe0f"
 ]
]$changes$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','8eb750b502dadc4295a50cc5fdde4e63c9224e6454c4e340be074c7a5f94544a','73cf60bf7d003e3a694303cc14b0db89eae7d179ba04e72c5556f0e78b6fb236',
  $changes$[
 [
  "a0b704f14d050e84c4c712a6fa9d6d1c4b152434ceba409f721d6544a0f887b4",
  "b6874b32493ddb7bf8bfe4e70afa10ebb0acb2c8ebf0792419c77969a40d6475"
 ],
 [
  "01ef36668b4499a8d9384c6887fab29393ce1cac455f307c68710c2e9e3bb479",
  "aa7e8d053574b69892a5f61f54099f9c6c8718554f47a97eee838d5670ffafeb"
 ],
 [
  "fb40b186a84a3f7303195ae6edb0829043ac43a7c2514bbdf0d1d1b2185027e0",
  "6f6abd4b8133c2bde6d037a7d30b591cefd32c5e1079d05979cc72144aeabe0f"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_early_walk_v1(jsonb,text,text,integer,integer,integer)','a0b704f14d050e84c4c712a6fa9d6d1c4b152434ceba409f721d6544a0f887b4','b6874b32493ddb7bf8bfe4e70afa10ebb0acb2c8ebf0792419c77969a40d6475',
  $changes$[
 [
  "  OR coalesce(p_root_model,'') !~ '^[a-z][a-z0-9_]*$' OR coalesce(p_root_id,'')=''\n  OR (p_root_model NOT IN ('account','project','iam_service_account')\n   AND NOT coalesce(p_seeds @> jsonb_build_array(jsonb_build_array(p_root_model,p_root_id)),false))",
  "  OR coalesce(p_root_model,'') NOT IN ('account','project','iam_service_account') OR coalesce(p_root_id,'')=''"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_early_closure_v1(jsonb,jsonb,integer,integer,integer)','01ef36668b4499a8d9384c6887fab29393ce1cac455f307c68710c2e9e3bb479','aa7e8d053574b69892a5f61f54099f9c6c8718554f47a97eee838d5670ffafeb',
  $changes$[
 [
  " walk:=kaname._authority_metadata_access_label_early_walk_v1(seed_list,root_model,root_id,",
  " walk:=kaname._authority_metadata_access_label_early_walk_v1(seed_list,CASE root_type WHEN 'iam.serviceAccount' THEN 'iam_service_account' ELSE split_part(root_type,'.',2) END,root_id,"
 ],
 [
  "\n IF external_root THEN\n  -- Сверяем физическую историю владельцев и постоянную привязку к проекту.\n  -- Пустую привязку явно сохраняем для последующего удержания предиката.\n  source_key:=jsonb_build_array(23,'account',p_packet->>'root_account','')::text;\n  IF idx->source_key->'states' IS DISTINCT FROM jsonb_build_array(root_scope->'account') THEN\n   RAISE EXCEPTION 'external metadata account changed during discovery' USING ERRCODE='40001';END IF;\n  IF root_project IS NOT NULL THEN\n   source_key:=jsonb_build_array(1,'project',root_project,'')::text;\n   IF idx->source_key->'states' IS DISTINCT FROM jsonb_build_array(root_scope->'project') THEN\n    RAISE EXCEPTION 'external metadata project changed during discovery' USING ERRCODE='40001';END IF;\n  END IF;\n  source_key:=jsonb_build_array(5,root_model,root_id,'')::text;\n  IF jsonb_typeof(idx->source_key->'states') IS DISTINCT FROM 'array'\n   OR (jsonb_array_length(idx->source_key->'states')=1\n    AND idx->source_key#>>'{states,0,2,project_id}' IS DISTINCT FROM root_project) THEN\n   RAISE EXCEPTION 'external metadata permanent scope not confirmed' USING ERRCODE='P1034';END IF;\n END IF;\n FOR expected IN SELECT value FROM jsonb_array_elements(p_packet#>'{census,selected}') LOOP",
  " FOR expected IN SELECT value FROM jsonb_array_elements(p_packet#>'{census,selected}') LOOP"
 ],
 [
  " source_key:=jsonb_build_array(root_source_kind,root_type,root_id,'')::text;",
  " source_key:=jsonb_build_array(30,root_type,root_id,'')::text;"
 ],
 [
  "    OR (k IN (2,5,27,30) AND jsonb_array_length(capture->'states')>1)",
  "    OR (k IN (2,27,30) AND jsonb_array_length(capture->'states')>1)"
 ],
 [
  "    additions:=additions||jsonb_build_array(jsonb_build_array(4,model,identifier));\n    IF external_root THEN\n     additions:=additions||jsonb_build_array(jsonb_build_array(5,model,identifier));\n    END IF;",
  "    additions:=additions||jsonb_build_array(jsonb_build_array(4,model,identifier));"
 ],
 [
  "\n IF external_root THEN\n  root_scope:=p_packet#>'{census,root_scope_states}';\n  root_model:=root_scope#>>'{catalog,2,object_type}';\n  root_project:=root_scope#>>'{project,2,id}';\n  root_source_kind:=2;\n  IF NOT coalesce((root_scope#>'{catalog,2,live}')='true'::jsonb,false)\n   OR root_scope#>>'{catalog,2,dotted}' IS DISTINCT FROM root_type\n   OR coalesce(root_model,'')=''\n   OR root_scope#>>'{account,2,id}' IS DISTINCT FROM p_packet->>'root_account'\n   OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p_catalog#>'{Live,Resources}') r\n    WHERE r->>'ObjectType'=root_model AND (r->>'Module')||'.'||(r->>'Resource')=root_type\n     AND r->>'Module'<>'iam') THEN\n   RAISE EXCEPTION 'external metadata canonical catalog or scope changed' USING ERRCODE='P1034';END IF;\n ELSE\n  root_source_kind:=30;\n  root_model:=CASE root_type WHEN 'iam.serviceAccount' THEN 'iam_service_account' ELSE split_part(root_type,'.',2) END;\n END IF;\n queue:=jsonb_build_array(jsonb_build_array(0,root_type,root_id));",
  " queue:=jsonb_build_array(jsonb_build_array(0,root_type,root_id));"
 ],
 [
  " external_root:=root_type NOT IN ('iam.account','iam.project','iam.serviceAccount');\n IF coalesce(root_type,'')='' OR coalesce(root_id,'')='' THEN",
  " IF coalesce(root_type,'') NOT IN ('iam.account','iam.project','iam.serviceAccount') OR coalesce(root_id,'')='' THEN"
 ],
 [
  " external_root boolean;root_model text;root_source_kind integer;root_scope jsonb;root_project text;\n ancestor_keys jsonb",
  " ancestor_keys jsonb"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_prefinal_carriers_v1(text,text,text,jsonb,jsonb,integer,integer,integer)','fb40b186a84a3f7303195ae6edb0829043ac43a7c2514bbdf0d1d1b2185027e0','6f6abd4b8133c2bde6d037a7d30b591cefd32c5e1079d05979cc72144aeabe0f',
  $changes$[
 [
  " root_ref:=jsonb_build_array(root_dotted,p_id);",
  " root_ref:=jsonb_build_array((CASE p_kind WHEN 'service_account' THEN 'iam.serviceAccount' ELSE 'iam.'||p_kind END),p_id);"
 ],
 [
  " used_rows:=prepare_rows+(census->>'logical_rows')::integer;\n used_reads:=prepare_reads+(census->>'logical_reads')::integer;\n work:=prepare_work+(census->>'work')::integer;",
  " used_rows:=1+(census->>'logical_rows')::integer;\n used_reads:=1+(census->>'logical_reads')::integer;work:=1+(census->>'work')::integer;"
 ],
 [
  "  OR census->>'root_type' IS DISTINCT FROM root_dotted",
  "  OR census->>'root_type' IS DISTINCT FROM (CASE p_kind WHEN 'service_account' THEN 'iam.serviceAccount' ELSE 'iam.'||p_kind END)"
 ],
 [
  " census:=kaname._authority_metadata_access_label_carrier_census_v1(\n  root_dotted,root_state->2,p_new_access,p_rows-prepare_rows,p_reads-prepare_reads,p_work-prepare_work);\n IF external_root AND (census#>'{root_scope_states,catalog}' IS DISTINCT FROM catalog_state\n  OR census#>'{root_scope_states,root}' IS DISTINCT FROM root_state\n  OR census->>'account_id' IS DISTINCT FROM account_id) THEN\n  RAISE EXCEPTION 'external metadata scope changed during discovery' USING ERRCODE='40001';END IF;\n",
  " census:=kaname._authority_metadata_access_label_carrier_census_v1(\n  (CASE p_kind WHEN 'service_account' THEN 'iam.serviceAccount' ELSE 'iam.'||p_kind END),root_state->2,p_new_access,p_rows-1,p_reads-1,p_work-1);\n"
 ],
 [
  " IF external_root THEN\n  account_id:=nullif(p_old->>'parent_account_id','');\n  IF account_id IS NULL THEN\n   IF p_rows<=prepare_rows OR p_reads<=prepare_reads+1 OR p_work<=prepare_work THEN\n    RAISE EXCEPTION 'external metadata owning project budget exhausted' USING ERRCODE='54000';END IF;\n   SELECT p.account_id INTO account_id FROM ONLY kaname.projects p WHERE p.id=nullif(p_old->>'parent_project_id','');\n   prepare_reads:=prepare_reads+1;prepare_work:=prepare_work+1;\n   IF FOUND THEN prepare_rows:=prepare_rows+1;END IF;\n  END IF;\n ELSE\n  account_id:=CASE p_kind WHEN 'account' THEN p_id ELSE p_old->>'account_id' END;\n END IF;\n",
  " account_id:=CASE p_kind WHEN 'account' THEN p_id ELSE p_old->>'account_id' END;\n"
 ],
 [
  " root_state:=kaname._authority_metadata_root_state_v1(root_dotted,p_id,false);",
  " root_state:=kaname._authority_metadata_root_state_v1(\n  CASE p_kind WHEN 'service_account' THEN 'iam.serviceAccount' ELSE 'iam.'||p_kind END,p_id,false);"
 ],
 [
  "\n IF external_root THEN\n  -- Тот же порядок, что у регистрации. Закрепляем активный тип до\n  -- общего набора advisory и строк эпох. При конфликте начинаем заново.\n  IF p_rows<=1 OR p_reads<=2 OR p_work<=1 THEN\n   RAISE EXCEPTION 'external metadata catalog budget exhausted' USING ERRCODE='54000';END IF;\n  BEGIN\n   LOCK TABLE ONLY kaname.catalog_resource IN ROW SHARE MODE NOWAIT;\n   IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n    WHERE c.oid='kaname.catalog_resource'::regclass\n    AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity\n    AND NOT c.relispartition AND NOT c.relhassubclass AND NOT c.relhasrules)\n    OR NOT coalesce(has_table_privilege(invoker,'kaname.catalog_resource','SELECT'),false) THEN\n    RAISE EXCEPTION 'external metadata catalog table shape differs' USING ERRCODE='42501';END IF;\n   SELECT jsonb_build_array(c.xmin::text,c.ctid::text,to_jsonb(c)) INTO catalog_state\n   FROM ONLY kaname.catalog_resource c\n   WHERE c.dotted=root_dotted AND c.live AND c.module<>'iam' FOR SHARE OF c NOWAIT;\n  EXCEPTION WHEN lock_not_available THEN\n   RAISE EXCEPTION 'external metadata catalog changed during prepare' USING ERRCODE='40001';\n  END;\n  IF catalog_state IS NULL THEN\n   RAISE EXCEPTION 'external metadata live catalog type absent' USING ERRCODE='P1034';END IF;\n  prepare_rows:=prepare_rows+1;prepare_reads:=prepare_reads+1;prepare_work:=prepare_work+1;\n END IF;\n root_state:=kaname._authority_metadata_root_state_v1(",
  " root_state:=kaname._authority_metadata_root_state_v1("
 ],
 [
  " -- Блокировки графа берём после discovery. Здесь удерживаем только\n -- каталожный тип внешнего корня, как в протоколе регистрации.",
  " -- Не берём tuple/advisory locks частичного графа: полный максимум должен\n -- быть выведен до первого acquisition. Здесь только наблюдение для discovery."
 ],
 [
  " FOREACH target IN ARRAY target_tables LOOP",
  " FOREACH target IN ARRAY ARRAY[table_name,'access_bindings','roles','projects'] LOOP"
 ],
 [
  " table_name:=CASE p_kind WHEN 'account' THEN 'accounts' WHEN 'project' THEN 'projects' WHEN 'service_account' THEN 'service_accounts' END;\n target_tables:=ARRAY[table_name,'access_bindings','roles','projects'];\n IF external_root THEN\n  table_name:='resource_mirror';\n  target_tables:=ARRAY[table_name,'catalog_resource','accounts','access_bindings','roles','projects'];\n END IF;",
  " table_name:=CASE p_kind WHEN 'account' THEN 'accounts' WHEN 'project' THEN 'projects' WHEN 'service_account' THEN 'service_accounts' END;"
 ],
 [
  "  OR (NOT external_root AND p_old->>'id' IS DISTINCT FROM p_id)\n  OR (external_root AND (p_old->>'object_type' IS DISTINCT FROM root_dotted\n   OR p_old->>'object_id' IS DISTINCT FROM p_id))",
  "  OR p_old->>'id' IS DISTINCT FROM p_id"
 ],
 [
  " external_root:=p_kind NOT IN ('account','project','service_account');\n root_dotted:=CASE WHEN external_root THEN p_kind ELSE CASE p_kind WHEN 'service_account' THEN 'iam.serviceAccount' ELSE 'iam.'||p_kind END END;\n IF p_kind IS NULL OR coalesce(p_id,'')=''\n  OR (external_root AND (octet_length(p_kind)>16384\n   OR p_kind !~ '^[^.:#*[:space:][:cntrl:]]+[.][^.:#*[:space:][:cntrl:]]+$'\n   OR split_part(p_kind,'.',1)='iam'))",
  " IF p_kind IS NULL OR p_kind NOT IN ('account','project','service_account') OR coalesce(p_id,'')=''"
 ],
 [
  " root_dotted text;external_root boolean;catalog_state jsonb;target_tables text[];\n prepare_rows integer:=1;prepare_reads integer:=1;prepare_work integer:=1;\n selected jsonb;binding jsonb;",
  " selected jsonb;binding jsonb;"
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
