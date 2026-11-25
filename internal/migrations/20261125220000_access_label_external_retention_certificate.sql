-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Закрытый сертификат удержания для внешнего OLD/NEW из подтверждённого replay.
-- Не добавляет writer, grants или публичный путь внешней записи.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('_authority_access_label_member_partition_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer)','f4367d9db5c32b4da4d5a364a244aa7d7e1437a50d9cc4622e69a7a89f03ec26','4654a6cb62d92fbdfcc2e0db90b7f2c1fc1580c505a2c03b6c2bbef54ce3a497',
  $changes$[
 [
  " model text;root_model text;key_value text;used integer:=0;work integer:=0;count_value integer;\nBEGIN\n IF p_root_type IS NULL OR p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') OR coalesce(p_root_id,'')=''\n OR p_bindings IS NULL OR cardinality(p_bindings)>4096\n OR jsonb_typeof(p_index) IS DISTINCT FROM 'object' OR jsonb_typeof(p_frontiers) IS DISTINCT FROM 'object'\n",
  " model text;root_model text;key_value text;used integer:=0;work integer:=0;count_value integer;\nBEGIN\n IF p_root_type IS NULL OR (p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') AND (p_root_type !~ '^[^.:#*[:space:][:cntrl:]]+[.][^.:#*[:space:][:cntrl:]]+$' OR split_part(p_root_type,'.',1)='iam')) OR coalesce(p_root_id,'')=''\n OR p_bindings IS NULL OR cardinality(p_bindings)>4096\n OR jsonb_typeof(p_index) IS DISTINCT FROM 'object' OR jsonb_typeof(p_frontiers) IS DISTINCT FROM 'object'\n"
 ],
 [
  "  RAISE EXCEPTION 'protected member partition input invalid' USING ERRCODE='42501';END IF;\n root_model:=CASE p_root_type WHEN 'iam.account' THEN 'account' WHEN 'iam.project' THEN 'project' WHEN 'iam.serviceAccount' THEN 'iam_service_account' END;\n -- Добавляем координаты из журнала, в том числе без текущего участника.\n -- required сохраняет полные удержанные предикаты.\n",
  "  RAISE EXCEPTION 'protected member partition input invalid' USING ERRCODE='42501';END IF;\n root_model:=CASE p_root_type WHEN 'iam.account' THEN 'account' WHEN 'iam.project' THEN 'project' WHEN 'iam.serviceAccount' THEN 'iam_service_account' END;\n IF p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN\n  SELECT count(*),min(r->>'ObjectType') INTO count_value,root_model\n  FROM jsonb_array_elements(p_catalog#>'{Live,Resources}') r\n  WHERE (r->>'Module')||'.'||(r->>'Resource')=p_root_type AND r->>'Module'<>'iam';\n  IF count_value<>1 OR coalesce(root_model,'') !~ '^[a-z][a-z0-9_]*$' THEN\n   RAISE EXCEPTION 'external retention root live model unconfirmed' USING ERRCODE='42501';END IF;\n END IF;\n\n IF p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN\n  work:=work+1;\n  IF work>p_work THEN RAISE EXCEPTION 'external retention root mapping budget exhausted' USING ERRCODE='54000';END IF;\n END IF;\n -- Добавляем координаты из журнала, в том числе без текущего участника.\n -- required сохраняет полные удержанные предикаты.\n"
 ]
]$changes$::jsonb),
 ('_authority_access_label_old_facts_v2(text,text,text[],jsonb,jsonb,jsonb,integer,integer)','33d20a2c1b37c3edee7949d1df8390bf2f26c31d4cd65ecc82c8dd4e1aa5ffa5','2c1f7492f38356a22db5a5dde186fb3b2337e51a27a265be46ca7e2eef4bb723',
  $changes$[
 [
  " used integer:=0; work integer:=0; n integer;partition jsonb;\nBEGIN\n IF p_root_type IS NULL OR p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount')\n OR p_root_id IS NULL OR p_root_id='' OR p_bindings IS NULL\n OR cardinality(p_bindings)>4096 OR jsonb_typeof(p_index) IS DISTINCT FROM 'object'\n",
  " used integer:=0; work integer:=0; n integer;partition jsonb;\nBEGIN\n IF p_root_type IS NULL OR (p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') AND (p_root_type !~ '^[^.:#*[:space:][:cntrl:]]+[.][^.:#*[:space:][:cntrl:]]+$' OR split_part(p_root_type,'.',1)='iam'))\n OR p_root_id IS NULL OR p_root_id='' OR p_bindings IS NULL\n OR cardinality(p_bindings)>4096 OR jsonb_typeof(p_index) IS DISTINCT FROM 'object'\n"
 ],
 [
  " OR cardinality(p_bindings)<>(SELECT count(DISTINCT b COLLATE \"C\") FROM unnest(p_bindings) b) THEN\n  RAISE EXCEPTION 'access label old output input invalid' USING ERRCODE='42501';END IF;\n root:=kaname._authority_resource_require_capture_v2(p_index,30,p_root_type,p_root_id);\n IF jsonb_array_length(root->'states')<>1 THEN\n  RAISE EXCEPTION 'access label old root missing' USING ERRCODE='42501';END IF;\n",
  " OR cardinality(p_bindings)<>(SELECT count(DISTINCT b COLLATE \"C\") FROM unnest(p_bindings) b) THEN\n  RAISE EXCEPTION 'access label old output input invalid' USING ERRCODE='42501';END IF;\n root:=kaname._authority_resource_require_capture_v2(p_index,\n  CASE WHEN p_root_type IN ('iam.account','iam.project','iam.serviceAccount') THEN 30 ELSE 2 END,p_root_type,p_root_id);\n IF jsonb_array_length(root->'states')<>1 THEN\n  RAISE EXCEPTION 'access label old root missing' USING ERRCODE='42501';END IF;\n"
 ],
 [
  " IF jsonb_typeof(state) IS DISTINCT FROM 'array' OR jsonb_array_length(state)<>3\n OR coalesce(state->>0,'')='' OR coalesce(state->>1,'')=''\n OR jsonb_typeof(row_value) IS DISTINCT FROM 'object' OR row_value->>'id' IS DISTINCT FROM p_root_id\n OR kaname.access_labels_valid_v1(row_value->'access_labels') IS DISTINCT FROM true THEN\n  RAISE EXCEPTION 'access label old root physical image missing' USING ERRCODE='42501';END IF;\n",
  " IF jsonb_typeof(state) IS DISTINCT FROM 'array' OR jsonb_array_length(state)<>3\n OR coalesce(state->>0,'')='' OR coalesce(state->>1,'')=''\n OR jsonb_typeof(row_value) IS DISTINCT FROM 'object'\n OR (p_root_type IN ('iam.account','iam.project','iam.serviceAccount') AND row_value->>'id' IS DISTINCT FROM p_root_id)\n OR (p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') AND (row_value->>'object_type' IS DISTINCT FROM p_root_type\n  OR row_value->>'object_id' IS DISTINCT FROM p_root_id))\n OR kaname.access_labels_valid_v1(row_value->'access_labels') IS DISTINCT FROM true THEN\n  RAISE EXCEPTION 'access label old root physical image missing' USING ERRCODE='42501';END IF;\n"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_retention_plan_v1(jsonb,jsonb,jsonb,jsonb,text,jsonb,jsonb,integer)','5afba290c6900e52f68700275d833d3f1af86d856f21d8f43fa7bf19892cc586','683ae6d0a044bc052e330bd1e75ac39b1541bf416ec6438ffce437d1359e4fb7',
  $changes$[
 [
  " facts jsonb; tuple_object text; tuple_user text; tuple_relation text; coordinate_key text;\n required jsonb:='{}'; graphs jsonb:='{}'; bindings jsonb:='{}'; coordinates jsonb:='{}';\n work integer:=0;\nBEGIN\n IF jsonb_typeof(p_index) IS DISTINCT FROM 'object'\n  OR jsonb_typeof(p_outputs) IS DISTINCT FROM 'object'\n  OR jsonb_typeof(p_old_outputs->'objects') IS DISTINCT FROM 'array'\n  OR jsonb_typeof(p_old_outputs->'facts') IS DISTINCT FROM 'array'\n  OR p_root_type IS NULL OR p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount')\n  OR p_old_outputs->>'root_type' IS DISTINCT FROM p_root_type\n  OR p_old_outputs->>'root_id' IS DISTINCT FROM p_old->>'id'\n  OR jsonb_typeof(p_old) IS DISTINCT FROM 'object' OR coalesce(p_old->>'id','')=''\n  OR jsonb_typeof(p_new) IS DISTINCT FROM 'object'\n  OR (p_old-ARRAY['name','description','labels','access_labels']) IS DISTINCT FROM\n     (p_new-ARRAY['name','description','labels','access_labels'])\n  OR p_old->'access_labels' IS NOT DISTINCT FROM p_new->'access_labels'\n  OR kaname.access_labels_valid_v1(p_new->'access_labels') IS DISTINCT FROM true\n",
  " facts jsonb; tuple_object text; tuple_user text; tuple_relation text; coordinate_key text;\n required jsonb:='{}'; graphs jsonb:='{}'; bindings jsonb:='{}'; coordinates jsonb:='{}';\n work integer:=0; root_id text;root_kind integer;root_model text;count_value integer;external_root boolean;\nBEGIN\n external_root:=p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount');\n root_id:=CASE WHEN external_root THEN p_old->>'object_id' ELSE p_old->>'id' END;\n root_kind:=CASE WHEN external_root THEN 2 ELSE 30 END;\n IF jsonb_typeof(p_index) IS DISTINCT FROM 'object'\n  OR jsonb_typeof(p_outputs) IS DISTINCT FROM 'object'\n  OR jsonb_typeof(p_old_outputs->'objects') IS DISTINCT FROM 'array'\n  OR jsonb_typeof(p_old_outputs->'facts') IS DISTINCT FROM 'array'\n  OR p_root_type IS NULL OR (external_root AND (p_root_type !~ '^[^.:#*[:space:][:cntrl:]]+[.][^.:#*[:space:][:cntrl:]]+$' OR split_part(p_root_type,'.',1)='iam'))\n  OR p_old_outputs->>'root_type' IS DISTINCT FROM p_root_type\n  OR p_old_outputs->>'root_id' IS DISTINCT FROM root_id\n  OR jsonb_typeof(p_old) IS DISTINCT FROM 'object' OR coalesce(root_id,'')=''\n  OR jsonb_typeof(p_new) IS DISTINCT FROM 'object'\n  OR (NOT external_root AND (p_old-ARRAY['name','description','labels','access_labels']) IS DISTINCT FROM\n     (p_new-ARRAY['name','description','labels','access_labels']))\n  OR (external_root AND (p_old->>'object_type' IS DISTINCT FROM p_root_type\n   OR (p_old-ARRAY['labels','access_labels']) IS DISTINCT FROM (p_new-ARRAY['labels','access_labels'])))\n  OR p_old->'access_labels' IS NOT DISTINCT FROM p_new->'access_labels'\n  OR kaname.access_labels_valid_v1(p_new->'access_labels') IS DISTINCT FROM true\n"
 ],
 [
  "   USING ERRCODE='42501';\n END IF;\n root_capture:=kaname._authority_resource_require_capture_v2(p_index,30,p_root_type,p_old->>'id');\n IF jsonb_array_length(root_capture->'states')<>1\n  OR root_capture#>'{states,0,2}' IS DISTINCT FROM p_old THEN\n",
  "   USING ERRCODE='42501';\n END IF;\n\n IF p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN\n  SELECT count(*),min(r->>'ObjectType') INTO count_value,root_model\n  FROM jsonb_array_elements(p_catalog#>'{Live,Resources}') r\n  WHERE (r->>'Module')||'.'||(r->>'Resource')=p_root_type AND r->>'Module'<>'iam';\n  IF count_value<>1 OR coalesce(root_model,'') !~ '^[a-z][a-z0-9_]*$' THEN\n   RAISE EXCEPTION 'external retention root live model unconfirmed' USING ERRCODE='42501';END IF;\n END IF;\n root_capture:=kaname._authority_resource_require_capture_v2(p_index,root_kind,p_root_type,root_id);\n IF jsonb_array_length(root_capture->'states')<>1\n  OR root_capture#>'{states,0,2}' IS DISTINCT FROM p_old THEN\n"
 ],
 [
  "  jsonb_build_array(f->>'object_type',f->>'object_id',f->>'relation',f->>'subject')::text,true),'{}')\n INTO facts FROM jsonb_array_elements(p_old_outputs->'facts') f;\n work:=jsonb_array_length(p_old_outputs->'facts');\n IF work>p_work THEN\n  RAISE EXCEPTION 'metadata retention plan fact budget exhausted' USING ERRCODE='54000';\n",
  "  jsonb_build_array(f->>'object_type',f->>'object_id',f->>'relation',f->>'subject')::text,true),'{}')\n INTO facts FROM jsonb_array_elements(p_old_outputs->'facts') f;\n work:=jsonb_array_length(p_old_outputs->'facts')+CASE WHEN external_root THEN 1 ELSE 0 END;\n IF work>p_work THEN\n  RAISE EXCEPTION 'metadata retention plan fact budget exhausted' USING ERRCODE='54000';\n"
 ],
 [
  "  ancestors:=kaname._authority_resource_ancestor_graph_v2(p_index,p_catalog,graph);\n  required:=required||(graph->'required')||(ancestors->'required');\n  IF graph->>'object_type'=p_root_type AND graph->>'object_id'=p_old->>'id' THEN\n   graph:=jsonb_set(graph,'{projection}',p_new);\n  END IF;\n  new_ancestors:='[]';\n  FOR ancestor IN SELECT value FROM jsonb_array_elements(ancestors->'ancestors') LOOP\n   IF ancestor->>'object_type'=p_root_type AND ancestor->>'object_id'=p_old->>'id' THEN\n    ancestor:=jsonb_set(ancestor,'{projection}',p_new);\n   END IF;\n",
  "  ancestors:=kaname._authority_resource_ancestor_graph_v2(p_index,p_catalog,graph);\n  required:=required||(graph->'required')||(ancestors->'required');\n  IF graph->>'object_type'=p_root_type AND graph->>'object_id'=root_id THEN\n   graph:=jsonb_set(graph,'{projection}',p_new);\n  END IF;\n  new_ancestors:='[]';\n  FOR ancestor IN SELECT value FROM jsonb_array_elements(ancestors->'ancestors') LOOP\n   IF ancestor->>'object_type'=p_root_type AND ancestor->>'object_id'=root_id THEN\n    ancestor:=jsonb_set(ancestor,'{projection}',p_new);\n   END IF;\n"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_retention_prepare_v1(jsonb,boolean,integer,integer,integer)','4e30808c3cd9bed41b0ad03446e0778037bc2b11a8fba1df60a57cbb034322d6','314631d2ffa09e89cf5240cfc47a028f3ac3d73ea07e8394cbae339727e637dc',
  $changes$[
 [
  " session_state jsonb; held jsonb; replay jsonb; census jsonb; source_index jsonb;\n root_type text; root_id text; old_row jsonb; new_row jsonb; holder_ids text[];\n bundle record; catalog_payload jsonb; invoker oid; frontiers jsonb; old_outputs jsonb;\n plan jsonb; inputs jsonb; packet jsonb; used_rows integer; used_reads integer; used_work integer;\n",
  " session_state jsonb; held jsonb; replay jsonb; census jsonb; source_index jsonb;\n root_type text; root_id text; old_row jsonb; new_row jsonb; holder_ids text[];\n external_root boolean;session_after jsonb;root_kind integer;root_model text;root_physical jsonb;\n bundle record; catalog_payload jsonb; invoker oid; frontiers jsonb; old_outputs jsonb;\n plan jsonb; inputs jsonb; packet jsonb; used_rows integer; used_reads integer; used_work integer;\n"
 ],
 [
  " old_row:=census->'old_root';\n new_row:=old_row||p_patch;\n IF root_type IS NULL OR root_id IS NULL OR root_id IS DISTINCT FROM old_row->>'id'\n  OR jsonb_typeof(census->'binding_ids') IS DISTINCT FROM 'array'\n  OR jsonb_typeof(replay->'frontier_witnesses') IS DISTINCT FROM 'object'\n",
  " old_row:=census->'old_root';\n new_row:=old_row||p_patch;\n external_root:=root_type NOT IN ('iam.account','iam.project','iam.serviceAccount');\n root_kind:=CASE WHEN external_root THEN 2 ELSE 30 END;\n root_model:=CASE root_type WHEN 'iam.account' THEN 'account' WHEN 'iam.project' THEN 'project'\n  WHEN 'iam.serviceAccount' THEN 'iam_service_account' ELSE census#>>'{root_scope_states,catalog,2,object_type}' END;\n root_physical:=held->'root_physical';\n IF root_type IS NULL OR root_id IS NULL\n  OR (NOT external_root AND root_id IS DISTINCT FROM old_row->>'id')\n  OR (external_root AND (old_row->>'object_type' IS DISTINCT FROM root_type\n   OR old_row->>'object_id' IS DISTINCT FROM root_id\n   OR coalesce(root_model,'') !~ '^[a-z][a-z0-9_]*$'))\n  OR jsonb_typeof(census->'binding_ids') IS DISTINCT FROM 'array'\n  OR jsonb_typeof(replay->'frontier_witnesses') IS DISTINCT FROM 'object'\n"
 ],
 [
  "  OR jsonb_typeof(held->'root_physical') IS DISTINCT FROM 'object' THEN\n  RAISE EXCEPTION 'metadata retention held replay incomplete' USING ERRCODE='42501';\n END IF;\n SELECT coalesce(array_agg(b.id ORDER BY b.id COLLATE \"C\"),ARRAY[]::text[])\n",
  "  OR jsonb_typeof(held->'root_physical') IS DISTINCT FROM 'object' THEN\n  RAISE EXCEPTION 'metadata retention held replay incomplete' USING ERRCODE='42501';\n END IF;\n IF external_root THEN\n  -- Hold добавил единственный receipt; сравнение остальных полей не ослабляем.\n  IF p_rows-used_rows<2 OR p_reads-used_reads<2 OR p_work-used_work<2 THEN\n   RAISE EXCEPTION 'external retention receipt budget exhausted' USING ERRCODE='54000';END IF;\n  session_after:=kaname._authority_metadata_access_label_stashed_v1();\n  used_rows:=used_rows+2;used_reads:=used_reads+2;used_work:=used_work+2;\n  IF (session_after-'registration_binding_holds') IS DISTINCT FROM session_state\n   OR jsonb_typeof(session_after->'registration_binding_holds') IS DISTINCT FROM 'object' THEN\n   RAISE EXCEPTION 'external retention custody changed outside hold receipt' USING ERRCODE='42501';END IF;\n  PERFORM kaname._authority_metadata_registration_binding_check_v1(root_model,root_id);\n  session_state:=session_after;\n  root_physical:=root_physical||jsonb_build_object('object_type',root_type);\n END IF;\n SELECT coalesce(array_agg(b.id ORDER BY b.id COLLATE \"C\"),ARRAY[]::text[])\n"
 ],
 [
  "  'source_index',source_index,'catalog',catalog_payload,'plan',plan,\n  'partition_required',old_outputs#>'{partition,required}','candidate_facts',old_outputs->'facts',\n  'root_physical',held->'root_physical','root_type',root_type,'root_id',root_id,\n  'old_row',old_row,'new_row',new_row);\n IF octet_length(packet::text)>67108864 THEN\n",
  "  'source_index',source_index,'catalog',catalog_payload,'plan',plan,\n  'partition_required',old_outputs#>'{partition,required}','candidate_facts',old_outputs->'facts',\n  'root_physical',root_physical,'root_type',root_type,'root_id',root_id,\n  'root_source_kind',root_kind,'root_model',root_model,\n  'old_row',old_row,'new_row',new_row);\n IF octet_length(packet::text)>67108864 THEN\n"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_retention_compile_v1(jsonb,integer)','e9e490723a1273c03f346f99033671548f6249b6ef1951736797267638b0db87','487d87c466857c875ec06e6c26d27f4c8dd15aef19522d2b11b52cbc6c9043b1',
  $changes$[
 [
  "DECLARE\n session_state jsonb; packet jsonb; certificate jsonb; required jsonb;\n sources jsonb; root_key text; used_work integer;\nBEGIN\n PERFORM kaname.authority_protocol_require_owner();\n",
  "DECLARE\n session_state jsonb; packet jsonb; certificate jsonb; required jsonb;\n sources jsonb; root_key text; used_work integer;root_kind integer;binding_key text;receipt_cost integer:=0;\nBEGIN\n PERFORM kaname.authority_protocol_require_owner();\n"
 ],
 [
  "  RAISE EXCEPTION 'metadata retention owner packet unavailable' USING ERRCODE='42501';\n END IF;\n certificate:=kaname._authority_metadata_access_label_retention_certify_v1(\n  packet->'source_index',packet->'catalog',packet->'plan',p_desired,p_work);\n root_key:=jsonb_build_array(30,packet->>'root_type',packet->>'root_id','')::text;\n required:=(packet->'partition_required')||(certificate->'required')||jsonb_build_object(root_key,true);\n sources:=kaname._authority_resource_object_physical_sources_v2(packet->'source_index',required);\n used_work:=(certificate->>'work')::integer+(sources->>'work')::integer;\n IF used_work>p_work THEN\n  RAISE EXCEPTION 'metadata retention shared compile budget exhausted' USING ERRCODE='54000';\n",
  "  RAISE EXCEPTION 'metadata retention owner packet unavailable' USING ERRCODE='42501';\n END IF;\n IF packet->>'root_type' NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN receipt_cost:=1;END IF;\n IF p_work<receipt_cost THEN\n  RAISE EXCEPTION 'retention compile receipt budget exhausted' USING ERRCODE='54000';END IF;\n certificate:=kaname._authority_metadata_access_label_retention_certify_v1(\n  packet->'source_index',packet->'catalog',packet->'plan',p_desired,p_work-receipt_cost);\n root_kind:=CASE WHEN packet->>'root_type' IN ('iam.account','iam.project','iam.serviceAccount') THEN 30 ELSE 2 END;\n IF packet->>'root_source_kind' IS DISTINCT FROM root_kind::text THEN\n  RAISE EXCEPTION 'retention root physical kind differs' USING ERRCODE='42501';END IF;\n root_key:=jsonb_build_array(root_kind,packet->>'root_type',packet->>'root_id','')::text;\n IF root_kind=2 THEN\n  PERFORM kaname._authority_metadata_registration_binding_check_v1(packet->>'root_model',packet->>'root_id');\n  binding_key:=jsonb_build_array(5,packet->>'root_model',packet->>'root_id','')::text;\n  IF NOT (packet->'source_index') ? binding_key\n   OR packet#>>'{root_physical,object_type}' IS DISTINCT FROM packet->>'root_type' THEN\n   RAISE EXCEPTION 'external retention held binding or root missing' USING ERRCODE='42501';END IF;\n END IF;\n required:=(packet->'partition_required')||(certificate->'required')||jsonb_build_object(root_key,true);\n IF binding_key IS NOT NULL THEN required:=required||jsonb_build_object(binding_key,true);END IF;\n sources:=kaname._authority_resource_object_physical_sources_v2(packet->'source_index',required);\n used_work:=receipt_cost+(certificate->>'work')::integer+(sources->>'work')::integer;\n IF used_work>p_work THEN\n  RAISE EXCEPTION 'metadata retention shared compile budget exhausted' USING ERRCODE='54000';\n"
 ],
 [
  "   'folded',jsonb_build_object('facts',sources->'facts')),\n  'root_physical',packet->'root_physical','old_row',packet->'old_row','new_row',packet->'new_row',\n  'rows',1,'reads',1,'work',used_work);\nEND;\n",
  "   'folded',jsonb_build_object('facts',sources->'facts')),\n  'root_physical',packet->'root_physical','old_row',packet->'old_row','new_row',packet->'new_row',\n  'rows',1+receipt_cost,'reads',1+receipt_cost,'work',used_work);\nEND;\n"
 ]
]$changes$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','7eb9e29bfec2e5c9fc457bf0818b2489f7d0faaa25838f74324bc4e04608432a','1a797d8c04e211d3e078b22128d2f5018b853a91792f4fa21a37a1679be6945a',
  $changes$[
 [
  "f4367d9db5c32b4da4d5a364a244aa7d7e1437a50d9cc4622e69a7a89f03ec26",
  "4654a6cb62d92fbdfcc2e0db90b7f2c1fc1580c505a2c03b6c2bbef54ce3a497"
 ],
 [
  "33d20a2c1b37c3edee7949d1df8390bf2f26c31d4cd65ecc82c8dd4e1aa5ffa5",
  "2c1f7492f38356a22db5a5dde186fb3b2337e51a27a265be46ca7e2eef4bb723"
 ],
 [
  "5afba290c6900e52f68700275d833d3f1af86d856f21d8f43fa7bf19892cc586",
  "683ae6d0a044bc052e330bd1e75ac39b1541bf416ec6438ffce437d1359e4fb7"
 ],
 [
  "4e30808c3cd9bed41b0ad03446e0778037bc2b11a8fba1df60a57cbb034322d6",
  "314631d2ffa09e89cf5240cfc47a028f3ac3d73ea07e8394cbae339727e637dc"
 ],
 [
  "e9e490723a1273c03f346f99033671548f6249b6ef1951736797267638b0db87",
  "487d87c466857c875ec06e6c26d27f4c8dd15aef19522d2b11b52cbc6c9043b1"
 ]
]$changes$::jsonb),
 ('authority_metadata_service_account_access_label_ready_v1()','d52e5eaea50e84d85a750ac5f81c0162cf5e50f186be99b673f6c940e7e470ca','bbee2b2d3b3aaf8dd45fa0ec16a518d032e3360a6fec5a4ddd08fe899e6d55a1',
  $changes$[
 [
  "f4367d9db5c32b4da4d5a364a244aa7d7e1437a50d9cc4622e69a7a89f03ec26",
  "4654a6cb62d92fbdfcc2e0db90b7f2c1fc1580c505a2c03b6c2bbef54ce3a497"
 ],
 [
  "33d20a2c1b37c3edee7949d1df8390bf2f26c31d4cd65ecc82c8dd4e1aa5ffa5",
  "2c1f7492f38356a22db5a5dde186fb3b2337e51a27a265be46ca7e2eef4bb723"
 ],
 [
  "5afba290c6900e52f68700275d833d3f1af86d856f21d8f43fa7bf19892cc586",
  "683ae6d0a044bc052e330bd1e75ac39b1541bf416ec6438ffce437d1359e4fb7"
 ],
 [
  "7eb9e29bfec2e5c9fc457bf0818b2489f7d0faaa25838f74324bc4e04608432a",
  "1a797d8c04e211d3e078b22128d2f5018b853a91792f4fa21a37a1679be6945a"
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
 ('authority_metadata_service_account_access_label_ready_v1()','bbee2b2d3b3aaf8dd45fa0ec16a518d032e3360a6fec5a4ddd08fe899e6d55a1','d52e5eaea50e84d85a750ac5f81c0162cf5e50f186be99b673f6c940e7e470ca',
  $changes$[
 [
  "1a797d8c04e211d3e078b22128d2f5018b853a91792f4fa21a37a1679be6945a",
  "7eb9e29bfec2e5c9fc457bf0818b2489f7d0faaa25838f74324bc4e04608432a"
 ],
 [
  "683ae6d0a044bc052e330bd1e75ac39b1541bf416ec6438ffce437d1359e4fb7",
  "5afba290c6900e52f68700275d833d3f1af86d856f21d8f43fa7bf19892cc586"
 ],
 [
  "2c1f7492f38356a22db5a5dde186fb3b2337e51a27a265be46ca7e2eef4bb723",
  "33d20a2c1b37c3edee7949d1df8390bf2f26c31d4cd65ecc82c8dd4e1aa5ffa5"
 ],
 [
  "4654a6cb62d92fbdfcc2e0db90b7f2c1fc1580c505a2c03b6c2bbef54ce3a497",
  "f4367d9db5c32b4da4d5a364a244aa7d7e1437a50d9cc4622e69a7a89f03ec26"
 ]
]$changes$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','1a797d8c04e211d3e078b22128d2f5018b853a91792f4fa21a37a1679be6945a','7eb9e29bfec2e5c9fc457bf0818b2489f7d0faaa25838f74324bc4e04608432a',
  $changes$[
 [
  "487d87c466857c875ec06e6c26d27f4c8dd15aef19522d2b11b52cbc6c9043b1",
  "e9e490723a1273c03f346f99033671548f6249b6ef1951736797267638b0db87"
 ],
 [
  "314631d2ffa09e89cf5240cfc47a028f3ac3d73ea07e8394cbae339727e637dc",
  "4e30808c3cd9bed41b0ad03446e0778037bc2b11a8fba1df60a57cbb034322d6"
 ],
 [
  "683ae6d0a044bc052e330bd1e75ac39b1541bf416ec6438ffce437d1359e4fb7",
  "5afba290c6900e52f68700275d833d3f1af86d856f21d8f43fa7bf19892cc586"
 ],
 [
  "2c1f7492f38356a22db5a5dde186fb3b2337e51a27a265be46ca7e2eef4bb723",
  "33d20a2c1b37c3edee7949d1df8390bf2f26c31d4cd65ecc82c8dd4e1aa5ffa5"
 ],
 [
  "4654a6cb62d92fbdfcc2e0db90b7f2c1fc1580c505a2c03b6c2bbef54ce3a497",
  "f4367d9db5c32b4da4d5a364a244aa7d7e1437a50d9cc4622e69a7a89f03ec26"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_retention_compile_v1(jsonb,integer)','487d87c466857c875ec06e6c26d27f4c8dd15aef19522d2b11b52cbc6c9043b1','e9e490723a1273c03f346f99033671548f6249b6ef1951736797267638b0db87',
  $changes$[
 [
  "   'folded',jsonb_build_object('facts',sources->'facts')),\n  'root_physical',packet->'root_physical','old_row',packet->'old_row','new_row',packet->'new_row',\n  'rows',1+receipt_cost,'reads',1+receipt_cost,'work',used_work);\nEND;\n",
  "   'folded',jsonb_build_object('facts',sources->'facts')),\n  'root_physical',packet->'root_physical','old_row',packet->'old_row','new_row',packet->'new_row',\n  'rows',1,'reads',1,'work',used_work);\nEND;\n"
 ],
 [
  "  RAISE EXCEPTION 'metadata retention owner packet unavailable' USING ERRCODE='42501';\n END IF;\n IF packet->>'root_type' NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN receipt_cost:=1;END IF;\n IF p_work<receipt_cost THEN\n  RAISE EXCEPTION 'retention compile receipt budget exhausted' USING ERRCODE='54000';END IF;\n certificate:=kaname._authority_metadata_access_label_retention_certify_v1(\n  packet->'source_index',packet->'catalog',packet->'plan',p_desired,p_work-receipt_cost);\n root_kind:=CASE WHEN packet->>'root_type' IN ('iam.account','iam.project','iam.serviceAccount') THEN 30 ELSE 2 END;\n IF packet->>'root_source_kind' IS DISTINCT FROM root_kind::text THEN\n  RAISE EXCEPTION 'retention root physical kind differs' USING ERRCODE='42501';END IF;\n root_key:=jsonb_build_array(root_kind,packet->>'root_type',packet->>'root_id','')::text;\n IF root_kind=2 THEN\n  PERFORM kaname._authority_metadata_registration_binding_check_v1(packet->>'root_model',packet->>'root_id');\n  binding_key:=jsonb_build_array(5,packet->>'root_model',packet->>'root_id','')::text;\n  IF NOT (packet->'source_index') ? binding_key\n   OR packet#>>'{root_physical,object_type}' IS DISTINCT FROM packet->>'root_type' THEN\n   RAISE EXCEPTION 'external retention held binding or root missing' USING ERRCODE='42501';END IF;\n END IF;\n required:=(packet->'partition_required')||(certificate->'required')||jsonb_build_object(root_key,true);\n IF binding_key IS NOT NULL THEN required:=required||jsonb_build_object(binding_key,true);END IF;\n sources:=kaname._authority_resource_object_physical_sources_v2(packet->'source_index',required);\n used_work:=receipt_cost+(certificate->>'work')::integer+(sources->>'work')::integer;\n IF used_work>p_work THEN\n  RAISE EXCEPTION 'metadata retention shared compile budget exhausted' USING ERRCODE='54000';\n",
  "  RAISE EXCEPTION 'metadata retention owner packet unavailable' USING ERRCODE='42501';\n END IF;\n certificate:=kaname._authority_metadata_access_label_retention_certify_v1(\n  packet->'source_index',packet->'catalog',packet->'plan',p_desired,p_work);\n root_key:=jsonb_build_array(30,packet->>'root_type',packet->>'root_id','')::text;\n required:=(packet->'partition_required')||(certificate->'required')||jsonb_build_object(root_key,true);\n sources:=kaname._authority_resource_object_physical_sources_v2(packet->'source_index',required);\n used_work:=(certificate->>'work')::integer+(sources->>'work')::integer;\n IF used_work>p_work THEN\n  RAISE EXCEPTION 'metadata retention shared compile budget exhausted' USING ERRCODE='54000';\n"
 ],
 [
  "DECLARE\n session_state jsonb; packet jsonb; certificate jsonb; required jsonb;\n sources jsonb; root_key text; used_work integer;root_kind integer;binding_key text;receipt_cost integer:=0;\nBEGIN\n PERFORM kaname.authority_protocol_require_owner();\n",
  "DECLARE\n session_state jsonb; packet jsonb; certificate jsonb; required jsonb;\n sources jsonb; root_key text; used_work integer;\nBEGIN\n PERFORM kaname.authority_protocol_require_owner();\n"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_retention_prepare_v1(jsonb,boolean,integer,integer,integer)','314631d2ffa09e89cf5240cfc47a028f3ac3d73ea07e8394cbae339727e637dc','4e30808c3cd9bed41b0ad03446e0778037bc2b11a8fba1df60a57cbb034322d6',
  $changes$[
 [
  "  'source_index',source_index,'catalog',catalog_payload,'plan',plan,\n  'partition_required',old_outputs#>'{partition,required}','candidate_facts',old_outputs->'facts',\n  'root_physical',root_physical,'root_type',root_type,'root_id',root_id,\n  'root_source_kind',root_kind,'root_model',root_model,\n  'old_row',old_row,'new_row',new_row);\n IF octet_length(packet::text)>67108864 THEN\n",
  "  'source_index',source_index,'catalog',catalog_payload,'plan',plan,\n  'partition_required',old_outputs#>'{partition,required}','candidate_facts',old_outputs->'facts',\n  'root_physical',held->'root_physical','root_type',root_type,'root_id',root_id,\n  'old_row',old_row,'new_row',new_row);\n IF octet_length(packet::text)>67108864 THEN\n"
 ],
 [
  "  OR jsonb_typeof(held->'root_physical') IS DISTINCT FROM 'object' THEN\n  RAISE EXCEPTION 'metadata retention held replay incomplete' USING ERRCODE='42501';\n END IF;\n IF external_root THEN\n  -- Hold добавил единственный receipt; сравнение остальных полей не ослабляем.\n  IF p_rows-used_rows<2 OR p_reads-used_reads<2 OR p_work-used_work<2 THEN\n   RAISE EXCEPTION 'external retention receipt budget exhausted' USING ERRCODE='54000';END IF;\n  session_after:=kaname._authority_metadata_access_label_stashed_v1();\n  used_rows:=used_rows+2;used_reads:=used_reads+2;used_work:=used_work+2;\n  IF (session_after-'registration_binding_holds') IS DISTINCT FROM session_state\n   OR jsonb_typeof(session_after->'registration_binding_holds') IS DISTINCT FROM 'object' THEN\n   RAISE EXCEPTION 'external retention custody changed outside hold receipt' USING ERRCODE='42501';END IF;\n  PERFORM kaname._authority_metadata_registration_binding_check_v1(root_model,root_id);\n  session_state:=session_after;\n  root_physical:=root_physical||jsonb_build_object('object_type',root_type);\n END IF;\n SELECT coalesce(array_agg(b.id ORDER BY b.id COLLATE \"C\"),ARRAY[]::text[])\n",
  "  OR jsonb_typeof(held->'root_physical') IS DISTINCT FROM 'object' THEN\n  RAISE EXCEPTION 'metadata retention held replay incomplete' USING ERRCODE='42501';\n END IF;\n SELECT coalesce(array_agg(b.id ORDER BY b.id COLLATE \"C\"),ARRAY[]::text[])\n"
 ],
 [
  " old_row:=census->'old_root';\n new_row:=old_row||p_patch;\n external_root:=root_type NOT IN ('iam.account','iam.project','iam.serviceAccount');\n root_kind:=CASE WHEN external_root THEN 2 ELSE 30 END;\n root_model:=CASE root_type WHEN 'iam.account' THEN 'account' WHEN 'iam.project' THEN 'project'\n  WHEN 'iam.serviceAccount' THEN 'iam_service_account' ELSE census#>>'{root_scope_states,catalog,2,object_type}' END;\n root_physical:=held->'root_physical';\n IF root_type IS NULL OR root_id IS NULL\n  OR (NOT external_root AND root_id IS DISTINCT FROM old_row->>'id')\n  OR (external_root AND (old_row->>'object_type' IS DISTINCT FROM root_type\n   OR old_row->>'object_id' IS DISTINCT FROM root_id\n   OR coalesce(root_model,'') !~ '^[a-z][a-z0-9_]*$'))\n  OR jsonb_typeof(census->'binding_ids') IS DISTINCT FROM 'array'\n  OR jsonb_typeof(replay->'frontier_witnesses') IS DISTINCT FROM 'object'\n",
  " old_row:=census->'old_root';\n new_row:=old_row||p_patch;\n IF root_type IS NULL OR root_id IS NULL OR root_id IS DISTINCT FROM old_row->>'id'\n  OR jsonb_typeof(census->'binding_ids') IS DISTINCT FROM 'array'\n  OR jsonb_typeof(replay->'frontier_witnesses') IS DISTINCT FROM 'object'\n"
 ],
 [
  " session_state jsonb; held jsonb; replay jsonb; census jsonb; source_index jsonb;\n root_type text; root_id text; old_row jsonb; new_row jsonb; holder_ids text[];\n external_root boolean;session_after jsonb;root_kind integer;root_model text;root_physical jsonb;\n bundle record; catalog_payload jsonb; invoker oid; frontiers jsonb; old_outputs jsonb;\n plan jsonb; inputs jsonb; packet jsonb; used_rows integer; used_reads integer; used_work integer;\n",
  " session_state jsonb; held jsonb; replay jsonb; census jsonb; source_index jsonb;\n root_type text; root_id text; old_row jsonb; new_row jsonb; holder_ids text[];\n bundle record; catalog_payload jsonb; invoker oid; frontiers jsonb; old_outputs jsonb;\n plan jsonb; inputs jsonb; packet jsonb; used_rows integer; used_reads integer; used_work integer;\n"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_retention_plan_v1(jsonb,jsonb,jsonb,jsonb,text,jsonb,jsonb,integer)','683ae6d0a044bc052e330bd1e75ac39b1541bf416ec6438ffce437d1359e4fb7','5afba290c6900e52f68700275d833d3f1af86d856f21d8f43fa7bf19892cc586',
  $changes$[
 [
  "  ancestors:=kaname._authority_resource_ancestor_graph_v2(p_index,p_catalog,graph);\n  required:=required||(graph->'required')||(ancestors->'required');\n  IF graph->>'object_type'=p_root_type AND graph->>'object_id'=root_id THEN\n   graph:=jsonb_set(graph,'{projection}',p_new);\n  END IF;\n  new_ancestors:='[]';\n  FOR ancestor IN SELECT value FROM jsonb_array_elements(ancestors->'ancestors') LOOP\n   IF ancestor->>'object_type'=p_root_type AND ancestor->>'object_id'=root_id THEN\n    ancestor:=jsonb_set(ancestor,'{projection}',p_new);\n   END IF;\n",
  "  ancestors:=kaname._authority_resource_ancestor_graph_v2(p_index,p_catalog,graph);\n  required:=required||(graph->'required')||(ancestors->'required');\n  IF graph->>'object_type'=p_root_type AND graph->>'object_id'=p_old->>'id' THEN\n   graph:=jsonb_set(graph,'{projection}',p_new);\n  END IF;\n  new_ancestors:='[]';\n  FOR ancestor IN SELECT value FROM jsonb_array_elements(ancestors->'ancestors') LOOP\n   IF ancestor->>'object_type'=p_root_type AND ancestor->>'object_id'=p_old->>'id' THEN\n    ancestor:=jsonb_set(ancestor,'{projection}',p_new);\n   END IF;\n"
 ],
 [
  "  jsonb_build_array(f->>'object_type',f->>'object_id',f->>'relation',f->>'subject')::text,true),'{}')\n INTO facts FROM jsonb_array_elements(p_old_outputs->'facts') f;\n work:=jsonb_array_length(p_old_outputs->'facts')+CASE WHEN external_root THEN 1 ELSE 0 END;\n IF work>p_work THEN\n  RAISE EXCEPTION 'metadata retention plan fact budget exhausted' USING ERRCODE='54000';\n",
  "  jsonb_build_array(f->>'object_type',f->>'object_id',f->>'relation',f->>'subject')::text,true),'{}')\n INTO facts FROM jsonb_array_elements(p_old_outputs->'facts') f;\n work:=jsonb_array_length(p_old_outputs->'facts');\n IF work>p_work THEN\n  RAISE EXCEPTION 'metadata retention plan fact budget exhausted' USING ERRCODE='54000';\n"
 ],
 [
  "   USING ERRCODE='42501';\n END IF;\n\n IF p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN\n  SELECT count(*),min(r->>'ObjectType') INTO count_value,root_model\n  FROM jsonb_array_elements(p_catalog#>'{Live,Resources}') r\n  WHERE (r->>'Module')||'.'||(r->>'Resource')=p_root_type AND r->>'Module'<>'iam';\n  IF count_value<>1 OR coalesce(root_model,'') !~ '^[a-z][a-z0-9_]*$' THEN\n   RAISE EXCEPTION 'external retention root live model unconfirmed' USING ERRCODE='42501';END IF;\n END IF;\n root_capture:=kaname._authority_resource_require_capture_v2(p_index,root_kind,p_root_type,root_id);\n IF jsonb_array_length(root_capture->'states')<>1\n  OR root_capture#>'{states,0,2}' IS DISTINCT FROM p_old THEN\n",
  "   USING ERRCODE='42501';\n END IF;\n root_capture:=kaname._authority_resource_require_capture_v2(p_index,30,p_root_type,p_old->>'id');\n IF jsonb_array_length(root_capture->'states')<>1\n  OR root_capture#>'{states,0,2}' IS DISTINCT FROM p_old THEN\n"
 ],
 [
  " facts jsonb; tuple_object text; tuple_user text; tuple_relation text; coordinate_key text;\n required jsonb:='{}'; graphs jsonb:='{}'; bindings jsonb:='{}'; coordinates jsonb:='{}';\n work integer:=0; root_id text;root_kind integer;root_model text;count_value integer;external_root boolean;\nBEGIN\n external_root:=p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount');\n root_id:=CASE WHEN external_root THEN p_old->>'object_id' ELSE p_old->>'id' END;\n root_kind:=CASE WHEN external_root THEN 2 ELSE 30 END;\n IF jsonb_typeof(p_index) IS DISTINCT FROM 'object'\n  OR jsonb_typeof(p_outputs) IS DISTINCT FROM 'object'\n  OR jsonb_typeof(p_old_outputs->'objects') IS DISTINCT FROM 'array'\n  OR jsonb_typeof(p_old_outputs->'facts') IS DISTINCT FROM 'array'\n  OR p_root_type IS NULL OR (external_root AND (p_root_type !~ '^[^.:#*[:space:][:cntrl:]]+[.][^.:#*[:space:][:cntrl:]]+$' OR split_part(p_root_type,'.',1)='iam'))\n  OR p_old_outputs->>'root_type' IS DISTINCT FROM p_root_type\n  OR p_old_outputs->>'root_id' IS DISTINCT FROM root_id\n  OR jsonb_typeof(p_old) IS DISTINCT FROM 'object' OR coalesce(root_id,'')=''\n  OR jsonb_typeof(p_new) IS DISTINCT FROM 'object'\n  OR (NOT external_root AND (p_old-ARRAY['name','description','labels','access_labels']) IS DISTINCT FROM\n     (p_new-ARRAY['name','description','labels','access_labels']))\n  OR (external_root AND (p_old->>'object_type' IS DISTINCT FROM p_root_type\n   OR (p_old-ARRAY['labels','access_labels']) IS DISTINCT FROM (p_new-ARRAY['labels','access_labels'])))\n  OR p_old->'access_labels' IS NOT DISTINCT FROM p_new->'access_labels'\n  OR kaname.access_labels_valid_v1(p_new->'access_labels') IS DISTINCT FROM true\n",
  " facts jsonb; tuple_object text; tuple_user text; tuple_relation text; coordinate_key text;\n required jsonb:='{}'; graphs jsonb:='{}'; bindings jsonb:='{}'; coordinates jsonb:='{}';\n work integer:=0;\nBEGIN\n IF jsonb_typeof(p_index) IS DISTINCT FROM 'object'\n  OR jsonb_typeof(p_outputs) IS DISTINCT FROM 'object'\n  OR jsonb_typeof(p_old_outputs->'objects') IS DISTINCT FROM 'array'\n  OR jsonb_typeof(p_old_outputs->'facts') IS DISTINCT FROM 'array'\n  OR p_root_type IS NULL OR p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount')\n  OR p_old_outputs->>'root_type' IS DISTINCT FROM p_root_type\n  OR p_old_outputs->>'root_id' IS DISTINCT FROM p_old->>'id'\n  OR jsonb_typeof(p_old) IS DISTINCT FROM 'object' OR coalesce(p_old->>'id','')=''\n  OR jsonb_typeof(p_new) IS DISTINCT FROM 'object'\n  OR (p_old-ARRAY['name','description','labels','access_labels']) IS DISTINCT FROM\n     (p_new-ARRAY['name','description','labels','access_labels'])\n  OR p_old->'access_labels' IS NOT DISTINCT FROM p_new->'access_labels'\n  OR kaname.access_labels_valid_v1(p_new->'access_labels') IS DISTINCT FROM true\n"
 ]
]$changes$::jsonb),
 ('_authority_access_label_old_facts_v2(text,text,text[],jsonb,jsonb,jsonb,integer,integer)','2c1f7492f38356a22db5a5dde186fb3b2337e51a27a265be46ca7e2eef4bb723','33d20a2c1b37c3edee7949d1df8390bf2f26c31d4cd65ecc82c8dd4e1aa5ffa5',
  $changes$[
 [
  " IF jsonb_typeof(state) IS DISTINCT FROM 'array' OR jsonb_array_length(state)<>3\n OR coalesce(state->>0,'')='' OR coalesce(state->>1,'')=''\n OR jsonb_typeof(row_value) IS DISTINCT FROM 'object'\n OR (p_root_type IN ('iam.account','iam.project','iam.serviceAccount') AND row_value->>'id' IS DISTINCT FROM p_root_id)\n OR (p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') AND (row_value->>'object_type' IS DISTINCT FROM p_root_type\n  OR row_value->>'object_id' IS DISTINCT FROM p_root_id))\n OR kaname.access_labels_valid_v1(row_value->'access_labels') IS DISTINCT FROM true THEN\n  RAISE EXCEPTION 'access label old root physical image missing' USING ERRCODE='42501';END IF;\n",
  " IF jsonb_typeof(state) IS DISTINCT FROM 'array' OR jsonb_array_length(state)<>3\n OR coalesce(state->>0,'')='' OR coalesce(state->>1,'')=''\n OR jsonb_typeof(row_value) IS DISTINCT FROM 'object' OR row_value->>'id' IS DISTINCT FROM p_root_id\n OR kaname.access_labels_valid_v1(row_value->'access_labels') IS DISTINCT FROM true THEN\n  RAISE EXCEPTION 'access label old root physical image missing' USING ERRCODE='42501';END IF;\n"
 ],
 [
  " OR cardinality(p_bindings)<>(SELECT count(DISTINCT b COLLATE \"C\") FROM unnest(p_bindings) b) THEN\n  RAISE EXCEPTION 'access label old output input invalid' USING ERRCODE='42501';END IF;\n root:=kaname._authority_resource_require_capture_v2(p_index,\n  CASE WHEN p_root_type IN ('iam.account','iam.project','iam.serviceAccount') THEN 30 ELSE 2 END,p_root_type,p_root_id);\n IF jsonb_array_length(root->'states')<>1 THEN\n  RAISE EXCEPTION 'access label old root missing' USING ERRCODE='42501';END IF;\n",
  " OR cardinality(p_bindings)<>(SELECT count(DISTINCT b COLLATE \"C\") FROM unnest(p_bindings) b) THEN\n  RAISE EXCEPTION 'access label old output input invalid' USING ERRCODE='42501';END IF;\n root:=kaname._authority_resource_require_capture_v2(p_index,30,p_root_type,p_root_id);\n IF jsonb_array_length(root->'states')<>1 THEN\n  RAISE EXCEPTION 'access label old root missing' USING ERRCODE='42501';END IF;\n"
 ],
 [
  " used integer:=0; work integer:=0; n integer;partition jsonb;\nBEGIN\n IF p_root_type IS NULL OR (p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') AND (p_root_type !~ '^[^.:#*[:space:][:cntrl:]]+[.][^.:#*[:space:][:cntrl:]]+$' OR split_part(p_root_type,'.',1)='iam'))\n OR p_root_id IS NULL OR p_root_id='' OR p_bindings IS NULL\n OR cardinality(p_bindings)>4096 OR jsonb_typeof(p_index) IS DISTINCT FROM 'object'\n",
  " used integer:=0; work integer:=0; n integer;partition jsonb;\nBEGIN\n IF p_root_type IS NULL OR p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount')\n OR p_root_id IS NULL OR p_root_id='' OR p_bindings IS NULL\n OR cardinality(p_bindings)>4096 OR jsonb_typeof(p_index) IS DISTINCT FROM 'object'\n"
 ]
]$changes$::jsonb),
 ('_authority_access_label_member_partition_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer)','4654a6cb62d92fbdfcc2e0db90b7f2c1fc1580c505a2c03b6c2bbef54ce3a497','f4367d9db5c32b4da4d5a364a244aa7d7e1437a50d9cc4622e69a7a89f03ec26',
  $changes$[
 [
  "  RAISE EXCEPTION 'protected member partition input invalid' USING ERRCODE='42501';END IF;\n root_model:=CASE p_root_type WHEN 'iam.account' THEN 'account' WHEN 'iam.project' THEN 'project' WHEN 'iam.serviceAccount' THEN 'iam_service_account' END;\n IF p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN\n  SELECT count(*),min(r->>'ObjectType') INTO count_value,root_model\n  FROM jsonb_array_elements(p_catalog#>'{Live,Resources}') r\n  WHERE (r->>'Module')||'.'||(r->>'Resource')=p_root_type AND r->>'Module'<>'iam';\n  IF count_value<>1 OR coalesce(root_model,'') !~ '^[a-z][a-z0-9_]*$' THEN\n   RAISE EXCEPTION 'external retention root live model unconfirmed' USING ERRCODE='42501';END IF;\n END IF;\n\n IF p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN\n  work:=work+1;\n  IF work>p_work THEN RAISE EXCEPTION 'external retention root mapping budget exhausted' USING ERRCODE='54000';END IF;\n END IF;\n -- Добавляем координаты из журнала, в том числе без текущего участника.\n -- required сохраняет полные удержанные предикаты.\n",
  "  RAISE EXCEPTION 'protected member partition input invalid' USING ERRCODE='42501';END IF;\n root_model:=CASE p_root_type WHEN 'iam.account' THEN 'account' WHEN 'iam.project' THEN 'project' WHEN 'iam.serviceAccount' THEN 'iam_service_account' END;\n -- Добавляем координаты из журнала, в том числе без текущего участника.\n -- required сохраняет полные удержанные предикаты.\n"
 ],
 [
  " model text;root_model text;key_value text;used integer:=0;work integer:=0;count_value integer;\nBEGIN\n IF p_root_type IS NULL OR (p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') AND (p_root_type !~ '^[^.:#*[:space:][:cntrl:]]+[.][^.:#*[:space:][:cntrl:]]+$' OR split_part(p_root_type,'.',1)='iam')) OR coalesce(p_root_id,'')=''\n OR p_bindings IS NULL OR cardinality(p_bindings)>4096\n OR jsonb_typeof(p_index) IS DISTINCT FROM 'object' OR jsonb_typeof(p_frontiers) IS DISTINCT FROM 'object'\n",
  " model text;root_model text;key_value text;used integer:=0;work integer:=0;count_value integer;\nBEGIN\n IF p_root_type IS NULL OR p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') OR coalesce(p_root_id,'')=''\n OR p_bindings IS NULL OR cardinality(p_bindings)>4096\n OR jsonb_typeof(p_index) IS DISTINCT FROM 'object' OR jsonb_typeof(p_frontiers) IS DISTINCT FROM 'object'\n"
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
