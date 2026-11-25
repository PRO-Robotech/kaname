-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Читаем полный снимок внешнего поколения по актуальной и снятой записи каталога.
-- Закрытие внешних поколений допускается отдельной программой владельца.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_external_aliases_v1(p_model text,p_rows integer)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $aliases$
DECLARE invoker oid; aliases jsonb; found_rows integer;
BEGIN
 SELECT r.oid INTO STRICT invoker FROM pg_catalog.pg_roles r
 WHERE r.rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 IF NOT coalesce(has_table_privilege(invoker,'kaname.catalog_resource'::regclass,'SELECT'),false)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c
  WHERE c.oid='kaname.catalog_resource'::regclass AND c.relkind='r' AND c.relpersistence='p'
   AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND NOT c.relispartition
   AND NOT c.relhassubclass AND NOT c.relhasrules) THEN
  RAISE EXCEPTION 'external generation requires original catalog read access and ordinary source' USING ERRCODE='42501';END IF;
 IF p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000 THEN
  RAISE EXCEPTION 'external generation catalog budget invalid' USING ERRCODE='54000';END IF;

 -- Пары (object_type,live) уникальны. Читаем обе строки, в том числе
 -- снятое описание типа, и связываем снимок с физическими версиями.
 WITH bounded AS MATERIALIZED (
  SELECT c.xmin::text AS row_xmin,c.ctid::text AS row_tid,c.dotted,c.module,c.live
  FROM ONLY kaname.catalog_resource c WHERE c.object_type=p_model
  LIMIT least(3,p_rows+1)
 )
 SELECT count(*)::integer,coalesce(jsonb_agg(jsonb_build_array(b.row_xmin,b.row_tid,
  jsonb_build_object('dotted',b.dotted,'module',b.module,'live',b.live))
  ORDER BY b.dotted COLLATE "C",b.live),'[]'::jsonb)
 INTO found_rows,aliases FROM bounded b;
 IF found_rows>p_rows THEN
  RAISE EXCEPTION 'external generation catalog row budget exhausted' USING ERRCODE='54000';END IF;
 IF found_rows NOT BETWEEN 1 AND 2 OR EXISTS(SELECT 1 FROM jsonb_array_elements(aliases) a
  WHERE a#>>'{2,module}'='iam'
   OR kaname._authority_access_label_dirty_root_type_valid_v1(a#>>'{2,dotted}') IS DISTINCT FROM true
   OR split_part(a#>>'{2,dotted}','.',1) IS DISTINCT FROM a#>>'{2,module}') THEN
  RAISE EXCEPTION 'external generation catalog identity unavailable' USING ERRCODE='42501';END IF;
 RETURN aliases;
END;
$aliases$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE target oid:='kaname._authority_access_label_external_aliases_v1(text,integer)'::regprocedure;recipient record;
BEGIN
 EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',target::regprocedure);
 FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
  JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid=target AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',target::regprocedure,recipient.rolname);
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('authority_resource_reconcile_pending_v1(text,text,integer,integer)','2bc27d802bf1b8461acc43e4bad5a4b5a155665db51740553af1061a3597f81c','6d15745d3afe3ea6e46cc82bbbbf8ab2c0d650f3a36e332bd49dee8d5fd79a8f',
  $changes$[
 [
  ";catalog_row record;catalog_item jsonb;catalog_rows jsonb:='[]';",
  ";catalog_item jsonb;catalog_rows jsonb;"
 ],
 [
  "  IF NOT coalesce(has_table_privilege(invoker,'kaname.catalog_resource'::regclass,'SELECT'),false)\n   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n    WHERE c.oid='kaname.catalog_resource'::regclass AND c.relkind='r' AND c.relpersistence='p'\n     AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND NOT c.relispartition\n     AND NOT c.relhassubclass AND NOT c.relhasrules) THEN\n   RAISE EXCEPTION 'external pending needs original catalog read access and ordinary source' USING ERRCODE='42501';END IF;\n  IF logical_reads>=p_reads THEN\n   RAISE EXCEPTION 'external pending catalog read budget exhausted' USING ERRCODE='54000';END IF;\n  logical_reads:=logical_reads+1;\n  -- UNIQUE(object_type,live) допускает две строки; третья означает отказ.\n  -- Сначала bounded census, затем любые проверки dirty predicates.\n  FOR catalog_row IN SELECT c.dotted,c.module,c.object_type,c.live\n   FROM ONLY kaname.catalog_resource c WHERE c.object_type=p_model\n   LIMIT least(3,p_rows-logical_rows+1) LOOP\n   logical_rows:=logical_rows+1;\n   IF logical_rows>p_rows THEN\n    RAISE EXCEPTION 'external pending catalog row budget exhausted' USING ERRCODE='54000';END IF;\n   IF jsonb_array_length(catalog_rows)>=2 OR catalog_row.module='iam'\n    OR catalog_row.object_type IS DISTINCT FROM p_model\n    OR kaname._authority_access_label_dirty_root_type_valid_v1(catalog_row.dotted) IS DISTINCT FROM true\n    OR split_part(catalog_row.dotted,'.',1) IS DISTINCT FROM catalog_row.module THEN\n    RAISE EXCEPTION 'external pending catalog identity unavailable' USING ERRCODE='42501';END IF;\n   catalog_rows:=catalog_rows||jsonb_build_array(to_jsonb(catalog_row));\n  END LOOP;\n  IF catalog_rows='[]'::jsonb THEN\n   RAISE EXCEPTION 'external pending catalog mapping unavailable' USING ERRCODE='42501';END IF;\n  FOR catalog_item IN SELECT value FROM jsonb_array_elements(catalog_rows)\n   ORDER BY value->>'dotted' COLLATE \"C\" LOOP\n",
  "  IF logical_reads>=p_reads THEN\n   RAISE EXCEPTION 'external pending catalog read budget exhausted' USING ERRCODE='54000';END IF;\n  logical_reads:=logical_reads+1;\n  catalog_rows:=kaname._authority_access_label_external_aliases_v1(p_model,p_rows-logical_rows);\n  logical_rows:=logical_rows+jsonb_array_length(catalog_rows);\n  FOR catalog_item IN SELECT value FROM jsonb_array_elements(catalog_rows) LOOP\n"
 ],
 [
  "r.root_type=catalog_item->>'dotted'",
  "r.root_type=catalog_item#>>'{2,dotted}'"
 ]
]$changes$::jsonb),
 ('_authority_access_label_object_generation_capture_v1(text,text,integer,integer)','e963c3d068d0baa9685d1d70b4f0c362a8cb834653687a3aa694ba06679f9823','1cde79ac24f64479fa75e599239f24fdc46c98026567c3f09469b2da77f71dac',
  $changes$[
 [
  " direct_type text;direct_root jsonb:='null';direct_linked boolean;",
  " direct_type text;direct_root jsonb:='null';direct_linked boolean;\n direct_types text[]:=ARRAY[]::text[];direct_roots jsonb:='[]';alias_rows jsonb;direct_external boolean;\n output_budget integer;result jsonb;"
 ],
 [
  " IF direct_type IS NOT NULL THEN\n  direct_root:=jsonb_build_object('root_type',direct_type,'root_id',p_id,'state',NULL);\n END IF;\n\n used_reads:=used_reads+1;",
  " IF direct_type IS NOT NULL THEN\n  direct_root:=jsonb_build_object('root_type',direct_type,'root_id',p_id,'state',NULL);\n  direct_types:=ARRAY[direct_type];\n ELSIF p_model NOT IN ('cluster','iam_user','iam_group','iam_role','iam_access_binding') THEN\n  IF p_reads<2 THEN\n   RAISE EXCEPTION 'generation catalog and output read budget exhausted' USING ERRCODE='54000';END IF;\n  alias_rows:=kaname._authority_access_label_external_aliases_v1(p_model,p_rows);\n  used_rows:=jsonb_array_length(alias_rows);used_reads:=1;\n  SELECT array_agg(a#>>'{2,dotted}' ORDER BY (a#>>'{2,dotted}') COLLATE \"C\")\n  INTO direct_types FROM jsonb_array_elements(alias_rows) a;\n END IF;\n\n used_reads:=used_reads+1;output_budget:=p_rows-used_rows;"
 ],
 [
  "WHERE d.object_type=p_model AND d.object_id=p_id LIMIT p_rows+1",
  "WHERE d.object_type=p_model AND d.object_id=p_id LIMIT output_budget+1"
 ],
 [
  "SELECT b.* FROM bounded b WHERE (SELECT n FROM counted)<=p_rows",
  "SELECT b.* FROM bounded b WHERE (SELECT n FROM counted)<=output_budget"
 ],
 [
  "UNION SELECT direct_type COLLATE \"C\",p_id COLLATE \"C\"\n     WHERE direct_type IS NOT NULL AND (SELECT n FROM counted)<=p_rows) k",
  "UNION SELECT coordinate COLLATE \"C\",p_id COLLATE \"C\" FROM unnest(direct_types) d(coordinate)\n     WHERE (SELECT n FROM counted)<=output_budget) k"
 ],
 [
  "IF captured_rows>p_rows THEN",
  "IF captured_rows>output_budget THEN"
 ],
 [
  "  IF root_identity=jsonb_build_array(direct_type,p_id) THEN",
  "  direct_external:=alias_rows IS NOT NULL AND (root_identity->>0)=ANY(direct_types) AND root_identity->>1=p_id;\n  IF direct_external THEN\n   direct_roots:=direct_roots||jsonb_build_array(jsonb_build_object('root_type',root_identity->>0,\n    'root_id',p_id,'state',coalesce(root_state,'null'::jsonb)));\n  END IF;\n  IF root_identity=jsonb_build_array(direct_type,p_id) THEN"
 ],
 [
  "   IF root_identity IS DISTINCT FROM jsonb_build_array(direct_type,p_id) OR direct_linked THEN\n    RAISE EXCEPTION 'generation output root missing' USING ERRCODE='40001';END IF;",
  "   IF direct_external THEN\n    IF EXISTS(SELECT 1 FROM jsonb_array_elements(output_states) s\n     WHERE s#>>'{2,root_type}'=root_identity->>0 AND s#>>'{2,root_id}'=root_identity->>1) THEN\n     RAISE EXCEPTION 'generation output root missing' USING ERRCODE='40001';END IF;\n   ELSIF root_identity IS DISTINCT FROM jsonb_build_array(direct_type,p_id) OR direct_linked THEN\n    RAISE EXCEPTION 'generation output root missing' USING ERRCODE='40001';END IF;"
 ],
 [
  " RETURN jsonb_build_object('object_type',p_model,'object_id',p_id,'direct_root',direct_root,\n  'output_states',output_states,'roots',to_jsonb(roots),'rows',used_rows,'reads',used_reads);",
  " result:=jsonb_build_object('object_type',p_model,'object_id',p_id,'direct_root',direct_root,\n  'output_states',output_states,'roots',to_jsonb(roots),'rows',used_rows,'reads',used_reads);\n IF alias_rows IS NOT NULL THEN\n  result:=result||jsonb_build_object('external_catalog',alias_rows,'direct_roots',direct_roots);\n END IF;\n RETURN result;"
 ]
]$changes$::jsonb),
 ('_authority_access_label_generation_root_keys_v1(jsonb)','1f982cdaa85d2f14a867b0388bfd31be71b1ec757315a8df6c672604441bd3f0','5e041d5238e6326ba07a8fc988a53ec325b37ff3924c67b8845304891b05d530',
  $changes$[
 [
  " IF typ NOT IN ('iam.account','iam.project','iam.serviceAccount') OR identifier=''",
  " IF kaname._authority_access_label_dirty_root_type_valid_v1(typ) IS DISTINCT FROM true OR identifier=''"
 ]
]$changes$::jsonb),
 ('_authority_access_label_generation_prepare_v1(text,text,text,integer,integer)','504f42f30014a48050c98a87efee67cd7d9aae1f6e1d87ab4243897732beac01','891930342ce17c3fd9d35dc1068a7fb9f5eadbaa363305b583ed695f50b7f4de',
  $changes$[
 [
  " SELECT coalesce(jsonb_agg(k.root_key",
  " -- Наблюдать внешнее поколение можно. Закрытие требует полного\n -- подтверждения прав и жизненного цикла внешнего ресурса.\n IF EXISTS(SELECT 1 FROM jsonb_array_elements(first_capture->'roots') r\n  WHERE r#>>'{state,2,root_type}' NOT IN ('iam.account','iam.project','iam.serviceAccount')) THEN\n  RAISE EXCEPTION 'external generation completion is not admitted' USING ERRCODE='42501';END IF;\n SELECT coalesce(jsonb_agg(k.root_key"
 ],
 [
  "   WHERE first_capture->'direct_root'<>'null'::jsonb\n ) k;",
  "   WHERE first_capture->'direct_root'<>'null'::jsonb\n  UNION\n  SELECT jsonb_build_array(d->>'root_type',d->>'root_id')\n   FROM jsonb_array_elements(first_capture->'direct_roots') d\n ) k;"
 ]
]$changes$::jsonb),
 ('_authority_access_label_generation_write_wait_v1(jsonb,integer,integer)','942b891c77f6f45f815120118166d8c4a1aec0a1af81d13b7bd6a2acb94e078d','5e8ed09502f74b405a0c1bf158ee9f58843496987284501677508eb99657f887',
  $changes$[
 [
  " root_count:=jsonb_array_length(capture->'roots');",
  " IF (capture ? 'direct_roots') IS DISTINCT FROM (capture ? 'external_catalog')\n OR ((capture ? 'direct_roots') AND (jsonb_typeof(capture->'direct_roots') IS DISTINCT FROM 'array'\n   OR jsonb_typeof(capture->'external_catalog') IS DISTINCT FROM 'array'\n   OR capture->'direct_root' IS DISTINCT FROM 'null'::jsonb)) THEN\n  RAISE EXCEPTION 'generation external capture shape invalid' USING ERRCODE='42501';END IF;\n IF (capture ? 'direct_roots') AND (jsonb_array_length(capture->'direct_roots') NOT BETWEEN 1 AND 2\n  OR jsonb_array_length(capture->'external_catalog')<>jsonb_array_length(capture->'direct_roots')) THEN\n  RAISE EXCEPTION 'generation external alias census invalid' USING ERRCODE='42501';END IF;\n root_count:=jsonb_array_length(capture->'roots');"
 ],
 [
  " SELECT coalesce(jsonb_agg(k.root_key),'[]'::jsonb) INTO coordinates FROM (",
  " -- Наблюдать внешнее поколение можно. Закрытие требует полного\n -- подтверждения прав и жизненного цикла внешнего ресурса.\n IF EXISTS(SELECT 1 FROM jsonb_array_elements(capture->'roots') r\n  WHERE r#>>'{state,2,root_type}' NOT IN ('iam.account','iam.project','iam.serviceAccount')) THEN\n  RAISE EXCEPTION 'external generation completion is not admitted' USING ERRCODE='42501';END IF;\n SELECT coalesce(jsonb_agg(k.root_key),'[]'::jsonb) INTO coordinates FROM ("
 ],
 [
  "   WHERE capture->'direct_root'<>'null'::jsonb\n ) k;",
  "   WHERE capture->'direct_root'<>'null'::jsonb\n  UNION SELECT jsonb_build_array(d->>'root_type',d->>'root_id')\n   FROM jsonb_array_elements(capture->'direct_roots') d\n ) k;"
 ],
 [
  " IF capture->'rows' IS DISTINCT FROM to_jsonb(capture_rows)",
  " IF capture ? 'direct_roots' THEN\n  capture_rows:=capture_rows+jsonb_array_length(capture->'external_catalog');\n  capture_reads:=capture_reads+1+(SELECT count(*)::integer FROM jsonb_array_elements(capture->'direct_roots') d\n   WHERE d->'state'='null'::jsonb);\n END IF;\n IF capture->'rows' IS DISTINCT FROM to_jsonb(capture_rows)"
 ]
]$changes$::jsonb),
 ('_authority_crud_storage_v3()','4228f0559ab4575a7f655dc66da9008b5d6919dc7f7a16d13c0ed640d9ca2743','8f74405db20549c6d05bc115b4cbabe476ff6fb43eadc2b5d4f2678b8f589981',
  $changes$[
 [
  "e963c3d068d0baa9685d1d70b4f0c362a8cb834653687a3aa694ba06679f9823",
  "1cde79ac24f64479fa75e599239f24fdc46c98026567c3f09469b2da77f71dac"
 ],
 [
  "1f982cdaa85d2f14a867b0388bfd31be71b1ec757315a8df6c672604441bd3f0",
  "5e041d5238e6326ba07a8fc988a53ec325b37ff3924c67b8845304891b05d530"
 ],
 [
  "504f42f30014a48050c98a87efee67cd7d9aae1f6e1d87ab4243897732beac01",
  "891930342ce17c3fd9d35dc1068a7fb9f5eadbaa363305b583ed695f50b7f4de"
 ],
 [
  "942b891c77f6f45f815120118166d8c4a1aec0a1af81d13b7bd6a2acb94e078d",
  "5e8ed09502f74b405a0c1bf158ee9f58843496987284501677508eb99657f887"
 ],
 [
  " ('_authority_access_label_object_generation_capture_v1(text,text,integer,integer)','1cde79ac24f64479fa75e599239f24fdc46c98026567c3f09469b2da77f71dac',false,'s',true,'private'),",
  " ('_authority_access_label_object_generation_capture_v1(text,text,integer,integer)','1cde79ac24f64479fa75e599239f24fdc46c98026567c3f09469b2da77f71dac',false,'s',true,'private'),\n ('_authority_access_label_external_aliases_v1(text,integer)','aeb9631d73897a7b33b600adb9bdf15f3cae25020209df9dcb1960a278bbbc3c',false,'s',true,'private'),"
 ],
 [
  "  ('access_label_rules_valid_v1(jsonb)','boolean',1,ARRAY['p_rules']),",
  "  ('access_label_rules_valid_v1(jsonb)','boolean',1,ARRAY['p_rules']),\n  ('_authority_access_label_external_aliases_v1(text,integer)','jsonb',2,ARRAY['p_model','p_rows']),"
 ]
]$changes$::jsonb),
 ('_authority_full_contract_storage_v3()','101f173a9ff06492d12bbbf3e41f9e52e5979fdcd7ff7d6c4b884ceafcde9ec6','b9402d9d61a06d324893798f483ef5f4aba3786ee7a4d45d1c22d5b6219b7364',
  $changes$[
 [
  "4228f0559ab4575a7f655dc66da9008b5d6919dc7f7a16d13c0ed640d9ca2743",
  "8f74405db20549c6d05bc115b4cbabe476ff6fb43eadc2b5d4f2678b8f589981"
 ]
]$changes$::jsonb),
 ('authority_metadata_service_account_access_label_ready_v1()','c41d55203f97c0db8cbc42a23534aaf6560ba3eea9e382f1dc1c8516e976e437','7cb001a7cd5dcaea693d88de1a7ee947a1f768224ff566b54e66ffe1070b0fc5',
  $changes$[
 [
  "2bc27d802bf1b8461acc43e4bad5a4b5a155665db51740553af1061a3597f81c",
  "6d15745d3afe3ea6e46cc82bbbbf8ab2c0d650f3a36e332bd49dee8d5fd79a8f"
 ],
 [
  "e963c3d068d0baa9685d1d70b4f0c362a8cb834653687a3aa694ba06679f9823",
  "1cde79ac24f64479fa75e599239f24fdc46c98026567c3f09469b2da77f71dac"
 ],
 [
  "1f982cdaa85d2f14a867b0388bfd31be71b1ec757315a8df6c672604441bd3f0",
  "5e041d5238e6326ba07a8fc988a53ec325b37ff3924c67b8845304891b05d530"
 ],
 [
  "4228f0559ab4575a7f655dc66da9008b5d6919dc7f7a16d13c0ed640d9ca2743",
  "8f74405db20549c6d05bc115b4cbabe476ff6fb43eadc2b5d4f2678b8f589981"
 ],
 [
  "101f173a9ff06492d12bbbf3e41f9e52e5979fdcd7ff7d6c4b884ceafcde9ec6",
  "b9402d9d61a06d324893798f483ef5f4aba3786ee7a4d45d1c22d5b6219b7364"
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
 ('authority_metadata_service_account_access_label_ready_v1()','7cb001a7cd5dcaea693d88de1a7ee947a1f768224ff566b54e66ffe1070b0fc5','c41d55203f97c0db8cbc42a23534aaf6560ba3eea9e382f1dc1c8516e976e437',
  $changes$[
 [
  "b9402d9d61a06d324893798f483ef5f4aba3786ee7a4d45d1c22d5b6219b7364",
  "101f173a9ff06492d12bbbf3e41f9e52e5979fdcd7ff7d6c4b884ceafcde9ec6"
 ],
 [
  "8f74405db20549c6d05bc115b4cbabe476ff6fb43eadc2b5d4f2678b8f589981",
  "4228f0559ab4575a7f655dc66da9008b5d6919dc7f7a16d13c0ed640d9ca2743"
 ],
 [
  "5e041d5238e6326ba07a8fc988a53ec325b37ff3924c67b8845304891b05d530",
  "1f982cdaa85d2f14a867b0388bfd31be71b1ec757315a8df6c672604441bd3f0"
 ],
 [
  "1cde79ac24f64479fa75e599239f24fdc46c98026567c3f09469b2da77f71dac",
  "e963c3d068d0baa9685d1d70b4f0c362a8cb834653687a3aa694ba06679f9823"
 ],
 [
  "6d15745d3afe3ea6e46cc82bbbbf8ab2c0d650f3a36e332bd49dee8d5fd79a8f",
  "2bc27d802bf1b8461acc43e4bad5a4b5a155665db51740553af1061a3597f81c"
 ]
]$changes$::jsonb),
 ('_authority_full_contract_storage_v3()','b9402d9d61a06d324893798f483ef5f4aba3786ee7a4d45d1c22d5b6219b7364','101f173a9ff06492d12bbbf3e41f9e52e5979fdcd7ff7d6c4b884ceafcde9ec6',
  $changes$[
 [
  "8f74405db20549c6d05bc115b4cbabe476ff6fb43eadc2b5d4f2678b8f589981",
  "4228f0559ab4575a7f655dc66da9008b5d6919dc7f7a16d13c0ed640d9ca2743"
 ]
]$changes$::jsonb),
 ('_authority_crud_storage_v3()','8f74405db20549c6d05bc115b4cbabe476ff6fb43eadc2b5d4f2678b8f589981','4228f0559ab4575a7f655dc66da9008b5d6919dc7f7a16d13c0ed640d9ca2743',
  $changes$[
 [
  "  ('access_label_rules_valid_v1(jsonb)','boolean',1,ARRAY['p_rules']),\n  ('_authority_access_label_external_aliases_v1(text,integer)','jsonb',2,ARRAY['p_model','p_rows']),",
  "  ('access_label_rules_valid_v1(jsonb)','boolean',1,ARRAY['p_rules']),"
 ],
 [
  " ('_authority_access_label_object_generation_capture_v1(text,text,integer,integer)','1cde79ac24f64479fa75e599239f24fdc46c98026567c3f09469b2da77f71dac',false,'s',true,'private'),\n ('_authority_access_label_external_aliases_v1(text,integer)','aeb9631d73897a7b33b600adb9bdf15f3cae25020209df9dcb1960a278bbbc3c',false,'s',true,'private'),",
  " ('_authority_access_label_object_generation_capture_v1(text,text,integer,integer)','1cde79ac24f64479fa75e599239f24fdc46c98026567c3f09469b2da77f71dac',false,'s',true,'private'),"
 ],
 [
  "5e8ed09502f74b405a0c1bf158ee9f58843496987284501677508eb99657f887",
  "942b891c77f6f45f815120118166d8c4a1aec0a1af81d13b7bd6a2acb94e078d"
 ],
 [
  "891930342ce17c3fd9d35dc1068a7fb9f5eadbaa363305b583ed695f50b7f4de",
  "504f42f30014a48050c98a87efee67cd7d9aae1f6e1d87ab4243897732beac01"
 ],
 [
  "5e041d5238e6326ba07a8fc988a53ec325b37ff3924c67b8845304891b05d530",
  "1f982cdaa85d2f14a867b0388bfd31be71b1ec757315a8df6c672604441bd3f0"
 ],
 [
  "1cde79ac24f64479fa75e599239f24fdc46c98026567c3f09469b2da77f71dac",
  "e963c3d068d0baa9685d1d70b4f0c362a8cb834653687a3aa694ba06679f9823"
 ]
]$changes$::jsonb),
 ('_authority_access_label_generation_write_wait_v1(jsonb,integer,integer)','5e8ed09502f74b405a0c1bf158ee9f58843496987284501677508eb99657f887','942b891c77f6f45f815120118166d8c4a1aec0a1af81d13b7bd6a2acb94e078d',
  $changes$[
 [
  " IF capture ? 'direct_roots' THEN\n  capture_rows:=capture_rows+jsonb_array_length(capture->'external_catalog');\n  capture_reads:=capture_reads+1+(SELECT count(*)::integer FROM jsonb_array_elements(capture->'direct_roots') d\n   WHERE d->'state'='null'::jsonb);\n END IF;\n IF capture->'rows' IS DISTINCT FROM to_jsonb(capture_rows)",
  " IF capture->'rows' IS DISTINCT FROM to_jsonb(capture_rows)"
 ],
 [
  "   WHERE capture->'direct_root'<>'null'::jsonb\n  UNION SELECT jsonb_build_array(d->>'root_type',d->>'root_id')\n   FROM jsonb_array_elements(capture->'direct_roots') d\n ) k;",
  "   WHERE capture->'direct_root'<>'null'::jsonb\n ) k;"
 ],
 [
  " -- Наблюдать внешнее поколение можно. Закрытие требует полного\n -- подтверждения прав и жизненного цикла внешнего ресурса.\n IF EXISTS(SELECT 1 FROM jsonb_array_elements(capture->'roots') r\n  WHERE r#>>'{state,2,root_type}' NOT IN ('iam.account','iam.project','iam.serviceAccount')) THEN\n  RAISE EXCEPTION 'external generation completion is not admitted' USING ERRCODE='42501';END IF;\n SELECT coalesce(jsonb_agg(k.root_key),'[]'::jsonb) INTO coordinates FROM (",
  " SELECT coalesce(jsonb_agg(k.root_key),'[]'::jsonb) INTO coordinates FROM ("
 ],
 [
  " IF (capture ? 'direct_roots') IS DISTINCT FROM (capture ? 'external_catalog')\n OR ((capture ? 'direct_roots') AND (jsonb_typeof(capture->'direct_roots') IS DISTINCT FROM 'array'\n   OR jsonb_typeof(capture->'external_catalog') IS DISTINCT FROM 'array'\n   OR capture->'direct_root' IS DISTINCT FROM 'null'::jsonb)) THEN\n  RAISE EXCEPTION 'generation external capture shape invalid' USING ERRCODE='42501';END IF;\n IF (capture ? 'direct_roots') AND (jsonb_array_length(capture->'direct_roots') NOT BETWEEN 1 AND 2\n  OR jsonb_array_length(capture->'external_catalog')<>jsonb_array_length(capture->'direct_roots')) THEN\n  RAISE EXCEPTION 'generation external alias census invalid' USING ERRCODE='42501';END IF;\n root_count:=jsonb_array_length(capture->'roots');",
  " root_count:=jsonb_array_length(capture->'roots');"
 ]
]$changes$::jsonb),
 ('_authority_access_label_generation_prepare_v1(text,text,text,integer,integer)','891930342ce17c3fd9d35dc1068a7fb9f5eadbaa363305b583ed695f50b7f4de','504f42f30014a48050c98a87efee67cd7d9aae1f6e1d87ab4243897732beac01',
  $changes$[
 [
  "   WHERE first_capture->'direct_root'<>'null'::jsonb\n  UNION\n  SELECT jsonb_build_array(d->>'root_type',d->>'root_id')\n   FROM jsonb_array_elements(first_capture->'direct_roots') d\n ) k;",
  "   WHERE first_capture->'direct_root'<>'null'::jsonb\n ) k;"
 ],
 [
  " -- Наблюдать внешнее поколение можно. Закрытие требует полного\n -- подтверждения прав и жизненного цикла внешнего ресурса.\n IF EXISTS(SELECT 1 FROM jsonb_array_elements(first_capture->'roots') r\n  WHERE r#>>'{state,2,root_type}' NOT IN ('iam.account','iam.project','iam.serviceAccount')) THEN\n  RAISE EXCEPTION 'external generation completion is not admitted' USING ERRCODE='42501';END IF;\n SELECT coalesce(jsonb_agg(k.root_key",
  " SELECT coalesce(jsonb_agg(k.root_key"
 ]
]$changes$::jsonb),
 ('_authority_access_label_generation_root_keys_v1(jsonb)','5e041d5238e6326ba07a8fc988a53ec325b37ff3924c67b8845304891b05d530','1f982cdaa85d2f14a867b0388bfd31be71b1ec757315a8df6c672604441bd3f0',
  $changes$[
 [
  " IF kaname._authority_access_label_dirty_root_type_valid_v1(typ) IS DISTINCT FROM true OR identifier=''",
  " IF typ NOT IN ('iam.account','iam.project','iam.serviceAccount') OR identifier=''"
 ]
]$changes$::jsonb),
 ('_authority_access_label_object_generation_capture_v1(text,text,integer,integer)','1cde79ac24f64479fa75e599239f24fdc46c98026567c3f09469b2da77f71dac','e963c3d068d0baa9685d1d70b4f0c362a8cb834653687a3aa694ba06679f9823',
  $changes$[
 [
  " result:=jsonb_build_object('object_type',p_model,'object_id',p_id,'direct_root',direct_root,\n  'output_states',output_states,'roots',to_jsonb(roots),'rows',used_rows,'reads',used_reads);\n IF alias_rows IS NOT NULL THEN\n  result:=result||jsonb_build_object('external_catalog',alias_rows,'direct_roots',direct_roots);\n END IF;\n RETURN result;",
  " RETURN jsonb_build_object('object_type',p_model,'object_id',p_id,'direct_root',direct_root,\n  'output_states',output_states,'roots',to_jsonb(roots),'rows',used_rows,'reads',used_reads);"
 ],
 [
  "   IF direct_external THEN\n    IF EXISTS(SELECT 1 FROM jsonb_array_elements(output_states) s\n     WHERE s#>>'{2,root_type}'=root_identity->>0 AND s#>>'{2,root_id}'=root_identity->>1) THEN\n     RAISE EXCEPTION 'generation output root missing' USING ERRCODE='40001';END IF;\n   ELSIF root_identity IS DISTINCT FROM jsonb_build_array(direct_type,p_id) OR direct_linked THEN\n    RAISE EXCEPTION 'generation output root missing' USING ERRCODE='40001';END IF;",
  "   IF root_identity IS DISTINCT FROM jsonb_build_array(direct_type,p_id) OR direct_linked THEN\n    RAISE EXCEPTION 'generation output root missing' USING ERRCODE='40001';END IF;"
 ],
 [
  "  direct_external:=alias_rows IS NOT NULL AND (root_identity->>0)=ANY(direct_types) AND root_identity->>1=p_id;\n  IF direct_external THEN\n   direct_roots:=direct_roots||jsonb_build_array(jsonb_build_object('root_type',root_identity->>0,\n    'root_id',p_id,'state',coalesce(root_state,'null'::jsonb)));\n  END IF;\n  IF root_identity=jsonb_build_array(direct_type,p_id) THEN",
  "  IF root_identity=jsonb_build_array(direct_type,p_id) THEN"
 ],
 [
  "IF captured_rows>output_budget THEN",
  "IF captured_rows>p_rows THEN"
 ],
 [
  "UNION SELECT coordinate COLLATE \"C\",p_id COLLATE \"C\" FROM unnest(direct_types) d(coordinate)\n     WHERE (SELECT n FROM counted)<=output_budget) k",
  "UNION SELECT direct_type COLLATE \"C\",p_id COLLATE \"C\"\n     WHERE direct_type IS NOT NULL AND (SELECT n FROM counted)<=p_rows) k"
 ],
 [
  "SELECT b.* FROM bounded b WHERE (SELECT n FROM counted)<=output_budget",
  "SELECT b.* FROM bounded b WHERE (SELECT n FROM counted)<=p_rows"
 ],
 [
  "WHERE d.object_type=p_model AND d.object_id=p_id LIMIT output_budget+1",
  "WHERE d.object_type=p_model AND d.object_id=p_id LIMIT p_rows+1"
 ],
 [
  " IF direct_type IS NOT NULL THEN\n  direct_root:=jsonb_build_object('root_type',direct_type,'root_id',p_id,'state',NULL);\n  direct_types:=ARRAY[direct_type];\n ELSIF p_model NOT IN ('cluster','iam_user','iam_group','iam_role','iam_access_binding') THEN\n  IF p_reads<2 THEN\n   RAISE EXCEPTION 'generation catalog and output read budget exhausted' USING ERRCODE='54000';END IF;\n  alias_rows:=kaname._authority_access_label_external_aliases_v1(p_model,p_rows);\n  used_rows:=jsonb_array_length(alias_rows);used_reads:=1;\n  SELECT array_agg(a#>>'{2,dotted}' ORDER BY (a#>>'{2,dotted}') COLLATE \"C\")\n  INTO direct_types FROM jsonb_array_elements(alias_rows) a;\n END IF;\n\n used_reads:=used_reads+1;output_budget:=p_rows-used_rows;",
  " IF direct_type IS NOT NULL THEN\n  direct_root:=jsonb_build_object('root_type',direct_type,'root_id',p_id,'state',NULL);\n END IF;\n\n used_reads:=used_reads+1;"
 ],
 [
  " direct_type text;direct_root jsonb:='null';direct_linked boolean;\n direct_types text[]:=ARRAY[]::text[];direct_roots jsonb:='[]';alias_rows jsonb;direct_external boolean;\n output_budget integer;result jsonb;",
  " direct_type text;direct_root jsonb:='null';direct_linked boolean;"
 ]
]$changes$::jsonb),
 ('authority_resource_reconcile_pending_v1(text,text,integer,integer)','6d15745d3afe3ea6e46cc82bbbbf8ab2c0d650f3a36e332bd49dee8d5fd79a8f','2bc27d802bf1b8461acc43e4bad5a4b5a155665db51740553af1061a3597f81c',
  $changes$[
 [
  "r.root_type=catalog_item#>>'{2,dotted}'",
  "r.root_type=catalog_item->>'dotted'"
 ],
 [
  "  IF logical_reads>=p_reads THEN\n   RAISE EXCEPTION 'external pending catalog read budget exhausted' USING ERRCODE='54000';END IF;\n  logical_reads:=logical_reads+1;\n  catalog_rows:=kaname._authority_access_label_external_aliases_v1(p_model,p_rows-logical_rows);\n  logical_rows:=logical_rows+jsonb_array_length(catalog_rows);\n  FOR catalog_item IN SELECT value FROM jsonb_array_elements(catalog_rows) LOOP\n",
  "  IF NOT coalesce(has_table_privilege(invoker,'kaname.catalog_resource'::regclass,'SELECT'),false)\n   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n    WHERE c.oid='kaname.catalog_resource'::regclass AND c.relkind='r' AND c.relpersistence='p'\n     AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND NOT c.relispartition\n     AND NOT c.relhassubclass AND NOT c.relhasrules) THEN\n   RAISE EXCEPTION 'external pending needs original catalog read access and ordinary source' USING ERRCODE='42501';END IF;\n  IF logical_reads>=p_reads THEN\n   RAISE EXCEPTION 'external pending catalog read budget exhausted' USING ERRCODE='54000';END IF;\n  logical_reads:=logical_reads+1;\n  -- UNIQUE(object_type,live) допускает две строки; третья означает отказ.\n  -- Сначала bounded census, затем любые проверки dirty predicates.\n  FOR catalog_row IN SELECT c.dotted,c.module,c.object_type,c.live\n   FROM ONLY kaname.catalog_resource c WHERE c.object_type=p_model\n   LIMIT least(3,p_rows-logical_rows+1) LOOP\n   logical_rows:=logical_rows+1;\n   IF logical_rows>p_rows THEN\n    RAISE EXCEPTION 'external pending catalog row budget exhausted' USING ERRCODE='54000';END IF;\n   IF jsonb_array_length(catalog_rows)>=2 OR catalog_row.module='iam'\n    OR catalog_row.object_type IS DISTINCT FROM p_model\n    OR kaname._authority_access_label_dirty_root_type_valid_v1(catalog_row.dotted) IS DISTINCT FROM true\n    OR split_part(catalog_row.dotted,'.',1) IS DISTINCT FROM catalog_row.module THEN\n    RAISE EXCEPTION 'external pending catalog identity unavailable' USING ERRCODE='42501';END IF;\n   catalog_rows:=catalog_rows||jsonb_build_array(to_jsonb(catalog_row));\n  END LOOP;\n  IF catalog_rows='[]'::jsonb THEN\n   RAISE EXCEPTION 'external pending catalog mapping unavailable' USING ERRCODE='42501';END IF;\n  FOR catalog_item IN SELECT value FROM jsonb_array_elements(catalog_rows)\n   ORDER BY value->>'dotted' COLLATE \"C\" LOOP\n"
 ],
 [
  ";catalog_item jsonb;catalog_rows jsonb;",
  ";catalog_row record;catalog_item jsonb;catalog_rows jsonb:='[]';"
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

DROP FUNCTION kaname._authority_access_label_external_aliases_v1(text,integer);
