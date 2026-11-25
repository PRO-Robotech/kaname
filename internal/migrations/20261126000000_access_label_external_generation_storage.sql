-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Храним ожидающие поколения внешних ресурсов по составной координате.
-- Перенос незавершённых фактов требует удержания точной строки и регистрации.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_dirty_root_type_valid_v1(p_root_type text)
RETURNS boolean LANGUAGE sql IMMUTABLE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $valid$
 SELECT p_root_type IS NOT NULL AND (
  p_root_type IN ('iam.account','iam.project','iam.serviceAccount')
  OR (octet_length(p_root_type)<=16384
   AND p_root_type ~ '^[^.:#*[:space:][:cntrl:]]+[.][^.:#*[:space:][:cntrl:]]+$'
   AND split_part(p_root_type,'.',1)<>'iam')
 );
$valid$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE grantee record;
BEGIN
 REVOKE ALL ON FUNCTION kaname._authority_access_label_dirty_root_type_valid_v1(text) FROM PUBLIC;
 FOR grantee IN
  SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
  JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname._authority_access_label_dirty_root_type_valid_v1(text)'::regprocedure AND a.grantee<>p.proowner
 LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_access_label_dirty_root_type_valid_v1(text) FROM %I',grantee.rolname);
 END LOOP;
END;
$private$;
-- +goose StatementEnd
ALTER TABLE kaname.authority_access_label_dirty_root DROP CONSTRAINT authority_access_label_dirty_root_type;
ALTER TABLE kaname.authority_access_label_dirty_root ADD CONSTRAINT authority_access_label_dirty_root_type
 CHECK (kaname._authority_access_label_dirty_root_type_valid_v1(root_type));

-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('_authority_access_label_freshness_storage_v1()','45464597290417cfad0f087b8ccf44453c7b4362b94bde2229fe3e0e785b33f5','d5892bc3912e46c57530c959d730e4a669707c34271798caa5a08cc954aed087',
  $changes$[
 [
  "root_type=ANYARRAY[''iam.account''::text,''iam.project''::text,''iam.serviceAccount''::text]",
  "kaname._authority_access_label_dirty_root_type_valid_v1root_type"
 ],
 [
  " RETURN true;\nEND",
  " IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('kaname._authority_access_label_dirty_root_type_valid_v1(text)')\n  AND p.proowner=owner_oid AND NOT p.prosecdef AND p.provolatile='i'\n  AND p.prokind='f' AND p.prorettype='boolean'::regtype AND NOT(p.proretset OR p.proisstrict OR p.proleakproof)\n  AND p.proparallel='u' AND p.pronargs=1 AND p.pronargdefaults=0 AND p.provariadic=0\n  AND p.proargnames=ARRAY['p_root_type']::text[] AND p.proargmodes IS NULL AND p.proallargtypes IS NULL\n  AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='sql')\n  AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[]\n  AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='4429396620413a4c7d3b205b4f25ce5495cc758113860cac4ace98b8677b9694'\n  AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a\n   WHERE a.grantee<>owner_oid)\n ) THEN RETURN false;END IF;\n RETURN true;\nEND"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_carry_v1(text,text,jsonb,integer,integer)','0c3a3bf0b6f329da989508ee996659557a419ca12e3c83eab11ae0daf5e126b7','45ab208874926a028090e251b2440a6304de296fdc5424dba056a6fc1f1892cf',
  $changes$[
 [
  "DECLARE previous_generation uuid;previous_labels jsonb;facts jsonb;n integer;",
  "DECLARE previous_generation uuid;previous_labels jsonb;facts jsonb;n integer;\n external_root boolean;prepared jsonb;retained jsonb;catalog_row jsonb;physical jsonb;actual_row jsonb;actual_xmin text;actual_ctid text;\n base_rows integer:=1;base_reads integer:=1;"
 ],
 [
  "IF coalesce(p_root_type,'') NOT IN ('iam.account','iam.project','iam.serviceAccount') OR coalesce(p_root_id,'')=''",
  "IF kaname._authority_access_label_dirty_root_type_valid_v1(p_root_type) IS DISTINCT FROM true OR coalesce(p_root_id,'')=''"
 ],
 [
  " -- Сначала удерживается строка ресурса. Подготавливаем запись в обе\n -- таблицы до финального решения, чтобы не ждать DDL после него.\n LOCK TABLE kaname.authority_access_label_dirty_root,kaname.authority_access_label_dirty_fact IN ROW EXCLUSIVE MODE;",
  " external_root:=p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount');\n IF external_root THEN\n  -- Внешний корень и привязка уже удержаны. Дополнительные подтверждения\n  -- учитываем до чтения, включая возможное отсутствие поколения.\n  base_rows:=4;base_reads:=4;\n  IF p_rows<base_rows OR p_reads<base_reads THEN\n   RAISE EXCEPTION 'external access label freshness carry budget exhausted' USING ERRCODE='54000';END IF;\n  prepared:=kaname._authority_metadata_access_label_stashed_v1();\n  retained:=prepared->'retention';\n  catalog_row:=prepared#>'{root,census,root_scope_states,catalog,2}';\n  physical:=retained->'root_physical';\n  IF prepared#>'{root,root_coordinate}' IS DISTINCT FROM jsonb_build_array(p_root_type,p_root_id)\n   OR retained->>'root_source_kind' IS DISTINCT FROM '2'\n   OR retained->>'root_model' IS DISTINCT FROM catalog_row->>'object_type'\n   OR retained->>'root_type' IS DISTINCT FROM p_root_type OR retained->>'root_id' IS DISTINCT FROM p_root_id\n   OR retained#>>'{old_row,object_type}' IS DISTINCT FROM p_root_type\n   OR retained#>>'{old_row,object_id}' IS DISTINCT FROM p_root_id\n   OR retained#>'{old_row,access_labels}' IS DISTINCT FROM p_old_labels\n   OR NOT coalesce((retained->'source_index') ? jsonb_build_array(2,p_root_type,p_root_id,'')::text,false)\n   OR NOT coalesce((retained->'source_index') ? jsonb_build_array(5,catalog_row->>'object_type',p_root_id,'')::text,false)\n   OR catalog_row->>'dotted' IS DISTINCT FROM p_root_type OR catalog_row->>'live' IS DISTINCT FROM 'true'\n   OR coalesce(catalog_row->>'module','') IN ('','iam')\n   OR coalesce(catalog_row->>'object_type','') !~ '^[a-z][a-z0-9_]*$'\n   OR physical->>'table' IS DISTINCT FROM 'resource_mirror'\n   OR physical->>'object_type' IS DISTINCT FROM p_root_type OR physical->>'id' IS DISTINCT FROM p_root_id THEN\n   RAISE EXCEPTION 'external access label freshness root is not held' USING ERRCODE='42501';END IF;\n  PERFORM kaname._authority_metadata_registration_binding_check_v1(catalog_row->>'object_type',p_root_id);\n  SELECT to_jsonb(m),m.xmin::text,m.ctid::text INTO actual_row,actual_xmin,actual_ctid\n  FROM ONLY kaname.resource_mirror m WHERE m.object_type=p_root_type AND m.object_id=p_root_id;\n  IF NOT FOUND OR actual_row IS DISTINCT FROM retained->'old_row'\n   OR actual_xmin IS DISTINCT FROM physical->>'xmin' OR actual_ctid IS DISTINCT FROM physical->>'ctid' THEN\n   RAISE EXCEPTION 'external access label freshness root changed during carry' USING ERRCODE='40001';END IF;\n END IF;\n -- Сначала удерживается строка ресурса. Подготавливаем запись в обе\n -- таблицы до финального решения, чтобы не ждать DDL после него.\n LOCK TABLE kaname.authority_access_label_dirty_root,kaname.authority_access_label_dirty_fact IN ROW EXCLUSIVE MODE;"
 ],
 [
  "'prior_facts','[]'::jsonb,'rows',1,'reads',1",
  "'prior_facts','[]'::jsonb,'rows',base_rows,'reads',base_reads"
 ],
 [
  "IF p_reads<2 THEN",
  "IF p_reads<=base_reads THEN"
 ],
 [
  "LIMIT p_rows FOR UPDATE OF d",
  "LIMIT p_rows-base_rows+1 FOR UPDATE OF d"
 ],
 [
  "IF n>=p_rows THEN",
  "IF n>p_rows-base_rows THEN"
 ],
 [
  "'rows',1+n,'reads',2",
  "'rows',base_rows+n,'reads',base_reads+1"
 ]
]$changes$::jsonb),
 ('_authority_full_contract_storage_v3()','c85f7b863c7202a0e951426ab51a8e18a906b86c7c7bec61b25886a57e75417b','55fa1ecf2a399ec6d808860833f09a66ff90232caf9d12eb31d72478b873c1d9',
  $changes$[
 [
  "45464597290417cfad0f087b8ccf44453c7b4362b94bde2229fe3e0e785b33f5",
  "d5892bc3912e46c57530c959d730e4a669707c34271798caa5a08cc954aed087"
 ]
]$changes$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','e40c32117191982841cdd3197aa9f09889caf673edcb995a9c0896b0e66242d3','f3f807f346b7e6809194341239ca3f5916c2860fa0d1fe5a24acef0296e3a478',
  $changes$[
 [
  "0c3a3bf0b6f329da989508ee996659557a419ca12e3c83eab11ae0daf5e126b7",
  "45ab208874926a028090e251b2440a6304de296fdc5424dba056a6fc1f1892cf"
 ]
]$changes$::jsonb),
 ('authority_resource_reconcile_pending_v1(text,text,integer,integer)','80ff9887f485df5264ab9e5fe596296624e5fee954620415d7d1cf032e1969dc','2bc27d802bf1b8461acc43e4bad5a4b5a155665db51740553af1061a3597f81c',
  $changes$[
 [
  "DECLARE invoker oid;direct_type text;",
  "DECLARE invoker oid;direct_type text;catalog_row record;catalog_item jsonb;catalog_rows jsonb:='[]';"
 ],
 [
  " direct_type:=CASE p_model WHEN 'account' THEN 'iam.account' WHEN 'project' THEN 'iam.project' WHEN 'iam_service_account' THEN 'iam.serviceAccount' END;\n",
  " direct_type:=CASE p_model WHEN 'account' THEN 'iam.account' WHEN 'project' THEN 'iam.project' WHEN 'iam_service_account' THEN 'iam.serviceAccount' END;\n -- Остальные штатные IAM output models не имеют собственного dirty root.\n -- Внешние aliases читаются в том же RR, включая retired: отсутствие mirror\n -- или live-флага не превращает оставшееся поколение в чистое состояние.\n IF direct_type IS NULL AND p_model NOT IN ('cluster','iam_user','iam_group','iam_role','iam_access_binding') THEN\n  logical_rows:=1;logical_reads:=1;\n  IF p_rows<logical_rows OR p_reads<logical_reads THEN\n   RAISE EXCEPTION 'external pending source budget exhausted' USING ERRCODE='54000';END IF;\n  IF NOT coalesce(has_table_privilege(invoker,'kaname.catalog_resource'::regclass,'SELECT'),false)\n   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n    WHERE c.oid='kaname.catalog_resource'::regclass AND c.relkind='r' AND c.relpersistence='p'\n     AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND NOT c.relispartition\n     AND NOT c.relhassubclass AND NOT c.relhasrules) THEN\n   RAISE EXCEPTION 'external pending needs original catalog read access and ordinary source' USING ERRCODE='42501';END IF;\n  IF logical_reads>=p_reads THEN\n   RAISE EXCEPTION 'external pending catalog read budget exhausted' USING ERRCODE='54000';END IF;\n  logical_reads:=logical_reads+1;\n  -- UNIQUE(object_type,live) допускает две строки; третья означает отказ.\n  -- Сначала bounded census, затем любые проверки dirty predicates.\n  FOR catalog_row IN SELECT c.dotted,c.module,c.object_type,c.live\n   FROM ONLY kaname.catalog_resource c WHERE c.object_type=p_model\n   LIMIT least(3,p_rows-logical_rows+1) LOOP\n   logical_rows:=logical_rows+1;\n   IF logical_rows>p_rows THEN\n    RAISE EXCEPTION 'external pending catalog row budget exhausted' USING ERRCODE='54000';END IF;\n   IF jsonb_array_length(catalog_rows)>=2 OR catalog_row.module='iam'\n    OR catalog_row.object_type IS DISTINCT FROM p_model\n    OR kaname._authority_access_label_dirty_root_type_valid_v1(catalog_row.dotted) IS DISTINCT FROM true\n    OR split_part(catalog_row.dotted,'.',1) IS DISTINCT FROM catalog_row.module THEN\n    RAISE EXCEPTION 'external pending catalog identity unavailable' USING ERRCODE='42501';END IF;\n   catalog_rows:=catalog_rows||jsonb_build_array(to_jsonb(catalog_row));\n  END LOOP;\n  IF catalog_rows='[]'::jsonb THEN\n   RAISE EXCEPTION 'external pending catalog mapping unavailable' USING ERRCODE='42501';END IF;\n  FOR catalog_item IN SELECT value FROM jsonb_array_elements(catalog_rows)\n   ORDER BY value->>'dotted' COLLATE \"C\" LOOP\n   IF logical_reads>=p_reads THEN\n    RAISE EXCEPTION 'external pending root read budget exhausted' USING ERRCODE='54000';END IF;\n   logical_reads:=logical_reads+1;\n   SELECT EXISTS(SELECT 1 FROM kaname.authority_access_label_dirty_root r\n    WHERE r.root_type=catalog_item->>'dotted' AND r.root_id=p_id) INTO pending;\n   IF pending THEN\n    logical_rows:=logical_rows+1;\n    IF logical_rows>p_rows THEN\n     RAISE EXCEPTION 'external pending root row budget exhausted' USING ERRCODE='54000';END IF;\n    RETURN NEXT;RETURN;\n   END IF;\n  END LOOP;\n  IF logical_reads>=p_reads THEN\n   RAISE EXCEPTION 'external pending fact read budget exhausted' USING ERRCODE='54000';END IF;\n  logical_reads:=logical_reads+1;\n  SELECT EXISTS(SELECT 1 FROM kaname.authority_access_label_dirty_fact d\n   WHERE d.object_type=p_model AND d.object_id=p_id) INTO pending;\n  logical_rows:=logical_rows+CASE WHEN pending THEN 1 ELSE 0 END;\n  IF logical_rows>p_rows THEN\n   RAISE EXCEPTION 'external pending fact row budget exhausted' USING ERRCODE='54000';END IF;\n  RETURN NEXT;RETURN;\n END IF;\n"
 ]
]$changes$::jsonb),
 ('authority_metadata_service_account_access_label_ready_v1()','f256e7f8258542c9fdbcacb424ed1ecf1689e03af494e066f73c76c789d861cd','d138be11188212363fc7dd6475d08b9b92f209d5834b0cb22b4e147aa88a6d9c',
  $changes$[
 [
  "45464597290417cfad0f087b8ccf44453c7b4362b94bde2229fe3e0e785b33f5",
  "d5892bc3912e46c57530c959d730e4a669707c34271798caa5a08cc954aed087"
 ],
 [
  "0c3a3bf0b6f329da989508ee996659557a419ca12e3c83eab11ae0daf5e126b7",
  "45ab208874926a028090e251b2440a6304de296fdc5424dba056a6fc1f1892cf"
 ],
 [
  "c85f7b863c7202a0e951426ab51a8e18a906b86c7c7bec61b25886a57e75417b",
  "55fa1ecf2a399ec6d808860833f09a66ff90232caf9d12eb31d72478b873c1d9"
 ],
 [
  "e40c32117191982841cdd3197aa9f09889caf673edcb995a9c0896b0e66242d3",
  "f3f807f346b7e6809194341239ca3f5916c2860fa0d1fe5a24acef0296e3a478"
 ],
 [
  "80ff9887f485df5264ab9e5fe596296624e5fee954620415d7d1cf032e1969dc",
  "2bc27d802bf1b8461acc43e4bad5a4b5a155665db51740553af1061a3597f81c"
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

LOCK TABLE kaname.authority_access_label_dirty_root,kaname.authority_access_label_dirty_fact IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $down$
BEGIN
 IF EXISTS(SELECT 1 FROM ONLY kaname.authority_access_label_dirty_root
  WHERE root_type NOT IN ('iam.account','iam.project','iam.serviceAccount')) THEN
  RAISE EXCEPTION 'Сначала завершите пересчёт прав внешних ресурсов' USING ERRCODE='55000';END IF;
END;
$down$;
-- +goose StatementEnd
ALTER TABLE kaname.authority_access_label_dirty_root DROP CONSTRAINT authority_access_label_dirty_root_type;
ALTER TABLE kaname.authority_access_label_dirty_root ADD CONSTRAINT authority_access_label_dirty_root_type
 CHECK (root_type IN ('iam.account','iam.project','iam.serviceAccount'));

-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('authority_metadata_service_account_access_label_ready_v1()','d138be11188212363fc7dd6475d08b9b92f209d5834b0cb22b4e147aa88a6d9c','f256e7f8258542c9fdbcacb424ed1ecf1689e03af494e066f73c76c789d861cd',
  $changes$[
 [
  "2bc27d802bf1b8461acc43e4bad5a4b5a155665db51740553af1061a3597f81c",
  "80ff9887f485df5264ab9e5fe596296624e5fee954620415d7d1cf032e1969dc"
 ],
 [
  "f3f807f346b7e6809194341239ca3f5916c2860fa0d1fe5a24acef0296e3a478",
  "e40c32117191982841cdd3197aa9f09889caf673edcb995a9c0896b0e66242d3"
 ],
 [
  "55fa1ecf2a399ec6d808860833f09a66ff90232caf9d12eb31d72478b873c1d9",
  "c85f7b863c7202a0e951426ab51a8e18a906b86c7c7bec61b25886a57e75417b"
 ],
 [
  "45ab208874926a028090e251b2440a6304de296fdc5424dba056a6fc1f1892cf",
  "0c3a3bf0b6f329da989508ee996659557a419ca12e3c83eab11ae0daf5e126b7"
 ],
 [
  "d5892bc3912e46c57530c959d730e4a669707c34271798caa5a08cc954aed087",
  "45464597290417cfad0f087b8ccf44453c7b4362b94bde2229fe3e0e785b33f5"
 ]
]$changes$::jsonb),
 ('authority_resource_reconcile_pending_v1(text,text,integer,integer)','2bc27d802bf1b8461acc43e4bad5a4b5a155665db51740553af1061a3597f81c','80ff9887f485df5264ab9e5fe596296624e5fee954620415d7d1cf032e1969dc',
  $changes$[
 [
  " direct_type:=CASE p_model WHEN 'account' THEN 'iam.account' WHEN 'project' THEN 'iam.project' WHEN 'iam_service_account' THEN 'iam.serviceAccount' END;\n -- Остальные штатные IAM output models не имеют собственного dirty root.\n -- Внешние aliases читаются в том же RR, включая retired: отсутствие mirror\n -- или live-флага не превращает оставшееся поколение в чистое состояние.\n IF direct_type IS NULL AND p_model NOT IN ('cluster','iam_user','iam_group','iam_role','iam_access_binding') THEN\n  logical_rows:=1;logical_reads:=1;\n  IF p_rows<logical_rows OR p_reads<logical_reads THEN\n   RAISE EXCEPTION 'external pending source budget exhausted' USING ERRCODE='54000';END IF;\n  IF NOT coalesce(has_table_privilege(invoker,'kaname.catalog_resource'::regclass,'SELECT'),false)\n   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n    WHERE c.oid='kaname.catalog_resource'::regclass AND c.relkind='r' AND c.relpersistence='p'\n     AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND NOT c.relispartition\n     AND NOT c.relhassubclass AND NOT c.relhasrules) THEN\n   RAISE EXCEPTION 'external pending needs original catalog read access and ordinary source' USING ERRCODE='42501';END IF;\n  IF logical_reads>=p_reads THEN\n   RAISE EXCEPTION 'external pending catalog read budget exhausted' USING ERRCODE='54000';END IF;\n  logical_reads:=logical_reads+1;\n  -- UNIQUE(object_type,live) допускает две строки; третья означает отказ.\n  -- Сначала bounded census, затем любые проверки dirty predicates.\n  FOR catalog_row IN SELECT c.dotted,c.module,c.object_type,c.live\n   FROM ONLY kaname.catalog_resource c WHERE c.object_type=p_model\n   LIMIT least(3,p_rows-logical_rows+1) LOOP\n   logical_rows:=logical_rows+1;\n   IF logical_rows>p_rows THEN\n    RAISE EXCEPTION 'external pending catalog row budget exhausted' USING ERRCODE='54000';END IF;\n   IF jsonb_array_length(catalog_rows)>=2 OR catalog_row.module='iam'\n    OR catalog_row.object_type IS DISTINCT FROM p_model\n    OR kaname._authority_access_label_dirty_root_type_valid_v1(catalog_row.dotted) IS DISTINCT FROM true\n    OR split_part(catalog_row.dotted,'.',1) IS DISTINCT FROM catalog_row.module THEN\n    RAISE EXCEPTION 'external pending catalog identity unavailable' USING ERRCODE='42501';END IF;\n   catalog_rows:=catalog_rows||jsonb_build_array(to_jsonb(catalog_row));\n  END LOOP;\n  IF catalog_rows='[]'::jsonb THEN\n   RAISE EXCEPTION 'external pending catalog mapping unavailable' USING ERRCODE='42501';END IF;\n  FOR catalog_item IN SELECT value FROM jsonb_array_elements(catalog_rows)\n   ORDER BY value->>'dotted' COLLATE \"C\" LOOP\n   IF logical_reads>=p_reads THEN\n    RAISE EXCEPTION 'external pending root read budget exhausted' USING ERRCODE='54000';END IF;\n   logical_reads:=logical_reads+1;\n   SELECT EXISTS(SELECT 1 FROM kaname.authority_access_label_dirty_root r\n    WHERE r.root_type=catalog_item->>'dotted' AND r.root_id=p_id) INTO pending;\n   IF pending THEN\n    logical_rows:=logical_rows+1;\n    IF logical_rows>p_rows THEN\n     RAISE EXCEPTION 'external pending root row budget exhausted' USING ERRCODE='54000';END IF;\n    RETURN NEXT;RETURN;\n   END IF;\n  END LOOP;\n  IF logical_reads>=p_reads THEN\n   RAISE EXCEPTION 'external pending fact read budget exhausted' USING ERRCODE='54000';END IF;\n  logical_reads:=logical_reads+1;\n  SELECT EXISTS(SELECT 1 FROM kaname.authority_access_label_dirty_fact d\n   WHERE d.object_type=p_model AND d.object_id=p_id) INTO pending;\n  logical_rows:=logical_rows+CASE WHEN pending THEN 1 ELSE 0 END;\n  IF logical_rows>p_rows THEN\n   RAISE EXCEPTION 'external pending fact row budget exhausted' USING ERRCODE='54000';END IF;\n  RETURN NEXT;RETURN;\n END IF;\n",
  " direct_type:=CASE p_model WHEN 'account' THEN 'iam.account' WHEN 'project' THEN 'iam.project' WHEN 'iam_service_account' THEN 'iam.serviceAccount' END;\n"
 ],
 [
  "DECLARE invoker oid;direct_type text;catalog_row record;catalog_item jsonb;catalog_rows jsonb:='[]';",
  "DECLARE invoker oid;direct_type text;"
 ]
]$changes$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','f3f807f346b7e6809194341239ca3f5916c2860fa0d1fe5a24acef0296e3a478','e40c32117191982841cdd3197aa9f09889caf673edcb995a9c0896b0e66242d3',
  $changes$[
 [
  "45ab208874926a028090e251b2440a6304de296fdc5424dba056a6fc1f1892cf",
  "0c3a3bf0b6f329da989508ee996659557a419ca12e3c83eab11ae0daf5e126b7"
 ]
]$changes$::jsonb),
 ('_authority_full_contract_storage_v3()','55fa1ecf2a399ec6d808860833f09a66ff90232caf9d12eb31d72478b873c1d9','c85f7b863c7202a0e951426ab51a8e18a906b86c7c7bec61b25886a57e75417b',
  $changes$[
 [
  "d5892bc3912e46c57530c959d730e4a669707c34271798caa5a08cc954aed087",
  "45464597290417cfad0f087b8ccf44453c7b4362b94bde2229fe3e0e785b33f5"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_carry_v1(text,text,jsonb,integer,integer)','45ab208874926a028090e251b2440a6304de296fdc5424dba056a6fc1f1892cf','0c3a3bf0b6f329da989508ee996659557a419ca12e3c83eab11ae0daf5e126b7',
  $changes$[
 [
  "'rows',base_rows+n,'reads',base_reads+1",
  "'rows',1+n,'reads',2"
 ],
 [
  "IF n>p_rows-base_rows THEN",
  "IF n>=p_rows THEN"
 ],
 [
  "LIMIT p_rows-base_rows+1 FOR UPDATE OF d",
  "LIMIT p_rows FOR UPDATE OF d"
 ],
 [
  "IF p_reads<=base_reads THEN",
  "IF p_reads<2 THEN"
 ],
 [
  "'prior_facts','[]'::jsonb,'rows',base_rows,'reads',base_reads",
  "'prior_facts','[]'::jsonb,'rows',1,'reads',1"
 ],
 [
  " external_root:=p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount');\n IF external_root THEN\n  -- Внешний корень и привязка уже удержаны. Дополнительные подтверждения\n  -- учитываем до чтения, включая возможное отсутствие поколения.\n  base_rows:=4;base_reads:=4;\n  IF p_rows<base_rows OR p_reads<base_reads THEN\n   RAISE EXCEPTION 'external access label freshness carry budget exhausted' USING ERRCODE='54000';END IF;\n  prepared:=kaname._authority_metadata_access_label_stashed_v1();\n  retained:=prepared->'retention';\n  catalog_row:=prepared#>'{root,census,root_scope_states,catalog,2}';\n  physical:=retained->'root_physical';\n  IF prepared#>'{root,root_coordinate}' IS DISTINCT FROM jsonb_build_array(p_root_type,p_root_id)\n   OR retained->>'root_source_kind' IS DISTINCT FROM '2'\n   OR retained->>'root_model' IS DISTINCT FROM catalog_row->>'object_type'\n   OR retained->>'root_type' IS DISTINCT FROM p_root_type OR retained->>'root_id' IS DISTINCT FROM p_root_id\n   OR retained#>>'{old_row,object_type}' IS DISTINCT FROM p_root_type\n   OR retained#>>'{old_row,object_id}' IS DISTINCT FROM p_root_id\n   OR retained#>'{old_row,access_labels}' IS DISTINCT FROM p_old_labels\n   OR NOT coalesce((retained->'source_index') ? jsonb_build_array(2,p_root_type,p_root_id,'')::text,false)\n   OR NOT coalesce((retained->'source_index') ? jsonb_build_array(5,catalog_row->>'object_type',p_root_id,'')::text,false)\n   OR catalog_row->>'dotted' IS DISTINCT FROM p_root_type OR catalog_row->>'live' IS DISTINCT FROM 'true'\n   OR coalesce(catalog_row->>'module','') IN ('','iam')\n   OR coalesce(catalog_row->>'object_type','') !~ '^[a-z][a-z0-9_]*$'\n   OR physical->>'table' IS DISTINCT FROM 'resource_mirror'\n   OR physical->>'object_type' IS DISTINCT FROM p_root_type OR physical->>'id' IS DISTINCT FROM p_root_id THEN\n   RAISE EXCEPTION 'external access label freshness root is not held' USING ERRCODE='42501';END IF;\n  PERFORM kaname._authority_metadata_registration_binding_check_v1(catalog_row->>'object_type',p_root_id);\n  SELECT to_jsonb(m),m.xmin::text,m.ctid::text INTO actual_row,actual_xmin,actual_ctid\n  FROM ONLY kaname.resource_mirror m WHERE m.object_type=p_root_type AND m.object_id=p_root_id;\n  IF NOT FOUND OR actual_row IS DISTINCT FROM retained->'old_row'\n   OR actual_xmin IS DISTINCT FROM physical->>'xmin' OR actual_ctid IS DISTINCT FROM physical->>'ctid' THEN\n   RAISE EXCEPTION 'external access label freshness root changed during carry' USING ERRCODE='40001';END IF;\n END IF;\n -- Сначала удерживается строка ресурса. Подготавливаем запись в обе\n -- таблицы до финального решения, чтобы не ждать DDL после него.\n LOCK TABLE kaname.authority_access_label_dirty_root,kaname.authority_access_label_dirty_fact IN ROW EXCLUSIVE MODE;",
  " -- Сначала удерживается строка ресурса. Подготавливаем запись в обе\n -- таблицы до финального решения, чтобы не ждать DDL после него.\n LOCK TABLE kaname.authority_access_label_dirty_root,kaname.authority_access_label_dirty_fact IN ROW EXCLUSIVE MODE;"
 ],
 [
  "IF kaname._authority_access_label_dirty_root_type_valid_v1(p_root_type) IS DISTINCT FROM true OR coalesce(p_root_id,'')=''",
  "IF coalesce(p_root_type,'') NOT IN ('iam.account','iam.project','iam.serviceAccount') OR coalesce(p_root_id,'')=''"
 ],
 [
  "DECLARE previous_generation uuid;previous_labels jsonb;facts jsonb;n integer;\n external_root boolean;prepared jsonb;retained jsonb;catalog_row jsonb;physical jsonb;actual_row jsonb;actual_xmin text;actual_ctid text;\n base_rows integer:=1;base_reads integer:=1;",
  "DECLARE previous_generation uuid;previous_labels jsonb;facts jsonb;n integer;"
 ]
]$changes$::jsonb),
 ('_authority_access_label_freshness_storage_v1()','d5892bc3912e46c57530c959d730e4a669707c34271798caa5a08cc954aed087','45464597290417cfad0f087b8ccf44453c7b4362b94bde2229fe3e0e785b33f5',
  $changes$[
 [
  " IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('kaname._authority_access_label_dirty_root_type_valid_v1(text)')\n  AND p.proowner=owner_oid AND NOT p.prosecdef AND p.provolatile='i'\n  AND p.prokind='f' AND p.prorettype='boolean'::regtype AND NOT(p.proretset OR p.proisstrict OR p.proleakproof)\n  AND p.proparallel='u' AND p.pronargs=1 AND p.pronargdefaults=0 AND p.provariadic=0\n  AND p.proargnames=ARRAY['p_root_type']::text[] AND p.proargmodes IS NULL AND p.proallargtypes IS NULL\n  AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='sql')\n  AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[]\n  AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='4429396620413a4c7d3b205b4f25ce5495cc758113860cac4ace98b8677b9694'\n  AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a\n   WHERE a.grantee<>owner_oid)\n ) THEN RETURN false;END IF;\n RETURN true;\nEND",
  " RETURN true;\nEND"
 ],
 [
  "kaname._authority_access_label_dirty_root_type_valid_v1root_type",
  "root_type=ANYARRAY[''iam.account''::text,''iam.project''::text,''iam.serviceAccount''::text]"
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

DROP FUNCTION kaname._authority_access_label_dirty_root_type_valid_v1(text);
