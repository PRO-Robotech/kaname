-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Закрытый census внешнего корня: только свидетельства, без нового writer API.
-- Native ABI, ACL и выходная форма сохраняются; внешний held путь ещё не включён.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('_authority_metadata_access_label_carrier_census_v1(text,jsonb,jsonb,integer,integer,integer)','96cd1f25c20b292affd41eea5c871cefb585bf232d5385c2c1f3bd67dad7bac8','3c7583258dda9c9bb1f2448835dca77b676d1a94f9aee2c687e189823b2a52fd',
  $changes$[
 [
  " used integer:=0;work integer:=0;changed boolean;rules jsonb;",
  " used integer:=0;work integer:=0;changed boolean;rules jsonb;\n mirror_root boolean;root_module text;root_project_id text;scope_states jsonb;\n logical_reads integer:=1;result jsonb;"
 ],
 [
  " IF p_root_type IS NULL OR p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount')\n OR jsonb_typeof(p_old_root) IS DISTINCT FROM 'object' OR coalesce(p_old_root->>'id','')=''",
  " mirror_root:=p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount');\n IF coalesce(p_root_type,'')='' OR jsonb_typeof(p_old_root) IS DISTINCT FROM 'object'\n OR (NOT mirror_root AND coalesce(p_old_root->>'id','')='')\n OR (mirror_root AND (split_part(p_root_type,'.',1)='iam'\n  OR octet_length(p_root_type)>16384\n  OR p_old_root->>'object_type' IS DISTINCT FROM p_root_type\n  OR coalesce(p_old_root->>'object_id','')='' OR octet_length(p_old_root->>'object_id')>16384\n  OR p_old_root->>'object_id'='*' OR p_old_root->>'object_id' ~ '[[:cntrl:]]'))"
 ],
 [
  " root_id:=p_old_root->>'id';root_resource:=split_part(p_root_type,'.',2);\n census_account_id:=CASE WHEN p_root_type='iam.account' THEN root_id ELSE p_old_root->>'account_id' END;\n IF coalesce(census_account_id,'')='' THEN RAISE EXCEPTION 'protected metadata owner absent' USING ERRCODE='42501';END IF;",
  " root_module:=split_part(p_root_type,'.',1);root_resource:=split_part(p_root_type,'.',2);\n IF mirror_root THEN\n  -- Отдельное физическое свидетельство включает composite identity и предков.\n  -- Оно входит целиком в повторный census; внешний held caller обязан заранее\n  -- удержать эти строки и catalog lifecycle в общей согласованной очереди.\n  IF EXISTS(SELECT 1 FROM unnest(ARRAY['resource_mirror','catalog_resource','accounts']) required(name)\n   LEFT JOIN pg_catalog.pg_class c ON c.oid=to_regclass('kaname.'||required.name)\n   WHERE c.oid IS NULL OR c.relkind<>'r' OR c.relrowsecurity OR c.relforcerowsecurity\n    OR c.relispartition OR c.relhassubclass) THEN\n   RAISE EXCEPTION 'metadata census mirror source shape unsupported' USING ERRCODE='42501';END IF;\n  logical_reads:=2;\n  IF p_reads<logical_reads THEN\n   RAISE EXCEPTION 'protected metadata mirror census read budget exceeded' USING ERRCODE='54000';END IF;\n  root_id:=p_old_root->>'object_id';\n  SELECT a.id,nullif(m.parent_project_id,''),jsonb_build_object(\n   'root',jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)),\n   'catalog',jsonb_build_array(c.xmin::text,c.ctid::text,to_jsonb(c)),\n   'account',jsonb_build_array(a.xmin::text,a.ctid::text,to_jsonb(a)),\n   'project',CASE WHEN rp.id IS NULL THEN 'null'::jsonb\n    ELSE jsonb_build_array(rp.xmin::text,rp.ctid::text,to_jsonb(rp)) END)\n  INTO census_account_id,root_project_id,scope_states\n  FROM ONLY kaname.resource_mirror m\n  JOIN ONLY kaname.catalog_resource c ON c.dotted=m.object_type AND c.live\n   AND c.module=root_module AND c.resource=root_resource AND c.module<>'iam'\n  LEFT JOIN ONLY kaname.projects rp ON rp.id=nullif(m.parent_project_id,'')\n  JOIN ONLY kaname.accounts a ON a.id=coalesce(nullif(m.parent_account_id,''),rp.account_id)\n  WHERE m.object_type=p_root_type AND m.object_id=root_id AND to_jsonb(m)=p_old_root\n   AND (nullif(m.parent_project_id,'') IS NULL OR (rp.id IS NOT NULL AND rp.account_id=a.id));\n  IF scope_states IS NULL THEN\n   RAISE EXCEPTION 'protected metadata mirror root or scope unconfirmed' USING ERRCODE='42501';END IF;\n  used:=3+CASE WHEN root_project_id IS NULL THEN 0 ELSE 1 END;work:=used;\n  IF used>p_rows OR work>p_work THEN\n   RAISE EXCEPTION 'protected metadata mirror census budget exceeded' USING ERRCODE='54000';END IF;\n ELSE\n  root_id:=p_old_root->>'id';\n  census_account_id:=CASE WHEN p_root_type='iam.account' THEN root_id ELSE p_old_root->>'account_id' END;\n END IF;\n IF coalesce(census_account_id,'')='' THEN RAISE EXCEPTION 'protected metadata owner absent' USING ERRCODE='42501';END IF;"
 ],
 [
  "    OR (p_root_type='iam.project' AND b.resource_id=root_id)\n    OR p.id IS NULL)))",
  "    OR (p_root_type='iam.project' AND b.resource_id=root_id)\n    OR (mirror_root AND b.resource_id=root_project_id)\n    OR p.id IS NULL)))"
 ],
 [
  "WHERE authored_rules.owner_rule->>'module'='iam' AND nodes.node->'resources' ? root_resource",
  "WHERE authored_rules.owner_rule->>'module'=root_module AND nodes.node->'resources' ? root_resource"
 ],
 [
  " LIMIT p_rows+1 LOOP",
  " LIMIT p_rows-used+1 LOOP"
 ],
 [
  "IF node ? 'match_access_labels' AND owner_rule->>'module'='iam'",
  "IF node ? 'match_access_labels' AND owner_rule->>'module'=root_module"
 ],
 [
  " RETURN jsonb_build_object('root_type',p_root_type,'root_id',root_id,'account_id',census_account_id,",
  " result:=jsonb_build_object('root_type',p_root_type,'root_id',root_id,'account_id',census_account_id,"
 ],
 [
  "  'logical_rows',used,'logical_reads',1,'work',work);\nEND ",
  "  'logical_rows',used,'logical_reads',logical_reads,'work',work);\n IF mirror_root THEN\n  result:=result||jsonb_build_object('root_scope_states',scope_states);\n END IF;\n RETURN result;\nEND "
 ]
]$changes$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','7266b951857e921d1b47b5a93c75caa6be5fc05d5b87acd5e522eb3a07faae34','fc78cf28e5acf0bec74cf60f8dfb792051ad2d9a798fdc8129c20a60e43f1a6f',
  $changes$[
 [
  "96cd1f25c20b292affd41eea5c871cefb585bf232d5385c2c1f3bd67dad7bac8",
  "3c7583258dda9c9bb1f2448835dca77b676d1a94f9aee2c687e189823b2a52fd"
 ]
]$changes$::jsonb),
 ('authority_metadata_service_account_access_label_ready_v1()','19fa82b53b9892819149e626d3e929f79e138f46054725029ab6b372de4d0910','fe87c2cd1c6952de181f6170d021a32e10bd02ca11e7fbeab3b1322b7f23ca51',
  $changes$[
 [
  "96cd1f25c20b292affd41eea5c871cefb585bf232d5385c2c1f3bd67dad7bac8",
  "3c7583258dda9c9bb1f2448835dca77b676d1a94f9aee2c687e189823b2a52fd"
 ],
 [
  "7266b951857e921d1b47b5a93c75caa6be5fc05d5b87acd5e522eb3a07faae34",
  "fc78cf28e5acf0bec74cf60f8dfb792051ad2d9a798fdc8129c20a60e43f1a6f"
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
-- +goose StatementBegin
DO $acl$
DECLARE target oid; recipient record;
BEGIN
 target:='kaname._authority_metadata_access_label_carrier_census_v1(text,jsonb,jsonb,integer,integer,integer)'::regprocedure;
 REVOKE ALL ON FUNCTION kaname._authority_metadata_access_label_carrier_census_v1(text,jsonb,jsonb,integer,integer,integer) FROM PUBLIC;
 FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
  JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid=target AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_metadata_access_label_carrier_census_v1(text,jsonb,jsonb,integer,integer,integer) FROM %I',recipient.rolname);
 END LOOP;
END;
$acl$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('authority_metadata_service_account_access_label_ready_v1()','fe87c2cd1c6952de181f6170d021a32e10bd02ca11e7fbeab3b1322b7f23ca51','19fa82b53b9892819149e626d3e929f79e138f46054725029ab6b372de4d0910',
  $changes$[
 [
  "fc78cf28e5acf0bec74cf60f8dfb792051ad2d9a798fdc8129c20a60e43f1a6f",
  "7266b951857e921d1b47b5a93c75caa6be5fc05d5b87acd5e522eb3a07faae34"
 ],
 [
  "3c7583258dda9c9bb1f2448835dca77b676d1a94f9aee2c687e189823b2a52fd",
  "96cd1f25c20b292affd41eea5c871cefb585bf232d5385c2c1f3bd67dad7bac8"
 ]
]$changes$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','fc78cf28e5acf0bec74cf60f8dfb792051ad2d9a798fdc8129c20a60e43f1a6f','7266b951857e921d1b47b5a93c75caa6be5fc05d5b87acd5e522eb3a07faae34',
  $changes$[
 [
  "3c7583258dda9c9bb1f2448835dca77b676d1a94f9aee2c687e189823b2a52fd",
  "96cd1f25c20b292affd41eea5c871cefb585bf232d5385c2c1f3bd67dad7bac8"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_carrier_census_v1(text,jsonb,jsonb,integer,integer,integer)','3c7583258dda9c9bb1f2448835dca77b676d1a94f9aee2c687e189823b2a52fd','96cd1f25c20b292affd41eea5c871cefb585bf232d5385c2c1f3bd67dad7bac8',
  $changes$[
 [
  "  'logical_rows',used,'logical_reads',logical_reads,'work',work);\n IF mirror_root THEN\n  result:=result||jsonb_build_object('root_scope_states',scope_states);\n END IF;\n RETURN result;\nEND ",
  "  'logical_rows',used,'logical_reads',1,'work',work);\nEND "
 ],
 [
  " result:=jsonb_build_object('root_type',p_root_type,'root_id',root_id,'account_id',census_account_id,",
  " RETURN jsonb_build_object('root_type',p_root_type,'root_id',root_id,'account_id',census_account_id,"
 ],
 [
  "IF node ? 'match_access_labels' AND owner_rule->>'module'=root_module",
  "IF node ? 'match_access_labels' AND owner_rule->>'module'='iam'"
 ],
 [
  " LIMIT p_rows-used+1 LOOP",
  " LIMIT p_rows+1 LOOP"
 ],
 [
  "WHERE authored_rules.owner_rule->>'module'=root_module AND nodes.node->'resources' ? root_resource",
  "WHERE authored_rules.owner_rule->>'module'='iam' AND nodes.node->'resources' ? root_resource"
 ],
 [
  "    OR (p_root_type='iam.project' AND b.resource_id=root_id)\n    OR (mirror_root AND b.resource_id=root_project_id)\n    OR p.id IS NULL)))",
  "    OR (p_root_type='iam.project' AND b.resource_id=root_id)\n    OR p.id IS NULL)))"
 ],
 [
  " root_module:=split_part(p_root_type,'.',1);root_resource:=split_part(p_root_type,'.',2);\n IF mirror_root THEN\n  -- Отдельное физическое свидетельство включает composite identity и предков.\n  -- Оно входит целиком в повторный census; внешний held caller обязан заранее\n  -- удержать эти строки и catalog lifecycle в общей согласованной очереди.\n  IF EXISTS(SELECT 1 FROM unnest(ARRAY['resource_mirror','catalog_resource','accounts']) required(name)\n   LEFT JOIN pg_catalog.pg_class c ON c.oid=to_regclass('kaname.'||required.name)\n   WHERE c.oid IS NULL OR c.relkind<>'r' OR c.relrowsecurity OR c.relforcerowsecurity\n    OR c.relispartition OR c.relhassubclass) THEN\n   RAISE EXCEPTION 'metadata census mirror source shape unsupported' USING ERRCODE='42501';END IF;\n  logical_reads:=2;\n  IF p_reads<logical_reads THEN\n   RAISE EXCEPTION 'protected metadata mirror census read budget exceeded' USING ERRCODE='54000';END IF;\n  root_id:=p_old_root->>'object_id';\n  SELECT a.id,nullif(m.parent_project_id,''),jsonb_build_object(\n   'root',jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)),\n   'catalog',jsonb_build_array(c.xmin::text,c.ctid::text,to_jsonb(c)),\n   'account',jsonb_build_array(a.xmin::text,a.ctid::text,to_jsonb(a)),\n   'project',CASE WHEN rp.id IS NULL THEN 'null'::jsonb\n    ELSE jsonb_build_array(rp.xmin::text,rp.ctid::text,to_jsonb(rp)) END)\n  INTO census_account_id,root_project_id,scope_states\n  FROM ONLY kaname.resource_mirror m\n  JOIN ONLY kaname.catalog_resource c ON c.dotted=m.object_type AND c.live\n   AND c.module=root_module AND c.resource=root_resource AND c.module<>'iam'\n  LEFT JOIN ONLY kaname.projects rp ON rp.id=nullif(m.parent_project_id,'')\n  JOIN ONLY kaname.accounts a ON a.id=coalesce(nullif(m.parent_account_id,''),rp.account_id)\n  WHERE m.object_type=p_root_type AND m.object_id=root_id AND to_jsonb(m)=p_old_root\n   AND (nullif(m.parent_project_id,'') IS NULL OR (rp.id IS NOT NULL AND rp.account_id=a.id));\n  IF scope_states IS NULL THEN\n   RAISE EXCEPTION 'protected metadata mirror root or scope unconfirmed' USING ERRCODE='42501';END IF;\n  used:=3+CASE WHEN root_project_id IS NULL THEN 0 ELSE 1 END;work:=used;\n  IF used>p_rows OR work>p_work THEN\n   RAISE EXCEPTION 'protected metadata mirror census budget exceeded' USING ERRCODE='54000';END IF;\n ELSE\n  root_id:=p_old_root->>'id';\n  census_account_id:=CASE WHEN p_root_type='iam.account' THEN root_id ELSE p_old_root->>'account_id' END;\n END IF;\n IF coalesce(census_account_id,'')='' THEN RAISE EXCEPTION 'protected metadata owner absent' USING ERRCODE='42501';END IF;",
  " root_id:=p_old_root->>'id';root_resource:=split_part(p_root_type,'.',2);\n census_account_id:=CASE WHEN p_root_type='iam.account' THEN root_id ELSE p_old_root->>'account_id' END;\n IF coalesce(census_account_id,'')='' THEN RAISE EXCEPTION 'protected metadata owner absent' USING ERRCODE='42501';END IF;"
 ],
 [
  " mirror_root:=p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount');\n IF coalesce(p_root_type,'')='' OR jsonb_typeof(p_old_root) IS DISTINCT FROM 'object'\n OR (NOT mirror_root AND coalesce(p_old_root->>'id','')='')\n OR (mirror_root AND (split_part(p_root_type,'.',1)='iam'\n  OR octet_length(p_root_type)>16384\n  OR p_old_root->>'object_type' IS DISTINCT FROM p_root_type\n  OR coalesce(p_old_root->>'object_id','')='' OR octet_length(p_old_root->>'object_id')>16384\n  OR p_old_root->>'object_id'='*' OR p_old_root->>'object_id' ~ '[[:cntrl:]]'))",
  " IF p_root_type IS NULL OR p_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount')\n OR jsonb_typeof(p_old_root) IS DISTINCT FROM 'object' OR coalesce(p_old_root->>'id','')=''"
 ],
 [
  " used integer:=0;work integer:=0;changed boolean;rules jsonb;\n mirror_root boolean;root_module text;root_project_id text;scope_states jsonb;\n logical_reads integer:=1;result jsonb;",
  " used integer:=0;work integer:=0;changed boolean;rules jsonb;"
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
-- +goose StatementBegin
DO $acl$
DECLARE target oid; recipient record;
BEGIN
 target:='kaname._authority_metadata_access_label_carrier_census_v1(text,jsonb,jsonb,integer,integer,integer)'::regprocedure;
 REVOKE ALL ON FUNCTION kaname._authority_metadata_access_label_carrier_census_v1(text,jsonb,jsonb,integer,integer,integer) FROM PUBLIC;
 FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
  JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid=target AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_metadata_access_label_carrier_census_v1(text,jsonb,jsonb,integer,integer,integer) FROM %I',recipient.rolname);
 END LOOP;
END;
$acl$;
-- +goose StatementEnd
