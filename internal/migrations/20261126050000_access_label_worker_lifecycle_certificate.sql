-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Черновик: lifecycle внешнего корня worker по committed-state снимкам.
-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_generation_lifecycle_validate_v1(
 p_lifecycle jsonb,p_root_state jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE dotted text;identifier text;model text;entry record;k jsonb;s jsonb;raw jsonb;
 mirror jsonb;scopes jsonb;rows_count integer:=1;reads_count integer:=1;work integer:=1;
 kind integer;typ text;obj text;source_key text;expected_keys jsonb:='{}';scope_key text;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 dotted:=p_root_state#>>'{2,root_type}';identifier:=p_root_state#>>'{2,root_id}';model:=p_lifecycle->>'model';
 IF p_lifecycle->'abi' IS DISTINCT FROM '1'::jsonb
 OR p_lifecycle->'root_state' IS DISTINCT FROM p_root_state
 OR p_lifecycle->>'dotted' IS DISTINCT FROM dotted OR p_lifecycle->>'id' IS DISTINCT FROM identifier
 OR kaname._authority_access_label_dirty_root_type_valid_v1(dotted) IS DISTINCT FROM true
 OR split_part(dotted,'.',1)='iam' OR coalesce(identifier,'')=''
 OR coalesce(model,'') !~ '^[a-z][a-z0-9_]*$'
 OR jsonb_typeof(p_lifecycle->'predicates') IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_lifecycle->'accounts') IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_lifecycle->'projects') IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_lifecycle->'present') IS DISTINCT FROM 'boolean'
 OR jsonb_typeof(p_lifecycle->'catalog_state') IS DISTINCT FROM 'array'
 OR jsonb_array_length(p_lifecycle->'catalog_state')<>3 THEN
  RAISE EXCEPTION 'generation lifecycle identity incomplete' USING ERRCODE='42501';END IF;
 s:=p_lifecycle->'catalog_state';raw:=s->2;
 IF jsonb_typeof(s->0) IS DISTINCT FROM 'string' OR coalesce(s->>0,'')=''
 OR jsonb_typeof(s->1) IS DISTINCT FROM 'string' OR coalesce(s->>1,'')=''
 OR raw->>'dotted' IS DISTINCT FROM dotted OR raw->>'object_type' IS DISTINCT FROM model
 OR jsonb_typeof(raw->'live') IS DISTINCT FROM 'boolean' THEN
  RAISE EXCEPTION 'generation lifecycle catalog identity differs' USING ERRCODE='42501';END IF;
 FOREACH kind IN ARRAY ARRAY[2,3,4,5,25,26,27,28] LOOP
  typ:=CASE WHEN kind=2 THEN dotted ELSE model END;
  expected_keys:=expected_keys||jsonb_build_object(jsonb_build_array(kind,typ,identifier,'')::text,true);
 END LOOP;
 FOR scope_key IN SELECT jsonb_object_keys(p_lifecycle->'accounts') LOOP
  IF scope_key='' OR p_lifecycle->'accounts'->scope_key IS DISTINCT FROM 'true'::jsonb THEN
   RAISE EXCEPTION 'generation lifecycle account malformed' USING ERRCODE='42501';END IF;
  expected_keys:=expected_keys||jsonb_build_object(jsonb_build_array(23,'account',scope_key,'')::text,true);
 END LOOP;
 FOR scope_key IN SELECT jsonb_object_keys(p_lifecycle->'projects') LOOP
  IF scope_key='' OR p_lifecycle->'projects'->scope_key IS DISTINCT FROM 'true'::jsonb THEN
   RAISE EXCEPTION 'generation lifecycle project malformed' USING ERRCODE='42501';END IF;
  expected_keys:=expected_keys||jsonb_build_object(jsonb_build_array(1,'project',scope_key,'')::text,true);
 END LOOP;
 IF (SELECT count(*) FROM jsonb_object_keys(expected_keys))>4096
 OR (SELECT count(*) FROM jsonb_object_keys(p_lifecycle->'predicates'))<>(SELECT count(*) FROM jsonb_object_keys(expected_keys)) THEN
  RAISE EXCEPTION 'generation lifecycle predicate bound differs' USING ERRCODE='54000';END IF;
 FOR entry IN SELECT * FROM jsonb_each(p_lifecycle->'predicates') LOOP
  IF NOT expected_keys ? entry.key OR jsonb_typeof(entry.value) IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'generation lifecycle foreign predicate' USING ERRCODE='42501';END IF;
  k:=entry.key::jsonb;kind:=(k->>0)::integer;typ:=k->>1;obj:=k->>2;
  IF kind IN (1,2,5,23,27) AND jsonb_array_length(entry.value)>1 THEN
   RAISE EXCEPTION 'generation lifecycle singleton ambiguous' USING ERRCODE='42501';END IF;
  IF kind=23 AND jsonb_array_length(entry.value)<>1 THEN
   RAISE EXCEPTION 'generation lifecycle owning account absent' USING ERRCODE='42501';END IF;
  IF jsonb_array_length(entry.value)>100000-rows_count THEN
   RAISE EXCEPTION 'generation lifecycle row bound exceeded' USING ERRCODE='54000';END IF;
  FOR s IN SELECT value FROM jsonb_array_elements(entry.value) LOOP
   IF jsonb_typeof(s) IS DISTINCT FROM 'array' OR jsonb_array_length(s)<>3
   OR jsonb_typeof(s->0) IS DISTINCT FROM 'string' OR coalesce(s->>0,'')=''
   OR jsonb_typeof(s->1) IS DISTINCT FROM 'string' OR coalesce(s->>1,'')=''
   OR jsonb_typeof(s->2) IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION 'generation lifecycle physical state malformed' USING ERRCODE='42501';END IF;
   raw:=s->2;
   IF (kind IN (1,23) AND raw->>'id' IS DISTINCT FROM obj)
   OR (kind NOT IN (1,23) AND (raw->>'object_type' IS DISTINCT FROM typ OR raw->>'object_id' IS DISTINCT FROM obj)) THEN
    RAISE EXCEPTION 'generation lifecycle physical coordinate differs' USING ERRCODE='42501';END IF;
   IF kind=4 AND (coalesce(raw->>'account_id','')=''
    OR p_lifecycle->'accounts'->(raw->>'account_id') IS DISTINCT FROM 'true'::jsonb
    OR (coalesce(raw->>'project_id','')<>'' AND p_lifecycle->'projects'->(raw->>'project_id') IS DISTINCT FROM 'true'::jsonb)) THEN
    RAISE EXCEPTION 'generation lifecycle retained scope differs' USING ERRCODE='42501';END IF;
  END LOOP;
  IF (SELECT count(DISTINCT value) FROM jsonb_array_elements(entry.value))<>jsonb_array_length(entry.value) THEN
   RAISE EXCEPTION 'generation lifecycle physical row repeated' USING ERRCODE='42501';END IF;
  rows_count:=rows_count+jsonb_array_length(entry.value);reads_count:=reads_count+1;
  work:=work+1+jsonb_array_length(entry.value);
  IF rows_count>100000 OR reads_count>4096 THEN
   RAISE EXCEPTION 'generation lifecycle census exceeded' USING ERRCODE='54000';END IF;
 END LOOP;
 source_key:=jsonb_build_array(2,dotted,identifier,'')::text;
 mirror:=p_lifecycle->'predicates'->source_key;
 scopes:=p_lifecycle->'predicates'->(jsonb_build_array(4,model,identifier,'')::text);
 IF p_lifecycle->'present' IS DISTINCT FROM to_jsonb(jsonb_array_length(mirror)=1)
 OR p_lifecycle->'accounts'='{}'::jsonb THEN
  RAISE EXCEPTION 'generation lifecycle root scope unavailable' USING ERRCODE='42501';END IF;
 IF jsonb_array_length(mirror)=1 THEN
  raw:=mirror->0->2;
  IF p_lifecycle#>'{catalog_state,2,live}' IS DISTINCT FROM 'true'::jsonb
  OR raw->'access_labels' IS DISTINCT FROM p_root_state#>'{2,new_labels}'
  OR kaname.access_labels_valid_v1(raw->'access_labels') IS DISTINCT FROM true
  OR (coalesce(raw->>'parent_account_id','')<>'' AND
   p_lifecycle->'accounts'->(raw->>'parent_account_id') IS DISTINCT FROM 'true'::jsonb)
  OR (coalesce(raw->>'parent_project_id','')<>'' AND
   p_lifecycle->'projects'->(raw->>'parent_project_id') IS DISTINCT FROM 'true'::jsonb) THEN
   RAISE EXCEPTION 'generation lifecycle live projection differs' USING ERRCODE='42501';END IF;
 ELSIF jsonb_array_length(scopes)=0 THEN
  RAISE EXCEPTION 'generation lifecycle absent root lacks retained scope' USING ERRCODE='42501';
 END IF;
 RETURN jsonb_build_object('rows',rows_count,'reads',reads_count,'work',work);
END;
$fn$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_generation_lifecycle_plan_v1(
 p_capture jsonb,p_certificate jsonb,p_index jsonb,p_current jsonb,p_binding jsonb,p_catalog jsonb,
 p_rows integer,p_reads integer,p_work integer) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE root jsonb;dotted text;identifier text;model text;graph_key text;graph jsonb;
 kind integer;typ text;key_value text;source jsonb;expected jsonb;actual jsonb;predicates jsonb;
 required jsonb;entry record;packet jsonb;catalog_state jsonb;catalog_matches integer;
 result jsonb:='{}';cost jsonb;used_rows integer:=0;used_reads integer:=0;work integer:=0;
BEGIN
 PERFORM kaname._authority_access_label_generation_latch_require_v1(false);
 IF jsonb_typeof(p_capture->'roots') IS DISTINCT FROM 'array'
 OR jsonb_typeof(p_certificate->'graphs') IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_current) IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_binding->'validated_keys') IS DISTINCT FROM 'array'
 OR jsonb_typeof(p_catalog) IS DISTINCT FROM 'array'
 OR p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000
 OR p_reads IS NULL OR p_reads NOT BETWEEN 0 AND 4096
 OR p_work IS NULL OR p_work NOT BETWEEN 0 AND 100000 THEN
  RAISE EXCEPTION 'generation lifecycle held input invalid' USING ERRCODE='42501';END IF;
 FOR root IN SELECT value FROM jsonb_array_elements(p_capture->'roots') LOOP
  dotted:=root#>>'{state,2,root_type}';identifier:=root#>>'{state,2,root_id}';
  IF dotted IN ('iam.account','iam.project','iam.serviceAccount') THEN CONTINUE;END IF;
  graph_key:=jsonb_build_array(dotted,identifier)::text;graph:=p_certificate->'graphs'->graph_key;
  model:=graph->>'model_type';
  IF graph->>'object_type' IS DISTINCT FROM dotted OR graph->>'object_id' IS DISTINCT FROM identifier
  OR jsonb_typeof(graph->'accounts') IS DISTINCT FROM 'object' OR jsonb_typeof(graph->'projects') IS DISTINCT FROM 'object'
  OR jsonb_typeof(graph->'present') IS DISTINCT FROM 'boolean' OR result ? graph_key THEN
   RAISE EXCEPTION 'generation lifecycle closed graph absent' USING ERRCODE='42501';END IF;
  required:='{}'::jsonb;predicates:='{}'::jsonb;
  FOREACH kind IN ARRAY ARRAY[2,3,4,5,25,26,27,28] LOOP
   typ:=CASE WHEN kind=2 THEN dotted ELSE model END;
   required:=required||jsonb_build_object(jsonb_build_array(kind,typ,identifier,'')::text,true);
  END LOOP;
  FOR key_value IN SELECT jsonb_object_keys(graph->'accounts') LOOP
   required:=required||jsonb_build_object(jsonb_build_array(23,'account',key_value,'')::text,true);
  END LOOP;
  FOR key_value IN SELECT jsonb_object_keys(graph->'projects') LOOP
   required:=required||jsonb_build_object(jsonb_build_array(1,'project',key_value,'')::text,true);
  END LOOP;
  FOR entry IN SELECT * FROM jsonb_each(required) LOOP
   kind:=(entry.key::jsonb->>0)::integer;typ:=entry.key::jsonb->>1;key_value:=entry.key::jsonb->>2;
   IF p_certificate->'required'->entry.key IS DISTINCT FROM 'true'::jsonb THEN
    RAISE EXCEPTION 'generation lifecycle predicate outside certificate' USING ERRCODE='42501';END IF;
   source:=kaname._authority_resource_require_capture_v2(p_index,kind,typ,key_value);
   SELECT coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C"),'[]'::jsonb) INTO expected
    FROM jsonb_array_elements(source->'states');
   IF kind=5 THEN
    IF NOT (p_binding->'validated_keys') ? entry.key THEN
     RAISE EXCEPTION 'generation lifecycle binding reread omitted' USING ERRCODE='42501';END IF;
   ELSE
    IF jsonb_typeof(p_current->entry.key) IS DISTINCT FROM 'array' THEN
     RAISE EXCEPTION 'generation lifecycle held predicate omitted' USING ERRCODE='42501';END IF;
    SELECT coalesce(jsonb_agg(jsonb_build_array(v->>'xmin',v->>'tid',v->'data')
     ORDER BY jsonb_build_array(v->>'xmin',v->>'tid',v->'data')::text COLLATE "C"),'[]'::jsonb)
     INTO actual FROM jsonb_array_elements(p_current->entry.key) v;
    IF actual IS DISTINCT FROM expected THEN
     RAISE EXCEPTION 'generation lifecycle held states differ' USING ERRCODE='P1034';END IF;
   END IF;
   predicates:=predicates||jsonb_build_object(entry.key,expected);
  END LOOP;
  -- catalog_wait уже вернул физическую строку в текстовом поле state.
  -- Не выдаём повторный SELECT за необходимость и не теряем ABA witness.
  SELECT count(DISTINCT c->>'state')::integer,min(c->>'state')::jsonb
   INTO catalog_matches,catalog_state FROM jsonb_array_elements(p_catalog) c
   WHERE c->>'dotted'=dotted AND c->>'object_type'=model;
  IF catalog_matches<>1 OR catalog_state IS NULL
  OR catalog_state#>>'{2,object_type}' IS DISTINCT FROM model
  OR catalog_state#>>'{2,dotted}' IS DISTINCT FROM dotted THEN
   RAISE EXCEPTION 'generation lifecycle held catalog missing' USING ERRCODE='42501';END IF;
  packet:=jsonb_build_object('abi',1,'root_state',root->'state','dotted',dotted,'id',identifier,'model',model,
   'present',graph->'present','accounts',graph->'accounts','projects',graph->'projects',
   'catalog_state',catalog_state,'predicates',predicates);
  cost:=kaname._authority_access_label_generation_lifecycle_validate_v1(packet,root->'state');
  work:=work+(cost->>'work')::integer;
  IF work>p_work THEN RAISE EXCEPTION 'generation lifecycle work exhausted' USING ERRCODE='54000';END IF;
  result:=result||jsonb_build_object(graph_key,packet);
 END LOOP;
 RETURN jsonb_build_object('roots',result,'rows',used_rows,'reads',used_reads,'work',work);
END;
$fn$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_generation_lifecycle_finish_v1(
 p_lifecycle jsonb,p_root_state jsonb,p_rows integer,p_reads integer) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE cost jsonb;actual jsonb;entry record;k jsonb;table_name text;predicate text;statement text;
 expected integer;captured integer;dotted text;
BEGIN
 cost:=kaname._authority_access_label_generation_lifecycle_validate_v1(p_lifecycle,p_root_state);
 IF p_rows IS NULL OR p_reads IS NULL OR p_rows<(cost->>'rows')::integer OR p_reads<(cost->>'reads')::integer THEN
  RAISE EXCEPTION 'generation lifecycle finish reserve insufficient' USING ERRCODE='54000';END IF;
 dotted:=p_lifecycle->>'dotted';
 SELECT jsonb_build_array(c.xmin::text,c.ctid::text,to_jsonb(c)) INTO actual
  FROM ONLY kaname.catalog_resource c WHERE c.dotted=p_lifecycle->>'dotted';
 IF actual IS DISTINCT FROM p_lifecycle->'catalog_state' THEN
  RAISE EXCEPTION 'generation lifecycle catalog changed before finish' USING ERRCODE='40001';END IF;
 -- Никаких новых locks: это bounded readback ранее закрытой программы.
 FOR entry IN SELECT * FROM jsonb_each(p_lifecycle->'predicates') ORDER BY key COLLATE "C" LOOP
  k:=entry.key::jsonb;expected:=jsonb_array_length(entry.value);
  CASE (k->>0)::integer
   WHEN 1 THEN table_name:='projects';
   WHEN 2 THEN table_name:='resource_mirror';
   WHEN 3 THEN table_name:='resource_parent_edge';
   WHEN 4 THEN table_name:='resource_registration_scope';
   WHEN 5 THEN table_name:='object_project_binding';
   WHEN 23 THEN table_name:='accounts';
   WHEN 25 THEN table_name:='resource_registration_pointer';
   WHEN 26 THEN table_name:='producer_source_receipt';
   WHEN 27 THEN table_name:='public_read_publication';
   WHEN 28 THEN table_name:='resource_registration_retirement';
   ELSE RAISE EXCEPTION 'generation lifecycle foreign readback' USING ERRCODE='42501';
  END CASE;
  predicate:=CASE WHEN (k->>0)::integer IN (1,23) THEN 'r.id=$2' ELSE 'r.object_type=$1 AND r.object_id=$2' END;
  statement:=format('WITH bounded AS MATERIALIZED (
   SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r)) state FROM ONLY kaname.%I r
   WHERE $1::text IS NOT NULL AND (%s) LIMIT $3), counted AS (SELECT count(*) n FROM bounded)
   SELECT (SELECT n FROM counted),coalesce(jsonb_agg(state ORDER BY state::text COLLATE "C"),''[]''::jsonb)
   FROM bounded WHERE (SELECT n FROM counted)<$3',table_name,predicate);
  EXECUTE statement INTO captured,actual USING k->>1,k->>2,expected+1;
  IF captured<>expected OR actual IS DISTINCT FROM entry.value THEN
   RAISE EXCEPTION 'generation lifecycle changed before finish' USING ERRCODE='40001';END IF;
 END LOOP;
 RETURN cost;
END;
$fn$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_generation_lifecycle_requirements_v1(
 p_capture jsonb,p_certificate jsonb,p_index jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE root jsonb;graph jsonb;identifier text;source jsonb;required jsonb;work integer;
BEGIN
 PERFORM kaname._authority_access_label_generation_latch_require_v1(false);
 required:=p_certificate->'required';work:=(p_certificate->>'work')::integer;
 IF jsonb_typeof(required) IS DISTINCT FROM 'object' OR work IS NULL THEN
  RAISE EXCEPTION 'generation lifecycle requirements unavailable' USING ERRCODE='42501';END IF;
 FOR root IN SELECT value FROM jsonb_array_elements(p_capture->'roots') LOOP
  IF root#>>'{state,2,root_type}' IN ('iam.account','iam.project','iam.serviceAccount') THEN CONTINUE;END IF;
  graph:=p_certificate->'graphs'->(jsonb_build_array(root#>>'{state,2,root_type}',root#>>'{state,2,root_id}')::text);
  IF jsonb_typeof(graph->'projects') IS DISTINCT FROM 'object' THEN
   RAISE EXCEPTION 'generation lifecycle project census unavailable' USING ERRCODE='42501';END IF;
  FOR identifier IN SELECT jsonb_object_keys(graph->'projects') LOOP
   source:=kaname._authority_resource_require_capture_v2(p_index,1,'project',identifier);
   IF jsonb_array_length(source->'states')>1 THEN
    RAISE EXCEPTION 'generation lifecycle project identity ambiguous' USING ERRCODE='42501';END IF;
   required:=required||jsonb_build_object(jsonb_build_array(1,'project',identifier,'')::text,true);work:=work+1;
  END LOOP;
 END LOOP;
 IF work>100000 OR (SELECT count(*) FROM jsonb_object_keys(required))>4096 THEN
  RAISE EXCEPTION 'generation lifecycle requirements exceeded' USING ERRCODE='54000';END IF;
 RETURN p_certificate||jsonb_build_object('required',required,'work',work);
END;
$fn$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $private$
DECLARE target regprocedure;recipient record;
BEGIN
 FOREACH target IN ARRAY ARRAY['kaname._authority_access_label_generation_lifecycle_validate_v1(jsonb,jsonb)'::regprocedure,'kaname._authority_access_label_generation_lifecycle_plan_v1(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,integer,integer,integer)'::regprocedure,'kaname._authority_access_label_generation_lifecycle_finish_v1(jsonb,jsonb,integer,integer)'::regprocedure,'kaname._authority_access_label_generation_lifecycle_requirements_v1(jsonb,jsonb,jsonb)'::regprocedure] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',target);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_proc p
   CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   JOIN pg_roles r ON r.oid=a.grantee WHERE p.oid=target AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',target,recipient.rolname);
  END LOOP;
 END LOOP;
END;
$private$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','d967ea237f994bd6651e8f7df77a074a4408d0edcff38d550fa611e03174c336','aed0564d7394c2b2880c24f2176e706bc430f81c746c856c5d5c570ac8586446',
  $changes$[
 [
  " generation_program jsonb;generation_write_wait jsonb;",
  " lifecycle jsonb;generation_program jsonb;generation_write_wait jsonb;"
 ],
 [
  "  certificate:=kaname._authority_access_label_generation_graphs_v1(source_index,catalog,certificate,generation->'capture');",
  "  certificate:=kaname._authority_access_label_generation_graphs_v1(source_index,catalog,certificate,generation->'capture');\n  certificate:=kaname._authority_access_label_generation_lifecycle_requirements_v1(generation->'capture',certificate,source_index);"
 ],
 [
  "  generation_write_wait:=kaname._authority_access_label_generation_write_wait_v1(",
  "  lifecycle:=kaname._authority_access_label_generation_lifecycle_plan_v1(\n   generation->'capture',certificate,source_index,current_result.held_rows,binding_hold,catalog_result.catalog_rows,\n   p_rows-used_rows,p_reads-used_reads,100000-(certificate->>'work')::integer);\n  used_rows:=used_rows+(lifecycle->>'rows')::integer;used_reads:=used_reads+(lifecycle->>'reads')::integer;\n  certificate:=jsonb_set(certificate,'{work}',to_jsonb((certificate->>'work')::integer+(lifecycle->>'work')::integer));\n  generation:=generation||jsonb_build_object('lifecycle',lifecycle->'roots');\n  generation_write_wait:=kaname._authority_access_label_generation_write_wait_v1("
 ]
]$changes$::jsonb),
 ('_authority_access_label_generation_prepare_v1(text,text,text,integer,integer)','891930342ce17c3fd9d35dc1068a7fb9f5eadbaa363305b583ed695f50b7f4de','49a89fd9042c168aaf7f5c8c05e291a5a97aa0c61dfe822f95732f2cfa12dfde',
  $changes$[
 [
  " IF EXISTS(SELECT 1 FROM jsonb_array_elements(first_capture->'roots') r\n  WHERE r#>>'{state,2,root_type}' NOT IN ('iam.account','iam.project','iam.serviceAccount')) THEN\n  RAISE EXCEPTION 'external generation completion is not admitted' USING ERRCODE='42501';END IF;",
  " -- Допуск закрытия внешнего корня ниже требует owner lifecycle certificate.\n -- Здесь захватывается только полное поколение под ранними root guards."
 ]
]$changes$::jsonb),
 ('_authority_access_label_generation_write_wait_v1(jsonb,integer,integer)','5e8ed09502f74b405a0c1bf158ee9f58843496987284501677508eb99657f887','ab379f18437a4de42305a13452a0242af6c3d401a75fb11365b0ad9d7acd199f',
  $changes$[
 [
  " IF EXISTS(SELECT 1 FROM jsonb_array_elements(capture->'roots') r\n  WHERE r#>>'{state,2,root_type}' NOT IN ('iam.account','iam.project','iam.serviceAccount')) THEN\n  RAISE EXCEPTION 'external generation completion is not admitted' USING ERRCODE='42501';END IF;",
  " IF EXISTS(SELECT 1 FROM jsonb_array_elements(capture->'roots') r\n  WHERE r#>>'{state,2,root_type}' NOT IN ('iam.account','iam.project','iam.serviceAccount')\n   AND (jsonb_typeof(p_generation->'lifecycle'->(jsonb_build_array(r#>>'{state,2,root_type}',r#>>'{state,2,root_id}')::text))\n    IS DISTINCT FROM 'object')) THEN\n  RAISE EXCEPTION 'external generation lifecycle is not certified' USING ERRCODE='42501';END IF;"
 ]
]$changes$::jsonb),
 ('_authority_access_label_generation_reserve_v1(jsonb,integer,integer)','a5534c220f2aecea6de405b3605f3580bd2f3ddd7e6dc049b64e182ec46f7478','ad4bd254b62c4ac19afb4833b0bbd583b710133a7be24ef33f8d675e8070bba0',
  $changes$[
 [
  "\nDECLARE program jsonb;budget_rows bigint;budget_reads bigint;\nBEGIN\n PERFORM kaname._authority_access_label_generation_latch_require_v1(false);\n IF p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000\n  OR p_reads IS NULL OR p_reads NOT BETWEEN 0 AND 4096 THEN\n  RAISE EXCEPTION 'generation completion reservation budget invalid' USING ERRCODE='54000';\n END IF;\n IF jsonb_typeof(p_held#>'{capture,roots}') IS DISTINCT FROM 'array'\n  OR jsonb_typeof(p_held->'held_advisory') IS DISTINCT FROM 'array'\n  OR jsonb_array_length(p_held#>'{capture,roots}')>4096 THEN\n  RAISE EXCEPTION 'generation completion reservation shape invalid' USING ERRCODE='42501';\n END IF;\n WITH receipts AS MATERIALIZED (\n   SELECT r AS receipt,jsonb_array_length(r->'facts') AS facts\n   FROM jsonb_array_elements(p_held#>'{capture,roots}') r\n ), bounded AS MATERIALIZED (\n   SELECT receipt,4+3::bigint*facts AS rows,4+facts::bigint AS reads FROM receipts\n ), costs AS MATERIALIZED (\n   SELECT coalesce(sum(rows),0)::bigint AS rows,coalesce(sum(reads),0)::bigint AS reads FROM bounded\n )\n SELECT c.rows,c.reads,CASE WHEN c.rows<=p_rows AND c.reads<=p_reads THEN\n   (SELECT coalesce(jsonb_agg(jsonb_build_object('receipt',b.receipt,'reserved_rows',b.rows,\n     'reserved_reads',b.reads) ORDER BY b.receipt#>>'{state,2,root_type}' COLLATE \"C\",\n     b.receipt#>>'{state,2,root_id}' COLLATE \"C\"),'[]'::jsonb) FROM bounded b)\n END\n INTO budget_rows,budget_reads,program FROM costs c;\n IF program IS NULL OR budget_rows>p_rows OR budget_reads>p_reads THEN\n  RAISE EXCEPTION 'generation completion exceeds shared budget' USING ERRCODE='54000';\n END IF;\n RETURN jsonb_build_object('roots',program,'reserved_rows',budget_rows,'reserved_reads',budget_reads);\nEND;\n",
  "\nDECLARE program jsonb:='[]';budget_rows bigint:=0;budget_reads bigint:=0;\n receipt jsonb;cost jsonb;rows_reserved bigint;reads_reserved bigint;key_value text;\nBEGIN\n PERFORM kaname._authority_access_label_generation_latch_require_v1(false);\n IF p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 0 AND 4096 THEN\n  RAISE EXCEPTION 'generation completion reservation budget invalid' USING ERRCODE='54000';END IF;\n IF jsonb_typeof(p_held#>'{capture,roots}') IS DISTINCT FROM 'array'\n OR jsonb_typeof(p_held->'held_advisory') IS DISTINCT FROM 'array' OR jsonb_array_length(p_held#>'{capture,roots}')>4096 THEN\n  RAISE EXCEPTION 'generation completion reservation shape invalid' USING ERRCODE='42501';END IF;\n FOR receipt IN SELECT value FROM jsonb_array_elements(p_held#>'{capture,roots}')\n  ORDER BY value#>>'{state,2,root_type}' COLLATE \"C\",value#>>'{state,2,root_id}' COLLATE \"C\" LOOP\n  cost:='{\"rows\":0,\"reads\":0}'::jsonb;\n  IF receipt#>>'{state,2,root_type}' NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN\n   key_value:=jsonb_build_array(receipt#>>'{state,2,root_type}',receipt#>>'{state,2,root_id}')::text;\n   receipt:=receipt||jsonb_build_object('lifecycle',p_held->'lifecycle'->key_value);\n   cost:=kaname._authority_access_label_generation_lifecycle_validate_v1(receipt->'lifecycle',receipt->'state');\n  END IF;\n  rows_reserved:=4+3::bigint*jsonb_array_length(receipt->'facts')+(cost->>'rows')::bigint;\n  reads_reserved:=4+jsonb_array_length(receipt->'facts')::bigint+(cost->>'reads')::bigint;\n  budget_rows:=budget_rows+rows_reserved;budget_reads:=budget_reads+reads_reserved;\n  IF budget_rows>p_rows OR budget_reads>p_reads THEN\n   RAISE EXCEPTION 'generation completion exceeds shared budget' USING ERRCODE='54000';END IF;\n  program:=program||jsonb_build_array(jsonb_build_object('receipt',receipt,'reserved_rows',rows_reserved,'reserved_reads',reads_reserved));\n END LOOP;\n RETURN jsonb_build_object('roots',program,'reserved_rows',budget_rows,'reserved_reads',budget_reads);\nEND;\n"
 ]
]$changes$::jsonb),
 ('_authority_access_label_generation_discharge_v1(jsonb,jsonb,jsonb,jsonb,timestamptz,integer)','753a8da9eb64f88c4adc7e6969eeb15eca68170defc3df7ebe914b0fcc8f5f9f','3900dfe8f33716564059882e47ccd4ad734922493c53811595dd1b232f9ea484',
  $changes$[
 [
  " pending_count integer;flat_count integer;",
  " pending_count integer;flat_count integer;lifecycle_cost jsonb;"
 ],
 [
  "   OR coalesce(root_row->>'root_type','') NOT IN ('iam.account','iam.project','iam.serviceAccount')",
  "   OR kaname._authority_access_label_dirty_root_type_valid_v1(root_row->>'root_type') IS DISTINCT FROM true"
 ],
 [
  "  reserve_rows:=(entry.value->>'reserved_rows')::integer;",
  "  lifecycle_cost:='{\"rows\":0,\"reads\":0,\"work\":0}'::jsonb;\n  IF root_row->>'root_type' NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN\n   lifecycle_cost:=kaname._authority_access_label_generation_lifecycle_validate_v1(receipt->'lifecycle',receipt->'state');\n  END IF;\n  reserve_rows:=(entry.value->>'reserved_rows')::integer;"
 ],
 [
  "  IF reserve_rows<4+3*count_facts OR reserve_reads<4+count_facts THEN",
  "  IF reserve_rows<4+3*count_facts+(lifecycle_cost->>'rows')::integer\n   OR reserve_reads<4+count_facts+(lifecycle_cost->>'reads')::integer THEN"
 ],
 [
  "  work:=work+1+3*count_facts;",
  "  work:=work+1+3*count_facts+(lifecycle_cost->>'work')::integer;"
 ]
]$changes$::jsonb),
 ('_authority_access_label_object_generation_finish_v1(jsonb,jsonb,integer,integer)','836ee3bddf4e49cf71ab918648cddd724d6c7146173ba06457fd5f6f53efb7c4','024a76a4c696799f0fcb173696ae37b8e7a98a9f5bfd0de77348bb472b248e33',
  $changes$[
 [
  " reserve_rows integer;reserve_reads integer;invalid_partition boolean;invalid_readback boolean;",
  " reserve_rows integer;reserve_reads integer;invalid_partition boolean;invalid_readback boolean;\n lifecycle_cost jsonb:='{\"rows\":0,\"reads\":0}'::jsonb;"
 ],
 [
  " IF v_root_type IS NULL OR v_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount')",
  " IF kaname._authority_access_label_dirty_root_type_valid_v1(v_root_type) IS DISTINCT FROM true"
 ],
 [
  " count_facts:=jsonb_array_length(p_receipt->'facts');",
  " IF v_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN\n  lifecycle_cost:=kaname._authority_access_label_generation_lifecycle_validate_v1(p_receipt->'lifecycle',p_receipt->'state');\n END IF;\n count_facts:=jsonb_array_length(p_receipt->'facts');"
 ],
 [
  " reserve_rows:=4+2*count_facts+count_confirmed;\n reserve_reads:=4+count_confirmed;",
  " reserve_rows:=4+2*count_facts+count_confirmed+(lifecycle_cost->>'rows')::integer;\n reserve_reads:=4+count_confirmed+(lifecycle_cost->>'reads')::integer;"
 ],
 [
  " DELETE FROM kaname.authority_access_label_dirty_fact f",
  " IF v_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN\n  PERFORM kaname._authority_access_label_generation_lifecycle_finish_v1(p_receipt->'lifecycle',p_receipt->'state',\n   (lifecycle_cost->>'rows')::integer,(lifecycle_cost->>'reads')::integer);\n END IF;\n\n DELETE FROM kaname.authority_access_label_dirty_fact f"
 ]
]$changes$::jsonb),
 ('_authority_crud_storage_v3()','56f15c782bbb6377d478b368271e44710d90104280b1335354742bb0d638cf2a','606347bf48fc31bde651be9822cb2dd89d7897a570fda2b5d15c4f4e617e291d',
  $changes$[
 [
  " ('_authority_access_label_generation_binding_read_hold_v1(jsonb,jsonb,jsonb,integer,integer,integer)','740bbbb7903d3fe059561165d0ba4486b7d5fd15822c5a8881da20b3f7de157d',false,'v',true,'private'),",
  " ('_authority_access_label_generation_lifecycle_validate_v1(jsonb,jsonb)','20961329fbde39231a81df6cfdc98857b525475e9179c190998283f84a219859',false,'v',true,'private'),\n ('_authority_access_label_generation_lifecycle_plan_v1(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,integer,integer,integer)','3f903b3dc8d1af5cf52841607f09df30d55ccc797b8e5d27d49e4d824666a100',false,'v',true,'private'),\n ('_authority_access_label_generation_lifecycle_finish_v1(jsonb,jsonb,integer,integer)','f4b57581ee948805697006a7b8065408b93b3044a27eceb4dfa3807d79631903',false,'v',true,'private'),\n ('_authority_access_label_generation_lifecycle_requirements_v1(jsonb,jsonb,jsonb)','1763740cb963df0df4cfc8f2b1f0bb4d46f2c6d992e652c63b2132bc71c8635a',false,'v',true,'private'),\n ('_authority_access_label_generation_binding_read_hold_v1(jsonb,jsonb,jsonb,integer,integer,integer)','740bbbb7903d3fe059561165d0ba4486b7d5fd15822c5a8881da20b3f7de157d',false,'v',true,'private'),"
 ],
 [
  "  ('_authority_access_label_generation_binding_read_hold_v1(jsonb,jsonb,jsonb,integer,integer,integer)','jsonb',6,ARRAY['p_capture','p_certificate','p_index','p_rows','p_reads','p_keys']),",
  "  ('_authority_access_label_generation_lifecycle_validate_v1(jsonb,jsonb)','jsonb',2,ARRAY['p_lifecycle','p_root_state']),\n  ('_authority_access_label_generation_lifecycle_plan_v1(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,integer,integer,integer)','jsonb',9,ARRAY['p_capture','p_certificate','p_index','p_current','p_binding','p_catalog','p_rows','p_reads','p_work']),\n  ('_authority_access_label_generation_lifecycle_finish_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_lifecycle','p_root_state','p_rows','p_reads']),\n  ('_authority_access_label_generation_lifecycle_requirements_v1(jsonb,jsonb,jsonb)','jsonb',3,ARRAY['p_capture','p_certificate','p_index']),\n  ('_authority_access_label_generation_binding_read_hold_v1(jsonb,jsonb,jsonb,integer,integer,integer)','jsonb',6,ARRAY['p_capture','p_certificate','p_index','p_rows','p_reads','p_keys']),"
 ],
 [
  "d967ea237f994bd6651e8f7df77a074a4408d0edcff38d550fa611e03174c336",
  "aed0564d7394c2b2880c24f2176e706bc430f81c746c856c5d5c570ac8586446"
 ],
 [
  "891930342ce17c3fd9d35dc1068a7fb9f5eadbaa363305b583ed695f50b7f4de",
  "49a89fd9042c168aaf7f5c8c05e291a5a97aa0c61dfe822f95732f2cfa12dfde"
 ],
 [
  "5e8ed09502f74b405a0c1bf158ee9f58843496987284501677508eb99657f887",
  "ab379f18437a4de42305a13452a0242af6c3d401a75fb11365b0ad9d7acd199f"
 ],
 [
  "a5534c220f2aecea6de405b3605f3580bd2f3ddd7e6dc049b64e182ec46f7478",
  "ad4bd254b62c4ac19afb4833b0bbd583b710133a7be24ef33f8d675e8070bba0"
 ],
 [
  "753a8da9eb64f88c4adc7e6969eeb15eca68170defc3df7ebe914b0fcc8f5f9f",
  "3900dfe8f33716564059882e47ccd4ad734922493c53811595dd1b232f9ea484"
 ],
 [
  "836ee3bddf4e49cf71ab918648cddd724d6c7146173ba06457fd5f6f53efb7c4",
  "024a76a4c696799f0fcb173696ae37b8e7a98a9f5bfd0de77348bb472b248e33"
 ]
]$changes$::jsonb),
 ('authority_metadata_service_account_access_label_ready_v1()','d67066668d5b82f23358662634aa815f010be19d0bf3ec63411ef222e6379dd0','27a1394930bf7124626312871154a81273124a54a5d860f9a60a2c283d4fb8e8',
  $changes$[
 [
  "753a8da9eb64f88c4adc7e6969eeb15eca68170defc3df7ebe914b0fcc8f5f9f",
  "3900dfe8f33716564059882e47ccd4ad734922493c53811595dd1b232f9ea484"
 ],
 [
  "836ee3bddf4e49cf71ab918648cddd724d6c7146173ba06457fd5f6f53efb7c4",
  "024a76a4c696799f0fcb173696ae37b8e7a98a9f5bfd0de77348bb472b248e33"
 ],
 [
  "56f15c782bbb6377d478b368271e44710d90104280b1335354742bb0d638cf2a",
  "8c84ee49978aca3378ce3b8ba6218c233d46ce1d57d9b90337e4c7a600e92cb6"
 ],
 [
  "8c84ee49978aca3378ce3b8ba6218c233d46ce1d57d9b90337e4c7a600e92cb6",
  "3ef50a61037ebdeef828209754baa8ed316158fe4678222736c9caa6bbde09da"
 ],
 [
  "3ef50a61037ebdeef828209754baa8ed316158fe4678222736c9caa6bbde09da",
  "a9dc37c8ce48e736ab52ce2ce765f0c645b14de6fe3bfd29a7ab7d112ebfb09f"
 ],
 [
  "a9dc37c8ce48e736ab52ce2ce765f0c645b14de6fe3bfd29a7ab7d112ebfb09f",
  "76ddb6d7dea3fd126acc45fcf7f99f78632300c2f9a4fc4498402bb07ed8ad97"
 ],
 [
  "76ddb6d7dea3fd126acc45fcf7f99f78632300c2f9a4fc4498402bb07ed8ad97",
  "78eef3ba30f1c1a5f1843fbbe82b46325924c78fbfb43327aabd2831a0404da1"
 ],
 [
  "78eef3ba30f1c1a5f1843fbbe82b46325924c78fbfb43327aabd2831a0404da1",
  "a6467f3afc8a82200c25ff2128bbaaed772b7fff124fc9cc99a9d1f297a72184"
 ],
 [
  "a6467f3afc8a82200c25ff2128bbaaed772b7fff124fc9cc99a9d1f297a72184",
  "606347bf48fc31bde651be9822cb2dd89d7897a570fda2b5d15c4f4e617e291d"
 ],
 [
  "b963938a65cbea58f5bc7605bb2910fc33bc2eb8b16fa04c0be4c29ffe8218de",
  "a15c43197e8ba4599176dd0ebaa4262a8d3692bfab3d71a97a8efdd7fa81582d"
 ],
 [
  "a15c43197e8ba4599176dd0ebaa4262a8d3692bfab3d71a97a8efdd7fa81582d",
  "0fdd1b4d925b8caa65dc615ae10a015aebb1cff8b0804611dd82b12e3f5c7317"
 ],
 [
  "0fdd1b4d925b8caa65dc615ae10a015aebb1cff8b0804611dd82b12e3f5c7317",
  "2feab11c2469aa54ba098d2cf19d69a5b005080540aed413a31e505dddcfec8a"
 ],
 [
  "2feab11c2469aa54ba098d2cf19d69a5b005080540aed413a31e505dddcfec8a",
  "0d181b5dfdf09f797399d8a59cfcda7b5b44a628cfd14e25537be41950e10483"
 ],
 [
  "0d181b5dfdf09f797399d8a59cfcda7b5b44a628cfd14e25537be41950e10483",
  "52acb018432add4ab0f61c9abb1fef17ccafdf19ba2a037e2f986090c3a4e591"
 ],
 [
  "52acb018432add4ab0f61c9abb1fef17ccafdf19ba2a037e2f986090c3a4e591",
  "eb15e6a554fc81a7e8b653a6b93a69e9019c01546c9af11eab8660e339ea693a"
 ],
 [
  "eb15e6a554fc81a7e8b653a6b93a69e9019c01546c9af11eab8660e339ea693a",
  "901778b1bbb405abe217911e9f3b51ecfa6b253fa277935b1368b27e155a982b"
 ]
]$changes$::jsonb),
 ('_authority_full_contract_storage_v3()','b963938a65cbea58f5bc7605bb2910fc33bc2eb8b16fa04c0be4c29ffe8218de','901778b1bbb405abe217911e9f3b51ecfa6b253fa277935b1368b27e155a982b',
  $changes$[
 [
  "56f15c782bbb6377d478b368271e44710d90104280b1335354742bb0d638cf2a",
  "8c84ee49978aca3378ce3b8ba6218c233d46ce1d57d9b90337e4c7a600e92cb6"
 ],
 [
  "8c84ee49978aca3378ce3b8ba6218c233d46ce1d57d9b90337e4c7a600e92cb6",
  "3ef50a61037ebdeef828209754baa8ed316158fe4678222736c9caa6bbde09da"
 ],
 [
  "3ef50a61037ebdeef828209754baa8ed316158fe4678222736c9caa6bbde09da",
  "a9dc37c8ce48e736ab52ce2ce765f0c645b14de6fe3bfd29a7ab7d112ebfb09f"
 ],
 [
  "a9dc37c8ce48e736ab52ce2ce765f0c645b14de6fe3bfd29a7ab7d112ebfb09f",
  "76ddb6d7dea3fd126acc45fcf7f99f78632300c2f9a4fc4498402bb07ed8ad97"
 ],
 [
  "76ddb6d7dea3fd126acc45fcf7f99f78632300c2f9a4fc4498402bb07ed8ad97",
  "78eef3ba30f1c1a5f1843fbbe82b46325924c78fbfb43327aabd2831a0404da1"
 ],
 [
  "78eef3ba30f1c1a5f1843fbbe82b46325924c78fbfb43327aabd2831a0404da1",
  "a6467f3afc8a82200c25ff2128bbaaed772b7fff124fc9cc99a9d1f297a72184"
 ],
 [
  "a6467f3afc8a82200c25ff2128bbaaed772b7fff124fc9cc99a9d1f297a72184",
  "606347bf48fc31bde651be9822cb2dd89d7897a570fda2b5d15c4f4e617e291d"
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
DO $unfinished$
BEGIN
 IF EXISTS(SELECT 1 FROM kaname.authority_access_label_dirty_root
  WHERE root_type NOT IN ('iam.account','iam.project','iam.serviceAccount')) THEN
  RAISE EXCEPTION 'external generations must drain before lifecycle rollback' USING ERRCODE='55000';END IF;
END;
$unfinished$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('_authority_full_contract_storage_v3()','901778b1bbb405abe217911e9f3b51ecfa6b253fa277935b1368b27e155a982b','b963938a65cbea58f5bc7605bb2910fc33bc2eb8b16fa04c0be4c29ffe8218de',
  $changes$[
 [
  "606347bf48fc31bde651be9822cb2dd89d7897a570fda2b5d15c4f4e617e291d",
  "a6467f3afc8a82200c25ff2128bbaaed772b7fff124fc9cc99a9d1f297a72184"
 ],
 [
  "a6467f3afc8a82200c25ff2128bbaaed772b7fff124fc9cc99a9d1f297a72184",
  "78eef3ba30f1c1a5f1843fbbe82b46325924c78fbfb43327aabd2831a0404da1"
 ],
 [
  "78eef3ba30f1c1a5f1843fbbe82b46325924c78fbfb43327aabd2831a0404da1",
  "76ddb6d7dea3fd126acc45fcf7f99f78632300c2f9a4fc4498402bb07ed8ad97"
 ],
 [
  "76ddb6d7dea3fd126acc45fcf7f99f78632300c2f9a4fc4498402bb07ed8ad97",
  "a9dc37c8ce48e736ab52ce2ce765f0c645b14de6fe3bfd29a7ab7d112ebfb09f"
 ],
 [
  "a9dc37c8ce48e736ab52ce2ce765f0c645b14de6fe3bfd29a7ab7d112ebfb09f",
  "3ef50a61037ebdeef828209754baa8ed316158fe4678222736c9caa6bbde09da"
 ],
 [
  "3ef50a61037ebdeef828209754baa8ed316158fe4678222736c9caa6bbde09da",
  "8c84ee49978aca3378ce3b8ba6218c233d46ce1d57d9b90337e4c7a600e92cb6"
 ],
 [
  "8c84ee49978aca3378ce3b8ba6218c233d46ce1d57d9b90337e4c7a600e92cb6",
  "56f15c782bbb6377d478b368271e44710d90104280b1335354742bb0d638cf2a"
 ]
]$changes$::jsonb),
 ('authority_metadata_service_account_access_label_ready_v1()','27a1394930bf7124626312871154a81273124a54a5d860f9a60a2c283d4fb8e8','d67066668d5b82f23358662634aa815f010be19d0bf3ec63411ef222e6379dd0',
  $changes$[
 [
  "901778b1bbb405abe217911e9f3b51ecfa6b253fa277935b1368b27e155a982b",
  "eb15e6a554fc81a7e8b653a6b93a69e9019c01546c9af11eab8660e339ea693a"
 ],
 [
  "eb15e6a554fc81a7e8b653a6b93a69e9019c01546c9af11eab8660e339ea693a",
  "52acb018432add4ab0f61c9abb1fef17ccafdf19ba2a037e2f986090c3a4e591"
 ],
 [
  "52acb018432add4ab0f61c9abb1fef17ccafdf19ba2a037e2f986090c3a4e591",
  "0d181b5dfdf09f797399d8a59cfcda7b5b44a628cfd14e25537be41950e10483"
 ],
 [
  "0d181b5dfdf09f797399d8a59cfcda7b5b44a628cfd14e25537be41950e10483",
  "2feab11c2469aa54ba098d2cf19d69a5b005080540aed413a31e505dddcfec8a"
 ],
 [
  "2feab11c2469aa54ba098d2cf19d69a5b005080540aed413a31e505dddcfec8a",
  "0fdd1b4d925b8caa65dc615ae10a015aebb1cff8b0804611dd82b12e3f5c7317"
 ],
 [
  "0fdd1b4d925b8caa65dc615ae10a015aebb1cff8b0804611dd82b12e3f5c7317",
  "a15c43197e8ba4599176dd0ebaa4262a8d3692bfab3d71a97a8efdd7fa81582d"
 ],
 [
  "a15c43197e8ba4599176dd0ebaa4262a8d3692bfab3d71a97a8efdd7fa81582d",
  "b963938a65cbea58f5bc7605bb2910fc33bc2eb8b16fa04c0be4c29ffe8218de"
 ],
 [
  "606347bf48fc31bde651be9822cb2dd89d7897a570fda2b5d15c4f4e617e291d",
  "a6467f3afc8a82200c25ff2128bbaaed772b7fff124fc9cc99a9d1f297a72184"
 ],
 [
  "a6467f3afc8a82200c25ff2128bbaaed772b7fff124fc9cc99a9d1f297a72184",
  "78eef3ba30f1c1a5f1843fbbe82b46325924c78fbfb43327aabd2831a0404da1"
 ],
 [
  "78eef3ba30f1c1a5f1843fbbe82b46325924c78fbfb43327aabd2831a0404da1",
  "76ddb6d7dea3fd126acc45fcf7f99f78632300c2f9a4fc4498402bb07ed8ad97"
 ],
 [
  "76ddb6d7dea3fd126acc45fcf7f99f78632300c2f9a4fc4498402bb07ed8ad97",
  "a9dc37c8ce48e736ab52ce2ce765f0c645b14de6fe3bfd29a7ab7d112ebfb09f"
 ],
 [
  "a9dc37c8ce48e736ab52ce2ce765f0c645b14de6fe3bfd29a7ab7d112ebfb09f",
  "3ef50a61037ebdeef828209754baa8ed316158fe4678222736c9caa6bbde09da"
 ],
 [
  "3ef50a61037ebdeef828209754baa8ed316158fe4678222736c9caa6bbde09da",
  "8c84ee49978aca3378ce3b8ba6218c233d46ce1d57d9b90337e4c7a600e92cb6"
 ],
 [
  "8c84ee49978aca3378ce3b8ba6218c233d46ce1d57d9b90337e4c7a600e92cb6",
  "56f15c782bbb6377d478b368271e44710d90104280b1335354742bb0d638cf2a"
 ],
 [
  "024a76a4c696799f0fcb173696ae37b8e7a98a9f5bfd0de77348bb472b248e33",
  "836ee3bddf4e49cf71ab918648cddd724d6c7146173ba06457fd5f6f53efb7c4"
 ],
 [
  "3900dfe8f33716564059882e47ccd4ad734922493c53811595dd1b232f9ea484",
  "753a8da9eb64f88c4adc7e6969eeb15eca68170defc3df7ebe914b0fcc8f5f9f"
 ]
]$changes$::jsonb),
 ('_authority_crud_storage_v3()','606347bf48fc31bde651be9822cb2dd89d7897a570fda2b5d15c4f4e617e291d','56f15c782bbb6377d478b368271e44710d90104280b1335354742bb0d638cf2a',
  $changes$[
 [
  "024a76a4c696799f0fcb173696ae37b8e7a98a9f5bfd0de77348bb472b248e33",
  "836ee3bddf4e49cf71ab918648cddd724d6c7146173ba06457fd5f6f53efb7c4"
 ],
 [
  "3900dfe8f33716564059882e47ccd4ad734922493c53811595dd1b232f9ea484",
  "753a8da9eb64f88c4adc7e6969eeb15eca68170defc3df7ebe914b0fcc8f5f9f"
 ],
 [
  "ad4bd254b62c4ac19afb4833b0bbd583b710133a7be24ef33f8d675e8070bba0",
  "a5534c220f2aecea6de405b3605f3580bd2f3ddd7e6dc049b64e182ec46f7478"
 ],
 [
  "ab379f18437a4de42305a13452a0242af6c3d401a75fb11365b0ad9d7acd199f",
  "5e8ed09502f74b405a0c1bf158ee9f58843496987284501677508eb99657f887"
 ],
 [
  "49a89fd9042c168aaf7f5c8c05e291a5a97aa0c61dfe822f95732f2cfa12dfde",
  "891930342ce17c3fd9d35dc1068a7fb9f5eadbaa363305b583ed695f50b7f4de"
 ],
 [
  "aed0564d7394c2b2880c24f2176e706bc430f81c746c856c5d5c570ac8586446",
  "d967ea237f994bd6651e8f7df77a074a4408d0edcff38d550fa611e03174c336"
 ],
 [
  "  ('_authority_access_label_generation_lifecycle_validate_v1(jsonb,jsonb)','jsonb',2,ARRAY['p_lifecycle','p_root_state']),\n  ('_authority_access_label_generation_lifecycle_plan_v1(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,integer,integer,integer)','jsonb',9,ARRAY['p_capture','p_certificate','p_index','p_current','p_binding','p_catalog','p_rows','p_reads','p_work']),\n  ('_authority_access_label_generation_lifecycle_finish_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_lifecycle','p_root_state','p_rows','p_reads']),\n  ('_authority_access_label_generation_lifecycle_requirements_v1(jsonb,jsonb,jsonb)','jsonb',3,ARRAY['p_capture','p_certificate','p_index']),\n  ('_authority_access_label_generation_binding_read_hold_v1(jsonb,jsonb,jsonb,integer,integer,integer)','jsonb',6,ARRAY['p_capture','p_certificate','p_index','p_rows','p_reads','p_keys']),",
  "  ('_authority_access_label_generation_binding_read_hold_v1(jsonb,jsonb,jsonb,integer,integer,integer)','jsonb',6,ARRAY['p_capture','p_certificate','p_index','p_rows','p_reads','p_keys']),"
 ],
 [
  " ('_authority_access_label_generation_lifecycle_validate_v1(jsonb,jsonb)','20961329fbde39231a81df6cfdc98857b525475e9179c190998283f84a219859',false,'v',true,'private'),\n ('_authority_access_label_generation_lifecycle_plan_v1(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,integer,integer,integer)','3f903b3dc8d1af5cf52841607f09df30d55ccc797b8e5d27d49e4d824666a100',false,'v',true,'private'),\n ('_authority_access_label_generation_lifecycle_finish_v1(jsonb,jsonb,integer,integer)','f4b57581ee948805697006a7b8065408b93b3044a27eceb4dfa3807d79631903',false,'v',true,'private'),\n ('_authority_access_label_generation_lifecycle_requirements_v1(jsonb,jsonb,jsonb)','1763740cb963df0df4cfc8f2b1f0bb4d46f2c6d992e652c63b2132bc71c8635a',false,'v',true,'private'),\n ('_authority_access_label_generation_binding_read_hold_v1(jsonb,jsonb,jsonb,integer,integer,integer)','740bbbb7903d3fe059561165d0ba4486b7d5fd15822c5a8881da20b3f7de157d',false,'v',true,'private'),",
  " ('_authority_access_label_generation_binding_read_hold_v1(jsonb,jsonb,jsonb,integer,integer,integer)','740bbbb7903d3fe059561165d0ba4486b7d5fd15822c5a8881da20b3f7de157d',false,'v',true,'private'),"
 ]
]$changes$::jsonb),
 ('_authority_access_label_object_generation_finish_v1(jsonb,jsonb,integer,integer)','024a76a4c696799f0fcb173696ae37b8e7a98a9f5bfd0de77348bb472b248e33','836ee3bddf4e49cf71ab918648cddd724d6c7146173ba06457fd5f6f53efb7c4',
  $changes$[
 [
  " IF v_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN\n  PERFORM kaname._authority_access_label_generation_lifecycle_finish_v1(p_receipt->'lifecycle',p_receipt->'state',\n   (lifecycle_cost->>'rows')::integer,(lifecycle_cost->>'reads')::integer);\n END IF;\n\n DELETE FROM kaname.authority_access_label_dirty_fact f",
  " DELETE FROM kaname.authority_access_label_dirty_fact f"
 ],
 [
  " reserve_rows:=4+2*count_facts+count_confirmed+(lifecycle_cost->>'rows')::integer;\n reserve_reads:=4+count_confirmed+(lifecycle_cost->>'reads')::integer;",
  " reserve_rows:=4+2*count_facts+count_confirmed;\n reserve_reads:=4+count_confirmed;"
 ],
 [
  " IF v_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN\n  lifecycle_cost:=kaname._authority_access_label_generation_lifecycle_validate_v1(p_receipt->'lifecycle',p_receipt->'state');\n END IF;\n count_facts:=jsonb_array_length(p_receipt->'facts');",
  " count_facts:=jsonb_array_length(p_receipt->'facts');"
 ],
 [
  " IF kaname._authority_access_label_dirty_root_type_valid_v1(v_root_type) IS DISTINCT FROM true",
  " IF v_root_type IS NULL OR v_root_type NOT IN ('iam.account','iam.project','iam.serviceAccount')"
 ],
 [
  " reserve_rows integer;reserve_reads integer;invalid_partition boolean;invalid_readback boolean;\n lifecycle_cost jsonb:='{\"rows\":0,\"reads\":0}'::jsonb;",
  " reserve_rows integer;reserve_reads integer;invalid_partition boolean;invalid_readback boolean;"
 ]
]$changes$::jsonb),
 ('_authority_access_label_generation_discharge_v1(jsonb,jsonb,jsonb,jsonb,timestamptz,integer)','3900dfe8f33716564059882e47ccd4ad734922493c53811595dd1b232f9ea484','753a8da9eb64f88c4adc7e6969eeb15eca68170defc3df7ebe914b0fcc8f5f9f',
  $changes$[
 [
  "  work:=work+1+3*count_facts+(lifecycle_cost->>'work')::integer;",
  "  work:=work+1+3*count_facts;"
 ],
 [
  "  IF reserve_rows<4+3*count_facts+(lifecycle_cost->>'rows')::integer\n   OR reserve_reads<4+count_facts+(lifecycle_cost->>'reads')::integer THEN",
  "  IF reserve_rows<4+3*count_facts OR reserve_reads<4+count_facts THEN"
 ],
 [
  "  lifecycle_cost:='{\"rows\":0,\"reads\":0,\"work\":0}'::jsonb;\n  IF root_row->>'root_type' NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN\n   lifecycle_cost:=kaname._authority_access_label_generation_lifecycle_validate_v1(receipt->'lifecycle',receipt->'state');\n  END IF;\n  reserve_rows:=(entry.value->>'reserved_rows')::integer;",
  "  reserve_rows:=(entry.value->>'reserved_rows')::integer;"
 ],
 [
  "   OR kaname._authority_access_label_dirty_root_type_valid_v1(root_row->>'root_type') IS DISTINCT FROM true",
  "   OR coalesce(root_row->>'root_type','') NOT IN ('iam.account','iam.project','iam.serviceAccount')"
 ],
 [
  " pending_count integer;flat_count integer;lifecycle_cost jsonb;",
  " pending_count integer;flat_count integer;"
 ]
]$changes$::jsonb),
 ('_authority_access_label_generation_reserve_v1(jsonb,integer,integer)','ad4bd254b62c4ac19afb4833b0bbd583b710133a7be24ef33f8d675e8070bba0','a5534c220f2aecea6de405b3605f3580bd2f3ddd7e6dc049b64e182ec46f7478',
  $changes$[
 [
  "\nDECLARE program jsonb:='[]';budget_rows bigint:=0;budget_reads bigint:=0;\n receipt jsonb;cost jsonb;rows_reserved bigint;reads_reserved bigint;key_value text;\nBEGIN\n PERFORM kaname._authority_access_label_generation_latch_require_v1(false);\n IF p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 0 AND 4096 THEN\n  RAISE EXCEPTION 'generation completion reservation budget invalid' USING ERRCODE='54000';END IF;\n IF jsonb_typeof(p_held#>'{capture,roots}') IS DISTINCT FROM 'array'\n OR jsonb_typeof(p_held->'held_advisory') IS DISTINCT FROM 'array' OR jsonb_array_length(p_held#>'{capture,roots}')>4096 THEN\n  RAISE EXCEPTION 'generation completion reservation shape invalid' USING ERRCODE='42501';END IF;\n FOR receipt IN SELECT value FROM jsonb_array_elements(p_held#>'{capture,roots}')\n  ORDER BY value#>>'{state,2,root_type}' COLLATE \"C\",value#>>'{state,2,root_id}' COLLATE \"C\" LOOP\n  cost:='{\"rows\":0,\"reads\":0}'::jsonb;\n  IF receipt#>>'{state,2,root_type}' NOT IN ('iam.account','iam.project','iam.serviceAccount') THEN\n   key_value:=jsonb_build_array(receipt#>>'{state,2,root_type}',receipt#>>'{state,2,root_id}')::text;\n   receipt:=receipt||jsonb_build_object('lifecycle',p_held->'lifecycle'->key_value);\n   cost:=kaname._authority_access_label_generation_lifecycle_validate_v1(receipt->'lifecycle',receipt->'state');\n  END IF;\n  rows_reserved:=4+3::bigint*jsonb_array_length(receipt->'facts')+(cost->>'rows')::bigint;\n  reads_reserved:=4+jsonb_array_length(receipt->'facts')::bigint+(cost->>'reads')::bigint;\n  budget_rows:=budget_rows+rows_reserved;budget_reads:=budget_reads+reads_reserved;\n  IF budget_rows>p_rows OR budget_reads>p_reads THEN\n   RAISE EXCEPTION 'generation completion exceeds shared budget' USING ERRCODE='54000';END IF;\n  program:=program||jsonb_build_array(jsonb_build_object('receipt',receipt,'reserved_rows',rows_reserved,'reserved_reads',reads_reserved));\n END LOOP;\n RETURN jsonb_build_object('roots',program,'reserved_rows',budget_rows,'reserved_reads',budget_reads);\nEND;\n",
  "\nDECLARE program jsonb;budget_rows bigint;budget_reads bigint;\nBEGIN\n PERFORM kaname._authority_access_label_generation_latch_require_v1(false);\n IF p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000\n  OR p_reads IS NULL OR p_reads NOT BETWEEN 0 AND 4096 THEN\n  RAISE EXCEPTION 'generation completion reservation budget invalid' USING ERRCODE='54000';\n END IF;\n IF jsonb_typeof(p_held#>'{capture,roots}') IS DISTINCT FROM 'array'\n  OR jsonb_typeof(p_held->'held_advisory') IS DISTINCT FROM 'array'\n  OR jsonb_array_length(p_held#>'{capture,roots}')>4096 THEN\n  RAISE EXCEPTION 'generation completion reservation shape invalid' USING ERRCODE='42501';\n END IF;\n WITH receipts AS MATERIALIZED (\n   SELECT r AS receipt,jsonb_array_length(r->'facts') AS facts\n   FROM jsonb_array_elements(p_held#>'{capture,roots}') r\n ), bounded AS MATERIALIZED (\n   SELECT receipt,4+3::bigint*facts AS rows,4+facts::bigint AS reads FROM receipts\n ), costs AS MATERIALIZED (\n   SELECT coalesce(sum(rows),0)::bigint AS rows,coalesce(sum(reads),0)::bigint AS reads FROM bounded\n )\n SELECT c.rows,c.reads,CASE WHEN c.rows<=p_rows AND c.reads<=p_reads THEN\n   (SELECT coalesce(jsonb_agg(jsonb_build_object('receipt',b.receipt,'reserved_rows',b.rows,\n     'reserved_reads',b.reads) ORDER BY b.receipt#>>'{state,2,root_type}' COLLATE \"C\",\n     b.receipt#>>'{state,2,root_id}' COLLATE \"C\"),'[]'::jsonb) FROM bounded b)\n END\n INTO budget_rows,budget_reads,program FROM costs c;\n IF program IS NULL OR budget_rows>p_rows OR budget_reads>p_reads THEN\n  RAISE EXCEPTION 'generation completion exceeds shared budget' USING ERRCODE='54000';\n END IF;\n RETURN jsonb_build_object('roots',program,'reserved_rows',budget_rows,'reserved_reads',budget_reads);\nEND;\n"
 ]
]$changes$::jsonb),
 ('_authority_access_label_generation_write_wait_v1(jsonb,integer,integer)','ab379f18437a4de42305a13452a0242af6c3d401a75fb11365b0ad9d7acd199f','5e8ed09502f74b405a0c1bf158ee9f58843496987284501677508eb99657f887',
  $changes$[
 [
  " IF EXISTS(SELECT 1 FROM jsonb_array_elements(capture->'roots') r\n  WHERE r#>>'{state,2,root_type}' NOT IN ('iam.account','iam.project','iam.serviceAccount')\n   AND (jsonb_typeof(p_generation->'lifecycle'->(jsonb_build_array(r#>>'{state,2,root_type}',r#>>'{state,2,root_id}')::text))\n    IS DISTINCT FROM 'object')) THEN\n  RAISE EXCEPTION 'external generation lifecycle is not certified' USING ERRCODE='42501';END IF;",
  " IF EXISTS(SELECT 1 FROM jsonb_array_elements(capture->'roots') r\n  WHERE r#>>'{state,2,root_type}' NOT IN ('iam.account','iam.project','iam.serviceAccount')) THEN\n  RAISE EXCEPTION 'external generation completion is not admitted' USING ERRCODE='42501';END IF;"
 ]
]$changes$::jsonb),
 ('_authority_access_label_generation_prepare_v1(text,text,text,integer,integer)','49a89fd9042c168aaf7f5c8c05e291a5a97aa0c61dfe822f95732f2cfa12dfde','891930342ce17c3fd9d35dc1068a7fb9f5eadbaa363305b583ed695f50b7f4de',
  $changes$[
 [
  " -- Допуск закрытия внешнего корня ниже требует owner lifecycle certificate.\n -- Здесь захватывается только полное поколение под ранними root guards.",
  " IF EXISTS(SELECT 1 FROM jsonb_array_elements(first_capture->'roots') r\n  WHERE r#>>'{state,2,root_type}' NOT IN ('iam.account','iam.project','iam.serviceAccount')) THEN\n  RAISE EXCEPTION 'external generation completion is not admitted' USING ERRCODE='42501';END IF;"
 ]
]$changes$::jsonb),
 ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','aed0564d7394c2b2880c24f2176e706bc430f81c746c856c5d5c570ac8586446','d967ea237f994bd6651e8f7df77a074a4408d0edcff38d550fa611e03174c336',
  $changes$[
 [
  "  lifecycle:=kaname._authority_access_label_generation_lifecycle_plan_v1(\n   generation->'capture',certificate,source_index,current_result.held_rows,binding_hold,catalog_result.catalog_rows,\n   p_rows-used_rows,p_reads-used_reads,100000-(certificate->>'work')::integer);\n  used_rows:=used_rows+(lifecycle->>'rows')::integer;used_reads:=used_reads+(lifecycle->>'reads')::integer;\n  certificate:=jsonb_set(certificate,'{work}',to_jsonb((certificate->>'work')::integer+(lifecycle->>'work')::integer));\n  generation:=generation||jsonb_build_object('lifecycle',lifecycle->'roots');\n  generation_write_wait:=kaname._authority_access_label_generation_write_wait_v1(",
  "  generation_write_wait:=kaname._authority_access_label_generation_write_wait_v1("
 ],
 [
  "  certificate:=kaname._authority_access_label_generation_graphs_v1(source_index,catalog,certificate,generation->'capture');\n  certificate:=kaname._authority_access_label_generation_lifecycle_requirements_v1(generation->'capture',certificate,source_index);",
  "  certificate:=kaname._authority_access_label_generation_graphs_v1(source_index,catalog,certificate,generation->'capture');"
 ],
 [
  " lifecycle jsonb;generation_program jsonb;generation_write_wait jsonb;",
  " generation_program jsonb;generation_write_wait jsonb;"
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
DROP FUNCTION kaname._authority_access_label_generation_lifecycle_requirements_v1(jsonb,jsonb,jsonb);
DROP FUNCTION kaname._authority_access_label_generation_lifecycle_finish_v1(jsonb,jsonb,integer,integer);
DROP FUNCTION kaname._authority_access_label_generation_lifecycle_plan_v1(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,integer,integer,integer);
DROP FUNCTION kaname._authority_access_label_generation_lifecycle_validate_v1(jsonb,jsonb);
