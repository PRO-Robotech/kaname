-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Приватное дополнение существующего object certificate. p_capture получен
-- владельцем после повторного чтения под удержанием всех корней поколения.
-- Дополнительные координаты расширяют только снимок источников и удержания.
-- Команды, выбранные носители и проверенные эффекты сохраняет основной компилятор.
CREATE FUNCTION kaname._authority_access_label_generation_graphs_v1(
 p_index jsonb,p_catalog jsonb,p_certificate jsonb,p_capture jsonb
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $graphs$
DECLARE entry record;targets jsonb;missing integer;graph_images jsonb[];
 graph jsonb;graphs jsonb;new_required jsonb;new_accounts jsonb;new_projects jsonb;
 carriers jsonb;scopes jsonb;binding_ids text[];full_bindings text[];work integer;
BEGIN
 PERFORM kaname._authority_access_label_generation_latch_require_v1(false);
 IF jsonb_typeof(p_capture->'roots') IS DISTINCT FROM 'array'
  OR jsonb_typeof(p_certificate->'graphs') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_certificate->'required') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_certificate->'carriers'->'bindings') IS DISTINCT FROM 'array'
  OR jsonb_typeof(p_certificate->'bindings') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_certificate->'accounts') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_certificate->'projects') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_certificate->'global') IS DISTINCT FROM 'boolean' THEN
  RAISE EXCEPTION 'generation object sources incomplete' USING ERRCODE='42501';
 END IF;
 IF p_capture->'roots'='[]'::jsonb THEN RETURN p_certificate; END IF;
 -- Замкнутый набор выходов берём от owner census, а не из RR proposal.
 -- Стоимость учитывает и повторные выходы разных получателей/поколений.
 WITH census AS MATERIALIZED (
  SELECT f->>'object_type' AS model,f->>'object_id' AS id
  FROM jsonb_array_elements(p_capture->'roots') r
  CROSS JOIN LATERAL jsonb_array_elements(r->'facts') f
 ), model_dictionary AS MATERIALIZED (
  SELECT r->>'ObjectType' AS model,min((r->>'Module')||'.'||(r->>'Resource')) AS dotted
  FROM jsonb_array_elements(coalesce(nullif(p_catalog#>'{Live,Resources}','null'::jsonb),'[]'::jsonb)||
     coalesce(nullif(p_catalog#>'{Retired,Resources}','null'::jsonb),'[]'::jsonb)) r
  GROUP BY r->>'ObjectType'
  HAVING count(DISTINCT (r->>'Module')||'.'||(r->>'Resource'))=1
 ), coordinates AS MATERIALIZED (
  SELECT DISTINCT c.model,c.id FROM census c
 ), mapped AS MATERIALIZED (
  SELECT c.model,c.id,d.dotted,jsonb_build_array(d.dotted,c.id)::text AS key
  FROM coordinates c LEFT JOIN model_dictionary d ON d.model=c.model
 )
 SELECT (SELECT count(*)::integer FROM census),
  count(*) FILTER(WHERE dotted IS NULL OR coalesce(id,'')='')::integer,
  coalesce(jsonb_agg(jsonb_build_object('model',model,'id',id,'dotted',dotted,'key',key)
   ORDER BY key COLLATE "C") FILTER(WHERE dotted IS NOT NULL),'[]'::jsonb)
 INTO work,missing,targets FROM mapped;
 IF missing<>0 THEN RAISE EXCEPTION 'generation output lacks canonical catalog identity' USING ERRCODE='42501';END IF;
 work:=work+(p_certificate->>'work')::integer;
 IF work IS NULL OR work>100000 OR jsonb_array_length(targets)>4096 THEN
  RAISE EXCEPTION 'generation object graph budget exceeded' USING ERRCODE='54000';END IF;
 graph_images:=ARRAY[]::jsonb[];
 FOR entry IN SELECT value->>'key' AS key,value->>'model' AS model,
  value->>'dotted' AS dotted,value->>'id' AS id FROM jsonb_array_elements(targets) LOOP
  IF (p_certificate->'graphs') ? entry.key THEN
   IF p_certificate->'graphs'->entry.key->>'model_type' IS DISTINCT FROM entry.model THEN
    RAISE EXCEPTION 'generation output conflicts with protected graph' USING ERRCODE='42501';END IF;
   CONTINUE;
  END IF;
  graph:=kaname._authority_resource_object_graph_v2(p_index,entry.dotted,entry.model,entry.id);
  graph_images:=array_append(graph_images,jsonb_build_array(entry.key,graph||
   jsonb_build_object('object_type',entry.dotted,'object_id',entry.id,'model_type',entry.model)));
 END LOOP;
 IF cardinality(graph_images)=0 THEN
  RETURN jsonb_set(p_certificate,'{work}',to_jsonb(work));
 END IF;
 SELECT coalesce(jsonb_object_agg(g->>0,g->1),'{}'::jsonb) INTO graphs FROM unnest(graph_images) g;
 SELECT coalesce(jsonb_object_agg(r.key,r.value),'{}'::jsonb) INTO new_required
 FROM jsonb_each(graphs) g CROSS JOIN LATERAL jsonb_each(g.value->'required') r;
 SELECT coalesce(jsonb_object_agg(r.key,r.value),'{}'::jsonb) INTO new_accounts
 FROM jsonb_each(graphs) g CROSS JOIN LATERAL jsonb_each(g.value->'accounts') r;
 SELECT coalesce(jsonb_object_agg(r.key,r.value),'{}'::jsonb) INTO new_projects
 FROM jsonb_each(graphs) g CROSS JOIN LATERAL jsonb_each(g.value->'projects') r;
 SELECT coalesce(array_agg(b.key ORDER BY b.key COLLATE "C"),ARRAY[]::text[]) INTO binding_ids FROM (
  SELECT k AS key FROM jsonb_array_elements_text(p_certificate->'carriers'->'bindings') k
  UNION
  SELECT r.key FROM jsonb_each(graphs) g CROSS JOIN LATERAL jsonb_object_keys(g.value->'bindings') r(key)
 ) b;
 SELECT coalesce(array_agg(key ORDER BY key COLLATE "C"),ARRAY[]::text[]) INTO full_bindings
 FROM jsonb_each(p_certificate->'bindings') WHERE value->>'whole'='true';
 IF cardinality(binding_ids)>4096 THEN
  RAISE EXCEPTION 'generation carrier budget exceeded' USING ERRCODE='54000';END IF;
 carriers:=kaname._authority_resource_carrier_graph_v2(p_index,binding_ids,full_bindings,ARRAY[]::text[],ARRAY[]::text[]);
 scopes:=kaname._authority_resource_carrier_scopes_v2(p_index,carriers->'bindings');
 new_required:=(p_certificate->'required')||new_required||(carriers->'required')||(scopes->'required');
 graphs:=(p_certificate->'graphs')||graphs;
 work:=work+(scopes->>'work')::integer;
 IF work IS NULL OR work>100000 OR (SELECT count(*) FROM jsonb_object_keys(new_required))>4096
  OR (SELECT count(*) FROM jsonb_object_keys(graphs))>4096 THEN
  RAISE EXCEPTION 'generation complete source budget exceeded' USING ERRCODE='54000';END IF;
 RETURN p_certificate||jsonb_build_object('required',new_required,'graphs',graphs,
  'accounts',(p_certificate->'accounts')||new_accounts||(scopes->'accounts'),
  'projects',(p_certificate->'projects')||new_projects||(scopes->'projects'),
  'carriers',carriers,'carrier_scopes',scopes,
  'global',(p_certificate->>'global')::boolean OR (scopes->>'global')::boolean,'work',work);
END;
$graphs$;

-- +goose StatementEnd
-- +goose StatementBegin
DO $private$
DECLARE recipient record;
BEGIN
 REVOKE ALL ON FUNCTION kaname._authority_access_label_generation_graphs_v1(jsonb,jsonb,jsonb,jsonb) FROM PUBLIC;
 FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname._authority_access_label_generation_graphs_v1(jsonb,jsonb,jsonb,jsonb)'::regprocedure
   AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_access_label_generation_graphs_v1(jsonb,jsonb,jsonb,jsonb) FROM %I',recipient.rolname);
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $generation_repin$
DECLARE item record; edit jsonb; fn oid; previous text; updated text; definition text; old_fragment text;
BEGIN
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'generation compiler prior closure incomplete' USING ERRCODE='55000';
 END IF;
 FOR item IN SELECT * FROM (VALUES
  ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','47aae35f146c1d05bf9f5f52f9f7b929d69d91f64b39844fd697530c467af440','354c92f45d67eacb524ae16293f8fe7c9bfa4456ea1a9263f945e3fd346a52a4',$patch$[["DECLARE proof jsonb;source_index jsonb;catalog jsonb;certificate jsonb;effects jsonb;audit_plan jsonb;", "DECLARE proof jsonb;source_index jsonb;catalog jsonb;certificate jsonb;effects jsonb;audit_plan jsonb;\n generation jsonb;generation_model text;generation_holds jsonb:='[]'::jsonb;"], [" certificate:=kaname._authority_resource_object_certificate_v2(source_index,catalog,p_envelope->'intent',effects);", " certificate:=kaname._authority_resource_object_certificate_v2(source_index,catalog,p_envelope->'intent',effects);\n -- Снимок передаёт только хеш. Полный состав поколения и удержания\n -- компилятор выводит самостоятельно до расчёта полного плана записи.\n IF p_envelope#>>'{intent,route}'='1' THEN\n  IF (p_envelope->'intent') ? 'generation_fingerprint'\n   AND jsonb_typeof(p_envelope#>'{intent,generation_fingerprint}') IS DISTINCT FROM 'string' THEN\n   RAISE EXCEPTION 'generation fingerprint shape invalid' USING ERRCODE='42501';END IF;\n  generation_model:=certificate->'graphs'->(jsonb_build_array(p_envelope#>>'{intent,object_type}',\n   p_envelope#>>'{intent,object_id}')::text)->>'model_type';\n  generation:=kaname._authority_access_label_generation_prepare_v1(\n   generation_model,p_envelope#>>'{intent,object_id}',p_envelope#>>'{intent,generation_fingerprint}',\n   p_rows-used_rows,p_reads-used_reads);\n  used_rows:=used_rows+(generation->>'rows')::integer;\n  used_reads:=used_reads+(generation->>'reads')::integer;\n  generation_holds:=generation->'held_advisory';\n  certificate:=kaname._authority_access_label_generation_graphs_v1(source_index,catalog,certificate,generation->'capture');\n ELSIF (p_envelope->'intent') ? 'generation_fingerprint' THEN\n  RAISE EXCEPTION 'generation is only observed by full object reconciliation' USING ERRCODE='42501';\n END IF;"], ["+(SELECT count(*) FROM jsonb_object_keys(maximum->'binding_epochs'))>4096 THEN", "+(SELECT count(*) FROM jsonb_object_keys(maximum->'binding_epochs'))+jsonb_array_length(generation_holds)>4096 THEN"], [" held_advisory:=(epoch_result.lock_witness->'held_advisory')||audit_result.lock_witness;", " held_advisory:=generation_holds||(epoch_result.lock_witness->'held_advisory')||audit_result.lock_witness;"]]$patch$::jsonb),
  ('_authority_crud_storage_v3()','27b57b5941d1b4a176ec722cba8538963606f86cefb53a1a37d619f6032e5a75','ec90a6d3537354d2c3626431dd548b14d4026f0e38475eeba22a91032ac30e62',$patch$[[" ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','47aae35f146c1d05bf9f5f52f9f7b929d69d91f64b39844fd697530c467af440',true,'v',true,'preserve'),", " ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','354c92f45d67eacb524ae16293f8fe7c9bfa4456ea1a9263f945e3fd346a52a4',true,'v',true,'preserve'),\n ('_authority_access_label_object_generation_capture_v1(text,text,integer,integer)','2d9e55e217c4435813bafca1a2af29623a08ceb13ae69b630d9aae4d973e9eb2',false,'s',true,'private'),\n ('_authority_access_label_generation_root_keys_v1(jsonb)','cf3e2c08b2f44e84d1f69a1cfd791ad4ab48b3e46cc4cf870e6294007c3cb620',false,'i',true,'private'),\n ('_authority_access_label_generation_latch_require_v1(boolean)','9d29f4dcc87da20d4ec92aa5fd23a62141e533f7f36be9d976c5dc14202adc67',false,'v',true,'private'),\n ('_authority_access_label_generation_roots_hold_v1(jsonb)','8ab061372b4efa353d48ea209d65bb38838df7fee00258024f57469e2e70691f',false,'v',true,'private'),\n ('_authority_access_label_generation_prepare_v1(text,text,text,integer,integer)','504f42f30014a48050c98a87efee67cd7d9aae1f6e1d87ab4243897732beac01',false,'v',true,'private'),\n ('_authority_access_label_generation_graphs_v1(jsonb,jsonb,jsonb,jsonb)','acc5b813a6461a380609c5bf5d70e0b60a4b62ac280974c828e17a876a49db4a',false,'v',true,'private'),"]]$patch$::jsonb),
  ('_authority_full_contract_storage_v3()','d58e745e786b96c831e081db8cb9af270e10028f4b64cecf373d5611a31fbadb','6145d6711e6ea5be129dbb7df42772138c100220072ef258b2998ec802eaad98',$patch$[[" ('_authority_crud_storage_v3()','27b57b5941d1b4a176ec722cba8538963606f86cefb53a1a37d619f6032e5a75',true),", " ('_authority_crud_storage_v3()','ec90a6d3537354d2c3626431dd548b14d4026f0e38475eeba22a91032ac30e62',true),"]]$patch$::jsonb)
 ) changes(signature,before_sha,after_sha,substitutions) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc INTO STRICT previous FROM pg_catalog.pg_proc p WHERE p.oid=fn;
  IF encode(sha256(convert_to(previous,'UTF8')),'hex') IS DISTINCT FROM item.before_sha THEN
   RAISE EXCEPTION 'generation compiler baseline changed: %',item.signature USING ERRCODE='55000';
  END IF;
  updated:=previous;
  FOR edit IN SELECT value FROM jsonb_array_elements(item.substitutions) LOOP
   old_fragment:=edit->>0;
   IF length(updated)-length(replace(updated,old_fragment,'')) IS DISTINCT FROM length(old_fragment) THEN
    RAISE EXCEPTION 'generation compiler patch ambiguous: %',item.signature USING ERRCODE='55000';
   END IF;
   updated:=replace(updated,old_fragment,edit->>1);
  END LOOP;
  IF encode(sha256(convert_to(updated,'UTF8')),'hex') IS DISTINCT FROM item.after_sha THEN
   RAISE EXCEPTION 'generation compiler candidate changed: %',item.signature USING ERRCODE='55000';
  END IF;
  definition:=pg_catalog.pg_get_functiondef(fn);
  IF length(definition)-length(replace(definition,previous,'')) IS DISTINCT FROM length(previous) THEN
   RAISE EXCEPTION 'generation compiler definition ambiguous: %',item.signature USING ERRCODE='55000';
  END IF;
  EXECUTE replace(definition,previous,updated);
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
   IS DISTINCT FROM item.after_sha THEN
   RAISE EXCEPTION 'generation compiler installed bytes changed: %',item.signature USING ERRCODE='55000';
  END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'generation compiler final closure incomplete' USING ERRCODE='55000';
 END IF;
END;
$generation_repin$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
-- +goose StatementBegin
DO $generation_repin$
DECLARE item record; edit jsonb; fn oid; previous text; updated text; definition text; old_fragment text;
BEGIN
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'generation compiler prior closure incomplete' USING ERRCODE='55000';
 END IF;
 FOR item IN SELECT * FROM (VALUES
  ('_authority_full_contract_storage_v3()','6145d6711e6ea5be129dbb7df42772138c100220072ef258b2998ec802eaad98','d58e745e786b96c831e081db8cb9af270e10028f4b64cecf373d5611a31fbadb',$patch$[[" ('_authority_crud_storage_v3()','ec90a6d3537354d2c3626431dd548b14d4026f0e38475eeba22a91032ac30e62',true),", " ('_authority_crud_storage_v3()','27b57b5941d1b4a176ec722cba8538963606f86cefb53a1a37d619f6032e5a75',true),"]]$patch$::jsonb),
  ('_authority_crud_storage_v3()','ec90a6d3537354d2c3626431dd548b14d4026f0e38475eeba22a91032ac30e62','27b57b5941d1b4a176ec722cba8538963606f86cefb53a1a37d619f6032e5a75',$patch$[[" ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','354c92f45d67eacb524ae16293f8fe7c9bfa4456ea1a9263f945e3fd346a52a4',true,'v',true,'preserve'),\n ('_authority_access_label_object_generation_capture_v1(text,text,integer,integer)','2d9e55e217c4435813bafca1a2af29623a08ceb13ae69b630d9aae4d973e9eb2',false,'s',true,'private'),\n ('_authority_access_label_generation_root_keys_v1(jsonb)','cf3e2c08b2f44e84d1f69a1cfd791ad4ab48b3e46cc4cf870e6294007c3cb620',false,'i',true,'private'),\n ('_authority_access_label_generation_latch_require_v1(boolean)','9d29f4dcc87da20d4ec92aa5fd23a62141e533f7f36be9d976c5dc14202adc67',false,'v',true,'private'),\n ('_authority_access_label_generation_roots_hold_v1(jsonb)','8ab061372b4efa353d48ea209d65bb38838df7fee00258024f57469e2e70691f',false,'v',true,'private'),\n ('_authority_access_label_generation_prepare_v1(text,text,text,integer,integer)','504f42f30014a48050c98a87efee67cd7d9aae1f6e1d87ab4243897732beac01',false,'v',true,'private'),\n ('_authority_access_label_generation_graphs_v1(jsonb,jsonb,jsonb,jsonb)','acc5b813a6461a380609c5bf5d70e0b60a4b62ac280974c828e17a876a49db4a',false,'v',true,'private'),", " ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','47aae35f146c1d05bf9f5f52f9f7b929d69d91f64b39844fd697530c467af440',true,'v',true,'preserve'),"]]$patch$::jsonb),
  ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','354c92f45d67eacb524ae16293f8fe7c9bfa4456ea1a9263f945e3fd346a52a4','47aae35f146c1d05bf9f5f52f9f7b929d69d91f64b39844fd697530c467af440',$patch$[[" held_advisory:=generation_holds||(epoch_result.lock_witness->'held_advisory')||audit_result.lock_witness;", " held_advisory:=(epoch_result.lock_witness->'held_advisory')||audit_result.lock_witness;"], ["+(SELECT count(*) FROM jsonb_object_keys(maximum->'binding_epochs'))+jsonb_array_length(generation_holds)>4096 THEN", "+(SELECT count(*) FROM jsonb_object_keys(maximum->'binding_epochs'))>4096 THEN"], [" certificate:=kaname._authority_resource_object_certificate_v2(source_index,catalog,p_envelope->'intent',effects);\n -- Снимок передаёт только хеш. Полный состав поколения и удержания\n -- компилятор выводит самостоятельно до расчёта полного плана записи.\n IF p_envelope#>>'{intent,route}'='1' THEN\n  IF (p_envelope->'intent') ? 'generation_fingerprint'\n   AND jsonb_typeof(p_envelope#>'{intent,generation_fingerprint}') IS DISTINCT FROM 'string' THEN\n   RAISE EXCEPTION 'generation fingerprint shape invalid' USING ERRCODE='42501';END IF;\n  generation_model:=certificate->'graphs'->(jsonb_build_array(p_envelope#>>'{intent,object_type}',\n   p_envelope#>>'{intent,object_id}')::text)->>'model_type';\n  generation:=kaname._authority_access_label_generation_prepare_v1(\n   generation_model,p_envelope#>>'{intent,object_id}',p_envelope#>>'{intent,generation_fingerprint}',\n   p_rows-used_rows,p_reads-used_reads);\n  used_rows:=used_rows+(generation->>'rows')::integer;\n  used_reads:=used_reads+(generation->>'reads')::integer;\n  generation_holds:=generation->'held_advisory';\n  certificate:=kaname._authority_access_label_generation_graphs_v1(source_index,catalog,certificate,generation->'capture');\n ELSIF (p_envelope->'intent') ? 'generation_fingerprint' THEN\n  RAISE EXCEPTION 'generation is only observed by full object reconciliation' USING ERRCODE='42501';\n END IF;", " certificate:=kaname._authority_resource_object_certificate_v2(source_index,catalog,p_envelope->'intent',effects);"], ["DECLARE proof jsonb;source_index jsonb;catalog jsonb;certificate jsonb;effects jsonb;audit_plan jsonb;\n generation jsonb;generation_model text;generation_holds jsonb:='[]'::jsonb;", "DECLARE proof jsonb;source_index jsonb;catalog jsonb;certificate jsonb;effects jsonb;audit_plan jsonb;"]]$patch$::jsonb)
 ) changes(signature,before_sha,after_sha,substitutions) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc INTO STRICT previous FROM pg_catalog.pg_proc p WHERE p.oid=fn;
  IF encode(sha256(convert_to(previous,'UTF8')),'hex') IS DISTINCT FROM item.before_sha THEN
   RAISE EXCEPTION 'generation compiler baseline changed: %',item.signature USING ERRCODE='55000';
  END IF;
  updated:=previous;
  FOR edit IN SELECT value FROM jsonb_array_elements(item.substitutions) LOOP
   old_fragment:=edit->>0;
   IF length(updated)-length(replace(updated,old_fragment,'')) IS DISTINCT FROM length(old_fragment) THEN
    RAISE EXCEPTION 'generation compiler patch ambiguous: %',item.signature USING ERRCODE='55000';
   END IF;
   updated:=replace(updated,old_fragment,edit->>1);
  END LOOP;
  IF encode(sha256(convert_to(updated,'UTF8')),'hex') IS DISTINCT FROM item.after_sha THEN
   RAISE EXCEPTION 'generation compiler candidate changed: %',item.signature USING ERRCODE='55000';
  END IF;
  definition:=pg_catalog.pg_get_functiondef(fn);
  IF length(definition)-length(replace(definition,previous,'')) IS DISTINCT FROM length(previous) THEN
   RAISE EXCEPTION 'generation compiler definition ambiguous: %',item.signature USING ERRCODE='55000';
  END IF;
  EXECUTE replace(definition,previous,updated);
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
   IS DISTINCT FROM item.after_sha THEN
   RAISE EXCEPTION 'generation compiler installed bytes changed: %',item.signature USING ERRCODE='55000';
  END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'generation compiler final closure incomplete' USING ERRCODE='55000';
 END IF;
END;
$generation_repin$;
-- +goose StatementEnd
DROP FUNCTION kaname._authority_access_label_generation_graphs_v1(jsonb,jsonb,jsonb,jsonb);
