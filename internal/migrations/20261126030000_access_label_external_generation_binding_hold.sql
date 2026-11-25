-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Удерживаем постоянную привязку внешнего корня и её отсутствие общим ключом с регистрацией.
-- Воркер читает точное состояние под удержанием до фиксации времени решения.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_generation_binding_read_hold_v1(p_capture jsonb,p_certificate jsonb,p_index jsonb,p_rows integer,p_reads integer,p_keys integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $binding_hold$
DECLARE proof jsonb;invoker oid;root_row jsonb;graph jsonb;source jsonb;entry record;
 model text;identifier text;dotted text;key_value text;physical integer;
 predicates jsonb:='{}';states jsonb;expected_rows integer:=0;physical_keys integer[];
 held_relations jsonb:='[]';held_advisory jsonb:='[]';used_reads integer;
 table_id oid:='kaname.object_project_binding'::regclass;
BEGIN
 proof:=kaname._authority_access_label_generation_latch_require_v1(false);
 IF jsonb_typeof(p_capture->'roots') IS DISTINCT FROM 'array'
 OR jsonb_typeof(p_certificate->'graphs') IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_certificate->'required') IS DISTINCT FROM 'object'
 OR jsonb_array_length(p_capture->'roots')>4096 THEN
  RAISE EXCEPTION 'generation binding graph incomplete' USING ERRCODE='42501';END IF;
 IF p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000
 OR p_reads IS NULL OR p_reads NOT BETWEEN 0 AND 4096
 OR p_keys IS NULL OR p_keys NOT BETWEEN 0 AND 4096 THEN
  RAISE EXCEPTION 'generation binding hold budget invalid' USING ERRCODE='54000';END IF;

 -- Координаты выводятся из точных внешних корней владельца. Снятые
 -- типы сохраняют исходное имя из каталога, включая совпадающие ID.
 FOR root_row IN SELECT r#>'{state,2}' FROM jsonb_array_elements(p_capture->'roots') r LOOP
  dotted:=root_row->>'root_type';identifier:=root_row->>'root_id';
  IF dotted IN ('iam.account','iam.project','iam.serviceAccount') THEN CONTINUE;END IF;
  IF kaname._authority_access_label_dirty_root_type_valid_v1(dotted) IS DISTINCT FROM true
  OR coalesce(identifier,'')='' THEN
   RAISE EXCEPTION 'generation binding root identity unavailable' USING ERRCODE='42501';END IF;
  graph:=p_certificate->'graphs'->(jsonb_build_array(dotted,identifier)::text);
  model:=graph->>'model_type';
  IF graph->>'object_type' IS DISTINCT FROM dotted OR graph->>'object_id' IS DISTINCT FROM identifier
  OR coalesce(model,'') !~ '^[a-z][a-z0-9_]*$' THEN
   RAISE EXCEPTION 'generation binding catalog identity unavailable' USING ERRCODE='42501';END IF;
  key_value:=jsonb_build_array(5,model,identifier,'')::text;
  IF (p_certificate->'required'->key_value) IS DISTINCT FROM 'true'::jsonb THEN
   RAISE EXCEPTION 'generation binding predicate missing' USING ERRCODE='42501';END IF;
  IF predicates ? key_value THEN CONTINUE;END IF;
  source:=kaname._authority_resource_require_capture_v2(p_index,5,model,identifier);
  IF jsonb_array_length(source->'states')>1 THEN
   RAISE EXCEPTION 'generation binding census is ambiguous' USING ERRCODE='42501';END IF;
  expected_rows:=expected_rows+jsonb_array_length(source->'states');
  predicates:=predicates||jsonb_build_object(key_value,jsonb_build_object(
   'model',model,'id',identifier,'expected',source->'states',
   'hash',hashtext(jsonb_build_array(model,identifier)::text)));
 END LOOP;
 IF predicates='{}'::jsonb THEN
  RETURN jsonb_build_object('held_relations',held_relations,'held_advisory',held_advisory,
   'validated_keys','[]'::jsonb,'rows',0,'reads',0);END IF;
 SELECT array_agg(k ORDER BY k) INTO physical_keys FROM (
  SELECT DISTINCT (value->>'hash')::integer k FROM jsonb_each(predicates)
 ) keys;
 -- Отношение, проверка источника, физические удержания и точные
 -- чтения предикатов учитываются до первого ожидания.
 used_reads:=2+cardinality(physical_keys)+(SELECT count(*)::integer FROM jsonb_object_keys(predicates));
 IF expected_rows>p_rows OR used_reads>p_reads OR cardinality(physical_keys)>p_keys THEN
  RAISE EXCEPTION 'generation binding hold budget exhausted' USING ERRCODE='54000';END IF;
 invoker:=(proof->>'invoker_oid')::oid;
 IF NOT coalesce(has_table_privilege(invoker,table_id,'SELECT'),false) THEN
  RAISE EXCEPTION 'generation binding requires original SELECT' USING ERRCODE='42501';END IF;
 BEGIN
  LOCK TABLE ONLY kaname.object_project_binding IN ACCESS SHARE MODE NOWAIT;
 EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'generation binding relation busy' USING ERRCODE='40001';
 END;
 IF current_setting('session_replication_role') NOT IN ('origin','local')
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=table_id
   AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
   AND NOT c.relispartition AND NOT c.relhassubclass AND NOT c.relhasrules
   AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid))
 OR EXISTS(SELECT 1 FROM (VALUES
   ('authority_registration_binding_guard_v2','authority_registration_binding_guard_v2',23,true,
    ARRAY['search_path=pg_catalog, pg_temp']::text[],'3419906be522c12cb827ee2ae9a7a76a86062643efc34f4148b2e15b9537f95f'),
   ('object_project_binding_is_permanent','object_project_binding_is_permanent',27,false,
    NULL::text[],'206a32d69a4102c901bba96952a071f809aed9004bc74fb0f1fbcb86fefc62c2'),
   ('object_project_binding_is_not_truncated','object_project_binding_is_permanent',34,false,
    NULL::text[],'206a32d69a4102c901bba96952a071f809aed9004bc74fb0f1fbcb86fefc62c2')
  ) e(trigger_name,function_name,trigger_type,definer,config,digest) WHERE NOT EXISTS(
   SELECT 1 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc f ON f.oid=t.tgfoid
   WHERE t.tgrelid=table_id AND t.tgname=e.trigger_name
   AND t.tgtype=e.trigger_type AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal AND t.tgnargs=0
   AND t.tgqual IS NULL AND t.tgattr::text='' AND t.tgconstraint=0 AND NOT (t.tgdeferrable OR t.tginitdeferred)
   AND f.oid=to_regprocedure('kaname.'||e.function_name||'()') AND f.proowner=current_user::regrole::oid
   AND f.prokind='f' AND f.prorettype='trigger'::regtype AND f.pronargs=0 AND NOT f.proretset
   AND f.provolatile='v' AND f.prosecdef=e.definer AND f.proconfig IS NOT DISTINCT FROM e.config
   AND f.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
   AND encode(sha256(convert_to(f.prosrc,'UTF8')),'hex')=e.digest)) THEN
  RAISE EXCEPTION 'generation binding source or guards unavailable' USING ERRCODE='42501';END IF;
 held_relations:=jsonb_build_array(jsonb_build_object('oid',table_id,'mode','AccessShareLock'));
 FOREACH physical IN ARRAY physical_keys LOOP
  IF NOT pg_try_advisory_xact_lock_shared(1262569300,physical) THEN
   RAISE EXCEPTION 'generation binding key busy' USING ERRCODE='40001';END IF;
  held_advisory:=held_advisory||jsonb_build_array(jsonb_build_object('classid',1262569300,
   'objid',(physical::bigint & 4294967295),'objsubid',2,'mode','ShareLock'));
 END LOOP;
 -- Общий ключ блокирует и INSERT в пустой предикат. Состояние
 -- перечитываем без tuple lock: BEFORE UPDATE может уже ждать тот же
 -- ключ с удержанной строкой. Одна и та же транзакция хранит оба proof.
 FOR entry IN SELECT * FROM jsonb_each(predicates) ORDER BY key COLLATE "C" LOOP
  SELECT coalesce(jsonb_agg(b.state),'[]'::jsonb) INTO states FROM (
   SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r)) state
   FROM ONLY kaname.object_project_binding r
   WHERE r.object_type=entry.value->>'model' AND r.object_id=entry.value->>'id' LIMIT 2
  ) b;
  IF states IS DISTINCT FROM entry.value->'expected' THEN
   RAISE EXCEPTION 'generation binding changed after capture' USING ERRCODE='P1034';END IF;
 END LOOP;
 RETURN jsonb_build_object('held_relations',held_relations,'held_advisory',held_advisory,
  'validated_keys',(SELECT jsonb_agg(k ORDER BY k COLLATE "C") FROM jsonb_object_keys(predicates) k),
  'rows',expected_rows,'reads',used_reads);
END;
$binding_hold$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE target oid:='kaname._authority_access_label_generation_binding_read_hold_v1(jsonb,jsonb,jsonb,integer,integer,integer)'::regprocedure;recipient record;
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
 ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','12eb8205cc999d9207d3497b838c5dc2badd80e28ded8805435c7a818a8a3c74','d967ea237f994bd6651e8f7df77a074a4408d0edcff38d550fa611e03174c336',
  $changes$[
 [
  " generation_program jsonb;generation_write_wait jsonb;generation_relation_holds jsonb:='[]'::jsonb;",
  " generation_program jsonb;generation_write_wait jsonb;generation_relation_holds jsonb:='[]'::jsonb;\n binding_hold jsonb:='{\"held_relations\":[],\"held_advisory\":[],\"validated_keys\":[],\"rows\":0,\"reads\":0}'::jsonb;\n binding_keys text[]:=ARRAY[]::text[];"
 ],
 [
  " used_rows:=used_rows+epoch_result.logical_rows;used_reads:=used_reads+epoch_result.logical_reads;\n SELECT * INTO STRICT catalog_result",
  " used_rows:=used_rows+epoch_result.logical_rows;used_reads:=used_reads+epoch_result.logical_reads;\n IF EXISTS(SELECT 1 FROM jsonb_array_elements(generation#>'{capture,roots}') r\n  WHERE r#>>'{state,2,root_type}' NOT IN ('iam.account','iam.project','iam.serviceAccount')) THEN\n  binding_hold:=kaname._authority_access_label_generation_binding_read_hold_v1(\n   generation->'capture',certificate,source_index,p_rows-used_rows,p_reads-used_reads,\n   4096-jsonb_array_length(generation_holds)-jsonb_array_length(epoch_result.lock_witness->'held_advisory')\n   -(SELECT count(*)::integer FROM jsonb_object_keys(audit_plan->'ids')));\n  used_rows:=used_rows+(binding_hold->>'rows')::integer;used_reads:=used_reads+(binding_hold->>'reads')::integer;\n  binding_keys:=ARRAY(SELECT jsonb_array_elements_text(binding_hold->'validated_keys'));\n  IF (sources->'write_keys') ?| binding_keys THEN\n   RAISE EXCEPTION 'generation binding read cannot authorize write' USING ERRCODE='42501';END IF;\n END IF;\n SELECT * INTO STRICT catalog_result"
 ],
 [
  "kaname._authority_resource_required_reread_v2(source_index,required,",
  "kaname._authority_resource_required_reread_v2(source_index,required-binding_keys,"
 ],
 [
  " held_advisory:=generation_holds||(epoch_result.lock_witness->'held_advisory')||audit_result.lock_witness;",
  " held_advisory:=generation_holds||(epoch_result.lock_witness->'held_advisory')||(binding_hold->'held_advisory')||audit_result.lock_witness;"
 ],
 [
  "'held_relations',relations_result.lock_witness||generation_relation_holds,'held_advisory'",
  "'held_relations',relations_result.lock_witness||generation_relation_holds||(binding_hold->'held_relations'),'held_advisory'"
 ]
]$changes$::jsonb),
 ('_authority_crud_storage_v3()','758c9c0009b779ac40b834b0ed906a61142c1ee450dab6ed1be7d3c0432f9952','1004277df4c2fb947cf7391d12f6526dffee6b71c9a6f9d7fcfce6c5d0813844',
  $changes$[
 [
  "12eb8205cc999d9207d3497b838c5dc2badd80e28ded8805435c7a818a8a3c74",
  "d967ea237f994bd6651e8f7df77a074a4408d0edcff38d550fa611e03174c336"
 ],
 [
  " ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','d967ea237f994bd6651e8f7df77a074a4408d0edcff38d550fa611e03174c336',true,'v',true,'preserve'),",
  " ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','d967ea237f994bd6651e8f7df77a074a4408d0edcff38d550fa611e03174c336',true,'v',true,'preserve'),\n ('_authority_access_label_generation_binding_read_hold_v1(jsonb,jsonb,jsonb,integer,integer,integer)','740bbbb7903d3fe059561165d0ba4486b7d5fd15822c5a8881da20b3f7de157d',false,'v',true,'private'),"
 ],
 [
  "  ('_authority_access_label_external_aliases_v1(text,integer)','jsonb',2,ARRAY['p_model','p_rows']),",
  "  ('_authority_access_label_external_aliases_v1(text,integer)','jsonb',2,ARRAY['p_model','p_rows']),\n  ('_authority_access_label_generation_binding_read_hold_v1(jsonb,jsonb,jsonb,integer,integer,integer)','jsonb',6,ARRAY['p_capture','p_certificate','p_index','p_rows','p_reads','p_keys']),"
 ]
]$changes$::jsonb),
 ('_authority_full_contract_storage_v3()','eaba8c4bde5ed93f75a75ad4a18486dbf108bc59ea986ca34586b3e23efc0818','fe9e4861420c1309e7dd9a7861bf6ee4b3d8afa33bbf5041d8dbf11e3cdc0757',
  $changes$[
 [
  "758c9c0009b779ac40b834b0ed906a61142c1ee450dab6ed1be7d3c0432f9952",
  "1004277df4c2fb947cf7391d12f6526dffee6b71c9a6f9d7fcfce6c5d0813844"
 ]
]$changes$::jsonb),
 ('authority_metadata_service_account_access_label_ready_v1()','58a0264a26a5e0f4cf1fe047801ec51f7475a5a1b97819ba0eb253849618d654','60186d3b97e1e4e799c5ce40a8c2c7045b28934706e2f7b46f57adb728a1355d',
  $changes$[
 [
  "758c9c0009b779ac40b834b0ed906a61142c1ee450dab6ed1be7d3c0432f9952",
  "1004277df4c2fb947cf7391d12f6526dffee6b71c9a6f9d7fcfce6c5d0813844"
 ],
 [
  "eaba8c4bde5ed93f75a75ad4a18486dbf108bc59ea986ca34586b3e23efc0818",
  "fe9e4861420c1309e7dd9a7861bf6ee4b3d8afa33bbf5041d8dbf11e3cdc0757"
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
 ('authority_metadata_service_account_access_label_ready_v1()','60186d3b97e1e4e799c5ce40a8c2c7045b28934706e2f7b46f57adb728a1355d','58a0264a26a5e0f4cf1fe047801ec51f7475a5a1b97819ba0eb253849618d654',
  $changes$[
 [
  "fe9e4861420c1309e7dd9a7861bf6ee4b3d8afa33bbf5041d8dbf11e3cdc0757",
  "eaba8c4bde5ed93f75a75ad4a18486dbf108bc59ea986ca34586b3e23efc0818"
 ],
 [
  "1004277df4c2fb947cf7391d12f6526dffee6b71c9a6f9d7fcfce6c5d0813844",
  "758c9c0009b779ac40b834b0ed906a61142c1ee450dab6ed1be7d3c0432f9952"
 ]
]$changes$::jsonb),
 ('_authority_full_contract_storage_v3()','fe9e4861420c1309e7dd9a7861bf6ee4b3d8afa33bbf5041d8dbf11e3cdc0757','eaba8c4bde5ed93f75a75ad4a18486dbf108bc59ea986ca34586b3e23efc0818',
  $changes$[
 [
  "1004277df4c2fb947cf7391d12f6526dffee6b71c9a6f9d7fcfce6c5d0813844",
  "758c9c0009b779ac40b834b0ed906a61142c1ee450dab6ed1be7d3c0432f9952"
 ]
]$changes$::jsonb),
 ('_authority_crud_storage_v3()','1004277df4c2fb947cf7391d12f6526dffee6b71c9a6f9d7fcfce6c5d0813844','758c9c0009b779ac40b834b0ed906a61142c1ee450dab6ed1be7d3c0432f9952',
  $changes$[
 [
  "  ('_authority_access_label_external_aliases_v1(text,integer)','jsonb',2,ARRAY['p_model','p_rows']),\n  ('_authority_access_label_generation_binding_read_hold_v1(jsonb,jsonb,jsonb,integer,integer,integer)','jsonb',6,ARRAY['p_capture','p_certificate','p_index','p_rows','p_reads','p_keys']),",
  "  ('_authority_access_label_external_aliases_v1(text,integer)','jsonb',2,ARRAY['p_model','p_rows']),"
 ],
 [
  " ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','d967ea237f994bd6651e8f7df77a074a4408d0edcff38d550fa611e03174c336',true,'v',true,'preserve'),\n ('_authority_access_label_generation_binding_read_hold_v1(jsonb,jsonb,jsonb,integer,integer,integer)','740bbbb7903d3fe059561165d0ba4486b7d5fd15822c5a8881da20b3f7de157d',false,'v',true,'private'),",
  " ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','d967ea237f994bd6651e8f7df77a074a4408d0edcff38d550fa611e03174c336',true,'v',true,'preserve'),"
 ],
 [
  "d967ea237f994bd6651e8f7df77a074a4408d0edcff38d550fa611e03174c336",
  "12eb8205cc999d9207d3497b838c5dc2badd80e28ded8805435c7a818a8a3c74"
 ]
]$changes$::jsonb),
 ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','d967ea237f994bd6651e8f7df77a074a4408d0edcff38d550fa611e03174c336','12eb8205cc999d9207d3497b838c5dc2badd80e28ded8805435c7a818a8a3c74',
  $changes$[
 [
  "'held_relations',relations_result.lock_witness||generation_relation_holds||(binding_hold->'held_relations'),'held_advisory'",
  "'held_relations',relations_result.lock_witness||generation_relation_holds,'held_advisory'"
 ],
 [
  " held_advisory:=generation_holds||(epoch_result.lock_witness->'held_advisory')||(binding_hold->'held_advisory')||audit_result.lock_witness;",
  " held_advisory:=generation_holds||(epoch_result.lock_witness->'held_advisory')||audit_result.lock_witness;"
 ],
 [
  "kaname._authority_resource_required_reread_v2(source_index,required-binding_keys,",
  "kaname._authority_resource_required_reread_v2(source_index,required,"
 ],
 [
  " used_rows:=used_rows+epoch_result.logical_rows;used_reads:=used_reads+epoch_result.logical_reads;\n IF EXISTS(SELECT 1 FROM jsonb_array_elements(generation#>'{capture,roots}') r\n  WHERE r#>>'{state,2,root_type}' NOT IN ('iam.account','iam.project','iam.serviceAccount')) THEN\n  binding_hold:=kaname._authority_access_label_generation_binding_read_hold_v1(\n   generation->'capture',certificate,source_index,p_rows-used_rows,p_reads-used_reads,\n   4096-jsonb_array_length(generation_holds)-jsonb_array_length(epoch_result.lock_witness->'held_advisory')\n   -(SELECT count(*)::integer FROM jsonb_object_keys(audit_plan->'ids')));\n  used_rows:=used_rows+(binding_hold->>'rows')::integer;used_reads:=used_reads+(binding_hold->>'reads')::integer;\n  binding_keys:=ARRAY(SELECT jsonb_array_elements_text(binding_hold->'validated_keys'));\n  IF (sources->'write_keys') ?| binding_keys THEN\n   RAISE EXCEPTION 'generation binding read cannot authorize write' USING ERRCODE='42501';END IF;\n END IF;\n SELECT * INTO STRICT catalog_result",
  " used_rows:=used_rows+epoch_result.logical_rows;used_reads:=used_reads+epoch_result.logical_reads;\n SELECT * INTO STRICT catalog_result"
 ],
 [
  " generation_program jsonb;generation_write_wait jsonb;generation_relation_holds jsonb:='[]'::jsonb;\n binding_hold jsonb:='{\"held_relations\":[],\"held_advisory\":[],\"validated_keys\":[],\"rows\":0,\"reads\":0}'::jsonb;\n binding_keys text[]:=ARRAY[]::text[];",
  " generation_program jsonb;generation_write_wait jsonb;generation_relation_holds jsonb:='[]'::jsonb;"
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

DROP FUNCTION kaname._authority_access_label_generation_binding_read_hold_v1(jsonb,jsonb,jsonb,integer,integer,integer);
