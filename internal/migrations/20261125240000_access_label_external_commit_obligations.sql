-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Перед фиксацией внешней команды подтверждаем запись, аудит и постановку
-- пересчёта. Этот шаг не открывает внешний писатель.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_mirror_command_v1()
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $command$
DECLARE program jsonb;proof jsonb;command jsonb;identity jsonb;state jsonb;freshness jsonb;
 prepared jsonb;retained jsonb;owning jsonb;actor jsonb;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 program:=kaname._authority_sequence_store_v3();
 IF program IS NULL THEN RETURN NULL;END IF;
 IF program#>>'{frozen,kind}' IS DISTINCT FROM 'metadata.mirror' THEN
  IF (program->'frozen') ? 'mirror_command' OR (program->'frozen') ? 'mirror_state'
   OR program->>'frozen_mode'='external_access_labels' THEN
   RAISE EXCEPTION 'mirror command escaped its explicit family' USING ERRCODE='42501';END IF;
  RETURN NULL;
 END IF;
 proof:=kaname.authority_protocol_attestation();
 command:=program#>'{frozen,mirror_command}';identity:=command->'identity';
 state:=program#>'{frozen,mirror_state}';freshness:=program#>'{frozen,access_label_freshness}';
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
  OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'full'
  OR proof->>'consumer_finalized' IS DISTINCT FROM 'true'
  OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
  OR NOT coalesce((proof->>'writer_contract'='2' AND proof->>'purpose'='decision')
    OR (proof->>'writer_contract'='1' AND proof->>'purpose'='participant'),false)
  OR program->>'family' IS DISTINCT FROM 'metadata'
  OR program->>'frozen_mode' IS DISTINCT FROM 'external_access_labels'
  OR program#>>'{frozen,mode}' IS DISTINCT FROM 'external_access_labels'
  OR program->'maximum' IS DISTINCT FROM '[]'::jsonb
  OR program->>'maximum_count' IS DISTINCT FROM '0'
  OR jsonb_typeof(command) IS DISTINCT FROM 'object'
  OR command-ARRAY['identity','old','new','physical','audit_row','reconcile_row','completion_reads']<>'{}'::jsonb
  OR command->'completion_reads' IS DISTINCT FROM '3'::jsonb
  OR jsonb_typeof(identity) IS DISTINCT FROM 'object'
  OR coalesce(identity->>'dotted','')='' OR coalesce(identity->>'model','') !~ '^[a-z][a-z0-9_]*$'
  OR split_part(identity->>'dotted','.',1)='iam'
  OR coalesce(identity->>'id','')='' OR coalesce(identity->>'account_id','')=''
  OR identity#>>'{catalog_state,2,dotted}' IS DISTINCT FROM identity->>'dotted'
  OR identity#>>'{catalog_state,2,object_type}' IS DISTINCT FROM identity->>'model'
  OR identity#>>'{catalog_state,2,live}' IS DISTINCT FROM 'true'
  OR coalesce(identity#>>'{catalog_state,2,module}','') IN ('','iam')
  OR (proof->>'mode'='accounts' AND NOT coalesce((proof->'accounts') ? (identity->>'account_id'),false))
  OR jsonb_typeof(command->'old') IS DISTINCT FROM 'object'
  OR jsonb_typeof(command->'new') IS DISTINCT FROM 'object'
  OR command#>>'{old,object_type}' IS DISTINCT FROM identity->>'dotted'
  OR command#>>'{old,object_id}' IS DISTINCT FROM identity->>'id'
  OR (command->'old'-ARRAY['labels','access_labels']) IS DISTINCT FROM
     (command->'new'-ARRAY['labels','access_labels'])
  OR command#>'{old,access_labels}' IS NOT DISTINCT FROM command#>'{new,access_labels}'
  OR kaname.access_labels_valid_v1(command#>'{new,access_labels}') IS DISTINCT FROM true
  OR jsonb_typeof(command#>'{new,labels}') IS DISTINCT FROM 'object'
  OR command#>>'{physical,table}' IS DISTINCT FROM 'resource_mirror'
  OR command#>>'{physical,object_type}' IS DISTINCT FROM identity->>'dotted'
  OR command#>>'{physical,id}' IS DISTINCT FROM identity->>'id'
  OR coalesce(command#>>'{physical,xmin}','')='' OR coalesce(command#>>'{physical,ctid}','')=''
  OR freshness->>'root_type' IS DISTINCT FROM identity->>'dotted'
  OR freshness->>'root_id' IS DISTINCT FROM identity->>'id'
  OR freshness->'old_labels' IS DISTINCT FROM command#>'{old,access_labels}'
  OR freshness->'new_labels' IS DISTINCT FROM command#>'{new,access_labels}'
  OR jsonb_typeof(state) IS DISTINCT FROM 'object'
  OR state-ARRAY['root_applied','root_after','audit_consumed','reconcile_consumed']<>'{}'::jsonb
  OR jsonb_typeof(state->'root_applied') IS DISTINCT FROM 'boolean'
  OR (state->'root_applied'='false'::jsonb AND state->'root_after' IS DISTINCT FROM 'null'::jsonb)
  OR (state->'root_applied'='true'::jsonb AND
   (jsonb_typeof(state->'root_after') IS DISTINCT FROM 'array'
    OR coalesce(state#>>'{root_after,0}','')='' OR coalesce(state#>>'{root_after,1}','')=''))
  OR jsonb_typeof(state->'audit_consumed') IS DISTINCT FROM 'boolean'
  OR jsonb_typeof(state->'reconcile_consumed') IS DISTINCT FROM 'boolean'
  OR jsonb_typeof(command->'audit_row') IS DISTINCT FROM 'object'
  OR coalesce(command#>>'{audit_row,id}','') !~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$'
  OR command#>>'{audit_row,id}' IS DISTINCT FROM program#>>'{frozen,access_label_audit_id}'
  OR command#>>'{audit_row,tenant_account_id}' IS DISTINCT FROM identity->>'account_id'
  OR jsonb_typeof(command->'reconcile_row') IS DISTINCT FROM 'object'
  OR coalesce(command#>>'{reconcile_row,id}','') !~ '^[1-9][0-9]*$'
  OR command#>>'{reconcile_row,object_type}' IS DISTINCT FROM identity->>'dotted'
  OR command#>>'{reconcile_row,object_id}' IS DISTINCT FROM identity->>'id'
  OR command#>>'{reconcile_row,event_type}' IS DISTINCT FROM 'mirror.upsert'
  OR command#>>'{audit_row,event_type}' IS DISTINCT FROM 'iam.resource_metadata.access_labels_updated' THEN
  RAISE EXCEPTION 'external metadata command custody or identity differs' USING ERRCODE='42501';END IF;
 -- Даже пустая sequence-программа обязана быть finalized. Для root/aux DML
 -- также требуется accept на том же окончательном clock.
 IF program->'selected' IS DISTINCT FROM '[]'::jsonb
  OR program->>'selected_count' IS DISTINCT FROM '0'
  OR program->'decision_at' IS DISTINCT FROM proof->'decision_at'
  OR program#>'{frozen,access_label_approved_at}' IS DISTINCT FROM program->'decision_at'
  OR program->>'decision_at' IS NULL
  OR NOT isfinite((program->>'decision_at')::timestamptz)
  OR (program->>'decision_at')::timestamptz<=(program->>'staged_decision_at')::timestamptz THEN
  RAISE EXCEPTION 'external metadata command is not finally approved' USING ERRCODE='42501';END IF;
 -- Область и физические образы должны совпасть с удержанным пакетом.
 prepared:=kaname._authority_metadata_access_label_stashed_v1();
 retained:=prepared->'retention';
 owning:=prepared#>'{root,census,root_scope_states}';
 actor:=program#>'{frozen,access_label_authority,actor}';
 IF retained->'old_row' IS DISTINCT FROM command->'old'
  OR retained->'new_row' IS DISTINCT FROM command->'new'
  OR retained->'root_physical' IS DISTINCT FROM command->'physical'
  OR retained->>'root_model' IS DISTINCT FROM identity->>'model'
  OR owning->'catalog' IS DISTINCT FROM identity->'catalog_state'
  OR prepared#>'{root,root_update_verb}' IS DISTINCT FROM identity->'update_state'
  OR jsonb_typeof(identity->'update_state') IS DISTINCT FROM 'array'
  OR owning#>>'{account,2,id}' IS DISTINCT FROM identity->>'account_id'
  OR coalesce(owning#>>'{project,2,id}','') IS DISTINCT FROM identity->>'project_id'
  OR coalesce(actor->>'type','') NOT IN ('user','service_account') OR coalesce(actor->>'id','')=''
  OR command#>'{audit_row,event_payload,actor}' IS DISTINCT FROM actor
  OR command#>>'{audit_row,event_payload,resource_type}' IS DISTINCT FROM identity->>'dotted'
  OR command#>>'{audit_row,event_payload,resource_id}' IS DISTINCT FROM identity->>'id' THEN
  RAISE EXCEPTION 'external metadata held scope or audit identity differs' USING ERRCODE='42501';END IF;
 RETURN program;
END;
$command$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_mirror_complete_v1()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $complete$
DECLARE program jsonb;command jsonb;state jsonb;actual jsonb;physical jsonb;
BEGIN
 program:=kaname._authority_metadata_mirror_command_v1();
 command:=program#>'{frozen,mirror_command}';state:=program#>'{frozen,mirror_state}';
 IF program IS NULL OR state->'root_applied' IS DISTINCT FROM 'true'::jsonb
  OR state->'audit_consumed' IS DISTINCT FROM 'true'::jsonb
  OR state->'reconcile_consumed' IS DISTINCT FROM 'true'::jsonb
  OR program#>'{frozen,access_label_freshness_installed}' IS DISTINCT FROM program->'nonce' THEN
  RAISE EXCEPTION 'external metadata command omitted root audit reconcile or freshness' USING ERRCODE='42501';END IF;
 -- Три зарезервированных точечных чтения. Сверяем фактические строки
 -- после всех действий транзакции, не начиная новых ожиданий.
 SELECT to_jsonb(m),jsonb_build_array(m.xmin::text,m.ctid::text) INTO actual,physical
 FROM ONLY kaname.resource_mirror m
 WHERE m.object_type=command#>>'{identity,dotted}' AND m.object_id=command#>>'{identity,id}';
 IF actual IS DISTINCT FROM command->'new' OR physical IS DISTINCT FROM state->'root_after' THEN
  RAISE EXCEPTION 'external metadata applied resource changed before commit' USING ERRCODE='40001';END IF;
 SELECT to_jsonb(a) INTO actual FROM ONLY kaname.audit_outbox a WHERE a.id=command#>>'{audit_row,id}';
 IF actual IS DISTINCT FROM command->'audit_row' THEN
  RAISE EXCEPTION 'external metadata audit changed before commit' USING ERRCODE='42501';END IF;
 SELECT to_jsonb(r) INTO actual FROM ONLY kaname.resource_reconcile_outbox r
 WHERE r.id=(command#>>'{reconcile_row,id}')::bigint;
 IF actual IS DISTINCT FROM command->'reconcile_row' THEN
  RAISE EXCEPTION 'external metadata reconcile changed before commit' USING ERRCODE='42501';END IF;
END;
$complete$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE target text;recipient record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 FOREACH target IN ARRAY ARRAY[
  '_authority_metadata_mirror_command_v1()',
  '_authority_metadata_mirror_complete_v1()'] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',target);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE p.oid=to_regprocedure('kaname.'||target) AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM %I',target,recipient.rolname);
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
 ('_authority_sequence_complete_v3()','a8d690b1e0af17cf3c09b53ce8cbb651a119c76f16d3c0a0c10990b3cb031c05','e5d4c583a372c86fdcdbfb3e23ee72116f2a9efd221de97510f539fddf483dd4',
  $changes$[
 [
  "  RAISE EXCEPTION 'selected sequence program is incomplete' USING ERRCODE='42501';END IF;",
  "  RAISE EXCEPTION 'selected sequence program is incomplete' USING ERRCODE='42501';END IF;\n IF program->>'family'='metadata' AND program#>>'{frozen,mode}'='external_access_labels' THEN\n  PERFORM kaname._authority_metadata_mirror_complete_v1();\n END IF;"
 ]
]$changes$::jsonb),
 ('_authority_crud_storage_v3()','1ec552fc5336a98cece075fa2d69e3cd78807ab57865e1ad1a499142512dce9f','4228f0559ab4575a7f655dc66da9008b5d6919dc7f7a16d13c0ed640d9ca2743',
  $changes$[
 [
  " ('_authority_sequence_complete_v3()','a8d690b1e0af17cf3c09b53ce8cbb651a119c76f16d3c0a0c10990b3cb031c05',true,'v',true,'private'),",
  " ('_authority_sequence_complete_v3()','e5d4c583a372c86fdcdbfb3e23ee72116f2a9efd221de97510f539fddf483dd4',true,'v',true,'private'),\n ('_authority_metadata_mirror_command_v1()','52823698e4b0ae99c11735589197cc0e7be627aca9ad3396e05f248241727aea',false,'v',true,'private'),\n ('_authority_metadata_mirror_complete_v1()','73a193078ce43a305df3253eed3a1957540eba61708f3138e3c4e8ffa38991ef',false,'v',true,'private'),"
 ]
]$changes$::jsonb),
 ('_authority_full_contract_storage_v3()','2822204d78946d3a74f9d8a1d498c2b64e8571da479d6280bf8dc1e63559d966','57c31f2abafba3f779aff359fc30dbdacc4827e2be18d9ed381831a27050996e',
  $changes$[
 [
  "1ec552fc5336a98cece075fa2d69e3cd78807ab57865e1ad1a499142512dce9f",
  "4228f0559ab4575a7f655dc66da9008b5d6919dc7f7a16d13c0ed640d9ca2743"
 ]
]$changes$::jsonb),
 ('authority_metadata_service_account_access_label_ready_v1()','3f15fa266924e9bfd02cd0f7595342ffb1f907b504f57dd474bec10216cb7be1','50eaf3862137e2bfe29e47c7b1e018794ce2f90606bac7f64702a5d8f441f201',
  $changes$[
 [
  "1ec552fc5336a98cece075fa2d69e3cd78807ab57865e1ad1a499142512dce9f",
  "4228f0559ab4575a7f655dc66da9008b5d6919dc7f7a16d13c0ed640d9ca2743"
 ],
 [
  "2822204d78946d3a74f9d8a1d498c2b64e8571da479d6280bf8dc1e63559d966",
  "57c31f2abafba3f779aff359fc30dbdacc4827e2be18d9ed381831a27050996e"
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
 ('authority_metadata_service_account_access_label_ready_v1()','50eaf3862137e2bfe29e47c7b1e018794ce2f90606bac7f64702a5d8f441f201','3f15fa266924e9bfd02cd0f7595342ffb1f907b504f57dd474bec10216cb7be1',
  $changes$[
 [
  "57c31f2abafba3f779aff359fc30dbdacc4827e2be18d9ed381831a27050996e",
  "2822204d78946d3a74f9d8a1d498c2b64e8571da479d6280bf8dc1e63559d966"
 ],
 [
  "4228f0559ab4575a7f655dc66da9008b5d6919dc7f7a16d13c0ed640d9ca2743",
  "1ec552fc5336a98cece075fa2d69e3cd78807ab57865e1ad1a499142512dce9f"
 ]
]$changes$::jsonb),
 ('_authority_full_contract_storage_v3()','57c31f2abafba3f779aff359fc30dbdacc4827e2be18d9ed381831a27050996e','2822204d78946d3a74f9d8a1d498c2b64e8571da479d6280bf8dc1e63559d966',
  $changes$[
 [
  "4228f0559ab4575a7f655dc66da9008b5d6919dc7f7a16d13c0ed640d9ca2743",
  "1ec552fc5336a98cece075fa2d69e3cd78807ab57865e1ad1a499142512dce9f"
 ]
]$changes$::jsonb),
 ('_authority_crud_storage_v3()','4228f0559ab4575a7f655dc66da9008b5d6919dc7f7a16d13c0ed640d9ca2743','1ec552fc5336a98cece075fa2d69e3cd78807ab57865e1ad1a499142512dce9f',
  $changes$[
 [
  " ('_authority_sequence_complete_v3()','e5d4c583a372c86fdcdbfb3e23ee72116f2a9efd221de97510f539fddf483dd4',true,'v',true,'private'),\n ('_authority_metadata_mirror_command_v1()','52823698e4b0ae99c11735589197cc0e7be627aca9ad3396e05f248241727aea',false,'v',true,'private'),\n ('_authority_metadata_mirror_complete_v1()','73a193078ce43a305df3253eed3a1957540eba61708f3138e3c4e8ffa38991ef',false,'v',true,'private'),",
  " ('_authority_sequence_complete_v3()','a8d690b1e0af17cf3c09b53ce8cbb651a119c76f16d3c0a0c10990b3cb031c05',true,'v',true,'private'),"
 ]
]$changes$::jsonb),
 ('_authority_sequence_complete_v3()','e5d4c583a372c86fdcdbfb3e23ee72116f2a9efd221de97510f539fddf483dd4','a8d690b1e0af17cf3c09b53ce8cbb651a119c76f16d3c0a0c10990b3cb031c05',
  $changes$[
 [
  "  RAISE EXCEPTION 'selected sequence program is incomplete' USING ERRCODE='42501';END IF;\n IF program->>'family'='metadata' AND program#>>'{frozen,mode}'='external_access_labels' THEN\n  PERFORM kaname._authority_metadata_mirror_complete_v1();\n END IF;",
  "  RAISE EXCEPTION 'selected sequence program is incomplete' USING ERRCODE='42501';END IF;"
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

DROP FUNCTION kaname._authority_metadata_mirror_complete_v1();
DROP FUNCTION kaname._authority_metadata_mirror_command_v1();
