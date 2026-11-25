-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Закрытая подготовка и сверка источников изменения защищённых меток.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Общее пространство блокировок с пересчётом ресурсов. Начальный допуск
-- используется до protectPolicyPlan. После ожиданий владелец заново выводит
-- полный набор ключей из удержанных источников и подтверждает каждую блокировку.
CREATE FUNCTION kaname._authority_metadata_access_label_source_locks_v1(
 p_sources jsonb,p_policy jsonb,p_binding jsonb,p_budget integer,p_check boolean
) RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $guards$
DECLARE proof jsonb;entry record;keys integer;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
  OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'full'
  OR NOT coalesce((proof->>'writer_contract'='2' AND proof->>'purpose'='decision')
        OR (proof->>'writer_contract'='1' AND proof->>'purpose'='participant'),false)
  OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
  OR p_check IS NULL OR NOT EXISTS(SELECT 1 FROM pg_temp.kaname_authority_consumer c WHERE c.finalized=p_check) THEN
  RAISE EXCEPTION 'metadata source locks require the matching signed phase' USING ERRCODE='42501';END IF;
 IF jsonb_typeof(p_sources) IS DISTINCT FROM 'object' OR jsonb_typeof(p_policy) IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_binding) IS DISTINCT FROM 'object' OR p_budget IS NULL OR p_budget NOT BETWEEN 2 AND 4096
  OR p_policy->>'*' IS DISTINCT FROM (CASE proof->>'mode' WHEN 'global' THEN 'write' ELSE 'share' END)
  OR NOT (p_binding ? '') THEN
  RAISE EXCEPTION 'metadata source lock set incomplete' USING ERRCODE='42501';END IF;
 SELECT (SELECT count(*) FROM jsonb_object_keys(p_sources))+
        (SELECT count(*) FROM jsonb_object_keys(p_policy))+
        (SELECT count(*) FROM jsonb_object_keys(p_binding)) INTO keys;
 IF keys>p_budget THEN RAISE EXCEPTION 'metadata source lock budget exceeded' USING ERRCODE='54000';END IF;
 IF EXISTS(SELECT 1 FROM (SELECT key,value FROM jsonb_each_text(p_sources)
   UNION ALL SELECT key,value FROM jsonb_each_text(p_policy)
   UNION ALL SELECT key,value FROM jsonb_each_text(p_binding)) t
  WHERE octet_length(t.key)>16384 OR t.key ~ '[[:space:][:cntrl:]]' OR coalesce(t.value,'') NOT IN ('share','write'))
  OR EXISTS(SELECT 1 FROM jsonb_each_text(p_sources) e WHERE e.key !~ '^(role|binding):[^:#*]+$' OR e.value<>'share')
  OR p_policy ? '' OR EXISTS(SELECT 1 FROM jsonb_object_keys(p_binding) k WHERE k<>'' AND k !~ '^acc[a-zA-Z0-9_-]{1,61}$') THEN
  RAISE EXCEPTION 'metadata source lock coordinate invalid' USING ERRCODE='42501';END IF;
 -- Коллизии hash получают сильнейший режим при первом захвате, как у
 -- _authority_resource_epoch_wait_v2. Проверка не захватывает новые ключи.
 FOR entry IN SELECT q.namespace,hashtext(q.key) AS lock_key,min(q.key COLLATE "C") AS original_key,
    bool_or(q.value='write') AS exclusive
  FROM (SELECT 1262569295 namespace,key,value FROM jsonb_each_text(p_sources)
   UNION ALL SELECT 1262569296,key,value FROM jsonb_each_text(p_policy)
   UNION ALL SELECT 1262569297,key,value FROM jsonb_each_text(p_binding)) q
  GROUP BY q.namespace,hashtext(q.key) ORDER BY q.namespace,hashtext(q.key)
 LOOP
  IF p_check THEN
   PERFORM kaname._authority_resource_preheld_key_v2(entry.namespace,entry.original_key,entry.exclusive);
  ELSIF entry.exclusive THEN
   PERFORM pg_advisory_xact_lock(entry.namespace,entry.lock_key);
  ELSE
   PERFORM pg_advisory_xact_lock_shared(entry.namespace,entry.lock_key);
  END IF;
 END LOOP;
 RETURN keys;
END;
$guards$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Вызывается владельцем после подписанного входа и до первой проверки
-- эпох политики. Полученный пакет остаётся у владельца до сверки под замками.
CREATE FUNCTION kaname._authority_metadata_access_label_prepare_lockset_v1(
 p_kind text,p_id text,p_old_xmin text,p_old jsonb,p_new_access jsonb,
 p_policy_expected jsonb,p_policy_writes text[],p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $prepare$
DECLARE
 proof jsonb; invoker oid; bundle record; catalog jsonb; carriers jsonb; discovery jsonb;
 binding_keys jsonb; policy_keys jsonb; source_keys jsonb; policy_key_count integer;
 root_account text; owner_plan jsonb; actual_keys integer; rows_used integer; reads_used integer; work_used integer;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
  OR proof->>'consumer_abi' IS DISTINCT FROM '2'
  OR proof->>'consumer_profile' IS DISTINCT FROM 'full'
  OR proof->>'consumer_finalized' IS DISTINCT FROM 'false'
  OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
  OR NOT coalesce((proof->>'writer_contract'='2' AND proof->>'purpose'='decision')
   OR (proof->>'writer_contract'='1' AND proof->>'purpose'='participant'),false)
  OR coalesce(proof->>'mode','') NOT IN ('accounts','global') THEN
  RAISE EXCEPTION 'metadata lockset requires pending signed full consumer' USING ERRCODE='42501';
 END IF;
 IF p_rows IS NULL OR p_rows NOT BETWEEN 2 AND 100000
  OR p_reads IS NULL OR p_reads NOT BETWEEN 3 AND 4096
  OR p_work IS NULL OR p_work NOT BETWEEN 2 AND 400000 THEN
  RAISE EXCEPTION 'metadata lockset budget invalid' USING ERRCODE='54000';END IF;
 IF jsonb_typeof(p_policy_expected) IS DISTINCT FROM 'object'
  OR NOT (p_policy_expected ? '*') OR p_policy_writes IS NULL
  OR cardinality(p_policy_writes)>4096
  OR EXISTS(SELECT 1 FROM unnest(p_policy_writes) w WHERE w IS NULL OR NOT (p_policy_expected ? w))
  OR (proof->>'mode'='global' AND cardinality(p_policy_writes)<>0) THEN
  RAISE EXCEPTION 'metadata lockset policy guards invalid' USING ERRCODE='42501';END IF;
 SELECT count(*)::integer INTO policy_key_count FROM jsonb_object_keys(p_policy_expected);
 IF policy_key_count+1>4096 OR policy_key_count>p_work-1 THEN
  RAISE EXCEPTION 'metadata policy lock set too large' USING ERRCODE='54000';END IF;

 invoker:=(proof->>'invoker_oid')::oid;
 IF invoker IS NULL
  OR NOT coalesce(has_table_privilege(invoker,'kaname.authority_semantic_identity','SELECT'),false)
  OR NOT coalesce(has_function_privilege(invoker,'kaname.authority_protocol_read_bundle()','EXECUTE'),false) THEN
  RAISE EXCEPTION 'metadata canonical bundle read denied' USING ERRCODE='42501';END IF;
 SELECT * INTO bundle FROM kaname.authority_protocol_read_bundle();
 IF NOT FOUND OR bundle.model_id IS DISTINCT FROM proof->>'model_id'
  OR bundle.catalog_id IS DISTINCT FROM proof->>'catalog_id'
  OR bundle.projector_version IS DISTINCT FROM proof->>'projector_version'
  OR octet_length(bundle.catalog_json) NOT BETWEEN 1 AND 8388608
  OR encode(sha256(bundle.catalog_json),'hex') IS DISTINCT FROM bundle.catalog_id
  OR encode(sha256(convert_to(bundle.model_source,'UTF8')),'hex') IS DISTINCT FROM bundle.model_id THEN
  RAISE EXCEPTION 'metadata admitted catalog changed' USING ERRCODE='P1034';END IF;
 catalog:=convert_from(bundle.catalog_json,'UTF8')::jsonb;
 carriers:=kaname._authority_metadata_access_label_prefinal_carriers_v1(
  p_kind,p_id,p_old_xmin,p_old,p_new_access,p_rows-1,p_reads-1,p_work-1-policy_key_count);
 rows_used:=1+(carriers->>'rows')::integer;
 reads_used:=1+(carriers->>'reads')::integer;
 work_used:=1+policy_key_count+(carriers->>'work')::integer;
 discovery:=kaname._authority_metadata_access_label_early_closure_v1(
  carriers,catalog,p_rows-rows_used,p_reads-reads_used,p_work-work_used);
 rows_used:=rows_used+(discovery->>'rows')::integer;
 reads_used:=reads_used+(discovery->>'reads')::integer;
 work_used:=work_used+(discovery->>'work')::integer;
 PERFORM kaname._authority_metadata_access_label_discovery_fence_v1(discovery);

 root_account:=carriers->>'root_account';
 IF coalesce(root_account,'')='' THEN
  RAISE EXCEPTION 'metadata root account absent from discovery' USING ERRCODE='42501';END IF;
 SELECT coalesce(jsonb_object_agg(key,CASE WHEN key=ANY(p_policy_writes)
  OR (key='*' AND proof->>'mode'='global') THEN 'write' ELSE 'share' END),'{}')
 INTO policy_keys FROM jsonb_object_keys(p_policy_expected) key;
 SELECT coalesce(jsonb_object_agg(v.id,CASE WHEN v.id=root_account THEN 'write' ELSE 'share' END),'{}')
 INTO binding_keys FROM (
  SELECT root_account AS id
  UNION
  SELECT entry.value#>>'{source,id}' FROM jsonb_each(discovery->'source_index') entry
   WHERE entry.value#>>'{source,kind}'='23'
 ) v;
 binding_keys:=binding_keys||jsonb_build_object('','share');
 IF EXISTS(SELECT 1 FROM jsonb_object_keys(binding_keys) k
  WHERE k<>'' AND NOT policy_keys ? ('scope:'||k)) THEN
  RAISE EXCEPTION 'metadata replay plan needs freshly staged policy scopes' USING ERRCODE='P1034';END IF;
 IF p_work-work_used<2 THEN
  RAISE EXCEPTION 'metadata lockset work exhausted' USING ERRCODE='54000';END IF;
 source_keys:=discovery->'carrier_source_guards';
 actual_keys:=kaname._authority_metadata_access_label_source_locks_v1(
  source_keys,policy_keys,binding_keys,least(p_work-work_used,4096),false);
 work_used:=work_used+actual_keys;
 owner_plan:=jsonb_build_object('backend',proof->'backend','transaction_id',proof->'transaction_id',
  'invoker_oid',proof->'invoker_oid','nonce',proof->'nonce','mode',proof->'mode','accounts',proof->'accounts',
  'source_guards',source_keys,'policy_epochs',policy_keys,'binding_epochs',binding_keys);
 RETURN jsonb_build_object('root',carriers,'discovery',discovery,'catalog_id',bundle.catalog_id,
  'plan',owner_plan,'rows',rows_used,'reads',reads_used,'work',work_used);
END;
$prepare$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Данные первого этапа остаются в транзакции и не выходят в runtime.
CREATE FUNCTION kaname._authority_metadata_access_label_stash_v1(p_prepared jsonb)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $stash$
DECLARE proof jsonb; recipient record; storage oid;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
  OR proof->>'consumer_abi' IS DISTINCT FROM '2'
  OR proof->>'consumer_profile' IS DISTINCT FROM 'full'
  OR proof->>'consumer_finalized' IS DISTINCT FROM 'false'
  OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
  OR NOT coalesce((proof->>'writer_contract'='2' AND proof->>'purpose'='decision')
   OR (proof->>'writer_contract'='1' AND proof->>'purpose'='participant'),false)
  OR jsonb_typeof(p_prepared->'root') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_prepared->'discovery') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_prepared->'plan') IS DISTINCT FROM 'object'
  OR p_prepared#>'{plan,nonce}' IS DISTINCT FROM proof->'nonce'
  OR p_prepared->'catalog_id' IS DISTINCT FROM proof->'catalog_id'
  OR to_regclass('pg_temp.kaname_authority_metadata_discovery') IS NOT NULL THEN
  RAISE EXCEPTION 'metadata owner discovery storage admission mismatch' USING ERRCODE='42501';END IF;
 IF octet_length(p_prepared::text)>67108864 THEN
  RAISE EXCEPTION 'metadata owner discovery storage budget exceeded' USING ERRCODE='54000';END IF;
 CREATE TEMP TABLE kaname_authority_metadata_discovery(
  singleton boolean PRIMARY KEY CHECK(singleton),
  prepared jsonb NOT NULL
 ) ON COMMIT DROP;
 storage:='pg_temp.kaname_authority_metadata_discovery'::regclass;
 REVOKE ALL ON TABLE pg_temp.kaname_authority_metadata_discovery FROM PUBLIC;
 FOR recipient IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_class c
  CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) a
  JOIN pg_catalog.pg_roles u ON u.oid=a.grantee
  WHERE c.oid=storage AND a.grantee<>c.relowner LOOP
  EXECUTE format('REVOKE ALL ON TABLE pg_temp.kaname_authority_metadata_discovery FROM %I',recipient.rolname);
 END LOOP;
 INSERT INTO pg_temp.kaname_authority_metadata_discovery VALUES(true,p_prepared);
END;
$stash$;
-- +goose StatementEnd

-- +goose StatementBegin
-- После первого protectPolicyPlan перечитываем только пакет этой попытки.
-- Затем owner replay отдельно подтверждает удержанные ключи и физические строки.
CREATE FUNCTION kaname._authority_metadata_access_label_stashed_v1()
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $stashed$
DECLARE proof jsonb; prepared jsonb; storage oid; field_name text;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
  OR proof->>'consumer_abi' IS DISTINCT FROM '2'
  OR proof->>'consumer_profile' IS DISTINCT FROM 'full'
  OR proof->>'consumer_finalized' IS DISTINCT FROM 'true'
  OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
  OR NOT coalesce((proof->>'writer_contract'='2' AND proof->>'purpose'='decision')
   OR (proof->>'writer_contract'='1' AND proof->>'purpose'='participant'),false) THEN
  RAISE EXCEPTION 'metadata owner discovery storage requires held policy' USING ERRCODE='42501';END IF;
 storage:=to_regclass('pg_temp.kaname_authority_metadata_discovery');
 IF storage IS NULL OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c
   WHERE c.oid=storage AND c.relowner=to_regrole(current_user) AND c.relkind='r' AND c.relpersistence='t')
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c
   CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))) a
   WHERE c.oid=storage AND a.grantee<>c.relowner) THEN
  RAISE EXCEPTION 'untrusted metadata owner discovery storage' USING ERRCODE='42501';END IF;
 SELECT d.prepared INTO STRICT prepared FROM pg_temp.kaname_authority_metadata_discovery d WHERE singleton;
 FOREACH field_name IN ARRAY ARRAY['backend','transaction_id','invoker_oid','nonce','mode','accounts'] LOOP
  IF NOT (proof ? field_name) OR prepared#>ARRAY['plan',field_name] IS DISTINCT FROM proof->field_name THEN
   RAISE EXCEPTION 'metadata owner discovery belongs to another attempt' USING ERRCODE='42501';END IF;
 END LOOP;
 IF prepared->'catalog_id' IS DISTINCT FROM proof->'catalog_id' THEN
  RAISE EXCEPTION 'metadata owner discovery catalog changed' USING ERRCODE='P1034';END IF;
 RETURN prepared;
END;
$stashed$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Удерживаем ресурс до binding epoch в том же порядке, что metadata preflight.
-- Источники перечитываем до окончательного времени решения по уже принятому плану.
CREATE FUNCTION kaname._authority_metadata_access_label_hold_and_replay_v1(
 p_patch jsonb,p_rename boolean,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $hold$
DECLARE
 prepared jsonb; old_state jsonb; physical_state jsonb; root_coordinate jsonb;
 plan jsonb; scope_record record; replay jsonb; table_name text; resource_id text;
 root_account text; locked_scope text; frontier_witnesses jsonb;
 invoker oid; relation_id oid; field_name text;
 rows_used integer:=2; reads_used integer:=7; work_used integer;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_rows IS NULL OR p_rows NOT BETWEEN 2 AND 100000
  OR p_reads IS NULL OR p_reads NOT BETWEEN 8 AND 4096
  OR p_work IS NULL OR p_work NOT BETWEEN 1 AND 400000 THEN
  RAISE EXCEPTION 'metadata physical replay budget invalid' USING ERRCODE='54000';END IF;
 prepared:=kaname._authority_metadata_access_label_stashed_v1();
 old_state:=prepared#>'{root,root_state}';
 root_coordinate:=prepared#>'{root,root_coordinate}';
 plan:=prepared->'plan';
 root_account:=prepared#>>'{root,root_account}';
 resource_id:=root_coordinate->>1;
 table_name:=CASE root_coordinate->>0 WHEN 'iam.account' THEN 'accounts'
  WHEN 'iam.project' THEN 'projects' END;
 IF table_name IS NULL OR coalesce(resource_id,'')='' OR coalesce(root_account,'')=''
  OR jsonb_typeof(old_state) IS DISTINCT FROM 'array' OR jsonb_array_length(old_state)<>3
  OR old_state#>>'{2,id}' IS DISTINCT FROM resource_id
  OR jsonb_typeof(p_patch) IS DISTINCT FROM 'object'
  OR p_patch-ARRAY['name','description','labels','access_labels']<>'{}'::jsonb
  OR (p_patch ? 'name' AND jsonb_typeof(p_patch->'name') IS DISTINCT FROM 'string')
  OR (p_patch ? 'description' AND jsonb_typeof(p_patch->'description') IS DISTINCT FROM 'string')
  OR (p_patch ? 'labels' AND jsonb_typeof(p_patch->'labels') IS DISTINCT FROM 'object')
  OR kaname.access_labels_valid_v1(p_patch->'access_labels') IS DISTINCT FROM true
  OR p_patch->'access_labels' IS DISTINCT FROM prepared#>'{root,census,new_labels}'
  OR p_rename IS DISTINCT FROM (p_patch ? 'name' AND p_patch->'name' IS DISTINCT FROM old_state#>'{2,name}')
  OR jsonb_typeof(plan->'binding_epochs') IS DISTINCT FROM 'object'
  OR plan#>>ARRAY['binding_epochs',root_account] IS DISTINCT FROM 'write'
  OR plan#>>ARRAY['binding_epochs',''] IS DISTINCT FROM 'share' THEN
  RAISE EXCEPTION 'metadata physical replay identity or patch differs' USING ERRCODE='42501';END IF;

 invoker:=(plan->>'invoker_oid')::oid;
 relation_id:=to_regclass('kaname.'||table_name);
 IF invoker IS NULL OR relation_id IS NULL
  OR NOT coalesce(has_table_privilege(invoker,relation_id,'SELECT'),false) THEN
  RAISE EXCEPTION 'metadata physical replay needs original read privilege' USING ERRCODE='42501';END IF;
 FOREACH field_name IN ARRAY ARRAY['name','description','labels','access_labels'] LOOP
  IF NOT coalesce(has_column_privilege(invoker,relation_id,field_name,'UPDATE'),false) THEN
   RAISE EXCEPTION 'metadata physical replay needs original write privilege' USING ERRCODE='42501';END IF;
 END LOOP;

 IF p_rename AND table_name='accounts' THEN
  LOCK TABLE kaname.accounts IN SHARE ROW EXCLUSIVE MODE;
 ELSE
  EXECUTE format('LOCK TABLE kaname.%I IN ROW EXCLUSIVE MODE',table_name);
 END IF;
 LOCK TABLE kaname.authority_binding_epoch IN ROW EXCLUSIVE MODE;
 EXECUTE format('SELECT jsonb_build_array(o.xmin::text,o.ctid::text,to_jsonb(o))
  FROM ONLY kaname.%I o WHERE o.id=$1 FOR UPDATE OF o',table_name)
 INTO physical_state USING resource_id;
 IF physical_state IS DISTINCT FROM old_state THEN
  RAISE EXCEPTION 'metadata root changed during physical wait' USING ERRCODE='40001';END IF;

 FOR scope_record IN SELECT e.key,e.value FROM jsonb_each_text(plan->'binding_epochs') e ORDER BY e.key COLLATE "C" LOOP
  IF reads_used>=p_reads OR rows_used>=p_rows THEN
   RAISE EXCEPTION 'metadata binding epoch replay budget exhausted' USING ERRCODE='54000';END IF;
  reads_used:=reads_used+1;
  locked_scope:=NULL;
  IF scope_record.value='write' THEN
   SELECT e.scope INTO locked_scope FROM ONLY kaname.authority_binding_epoch e
   WHERE e.scope=scope_record.key FOR UPDATE OF e;
  ELSIF scope_record.value='share' THEN
   SELECT e.scope INTO locked_scope FROM ONLY kaname.authority_binding_epoch e
   WHERE e.scope=scope_record.key FOR SHARE OF e;
  ELSE
   RAISE EXCEPTION 'metadata binding epoch lock mode differs' USING ERRCODE='42501';
  END IF;
  IF locked_scope IS NOT NULL THEN
   rows_used:=rows_used+1;
  ELSIF scope_record.key IN ('',root_account) THEN
   RAISE EXCEPTION 'metadata binding epoch missing' USING ERRCODE='P1034';
  END IF;
 END LOOP;

 frontier_witnesses:=prepared#>'{discovery,frontier,witnesses}';
 IF jsonb_typeof(frontier_witnesses) IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'metadata replay frontier witness missing' USING ERRCODE='42501';END IF;
 SELECT count(*)::integer INTO work_used FROM jsonb_object_keys(frontier_witnesses);
 IF work_used>=p_work THEN
  RAISE EXCEPTION 'metadata replay frontier work exhausted' USING ERRCODE='54000';END IF;
 IF EXISTS(SELECT 1 FROM jsonb_each(frontier_witnesses) w WHERE w.value->'cluster_states'='[]'::jsonb) THEN
  -- В отсутствие singleton строку удержать невозможно. Защищаем предикат
  -- от вставки до конца транзакции.
  LOCK TABLE kaname.clusters IN SHARE MODE;
 END IF;

 replay:=kaname._authority_metadata_access_label_held_replay_v1(
  prepared->'root',prepared->'discovery',plan,p_rows-rows_used,p_reads-reads_used,p_work-work_used);
 IF jsonb_typeof(replay) IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'metadata replay did not confirm sources' USING ERRCODE='42501';END IF;
 RETURN jsonb_build_object('replay',replay,
  'root_physical',jsonb_build_object('table',table_name,'id',resource_id,'xmin',physical_state->>0,'ctid',physical_state->>1),
  'rows',rows_used+(replay->>'rows')::integer,'reads',reads_used+(replay->>'reads')::integer,
  'work',work_used+(replay->>'work')::integer);
END;
$hold$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE signature text; recipient record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 FOREACH signature IN ARRAY ARRAY[
  '_authority_metadata_access_label_source_locks_v1(jsonb,jsonb,jsonb,integer,boolean)',
  '_authority_metadata_access_label_prepare_lockset_v1(text,text,text,jsonb,jsonb,jsonb,text[],integer,integer,integer)',
  '_authority_metadata_access_label_stash_v1(jsonb)',
  '_authority_metadata_access_label_stashed_v1()',
  '_authority_metadata_access_label_hold_and_replay_v1(jsonb,boolean,integer,integer,integer)'
 ] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',signature);
  FOR recipient IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_proc f
   CROSS JOIN LATERAL pg_catalog.aclexplode(f.proacl) a
   JOIN pg_catalog.pg_roles u ON u.oid=a.grantee
   WHERE f.oid=to_regprocedure('kaname.'||signature) AND a.grantee<>f.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM %I',signature,recipient.rolname);
  END LOOP;
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_metadata_access_label_hold_and_replay_v1(jsonb,boolean,integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_access_label_stashed_v1();
DROP FUNCTION kaname._authority_metadata_access_label_stash_v1(jsonb);
DROP FUNCTION kaname._authority_metadata_access_label_prepare_lockset_v1(text,text,text,jsonb,jsonb,jsonb,text[],integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_access_label_source_locks_v1(jsonb,jsonb,jsonb,integer,boolean);
