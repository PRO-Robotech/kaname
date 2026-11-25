-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Физическая идентичность обычной правки и no-op. Старый снимок сверяется
-- под удержаниями. Grant-решение и выходные записи принадлежат следующей
-- фазе команды; этот helper самостоятельно ничего не применяет.
-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_metadata_mirror_ordinary_identity_v1(p_dotted text,p_id text)
RETURNS jsonb LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $identity$
 SELECT jsonb_build_object('dotted',m.object_type,'id',m.object_id,
  'mirror',jsonb_build_array(m.xmin::text,m.ctid::text,jsonb_build_object('rel',m.tableoid::oid)),
  'catalog',jsonb_build_array(c.xmin::text,c.ctid::text,jsonb_build_object('rel',c.tableoid::oid,'module',c.module,'resource',c.resource,'dotted',c.dotted,'object_type',c.object_type)),
  'verb',jsonb_build_array(v.xmin::text,v.ctid::text,jsonb_build_object('rel',v.tableoid::oid)),
  'account',jsonb_build_array(a.xmin::text,a.ctid::text,jsonb_build_object('rel',a.tableoid::oid,'id',a.id)),
  'project',CASE WHEN p.id IS NOT NULL THEN jsonb_build_array(p.xmin::text,p.ctid::text,jsonb_build_object('rel',p.tableoid::oid,'id',p.id,'account_id',p.account_id)) END,
  'binding',CASE WHEN b.object_type IS NOT NULL THEN jsonb_build_array(b.xmin::text,b.ctid::text,jsonb_build_object('rel',b.tableoid::oid,'project_id',b.project_id)) END,
  'policy',kaname.authority_policy_epoch_read(ARRAY['*','scope:'||a.id]),
  'binding_epoch',kaname.authority_binding_epoch_read(ARRAY[a.id]),
  'has_receipt',EXISTS(SELECT FROM ONLY kaname.producer_source_receipt r
   WHERE r.catalog_type=m.object_type AND r.object_id=m.object_id))
 FROM ONLY kaname.resource_mirror m
 JOIN ONLY kaname.catalog_resource c ON c.dotted=m.object_type AND c.live AND c.module<>'iam'
  AND c.module||'.'||c.resource=c.dotted
 JOIN ONLY kaname.catalog_verb v ON (v.module,v.resource)=(c.module,c.resource)
  AND v.verb='update' AND v.live AND v.per_object
 LEFT JOIN ONLY kaname.projects p ON p.id=nullif(m.parent_project_id,'')
 JOIN ONLY kaname.accounts a ON a.id=coalesce(nullif(m.parent_account_id,''),p.account_id)
 LEFT JOIN ONLY kaname.object_project_binding b ON b.object_type=c.object_type AND b.object_id=m.object_id
 WHERE m.object_type=p_dotted AND m.object_id=p_id
  AND (nullif(m.parent_project_id,'') IS NULL OR (p.id IS NOT NULL AND p.account_id=a.id))
  AND (b.object_type IS NULL OR b.project_id=p.id)
  AND c.object_type NOT IN ('iam_grant_scope','iam_grant_role','iam_grant_access_label')
  AND greatest(octet_length(m.object_type),octet_length(m.object_id),octet_length(c.object_type),
   octet_length(a.id),octet_length(p.id))<=16384
$identity$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_mirror_ordinary_root_v1(
 p_dotted text,p_id text,p_rr jsonb,p_patch jsonb,p_rows integer,p_reads integer,p_work integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $root$
DECLARE
 proof jsonb; actual jsonb; old_row jsonb; new_row jsonb; kind text; write_labels boolean; same_access boolean;
 policy_keys text[]; expected_key text; binding_scope text; epoch_state jsonb;
 model text; v_account_id text; v_project_id text; invoker oid; k text; relation_id oid;
 -- Семь таблиц, физические удержания, два чтения identity и проверка допуска.
 fixed_rows constant integer:=64; fixed_reads constant integer:=96; fixed_work constant integer:=64;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
  OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'full'
  OR proof->>'consumer_finalized' IS DISTINCT FROM 'false'
  OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
  OR NOT coalesce((proof->>'writer_contract'='2' AND proof->>'purpose'='decision')
   OR (proof->>'writer_contract'='1' AND proof->>'purpose'='participant'),false)
  OR kaname._authority_sequence_store_v3() IS NOT NULL
  OR coalesce(proof->>'mode','') NOT IN ('global','accounts') THEN
  RAISE EXCEPTION 'ordinary mirror root requires signed pending full consumer' USING ERRCODE='42501';
 END IF;
 IF p_rows IS NULL OR p_rows NOT BETWEEN fixed_rows AND 100000
  OR p_reads IS NULL OR p_reads NOT BETWEEN fixed_reads AND 4096
  OR p_work IS NULL OR p_work NOT BETWEEN fixed_work AND 400000 THEN
  RAISE EXCEPTION 'ordinary mirror root budget exhausted' USING ERRCODE='54000';
 END IF;
 IF coalesce(p_dotted,'')='' OR octet_length(p_dotted)>16384 OR p_dotted ~ '[:#*[:space:][:cntrl:]]' OR split_part(p_dotted,'.',1)='iam'
  OR coalesce(p_id,'')='' OR octet_length(p_id)>16384 OR p_id ~ '[:#*[:space:][:cntrl:]]'
  OR jsonb_typeof(p_rr) IS DISTINCT FROM 'object' OR pg_column_size(p_rr)>262144
  OR octet_length(p_rr::text)>262144
  OR jsonb_typeof(p_patch) IS DISTINCT FROM 'object' OR octet_length(p_patch::text)>1048576
  OR p_patch-ARRAY['labels','access_labels']<>'{}'::jsonb
  OR (p_patch ? 'access_labels' AND kaname.access_labels_valid_v1(p_patch->'access_labels') IS DISTINCT FROM true)
  OR (p_patch ? 'labels' AND kaname.labels_valid(p_patch->'labels') IS DISTINCT FROM true) THEN
  RAISE EXCEPTION 'invalid ordinary mirror coordinate or patch' USING ERRCODE='42501';
 END IF;
 IF p_patch ? 'labels' AND EXISTS(SELECT FROM jsonb_each(p_patch->'labels') e WHERE jsonb_typeof(e.value)<>'string') THEN
  RAISE EXCEPTION 'ordinary mirror label value must be a string' USING ERRCODE='42501';
 END IF;
 -- DDL несовместимый с чтением, включая включение RLS, не должен сменить
 -- уже подтверждённую форму источников. Все ожидания до decision_at.
 LOCK TABLE ONLY kaname.catalog_resource, ONLY kaname.catalog_verb, ONLY kaname.accounts,
  ONLY kaname.projects, ONLY kaname.object_project_binding, ONLY kaname.resource_mirror IN ROW SHARE MODE NOWAIT;
 LOCK TABLE ONLY kaname.producer_source_receipt IN ACCESS SHARE MODE NOWAIT;
 LOCK TABLE ONLY kaname.authority_policy_epoch, ONLY kaname.authority_binding_epoch IN ROW SHARE MODE NOWAIT;
 IF current_setting('session_replication_role') NOT IN ('origin','local')
  OR EXISTS(SELECT FROM (VALUES
   ('object_project_binding','authority_registration_binding_guard_v2','authority_registration_binding_guard_v2',23,NULL,NULL),
   ('object_project_binding','object_project_binding_is_permanent','object_project_binding_is_permanent',27,NULL,NULL),
   ('object_project_binding','object_project_binding_is_not_truncated','object_project_binding_is_permanent',34,NULL,NULL),
   ('producer_source_receipt','policy_epoch_insert','authority_policy_changed',4,NULL,'new_policy_rows'),
   ('producer_source_receipt','policy_epoch_update','authority_policy_changed',16,'old_policy_rows','new_policy_rows'),
   ('producer_source_receipt','policy_epoch_delete','authority_policy_changed',8,'old_policy_rows',NULL),
   ('producer_source_receipt','policy_epoch_truncate','authority_policy_changed',32,NULL,NULL),
   ('resource_mirror','policy_epoch_update','authority_policy_changed',16,'old_policy_rows','new_policy_rows'),
   ('resource_mirror','binding_epoch_update','authority_binding_epoch_changed',16,'old_epoch_rows','new_epoch_rows'),
   ('resource_mirror','resource_registration_locks_writers','resource_registration_locks_writers',62,NULL,NULL),
   ('resource_mirror','resource_mirror_keeps_the_bound_project','resource_mirror_keeps_the_bound_project',23,NULL,NULL)
  ) q(rel,name,fn,kind,oldref,newref) WHERE NOT EXISTS(SELECT FROM pg_catalog.pg_trigger t
   WHERE t.tgrelid=to_regclass('kaname.'||q.rel) AND t.tgname=q.name
    AND t.tgfoid=to_regprocedure('kaname.'||q.fn||'()') AND t.tgtype=q.kind
    AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal AND t.tgqual IS NULL
    AND t.tgnargs=0 AND t.tgattr::text='' AND t.tgconstraint=0 AND NOT t.tgdeferrable AND NOT t.tginitdeferred
    AND t.tgoldtable::text IS NOT DISTINCT FROM q.oldref AND t.tgnewtable::text IS NOT DISTINCT FROM q.newref)) THEN
  RAISE EXCEPTION 'ordinary mirror physical registration or epoch guard unavailable' USING ERRCODE='42501';
 END IF;
 invoker:=(proof->>'invoker_oid')::oid;
 FOREACH relation_id IN ARRAY ARRAY['kaname.catalog_resource'::regclass,'kaname.catalog_verb'::regclass,
  'kaname.resource_mirror'::regclass,'kaname.projects'::regclass,'kaname.accounts'::regclass,
  'kaname.object_project_binding'::regclass,'kaname.producer_source_receipt'::regclass] LOOP
  IF NOT EXISTS(SELECT FROM pg_catalog.pg_class c WHERE c.oid=relation_id AND c.relkind='r'
   AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND NOT c.relispartition
   AND NOT c.relhassubclass AND NOT c.relhasrules
   AND NOT EXISTS(SELECT FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid)
   AND has_table_privilege(invoker,c.oid,'SELECT')) THEN
   RAISE EXCEPTION 'ordinary mirror requires original SELECT on physical source' USING ERRCODE='42501';
  END IF;
 END LOOP;
 actual:=kaname.authority_metadata_mirror_ordinary_identity_v1(p_dotted,p_id);
 IF actual IS NULL OR actual IS DISTINCT FROM p_rr THEN
  RAISE EXCEPTION 'ordinary mirror identity changed after RR' USING ERRCODE='40001';
 END IF;
 SELECT p_patch ? 'labels' AND m.labels IS DISTINCT FROM p_patch->'labels',
  NOT (p_patch ? 'access_labels') OR m.access_labels IS NOT DISTINCT FROM p_patch->'access_labels'
 INTO write_labels,same_access FROM ONLY kaname.resource_mirror m
 WHERE m.object_type=p_dotted AND m.object_id=p_id
  AND m.xmin::text=actual#>>'{mirror,0}' AND m.ctid::text=actual#>>'{mirror,1}';
 IF NOT FOUND THEN RAISE EXCEPTION 'ordinary mirror changed before classification' USING ERRCODE='40001';END IF;
 model:=actual#>>'{catalog,2,object_type}'; v_account_id:=actual#>>'{account,2,id}';
 v_project_id:=actual#>>'{project,2,id}';
 IF same_access IS DISTINCT FROM true
  OR coalesce(model,'') !~ '^[a-z][a-z0-9_]*$'
  OR (proof->>'mode'='accounts' AND NOT coalesce((proof->'accounts') ? v_account_id,false)) THEN
  RAISE EXCEPTION 'ordinary mirror held scope or unchanged protected labels required' USING ERRCODE='42501';
 END IF;
 kind:=CASE WHEN write_labels THEN 'ordinary' ELSE 'noop' END;
 IF kind='ordinary' AND NOT coalesce(has_column_privilege(invoker,'kaname.resource_mirror','labels','UPDATE'),false) THEN
  RAISE EXCEPTION 'ordinary mirror original labels write privilege missing' USING ERRCODE='42501';
 END IF;
 -- Физический UPDATE вызывает legacy BEFORE STATEMENT. Для чтения
 -- достаточно guard на точную привязку и policy root для receipt.
 IF kind='ordinary' THEN
  IF NOT pg_try_advisory_xact_lock(hashtextextended('kaname.resource_registration_writers',0)) THEN
   RAISE EXCEPTION 'ordinary mirror registration writer busy' USING ERRCODE='40001';
  END IF;
  LOCK TABLE ONLY kaname.resource_mirror IN ROW EXCLUSIVE MODE NOWAIT;
 END IF;
 PERFORM c.dotted FROM ONLY kaname.catalog_resource c WHERE c.dotted=p_dotted AND c.live AND c.module<>'iam' FOR SHARE OF c NOWAIT;
 PERFORM v.verb FROM ONLY kaname.catalog_verb v WHERE v.module=actual#>>'{catalog,2,module}'
  AND v.resource=actual#>>'{catalog,2,resource}' AND v.verb='update' AND v.live AND v.per_object FOR SHARE OF v NOWAIT;
 PERFORM a.id FROM ONLY kaname.accounts a WHERE a.id=v_account_id FOR SHARE OF a NOWAIT;
 IF v_project_id IS NOT NULL THEN
  PERFORM p.id FROM ONLY kaname.projects p WHERE p.id=v_project_id FOR SHARE OF p NOWAIT;
 END IF;
 -- Producer receipts на INSERT/UPDATE/DELETE/TRUNCATE меняют policy '*'.
 -- Берём тот же корень до повторного чтения. Пустой receipt защищён
 -- даже если писатель начал до нас, но ещё не прошёл свой AFTER trigger.
 IF proof->>'mode'='global' THEN
  PERFORM e.key FROM ONLY kaname.authority_policy_epoch e WHERE e.key='*' FOR UPDATE NOWAIT;
 ELSE
  PERFORM e.key FROM ONLY kaname.authority_policy_epoch e WHERE e.key='*' FOR SHARE NOWAIT;
 END IF;
 IF NOT FOUND THEN RAISE EXCEPTION 'ordinary mirror policy root missing' USING ERRCODE='40001';END IF;
 IF (actual->>'has_receipt')::boolean AND proof->>'mode'<>'global' THEN
  RAISE EXCEPTION 'ordinary mirror receipt requires global entry' USING ERRCODE='40001';END IF;
 expected_key:=CASE WHEN (actual->>'has_receipt')::boolean THEN '*' ELSE 'scope:'||v_account_id END;
 IF write_labels AND expected_key<>'*' THEN
  PERFORM e.key FROM ONLY kaname.authority_policy_epoch e WHERE e.key=('scope:'||v_account_id) FOR UPDATE NOWAIT;
 ELSE
  PERFORM e.key FROM ONLY kaname.authority_policy_epoch e WHERE e.key=('scope:'||v_account_id) FOR SHARE NOWAIT;
 END IF;
 IF NOT FOUND THEN RAISE EXCEPTION 'ordinary mirror scoped policy epoch missing' USING ERRCODE='40001';END IF;
 PERFORM e.scope FROM ONLY kaname.authority_binding_epoch e WHERE e.scope='' FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'ordinary mirror binding epoch root missing' USING ERRCODE='40001';END IF;
 IF write_labels THEN
  PERFORM e.scope FROM ONLY kaname.authority_binding_epoch e WHERE e.scope=v_account_id FOR UPDATE NOWAIT;
 ELSE
  PERFORM e.scope FROM ONLY kaname.authority_binding_epoch e WHERE e.scope=v_account_id FOR SHARE NOWAIT;
 END IF;
 IF NOT FOUND THEN RAISE EXCEPTION 'ordinary mirror scoped binding epoch missing' USING ERRCODE='40001';END IF;
 k:=jsonb_build_array(model,p_id)::text;
 IF NOT pg_try_advisory_xact_lock_shared(1262569300,hashtext(k)) THEN
  RAISE EXCEPTION 'ordinary mirror registration binding busy' USING ERRCODE='40001';
 END IF;
 PERFORM b.project_id FROM ONLY kaname.object_project_binding b
 WHERE b.object_type=model AND b.object_id=p_id FOR SHARE OF b NOWAIT;
 IF kind='ordinary' THEN
  PERFORM m.object_id FROM ONLY kaname.resource_mirror m WHERE m.object_type=p_dotted AND m.object_id=p_id FOR UPDATE OF m NOWAIT;
 ELSE
  PERFORM m.object_id FROM ONLY kaname.resource_mirror m WHERE m.object_type=p_dotted AND m.object_id=p_id FOR SHARE OF m NOWAIT;
 END IF;
 IF NOT FOUND OR kaname.authority_metadata_mirror_ordinary_identity_v1(p_dotted,p_id) IS DISTINCT FROM p_rr THEN
  RAISE EXCEPTION 'ordinary mirror physical input changed during hold' USING ERRCODE='40001';
 END IF;
 -- Реальный OLD читается исключительно после повторной физической сверки.
 -- granteffect.MaxInputBytes ограничивает каждый обрабатываемый образ.
 SELECT to_jsonb(m) INTO STRICT old_row FROM ONLY kaname.resource_mirror m
 WHERE m.object_type=p_dotted AND m.object_id=p_id
  AND m.xmin::text=actual#>>'{mirror,0}' AND m.ctid::text=actual#>>'{mirror,1}';
 IF octet_length(old_row::text)>8388608 THEN
  RAISE EXCEPTION 'ordinary mirror root exceeds input bytes' USING ERRCODE='54000';END IF;
 new_row:=old_row||p_patch;
 IF octet_length(new_row::text)>8388608 THEN
  RAISE EXCEPTION 'ordinary mirror candidate exceeds input bytes' USING ERRCODE='54000';END IF;
 IF new_row->'access_labels' IS DISTINCT FROM old_row->'access_labels'
  OR (old_row IS DISTINCT FROM new_row) IS DISTINCT FROM write_labels THEN
  RAISE EXCEPTION 'ordinary mirror selected fields changed' USING ERRCODE='40001';END IF;
 -- Проверяем OLD и NEW по самим функциям statement-триггеров.
 policy_keys:=kaname.authority_policy_keys('resource_mirror',old_row);
 binding_scope:=kaname.authority_binding_epoch_scope('resource_mirror',old_row);
 IF policy_keys IS DISTINCT FROM ARRAY[expected_key]
  OR kaname.authority_policy_keys('resource_mirror',new_row) IS DISTINCT FROM policy_keys
  OR binding_scope IS DISTINCT FROM v_account_id
  OR kaname.authority_binding_epoch_scope('resource_mirror',new_row) IS DISTINCT FROM binding_scope THEN
  RAISE EXCEPTION 'ordinary mirror write epoch scope changed' USING ERRCODE='40001';END IF;
 epoch_state:=jsonb_build_object('policy',actual->'policy','binding',actual->'binding_epoch',
  'policy_write',CASE WHEN write_labels THEN expected_key END,
  'binding_write',CASE WHEN write_labels THEN binding_scope END);
 RETURN jsonb_build_object('custody',jsonb_build_object('nonce',proof->'nonce','backend',proof->'backend',
  'transaction_id',proof->'transaction_id','invoker_oid',proof->'invoker_oid','mode',proof->'mode','accounts',proof->'accounts'),
  'mode',kind,'identity',actual,'old',old_row,'new',new_row,'epoch',epoch_state,
  'rows',fixed_rows,'reads',fixed_reads,'work',fixed_work);
EXCEPTION WHEN lock_not_available THEN
 RAISE EXCEPTION 'ordinary mirror physical source busy' USING ERRCODE='40001';
END;
$root$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure; recipient record;
BEGIN
 FOREACH fn IN ARRAY ARRAY[
  'kaname.authority_metadata_mirror_ordinary_identity_v1(text,text)'::regprocedure,
  'kaname._authority_metadata_mirror_ordinary_root_v1(text,text,jsonb,jsonb,integer,integer,integer)'::regprocedure] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',fn);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',fn,recipient.rolname);
  END LOOP;
 END LOOP;
END;
$private$;
-- +goose StatementEnd
-- Пины установленных триггеров и их функций не подменяют будущую readiness.
-- +goose StatementBegin
DO $pins$
DECLARE pin record;
BEGIN
 FOR pin IN SELECT * FROM (VALUES
  ('kaname.authority_policy_changed()','46a479262309d1ab8cd6efd41ea519921eb57c13ca7b5054ce6550aba366371d'),
  ('kaname.authority_policy_keys(text,jsonb)','5bed24d2efa4e9dd3eadd3224d06031b5eeebf6785e7461ece8a4830adb46e86'),
  ('kaname.authority_binding_epoch_changed()','bcf0e606baaa81d738d99f2dfb8882f9723c37ccb59f70fb0785e2507119ccef'),
  ('kaname.authority_binding_epoch_scope(text,jsonb)','ae4b14d1640a4473eb8852512b1722b6439a178b2f1fde5fdc76dcc637e2fb30'),
  ('kaname.authority_registration_binding_guard_v2()','3419906be522c12cb827ee2ae9a7a76a86062643efc34f4148b2e15b9537f95f'),
  ('kaname.object_project_binding_is_permanent()','206a32d69a4102c901bba96952a071f809aed9004bc74fb0f1fbcb86fefc62c2'),
  ('kaname.resource_mirror_keeps_the_bound_project()','71f936f3383ae6f73f2e3ff2eca2c95ccc9fb79c8962aa3e964c803b311ed34b'),
  ('kaname.resource_registration_locks_writers()','296db8b4f26f47e0189ce71b01295d5e2ff8e5a8f40b8cdf9807fac347a787c0'),
  ('kaname.authority_policy_epoch_read(text[])','b8f543a39426d32d65d763fd231bea88987b8a6c3540b8cc4e3435563904dd23'),
  ('kaname.authority_binding_epoch_read(text[])','37c8fcd579b297a3c7a749b2889ad95a95561341c63bfa4eb3355284ed583b05'),
  ('kaname.authority_metadata_mirror_ordinary_identity_v1(text,text)','438b1f5b2c18e1ee14595ba2748cdd6b354cc86b8689579a3612a6db2331778e'),
  ('kaname._authority_metadata_mirror_ordinary_root_v1(text,text,jsonb,jsonb,integer,integer,integer)','ff14596e44ce2b5e14045d3a5785de0685fa6bedea193234471fe5cfa4f194d4')
 ) AS x(signature,digest) LOOP
  IF NOT EXISTS(SELECT FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure(pin.signature)
   AND p.proowner=current_user::regrole AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=pin.digest) THEN
   RAISE EXCEPTION 'ordinary mirror function missing or changed: %',pin.signature;
  END IF;
 END LOOP;
END;
$pins$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_metadata_mirror_ordinary_root_v1(text,text,jsonb,jsonb,integer,integer,integer);
DROP FUNCTION kaname.authority_metadata_mirror_ordinary_identity_v1(text,text);
