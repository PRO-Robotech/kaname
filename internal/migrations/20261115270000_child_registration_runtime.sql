-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1045: узкий вход исполнителя Kaname в закрытое тело регистрации.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd

-- Runtime Kaname проверяет пользователя на текущем DecisionAt перед входом.
-- SQL сохраняет снимок, точный шаг и обязательный commit; ключи клиента и
-- произвольные образы записи здесь не принимаются.
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_child_registration_begin_body_v1(p_intent jsonb) RETURNS jsonb
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT kaname._authority_child_registration_begin_body_v1(p_intent);
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_child_registration_step_v1(p_ordinal integer) RETURNS jsonb
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT kaname._authority_child_registration_step_v1(p_ordinal);
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_child_registration_complete_v1() RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT kaname._authority_child_registration_complete_v1();
$$;
-- +goose StatementEnd

-- Закрытие связывается с текущей версией зарегистрированного родителя.
-- Общий авторитет модуля проверяется по удержанным установке и факту fga_writer.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_child_parent_close_prepare_v1(p_envelope jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 proof jsonb; intent jsonb; parent_row jsonb; index_value jsonb; scopes jsonb; accounts jsonb;
 required jsonb; predicate jsonb; policy jsonb; native_epochs jsonb; mirror jsonb;
 parent_type text; parent_model text; parent_id text; module_value text; parent_key text;
 version_value timestamptz; captured_state jsonb; incarnation uuid; relation_id oid;
 locks jsonb; relations jsonb; authority_result record; bundle_result record;
 catalog_result record; epoch_result record; current_result record; audit_result record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 proof:=kaname.authority_protocol_attestation();
 intent:=p_envelope->'intent';
 parent_type:=intent->>'resource_type';
 parent_id:=intent->>'resource_id';
 IF proof->>'writer_contract' IS DISTINCT FROM '2'
  OR proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'purpose' IS DISTINCT FROM 'participant'
  OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_source_pending'
  OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_finalized' IS DISTINCT FROM 'false'
  OR current_setting('transaction_isolation')<>'read committed'
  OR to_regclass('pg_temp.kaname_authority_resource_manifest') IS NOT NULL
  OR p_envelope->>'abi' IS DISTINCT FROM '2'
  OR intent->>'kind' IS DISTINCT FROM 'child_parent_close'
  OR intent-ARRAY['kind','resource_type','resource_id','source_version','actor','audit_id']<>'{}'::jsonb
  OR jsonb_typeof(intent->'resource_type') IS DISTINCT FROM 'string'
  OR jsonb_typeof(intent->'resource_id') IS DISTINCT FROM 'string'
  OR jsonb_typeof(intent->'source_version') IS DISTINCT FROM 'string'
  OR coalesce(parent_type,'')='' OR coalesce(parent_id,'')=''
  OR octet_length(parent_type)+1+octet_length(parent_id)>512
  OR parent_type ~ '[[:space:][:cntrl:]:#*]' OR parent_id ~ '[[:space:][:cntrl:]:#*]'
  OR intent->'actor' IS DISTINCT FROM p_envelope->'actor'
  OR coalesce(intent->>'audit_id','') !~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$'
  OR p_envelope ?| ARRAY['object_effects','registration_effects','refusal_effects']
  OR coalesce(nullif(p_envelope->'source_effects','null'::jsonb),'[]'::jsonb)<>'[]'::jsonb THEN
  RAISE EXCEPTION 'child parent close requires an exact pending full participant' USING ERRCODE='42501';
 END IF;
 version_value:=(intent->>'source_version')::timestamptz;
 IF NOT isfinite(version_value) THEN
  RAISE EXCEPTION 'child parent close source version must be finite' USING ERRCODE='42501';
 END IF;
 SELECT * INTO STRICT bundle_result FROM kaname._authority_resource_bundle_catalog_v2(p_rows,p_reads);
 logical_rows:=bundle_result.logical_rows;
 logical_reads:=bundle_result.logical_reads;
 SELECT * INTO STRICT catalog_result FROM kaname._authority_resource_catalog_wait_v2(
  p_envelope->'catalogs',p_rows-logical_rows,p_reads-logical_reads);
 logical_rows:=logical_rows+catalog_result.logical_rows;
 logical_reads:=logical_reads+catalog_result.logical_reads;
 SELECT (item->>'state')::jsonb->2 INTO parent_row FROM jsonb_array_elements(catalog_result.catalog_rows) item
 WHERE item->>'dotted'=parent_type AND ((item->>'state')::jsonb #>'{2,live}')='true'::jsonb;
 parent_model:=parent_row->>'object_type';
 module_value:=parent_row->>'module';
 IF parent_model IS NULL OR NOT EXISTS(
  SELECT 1 FROM jsonb_array_elements(coalesce(nullif(bundle_result.catalog#>'{Live,Resources}','null'::jsonb),'[]'::jsonb)) p
  WHERE p->>'ObjectType'=parent_model AND p->>'Module'=module_value
   AND (p->>'Module')||'.'||(p->>'Resource')=parent_type
 ) OR NOT EXISTS(
  SELECT 1 FROM jsonb_array_elements(catalog_result.catalog_rows) item
  CROSS JOIN LATERAL (SELECT (item->>'state')::jsonb->2 AS image) c
  CROSS JOIN LATERAL jsonb_array_elements_text(c.image->'parent_names') WITH ORDINALITY edge(name,n)
  JOIN LATERAL jsonb_array_elements(coalesce(nullif(bundle_result.catalog#>'{Live,Resources}','null'::jsonb),'[]'::jsonb)) b
   ON b->>'ObjectType'=c.image->>'object_type' AND b->>'Module'=module_value
  WHERE c.image->>'module'=module_value AND c.image->'live'='true'::jsonb
   AND (b->>'Module')||'.'||(b->>'Resource')=c.image->>'dotted'
   AND jsonb_typeof(b->'ChildRegistration')='object' AND b->'ChildRegistration'=c.image->'child_registration'
   AND edge.name='parent' AND c.image->'parent_types'->>((edge.n-1)::integer)=parent_model
   AND b->'ParentNames'->>((edge.n-1)::integer)='parent' AND b->'ParentTypes'->>((edge.n-1)::integer)=parent_model
 ) THEN
  RAISE EXCEPTION 'child parent close requires an active parent policy' USING ERRCODE='42501';
 END IF;
 index_value:=kaname._authority_resource_capture_index_v2(p_envelope->'sources',100000);
 parent_key:=jsonb_build_array(2,parent_type,parent_id,'')::text;
 mirror:=kaname._authority_resource_require_capture_v2(index_value,2,parent_type,parent_id)->'states';
 IF jsonb_array_length(mirror)<>1 OR (mirror#>>'{0,2,source_version}')::timestamptz IS DISTINCT FROM version_value THEN
  RAISE EXCEPTION 'child parent close snapshot version differs' USING ERRCODE='P1034';
 END IF;
 scopes:=kaname._authority_resource_registration_saved_scopes_v2(index_value,bundle_result.catalog,parent_model,parent_id);
 SELECT jsonb_object_agg(scope->>'AccountID',true) INTO accounts FROM jsonb_array_elements(scopes->'scopes') scope;
 IF accounts IS NULL THEN RAISE EXCEPTION 'child parent close ownership unavailable' USING ERRCODE='42501';END IF;
 required:=(scopes->'required')||jsonb_build_object(parent_key,true);
 predicate:=kaname._authority_resource_predicate_maximum_v2(index_value,required);
 IF (proof->>'mode'='global') IS DISTINCT FROM (predicate->>'global')::boolean OR
  (proof->>'mode'='accounts' AND proof->'accounts' IS DISTINCT FROM
   (SELECT jsonb_agg(k ORDER BY k COLLATE "C") FROM jsonb_object_keys(accounts) k)) THEN
  RAISE EXCEPTION 'child parent close scope fence differs' USING ERRCODE='P1034';
 END IF;
 SELECT jsonb_object_agg(k,'share') INTO policy FROM jsonb_array_elements_text(p_envelope->'native_guards') k;
 policy:=coalesce(policy,'{}'::jsonb)||(predicate->'policy_epochs')
  ||jsonb_build_object('object:'||jsonb_build_array(parent_type,parent_id)::text,'write');
 SELECT * INTO STRICT epoch_result FROM kaname._authority_resource_epoch_wait_v2(
  '{}'::jsonb,policy,'{}'::jsonb,p_rows-logical_rows,p_reads-logical_reads);
 logical_rows:=logical_rows+epoch_result.logical_rows;
 logical_reads:=logical_reads+epoch_result.logical_reads;
 SELECT * INTO STRICT current_result FROM kaname._authority_resource_required_reread_v2(
  index_value,required,'{}'::jsonb,p_rows-logical_rows,p_reads-logical_reads);
 logical_rows:=logical_rows+current_result.logical_rows;
 logical_reads:=logical_reads+current_result.logical_reads;
 IF current_result.predicate_protections IS DISTINCT FROM predicate->'protections' THEN
  RAISE EXCEPTION 'child parent close predicates changed' USING ERRCODE='P1034';
 END IF;
 SELECT * INTO STRICT authority_result FROM kaname._authority_resource_registration_authority_wait_v2(
  p_envelope,jsonb_build_object('module',module_value,'registration_accounts',accounts),
  bundle_result.model_source,epoch_result.lock_witness,p_rows-logical_rows,p_reads-logical_reads);
 logical_rows:=logical_rows+authority_result.logical_rows;
 logical_reads:=logical_reads+authority_result.logical_reads;
 IF logical_rows+1>p_rows OR logical_reads+2>p_reads THEN
  RAISE EXCEPTION 'child parent close state exceeds budget' USING ERRCODE='54000';
 END IF;
 -- Общий object WRITE защищает также отсутствие строки у открытого родителя.
 -- FK на mirror уже удерживается через перечитанный parent source.
 LOCK TABLE ONLY kaname.authority_child_parent_state IN ROW EXCLUSIVE MODE;
 SELECT to_jsonb(p) INTO captured_state FROM ONLY kaname.authority_child_parent_state p
  WHERE p.object_type=parent_type AND p.object_id=parent_id FOR UPDATE OF p;
 logical_rows:=logical_rows+1;
 logical_reads:=logical_reads+2;
 incarnation:=coalesce((captured_state->>'incarnation')::uuid,gen_random_uuid());
 relations:=jsonb_build_array(jsonb_build_object(
  'oid','kaname.authority_child_parent_state'::regclass::oid,'mode','RowExclusiveLock'));
 locks:=epoch_result.lock_witness->'held_advisory';
 IF captured_state->>'closed_at' IS NULL THEN
  SELECT * INTO STRICT audit_result FROM kaname._authority_resource_audit_wait_v2(
   jsonb_build_object(intent->>'audit_id',true),p_rows-logical_rows,p_reads-logical_reads);
  logical_reads:=logical_reads+audit_result.logical_reads;
  locks:=locks||audit_result.lock_witness;
  relations:=relations||jsonb_build_array(jsonb_build_object(
   'oid','kaname.audit_outbox'::regclass::oid,'mode','RowExclusiveLock'));
 END IF;
 SELECT jsonb_object_agg(k,epoch_result.lock_witness->'policy_after'->k) INTO native_epochs
 FROM jsonb_object_keys(authority_result.authority->'native_epochs') k;
 relation_id:=kaname._authority_resource_manifest_create_v2();
 INSERT INTO pg_temp.kaname_authority_resource_manifest(
  abi,backend,transaction_id,invoker_oid,nonce,model_id,catalog_id,projector_version,mode,consumer_profile,accounts,
  intent,state,transaction_at,held_relations,held_advisory,catalog_rows,native_epochs,
  epoch_write_keys,epoch_share_keys,source_guard_write_keys,source_guard_read_keys,binding_epoch_write_scopes,binding_epoch_share_scopes,
  deferred_carrier_roles,epoch_lock_witness,writes,object_certificate,object_effects,object_sources,object_audit_reservations,
  registration_authority,registration_body)
 VALUES(2,proof->>'backend',proof->>'transaction_id',(proof->>'invoker_oid')::oid,proof->>'nonce',
  proof->>'model_id',proof->>'catalog_id',proof->>'projector_version',proof->>'mode',proof->>'consumer_profile',proof->'accounts',
  intent,'prepared',transaction_timestamp(),relations||jsonb_build_array(jsonb_build_object('oid',relation_id,'mode','AccessExclusiveLock')),
  locks,catalog_result.catalog_rows,native_epochs,
  to_jsonb(ARRAY(SELECT key FROM jsonb_each_text(policy) WHERE value='write' ORDER BY key COLLATE "C")),
  to_jsonb(ARRAY(SELECT key FROM jsonb_each_text(policy) WHERE value='share' ORDER BY key COLLATE "C")),
  '[]','[]','[]','[]','[]',epoch_result.lock_witness,'[]','{}','{}','{}','{}',authority_result.authority,
  jsonb_build_object('parent_state',captured_state,'incarnation',incarnation,'module',module_value));
 PERFORM kaname._authority_resource_manifest_v2();
 RETURN NEXT;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_child_parent_close_apply_v1(p_intent jsonb) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 manifest jsonb; previous jsonb; audit_row jsonb; audits jsonb:='[]'; commands jsonb:='[]';
 closed timestamptz; at_time timestamptz; tx_at timestamptz; token uuid; tenant text;
BEGIN
 manifest:=kaname._authority_resource_manifest_v2();
 IF manifest->>'state' IS DISTINCT FROM 'final' OR manifest->'intent'->>'kind' IS DISTINCT FROM 'child_parent_close'
  OR p_intent IS DISTINCT FROM manifest->'intent' OR manifest->'writes' IS DISTINCT FROM '[]'::jsonb THEN
  RAISE EXCEPTION 'child parent close requires its final private manifest' USING ERRCODE='42501';
 END IF;
 previous:=manifest#>'{registration_body,parent_state}';
 token:=(manifest#>>'{registration_body,incarnation}')::uuid;
 at_time:=(manifest->>'decision_at')::timestamptz;
 tx_at:=(manifest->>'transaction_at')::timestamptz;
 closed:=(previous->>'closed_at')::timestamptz;
 IF token IS NULL OR at_time IS NULL OR tx_at IS NULL OR closed>at_time THEN
  RAISE EXCEPTION 'child parent close prepared state invalid' USING ERRCODE='42501';
 END IF;
 IF closed IS NULL THEN
  SELECT CASE WHEN count(*)=1 THEN min(k) END INTO tenant
   FROM jsonb_object_keys(manifest#>'{registration_authority,accounts}') k;
  audit_row:=jsonb_build_object('id',p_intent->>'audit_id','event_type','iam.resource_registration.parent_closed',
   'tenant_account_id',tenant,'event_payload',jsonb_build_object(
    'actor','service_account:'||(p_intent->>'actor'),'module',manifest#>>'{registration_body,module}',
    'object',jsonb_build_object('type',p_intent->>'resource_type','id',p_intent->>'resource_id'),
    'source_version',p_intent->'source_version','closed_at',at_time,'outcome','closed'),
   'status','pending','attempts',0,'created_at',tx_at,'next_attempt_at',tx_at,'sent_at',NULL,'last_error',NULL);
  audits:=jsonb_build_array(jsonb_build_object('command',1,'row',audit_row));
  commands:='[{"kind":"close_parent_audit","operations":{"audit_outbox":["INSERT"]}}]';
 END IF;
 UPDATE pg_temp.kaname_authority_resource_manifest SET state='body',registration_program_claimed=true,
  object_command=jsonb_array_length(commands),registration_program=jsonb_build_object('commands',commands),
  registration_physical=jsonb_build_object('audits',audits,'outboxes','[]'::jsonb,'bindings','[]'::jsonb,
   'reconcile','[]'::jsonb,'subject_changes','[]'::jsonb);
 IF closed IS NULL THEN
  IF previous='null'::jsonb THEN
   INSERT INTO kaname.authority_child_parent_state(object_type,object_id,incarnation,closed_at)
   VALUES(p_intent->>'resource_type',p_intent->>'resource_id',token,at_time);
  ELSE
   UPDATE ONLY kaname.authority_child_parent_state
   SET closed_at=at_time WHERE object_type=p_intent->>'resource_type' AND object_id=p_intent->>'resource_id'
     AND incarnation=token AND closed_at IS NULL;
   IF NOT FOUND THEN RAISE EXCEPTION 'child parent close state escaped prewait' USING ERRCODE='42501';END IF;
  END IF;
  INSERT INTO kaname.audit_outbox(id,event_type,tenant_account_id,event_payload,status,attempts,created_at,next_attempt_at)
  VALUES(audit_row->>'id',audit_row->>'event_type',tenant,audit_row->'event_payload','pending',0,tx_at,tx_at);
  closed:=at_time;
 END IF;
 UPDATE pg_temp.kaname_authority_resource_manifest
 SET registration_body=registration_body||'{"private_effects_done":true}'::jsonb;
 RETURN closed;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_child_runtime_storage_v1() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 WITH owner_role AS (
  SELECT relowner AS oid FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass
 ), approved AS (
  SELECT a.grantee FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a, owner_role o
  WHERE p.oid='kaname.authority_resource_source_enter_v3(text,text[],jsonb,text,text,text)'::regprocedure
   AND a.grantee NOT IN (0,o.oid) AND a.privilege_type='EXECUTE' AND NOT a.is_grantable
 ), expected(signature,digest,definer,volatility,language) AS (VALUES
  ('_authority_child_registration_capture_v1(text,text,integer,integer)','13726c6180cfc4c7c9bb7001f0363f06d64bad31035ed845821fb9fd2c8257dc',false,'s','plpgsql'),
  ('_authority_child_registration_recheck_v1(text,text,jsonb,jsonb,jsonb,integer,integer)','5472c35ce47f678131d75e938ceffafecef57c1fcf7630f8b3ae70f1349e1c82',false,'v','plpgsql'),
  ('_authority_child_registration_outcome_v1(jsonb,timestamptz)','868d3dcfd39cdbbcec87e550e8504472db5aa9cec700ed74ca50111f2db9a2fa',false,'s','plpgsql'),
  ('_authority_child_registration_sources_v1(jsonb,jsonb,jsonb,jsonb)','b9a7213485e415a32ad2d71f2b2a47c93b236e0617f2934dd76017e7c884e7be',false,'s','plpgsql'),
  ('_authority_child_registration_program_v1(jsonb,jsonb,jsonb,jsonb,text,text,timestamptz,timestamptz,uuid)','1cb416806c3d5123b4aacc5676e5cc58c9b7c7ab6eaf18d0b5be1b77686549b7',false,'s','plpgsql'),
  ('_authority_child_registration_maximum_v1(jsonb,jsonb,jsonb)','21f54ca5cea648271cde409fc8cab9175cf1cc69d712bd14395f9a32aa378ded',false,'s','plpgsql'),
  ('_authority_child_registration_hold_v1(jsonb,integer,integer)','546f11cf9b517b00d48c050df26637da333f7dc5016610738ac2081677a9c29b',false,'v','plpgsql'),
  ('_authority_child_registration_select_v1(jsonb,timestamptz)','1a6505db61eda4a1447c3e8c837604a308adb74387da25dc4f63e2428c53ccb3',false,'v','plpgsql'),
  ('_authority_child_registration_prepare_v1(jsonb,integer,integer)','d5f65b20fa5af6ea25a043ec99696c488f00521741413e833216e678608cb089',false,'v','plpgsql'),
  ('_authority_child_registration_finalize_v1(jsonb,integer,integer)','9007c266ff5ad31f8cf44cc94b0a1ba6529f8d02ba4ee54f6507e7b102076353',false,'v','plpgsql'),
  ('_authority_child_registration_begin_body_v1(jsonb)','23d1cf16c9baaafb585de00185a2c73dbcb72a6e0b59f6373fed171a838aa578',false,'v','plpgsql'),
  ('_authority_child_registration_step_done_v1(jsonb,integer)','9f7888e6001f38328963d17053bf6d7640688e0a16c09fb82cc10c7971f30586',false,'s','plpgsql'),
  ('_authority_child_registration_step_v1(integer)','2602fe97ef81b1a242b322c697e90b63d005dd30454010fa64abebb0387893eb',false,'v','plpgsql'),
  ('_authority_child_registration_complete_v1()','17686473c29efe97fb787cf2a1495997240719a5913a272404c9b87823f997bb',false,'v','plpgsql'),
  ('authority_child_registration_begin_body_v1(jsonb)','bf7b041190118779c428cbd9bb6a6be6fed8f840f5c571c54f057115343425f9',true,'v','sql'),
  ('authority_child_registration_step_v1(integer)','7ba85ac77d2ac21e1d2afa3ff50738d4547062f850490d20e3f9bf0b9ec7abbc',true,'v','sql'),
  ('_authority_child_parent_close_prepare_v1(jsonb,integer,integer)','305e9fc3c923435b9afb79b4b41fdde5a59f0f529dade4ac17df7ce55712d7d1',false,'v','plpgsql'),
  ('authority_child_parent_close_apply_v1(jsonb)','2f373544a8215634f5222896c93b74416c5c2e9718346553fc9107486d32e8cf',true,'v','plpgsql'),
  ('authority_child_registration_complete_v1()','4f44ebad4a5aea644f7180b9ae686edc411ef1c7f0262bd12ba6c1064fe5ac23',true,'v','sql')
 )
 SELECT EXISTS(SELECT 1 FROM owner_role o JOIN pg_catalog.pg_roles r ON r.oid=o.oid WHERE r.rolname=current_user)
 AND NOT EXISTS(
  SELECT 1 FROM expected e CROSS JOIN owner_role o
  LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||e.signature)
  LEFT JOIN pg_catalog.pg_language l ON l.oid=p.prolang
  WHERE (p.proowner=o.oid AND p.prosecdef=e.definer AND p.provolatile::text=e.volatility
   AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp'] AND l.lanname=e.language
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=e.digest) IS NOT TRUE
  OR EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   WHERE a.grantee<>o.oid AND (NOT e.definer OR a.is_grantable OR a.privilege_type<>'EXECUTE'
    OR NOT EXISTS(SELECT 1 FROM approved r WHERE r.grantee=a.grantee)))
  OR (e.definer AND EXISTS(SELECT 1 FROM approved r
   WHERE NOT EXISTS(SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee=r.grantee AND a.privilege_type='EXECUTE')))
 );
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_full_contract_storage_v3() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE owner_oid oid; target text;
BEGIN
 SELECT relowner INTO owner_oid FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass;
 IF owner_oid IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=to_regclass('kaname.authority_writer_contract') AND relowner=owner_oid AND relkind='r' AND relpersistence='p')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
  WHERE c.oid=to_regclass('kaname.authority_writer_contract') AND a.grantee<>owner_oid) THEN RETURN false; END IF;
 -- Хранилище инкарнаций и квитанций принадлежит только владельцу протокола.
 IF EXISTS(SELECT 1
  FROM unnest(ARRAY['authority_child_parent_state','authority_child_creation']) AS required(name)
  LEFT JOIN pg_catalog.pg_class c ON c.oid=to_regclass('kaname.'||required.name)
  WHERE c.oid IS NULL OR c.relowner IS DISTINCT FROM owner_oid OR c.relkind<>'r' OR c.relpersistence<>'p'
   OR EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee<>owner_oid)
   OR EXISTS(SELECT 1 FROM pg_catalog.pg_attribute col
    CROSS JOIN LATERAL aclexplode(col.attacl) a
    WHERE col.attrelid=c.oid AND col.attnum>0 AND NOT col.attisdropped AND a.grantee<>owner_oid)
 ) THEN RETURN false;END IF;
 FOR target IN SELECT unnest(kaname.authority_protocol_tables()) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=to_regclass('kaname.'||target)
   AND t.tgname='authority_protocol_statement' AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=62
   AND t.tgfoid='kaname.authority_protocol_statement_guard()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=to_regclass('kaname.'||target)
   AND t.tgname='authority_protocol_row' AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=31
   AND t.tgfoid='kaname.authority_protocol_row_guard()'::regprocedure) THEN RETURN false; END IF;
 END LOOP;
 -- Catalog invalidation is part of the full writer ABI: no early row close
 -- and no missed commit close. Check both pg_trigger and its constraint row.
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname._authority_protocol_catalog_changed_v3()'::regprocedure)<>6
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgfoid='kaname.authority_protocol_catalog_changed()'::regprocedure) THEN RETURN false; END IF;
 FOR target IN SELECT unnest(ARRAY['catalog_module','catalog_resource','catalog_verb']) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=to_regclass('kaname.'||target) AND c.relowner=owner_oid AND c.relkind='r' AND c.relpersistence='p') THEN RETURN false; END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_constraint c ON c.oid=t.tgconstraint
   WHERE t.tgrelid=to_regclass('kaname.'||target) AND t.tgname='authority_catalog_changed'
   AND t.tgfoid='kaname._authority_protocol_catalog_changed_v3()'::regprocedure
   AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=29
   AND t.tgdeferrable AND t.tginitdeferred AND t.tgnargs=0 AND t.tgqual IS NULL AND t.tgattr=''::int2vector
   AND c.contype='t' AND c.conname='authority_catalog_changed' AND c.conrelid=t.tgrelid AND c.condeferrable AND c.condeferred)
  OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t
   WHERE t.tgrelid=to_regclass('kaname.'||target) AND t.tgname='authority_catalog_truncated'
   AND t.tgfoid='kaname._authority_protocol_catalog_changed_v3()'::regprocedure
   AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=32 AND t.tgconstraint=0
   AND NOT t.tgdeferrable AND NOT t.tginitdeferred AND t.tgnargs=0 AND t.tgqual IS NULL)
  THEN RETURN false; END IF;
 END LOOP;
 -- Публичен только void-вход. PUBLIC, grant option и посторонний executor
 -- не являются частью approved runtime profile.
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid='kaname.authority_role_prelock_admit_v3()'::regprocedure
  AND a.grantee<>owner_oid AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE'
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc e
    CROSS JOIN LATERAL aclexplode(coalesce(e.proacl,acldefault('f',e.proowner))) g
    WHERE e.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure
    AND g.grantee=a.grantee AND g.privilege_type='EXECUTE')))
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname.authority_role_prelock_admit_v3()'::regprocedure
  AND p.prorettype='void'::regtype AND p.provolatile='v'
  AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']) THEN RETURN false; END IF;
 -- Общий cutoff backstop принадлежит владельцу и действует на все INSERT/UPDATE.
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid='kaname.minted_token_revocations'::regclass
  AND relowner=owner_oid AND relkind='r' AND relpersistence='p')
 OR (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname._authority_minted_cutoff_order_v3()'::regprocedure)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid='kaname.minted_token_revocations'::regclass
  AND tgname='authority_minted_cutoff_order_v3' AND tgfoid='kaname._authority_minted_cutoff_order_v3()'::regprocedure
  AND tgenabled='O' AND NOT tgisinternal AND tgtype::integer=23 AND tgnargs=0 AND tgqual IS NULL
  AND tgattr=''::int2vector AND tgconstraint=0 AND NOT tgdeferrable AND NOT tginitdeferred)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid='kaname.authority_sa_state_preflight_v3(text,boolean,text)'::regprocedure AND a.grantee<>owner_oid
  AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR NOT EXISTS(
   SELECT 1 FROM pg_catalog.pg_proc e CROSS JOIN LATERAL aclexplode(e.proacl) g
   WHERE e.oid='kaname.authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)'::regprocedure
   AND g.grantee=a.grantee AND g.privilege_type='EXECUTE'))) THEN RETURN false; END IF;
 -- Публичен только void-вход. PUBLIC, grant option и посторонний executor
 -- не являются частью approved runtime profile.
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid='kaname.authority_parent_prelock_admit_v3()'::regprocedure
  AND a.grantee<>owner_oid AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE'
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc e
    CROSS JOIN LATERAL aclexplode(coalesce(e.proacl,acldefault('f',e.proowner))) g
    WHERE e.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure
    AND g.grantee=a.grantee AND g.privilege_type='EXECUTE')))
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname.authority_parent_prelock_admit_v3()'::regprocedure
  AND p.prorettype='void'::regtype AND p.provolatile='v'
  AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']) THEN RETURN false; END IF;
 -- Один SQL-запрос на все отпечатки; ACL читается только после совпадения
 -- тела и параметров приватной функции.
 IF EXISTS(SELECT 1 FROM (VALUES
 ('_authority_child_runtime_storage_v1()','7ac364c7e27045f5dcfabafbac9f3394b3c646cb54c514509db656fc5c2b32af',true),
 ('_authority_crud_storage_v3()','36bd005f8ee097ce2f71fb396bed20e968aa1c3f9f0baab4554e932e251a9a64',true),
 ('authority_parent_prelock_admit_v3()','0a5d8d81822501af40183c78d52e8897d3bf8583e8b888589a64951a88139247',true),
 ('_authority_minted_cutoff_key_v3(text)','e070405bfea920fb884831cd02890bd90810a65f4d617a828b1af9ea48542623',true),
 ('_authority_minted_cutoff_order_v3()','d911640bce1f00a365213aa03845461e4d6f479ca564e40745b810ad2976dd29',true),
 ('authority_sa_state_preflight_v3(text,boolean,text)','980a05e9e1dc6973b93ba6694ea376a70efaa22a4639e5b762b425b81dbad3f7',true),
 ('authority_role_prelock_admit_v3()','0a5d8d81822501af40183c78d52e8897d3bf8583e8b888589a64951a88139247',true),
 ('_authority_protocol_catalog_changed_v3()','974332f1dc2c6f42d12d35c49c89c201ac5deecf153f46070746ca0fcef6fbbb',true),
 ('authority_metadata_preflight_v3(text,text,boolean,text)','ea89b06dc47ce62579a99026522c1d8dd4c0edc585922c71ca77c9ea11b07ed3',true),
 ('_authority_protocol_enter_contract_v3(text,text[],jsonb,text,text,text,text,integer,text,integer)','1eae08ffff7b4eb936b224dfa08ed3e49679e968033a8e823e0bd3ef6d9786cf',true),
 ('_authority_consumer_enter_contract_v3(text,text[],jsonb,text,text,text,text,text,text,jsonb,integer)','7109bc396aeecee56a015a868826ebcf88bc15a050fceacf033b73971ff50aca',true),
 ('_authority_protocol_enter_v1_body(text,text[],jsonb,text,text,text,text,integer,text)','e71e29754a20d3a18054206600cf26cc6c234f26e798a41d9430177f612d68e4',true),
 ('_authority_protocol_enter_v2(text,text[],jsonb,text,text,text,text,text,text,jsonb)','e4a1ca86b280c64e7c9b5a54bbfb1e4152f59732f40c7f0748a5bb1a86fb77b1',true),
 ('_authority_protocol_attestation_v1_body()','2c6a618c91d3b7fff8a5e23734d8d7815d6c38cb9b82adacd2e472202584fc54',true),
 ('authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)','86ecf97ccb3cd5599f434955609fb3f1335dd82231f881deb510638981c8ec7a',true),
 ('authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)','33c57c5d0b23128b4fa5e694f4863073e7b6bcce4789c3cd98953285a991f1ea',true),
 ('authority_resource_enter_v3(text,text[],jsonb,text,text,text)','8e54f4da31fab3d4706a58039ea84de5ee88c8c258f92f73c65b7e098aebcc2d',true),
 ('authority_resource_source_enter_v3(text,text[],jsonb,text,text,text)','26f28ff899f445a4b2ca54c2d4ea4ac285fb0bf928082475fc862b1d6bddbd6a',true),
 ('authority_installation_enter_v3(text,text,text,text)','c9d988aa2dfb5851a95037d88ab9847da36ec8154507487bc962cc1b3c1f5b44',true),
 ('authority_full_contract_validate_v3(text,text,text)','25bfc4bd59d30c59e9246889a4279e1326b0ecbb5940b220fd52490a8777d1ea',true),
 ('authority_staged_contract_validate_v3()','0438c79b89809642700ab1d12a3dee84f8a0432c3b33589d47d16e8d9ce885b8',true),
 ('authority_protocol_stage_full_v3(text,bytea,text,text,text)','1f7a9c17af7a4c3ec041405fa9f0dddc69cdf3fa666ba72db47247cde8447037',false),
 ('authority_protocol_activate_full_v3(text,text,text)','646328a2433e1d31d17a9c178ac3ab59a5a65d8252accf5295a20d22705d31cf',false),
 ('authority_protocol_attestation()','130a504f7da2b6780cd4e91a2c7103f9fabe765541f0f2611f900ce679ddd502',true),
 ('authority_protocol_statement_guard()','7608e2d0a1b1ce2bb11182a349150e5369e2bd97c5fb8abc3da84b3d2e0c229a',true),
 ('authority_protocol_row_guard()','cb90a95df9b7105f053ae0c8652407335ef82745a2e749dc395b1c82e8435d12',true),
 ('_authority_protocol_stage_generation1(text,bytea,text,text,text)','7ffb942af742bff4b556f07b00d9d8f75fefba3aa1f00445073140b5c8072bde',false),
 ('_authority_protocol_activate_generation1(text,text,text)','00d97c37e2ab533c232e4cffb975e8d71c3eefa98228e0f39d90249526bf041c',false),
 ('authority_protocol_drain()','f0e36bb29e96ba0417e9143821391b9df518541a017dcd9b171c037e167bc500',false),
 ('authority_protocol_require_drain()','61686507d75a6352d1f0fd97c9e3886c5c361af00778bdf3513693ee2dd6468b',false)
 ) AS pinned(signature,digest,definer)
 LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||pinned.signature)
 WHERE CASE
  WHEN (p.proowner=owner_oid AND p.prosecdef=pinned.definer
   AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=pinned.digest) IS NOT TRUE THEN true
  WHEN left(pinned.signature,1)='_' THEN
   EXISTS(SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee<>owner_oid)
  ELSE false
 END) THEN RETURN false; END IF;
 RETURN kaname._authority_crud_storage_v3() AND kaname._authority_child_runtime_storage_v1();
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$ DECLARE signature text; owner_oid oid; principal record; BEGIN
 SELECT relowner INTO STRICT owner_oid FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass;
 FOREACH signature IN ARRAY ARRAY[
   'authority_child_registration_begin_body_v1(jsonb)',
   'authority_child_registration_step_v1(integer)',
   'authority_child_registration_complete_v1()',
   'authority_child_parent_close_apply_v1(jsonb)',
   '_authority_child_parent_close_prepare_v1(jsonb,integer,integer)',
   '_authority_child_runtime_storage_v1()'
 ] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',signature);
  FOR principal IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE p.oid=to_regprocedure('kaname.'||signature) AND a.grantee<>owner_oid LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM %I',signature,principal.rolname);
  END LOOP;
  IF left(signature,1)='_' THEN CONTINUE;END IF;
  -- Обновляем только уже допущенных участников подписанной resource-транзакции.
  FOR principal IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE p.oid='kaname.authority_resource_source_enter_v3(text,text[],jsonb,text,text,text)'::regprocedure
    AND a.grantee<>owner_oid AND a.privilege_type='EXECUTE' AND NOT a.is_grantable LOOP
   EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.%s TO %I',signature,principal.rolname);
  END LOOP;
 END LOOP;
 IF NOT kaname._authority_full_contract_storage_v3() THEN
  RAISE EXCEPTION 'child registration runtime closure incomplete' USING ERRCODE='55000';
 END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 PERFORM kaname.authority_protocol_drain();
 IF EXISTS(SELECT 1 FROM kaname.authority_writer_contract WHERE required_contract=2) THEN
  RAISE EXCEPTION 'cannot remove active child registration runtime' USING ERRCODE='P1036';
 END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_full_contract_storage_v3() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE owner_oid oid; target text;
BEGIN
 SELECT relowner INTO owner_oid FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass;
 IF owner_oid IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=to_regclass('kaname.authority_writer_contract') AND relowner=owner_oid AND relkind='r' AND relpersistence='p')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
  WHERE c.oid=to_regclass('kaname.authority_writer_contract') AND a.grantee<>owner_oid) THEN RETURN false; END IF;
 -- Хранилище инкарнаций и квитанций принадлежит только владельцу протокола.
 IF EXISTS(SELECT 1
  FROM unnest(ARRAY['authority_child_parent_state','authority_child_creation']) AS required(name)
  LEFT JOIN pg_catalog.pg_class c ON c.oid=to_regclass('kaname.'||required.name)
  WHERE c.oid IS NULL OR c.relowner IS DISTINCT FROM owner_oid OR c.relkind<>'r' OR c.relpersistence<>'p'
   OR EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee<>owner_oid)
   OR EXISTS(SELECT 1 FROM pg_catalog.pg_attribute col
    CROSS JOIN LATERAL aclexplode(col.attacl) a
    WHERE col.attrelid=c.oid AND col.attnum>0 AND NOT col.attisdropped AND a.grantee<>owner_oid)
 ) THEN RETURN false;END IF;
 FOR target IN SELECT unnest(kaname.authority_protocol_tables()) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=to_regclass('kaname.'||target)
   AND t.tgname='authority_protocol_statement' AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=62
   AND t.tgfoid='kaname.authority_protocol_statement_guard()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=to_regclass('kaname.'||target)
   AND t.tgname='authority_protocol_row' AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=31
   AND t.tgfoid='kaname.authority_protocol_row_guard()'::regprocedure) THEN RETURN false; END IF;
 END LOOP;
 -- Catalog invalidation is part of the full writer ABI: no early row close
 -- and no missed commit close. Check both pg_trigger and its constraint row.
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname._authority_protocol_catalog_changed_v3()'::regprocedure)<>6
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgfoid='kaname.authority_protocol_catalog_changed()'::regprocedure) THEN RETURN false; END IF;
 FOR target IN SELECT unnest(ARRAY['catalog_module','catalog_resource','catalog_verb']) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=to_regclass('kaname.'||target) AND c.relowner=owner_oid AND c.relkind='r' AND c.relpersistence='p') THEN RETURN false; END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_constraint c ON c.oid=t.tgconstraint
   WHERE t.tgrelid=to_regclass('kaname.'||target) AND t.tgname='authority_catalog_changed'
   AND t.tgfoid='kaname._authority_protocol_catalog_changed_v3()'::regprocedure
   AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=29
   AND t.tgdeferrable AND t.tginitdeferred AND t.tgnargs=0 AND t.tgqual IS NULL AND t.tgattr=''::int2vector
   AND c.contype='t' AND c.conname='authority_catalog_changed' AND c.conrelid=t.tgrelid AND c.condeferrable AND c.condeferred)
  OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t
   WHERE t.tgrelid=to_regclass('kaname.'||target) AND t.tgname='authority_catalog_truncated'
   AND t.tgfoid='kaname._authority_protocol_catalog_changed_v3()'::regprocedure
   AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=32 AND t.tgconstraint=0
   AND NOT t.tgdeferrable AND NOT t.tginitdeferred AND t.tgnargs=0 AND t.tgqual IS NULL)
  THEN RETURN false; END IF;
 END LOOP;
 -- Публичен только void-вход. PUBLIC, grant option и посторонний executor
 -- не являются частью approved runtime profile.
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid='kaname.authority_role_prelock_admit_v3()'::regprocedure
  AND a.grantee<>owner_oid AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE'
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc e
    CROSS JOIN LATERAL aclexplode(coalesce(e.proacl,acldefault('f',e.proowner))) g
    WHERE e.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure
    AND g.grantee=a.grantee AND g.privilege_type='EXECUTE')))
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname.authority_role_prelock_admit_v3()'::regprocedure
  AND p.prorettype='void'::regtype AND p.provolatile='v'
  AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']) THEN RETURN false; END IF;
 -- Общий cutoff backstop принадлежит владельцу и действует на все INSERT/UPDATE.
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid='kaname.minted_token_revocations'::regclass
  AND relowner=owner_oid AND relkind='r' AND relpersistence='p')
 OR (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname._authority_minted_cutoff_order_v3()'::regprocedure)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid='kaname.minted_token_revocations'::regclass
  AND tgname='authority_minted_cutoff_order_v3' AND tgfoid='kaname._authority_minted_cutoff_order_v3()'::regprocedure
  AND tgenabled='O' AND NOT tgisinternal AND tgtype::integer=23 AND tgnargs=0 AND tgqual IS NULL
  AND tgattr=''::int2vector AND tgconstraint=0 AND NOT tgdeferrable AND NOT tginitdeferred)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid='kaname.authority_sa_state_preflight_v3(text,boolean,text)'::regprocedure AND a.grantee<>owner_oid
  AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR NOT EXISTS(
   SELECT 1 FROM pg_catalog.pg_proc e CROSS JOIN LATERAL aclexplode(e.proacl) g
   WHERE e.oid='kaname.authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)'::regprocedure
   AND g.grantee=a.grantee AND g.privilege_type='EXECUTE'))) THEN RETURN false; END IF;
 -- Публичен только void-вход. PUBLIC, grant option и посторонний executor
 -- не являются частью approved runtime profile.
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid='kaname.authority_parent_prelock_admit_v3()'::regprocedure
  AND a.grantee<>owner_oid AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE'
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc e
    CROSS JOIN LATERAL aclexplode(coalesce(e.proacl,acldefault('f',e.proowner))) g
    WHERE e.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure
    AND g.grantee=a.grantee AND g.privilege_type='EXECUTE')))
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname.authority_parent_prelock_admit_v3()'::regprocedure
  AND p.prorettype='void'::regtype AND p.provolatile='v'
  AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']) THEN RETURN false; END IF;
 -- Один SQL-запрос на все отпечатки; ACL читается только после совпадения
 -- тела и параметров приватной функции.
 IF EXISTS(SELECT 1 FROM (VALUES
 ('_authority_crud_storage_v3()','36bd005f8ee097ce2f71fb396bed20e968aa1c3f9f0baab4554e932e251a9a64',true),
 ('authority_parent_prelock_admit_v3()','0a5d8d81822501af40183c78d52e8897d3bf8583e8b888589a64951a88139247',true),
 ('_authority_minted_cutoff_key_v3(text)','e070405bfea920fb884831cd02890bd90810a65f4d617a828b1af9ea48542623',true),
 ('_authority_minted_cutoff_order_v3()','d911640bce1f00a365213aa03845461e4d6f479ca564e40745b810ad2976dd29',true),
 ('authority_sa_state_preflight_v3(text,boolean,text)','980a05e9e1dc6973b93ba6694ea376a70efaa22a4639e5b762b425b81dbad3f7',true),
 ('authority_role_prelock_admit_v3()','0a5d8d81822501af40183c78d52e8897d3bf8583e8b888589a64951a88139247',true),
 ('_authority_protocol_catalog_changed_v3()','974332f1dc2c6f42d12d35c49c89c201ac5deecf153f46070746ca0fcef6fbbb',true),
 ('authority_metadata_preflight_v3(text,text,boolean,text)','ea89b06dc47ce62579a99026522c1d8dd4c0edc585922c71ca77c9ea11b07ed3',true),
 ('_authority_protocol_enter_contract_v3(text,text[],jsonb,text,text,text,text,integer,text,integer)','1eae08ffff7b4eb936b224dfa08ed3e49679e968033a8e823e0bd3ef6d9786cf',true),
 ('_authority_consumer_enter_contract_v3(text,text[],jsonb,text,text,text,text,text,text,jsonb,integer)','7109bc396aeecee56a015a868826ebcf88bc15a050fceacf033b73971ff50aca',true),
 ('_authority_protocol_enter_v1_body(text,text[],jsonb,text,text,text,text,integer,text)','e71e29754a20d3a18054206600cf26cc6c234f26e798a41d9430177f612d68e4',true),
 ('_authority_protocol_enter_v2(text,text[],jsonb,text,text,text,text,text,text,jsonb)','e4a1ca86b280c64e7c9b5a54bbfb1e4152f59732f40c7f0748a5bb1a86fb77b1',true),
 ('_authority_protocol_attestation_v1_body()','2c6a618c91d3b7fff8a5e23734d8d7815d6c38cb9b82adacd2e472202584fc54',true),
 ('authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)','86ecf97ccb3cd5599f434955609fb3f1335dd82231f881deb510638981c8ec7a',true),
 ('authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)','33c57c5d0b23128b4fa5e694f4863073e7b6bcce4789c3cd98953285a991f1ea',true),
 ('authority_resource_enter_v3(text,text[],jsonb,text,text,text)','8e54f4da31fab3d4706a58039ea84de5ee88c8c258f92f73c65b7e098aebcc2d',true),
 ('authority_resource_source_enter_v3(text,text[],jsonb,text,text,text)','26f28ff899f445a4b2ca54c2d4ea4ac285fb0bf928082475fc862b1d6bddbd6a',true),
 ('authority_installation_enter_v3(text,text,text,text)','c9d988aa2dfb5851a95037d88ab9847da36ec8154507487bc962cc1b3c1f5b44',true),
 ('authority_full_contract_validate_v3(text,text,text)','25bfc4bd59d30c59e9246889a4279e1326b0ecbb5940b220fd52490a8777d1ea',true),
 ('authority_staged_contract_validate_v3()','0438c79b89809642700ab1d12a3dee84f8a0432c3b33589d47d16e8d9ce885b8',true),
 ('authority_protocol_stage_full_v3(text,bytea,text,text,text)','1f7a9c17af7a4c3ec041405fa9f0dddc69cdf3fa666ba72db47247cde8447037',false),
 ('authority_protocol_activate_full_v3(text,text,text)','646328a2433e1d31d17a9c178ac3ab59a5a65d8252accf5295a20d22705d31cf',false),
 ('authority_protocol_attestation()','130a504f7da2b6780cd4e91a2c7103f9fabe765541f0f2611f900ce679ddd502',true),
 ('authority_protocol_statement_guard()','7608e2d0a1b1ce2bb11182a349150e5369e2bd97c5fb8abc3da84b3d2e0c229a',true),
 ('authority_protocol_row_guard()','cb90a95df9b7105f053ae0c8652407335ef82745a2e749dc395b1c82e8435d12',true),
 ('_authority_protocol_stage_generation1(text,bytea,text,text,text)','7ffb942af742bff4b556f07b00d9d8f75fefba3aa1f00445073140b5c8072bde',false),
 ('_authority_protocol_activate_generation1(text,text,text)','00d97c37e2ab533c232e4cffb975e8d71c3eefa98228e0f39d90249526bf041c',false),
 ('authority_protocol_drain()','f0e36bb29e96ba0417e9143821391b9df518541a017dcd9b171c037e167bc500',false),
 ('authority_protocol_require_drain()','61686507d75a6352d1f0fd97c9e3886c5c361af00778bdf3513693ee2dd6468b',false)
 ) AS pinned(signature,digest,definer)
 LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||pinned.signature)
 WHERE CASE
  WHEN (p.proowner=owner_oid AND p.prosecdef=pinned.definer
   AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=pinned.digest) IS NOT TRUE THEN true
  WHEN left(pinned.signature,1)='_' THEN
   EXISTS(SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee<>owner_oid)
  ELSE false
 END) THEN RETURN false; END IF;
 RETURN kaname._authority_crud_storage_v3();
END $$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_child_runtime_storage_v1();
DROP FUNCTION kaname.authority_child_parent_close_apply_v1(jsonb);
DROP FUNCTION kaname._authority_child_parent_close_prepare_v1(jsonb,integer,integer);
DROP FUNCTION kaname.authority_child_registration_complete_v1();
DROP FUNCTION kaname.authority_child_registration_step_v1(integer);
DROP FUNCTION kaname.authority_child_registration_begin_body_v1(jsonb);
