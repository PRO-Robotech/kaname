-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_metadata_mirror_ordinary_discover_v1(
 p_dotted text,p_id text,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $discover$
DECLARE
 proof jsonb; replay_program jsonb; identity jsonb; model text; project_id text; account_id text; src text;
 rel regclass; invoker oid:=current_user::regrole; states jsonb; registration jsonb:='{}'; valid boolean;
 checked_sql text; lock_sql text:=''; held boolean; replay boolean:=false; used_rows integer:=24; used_reads integer:=24;
BEGIN
 IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads+7 AND 4096 THEN
  RAISE EXCEPTION 'ordinary discovery budget exhausted' USING ERRCODE='54000';END IF;
 held:=current_setting('transaction_isolation')='read committed';
 IF held THEN
  PERFORM kaname.authority_protocol_require_owner();
  proof:=kaname.authority_protocol_attestation();
  replay:=proof->>'consumer_finalized'='true';
  IF proof IS NULL OR coalesce(proof->>'consumer_finalized','') NOT IN ('true','false')
   OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'full'
   OR proof->>'kind' IS DISTINCT FROM 'resource'
   OR NOT coalesce((proof->>'writer_contract'='2' AND proof->>'purpose'='decision')
    OR (proof->>'writer_contract'='1' AND proof->>'purpose'='participant'),false) THEN
   RAISE EXCEPTION 'ordinary source hold requires pending signed metadata' USING ERRCODE='42501';END IF;
  invoker:=(proof->>'invoker_oid')::oid;
  IF replay THEN
   -- Без новых блокировок читаем только DONE-команду этой координаты.
   -- Общее чтение проверяет family, nonce, исходный LOGIN и выбранный clock.
   replay_program:=kaname._authority_metadata_mirror_ordinary_command_v1();
   IF replay_program IS NULL OR replay_program#>>'{frozen,phase}' IS DISTINCT FROM 'done'
    OR replay_program#>>'{frozen,ordinary_command,root,identity,dotted}' IS DISTINCT FROM p_dotted
    OR replay_program#>>'{frozen,ordinary_command,root,identity,id}' IS DISTINCT FROM p_id THEN
    RAISE EXCEPTION 'ordinary registration replay outside selected sequence' USING ERRCODE='42501';END IF;
  ELSE
   lock_sql:=' FOR SHARE OF r NOWAIT';
  -- В legacy/стандартном режиме authority_policy_changed для указателя ничего
  -- не меняет. Одна совместимая между читателями блокировка закрывает phantom.
   LOCK TABLE ONLY kaname.resource_registration_pointer IN SHARE MODE NOWAIT;
  END IF;
 ELSIF current_setting('transaction_isolation')<>'repeatable read' OR current_setting('transaction_read_only')<>'on' THEN
  RAISE EXCEPTION 'ordinary discovery requires a read-only RR snapshot' USING ERRCODE='42501';
 END IF;
 identity:=kaname.authority_metadata_mirror_ordinary_identity_v1(p_dotted,p_id);
 IF identity IS NULL THEN RAISE EXCEPTION 'ordinary resource identity absent' USING ERRCODE='40001';END IF;
 model:=identity#>>'{catalog,2,object_type}';project_id:=coalesce(identity#>>'{project,2,id}','');
 account_id:=identity#>>'{account,2,id}';
 FOREACH src IN ARRAY ARRAY['producer_source_receipt','public_read_publication','relation_fact',
  'resource_parent_edge','resource_registration_pointer','resource_registration_retirement','resource_registration_scope'] LOOP
  rel:=to_regclass('kaname.'||src);
  IF held AND NOT replay THEN EXECUTE format('LOCK TABLE ONLY kaname.%I IN ROW SHARE MODE NOWAIT',src);END IF;
  IF NOT EXISTS(SELECT FROM pg_catalog.pg_class c WHERE c.oid=rel AND c.relkind='r' AND c.relpersistence='p'
   AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relhasrules OR c.relhassubclass OR c.relispartition)
   AND NOT EXISTS(SELECT FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid)
   AND has_table_privilege(invoker,c.oid,'SELECT')) THEN
   RAISE EXCEPTION 'ordinary registration source unavailable' USING ERRCODE='42501';END IF;
  checked_sql:=CASE src
    WHEN 'resource_registration_scope' THEN 'r.project_id IS NOT DISTINCT FROM $4 AND r.account_id IS NOT DISTINCT FROM $5'
    WHEN 'resource_parent_edge' THEN
     'r.depth BETWEEN 1 AND 4 AND r.parent_type<>'''' AND r.parent_id<>''''
      AND r.parent_type !~ ''[:#*[:space:][:cntrl:]]'' AND r.parent_id !~ ''[:#*[:space:][:cntrl:]]''
      AND (r.parent_type<>''project'' OR r.parent_id=$4) AND (r.parent_type<>''account'' OR r.parent_id=$5)'
    ELSE 'true' END;
  -- LIMIT перед сортировкой и jsonb_agg. Оpaque witness не переносит payload
  -- или relation_fact.subject. Физические версии сравниваются без усечения.
  EXECUTE format('SELECT coalesce(jsonb_agg(q.state ORDER BY q.state),''[]''::jsonb),coalesce(bool_and(q.valid),true)
   FROM (SELECT jsonb_build_array(r.xmin::text,r.ctid::text) state,(%s) IS TRUE valid
   FROM ONLY kaname.%I r WHERE r.object_type=$1 AND r.object_id=$2 LIMIT $3%s) q',checked_sql,src,lock_sql)
   INTO states,valid USING model,p_id,p_rows-used_rows+1,project_id,account_id;
  used_rows:=used_rows+jsonb_array_length(states);used_reads:=used_reads+1;
  IF used_rows>p_rows OR octet_length(states::text)>8388608 THEN
   RAISE EXCEPTION 'ordinary registration source budget exhausted' USING ERRCODE='54000';END IF;
  IF NOT valid THEN RAISE EXCEPTION 'ordinary registration scope changed' USING ERRCODE='40001';END IF;
  registration:=registration||jsonb_build_object(src,jsonb_build_array(rel::oid,states));
 END LOOP;
 IF octet_length(registration::text)+octet_length(identity::text)>8388608 THEN
  RAISE EXCEPTION 'ordinary registration input exceeds byte limit' USING ERRCODE='54000';END IF;
 RETURN jsonb_build_object('identity',identity,'registration',registration,'rows',used_rows,'reads',used_reads);
EXCEPTION WHEN lock_not_available THEN
 RAISE EXCEPTION 'ordinary registration source busy' USING ERRCODE='40001';
END;
$discover$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_metadata_mirror_ordinary_preflight_v1(
 p_dotted text,p_id text,p_rr jsonb,p_patch jsonb,p_actor_type text,p_actor_id text,p_audit text,
 p_rows integer,p_reads integer,p_work integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $reserve$
DECLARE
 proof jsonb; root jsonb; observed jsonb; outputs jsonb:='{}'; command jsonb; actor jsonb; actor_state jsonb;
 actor_rel regclass; invoker oid; account_id text; audit_row kaname.audit_outbox; reconcile_row kaname.resource_reconcile_outbox;
 used_rows integer:=32; used_reads integer:=64; used_work integer:=32;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
  OR p_work IS NULL OR p_work NOT BETWEEN used_work AND 400000 THEN
  RAISE EXCEPTION 'ordinary reserve budget exhausted' USING ERRCODE='54000';END IF;
 IF jsonb_typeof(p_rr) IS DISTINCT FROM 'object' OR octet_length(p_rr::text)>8650752
  OR coalesce(p_actor_type,'') NOT IN ('user','service_account') OR coalesce(p_actor_id,'')=''
  OR octet_length(p_actor_id)>16384 OR p_actor_id ~ '[:#*[:space:][:cntrl:]]' THEN
  RAISE EXCEPTION 'ordinary actor or RR envelope invalid' USING ERRCODE='42501';END IF;
 root:=kaname._authority_metadata_mirror_ordinary_root_v1(p_dotted,p_id,p_rr->'identity',p_patch,
  p_rows-used_rows,p_reads-used_reads,p_work-used_work);
 used_rows:=used_rows+(root->>'rows')::integer;used_reads:=used_reads+(root->>'reads')::integer;
 used_work:=used_work+(root->>'work')::integer;
 IF NOT EXISTS(SELECT FROM pg_catalog.pg_trigger t WHERE t.tgrelid='kaname.resource_mirror'::regclass
  AND t.tgname='resource_mirror_binds_effective_registration' AND t.tgtype=21
  AND t.tgfoid='kaname.resource_mirror_keeps_the_bound_project()'::regprocedure AND t.tgenabled IN ('O','A')
  AND NOT t.tgisinternal AND t.tgqual IS NULL AND t.tgattr::text='' AND t.tgnargs=0) THEN
  RAISE EXCEPTION 'ordinary registration AFTER guard unavailable' USING ERRCODE='42501';END IF;
 observed:=kaname.authority_metadata_mirror_ordinary_discover_v1(p_dotted,p_id,p_rows-used_rows,p_reads-used_reads);
 IF observed IS DISTINCT FROM p_rr THEN RAISE EXCEPTION 'ordinary registration changed since RR' USING ERRCODE='40001';END IF;
 -- Бюджет полного повторного чтения при отложенной проверке резервируется сейчас.
 used_rows:=used_rows+2*(observed->>'rows')::integer;used_reads:=used_reads+2*(observed->>'reads')::integer;
 used_work:=used_work+2*(observed->>'rows')::integer;
 IF used_rows>p_rows OR used_reads>p_reads OR used_work>p_work THEN RAISE EXCEPTION 'ordinary source work exhausted' USING ERRCODE='54000';END IF;
 proof:=kaname.authority_protocol_attestation();invoker:=(proof->>'invoker_oid')::oid;
 IF p_actor_type='user' THEN
  actor_rel:='kaname.users'::regclass;
  LOCK TABLE ONLY kaname.users IN ROW SHARE MODE NOWAIT;
 ELSE
  actor_rel:='kaname.service_accounts'::regclass;
  LOCK TABLE ONLY kaname.service_accounts IN ROW SHARE MODE NOWAIT;
 END IF;
 IF NOT EXISTS(SELECT FROM pg_catalog.pg_class c WHERE c.oid=actor_rel AND c.relkind='r' AND c.relpersistence='p'
  AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relhasrules OR c.relispartition OR c.relhassubclass)
  AND has_table_privilege(invoker,c.oid,'SELECT')) THEN
  RAISE EXCEPTION 'ordinary actor source unavailable' USING ERRCODE='42501';END IF;
 IF p_actor_type='user' THEN
  SELECT jsonb_build_array(u.xmin::text,u.ctid::text) INTO actor_state FROM ONLY kaname.users u
   WHERE u.id=p_actor_id FOR SHARE OF u NOWAIT;
 ELSE
  SELECT jsonb_build_array(s.xmin::text,s.ctid::text) INTO actor_state FROM ONLY kaname.service_accounts s
   WHERE s.id=p_actor_id FOR SHARE OF s NOWAIT;
 END IF;
 IF NOT FOUND THEN RAISE EXCEPTION 'ordinary actor source absent' USING ERRCODE='42501';END IF;
 actor:=jsonb_build_object('type',p_actor_type,'id',p_actor_id);
 account_id:=root#>>'{identity,account,2,id}';
 IF root->>'mode'='ordinary' THEN
  -- Оба AFTER STATEMENT выполняют реальный UPDATE/UPSERT соответствующей эпохи.
  -- Берём DML table lock до final clock, включая ветвь typed key под GLOBAL.
  LOCK TABLE ONLY kaname.authority_policy_epoch, ONLY kaname.authority_binding_epoch IN ROW EXCLUSIVE MODE NOWAIT;
  IF (SELECT count(*) FROM pg_catalog.pg_class c WHERE c.oid IN
   ('kaname.authority_policy_epoch'::regclass,'kaname.authority_binding_epoch'::regclass)
   AND c.relkind='r' AND c.relpersistence='p' AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relispartition
    OR c.relhasrules OR c.relhassubclass) AND NOT EXISTS(SELECT FROM pg_catalog.pg_inherits i
    WHERE i.inhrelid=c.oid OR i.inhparent=c.oid))<>2 THEN
   RAISE EXCEPTION 'ordinary epoch relation shape differs' USING ERRCODE='42501';END IF;
  IF coalesce(p_audit,'') !~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$' THEN
   RAISE EXCEPTION 'ordinary audit identifier unavailable' USING ERRCODE='42501';END IF;
  LOCK TABLE ONLY kaname.audit_outbox, ONLY kaname.resource_reconcile_outbox IN ROW EXCLUSIVE MODE NOWAIT;
  IF (SELECT count(*) FROM pg_catalog.pg_class c
   WHERE c.oid IN ('kaname.audit_outbox'::regclass,'kaname.resource_reconcile_outbox'::regclass)
    AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
    AND NOT c.relhasrules AND NOT c.relhassubclass AND NOT c.relispartition
    AND has_table_privilege(invoker,c.oid,'INSERT'))<>2
   OR to_regclass(pg_get_serial_sequence('kaname.resource_reconcile_outbox','id'))
     IS DISTINCT FROM 'kaname.resource_reconcile_outbox_id_seq'::regclass
   OR NOT EXISTS (SELECT FROM pg_catalog.pg_attribute a WHERE a.attrelid='kaname.resource_reconcile_outbox'::regclass
    AND a.attname='id' AND a.attidentity='a' AND a.atttypid='bigint'::regtype AND NOT a.attisdropped)
   OR EXISTS(SELECT FROM (VALUES
    ('kaname.audit_outbox'::regclass,'authority_audit_id_guard_v2','kaname.authority_audit_id_guard_v2()'::regprocedure),
    ('kaname.resource_reconcile_outbox'::regclass,'authority_reconcile_id_guard_v2','kaname.authority_reconcile_id_guard_v2()'::regprocedure)
   ) AS required(rel,name,fn) WHERE NOT EXISTS(SELECT FROM pg_catalog.pg_trigger t
    JOIN pg_catalog.pg_attribute a ON a.attrelid=t.tgrelid AND a.attname='id' AND NOT a.attisdropped
    WHERE t.tgrelid=required.rel AND t.tgname=required.name AND t.tgfoid=required.fn
     AND t.tgtype=23 AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal AND t.tgqual IS NULL
     AND t.tgattr::text=a.attnum::text)) THEN
   RAISE EXCEPTION 'external metadata output relations or original INSERT access differ' USING ERRCODE='42501';
  END IF;
  reconcile_row.id:=nextval('kaname.resource_reconcile_outbox_id_seq');
  IF reconcile_row.id<=0 THEN
   RAISE EXCEPTION 'external metadata reconcile sequence exhausted' USING ERRCODE='P1034';
  END IF;
  IF NOT pg_try_advisory_xact_lock(1262569298,hashtext(p_audit)) THEN
   RAISE EXCEPTION 'external metadata audit identifier busy' USING ERRCODE='40001';
  END IF;
  IF NOT pg_try_advisory_xact_lock(1262569299,hashtext(reconcile_row.id::text)) THEN
   RAISE EXCEPTION 'external metadata reconcile identifier busy' USING ERRCODE='40001';
  END IF;
  IF EXISTS(SELECT FROM ONLY kaname.audit_outbox a WHERE a.id=p_audit)
   OR EXISTS(SELECT FROM ONLY kaname.resource_reconcile_outbox r WHERE r.id=reconcile_row.id) THEN
   RAISE EXCEPTION 'external metadata reserved output identifier occupied' USING ERRCODE='40001';
  END IF;
  audit_row.id:=p_audit;audit_row.event_type:='iam.resource_metadata.labels_updated';
  audit_row.tenant_account_id:=account_id;audit_row.status:='pending';audit_row.attempts:=0;
  audit_row.created_at:=transaction_timestamp();audit_row.next_attempt_at:=audit_row.created_at;
  audit_row.event_payload:=jsonb_build_object('actor',actor,'resource_type',p_dotted,'resource_id',p_id,
   'account_id',account_id,'changed_fields',jsonb_build_array('labels'));
  reconcile_row.object_type:=p_dotted;reconcile_row.object_id:=p_id;reconcile_row.event_type:='mirror.upsert';
  reconcile_row.created_at:=audit_row.created_at;reconcile_row.attempt_count:=0;
  outputs:=jsonb_build_object('audit_row',to_jsonb(audit_row),'reconcile_row',to_jsonb(reconcile_row));
 ELSIF root->>'mode' IS DISTINCT FROM 'noop' OR p_audit IS NOT NULL THEN
  RAISE EXCEPTION 'ordinary no-op does not reserve an audit identifier' USING ERRCODE='42501';
 END IF;
 command:=jsonb_build_object('root',root-ARRAY['rows','reads','work'],'actor',actor,'actor_state',actor_state,
  'outputs',outputs,'replay_rows',observed->'rows','replay_reads',observed->'reads',
  'registration_digest',encode(sha256(convert_to((observed->'registration')::text,'UTF8')),'hex'));
 PERFORM kaname._authority_sequence_reserve_v3('metadata','[]'::jsonb,8);
 PERFORM kaname._authority_sequence_freeze_v3(jsonb_build_object('kind','metadata.mirror.labels',
  'mode','external_'||(root->>'mode'),'ordinary_command',command,'phase','reserved'));
 RETURN jsonb_build_object('mode',root->'mode','rows',used_rows,'reads',used_reads,'work',used_work);
EXCEPTION WHEN lock_not_available THEN
 RAISE EXCEPTION 'ordinary mirror reserve busy' USING ERRCODE='40001';
END;
$reserve$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_mirror_ordinary_command_v1()
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $command$
DECLARE program jsonb; proof jsonb; cmd jsonb; root jsonb; phase text; mode text; actor jsonb; field text; actor_state jsonb;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 program:=kaname._authority_sequence_store_v3();
 IF program IS NULL OR program#>>'{frozen,kind}' IS DISTINCT FROM 'metadata.mirror.labels' THEN RETURN NULL;END IF;
 proof:=kaname.authority_protocol_attestation();cmd:=program#>'{frozen,ordinary_command}';root:=cmd->'root';
 phase:=program#>>'{frozen,phase}';mode:=root->>'mode';actor:=cmd->'actor';
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'consumer_abi' IS DISTINCT FROM '2'
  OR proof->>'consumer_profile' IS DISTINCT FROM 'full' OR proof->>'consumer_finalized' IS DISTINCT FROM 'true'
  OR NOT coalesce((proof->>'writer_contract'='2' AND proof->>'purpose'='decision')
   OR (proof->>'writer_contract'='1' AND proof->>'purpose'='participant'),false)
  OR current_setting('transaction_isolation')<>'read committed'
  OR program->>'family' IS DISTINCT FROM 'metadata' OR coalesce(mode,'') NOT IN ('ordinary','noop')
  OR program->>'frozen_mode' IS DISTINCT FROM 'external_'||mode OR program#>>'{frozen,mode}' IS DISTINCT FROM 'external_'||mode
  OR program->'maximum' IS DISTINCT FROM '[]'::jsonb OR program->'selected' IS DISTINCT FROM '[]'::jsonb
  OR program->>'maximum_count' IS DISTINCT FROM '0' OR program->>'selected_count' IS DISTINCT FROM '0'
  OR coalesce(phase,'') NOT IN ('reserved','accepted','applying','done')
  OR program->>'decision_at' IS NULL OR program->'decision_at' IS DISTINCT FROM proof->'decision_at'
  OR program->>'staged_decision_at' IS NULL OR NOT isfinite((program->>'staged_decision_at')::timestamptz)
  OR NOT isfinite((program->>'decision_at')::timestamptz)
  OR (program->>'decision_at')::timestamptz <= (program->>'staged_decision_at')::timestamptz
  OR coalesce(actor->>'type','') NOT IN ('user','service_account') OR coalesce(actor->>'id','')=''
  OR root#>>'{identity,dotted}' IS DISTINCT FROM root#>>'{old,object_type}'
  OR root#>>'{identity,id}' IS DISTINCT FROM root#>>'{old,object_id}'
  OR ((root->'old')-'labels') IS DISTINCT FROM ((root->'new')-'labels')
  OR (root->'old' IS DISTINCT FROM root->'new') IS DISTINCT FROM (mode='ordinary')
  OR cmd->>'registration_digest' IS NULL OR coalesce(cmd->>'registration_digest','') !~ '^[a-f0-9]{64}$'
  OR (mode='noop' AND cmd->'outputs' IS DISTINCT FROM '{}'::jsonb)
  OR (mode='ordinary' AND (cmd#>'{outputs,audit_row,event_payload,actor}' IS DISTINCT FROM actor
   OR cmd#>>'{outputs,reconcile_row,object_type}' IS DISTINCT FROM root#>>'{identity,dotted}'
   OR cmd#>>'{outputs,reconcile_row,object_id}' IS DISTINCT FROM root#>>'{identity,id}'))
  OR (phase<>'reserved' AND program#>'{frozen,accepted_at}' IS DISTINCT FROM program->'decision_at') THEN
  RAISE EXCEPTION 'ordinary mirror command clock or custody changed' USING ERRCODE='42501';
 END IF;
 FOREACH field IN ARRAY ARRAY['backend','transaction_id','invoker_oid','nonce','mode','accounts'] LOOP
  IF NOT (proof ? field) OR root#>ARRAY['custody',field] IS DISTINCT FROM proof->field THEN
   RAISE EXCEPTION 'ordinary mirror attempt changed' USING ERRCODE='42501';END IF;
 END LOOP;
 IF program->'nonce' IS DISTINCT FROM proof->'nonce' OR program->'transaction_id' IS DISTINCT FROM proof->'transaction_id' THEN
  RAISE EXCEPTION 'ordinary mirror sequence identity changed' USING ERRCODE='42501';END IF;
 IF actor->>'type'='user' THEN
  SELECT jsonb_build_array(u.xmin::text,u.ctid::text) INTO actor_state FROM ONLY kaname.users u
   WHERE u.id=actor->>'id';
 ELSE
  SELECT jsonb_build_array(s.xmin::text,s.ctid::text) INTO actor_state FROM ONLY kaname.service_accounts s
   WHERE s.id=actor->>'id';
 END IF;
 IF NOT FOUND OR actor_state IS DISTINCT FROM cmd->'actor_state' THEN
  RAISE EXCEPTION 'ordinary final actor changed' USING ERRCODE='40001';END IF;
 RETURN program;
END;
$command$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_metadata_mirror_ordinary_accept_v1(p_actor_type text,p_actor_id text)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $accept$
DECLARE program jsonb; actor jsonb;
BEGIN
 -- Как в staged metadata, доверенный сервис вызывает этот переход только
 -- после v_update и полного RequireMetadataGrant на том же DecisionAt.
 program:=kaname._authority_metadata_mirror_ordinary_command_v1();
 actor:=jsonb_build_object('type',p_actor_type,'id',p_actor_id);
 IF program IS NULL OR program#>>'{frozen,phase}' IS DISTINCT FROM 'reserved'
  OR program#>'{frozen,ordinary_command,actor}' IS DISTINCT FROM actor THEN
  RAISE EXCEPTION 'ordinary mirror actor or acceptance phase changed' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_authority_sequence_program s
 SET frozen=s.frozen||jsonb_build_object('phase','accepted','accepted_at',s.decision_at)
 WHERE s.singleton AND s.nonce=(program->>'nonce')::uuid AND s.frozen=program->'frozen';
 IF NOT FOUND THEN RAISE EXCEPTION 'ordinary mirror approval changed' USING ERRCODE='42501';END IF;
END;
$accept$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_mirror_ordinary_write_v1(p_dotted text,p_id text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $write$
DECLARE program jsonb; cmd jsonb; root jsonb; identity jsonb; expected jsonb; applying_state jsonb;
 actual jsonb; after_version jsonb; after_root jsonb; audit_row kaname.audit_outbox; reconcile_row kaname.resource_reconcile_outbox;
BEGIN
 program:=kaname._authority_metadata_mirror_ordinary_command_v1();
 cmd:=program#>'{frozen,ordinary_command}';root:=cmd->'root';identity:=root->'identity';expected:=root->'new';
 IF program IS NULL OR program#>>'{frozen,phase}' IS DISTINCT FROM 'accepted'
  OR p_dotted IS DISTINCT FROM identity->>'dotted' OR p_id IS DISTINCT FROM identity->>'id' THEN
  RAISE EXCEPTION 'ordinary mirror consume changed or repeated' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_authority_sequence_program s SET frozen=s.frozen||jsonb_build_object('phase','applying')
  WHERE s.singleton AND s.nonce=(program->>'nonce')::uuid AND s.frozen=program->'frozen' RETURNING s.frozen INTO applying_state;
 IF NOT FOUND THEN RAISE EXCEPTION 'ordinary mirror consume already active' USING ERRCODE='42501';END IF;
 IF root->>'mode'='noop' THEN
  SELECT to_jsonb(m),jsonb_build_array(m.xmin::text,m.ctid::text) INTO after_root,after_version
   FROM ONLY kaname.resource_mirror m WHERE m.object_type=p_dotted AND m.object_id=p_id
    AND m.xmin::text=identity#>>'{mirror,0}' AND m.ctid::text=identity#>>'{mirror,1}' AND to_jsonb(m)=root->'old';
 ELSE
  UPDATE ONLY kaname.resource_mirror AS m SET labels=expected->'labels'
   WHERE m.object_type=p_dotted AND m.object_id=p_id AND m.xmin::text=identity#>>'{mirror,0}'
    AND m.ctid::text=identity#>>'{mirror,1}' AND to_jsonb(m)=root->'old'
   RETURNING to_jsonb(m),jsonb_build_array(m.xmin::text,m.ctid::text) INTO after_root,after_version;
 END IF;
 IF NOT FOUND OR after_root IS DISTINCT FROM expected THEN
  RAISE EXCEPTION 'ordinary mirror physical CAS changed' USING ERRCODE='40001';END IF;
 IF root->>'mode'='ordinary' THEN
  audit_row:=jsonb_populate_record(NULL::kaname.audit_outbox,cmd#>'{outputs,audit_row}');
  INSERT INTO kaname.audit_outbox AS a
   (id,event_type,tenant_account_id,event_payload,status,attempts,created_at,next_attempt_at,sent_at,last_error)
  VALUES(audit_row.id,audit_row.event_type,audit_row.tenant_account_id,audit_row.event_payload,audit_row.status,
   audit_row.attempts,audit_row.created_at,audit_row.next_attempt_at,audit_row.sent_at,audit_row.last_error)
  RETURNING to_jsonb(a) INTO actual;
  IF actual IS DISTINCT FROM cmd#>'{outputs,audit_row}' THEN
   RAISE EXCEPTION 'external metadata audit output differs from reservation' USING ERRCODE='42501';
  END IF;
  reconcile_row:=jsonb_populate_record(NULL::kaname.resource_reconcile_outbox,cmd#>'{outputs,reconcile_row}');
  INSERT INTO kaname.resource_reconcile_outbox AS r
   (id,object_type,object_id,event_type,created_at,sent_at,last_error,attempt_count)
  OVERRIDING SYSTEM VALUE VALUES(reconcile_row.id,reconcile_row.object_type,reconcile_row.object_id,reconcile_row.event_type,
   reconcile_row.created_at,reconcile_row.sent_at,reconcile_row.last_error,reconcile_row.attempt_count)
  RETURNING to_jsonb(r) INTO actual;
  IF actual IS DISTINCT FROM cmd#>'{outputs,reconcile_row}' THEN
   RAISE EXCEPTION 'external metadata reconcile output differs from reservation' USING ERRCODE='42501';
  END IF;
 END IF;
 UPDATE pg_temp.kaname_authority_sequence_program s
 SET frozen=s.frozen||jsonb_build_object('phase','done','root_after',after_version)
 WHERE s.singleton AND s.nonce=(program->>'nonce')::uuid AND s.frozen=applying_state;
 IF NOT FOUND THEN RAISE EXCEPTION 'ordinary mirror consume changed before completion' USING ERRCODE='42501';END IF;
 RETURN after_root;
END;
$write$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_mirror_ordinary_complete_v1()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $complete$
DECLARE program jsonb; root jsonb; outputs jsonb; row_value jsonb; physical jsonb; identity jsonb; observed jsonb;
 policy_key text; binding_key text; policy_epoch jsonb; binding_epoch jsonb;
BEGIN
 program:=kaname._authority_metadata_mirror_ordinary_command_v1();
 IF program IS NULL OR program#>>'{frozen,phase}' IS DISTINCT FROM 'done' THEN
  RAISE EXCEPTION 'ordinary mirror final command was not consumed' USING ERRCODE='42501';END IF;
 root:=program#>'{frozen,ordinary_command,root}';outputs:=program#>'{frozen,ordinary_command,outputs}';identity:=root->'identity';
 SELECT to_jsonb(m),jsonb_build_array(m.xmin::text,m.ctid::text) INTO row_value,physical FROM ONLY kaname.resource_mirror m
 WHERE m.object_type=identity->>'dotted' AND m.object_id=identity->>'id';
 IF NOT FOUND OR row_value IS DISTINCT FROM root->'new' OR physical IS DISTINCT FROM program#>'{frozen,root_after}' THEN
  RAISE EXCEPTION 'ordinary mirror final root changed' USING ERRCODE='40001';END IF;
 observed:=kaname.authority_metadata_mirror_ordinary_discover_v1(identity->>'dotted',identity->>'id',
  (program#>>'{frozen,ordinary_command,replay_rows}')::integer,(program#>>'{frozen,ordinary_command,replay_reads}')::integer);
 IF encode(sha256(convert_to((observed->'registration')::text,'UTF8')),'hex')
  IS DISTINCT FROM program#>>'{frozen,ordinary_command,registration_digest}'
  OR (observed->'identity')-ARRAY['policy','binding_epoch','mirror'] IS DISTINCT FROM identity-ARRAY['policy','binding_epoch','mirror'] THEN
  RAISE EXCEPTION 'ordinary mirror registration changed before completion' USING ERRCODE='40001';END IF;
 IF root->>'mode'='noop' THEN
  IF observed->'identity' IS DISTINCT FROM identity THEN
   RAISE EXCEPTION 'no-op mirror physical input changed' USING ERRCODE='40001';END IF;
  RETURN;
 END IF;
 -- Один UPDATE зеркала меняет ровно эти два поколения. Захваченные root и
 -- account keys не позволяют спутать изменения с конкурентным писателем.
 policy_key:=root#>>'{epoch,policy_write}';binding_key:=root#>>'{epoch,binding_write}';
 IF policy_key IS NULL OR binding_key IS NULL THEN
  RAISE EXCEPTION 'ordinary write epoch keys absent' USING ERRCODE='42501';END IF;
 policy_epoch:=jsonb_set(identity->'policy',ARRAY[policy_key,'1'],
  to_jsonb((identity#>>ARRAY['policy',policy_key,'1'])::numeric+1),false);
 binding_epoch:=jsonb_set(identity->'binding_epoch',ARRAY[binding_key],
  to_jsonb((identity#>>ARRAY['binding_epoch',binding_key])::numeric+1),false);
 IF observed#>'{identity,policy}' IS DISTINCT FROM policy_epoch OR observed#>'{identity,binding_epoch}' IS DISTINCT FROM binding_epoch THEN
  RAISE EXCEPTION 'ordinary mirror actual epoch effects differ' USING ERRCODE='40001';END IF;
 SELECT to_jsonb(a) INTO row_value FROM ONLY kaname.audit_outbox a WHERE a.id=outputs#>>'{audit_row,id}';
 IF row_value IS DISTINCT FROM outputs->'audit_row' THEN RAISE EXCEPTION 'ordinary audit changed' USING ERRCODE='42501';END IF;
 SELECT to_jsonb(r) INTO row_value FROM ONLY kaname.resource_reconcile_outbox r WHERE r.id=(outputs#>>'{reconcile_row,id}')::bigint;
 IF row_value IS DISTINCT FROM outputs->'reconcile_row' THEN RAISE EXCEPTION 'ordinary reconcile changed' USING ERRCODE='42501';END IF;
END;
$complete$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $seal$
DECLARE expected record; target regprocedure;recipient record;
BEGIN
 FOR expected IN SELECT * FROM (VALUES
  ('authority_metadata_mirror_ordinary_discover_v1(text,text,integer,integer)','d781ab3c4a458e8372b1e9b2da20839c2ac819f7132b3aaafd526e712e62e317'),
  ('authority_metadata_mirror_ordinary_preflight_v1(text,text,jsonb,jsonb,text,text,text,integer,integer,integer)','adef1db014842ae1bbeb10f5cea328848c5b78e50736a9b2f36b2e76af1f1fc4'),
  ('_authority_metadata_mirror_ordinary_command_v1()','e1fc6d44aa691e22291ce90c09b739465c863e04e644b50f9367ae20e88b2088'),
  ('authority_metadata_mirror_ordinary_accept_v1(text,text)','505a89d1cbd2b901d4e795a493233b5b8d2c84a9efff5504ed895c447b993e33'),
  ('_authority_metadata_mirror_ordinary_write_v1(text,text)','33b138ea0156788ad343d1aa73061cbf390bc3ea8b542878bc86b04100ba988c'),
  ('_authority_metadata_mirror_ordinary_complete_v1()','afaa7ee678a18235c86b0c1e363d5fc69dd26c179867fb650e6c9a37f80f4f88')
 ) AS x(signature,digest) LOOP
  target:=to_regprocedure('kaname.'||expected.signature);
  IF NOT EXISTS(SELECT FROM pg_catalog.pg_proc p WHERE p.oid=target AND p.proowner=current_user::regrole
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=expected.digest) THEN
   RAISE EXCEPTION 'ordinary private function changed: %',expected.signature;END IF;
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',target);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=target AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',target,recipient.rolname);
  END LOOP;
 END LOOP;
END;
$seal$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $apply$
DECLARE step record;target oid;body text;definition text;pair jsonb;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('resource_mirror_keeps_the_bound_project()','71f936f3383ae6f73f2e3ff2eca2c95ccc9fb79c8962aa3e964c803b311ed34b','1857706cd41c2dfce6c97b2e162d8431260a72152840c43ff6d1a98fef80d994',$change$[
 [
  "    IF TG_OP='UPDATE' AND NEW.access_labels IS DISTINCT FROM OLD.access_labels THEN",
  "    IF TG_OP='UPDATE' AND NEW.labels IS DISTINCT FROM OLD.labels AND NEW.access_labels IS NOT DISTINCT FROM OLD.access_labels\n       AND current_user::regrole=(SELECT c.relowner FROM pg_catalog.pg_class c WHERE c.oid=TG_RELID)\n       AND pg_my_temp_schema()<>0 AND to_regclass('pg_temp.kaname_authority_sequence_program') IS NOT NULL\n       AND kaname.authority_protocol_attestation() IS NOT NULL THEN\n        IF kaname._authority_sequence_header_v3()#>>'{frozen,mode}' IN ('external_ordinary','external_noop') THEN\n            approved:=kaname._authority_metadata_mirror_ordinary_command_v1();\n            IF approved#>>'{frozen,phase}' IS DISTINCT FROM 'applying'\n               OR approved#>>'{frozen,ordinary_command,root,mode}' IS DISTINCT FROM 'ordinary'\n               OR TG_RELID<>'kaname.resource_mirror'::regclass OR TG_LEVEL<>'ROW'\n               OR TG_WHEN NOT IN ('BEFORE','AFTER') OR TG_NAME NOT IN ('resource_mirror_keeps_the_bound_project','resource_mirror_binds_effective_registration')\n               OR approved#>'{frozen,ordinary_command,root,old}' IS DISTINCT FROM to_jsonb(OLD)\n               OR approved#>'{frozen,ordinary_command,root,new}' IS DISTINCT FROM to_jsonb(NEW)\n               OR approved#>>'{frozen,ordinary_command,root,identity,mirror,0}' IS DISTINCT FROM OLD.xmin::text\n               OR approved#>>'{frozen,ordinary_command,root,identity,mirror,1}' IS DISTINCT FROM OLD.ctid::text THEN\n                RAISE EXCEPTION 'ordinary registration trigger lost exact physical command' USING ERRCODE='42501';\n            END IF;\n            PERFORM kaname._authority_resource_preheld_key_v2(1262569300,\n                jsonb_build_array(approved#>>'{frozen,ordinary_command,root,identity,catalog,2,object_type}',OLD.object_id)::text,false);\n            RETURN NEW;\n        END IF;\n    END IF;\n    IF TG_OP='UPDATE' AND NEW.access_labels IS DISTINCT FROM OLD.access_labels THEN"
 ]
]$change$::jsonb),
 ('authority_metadata_mirror_write_v1(text,text)','2993793f4e7d0a5f24fbdcf9450f95fffced40066dd3c66bf264acced3645bf1','1be599e4f939bfcb72e7d062f4d5916b857917295c858235be0e2912408e47a2',$change$[
 [
  " SELECT kaname._authority_metadata_mirror_write_v1(p_dotted,p_id)",
  " SELECT CASE WHEN kaname._authority_sequence_header_v3()#>>'{frozen,mode}' IN ('external_ordinary','external_noop')\n  THEN kaname._authority_metadata_mirror_ordinary_write_v1(p_dotted,p_id)\n  ELSE kaname._authority_metadata_mirror_write_v1(p_dotted,p_id) END"
 ]
]$change$::jsonb),
 ('_authority_sequence_complete_v3()','e5d4c583a372c86fdcdbfb3e23ee72116f2a9efd221de97510f539fddf483dd4','ea51295fc9a86b810572e9400319ae8defec75a270ef20b5ed1ce68acd5a9915',$change$[
 [
  " IF program->>'family'='metadata' AND program#>>'{frozen,mode}'='external_access_labels' THEN",
  " IF program->>'family'='metadata' AND program#>>'{frozen,mode}' IN ('external_ordinary','external_noop') THEN\n  PERFORM kaname._authority_metadata_mirror_ordinary_complete_v1();\n END IF;\n IF program->>'family'='metadata' AND program#>>'{frozen,mode}'='external_access_labels' THEN"
 ]
]$change$::jsonb),
 ('_authority_crud_storage_v3()','606347bf48fc31bde651be9822cb2dd89d7897a570fda2b5d15c4f4e617e291d','b44ee8e5cca78dbd2e8301fc9dafc3e7fbee4b88a10a052afad82d5e37f8f92b',$change$[
 [
  "e5d4c583a372c86fdcdbfb3e23ee72116f2a9efd221de97510f539fddf483dd4",
  "ea51295fc9a86b810572e9400319ae8defec75a270ef20b5ed1ce68acd5a9915"
 ]
]$change$::jsonb),
 ('_authority_full_contract_storage_v3()','901778b1bbb405abe217911e9f3b51ecfa6b253fa277935b1368b27e155a982b','71ca5801eac3776fc448745b5abde9387b58f9cc267bada41de0b7196d0d639b',$change$[
 [
  "606347bf48fc31bde651be9822cb2dd89d7897a570fda2b5d15c4f4e617e291d",
  "b44ee8e5cca78dbd2e8301fc9dafc3e7fbee4b88a10a052afad82d5e37f8f92b"
 ]
]$change$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','75edcda1114c591fa1dfd40a80930d3fade6f9eb6a9b34caebc97eef02f64986','a164a004464da5e8a822c3c235775c6801a7d2201edb2089b37c69559ffd71d1',$change$[
 [
  "2993793f4e7d0a5f24fbdcf9450f95fffced40066dd3c66bf264acced3645bf1",
  "1be599e4f939bfcb72e7d062f4d5916b857917295c858235be0e2912408e47a2"
 ]
]$change$::jsonb),
 ('authority_metadata_service_account_access_label_ready_v1()','29f99c8f1b9b0965606002b6e2f37cd6c2eaf38a05e450de8107c380fa589e0c','cc1b08c90db8a42c290cd0404a0d6692c0cd28a7ce0d7a711d79ed7367a48b07',$change$[
 [
  "606347bf48fc31bde651be9822cb2dd89d7897a570fda2b5d15c4f4e617e291d",
  "b44ee8e5cca78dbd2e8301fc9dafc3e7fbee4b88a10a052afad82d5e37f8f92b"
 ],
 [
  "901778b1bbb405abe217911e9f3b51ecfa6b253fa277935b1368b27e155a982b",
  "71ca5801eac3776fc448745b5abde9387b58f9cc267bada41de0b7196d0d639b"
 ],
 [
  "75edcda1114c591fa1dfd40a80930d3fade6f9eb6a9b34caebc97eef02f64986",
  "a164a004464da5e8a822c3c235775c6801a7d2201edb2089b37c69559ffd71d1"
 ]
]$change$::jsonb)
 ) AS s(signature,prior,result,changes) LOOP
  target:=to_regprocedure('kaname.'||step.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT body,definition FROM pg_catalog.pg_proc p
   WHERE p.oid=target AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM step.prior THEN
   RAISE EXCEPTION 'ordinary metadata source changed: %',step.signature;END IF;
  FOR pair IN SELECT value FROM jsonb_array_elements(step.changes) LOOP
   IF length(body)-length(replace(body,pair->>0,''))<>length(pair->>0) THEN
    RAISE EXCEPTION 'ordinary metadata splice changed: %',step.signature;END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex')<>step.result THEN
   RAISE EXCEPTION 'ordinary metadata result changed: %',step.signature;END IF;
  EXECUTE replace(definition,(SELECT prosrc FROM pg_catalog.pg_proc WHERE oid=target),body);
 END LOOP;
END;
$apply$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
-- +goose StatementBegin
DO $apply$
DECLARE step record;target oid;body text;definition text;pair jsonb;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('authority_metadata_service_account_access_label_ready_v1()','cc1b08c90db8a42c290cd0404a0d6692c0cd28a7ce0d7a711d79ed7367a48b07','29f99c8f1b9b0965606002b6e2f37cd6c2eaf38a05e450de8107c380fa589e0c',$change$[
 [
  "a164a004464da5e8a822c3c235775c6801a7d2201edb2089b37c69559ffd71d1",
  "75edcda1114c591fa1dfd40a80930d3fade6f9eb6a9b34caebc97eef02f64986"
 ],
 [
  "71ca5801eac3776fc448745b5abde9387b58f9cc267bada41de0b7196d0d639b",
  "901778b1bbb405abe217911e9f3b51ecfa6b253fa277935b1368b27e155a982b"
 ],
 [
  "b44ee8e5cca78dbd2e8301fc9dafc3e7fbee4b88a10a052afad82d5e37f8f92b",
  "606347bf48fc31bde651be9822cb2dd89d7897a570fda2b5d15c4f4e617e291d"
 ]
]$change$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','a164a004464da5e8a822c3c235775c6801a7d2201edb2089b37c69559ffd71d1','75edcda1114c591fa1dfd40a80930d3fade6f9eb6a9b34caebc97eef02f64986',$change$[
 [
  "1be599e4f939bfcb72e7d062f4d5916b857917295c858235be0e2912408e47a2",
  "2993793f4e7d0a5f24fbdcf9450f95fffced40066dd3c66bf264acced3645bf1"
 ]
]$change$::jsonb),
 ('_authority_full_contract_storage_v3()','71ca5801eac3776fc448745b5abde9387b58f9cc267bada41de0b7196d0d639b','901778b1bbb405abe217911e9f3b51ecfa6b253fa277935b1368b27e155a982b',$change$[
 [
  "b44ee8e5cca78dbd2e8301fc9dafc3e7fbee4b88a10a052afad82d5e37f8f92b",
  "606347bf48fc31bde651be9822cb2dd89d7897a570fda2b5d15c4f4e617e291d"
 ]
]$change$::jsonb),
 ('_authority_crud_storage_v3()','b44ee8e5cca78dbd2e8301fc9dafc3e7fbee4b88a10a052afad82d5e37f8f92b','606347bf48fc31bde651be9822cb2dd89d7897a570fda2b5d15c4f4e617e291d',$change$[
 [
  "ea51295fc9a86b810572e9400319ae8defec75a270ef20b5ed1ce68acd5a9915",
  "e5d4c583a372c86fdcdbfb3e23ee72116f2a9efd221de97510f539fddf483dd4"
 ]
]$change$::jsonb),
 ('_authority_sequence_complete_v3()','ea51295fc9a86b810572e9400319ae8defec75a270ef20b5ed1ce68acd5a9915','e5d4c583a372c86fdcdbfb3e23ee72116f2a9efd221de97510f539fddf483dd4',$change$[
 [
  " IF program->>'family'='metadata' AND program#>>'{frozen,mode}' IN ('external_ordinary','external_noop') THEN\n  PERFORM kaname._authority_metadata_mirror_ordinary_complete_v1();\n END IF;\n IF program->>'family'='metadata' AND program#>>'{frozen,mode}'='external_access_labels' THEN",
  " IF program->>'family'='metadata' AND program#>>'{frozen,mode}'='external_access_labels' THEN"
 ]
]$change$::jsonb),
 ('authority_metadata_mirror_write_v1(text,text)','1be599e4f939bfcb72e7d062f4d5916b857917295c858235be0e2912408e47a2','2993793f4e7d0a5f24fbdcf9450f95fffced40066dd3c66bf264acced3645bf1',$change$[
 [
  " SELECT CASE WHEN kaname._authority_sequence_header_v3()#>>'{frozen,mode}' IN ('external_ordinary','external_noop')\n  THEN kaname._authority_metadata_mirror_ordinary_write_v1(p_dotted,p_id)\n  ELSE kaname._authority_metadata_mirror_write_v1(p_dotted,p_id) END",
  " SELECT kaname._authority_metadata_mirror_write_v1(p_dotted,p_id)"
 ]
]$change$::jsonb),
 ('resource_mirror_keeps_the_bound_project()','1857706cd41c2dfce6c97b2e162d8431260a72152840c43ff6d1a98fef80d994','71f936f3383ae6f73f2e3ff2eca2c95ccc9fb79c8962aa3e964c803b311ed34b',$change$[
 [
  "    IF TG_OP='UPDATE' AND NEW.labels IS DISTINCT FROM OLD.labels AND NEW.access_labels IS NOT DISTINCT FROM OLD.access_labels\n       AND current_user::regrole=(SELECT c.relowner FROM pg_catalog.pg_class c WHERE c.oid=TG_RELID)\n       AND pg_my_temp_schema()<>0 AND to_regclass('pg_temp.kaname_authority_sequence_program') IS NOT NULL\n       AND kaname.authority_protocol_attestation() IS NOT NULL THEN\n        IF kaname._authority_sequence_header_v3()#>>'{frozen,mode}' IN ('external_ordinary','external_noop') THEN\n            approved:=kaname._authority_metadata_mirror_ordinary_command_v1();\n            IF approved#>>'{frozen,phase}' IS DISTINCT FROM 'applying'\n               OR approved#>>'{frozen,ordinary_command,root,mode}' IS DISTINCT FROM 'ordinary'\n               OR TG_RELID<>'kaname.resource_mirror'::regclass OR TG_LEVEL<>'ROW'\n               OR TG_WHEN NOT IN ('BEFORE','AFTER') OR TG_NAME NOT IN ('resource_mirror_keeps_the_bound_project','resource_mirror_binds_effective_registration')\n               OR approved#>'{frozen,ordinary_command,root,old}' IS DISTINCT FROM to_jsonb(OLD)\n               OR approved#>'{frozen,ordinary_command,root,new}' IS DISTINCT FROM to_jsonb(NEW)\n               OR approved#>>'{frozen,ordinary_command,root,identity,mirror,0}' IS DISTINCT FROM OLD.xmin::text\n               OR approved#>>'{frozen,ordinary_command,root,identity,mirror,1}' IS DISTINCT FROM OLD.ctid::text THEN\n                RAISE EXCEPTION 'ordinary registration trigger lost exact physical command' USING ERRCODE='42501';\n            END IF;\n            PERFORM kaname._authority_resource_preheld_key_v2(1262569300,\n                jsonb_build_array(approved#>>'{frozen,ordinary_command,root,identity,catalog,2,object_type}',OLD.object_id)::text,false);\n            RETURN NEW;\n        END IF;\n    END IF;\n    IF TG_OP='UPDATE' AND NEW.access_labels IS DISTINCT FROM OLD.access_labels THEN",
  "    IF TG_OP='UPDATE' AND NEW.access_labels IS DISTINCT FROM OLD.access_labels THEN"
 ]
]$change$::jsonb)
 ) AS s(signature,prior,result,changes) LOOP
  target:=to_regprocedure('kaname.'||step.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT body,definition FROM pg_catalog.pg_proc p
   WHERE p.oid=target AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM step.prior THEN
   RAISE EXCEPTION 'ordinary metadata source changed: %',step.signature;END IF;
  FOR pair IN SELECT value FROM jsonb_array_elements(step.changes) LOOP
   IF length(body)-length(replace(body,pair->>0,''))<>length(pair->>0) THEN
    RAISE EXCEPTION 'ordinary metadata splice changed: %',step.signature;END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex')<>step.result THEN
   RAISE EXCEPTION 'ordinary metadata result changed: %',step.signature;END IF;
  EXECUTE replace(definition,(SELECT prosrc FROM pg_catalog.pg_proc WHERE oid=target),body);
 END LOOP;
END;
$apply$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_metadata_mirror_ordinary_complete_v1();
DROP FUNCTION kaname._authority_metadata_mirror_ordinary_write_v1(text,text);
DROP FUNCTION kaname.authority_metadata_mirror_ordinary_accept_v1(text,text);
DROP FUNCTION kaname._authority_metadata_mirror_ordinary_command_v1();
DROP FUNCTION kaname.authority_metadata_mirror_ordinary_preflight_v1(text,text,jsonb,jsonb,text,text,text,integer,integer,integer);
DROP FUNCTION kaname.authority_metadata_mirror_ordinary_discover_v1(text,text,integer,integer);
