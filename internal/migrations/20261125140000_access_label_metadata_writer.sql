-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Штатная запись меток доступа аккаунта и проекта по утверждённому образу.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Штатный вход в первый этап. Возвращает только стоимость: снимок, план и
-- физические свидетельства остаются в приватной таблице этой транзакции.
CREATE FUNCTION kaname.authority_metadata_access_label_prepare_v1(
 p_kind text,p_id text,p_old_xmin text,p_old jsonb,p_new_access jsonb,
 p_policy_expected jsonb,p_policy_writes text[],p_rows integer,p_reads integer,p_work integer
) RETURNS TABLE(used_rows integer,used_reads integer,used_work integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $prepare$
DECLARE prepared jsonb;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 prepared:=kaname._authority_metadata_access_label_prepare_lockset_v1(
  p_kind,p_id,p_old_xmin,p_old,p_new_access,p_policy_expected,p_policy_writes,p_rows,p_reads,p_work);
 used_rows:=(prepared->>'rows')::integer;
 used_reads:=(prepared->>'reads')::integer;
 used_work:=(prepared->>'work')::integer;
 IF used_rows IS NULL OR used_rows NOT BETWEEN 1 AND p_rows
  OR used_reads IS NULL OR used_reads NOT BETWEEN 1 AND p_reads
  OR used_work IS NULL OR used_work NOT BETWEEN 1 AND p_work THEN
  RAISE EXCEPTION 'metadata prepare budget receipt invalid' USING ERRCODE='54000';END IF;
 PERFORM kaname._authority_metadata_access_label_stash_v1(prepared);
 RETURN NEXT;
END;
$prepare$;

-- Устанавливается в закрытом виде. Runtime grant добавляется вместе с
-- проверкой полного preflight, finalizer и exact writer.
DO $prepare_acl$
DECLARE recipient record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 REVOKE ALL ON FUNCTION kaname.authority_metadata_access_label_prepare_v1(
  text,text,text,jsonb,jsonb,jsonb,text[],integer,integer,integer) FROM PUBLIC;
 FOR recipient IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_proc f
  CROSS JOIN LATERAL pg_catalog.aclexplode(f.proacl) a
  JOIN pg_catalog.pg_roles u ON u.oid=a.grantee
  WHERE f.oid='kaname.authority_metadata_access_label_prepare_v1(text,text,text,jsonb,jsonb,jsonb,text[],integer,integer,integer)'::regprocedure
   AND a.grantee<>f.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.authority_metadata_access_label_prepare_v1(text,text,text,jsonb,jsonb,jsonb,text[],integer,integer,integer) FROM %I',recipient.rolname);
 END LOOP;
END;
$prepare_acl$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_metadata_access_label_retention_inputs_v1(
 p_patch jsonb,p_rename boolean,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $inputs$
BEGIN
 RETURN kaname._authority_metadata_access_label_retention_prepare_v1(
  p_patch,p_rename,p_rows,p_reads,p_work);
END;
$inputs$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_access_label_compile_reserve_v1(
 p_desired jsonb,p_audit text,p_actor_type text,p_actor_id text,
 p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $reserve$
DECLARE
 proof jsonb; compiled jsonb; old_row jsonb; new_row jsonb; physical jsonb;
 root_type text; root_id text; resource_kind text; table_name text;
 definitions jsonb; sources jsonb; carry jsonb; freshness jsonb; evidence jsonb;
 origin jsonb; journal_row jsonb; maximum jsonb; frozen_program jsonb;
 used_rows integer:=4; used_reads integer:=24; used_work integer:=1;
 union_input_count integer; reserve_reads integer; affected integer;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
  OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
  OR p_work IS NULL OR p_work NOT BETWEEN used_work AND 400000 THEN
  RAISE EXCEPTION 'metadata reserve budget exhausted' USING ERRCODE='54000';END IF;
 IF coalesce(p_audit,'')='' OR length(p_audit)>64
  OR coalesce(p_actor_type,'') NOT IN ('user','service_account')
  OR coalesce(p_actor_id,'')='' OR p_actor_id ~ '[:#*[:space:][:cntrl:]]' THEN
  RAISE EXCEPTION 'metadata reserve actor or audit invalid' USING ERRCODE='42501';END IF;
 -- stashed_v1 привязывает сертификат к подтверждённой сессии,
 -- транзакции, каталогу, исходной роли БД и областям.
 compiled:=kaname._authority_metadata_access_label_retention_compile_v1(p_desired,p_work-used_work);
 used_rows:=used_rows+(compiled->>'rows')::integer;
 used_reads:=used_reads+(compiled->>'reads')::integer;
 used_work:=used_work+(compiled->>'work')::integer;
 proof:=kaname.authority_protocol_attestation();
 old_row:=compiled->'old_row';new_row:=compiled->'new_row';physical:=compiled->'root_physical';
 root_type:=compiled#>>'{receipt,root_type}';root_id:=compiled#>>'{receipt,root_id}';
 resource_kind:=CASE root_type WHEN 'iam.account' THEN 'account' WHEN 'iam.project' THEN 'project' END;
 table_name:=CASE resource_kind WHEN 'account' THEN 'accounts' WHEN 'project' THEN 'projects' END;
 IF resource_kind IS NULL OR coalesce(root_id,'')=''
  OR jsonb_typeof(old_row) IS DISTINCT FROM 'object' OR jsonb_typeof(new_row) IS DISTINCT FROM 'object'
  OR old_row->>'id' IS DISTINCT FROM root_id OR new_row->>'id' IS DISTINCT FROM root_id
  OR (old_row-ARRAY['name','description','labels','access_labels']) IS DISTINCT FROM
     (new_row-ARRAY['name','description','labels','access_labels'])
  OR old_row->'access_labels' IS NOT DISTINCT FROM new_row->'access_labels'
  OR compiled#>'{receipt,old_labels}' IS DISTINCT FROM old_row->'access_labels'
  OR compiled#>'{receipt,new_labels}' IS DISTINCT FROM new_row->'access_labels'
  OR physical->>'table' IS DISTINCT FROM table_name OR physical->>'id' IS DISTINCT FROM root_id
  OR coalesce(physical->>'xmin','')='' OR coalesce(physical->>'ctid','')=''
  OR jsonb_typeof(compiled#>'{receipt,facts}') IS DISTINCT FROM 'array'
  OR jsonb_typeof(compiled->'retention') IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'metadata reserve exact compiler receipt incomplete' USING ERRCODE='42501';END IF;
 IF used_rows IS NULL OR used_rows>p_rows OR used_reads IS NULL OR used_reads>p_reads
  OR used_work IS NULL OR used_work>p_work THEN
  RAISE EXCEPTION 'metadata reserve shared compile budget exhausted' USING ERRCODE='54000';END IF;
 IF kaname._authority_sequence_store_v3() IS NOT NULL THEN
  RAISE EXCEPTION 'metadata sequence program already reserved' USING ERRCODE='42501';END IF;
 -- Здесь ожидаем только ещё не удержанные источники записи.
 -- Ключи строк и эпох уже удерживает hold_and_replay.
 LOCK TABLE kaname.audit_outbox,kaname.resource_journal,
  kaname.resource_reconcile_outbox IN ROW EXCLUSIVE MODE;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_backend_pid()
  AND l.locktype='relation' AND l.relation='kaname.resource_reconcile_outbox_id_seq'::regclass
  AND l.mode='RowExclusiveLock' AND l.granted) THEN
  PERFORM nextval('kaname.resource_reconcile_outbox_id_seq');
 END IF;
 PERFORM pg_advisory_xact_lock(1262569298,hashtext(p_audit));
 PERFORM a.id FROM kaname.audit_outbox a WHERE a.id=p_audit FOR UPDATE;
 definitions:=kaname._authority_resource_access_label_requirements_v1(
  resource_kind,old_row,new_row,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+(definitions->>'rows')::integer;used_reads:=used_reads+(definitions->>'reads')::integer;
 sources:=kaname._authority_resource_access_label_sources_hold_v1(
  p_actor_type,p_actor_id,definitions->'requirements',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+(sources->>'rows')::integer;used_reads:=used_reads+(sources->>'reads')::integer;
 -- Удержание корня сериализует смену поколения. Carry захватывает
 -- таблицы, прежнее поколение и все ожидающие факты.
 carry:=kaname._authority_metadata_access_label_carry_v1(
  root_type,root_id,old_row->'access_labels',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+(carry->>'rows')::integer;used_reads:=used_reads+(carry->>'reads')::integer;
 union_input_count:=jsonb_array_length(compiled#>'{receipt,facts}')+jsonb_array_length(carry->'prior_facts');
 IF union_input_count IS NULL OR used_rows IS NULL OR used_rows+union_input_count>p_rows
  OR used_reads IS NULL OR used_reads>p_reads OR used_work+2*union_input_count>p_work THEN
  RAISE EXCEPTION 'metadata maximum freshness budget exhausted' USING ERRCODE='54000';END IF;
 SELECT jsonb_build_object('root_type',root_type,'root_id',root_id,
  'old_labels',old_row->'access_labels','new_labels',new_row->'access_labels',
  'prior_generation',carry->'prior_generation',
  'facts',coalesce(jsonb_agg(fact ORDER BY fact::text COLLATE "C"),'[]'::jsonb)) INTO freshness
 FROM (SELECT value fact FROM jsonb_array_elements(compiled#>'{receipt,facts}')
  UNION SELECT value fact FROM jsonb_array_elements(carry->'prior_facts')) q;
 used_rows:=used_rows+jsonb_array_length(freshness->'facts');
 used_work:=used_work+union_input_count+jsonb_array_length(freshness->'facts');
 evidence:=jsonb_build_object('candidate_facts',compiled#>'{receipt,facts}',
  'prior_facts',carry->'prior_facts','retention',compiled->'retention');
 -- Резервируем один UPDATED с точным образом OLD и NEW.
 origin:=jsonb_build_object('table',table_name,'operation','UPDATE','when','AFTER','old',old_row,'new',new_row);
 journal_row:=jsonb_build_object('resource_kind',resource_kind,'resource_id',root_id,
  'project_id',kaname.resource_journal_project(resource_kind,new_row),
  'scope',kaname.resource_journal_scope(resource_kind,new_row),
  'event_type','UPDATED','payload',jsonb_build_object('id',root_id));
 maximum:=jsonb_build_array(jsonb_build_object('table','resource_journal','origin',origin,
  'ordinal',1,'row',journal_row,'stamp','transaction'));
 -- В базовой стоимости учтён верхний предел для резерва журнала.
 reserve_reads:=kaname._authority_sequence_reserve_v3('metadata',maximum,16);
 IF reserve_reads IS NULL OR reserve_reads>16 THEN
  RAISE EXCEPTION 'metadata journal reservation exceeded bound' USING ERRCODE='54000';END IF;
 frozen_program:=jsonb_build_object('kind','metadata.access_labels',
  'access_label_authority',sources,'access_label_requirements',definitions->'requirements',
  'access_label_freshness',freshness,'access_label_root_physical',physical,
  'access_label_freshness_proofs',evidence,'access_label_audit_id',p_audit);
 IF octet_length(frozen_program::text)>67108864 THEN
  RAISE EXCEPTION 'metadata frozen receipt exceeds byte budget' USING ERRCODE='54000';END IF;
 UPDATE pg_temp.kaname_authority_sequence_program p SET frozen=frozen_program
 WHERE p.singleton AND p.nonce=(proof->>'nonce')::uuid AND p.family='metadata'
  AND p.staged_decision_at=(proof->>'decision_at')::timestamptz
  AND p.frozen='{}'::jsonb AND p.selected_count IS NULL;
 GET DIAGNOSTICS affected=ROW_COUNT;
 IF affected<>1 THEN RAISE EXCEPTION 'metadata verified result was not frozen exactly once' USING ERRCODE='42501';END IF;
 RETURN jsonb_build_object('rows',used_rows,'reads',used_reads,'work',used_work);
END;
$reserve$;

CREATE FUNCTION kaname._authority_metadata_access_label_retention_accept_v1(
 p_actor_type text,p_actor_id text,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $approve$
DECLARE
 proof jsonb;
 header jsonb;
 program jsonb;
 frozen_program jsonb;
 authority_receipt jsonb;
 requirements jsonb;
 freshness jsonb;
 decision timestamptz;
 matches integer;
 affected integer;
 receipt_cost jsonb;
 retained jsonb; final_freshness jsonb;
 used_work integer:=1; compare_work integer;
 used_rows integer:=4;
 used_reads integer:=3;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
  OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
  OR p_work IS NULL OR p_work NOT BETWEEN used_work AND 400000 THEN
  RAISE EXCEPTION 'metadata apply approval budget exhausted' USING ERRCODE='54000';END IF;
 SELECT x.proof,x.header INTO STRICT proof,header FROM kaname._authority_sequence_probe_v3() x;
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
  OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'full'
  OR proof->>'consumer_finalized' IS DISTINCT FROM 'true'
  OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
  OR NOT coalesce((proof->>'writer_contract'='2' AND proof->>'purpose'='decision')
       OR (proof->>'writer_contract'='1' AND proof->>'purpose'='participant'
        AND proof->>'consumer_abi'='2' AND proof->>'consumer_profile'='full'),false)
  OR header->>'family' IS DISTINCT FROM 'metadata'
  OR jsonb_typeof(header->'selected') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'metadata apply approval lacks final owner program' USING ERRCODE='42501';END IF;
 program:=kaname._authority_sequence_store_v3();
 frozen_program:=program->'frozen';
 authority_receipt:=frozen_program->'access_label_authority';
 requirements:=frozen_program->'access_label_requirements';
 freshness:=frozen_program->'access_label_freshness';
 decision:=(program->>'decision_at')::timestamptz;
 IF frozen_program->>'kind' IS DISTINCT FROM 'metadata.access_labels'
  OR frozen_program ? 'access_label_approved_at'
  OR decision IS NULL OR NOT isfinite(decision)
  OR decision IS DISTINCT FROM (proof->>'decision_at')::timestamptz
  OR decision<=(program->>'staged_decision_at')::timestamptz
  OR jsonb_typeof(requirements) IS DISTINCT FROM 'array' OR jsonb_array_length(requirements) NOT BETWEEN 1 AND 128
  OR jsonb_typeof(freshness) IS DISTINCT FROM 'object'
  OR jsonb_typeof(freshness->'facts') IS DISTINCT FROM 'array'
  OR coalesce(p_actor_type,'') NOT IN ('user','service_account')
  OR coalesce(p_actor_id,'')='' OR p_actor_id ~ '[:#*[:space:][:cntrl:]]'
  OR authority_receipt->'actor' IS DISTINCT FROM jsonb_build_object('type',p_actor_type,'id',p_actor_id) THEN
  RAISE EXCEPTION 'metadata apply actor or evidence differs from prepared command' USING ERRCODE='42501';END IF;
 SELECT count(*)::integer INTO matches FROM pg_temp.kaname_authority_sequence_effects e
 WHERE e.nonce=(header->>'nonce')::uuid AND e.ordinal=1
  AND e.table_name='resource_journal' AND e.selected
  AND NOT (e.registered OR e.claimed OR e.consumed)
  AND e.origin->>'operation'='UPDATE' AND e.origin->>'when'='AFTER'
  AND e.origin->>'table'=CASE freshness->>'root_type' WHEN 'iam.account' THEN 'accounts' WHEN 'iam.project' THEN 'projects' END
  AND e.origin#>>'{old,id}'=freshness->>'root_id' AND e.origin#>>'{new,id}'=freshness->>'root_id'
  AND e.origin#>'{old,access_labels}'=freshness->'old_labels'
  AND e.origin#>'{new,access_labels}'=freshness->'new_labels';
 IF matches<>1 OR (program->>'selected_count')::integer IS DISTINCT FROM 1 THEN
  RAISE EXCEPTION 'metadata apply origin changed before approval' USING ERRCODE='42501';END IF;
 receipt_cost:=kaname._authority_resource_access_label_sources_require_v1(
  authority_receipt,requirements,decision,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+(receipt_cost->>'rows')::integer;
 used_reads:=used_reads+(receipt_cost->>'reads')::integer;
 IF used_rows IS NULL OR used_rows>p_rows OR used_reads IS NULL OR used_reads>p_reads THEN
  RAISE EXCEPTION 'metadata apply approval budget exhausted' USING ERRCODE='54000';END IF;
 -- На окончательном времени решения используем удержанные сертификат
 -- и физические свидетельства.
 retained:=kaname._authority_metadata_access_label_retained_select_v1(
  frozen_program->'access_label_freshness_proofs',decision,p_work-used_work);
 used_work:=used_work+(retained->>'work')::integer;
 IF jsonb_typeof(retained->'facts') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'metadata retained selection omitted facts' USING ERRCODE='42501';END IF;
 compare_work:=2*jsonb_array_length(retained->'facts')+jsonb_array_length(freshness->'facts')
  +jsonb_array_length(frozen_program#>'{access_label_freshness_proofs,prior_facts}');
 IF used_work IS NULL OR compare_work IS NULL OR used_work+compare_work>p_work THEN
  RAISE EXCEPTION 'metadata retained selection shared budget exhausted' USING ERRCODE='54000';END IF;
 used_work:=used_work+compare_work;
 IF EXISTS(SELECT value FROM jsonb_array_elements(retained->'facts')
    EXCEPT SELECT value FROM jsonb_array_elements(freshness->'facts'))
  OR EXISTS(SELECT value FROM jsonb_array_elements(frozen_program#>'{access_label_freshness_proofs,prior_facts}')
    EXCEPT SELECT value FROM jsonb_array_elements(retained->'facts')) THEN
  RAISE EXCEPTION 'metadata retained selection escaped reserved maximum or lost prior facts' USING ERRCODE='42501';END IF;
 final_freshness:=jsonb_set(freshness,'{facts}',retained->'facts');
 UPDATE pg_temp.kaname_authority_sequence_program p
 SET frozen=p.frozen||jsonb_build_object('access_label_approved_at',decision,
  'access_label_freshness',final_freshness)
 WHERE p.singleton AND p.nonce=(header->>'nonce')::uuid AND p.family='metadata'
  AND p.decision_at=decision AND p.frozen=frozen_program;
 GET DIAGNOSTICS affected=ROW_COUNT;
 IF affected<>1 THEN RAISE EXCEPTION 'metadata apply approval was not recorded exactly once' USING ERRCODE='42501';END IF;
 RETURN jsonb_build_object('rows',used_rows,'reads',used_reads,'work',used_work);
END;
$approve$;

-- Обе внутренние функции доступны только владельцу протокола.
DO $private$
DECLARE target text; recipient record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 FOREACH target IN ARRAY ARRAY[
  '_authority_metadata_access_label_compile_reserve_v1(jsonb,text,text,text,integer,integer,integer)',
  '_authority_metadata_access_label_retention_accept_v1(text,text,integer,integer,integer)'
 ] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',target);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a
   JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE p.oid=to_regprocedure('kaname.'||target) AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM %I',target,recipient.rolname);
  END LOOP;
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_metadata_access_label_preflight_v2(
 p_desired jsonb,p_audit text,p_actor_type text,p_actor_id text,
 p_rows integer,p_reads integer,p_work integer
) RETURNS TABLE(used_rows integer,used_reads integer,used_work integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $preflight$
DECLARE receipt jsonb;
BEGIN
 receipt:=kaname._authority_metadata_access_label_compile_reserve_v1(
  p_desired,p_audit,p_actor_type,p_actor_id,p_rows,p_reads,p_work);
 used_rows:=(receipt->>'rows')::integer;used_reads:=(receipt->>'reads')::integer;
 used_work:=(receipt->>'work')::integer;
 IF used_rows IS NULL OR used_rows<1 OR used_rows>p_rows
  OR used_reads IS NULL OR used_reads<1 OR used_reads>p_reads
  OR used_work IS NULL OR used_work<0 OR used_work>p_work THEN
  RAISE EXCEPTION 'metadata preflight budget receipt incomplete' USING ERRCODE='42501';END IF;
 RETURN NEXT;
END;
$preflight$;

CREATE FUNCTION kaname.authority_metadata_access_label_accept_v2(
 p_actor_type text,p_actor_id text,p_rows integer,p_reads integer,p_work integer
) RETURNS TABLE(used_rows integer,used_reads integer,used_work integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $accept$
DECLARE receipt jsonb;
BEGIN
 receipt:=kaname._authority_metadata_access_label_retention_accept_v1(
  p_actor_type,p_actor_id,p_rows,p_reads,p_work);
 used_rows:=(receipt->>'rows')::integer;used_reads:=(receipt->>'reads')::integer;
 used_work:=(receipt->>'work')::integer;
 IF used_rows IS NULL OR used_rows<1 OR used_rows>p_rows
  OR used_reads IS NULL OR used_reads<1 OR used_reads>p_reads
  OR used_work IS NULL OR used_work<0 OR used_work>p_work THEN
  RAISE EXCEPTION 'metadata accept budget receipt incomplete' USING ERRCODE='42501';END IF;
 RETURN NEXT;
END;
$accept$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Проверка исходной схемы и смена тела выполняются в одной миграции.
DO $guard_pin$
BEGIN
 IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname.authority_access_label_storage_valid_v1()'::regprocedure) IS DISTINCT FROM '0acf348156e88d80a71cdc67c6a0a952719e1e288e657ec565a8986fb92d2f12'
 OR (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname.access_labels_immutable_v1()'::regprocedure) IS DISTINCT FROM 'ebae429f31cb7558e7c01285fd82e947de6470eb1acc921bab06f46251f62046' THEN
  RAISE EXCEPTION 'access label storage guard differs before activation' USING ERRCODE='55000';END IF;
END;
$guard_pin$;
CREATE OR REPLACE FUNCTION kaname.access_labels_immutable_v1() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $guard$
DECLARE command jsonb;owner_oid oid;
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME NOT IN
 ('accounts','projects','users','service_accounts','groups','roles','access_bindings','resource_mirror')
 OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_OP NOT IN ('INSERT','UPDATE') THEN
  RAISE EXCEPTION 'access label guard context invalid' USING ERRCODE='42501';
 END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.access_labels IS DISTINCT FROM '{}'::jsonb THEN
   RAISE EXCEPTION 'access label mutation requires a protected writer' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
 END IF;
 IF NEW.access_labels IS NOT DISTINCT FROM OLD.access_labels THEN RETURN NEW;END IF;
 SELECT c.relowner INTO STRICT owner_oid FROM pg_catalog.pg_class c WHERE c.oid='kaname.authority_writer_protocol'::regclass;
 IF TG_TABLE_NAME NOT IN ('accounts','projects')
  OR owner_oid IS DISTINCT FROM (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname=current_user) THEN
  RAISE EXCEPTION 'access label mutation requires a protected writer' USING ERRCODE='42501';END IF;
 command:=kaname._authority_metadata_access_label_origin_v1(TG_TABLE_NAME,OLD.id);
 IF command->'old' IS DISTINCT FROM to_jsonb(OLD) OR command->'new' IS DISTINCT FROM to_jsonb(NEW) THEN
  RAISE EXCEPTION 'access label UPDATE differs from protected writer approval' USING ERRCODE='42501';END IF;
 RETURN NEW;
END;
$guard$;
CREATE OR REPLACE FUNCTION kaname.authority_access_label_storage_valid_v1() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE owner_oid oid;target text;relation_id oid;column_number smallint;expected record;
BEGIN
 SELECT relowner INTO owner_oid FROM pg_class WHERE oid='kaname.authority_writer_protocol'::regclass;
 IF owner_oid IS DISTINCT FROM (SELECT oid FROM pg_roles WHERE rolname=current_user) THEN RETURN false;END IF;
 FOR expected IN SELECT * FROM (VALUES
 ('access_labels_valid_v1(jsonb)','5bdcbf012ab0dee0838575bc22c3109d97483e1caf2f5543d810f46be03f9c60',false,'i'),
 ('access_labels_immutable_v1()','78051349c7cec4e3c5df8cdd8e11bc36243d9ad8d0c227fde363babfeaa258d9',false,'v')
 ) p(signature,digest,definer,volatility) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid=to_regprocedure('kaname.'||expected.signature)
   AND p.proowner=owner_oid AND p.prosecdef=expected.definer AND p.provolatile::text=expected.volatility
   AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=expected.digest
   AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
    WHERE a.grantee<>owner_oid AND NOT (expected.signature='access_labels_valid_v1(jsonb)'
     AND a.grantee=0 AND a.privilege_type='EXECUTE' AND NOT a.is_grantable))) THEN RETURN false;END IF;
 END LOOP;
 -- Проверяем только собственный footprint; чужие штатные триггеры не запрещаем.
 FOREACH target IN ARRAY ARRAY['accounts','projects','users','service_accounts','groups','roles','access_bindings','resource_mirror'] LOOP
  relation_id:=to_regclass('kaname.'||target);
  IF NOT EXISTS(SELECT 1 FROM pg_class WHERE oid=relation_id AND relowner=owner_oid AND relkind='r') THEN RETURN false;END IF;
  SELECT a.attnum INTO column_number FROM pg_attribute a JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
   WHERE a.attrelid=relation_id AND a.attname='access_labels' AND NOT a.attisdropped
    AND a.atttypid='jsonb'::regtype AND a.attnotnull AND a.attgenerated=''
    AND pg_get_expr(d.adbin,d.adrelid)='''{}''::jsonb';
  IF column_number IS NULL THEN RETURN false;END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid=relation_id AND c.conname='access_labels_valid'
   AND c.contype='c' AND c.convalidated AND NOT c.connoinherit AND c.conkey=ARRAY[column_number]
   AND pg_get_expr(c.conbin,c.conrelid)='kaname.access_labels_valid_v1(access_labels)') THEN RETURN false;END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=relation_id AND t.tgname='access_labels_immutable'
   AND t.tgfoid='kaname.access_labels_immutable_v1()'::regprocedure AND t.tgtype=23
   AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgnargs=0 AND t.tgqual IS NULL AND t.tgattr=''::int2vector)
  THEN RETURN false;END IF;
 END LOOP;
 RETURN true;
END $$;
DO $guard_pin$
BEGIN
 IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname.authority_access_label_storage_valid_v1()'::regprocedure) IS DISTINCT FROM 'a24dc7f2ffbb450fb0229aa05a3af307a831a106d673fa34f35424644f77016f'
 OR (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname.access_labels_immutable_v1()'::regprocedure) IS DISTINCT FROM '78051349c7cec4e3c5df8cdd8e11bc36243d9ad8d0c227fde363babfeaa258d9' THEN
  RAISE EXCEPTION 'access label storage guard differs before publication' USING ERRCODE='55000';END IF;
END;
$guard_pin$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER access_labels_000_commit_freshness AFTER UPDATE ON kaname.accounts
FOR EACH ROW WHEN (OLD.access_labels IS DISTINCT FROM NEW.access_labels)
EXECUTE FUNCTION kaname._authority_metadata_access_label_freshness_v1();
CREATE TRIGGER access_labels_000_commit_freshness AFTER UPDATE ON kaname.projects
FOR EACH ROW WHEN (OLD.access_labels IS DISTINCT FROM NEW.access_labels)
EXECUTE FUNCTION kaname._authority_metadata_access_label_freshness_v1();
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_metadata_access_label_ready_v2(p_client_abi text)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $ready$
DECLARE owner_oid oid;invoker_oid oid;item record;target text;fn oid;bundle record;
 manifest jsonb:=$manifest$
[
  {
    "signature": "_authority_access_label_member_partition_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer)",
    "digest": "7d144d72bb0cc2158cc45224fe6a961c79616f75ad9d4b48a065b81a85ec9965",
    "definer": false,
    "volatility": "i",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_root_type",
      "p_root_id",
      "p_bindings",
      "p_index",
      "p_catalog",
      "p_frontiers",
      "p_rows",
      "p_work"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_access_label_old_facts_v2(text,text,text[],jsonb,jsonb,jsonb,integer,integer)",
    "digest": "2e6309906dbdd8db09d3d396a40bf056da169276a6fb2d422c8ea2a9aa232bf3",
    "definer": false,
    "volatility": "i",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_root_type",
      "p_root_id",
      "p_bindings",
      "p_index",
      "p_catalog",
      "p_frontiers",
      "p_rows",
      "p_work"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_carrier_census_v1(text,jsonb,jsonb,integer,integer,integer)",
    "digest": "dbd3a92094d37acfc7c322a661ca1e3e44543eb44ba8f7f97329a2a81a40fe13",
    "definer": false,
    "volatility": "s",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_root_type",
      "p_old_root",
      "p_new_labels",
      "p_rows",
      "p_reads",
      "p_work"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_carry_v1(text,text,jsonb,integer,integer)",
    "digest": "9d099e8fb586eaca406c87cc4d1bf2e0fe91ebec8ecbbaff8e7e307978c29b9e",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_root_type",
      "p_root_id",
      "p_old_labels",
      "p_rows",
      "p_reads"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_compile_reserve_v1(jsonb,text,text,text,integer,integer,integer)",
    "digest": "ffde4521606fea996b97ed4d64ad1fdb4664150b5be86679a08ee5ed19997405",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_desired",
      "p_audit",
      "p_actor_type",
      "p_actor_id",
      "p_rows",
      "p_reads",
      "p_work"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_discovery_fence_v1(jsonb)",
    "digest": "edb8b5bcfe4e7b0ca20b74a7226b4f8c2f1a7c344b5eb710d7ed95def017add2",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "void",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_closure"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_early_closure_v1(jsonb,jsonb,integer,integer,integer)",
    "digest": "09f57f322d90390478139f383c251a177901530cadcc61ba9f94ee0c9b1fbe2d",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_packet",
      "p_catalog",
      "p_rows",
      "p_reads",
      "p_work"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_early_frontier_v1(text,text,integer,integer)",
    "digest": "9b5b80bf056943d737a373f112351d0ca4583ac3a27f95bbbf22672acb5f1fea",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "record",
    "result_set": true,
    "language": "plpgsql",
    "argnames": [
      "p_model",
      "p_id",
      "p_rows",
      "p_reads",
      "frontier",
      "source_index",
      "cluster_states",
      "logical_rows",
      "logical_reads"
    ],
    "argmodes": [
      "i",
      "i",
      "i",
      "i",
      "t",
      "t",
      "t",
      "t",
      "t"
    ],
    "allargtypes": [
      "text",
      "text",
      "integer",
      "integer",
      "jsonb",
      "jsonb",
      "jsonb",
      "integer",
      "integer"
    ]
  },
  {
    "signature": "_authority_metadata_access_label_early_source_v1(integer,text,text,integer,integer)",
    "digest": "0b20a22f6bdcc1e18e9de51fda69bfac31a86807e3f265ef05bf74c42d915f78",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_kind",
      "p_type",
      "p_id",
      "p_rows",
      "p_reads"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_early_walk_v1(jsonb,text,text,integer,integer,integer)",
    "digest": "a1127ec95e0e470c0473ec006bbffe4a7a1b30a07f8e514d1a69fb10905a5052",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_seeds",
      "p_root_model",
      "p_root_id",
      "p_rows",
      "p_reads",
      "p_work"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_freshness_v1()",
    "digest": "c51c9eeb9de625b8282b552c6f92be83793e9c037d97c8e767c6830e64bb8347",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "trigger",
    "result_set": false,
    "language": "plpgsql",
    "argnames": null,
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_frontier_capture_v1(text,text,integer,integer)",
    "digest": "155ab3137a964daf79f7d4e0bfbe9df0c9d082b4fe14e28e252cb23078846c8e",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "record",
    "result_set": true,
    "language": "plpgsql",
    "argnames": [
      "p_model",
      "p_id",
      "p_rows",
      "p_reads",
      "frontier",
      "source_index",
      "cluster_states",
      "logical_rows",
      "logical_reads"
    ],
    "argmodes": [
      "i",
      "i",
      "i",
      "i",
      "t",
      "t",
      "t",
      "t",
      "t"
    ],
    "allargtypes": [
      "text",
      "text",
      "integer",
      "integer",
      "jsonb",
      "jsonb",
      "jsonb",
      "integer",
      "integer"
    ]
  },
  {
    "signature": "_authority_metadata_access_label_frontier_recheck_v1(jsonb,jsonb,jsonb,integer,integer)",
    "digest": "6a6b1aee2d333cd93cfdf2cbc5816036719190c439942e2f3f5dbce31bd00a25",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "record",
    "result_set": true,
    "language": "plpgsql",
    "argnames": [
      "p_frontier",
      "p_source_index",
      "p_cluster_states",
      "p_rows",
      "p_reads",
      "logical_rows",
      "logical_reads"
    ],
    "argmodes": [
      "i",
      "i",
      "i",
      "i",
      "i",
      "t",
      "t"
    ],
    "allargtypes": [
      "jsonb",
      "jsonb",
      "jsonb",
      "integer",
      "integer",
      "integer",
      "integer"
    ]
  },
  {
    "signature": "_authority_metadata_access_label_frontier_storage_v1()",
    "digest": "624a4fde07d4cbdcdf9178390332c4ce4ddd44e00b2784c0d475ede8e1aad898",
    "definer": false,
    "volatility": "s",
    "exported": false,
    "result_type": "boolean",
    "result_set": false,
    "language": "sql",
    "argnames": null,
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_grant_v2(regrole)",
    "digest": "b4403ceff3ac8fc3c40e13184c76b405d4d321b322bc0e87510252f6df96824f",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "void",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_runtime"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_held_frontier_v1(text,text,integer,integer)",
    "digest": "d17ebe86f78aa5e540792689502b52325fb04796e4649c62982fd88a6c428ea0",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "record",
    "result_set": true,
    "language": "plpgsql",
    "argnames": [
      "p_model",
      "p_id",
      "p_rows",
      "p_reads",
      "frontier",
      "source_index",
      "cluster_states",
      "logical_rows",
      "logical_reads",
      "held_rows"
    ],
    "argmodes": [
      "i",
      "i",
      "i",
      "i",
      "t",
      "t",
      "t",
      "t",
      "t",
      "t"
    ],
    "allargtypes": [
      "text",
      "text",
      "integer",
      "integer",
      "jsonb",
      "jsonb",
      "jsonb",
      "integer",
      "integer",
      "jsonb"
    ]
  },
  {
    "signature": "_authority_metadata_access_label_held_replay_v1(jsonb,jsonb,jsonb,integer,integer,integer)",
    "digest": "f5c3d793b42f4224239afbf3bfce68b61895b62fb4b01af967160d9478cd6f8c",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_packet",
      "p_closure",
      "p_plan",
      "p_rows",
      "p_reads",
      "p_work"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_held_source_v1(integer,text,text,integer,integer)",
    "digest": "581fe110a541b51ea8e678008906987660a541d2c2f4219bbf11a1feb7bbedbd",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_kind",
      "p_type",
      "p_id",
      "p_rows",
      "p_reads"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_hold_and_replay_v1(jsonb,boolean,integer,integer,integer)",
    "digest": "562b1315b1b11ac8692004ff99e4f1cf2d01adb355c9e4a319637a5a959a9926",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_patch",
      "p_rename",
      "p_rows",
      "p_reads",
      "p_work"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_origin_v1(text,text)",
    "digest": "c44e76add35923e06780067d14e936764fe3262bbfb277eb499ad1260bccc39c",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_table",
      "p_id"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_prefinal_carriers_v1(text,text,text,jsonb,jsonb,integer,integer,integer)",
    "digest": "3d841a54259f14fada16af120b6aed47a323f521e1ee77fa11d097e6a22e98b4",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_kind",
      "p_id",
      "p_old_xmin",
      "p_old",
      "p_new_access",
      "p_rows",
      "p_reads",
      "p_work"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_prepare_lockset_v1(text,text,text,jsonb,jsonb,jsonb,text[],integer,integer,integer)",
    "digest": "672dc4415221670568cfa3a3de79af1e28daccd103456297b2575cc5b7c98066",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_kind",
      "p_id",
      "p_old_xmin",
      "p_old",
      "p_new_access",
      "p_policy_expected",
      "p_policy_writes",
      "p_rows",
      "p_reads",
      "p_work"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_retained_select_v1(jsonb,timestamptz,integer)",
    "digest": "3cb055e64048503068577d680a32206ff246b804f572dae14ba73eaa0fe2291d",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_frozen",
      "p_at",
      "p_work"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_retention_accept_v1(text,text,integer,integer,integer)",
    "digest": "10f59d51004e3fbaaac5e93c1ef515fb8eadf44baaf602e57864acca770a35a4",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_actor_type",
      "p_actor_id",
      "p_rows",
      "p_reads",
      "p_work"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_retention_certify_v1(jsonb,jsonb,jsonb,jsonb,integer)",
    "digest": "4d3dadb58632329f4fbb1dd95f3006e7eba343c2f85ec99ee28e0c45fc525c72",
    "definer": false,
    "volatility": "i",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_index",
      "p_catalog",
      "p_plan",
      "p_desired",
      "p_work"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_retention_compile_v1(jsonb,integer)",
    "digest": "e9e490723a1273c03f346f99033671548f6249b6ef1951736797267638b0db87",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_desired",
      "p_work"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_retention_inputs_v1(jsonb,jsonb,integer)",
    "digest": "c4ec897ab06ca262142bf8fa0914d51baf890470b59d311a08f294d3bf256563",
    "definer": false,
    "volatility": "i",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_index",
      "p_plan",
      "p_work"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_retention_plan_v1(jsonb,jsonb,jsonb,jsonb,text,jsonb,jsonb,integer)",
    "digest": "16e5e9c0eab8e1cc435726cc74d6bfa240d221837af6274c859147e3a4ecee27",
    "definer": false,
    "volatility": "i",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_index",
      "p_catalog",
      "p_outputs",
      "p_old_outputs",
      "p_root_type",
      "p_old",
      "p_new",
      "p_work"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_retention_prepare_v1(jsonb,boolean,integer,integer,integer)",
    "digest": "4e30808c3cd9bed41b0ad03446e0778037bc2b11a8fba1df60a57cbb034322d6",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_patch",
      "p_rename",
      "p_rows",
      "p_reads",
      "p_work"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_runtime_cohort_v2(oid)",
    "digest": "4b20b61ecf869d8418628d2d2566bb9b74da60b7998177679375e002f0c3daef",
    "definer": false,
    "volatility": "s",
    "exported": false,
    "result_type": "boolean",
    "result_set": false,
    "language": "sql",
    "argnames": [
      "p_runtime"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_source_capture_v1(integer,text,text,integer,integer)",
    "digest": "fbed8261670d1e1aaf0d52574c03dc2a3fd27604555c0ddc095ea78f2a516274",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_kind",
      "p_type",
      "p_id",
      "p_rows",
      "p_reads"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_source_locks_v1(jsonb,jsonb,jsonb,integer,boolean)",
    "digest": "b53eba92033fe1c3f1ff5f2d122d1eca9c63cb1cc17d739b65d29fa9ccc1fa1d",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "integer",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_sources",
      "p_policy",
      "p_binding",
      "p_budget",
      "p_check"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_stash_v1(jsonb)",
    "digest": "3e37f89e0c84ddaf757331eeabe31f351b2d3e7493c131a03c716f60083a5909",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "void",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_prepared"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "_authority_metadata_access_label_stashed_v1()",
    "digest": "e50563c6d0bbc131d46e811c594a5fe8aabd8f8094522ed8fb82222cc449ec2e",
    "definer": false,
    "volatility": "v",
    "exported": false,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": null,
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "authority_metadata_access_label_accept_v2(text,text,integer,integer,integer)",
    "digest": "8909688924adf5a5d62632d0b3aff9f0fdf66e68483299e846b578d03ba00fe6",
    "definer": true,
    "volatility": "v",
    "exported": true,
    "result_type": "record",
    "result_set": true,
    "language": "plpgsql",
    "argnames": [
      "p_actor_type",
      "p_actor_id",
      "p_rows",
      "p_reads",
      "p_work",
      "used_rows",
      "used_reads",
      "used_work"
    ],
    "argmodes": [
      "i",
      "i",
      "i",
      "i",
      "i",
      "t",
      "t",
      "t"
    ],
    "allargtypes": [
      "text",
      "text",
      "integer",
      "integer",
      "integer",
      "integer",
      "integer",
      "integer"
    ]
  },
  {
    "signature": "authority_metadata_access_label_preflight_v2(jsonb,text,text,text,integer,integer,integer)",
    "digest": "d6cea33735bb57b901207445fc96685affc5c7c53581d1bb0eb37005167325ac",
    "definer": true,
    "volatility": "v",
    "exported": true,
    "result_type": "record",
    "result_set": true,
    "language": "plpgsql",
    "argnames": [
      "p_desired",
      "p_audit",
      "p_actor_type",
      "p_actor_id",
      "p_rows",
      "p_reads",
      "p_work",
      "used_rows",
      "used_reads",
      "used_work"
    ],
    "argmodes": [
      "i",
      "i",
      "i",
      "i",
      "i",
      "i",
      "i",
      "t",
      "t",
      "t"
    ],
    "allargtypes": [
      "jsonb",
      "text",
      "text",
      "text",
      "integer",
      "integer",
      "integer",
      "integer",
      "integer",
      "integer"
    ]
  },
  {
    "signature": "authority_metadata_access_label_prepare_v1(text,text,text,jsonb,jsonb,jsonb,text[],integer,integer,integer)",
    "digest": "c72e734982761f69bf23055032a3440a600cac6cc529663bbdff97e5cb46b49c",
    "definer": true,
    "volatility": "v",
    "exported": true,
    "result_type": "record",
    "result_set": true,
    "language": "plpgsql",
    "argnames": [
      "p_kind",
      "p_id",
      "p_old_xmin",
      "p_old",
      "p_new_access",
      "p_policy_expected",
      "p_policy_writes",
      "p_rows",
      "p_reads",
      "p_work",
      "used_rows",
      "used_reads",
      "used_work"
    ],
    "argmodes": [
      "i",
      "i",
      "i",
      "i",
      "i",
      "i",
      "i",
      "i",
      "i",
      "i",
      "t",
      "t",
      "t"
    ],
    "allargtypes": [
      "text",
      "text",
      "text",
      "jsonb",
      "jsonb",
      "jsonb",
      "text[]",
      "integer",
      "integer",
      "integer",
      "integer",
      "integer",
      "integer"
    ]
  },
  {
    "signature": "authority_metadata_access_label_retention_inputs_v1(jsonb,boolean,integer,integer,integer)",
    "digest": "3cc8a0bec6f9acdb137448dec13a7e38e0fa72fb52ec89cd8ca049cf3b511d8f",
    "definer": true,
    "volatility": "v",
    "exported": true,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_patch",
      "p_rename",
      "p_rows",
      "p_reads",
      "p_work"
    ],
    "argmodes": null,
    "allargtypes": null
  },
  {
    "signature": "authority_metadata_access_label_write_v1(text,text)",
    "digest": "42b01eb82596515d6ee62be5dc4befc2d7ccbc90c9e73c02a72f91833cc4d434",
    "definer": true,
    "volatility": "v",
    "exported": true,
    "result_type": "jsonb",
    "result_set": false,
    "language": "plpgsql",
    "argnames": [
      "p_kind",
      "p_id"
    ],
    "argmodes": null,
    "allargtypes": null
  }
]
$manifest$::jsonb;
 required text[]:=ARRAY[
  'authority_metadata_access_label_prepare_v1(text,text,text,jsonb,jsonb,jsonb,text[],integer,integer,integer)',
  'authority_metadata_access_label_retention_inputs_v1(jsonb,boolean,integer,integer,integer)',
  'authority_metadata_access_label_preflight_v2(jsonb,text,text,text,integer,integer,integer)',
  'authority_metadata_access_label_accept_v2(text,text,integer,integer,integer)',
  'authority_metadata_access_label_write_v1(text,text)',
  '_authority_metadata_access_label_runtime_cohort_v2(oid)',
  '_authority_metadata_access_label_grant_v2(regrole)',
  '_authority_metadata_access_label_compile_reserve_v1(jsonb,text,text,text,integer,integer,integer)',
  '_authority_metadata_access_label_retention_accept_v1(text,text,integer,integer,integer)',
  '_authority_metadata_access_label_retention_prepare_v1(jsonb,boolean,integer,integer,integer)',
  '_authority_metadata_access_label_retention_compile_v1(jsonb,integer)',
  '_authority_metadata_access_label_freshness_v1()',
  '_authority_metadata_access_label_origin_v1(text,text)'
 ];
BEGIN
 -- Согласовываем версию контракта со штатным клиентом.
 IF p_client_abi IS DISTINCT FROM 'metadata-access-label/owner-retention-v2' THEN RETURN false;END IF;
 SELECT c.relowner INTO owner_oid FROM pg_catalog.pg_class c
 WHERE c.oid=to_regclass('kaname.authority_writer_protocol');
 SELECT r.oid INTO invoker_oid FROM pg_catalog.pg_roles r
 WHERE r.rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 IF owner_oid IS NULL OR owner_oid<>current_user::regrole::oid OR invoker_oid IS NULL
  OR kaname._authority_metadata_access_label_runtime_cohort_v2(invoker_oid) IS DISTINCT FROM true
  OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true
  OR kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN RETURN false;END IF;
 -- Сверяем сохранённое состояние протокола и его режима.
 IF NOT EXISTS(SELECT 1 FROM kaname.authority_semantic_identity a
  CROSS JOIN kaname.authority_writer_protocol p CROSS JOIN kaname.authority_writer_contract c
  WHERE a.singleton AND p.singleton AND c.singleton
   AND a.protocol_version=p.protocol_version AND a.protocol_version=1
   AND a.model_id ~ '^[0-9a-f]{64}$' AND a.catalog_id ~ '^[0-9a-f]{64}$'
   AND coalesce(a.projector_version,'')<>''
   AND ((a.phase='prepared' AND p.enforcement='compatibility') OR (a.phase='active' AND p.enforcement='strict'))
   AND c.required_contract IN (1,2) AND c.staged_contract IN (1,2)) THEN RETURN false;END IF;
 IF NOT has_function_privilege(invoker_oid,'kaname.authority_protocol_read_bundle()','EXECUTE')
  OR NOT has_table_privilege(invoker_oid,'kaname.authority_semantic_identity','SELECT') THEN RETURN false;END IF;
 FOREACH target IN ARRAY ARRAY['accounts','projects'] LOOP
  IF NOT has_table_privilege(invoker_oid,to_regclass('kaname.'||target),'SELECT')
   OR EXISTS(SELECT 1 FROM unnest(ARRAY['name','description','labels','access_labels']) f
    WHERE NOT has_column_privilege(invoker_oid,to_regclass('kaname.'||target),f,'UPDATE')) THEN RETURN false;END IF;
 END LOOP;
 SELECT * INTO bundle FROM kaname.authority_protocol_read_bundle();
 IF NOT FOUND OR octet_length(bundle.catalog_json) NOT BETWEEN 1 AND 8388608
  OR encode(sha256(bundle.catalog_json),'hex') IS DISTINCT FROM bundle.catalog_id
  OR encode(sha256(convert_to(bundle.model_source,'UTF8')),'hex') IS DISTINCT FROM bundle.model_id
  OR NOT EXISTS(SELECT 1 FROM kaname.authority_semantic_identity a WHERE a.singleton
   AND a.model_id=bundle.model_id AND a.catalog_id=bundle.catalog_id AND a.projector_version=bundle.projector_version)
 THEN RETURN false;END IF;
 IF jsonb_typeof(manifest) IS DISTINCT FROM 'array' OR jsonb_array_length(manifest)<cardinality(required)
  OR EXISTS(SELECT 1 FROM unnest(required) s WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(manifest) m WHERE m->>'signature'=s))
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(manifest) m GROUP BY m->>'signature' HAVING count(*)<>1)
 THEN RETURN false;END IF;
 FOR item IN SELECT * FROM jsonb_to_recordset(manifest) x(
  signature text,digest text,definer boolean,volatility text,exported boolean,
  result_type text,result_set boolean,language text,argnames text[],argmodes text[],allargtypes text[]
 ) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  IF fn IS NULL OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=fn
   AND p.proowner=owner_oid AND p.prosecdef=item.definer AND p.provolatile::text=item.volatility
   AND p.prokind='f' AND p.prorettype=to_regtype(item.result_type) AND p.proretset=item.result_set
   AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname=item.language)
   AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[]
   AND NOT(p.proleakproof OR p.proisstrict) AND p.proparallel='u'
   AND p.pronargdefaults=0 AND p.provariadic=0
   AND p.proargnames IS NOT DISTINCT FROM item.argnames
   AND p.proargmodes::text[] IS NOT DISTINCT FROM item.argmodes
   AND p.proallargtypes IS NOT DISTINCT FROM (CASE WHEN item.allargtypes IS NULL THEN NULL ELSE
    ARRAY(SELECT to_regtype(t)::oid FROM unnest(item.allargtypes) WITH ORDINALITY q(t,n) ORDER BY n) END)
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=item.digest
   AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
    WHERE a.grantee<>owner_oid AND (NOT item.exported OR a.grantee=0 OR a.is_grantable
     OR a.privilege_type<>'EXECUTE'
     OR kaname._authority_metadata_access_label_runtime_cohort_v2(a.grantee) IS DISTINCT FROM true))
   AND (NOT item.exported OR has_function_privilege(invoker_oid,p.oid,'EXECUTE'))
  ) THEN RETURN false;END IF;
 END LOOP;
 -- Доступ к проверке готовности получает та же роль, что к защищённой записи.
 fn:=to_regprocedure('kaname.authority_metadata_access_label_ready_v2(text)');
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=owner_oid
  AND p.prosecdef AND p.provolatile='s' AND p.prorettype='boolean'::regtype
  AND NOT(p.proretset OR p.proisstrict OR p.proleakproof) AND p.proparallel='u'
  AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[]
  AND p.proargnames=ARRAY['p_client_abi']::text[] AND p.pronargdefaults=0 AND p.provariadic=0
  AND has_function_privilege(invoker_oid,p.oid,'EXECUTE')
  AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   WHERE a.grantee<>owner_oid AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE'
    OR kaname._authority_metadata_access_label_runtime_cohort_v2(a.grantee) IS DISTINCT FROM true))) THEN RETURN false;END IF;
 FOREACH target IN ARRAY ARRAY['accounts','projects'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t
   WHERE t.tgrelid=to_regclass('kaname.'||target) AND t.tgname='access_labels_000_commit_freshness'
    AND t.tgfoid=to_regprocedure('kaname._authority_metadata_access_label_freshness_v1()')
    AND t.tgtype=17 AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgnargs=0 AND t.tgattr=''::int2vector
    AND t.tgconstraint=0 AND NOT t.tgdeferrable AND NOT t.tginitdeferred
    AND pg_catalog.pg_get_triggerdef(t.oid) LIKE '% WHEN ((old.access_labels IS DISTINCT FROM new.access_labels)) EXECUTE FUNCTION %')
  THEN RETURN false;END IF;
 END LOOP;
 RETURN true;
END;
$ready$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_access_label_runtime_cohort_v2(p_runtime oid)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $cohort$
 SELECT p_runtime IS NOT NULL
  AND p_runtime<>(SELECT relowner FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass)
  AND EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE oid=p_runtime)
  AND NOT EXISTS(SELECT 1 FROM kaname.authority_role_actor_login WHERE singleton AND role_oid=p_runtime)
  AND NOT EXISTS(SELECT 1 FROM (VALUES
   ('kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'),
   ('kaname.authority_metadata_preflight_staged_v1(text,text,boolean,text,jsonb)')
  ) required(signature) WHERE NOT EXISTS(
   SELECT 1 FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
   WHERE p.oid=to_regprocedure(required.signature) AND a.grantee=p_runtime
    AND a.privilege_type='EXECUTE' AND NOT a.is_grantable))
$cohort$;

CREATE FUNCTION kaname._authority_metadata_access_label_grant_v2(p_runtime regrole)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $grant$
DECLARE signature text;runtime_name name;owner_oid oid;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 owner_oid:=current_user::regrole::oid;
 IF kaname._authority_metadata_access_label_runtime_cohort_v2(p_runtime::oid) IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'protected metadata runtime lacks both original grants or is the role-only actor' USING ERRCODE='42501';END IF;
 SELECT rolname INTO STRICT runtime_name FROM pg_catalog.pg_roles WHERE oid=p_runtime::oid;
 FOREACH signature IN ARRAY ARRAY[
  'authority_metadata_access_label_prepare_v1(text,text,text,jsonb,jsonb,jsonb,text[],integer,integer,integer)',
  'authority_metadata_access_label_retention_inputs_v1(jsonb,boolean,integer,integer,integer)',
  'authority_metadata_access_label_preflight_v2(jsonb,text,text,text,integer,integer,integer)',
  'authority_metadata_access_label_accept_v2(text,text,integer,integer,integer)',
  'authority_metadata_access_label_write_v1(text,text)',
  'authority_metadata_access_label_ready_v2(text)'
 ] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc WHERE oid=to_regprocedure('kaname.'||signature) AND proowner=owner_oid) THEN
   RAISE EXCEPTION 'protected metadata export missing or wrong owner: %',signature USING ERRCODE='55000';END IF;
  EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.%s TO %I',signature,runtime_name);
 END LOOP;
END;
$grant$;

DO $seal$
DECLARE signature text;recipient record;target oid;owner_oid oid;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 owner_oid:=current_user::regrole::oid;
 FOR signature IN SELECT p.oid::regprocedure::text FROM pg_catalog.pg_proc p
 JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='kaname'
 AND (p.proname LIKE '\_authority\_metadata\_access\_label\_%' ESCAPE '\'
  OR p.proname IN ('_authority_access_label_member_partition_v1','_authority_access_label_old_facts_v2'))
 UNION SELECT 'kaname.'||s FROM unnest(ARRAY[
  'authority_metadata_access_label_prepare_v1(text,text,text,jsonb,jsonb,jsonb,text[],integer,integer,integer)',
  'authority_metadata_access_label_retention_inputs_v1(jsonb,boolean,integer,integer,integer)',
  'authority_metadata_access_label_preflight_v2(jsonb,text,text,text,integer,integer,integer)',
  'authority_metadata_access_label_accept_v2(text,text,integer,integer,integer)',
  'authority_metadata_access_label_write_v1(text,text)',
  'authority_metadata_access_label_ready_v2(text)'
 ]) s LOOP
  target:=to_regprocedure(signature);
  IF target IS NULL OR (SELECT proowner FROM pg_catalog.pg_proc WHERE oid=target) IS DISTINCT FROM owner_oid THEN
   RAISE EXCEPTION 'metadata ACL target missing or wrong owner: %',signature USING ERRCODE='55000';END IF;
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',target::regprocedure);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
   JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=target AND a.grantee<>owner_oid LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',target::regprocedure,recipient.rolname);
  END LOOP;
 END LOOP;
END;
$seal$;

DO $existing_runtime$
DECLARE recipient record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 FOR recipient IN SELECT r.oid FROM pg_catalog.pg_roles r
 WHERE kaname._authority_metadata_access_label_runtime_cohort_v2(r.oid) LOOP
  PERFORM kaname._authority_metadata_access_label_grant_v2(recipient.oid::regrole);
 END LOOP;
END;
$existing_runtime$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $repin$
DECLARE item record;fn regprocedure;old_body text;new_body text;definition text;pair jsonb;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 FOR item IN SELECT * FROM (VALUES
 ('authority_protocol_grant_runtime(regrole)','90b9f746e64b79902c3c399dde9a2aed399f8445dea1491daf9e86161e814449','e1c3edd3c1dbebc005c988e73ce5d61eb377a7ab741138b2e3916ac83a1bc932',$patch$[[" END LOOP;\nEND ", " END LOOP;\n PERFORM kaname._authority_metadata_access_label_grant_v2(p_runtime);\nEND "]]$patch$::jsonb),
 ('_authority_crud_storage_v3()','56c2e296dc66ed338ef7a05eacc9530d3122ca0565f0cf812be7e4cc013a9406','b065686a1d4f6b384cb83e82e4f901837e8822aba9e1149fbc3b3d2fa21b59b3',$patch$[[" ('authority_protocol_grant_runtime(regrole)','90b9f746e64b79902c3c399dde9a2aed399f8445dea1491daf9e86161e814449',false,'v',true,'preserve'),", " ('authority_protocol_grant_runtime(regrole)','e1c3edd3c1dbebc005c988e73ce5d61eb377a7ab741138b2e3916ac83a1bc932',false,'v',true,'preserve'),\n ('_authority_metadata_access_label_runtime_cohort_v2(oid)','4b20b61ecf869d8418628d2d2566bb9b74da60b7998177679375e002f0c3daef',false,'s',true,'private'),\n ('_authority_metadata_access_label_grant_v2(regrole)','b4403ceff3ac8fc3c40e13184c76b405d4d321b322bc0e87510252f6df96824f',false,'v',true,'private'),"]]$patch$::jsonb),
 ('_authority_full_contract_storage_v3()','a001ff8d593802a5d1fe28dafc4e032ebba966ce5598dafab2f7b3c519482c8d','998549dbffbe38b59645c3821561f2e000301b271b355a8aa28834bb378bd07d',$patch$[["('_authority_crud_storage_v3()','56c2e296dc66ed338ef7a05eacc9530d3122ca0565f0cf812be7e4cc013a9406'", "('_authority_crud_storage_v3()','b065686a1d4f6b384cb83e82e4f901837e8822aba9e1149fbc3b3d2fa21b59b3'"]]$patch$::jsonb)
 ) changes(signature,before_hash,after_hash,replacements) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT prosrc INTO STRICT old_body FROM pg_catalog.pg_proc WHERE oid=fn;
  IF encode(sha256(convert_to(old_body,'UTF8')),'hex')<>item.before_hash THEN
   RAISE EXCEPTION 'metadata activation predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  new_body:=old_body;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.replacements) LOOP
   IF (length(new_body)-length(replace(new_body,pair->>0,'')))/length(pair->>0)<>1 THEN
    RAISE EXCEPTION 'metadata activation splice is not unique: %',item.signature USING ERRCODE='55000';END IF;
   new_body:=replace(new_body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(new_body,'UTF8')),'hex')<>item.after_hash THEN
   RAISE EXCEPTION 'metadata activation result differs: %',item.signature USING ERRCODE='55000';END IF;
  definition:=pg_get_functiondef(fn);
  IF position(old_body IN definition)=0 THEN RAISE EXCEPTION 'function body not found' USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,old_body,new_body);
 END LOOP;
 IF NOT kaname._authority_full_contract_storage_v3() THEN
  RAISE EXCEPTION 'metadata activation ordinary closure differs' USING ERRCODE='55000';END IF;
END;
$repin$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $repin$
DECLARE item record;fn regprocedure;old_body text;new_body text;definition text;pair jsonb;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 FOR item IN SELECT * FROM (VALUES
 ('_authority_full_contract_storage_v3()','998549dbffbe38b59645c3821561f2e000301b271b355a8aa28834bb378bd07d','a001ff8d593802a5d1fe28dafc4e032ebba966ce5598dafab2f7b3c519482c8d',$patch$[["('_authority_crud_storage_v3()','b065686a1d4f6b384cb83e82e4f901837e8822aba9e1149fbc3b3d2fa21b59b3'", "('_authority_crud_storage_v3()','56c2e296dc66ed338ef7a05eacc9530d3122ca0565f0cf812be7e4cc013a9406'"]]$patch$::jsonb),
 ('_authority_crud_storage_v3()','b065686a1d4f6b384cb83e82e4f901837e8822aba9e1149fbc3b3d2fa21b59b3','56c2e296dc66ed338ef7a05eacc9530d3122ca0565f0cf812be7e4cc013a9406',$patch$[[" ('authority_protocol_grant_runtime(regrole)','e1c3edd3c1dbebc005c988e73ce5d61eb377a7ab741138b2e3916ac83a1bc932',false,'v',true,'preserve'),\n ('_authority_metadata_access_label_runtime_cohort_v2(oid)','4b20b61ecf869d8418628d2d2566bb9b74da60b7998177679375e002f0c3daef',false,'s',true,'private'),\n ('_authority_metadata_access_label_grant_v2(regrole)','b4403ceff3ac8fc3c40e13184c76b405d4d321b322bc0e87510252f6df96824f',false,'v',true,'private'),", " ('authority_protocol_grant_runtime(regrole)','90b9f746e64b79902c3c399dde9a2aed399f8445dea1491daf9e86161e814449',false,'v',true,'preserve'),"]]$patch$::jsonb),
 ('authority_protocol_grant_runtime(regrole)','e1c3edd3c1dbebc005c988e73ce5d61eb377a7ab741138b2e3916ac83a1bc932','90b9f746e64b79902c3c399dde9a2aed399f8445dea1491daf9e86161e814449',$patch$[[" END LOOP;\n PERFORM kaname._authority_metadata_access_label_grant_v2(p_runtime);\nEND ", " END LOOP;\nEND "]]$patch$::jsonb)
 ) changes(signature,before_hash,after_hash,replacements) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT prosrc INTO STRICT old_body FROM pg_catalog.pg_proc WHERE oid=fn;
  IF encode(sha256(convert_to(old_body,'UTF8')),'hex')<>item.before_hash THEN
   RAISE EXCEPTION 'metadata activation predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  new_body:=old_body;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.replacements) LOOP
   IF (length(new_body)-length(replace(new_body,pair->>0,'')))/length(pair->>0)<>1 THEN
    RAISE EXCEPTION 'metadata activation splice is not unique: %',item.signature USING ERRCODE='55000';END IF;
   new_body:=replace(new_body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(new_body,'UTF8')),'hex')<>item.after_hash THEN
   RAISE EXCEPTION 'metadata activation result differs: %',item.signature USING ERRCODE='55000';END IF;
  definition:=pg_get_functiondef(fn);
  IF position(old_body IN definition)=0 THEN RAISE EXCEPTION 'function body not found' USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,old_body,new_body);
 END LOOP;
 IF NOT kaname._authority_full_contract_storage_v3() THEN
  RAISE EXCEPTION 'metadata activation ordinary closure differs' USING ERRCODE='55000';END IF;
END;
$repin$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $revoke$
DECLARE signature text;recipient record;target oid;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 FOREACH signature IN ARRAY ARRAY[
  'authority_metadata_access_label_prepare_v1(text,text,text,jsonb,jsonb,jsonb,text[],integer,integer,integer)',
  'authority_metadata_access_label_retention_inputs_v1(jsonb,boolean,integer,integer,integer)',
  'authority_metadata_access_label_preflight_v2(jsonb,text,text,text,integer,integer,integer)',
  'authority_metadata_access_label_accept_v2(text,text,integer,integer,integer)',
  'authority_metadata_access_label_write_v1(text,text)',
  'authority_metadata_access_label_ready_v2(text)'
 ] LOOP
  target:=to_regprocedure('kaname.'||signature);
  IF target IS NULL THEN RAISE EXCEPTION 'activation export missing' USING ERRCODE='55000';END IF;
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',target::regprocedure);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=target AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',target::regprocedure,recipient.rolname);
  END LOOP;
 END LOOP;
END;
$revoke$;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TRIGGER access_labels_000_commit_freshness ON kaname.projects;
DROP TRIGGER access_labels_000_commit_freshness ON kaname.accounts;
-- +goose StatementEnd

-- +goose StatementBegin
-- Проверка исходной схемы и смена тела выполняются в одной миграции.
DO $guard_pin$
BEGIN
 IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname.authority_access_label_storage_valid_v1()'::regprocedure) IS DISTINCT FROM 'a24dc7f2ffbb450fb0229aa05a3af307a831a106d673fa34f35424644f77016f'
 OR (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname.access_labels_immutable_v1()'::regprocedure) IS DISTINCT FROM '78051349c7cec4e3c5df8cdd8e11bc36243d9ad8d0c227fde363babfeaa258d9' THEN
  RAISE EXCEPTION 'access label storage guard differs before rollback' USING ERRCODE='55000';END IF;
END;
$guard_pin$;
CREATE OR REPLACE FUNCTION kaname.access_labels_immutable_v1() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME NOT IN
 ('accounts','projects','users','service_accounts','groups','roles','access_bindings','resource_mirror')
 OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_OP NOT IN ('INSERT','UPDATE') THEN
  RAISE EXCEPTION 'access label guard context invalid' USING ERRCODE='42501';
 END IF;
 IF (TG_OP='INSERT' AND NEW.access_labels IS DISTINCT FROM '{}'::jsonb)
 OR (TG_OP='UPDATE' AND NEW.access_labels IS DISTINCT FROM OLD.access_labels) THEN
  RAISE EXCEPTION 'access label mutation requires a protected writer' USING ERRCODE='42501';
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION kaname.authority_access_label_storage_valid_v1() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE owner_oid oid;target text;relation_id oid;column_number smallint;expected record;
BEGIN
 SELECT relowner INTO owner_oid FROM pg_class WHERE oid='kaname.authority_writer_protocol'::regclass;
 IF owner_oid IS DISTINCT FROM (SELECT oid FROM pg_roles WHERE rolname=current_user) THEN RETURN false;END IF;
 FOR expected IN SELECT * FROM (VALUES
 ('access_labels_valid_v1(jsonb)','5bdcbf012ab0dee0838575bc22c3109d97483e1caf2f5543d810f46be03f9c60',false,'i'),
 ('access_labels_immutable_v1()','ebae429f31cb7558e7c01285fd82e947de6470eb1acc921bab06f46251f62046',false,'v')
 ) p(signature,digest,definer,volatility) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid=to_regprocedure('kaname.'||expected.signature)
   AND p.proowner=owner_oid AND p.prosecdef=expected.definer AND p.provolatile::text=expected.volatility
   AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=expected.digest
   AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
    WHERE a.grantee<>owner_oid AND NOT (expected.signature='access_labels_valid_v1(jsonb)'
     AND a.grantee=0 AND a.privilege_type='EXECUTE' AND NOT a.is_grantable))) THEN RETURN false;END IF;
 END LOOP;
 -- Проверяем только собственный footprint; чужие штатные триггеры не запрещаем.
 FOREACH target IN ARRAY ARRAY['accounts','projects','users','service_accounts','groups','roles','access_bindings','resource_mirror'] LOOP
  relation_id:=to_regclass('kaname.'||target);
  IF NOT EXISTS(SELECT 1 FROM pg_class WHERE oid=relation_id AND relowner=owner_oid AND relkind='r') THEN RETURN false;END IF;
  SELECT a.attnum INTO column_number FROM pg_attribute a JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
   WHERE a.attrelid=relation_id AND a.attname='access_labels' AND NOT a.attisdropped
    AND a.atttypid='jsonb'::regtype AND a.attnotnull AND a.attgenerated=''
    AND pg_get_expr(d.adbin,d.adrelid)='''{}''::jsonb';
  IF column_number IS NULL THEN RETURN false;END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid=relation_id AND c.conname='access_labels_valid'
   AND c.contype='c' AND c.convalidated AND NOT c.connoinherit AND c.conkey=ARRAY[column_number]
   AND pg_get_expr(c.conbin,c.conrelid)='kaname.access_labels_valid_v1(access_labels)') THEN RETURN false;END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=relation_id AND t.tgname='access_labels_immutable'
   AND t.tgfoid='kaname.access_labels_immutable_v1()'::regprocedure AND t.tgtype=23
   AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgnargs=0 AND t.tgqual IS NULL AND t.tgattr=''::int2vector)
  THEN RETURN false;END IF;
 END LOOP;
 RETURN true;
END $$;
DO $guard_pin$
BEGIN
 IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname.authority_access_label_storage_valid_v1()'::regprocedure) IS DISTINCT FROM '0acf348156e88d80a71cdc67c6a0a952719e1e288e657ec565a8986fb92d2f12'
 OR (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname.access_labels_immutable_v1()'::regprocedure) IS DISTINCT FROM 'ebae429f31cb7558e7c01285fd82e947de6470eb1acc921bab06f46251f62046' THEN
  RAISE EXCEPTION 'access label storage guard differs before restore' USING ERRCODE='55000';END IF;
END;
$guard_pin$;
-- +goose StatementEnd

DROP FUNCTION kaname.authority_metadata_access_label_ready_v2(text);
DROP FUNCTION kaname.authority_metadata_access_label_accept_v2(text,text,integer,integer,integer);
DROP FUNCTION kaname.authority_metadata_access_label_preflight_v2(jsonb,text,text,text,integer,integer,integer);
DROP FUNCTION kaname.authority_metadata_access_label_retention_inputs_v1(jsonb,boolean,integer,integer,integer);
DROP FUNCTION kaname.authority_metadata_access_label_prepare_v1(text,text,text,jsonb,jsonb,jsonb,text[],integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_access_label_retention_accept_v1(text,text,integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_access_label_compile_reserve_v1(jsonb,text,text,text,integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_access_label_grant_v2(regrole);
DROP FUNCTION kaname._authority_metadata_access_label_runtime_cohort_v2(oid);
