-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- До окончательного времени решения владелец резервирует версию зеркала,
-- поколение отзыва и две выходные строки. Пустой journal не снимает
-- отложенную проверку _authority_metadata_mirror_complete_v1.
-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_mirror_reserve_v1(
 p_compiled jsonb,p_audit text,p_actor_type text,p_actor_id text,
 p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $reserve$
DECLARE
 prepared jsonb; compiled jsonb; receipt jsonb; physical jsonb; held jsonb;
 dotted text; object_id text; account_id text; old_row jsonb; new_row jsonb;
 requirements jsonb; sources jsonb; carry jsonb; facts jsonb;
 identity jsonb; actor jsonb; command jsonb; frozen jsonb;
 fields text[]; audit_row kaname.audit_outbox; reconcile_row kaname.resource_reconcile_outbox;
 invoker oid; epoch_key text; count_inputs integer;
 -- Верхний предел фиксированных точечных операций, включая резерв трёх
 -- точечных чтений при commit и восемь логических чтений пустого sequence.
 used_rows integer:=32; used_reads integer:=64; used_work integer:=32;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
  OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
  OR p_work IS NULL OR p_work NOT BETWEEN used_work AND 400000 THEN
  RAISE EXCEPTION 'external metadata reserve budget exhausted' USING ERRCODE='54000';
 END IF;
 IF coalesce(p_audit,'') !~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$'
  OR coalesce(p_actor_type,'') NOT IN ('user','service_account')
  OR coalesce(p_actor_id,'')='' OR p_actor_id ~ '[:#*[:space:][:cntrl:]]' THEN
  RAISE EXCEPTION 'external metadata actor or audit identifier invalid' USING ERRCODE='42501';
 END IF;
 prepared:=kaname._authority_metadata_access_label_stashed_v1();
 -- Штатный BEFORE STATEMENT для UPDATE зеркала возьмёт этот самый замок.
 -- Не допускаем ожидания за регистрацией после окончательного решения.
 IF NOT pg_try_advisory_xact_lock(hashtextextended('kaname.resource_registration_writers',0)) THEN
  RAISE EXCEPTION 'external metadata registration writer busy' USING ERRCODE='40001';
 END IF;
 -- Тот же RX понадобится физическому UPDATE после final clock.
 LOCK TABLE ONLY kaname.resource_mirror IN ROW EXCLUSIVE MODE NOWAIT;
 epoch_key:=kaname._authority_metadata_mirror_epoch_hold_v1();
 compiled:=p_compiled;
 used_rows:=used_rows+(compiled->>'rows')::integer;
 used_reads:=used_reads+(compiled->>'reads')::integer;
 used_work:=used_work+(compiled->>'work')::integer;
 receipt:=compiled->'receipt'; physical:=compiled->'root_physical';
 dotted:=receipt->>'root_type'; object_id:=receipt->>'root_id';
 old_row:=compiled->'old_row'; new_row:=compiled->'new_row';
 held:=prepared#>'{root,census,root_scope_states}'; account_id:=held#>>'{account,2,id}';
 requirements:=compiled->'resource_requirements';
 IF old_row IS DISTINCT FROM prepared#>'{retention,old_row}'
  OR new_row IS DISTINCT FROM prepared#>'{retention,new_row}'
  OR physical IS DISTINCT FROM prepared#>'{retention,root_physical}'
  OR physical->>'object_type' IS DISTINCT FROM dotted OR physical->>'id' IS DISTINCT FROM object_id
  OR receipt->'old_labels' IS DISTINCT FROM old_row->'access_labels'
  OR receipt->'new_labels' IS DISTINCT FROM new_row->'access_labels'
  OR requirements IS DISTINCT FROM prepared#>'{retention,resource_requirements}'
  OR jsonb_typeof(requirements) IS DISTINCT FROM 'array'
  OR jsonb_typeof(receipt->'facts') IS DISTINCT FROM 'array'
  OR jsonb_typeof(compiled->'retention') IS DISTINCT FROM 'object'
  OR coalesce(held#>>'{catalog,2,object_type}','')='' OR held#>>'{catalog,2,dotted}' IS DISTINCT FROM dotted
  OR prepared#>>'{root,root_update_verb,2,verb}' IS DISTINCT FROM 'update'
  OR used_rows IS NULL OR used_reads IS NULL OR used_work IS NULL THEN
  RAISE EXCEPTION 'external metadata compiler receipt changed' USING ERRCODE='42501';
 END IF;
 sources:=kaname._authority_resource_access_label_sources_hold_v1(
  p_actor_type,p_actor_id,requirements,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+(sources->>'rows')::integer; used_reads:=used_reads+(sources->>'reads')::integer;
 carry:=kaname._authority_metadata_access_label_carry_v1(
  dotted,object_id,old_row->'access_labels',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+(carry->>'rows')::integer; used_reads:=used_reads+(carry->>'reads')::integer;
 count_inputs:=jsonb_array_length(receipt->'facts')+jsonb_array_length(carry->'prior_facts');
 IF count_inputs IS NULL OR used_rows IS NULL OR used_rows+count_inputs>p_rows
  OR used_reads IS NULL OR used_reads>p_reads OR used_work+2*count_inputs>p_work THEN
  RAISE EXCEPTION 'external metadata freshness budget exhausted' USING ERRCODE='54000';
 END IF;
 SELECT coalesce(jsonb_agg(f ORDER BY f::text COLLATE "C"),'[]'::jsonb) INTO facts
 FROM (SELECT value f FROM jsonb_array_elements(receipt->'facts')
  UNION SELECT value FROM jsonb_array_elements(carry->'prior_facts')) AS merged;
 used_rows:=used_rows+jsonb_array_length(facts); used_work:=used_work+count_inputs+jsonb_array_length(facts);

 -- Обычные INSERT и перенос ID используют эти же advisory keys. Проверяем
 -- физические таблицы и GENERATED ALWAYS до выделения единственного ID.
 invoker:=(prepared#>>'{plan,invoker_oid}')::oid;
 IF NOT coalesce(has_table_privilege(invoker,'kaname.resource_mirror','SELECT'),false)
  OR NOT coalesce(has_column_privilege(invoker,'kaname.resource_mirror','access_labels','UPDATE'),false)
  OR (old_row->'labels' IS DISTINCT FROM new_row->'labels' AND
   NOT coalesce(has_column_privilege(invoker,'kaname.resource_mirror','labels','UPDATE'),false)) THEN
  RAISE EXCEPTION 'external metadata original row read or column write access missing' USING ERRCODE='42501';
 END IF;
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
 fields:=CASE WHEN old_row->'labels' IS DISTINCT FROM new_row->'labels'
  THEN ARRAY['labels','access_labels'] ELSE ARRAY['access_labels'] END;
 actor:=sources->'actor';
 audit_row.id:=p_audit; audit_row.event_type:='iam.resource_metadata.access_labels_updated';
 audit_row.tenant_account_id:=account_id; audit_row.status:='pending'; audit_row.attempts:=0;
 audit_row.created_at:=transaction_timestamp(); audit_row.next_attempt_at:=audit_row.created_at;
 audit_row.event_payload:=jsonb_build_object('actor',actor,'resource_type',dotted,'resource_id',object_id,
  'account_id',account_id,'changed_fields',fields);
 reconcile_row.object_type:=dotted; reconcile_row.object_id:=object_id; reconcile_row.event_type:='mirror.upsert';
 reconcile_row.created_at:=audit_row.created_at; reconcile_row.attempt_count:=0;
 identity:=jsonb_build_object('dotted',dotted,'id',object_id,'model',held#>>'{catalog,2,object_type}',
  'account_id',account_id,'project_id',coalesce(held#>>'{project,2,id}',''),
  'catalog_state',held->'catalog','update_state',prepared#>'{root,root_update_verb}');
 command:=jsonb_build_object('identity',identity,'old',old_row,'new',new_row,'physical',physical,
  'audit_row',to_jsonb(audit_row),'reconcile_row',to_jsonb(reconcile_row),'completion_reads',3);
 frozen:=jsonb_build_object('kind','metadata.mirror','mode','external_access_labels','mirror_command',command,
  'mirror_state',jsonb_build_object('root_applied',false,'root_after',NULL,'audit_consumed',false,'reconcile_consumed',false),
  'mirror_write_epoch',epoch_key,'access_label_root_physical',physical,'access_label_audit_id',p_audit,
  'access_label_authority',sources,'access_label_requirements',requirements,
  'access_label_freshness',jsonb_build_object('root_type',dotted,'root_id',object_id,'old_labels',receipt->'old_labels',
   'new_labels',receipt->'new_labels','prior_generation',carry->'prior_generation','facts',facts),
  'access_label_freshness_proofs',jsonb_build_object('candidate_facts',receipt->'facts',
   'prior_facts',carry->'prior_facts','retention',compiled->'retention'));
 PERFORM kaname._authority_sequence_reserve_v3('metadata','[]'::jsonb,8);
 PERFORM kaname._authority_sequence_freeze_v3(frozen);
 RETURN jsonb_build_object('rows',used_rows,'reads',used_reads,'work',used_work);
EXCEPTION WHEN lock_not_available THEN
 RAISE EXCEPTION 'external metadata output reservation changed' USING ERRCODE='40001';
END;
$reserve$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE target regprocedure:='kaname._authority_metadata_mirror_reserve_v1(jsonb,text,text,text,integer,integer,integer)'::regprocedure;
 recipient record;
BEGIN
 EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',target);
 FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=target AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',target,recipient.rolname);
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_metadata_mirror_reserve_v1(jsonb,text,text,text,integer,integer,integer);
