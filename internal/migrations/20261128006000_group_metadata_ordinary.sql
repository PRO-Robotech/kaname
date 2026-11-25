-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Содержимое событий выводится из реальной разницы. Резервирование и проверка
-- выбранной команды используют один формат. Время строк задают DEFAULT таблиц.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_ordinary_outputs_v1(
    p_old jsonb,p_new jsonb,p_actor text,p_audit text,p_reconcile bigint
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $outputs$
DECLARE
    fields jsonb;
    origin jsonb;
    row_value jsonb;
    maximum jsonb:='[]';
    audit kaname.audit_outbox;
    reconcile kaname.resource_reconcile_outbox;
    gid text:=p_old->>'id';
    account text:=p_old->>'account_id';
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF jsonb_typeof(p_old) IS DISTINCT FROM 'object' OR jsonb_typeof(p_new) IS DISTINCT FROM 'object'
        OR p_old-ARRAY['name','description','labels'] IS DISTINCT FROM p_new-ARRAY['name','description','labels']
        OR coalesce(gid,'')='' OR coalesce(account,'')='' OR coalesce(p_actor,'')='' THEN
        RAISE EXCEPTION 'invalid ordinary group images' USING ERRCODE='42501';
    END IF;
    SELECT coalesce(jsonb_agg(k ORDER BY n),'[]') INTO fields
    FROM unnest(ARRAY['name','description','labels']) WITH ORDINALITY f(k,n)
    WHERE p_old->k IS DISTINCT FROM p_new->k;
    IF (fields='[]') IS DISTINCT FROM (p_audit IS NULL)
        OR (p_audit IS NOT NULL AND p_audit COLLATE "C" !~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$')
        OR (fields ? 'labels') IS DISTINCT FROM (p_reconcile IS NOT NULL) OR p_reconcile<=0 THEN
        RAISE EXCEPTION 'ordinary group output identifier differs from change' USING ERRCODE='42501';
    END IF;
    IF p_audit IS NOT NULL THEN
        origin:=jsonb_build_object('table','groups','operation','UPDATE','when','AFTER','old',p_old,'new',p_new);
        row_value:=jsonb_build_object('resource_kind','iam_group','resource_id',gid,
            'scope',kaname.resource_journal_scope('iam_group',p_new),'project_id',kaname.resource_journal_project('iam_group',p_new),
            'event_type','UPDATED','payload',jsonb_build_object('id',gid));
        maximum:=jsonb_build_array(jsonb_build_object('table','resource_journal','origin',origin,'ordinal',1,
            'row',row_value,'stamp','transaction'));
        audit.id:=p_audit;
        audit.event_type:='iam.group.updated';
        audit.tenant_account_id:=account;
        audit.event_payload:=jsonb_build_object('actor',p_actor,'resource_type','group','resource_id',gid,
            'account_id',account,'changed_fields',fields);
        audit.status:='pending';
        audit.attempts:=0;
        audit.created_at:=transaction_timestamp();
        audit.next_attempt_at:=audit.created_at;
    END IF;
    IF p_reconcile IS NOT NULL THEN
        reconcile.id:=p_reconcile;
        reconcile.object_type:='iam.group';
        reconcile.object_id:=gid;
        reconcile.event_type:='mirror.upsert';
        reconcile.created_at:=transaction_timestamp();
        reconcile.attempt_count:=0;
    END IF;
    RETURN jsonb_build_object('changed_fields',fields,'maximum',maximum,
        'audit_row',CASE WHEN p_audit IS NOT NULL THEN to_jsonb(audit) END,
        'reconcile_row',CASE WHEN p_reconcile IS NOT NULL THEN to_jsonb(reconcile) END);
END;
$outputs$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_ordinary_reserve_v1(
    p_id text,p_xmin text,p_ctid text,p_old jsonb,p_patch jsonb,p_actor_type text,p_actor_id text,p_audit text,
    p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $reserve$
DECLARE
    proof jsonb;
    target jsonb;
    actual jsonb;
    next_row jsonb;
    account text;
    changed boolean;
    labels_changed boolean;
    mode_name text;
    policy_key text:='group:'||p_id;
    policy_epoch jsonb;
    binding_epoch jsonb;
    actor_after jsonb;
    actor_rel regclass;
    rel regclass;
    invoker oid;
    field text;
    outputs jsonb;
    scope record;
    command jsonb;
    custody jsonb;
    reconcile_id bigint;
    used_rows integer:=32;
    used_reads integer:=32;
    used_work integer:=32;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
        OR p_work IS NULL OR p_work NOT BETWEEN used_work AND 400000 THEN
        RAISE EXCEPTION 'ordinary group reserve budget exhausted' USING ERRCODE='54000';
    END IF;
    proof:=kaname.authority_protocol_attestation();
    IF proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'full'
        OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
        OR current_setting('session_replication_role') NOT IN ('origin','local')
        OR kaname._authority_sequence_store_v3() IS NOT NULL THEN
        RAISE EXCEPTION 'ordinary group reserve requires pending full resource writer' USING ERRCODE='42501';
    END IF;
    IF jsonb_typeof(p_patch) IS DISTINCT FROM 'object' OR octet_length(p_patch::text)>8388608
        OR p_patch-ARRAY['access_labels','name','description','labels']<>'{}'
        OR NOT (p_patch ? 'access_labels') OR kaname.access_labels_valid_v1(p_patch->'access_labels') IS DISTINCT FROM true
        OR (p_patch ? 'name' AND (jsonb_typeof(p_patch->'name') IS DISTINCT FROM 'string'
            OR (p_patch->>'name') COLLATE "C" !~ '^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$'))
        OR (p_patch ? 'description' AND (jsonb_typeof(p_patch->'description') IS DISTINCT FROM 'string'
            OR length(p_patch->>'description')>256))
        OR (p_patch ? 'labels' AND kaname.labels_valid(p_patch->'labels') IS DISTINCT FROM true) THEN
        RAISE EXCEPTION 'invalid ordinary group patch' USING ERRCODE='42501';
    END IF;
    IF p_patch ? 'labels' AND EXISTS(SELECT FROM jsonb_each(p_patch->'labels') x WHERE jsonb_typeof(x.value)<>'string') THEN
        RAISE EXCEPTION 'ordinary group labels require string values' USING ERRCODE='42501';
    END IF;
    target:=kaname._authority_metadata_group_target_v1(p_id,p_xmin,p_ctid,p_old,p_actor_type,p_actor_id,1,1);
    account:=target->>'root_account';
    IF p_patch->'access_labels' IS DISTINCT FROM p_old->'access_labels' OR octet_length(p_old::text)>8388608 THEN
        RAISE EXCEPTION 'ordinary group requires unchanged protected labels' USING ERRCODE='42501';
    END IF;
    next_row:=p_old||p_patch;
    changed:=p_old IS DISTINCT FROM next_row;
    labels_changed:=p_old->'labels' IS DISTINCT FROM next_row->'labels';
    mode_name:=CASE WHEN changed THEN 'ordinary' ELSE 'noop' END;
    IF changed IS DISTINCT FROM (p_audit IS NOT NULL) THEN
        RAISE EXCEPTION 'ordinary group audit differs from held change' USING ERRCODE='42501';
    END IF;
    invoker:=(proof->>'invoker_oid')::oid;
    actor_rel:=CASE p_actor_type WHEN 'user' THEN 'kaname.users'::regclass ELSE 'kaname.service_accounts'::regclass END;
    IF changed THEN
        LOCK TABLE ONLY kaname.authority_policy_epoch, ONLY kaname.authority_binding_epoch IN ROW EXCLUSIVE MODE NOWAIT;
        IF p_old->'name' IS DISTINCT FROM next_row->'name' THEN
            -- Стабилизируем имена до решения. Конфликт сообщит ограничение
            -- groups_account_name_unique при разрешённом UPDATE.
            LOCK TABLE ONLY kaname.groups IN SHARE ROW EXCLUSIVE MODE NOWAIT;
        ELSE
            LOCK TABLE ONLY kaname.groups IN ROW EXCLUSIVE MODE NOWAIT;
        END IF;
        LOCK TABLE ONLY kaname.audit_outbox IN ROW EXCLUSIVE MODE NOWAIT;
        IF labels_changed THEN
            LOCK TABLE ONLY kaname.resource_reconcile_outbox IN ROW EXCLUSIVE MODE NOWAIT;
        END IF;
    ELSE
        LOCK TABLE ONLY kaname.groups, ONLY kaname.authority_policy_epoch, ONLY kaname.authority_binding_epoch IN ROW SHARE MODE NOWAIT;
    END IF;
    EXECUTE format('LOCK TABLE ONLY %s IN ROW SHARE MODE NOWAIT',actor_rel);
    FOREACH rel IN ARRAY ARRAY['kaname.groups'::regclass,actor_rel,'kaname.authority_policy_epoch'::regclass,
        'kaname.authority_binding_epoch'::regclass,
        CASE WHEN changed THEN 'kaname.audit_outbox'::regclass END,
        CASE WHEN labels_changed THEN 'kaname.resource_reconcile_outbox'::regclass END] LOOP
        IF rel IS NOT NULL AND NOT EXISTS(SELECT FROM pg_catalog.pg_class c WHERE c.oid=rel AND c.relkind='r'
            AND c.relpersistence='p' AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relhasrules OR c.relispartition)
            AND NOT EXISTS(SELECT FROM pg_catalog.pg_inherits i WHERE i.inhrelid=rel OR i.inhparent=rel)) THEN
            RAISE EXCEPTION 'ordinary group requires exact physical relation' USING ERRCODE='42501';
        END IF;
    END LOOP;
    IF NOT coalesce(has_table_privilege(invoker,'kaname.groups','SELECT') AND has_table_privilege(invoker,actor_rel,'SELECT'),false)
        OR (changed AND has_table_privilege(invoker,'kaname.audit_outbox','INSERT') IS DISTINCT FROM true)
        OR (labels_changed AND NOT coalesce(has_table_privilege(invoker,'kaname.resource_reconcile_outbox','INSERT')
            AND has_sequence_privilege(invoker,'kaname.resource_reconcile_outbox_id_seq','USAGE,UPDATE'),false)) THEN
        RAISE EXCEPTION 'ordinary group original login privileges missing' USING ERRCODE='42501';
    END IF;
    FOREACH field IN ARRAY ARRAY['name','description','labels'] LOOP
        IF p_old->field IS DISTINCT FROM next_row->field
            AND has_column_privilege(invoker,'kaname.groups',field,'UPDATE') IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'ordinary group original column privilege missing' USING ERRCODE='42501';
        END IF;
    END LOOP;
    -- При глобальной ограде statement-триггер всё равно пишет group:<id>.
    -- Сначала закрепляем ключи отсутствия, затем версии существующих строк эпох.
    PERFORM kaname._authority_metadata_access_label_source_locks_v1('{}',jsonb_build_object(
        '*',CASE WHEN proof->>'mode'='global' THEN 'write' ELSE 'share' END,
        'scope:'||account,'share',policy_key,CASE WHEN changed THEN 'write' ELSE 'share' END),
        jsonb_build_object('','share',account,CASE WHEN changed THEN 'write' ELSE 'share' END),5,false);
    IF proof->>'mode'='global' THEN
        PERFORM FROM ONLY kaname.authority_policy_epoch e WHERE e.key='*' FOR UPDATE NOWAIT;
    ELSE
        PERFORM FROM ONLY kaname.authority_policy_epoch e WHERE e.key='*' FOR SHARE NOWAIT;
    END IF;
    IF NOT FOUND THEN RAISE EXCEPTION 'ordinary group policy root absent' USING ERRCODE='40001';END IF;
    IF changed THEN
        SELECT jsonb_build_array(e.generation,e.revision) INTO policy_epoch FROM ONLY kaname.authority_policy_epoch e
        WHERE e.key=policy_key FOR UPDATE NOWAIT;
    ELSE
        SELECT jsonb_build_array(e.generation,e.revision) INTO policy_epoch FROM ONLY kaname.authority_policy_epoch e
        WHERE e.key=policy_key FOR SHARE NOWAIT;
    END IF;
    PERFORM FROM ONLY kaname.authority_policy_epoch e WHERE e.key='scope:'||account FOR SHARE NOWAIT;
    IF NOT FOUND OR policy_epoch IS NULL THEN RAISE EXCEPTION 'ordinary group policy epoch absent' USING ERRCODE='40001';END IF;
    PERFORM FROM ONLY kaname.authority_binding_epoch e WHERE e.scope='' FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'ordinary group binding root absent' USING ERRCODE='40001';END IF;
    IF changed THEN
        SELECT jsonb_build_array(e.generation,e.revision) INTO binding_epoch FROM ONLY kaname.authority_binding_epoch e
        WHERE e.scope=account FOR UPDATE NOWAIT;
        SELECT jsonb_build_array(g.xmin::text,g.ctid::text,to_jsonb(g)) INTO actual FROM ONLY kaname.groups g
        WHERE g.id=p_id FOR UPDATE NOWAIT;
    ELSE
        SELECT jsonb_build_array(e.generation,e.revision) INTO binding_epoch FROM ONLY kaname.authority_binding_epoch e
        WHERE e.scope=account FOR SHARE NOWAIT;
        SELECT jsonb_build_array(g.xmin::text,g.ctid::text,to_jsonb(g)) INTO actual FROM ONLY kaname.groups g
        WHERE g.id=p_id FOR SHARE NOWAIT;
    END IF;
    IF binding_epoch IS NULL OR actual IS DISTINCT FROM target->'root_state' THEN
        RAISE EXCEPTION 'ordinary group held physical root changed' USING ERRCODE='40001';
    END IF;
    EXECUTE format('SELECT jsonb_build_array(a.xmin::text,a.ctid::text) FROM ONLY %s a WHERE a.id=$1 FOR SHARE NOWAIT',actor_rel)
        INTO actor_after USING p_actor_id;
    IF actor_after IS NULL THEN RAISE EXCEPTION 'ordinary group actor absent' USING ERRCODE='42501';END IF;
    IF changed THEN
        IF kaname.authority_policy_keys('groups',p_old) IS DISTINCT FROM ARRAY[policy_key]
            OR kaname.authority_policy_keys('groups',next_row) IS DISTINCT FROM ARRAY[policy_key]
            OR kaname.authority_binding_epoch_scope('groups',p_old) IS DISTINCT FROM account
            OR kaname.authority_binding_epoch_scope('groups',next_row) IS DISTINCT FROM account THEN
            RAISE EXCEPTION 'ordinary group trigger scope differs' USING ERRCODE='40001';
        END IF;
        IF proof->>'mode'='accounts' THEN
            SELECT * INTO STRICT scope FROM kaname.authority_group_object_scopes(p_id,account);
            IF scope.global_scope IS DISTINCT FROM false OR cardinality(scope.accounts)=0
                OR (proof->'accounts' ?& scope.accounts) IS DISTINCT FROM true THEN
                RAISE EXCEPTION 'ordinary group needs restaged object scopes' USING ERRCODE='40001';
            END IF;
        END IF;
        IF NOT pg_try_advisory_xact_lock(1262569298,hashtext(p_audit)) THEN
            RAISE EXCEPTION 'ordinary group audit ID busy' USING ERRCODE='40001';
        END IF;
        IF EXISTS(SELECT FROM ONLY kaname.audit_outbox a WHERE a.id=p_audit) THEN
            RAISE EXCEPTION 'ordinary group audit ID busy' USING ERRCODE='40001';
        END IF;
    END IF;
    IF changed AND EXISTS (SELECT FROM (VALUES
        ('kaname.audit_outbox'::regclass,'authority_audit_id_guard_v2','kaname.authority_audit_id_guard_v2()'::regprocedure,true),
        ('kaname.resource_reconcile_outbox'::regclass,'authority_reconcile_id_guard_v2',
            'kaname.authority_reconcile_id_guard_v2()'::regprocedure,labels_changed)
    ) need(rel,name,fn,required) WHERE need.required AND NOT EXISTS(
        SELECT FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_attribute a ON a.attrelid=t.tgrelid AND a.attname='id'
        WHERE t.tgrelid=need.rel AND t.tgname=need.name AND t.tgfoid=need.fn AND t.tgtype=23
            AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal AND t.tgqual IS NULL AND t.tgattr::text=a.attnum::text
    )) THEN
        RAISE EXCEPTION 'ordinary group output guard differs' USING ERRCODE='42501';
    END IF;
    IF labels_changed THEN
        IF to_regclass(pg_get_serial_sequence('kaname.resource_reconcile_outbox','id'))
            IS DISTINCT FROM 'kaname.resource_reconcile_outbox_id_seq'::regclass THEN
            RAISE EXCEPTION 'ordinary group reconcile identity differs' USING ERRCODE='42501';
        END IF;
        reconcile_id:=nextval('kaname.resource_reconcile_outbox_id_seq');
        IF reconcile_id<=0 OR NOT pg_try_advisory_xact_lock(1262569299,hashtext(reconcile_id::text)) THEN
            RAISE EXCEPTION 'ordinary group reconcile ID busy' USING ERRCODE='40001';
        END IF;
        IF EXISTS(SELECT FROM ONLY kaname.resource_reconcile_outbox r WHERE r.id=reconcile_id) THEN
            RAISE EXCEPTION 'ordinary group reconcile ID busy' USING ERRCODE='40001';
        END IF;
    END IF;
    outputs:=kaname._authority_metadata_group_ordinary_outputs_v1(p_old,next_row,p_actor_id,p_audit,reconcile_id);
    used_reads:=used_reads+kaname._authority_sequence_reserve_v3('metadata',outputs->'maximum',least(16,p_reads-used_reads));
    SELECT jsonb_object_agg(t.key,t.value) INTO custody FROM jsonb_each(proof) t
    WHERE t.key=ANY(ARRAY['backend','transaction_id','invoker_oid','nonce','mode','accounts']);
    command:=jsonb_build_object('id',p_id,'account_id',account,'old',p_old,'new',next_row,'custody',custody,
        'physical',jsonb_build_array(p_xmin,p_ctid),'actor',jsonb_build_object('type',p_actor_type,'id',p_actor_id),
        'actor_version',actor_after,'question',target->'update_question','policy_epoch',policy_epoch,
        'binding_epoch',binding_epoch,'outputs',outputs);
    PERFORM kaname._authority_sequence_freeze_v3(jsonb_build_object('kind','metadata.group.ordinary',
        'mode','group_'||mode_name,'phase','reserved','command',command));
    RETURN jsonb_build_object('mode',mode_name,'changed_fields',outputs->'changed_fields',
        'rows',used_rows,'reads',used_reads,'work',used_work);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'ordinary group reserve busy' USING ERRCODE='40001';
END;
$reserve$;
-- +goose StatementEnd

-- Из финального решения и закрытых таблиц восстанавливаем ровно ту ветвь,
-- для которой резервировали физическую строку и ID до выбора времени.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_ordinary_command_v1()
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $command$
DECLARE
    proof jsonb;
    program jsonb;
    cmd jsonb;
    actor jsonb;
    observed jsonb;
    outputs jsonb;
    maximum jsonb;
    slot jsonb;
    stamped jsonb;
    mode_name text;
    phase text;
    dirty boolean;
    effect record;
    field text;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    program:=kaname._authority_sequence_store_v3();
    proof:=kaname.authority_protocol_attestation();
    cmd:=program#>'{frozen,command}';
    actor:=cmd->'actor';
    mode_name:=program->>'frozen_mode';
    phase:=program#>>'{frozen,phase}';
    dirty:=mode_name='group_ordinary';
    IF proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'purpose' IS DISTINCT FROM 'decision'
        OR proof->>'writer_contract' IS DISTINCT FROM '2' OR proof->>'consumer_abi' IS DISTINCT FROM '2'
        OR proof->>'consumer_profile' IS DISTINCT FROM 'full' OR proof->>'consumer_finalized' IS DISTINCT FROM 'true'
        OR current_setting('transaction_isolation')<>'read committed' OR current_setting('session_replication_role') NOT IN ('origin','local')
        OR program->>'family' IS DISTINCT FROM 'metadata' OR program#>>'{frozen,kind}' IS DISTINCT FROM 'metadata.group.ordinary'
        OR coalesce(mode_name,'') NOT IN ('group_ordinary','group_noop') OR program#>>'{frozen,mode}' IS DISTINCT FROM mode_name
        OR coalesce(phase,'') NOT IN ('reserved','accepted','done')
        OR program->'nonce' IS DISTINCT FROM proof->'nonce' OR program->'transaction_id' IS DISTINCT FROM proof->'transaction_id'
        OR program->>'decision_at' IS NULL OR program->'decision_at' IS DISTINCT FROM proof->'decision_at'
        OR program->>'staged_decision_at' IS NULL OR NOT isfinite((program->>'staged_decision_at')::timestamptz)
        OR NOT isfinite((program->>'decision_at')::timestamptz)
        OR (program->>'decision_at')::timestamptz <= (program->>'staged_decision_at')::timestamptz
        OR (phase='reserved' AND program->'frozen' ? 'accepted_at')
        OR (phase<>'reserved' AND program#>'{frozen,accepted_at}' IS DISTINCT FROM program->'decision_at')
        OR (phase='done') IS DISTINCT FROM (program->'frozen' ? 'after_versions')
        OR coalesce(cmd->>'id','') COLLATE "C" !~ '^grp[a-zA-Z0-9_-]{1,61}$'
        OR coalesce(cmd->>'account_id','') COLLATE "C" !~ '^acc[a-zA-Z0-9_-]{1,61}$'
        OR coalesce(proof->>'mode','') NOT IN ('accounts','global')
        OR (proof->>'mode'='accounts' AND (proof->'accounts' ? (cmd->>'account_id')) IS DISTINCT FROM true)
        OR cmd#>'{old,id}' IS DISTINCT FROM cmd->'id' OR cmd#>'{old,account_id}' IS DISTINCT FROM cmd->'account_id'
        OR coalesce(cmd#>>'{physical,0}','')='' OR coalesce(cmd#>>'{physical,1}','')=''
        OR dirty IS DISTINCT FROM (cmd->'old' IS DISTINCT FROM cmd->'new')
        OR coalesce(actor->>'type','') NOT IN ('user','service_account') OR coalesce(actor->>'id','')=''
        OR cmd->'question' IS DISTINCT FROM jsonb_build_object('subject',(actor->>'type')||':'||(actor->>'id'),
            'relation','v_update','object_type','iam_group','object_id',cmd->>'id') THEN
        RAISE EXCEPTION 'ordinary group command differs from signed decision' USING ERRCODE='42501';
    END IF;
    FOREACH field IN ARRAY ARRAY['backend','transaction_id','invoker_oid','nonce','mode','accounts'] LOOP
        IF NOT (proof ? field) OR cmd#>ARRAY['custody',field] IS DISTINCT FROM proof->field THEN
            RAISE EXCEPTION 'ordinary group attempt changed' USING ERRCODE='42501';
        END IF;
    END LOOP;
    IF actor->>'type'='user' THEN
        SELECT jsonb_build_array(a.xmin::text,a.ctid::text) INTO observed FROM ONLY kaname.users a WHERE a.id=actor->>'id';
    ELSE
        SELECT jsonb_build_array(a.xmin::text,a.ctid::text) INTO observed FROM ONLY kaname.service_accounts a WHERE a.id=actor->>'id';
    END IF;
    IF observed IS NULL OR observed IS DISTINCT FROM cmd->'actor_version' THEN
        RAISE EXCEPTION 'ordinary group held actor changed' USING ERRCODE='40001';
    END IF;
    outputs:=kaname._authority_metadata_group_ordinary_outputs_v1(cmd->'old',cmd->'new',actor->>'id',
        cmd#>>'{outputs,audit_row,id}',(cmd#>>'{outputs,reconcile_row,id}')::bigint);
    IF cmd->'outputs' IS DISTINCT FROM outputs OR program->'unselected' IS DISTINCT FROM '[]'::jsonb
        OR (program->>'maximum_count')::integer IS DISTINCT FROM dirty::integer
        OR (program->>'selected_count')::integer IS DISTINCT FROM dirty::integer THEN
        RAISE EXCEPTION 'ordinary group reserved output set differs' USING ERRCODE='42501';
    END IF;
    maximum:=outputs->'maximum';
    IF dirty THEN
        BEGIN
            SELECT e.* INTO STRICT effect FROM pg_temp.kaname_authority_sequence_effects e LIMIT 2;
        EXCEPTION WHEN no_data_found OR too_many_rows THEN
            RAISE EXCEPTION 'ordinary group journal must be a singleton' USING ERRCODE='42501';
        END;
        slot:=(maximum->0)||jsonb_build_object('reserved_id',effect.reserved_id);
        stamped:=(slot->'row')||jsonb_build_object('created_at',transaction_timestamp());
        IF effect.nonce IS DISTINCT FROM (proof->>'nonce')::uuid OR effect.table_name IS DISTINCT FROM 'resource_journal'
            OR effect.ordinal IS DISTINCT FROM 1 OR effect.selected IS DISTINCT FROM true
            OR effect.reserved_id IS NULL OR effect.reserved_id<=0 OR effect.origin IS DISTINCT FROM slot->'origin'
            OR effect.origin_digest IS DISTINCT FROM sha256(convert_to((slot->'origin')::text,'UTF8'))
            OR effect.row_value IS DISTINCT FROM stamped OR effect.row_digest IS DISTINCT FROM sha256(convert_to(stamped::text,'UTF8'))
            OR effect.consumed IS DISTINCT FROM (phase='done') OR effect.registered IS DISTINCT FROM effect.consumed
            OR effect.claimed IS DISTINCT FROM effect.consumed OR program->'maximum' IS DISTINCT FROM jsonb_build_array(slot)
            OR program->'selected' IS DISTINCT FROM jsonb_build_array(slot||jsonb_build_object('row',stamped)) THEN
            RAISE EXCEPTION 'ordinary group selected journal differs' USING ERRCODE='42501';
        END IF;
    ELSIF program->'selected' IS DISTINCT FROM maximum OR program->'maximum' IS DISTINCT FROM maximum
        OR EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_effects) THEN
        RAISE EXCEPTION 'group no-op acquired a journal effect' USING ERRCODE='42501';
    END IF;
    RETURN program;
END;
$command$;
-- +goose StatementEnd

-- Вызывается после проверки v_update и RequireMetadataGrant на финальных
-- часах. Расход включает повторные точечные чтения при записи и перед COMMIT.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_ordinary_accept_v1(
    p_actor_type text,p_actor_id text,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $accept$
DECLARE
    program jsonb;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN 24 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 24 AND 4096
        OR p_work IS NULL OR p_work NOT BETWEEN 24 AND 400000 THEN
        RAISE EXCEPTION 'ordinary group acceptance budget exhausted' USING ERRCODE='54000';
    END IF;
    program:=kaname._authority_metadata_group_ordinary_command_v1();
    IF program#>>'{frozen,phase}' IS DISTINCT FROM 'reserved' OR program#>'{frozen,command,actor}'
        IS DISTINCT FROM jsonb_build_object('type',p_actor_type,'id',p_actor_id) THEN
        RAISE EXCEPTION 'ordinary group acceptance phase or actor differs' USING ERRCODE='42501';
    END IF;
    UPDATE pg_temp.kaname_authority_sequence_program s
    SET frozen=s.frozen||jsonb_build_object('phase','accepted','accepted_at',s.decision_at)
    WHERE s.singleton AND s.nonce=(program->>'nonce')::uuid AND s.frozen=program->'frozen';
    IF NOT FOUND THEN RAISE EXCEPTION 'ordinary group acceptance changed' USING ERRCODE='42501';END IF;
    RETURN jsonb_build_object('rows',24,'reads',24,'work',24);
END;
$accept$;
-- +goose StatementEnd

-- Версии физических строк отличают замену UPDATE с теми же данными. У no-op
-- сохраняется исходный ctid группы, остальные таблицы вообще не читаются.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_ordinary_versions_v1(p_program jsonb)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $versions$
DECLARE
    cmd jsonb:=p_program#>'{frozen,command}';
    outputs jsonb:=cmd->'outputs';
    slot jsonb:=p_program#>'{selected,0}';
    gv jsonb;
    av jsonb;
    rv jsonb;
    jv jsonb;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    SELECT jsonb_build_array(g.xmin::text,g.ctid::text) INTO gv FROM ONLY kaname.groups g
    WHERE g.id=cmd->>'id' AND to_jsonb(g)=cmd->'new';
    IF gv IS NULL OR (gv=cmd->'physical') IS DISTINCT FROM (p_program->>'frozen_mode'='group_noop') THEN
        RAISE EXCEPTION 'ordinary group output version differs' USING ERRCODE='40001';
    END IF;
    IF p_program->>'frozen_mode'='group_ordinary' THEN
        SELECT jsonb_build_array(j.xmin::text,j.ctid::text) INTO jv FROM ONLY kaname.resource_journal j
        WHERE j.sequence_no=(slot->>'reserved_id')::bigint
            AND to_jsonb(j)=(slot->'row')||jsonb_build_object('sequence_no',slot->'reserved_id');
        SELECT jsonb_build_array(a.xmin::text,a.ctid::text) INTO av FROM ONLY kaname.audit_outbox a
        WHERE a.id=outputs#>>'{audit_row,id}' AND to_jsonb(a)=outputs->'audit_row';
        IF jv IS NULL OR av IS NULL THEN
            RAISE EXCEPTION 'ordinary group audit or journal differs' USING ERRCODE='42501';
        END IF;
        IF outputs->'changed_fields' ? 'labels' THEN
            SELECT jsonb_build_array(r.xmin::text,r.ctid::text) INTO rv FROM ONLY kaname.resource_reconcile_outbox r
            WHERE r.id=(outputs#>>'{reconcile_row,id}')::bigint AND to_jsonb(r)=outputs->'reconcile_row';
            IF rv IS NULL THEN RAISE EXCEPTION 'ordinary group reconcile differs' USING ERRCODE='42501';END IF;
        END IF;
    END IF;
    RETURN jsonb_build_object('group',gv,'audit',av,'reconcile',rv,'journal',jv);
END;
$versions$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_ordinary_write_v1(p_id text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $write$
DECLARE
    program jsonb;
    cmd jsonb;
    outputs jsonb;
    applying jsonb;
    versions jsonb;
    actual jsonb;
    assignments text;
    audit kaname.audit_outbox;
    reconcile kaname.resource_reconcile_outbox;
BEGIN
    program:=kaname._authority_metadata_group_ordinary_command_v1();
    cmd:=program#>'{frozen,command}';
    outputs:=cmd->'outputs';
    IF p_id IS DISTINCT FROM cmd->>'id' OR program#>>'{frozen,phase}' IS DISTINCT FROM 'accepted' THEN
        RAISE EXCEPTION 'ordinary group write phase or ID differs' USING ERRCODE='42501';
    END IF;
    applying:=(program->'frozen')||jsonb_build_object('phase','applying');
    UPDATE pg_temp.kaname_authority_sequence_program s SET frozen=applying
    WHERE s.singleton AND s.nonce=(program->>'nonce')::uuid AND s.frozen=program->'frozen';
    IF NOT FOUND THEN RAISE EXCEPTION 'ordinary group applying state changed' USING ERRCODE='42501';END IF;
    IF program->>'frozen_mode'='group_noop' THEN
        SELECT to_jsonb(g) INTO actual FROM ONLY kaname.groups g
        WHERE g.id=p_id AND g.account_id=cmd->>'account_id' AND to_jsonb(g)=cmd->'old'
            AND g.xmin::text=cmd#>>'{physical,0}' AND g.ctid::text=cmd#>>'{physical,1}';
    ELSE
        -- SET строится из закрытого списка столбцов с проверенным UPDATE ACL.
        -- В запрос не попадают ни имена столбцов, ни значения от вызывающего.
        SELECT string_agg(v.expr,', ' ORDER BY v.field) INTO assignments FROM (VALUES
            ('name','name=$1->>''name'''),('description','description=$1->>''description'''),('labels','labels=$1->''labels''')
        ) v(field,expr) WHERE outputs->'changed_fields' ? v.field;
        EXECUTE 'UPDATE ONLY kaname.groups g SET '||assignments||
            ' WHERE g.id=$2 AND g.account_id=$3 AND g.xmin::text=$4 AND g.ctid::text=$5 AND to_jsonb(g)=$6 RETURNING to_jsonb(g)'
        INTO actual USING cmd->'new',p_id,cmd->>'account_id',cmd#>>'{physical,0}',cmd#>>'{physical,1}',cmd->'old';
    END IF;
    IF actual IS DISTINCT FROM cmd->'new' THEN
        RAISE EXCEPTION 'ordinary group physical CAS changed' USING ERRCODE='40001';
    END IF;
    IF program->>'frozen_mode'='group_ordinary' THEN
        audit:=jsonb_populate_record(NULL::kaname.audit_outbox,outputs->'audit_row');
        INSERT INTO kaname.audit_outbox(id,event_type,tenant_account_id,event_payload,status,attempts,
            created_at,next_attempt_at,sent_at,last_error)
        VALUES(audit.id,audit.event_type,audit.tenant_account_id,audit.event_payload,audit.status,audit.attempts,
            audit.created_at,audit.next_attempt_at,audit.sent_at,audit.last_error);
        IF outputs->'changed_fields' ? 'labels' THEN
            reconcile:=jsonb_populate_record(NULL::kaname.resource_reconcile_outbox,outputs->'reconcile_row');
            INSERT INTO kaname.resource_reconcile_outbox(id,object_type,object_id,event_type,created_at,sent_at,last_error,attempt_count)
            OVERRIDING SYSTEM VALUE VALUES(reconcile.id,reconcile.object_type,reconcile.object_id,reconcile.event_type,
                reconcile.created_at,reconcile.sent_at,reconcile.last_error,reconcile.attempt_count);
        END IF;
    END IF;
    versions:=kaname._authority_metadata_group_ordinary_versions_v1(program);
    UPDATE pg_temp.kaname_authority_sequence_program s SET frozen=applying||jsonb_build_object('phase','done','after_versions',versions)
    WHERE s.singleton AND s.nonce=(program->>'nonce')::uuid AND s.frozen=applying;
    IF NOT FOUND THEN RAISE EXCEPTION 'ordinary group receipt changed' USING ERRCODE='42501';END IF;
    RETURN actual;
END;
$write$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_ordinary_complete_v1()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $complete$
DECLARE
    program jsonb;
    cmd jsonb;
    delta integer;
    policy_epoch jsonb;
    binding_epoch jsonb;
BEGIN
    program:=kaname._authority_metadata_group_ordinary_command_v1();
    cmd:=program#>'{frozen,command}';
    IF program#>>'{frozen,phase}' IS DISTINCT FROM 'done' OR program#>'{frozen,after_versions}'
        IS DISTINCT FROM kaname._authority_metadata_group_ordinary_versions_v1(program) THEN
        RAISE EXCEPTION 'ordinary group commit requires exact completed outputs' USING ERRCODE='42501';
    END IF;
    delta:=(program->>'frozen_mode'='group_ordinary')::integer;
    SELECT jsonb_build_array(e.generation,e.revision) INTO policy_epoch FROM ONLY kaname.authority_policy_epoch e
    WHERE e.key='group:'||(cmd->>'id');
    SELECT jsonb_build_array(e.generation,e.revision) INTO binding_epoch FROM ONLY kaname.authority_binding_epoch e
    WHERE e.scope=cmd->>'account_id';
    IF policy_epoch IS DISTINCT FROM jsonb_build_array(cmd#>'{policy_epoch,0}',(cmd#>>'{policy_epoch,1}')::numeric+delta)
        OR binding_epoch IS DISTINCT FROM jsonb_build_array(cmd#>'{binding_epoch,0}',(cmd#>>'{binding_epoch,1}')::numeric+delta) THEN
        RAISE EXCEPTION 'ordinary group commit epoch effects differ' USING ERRCODE='40001';
    END IF;
END;
$complete$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE
    signature text;
    fn regprocedure;
    grantee record;
BEGIN
    FOREACH signature IN ARRAY ARRAY[
        '_authority_metadata_group_ordinary_outputs_v1(jsonb,jsonb,text,text,bigint)',
        '_authority_metadata_group_ordinary_reserve_v1(text,text,text,jsonb,jsonb,text,text,text,integer,integer,integer)',
        '_authority_metadata_group_ordinary_command_v1()',
        '_authority_metadata_group_ordinary_accept_v1(text,text,integer,integer,integer)',
        '_authority_metadata_group_ordinary_versions_v1(jsonb)',
        '_authority_metadata_group_ordinary_write_v1(text)',
        '_authority_metadata_group_ordinary_complete_v1()'
    ] LOOP
        fn:=('kaname.'||signature)::regprocedure;
        FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
            WHERE p.oid=fn AND a.grantee<>p.proowner
        LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
                CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE quote_ident(grantee.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_metadata_group_ordinary_complete_v1();
DROP FUNCTION kaname._authority_metadata_group_ordinary_write_v1(text);
DROP FUNCTION kaname._authority_metadata_group_ordinary_versions_v1(jsonb);
DROP FUNCTION kaname._authority_metadata_group_ordinary_accept_v1(text,text,integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_group_ordinary_command_v1();
DROP FUNCTION kaname._authority_metadata_group_ordinary_reserve_v1(text,text,text,jsonb,jsonb,text,text,text,integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_group_ordinary_outputs_v1(jsonb,jsonb,text,text,bigint);
