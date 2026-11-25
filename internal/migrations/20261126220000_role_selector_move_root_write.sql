-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Тип и владелец для аудита выводятся из удержанного ресурса. У зеркала
-- аккаунт может быть задан только проектом. Форматы событий совпадают с
-- обычными Account.Update, Project.Update, ServiceAccount.Update и metadata.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_root_outputs_v1(
    p_root jsonb,p_actor jsonb,p_audit text,p_reconcile bigint
) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $outputs$
DECLARE
    dotted text:=p_root->>'root_type';
    resource_id text:=p_root->>'root_id';
    old_row jsonb:=p_root#>'{physical,2}';
    account_id text;
    resource_kind text;
    payload jsonb;
    audit_row kaname.audit_outbox;
    reconcile_row kaname.resource_reconcile_outbox;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF kaname._authority_access_label_dirty_root_type_valid_v1(dotted) IS DISTINCT FROM true
        OR coalesce(resource_id,'')='' OR octet_length(resource_id)>16384 OR resource_id ~ '[:#*[:space:][:cntrl:]]'
        OR jsonb_typeof(old_row) IS DISTINCT FROM 'object'
        OR jsonb_typeof(p_actor) IS DISTINCT FROM 'object' OR p_actor-ARRAY['type','id']<>'{}'::jsonb
        OR coalesce(p_actor->>'type','') NOT IN ('user','service_account')
        OR jsonb_typeof(p_actor->'id') IS DISTINCT FROM 'string' OR coalesce(p_actor->>'id','')=''
        OR p_root#>'{authority,actor}' IS DISTINCT FROM p_actor
        OR coalesce(p_audit,'') !~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$'
        OR p_reconcile IS NULL OR p_reconcile<=0 THEN
        RAISE EXCEPTION 'invalid selector move output identity' USING ERRCODE='42501';
    END IF;
    resource_kind:=CASE dotted WHEN 'iam.account' THEN 'account' WHEN 'iam.project' THEN 'project'
        WHEN 'iam.serviceAccount' THEN 'service_account' END;
    IF resource_kind IS NOT NULL THEN
        IF old_row->>'id' IS DISTINCT FROM resource_id THEN
            RAISE EXCEPTION 'selector move IAM output root differs' USING ERRCODE='42501';
        END IF;
        account_id:=CASE WHEN resource_kind='account' THEN resource_id ELSE old_row->>'account_id' END;
        audit_row.event_type:='iam.'||resource_kind||'.updated';
        payload:=jsonb_build_object('actor',p_actor->>'id','resource_type',resource_kind);
    ELSE
        account_id:=p_root#>>'{account,2,id}';
        IF split_part(dotted,'.',1)='iam' OR old_row->>'object_type' IS DISTINCT FROM dotted
            OR old_row->>'object_id' IS DISTINCT FROM resource_id
            OR p_root#>>'{catalog,2,dotted}' IS DISTINCT FROM dotted
            OR p_root#>'{catalog,2,live}' IS DISTINCT FROM 'true'::jsonb
            OR p_root#>>'{root_update_verb,2,verb}' IS DISTINCT FROM 'update'
            OR p_root#>'{root_update_verb,2,live}' IS DISTINCT FROM 'true'::jsonb
            OR p_root#>'{root_update_verb,2,per_object}' IS DISTINCT FROM 'true'::jsonb
            OR account_id IS DISTINCT FROM coalesce(nullif(old_row->>'parent_account_id',''),p_root#>>'{project,2,account_id}')
            OR nullif(old_row->>'parent_project_id','') IS DISTINCT FROM p_root#>>'{project,2,id}'
            OR (nullif(old_row->>'parent_project_id','') IS NOT NULL
                AND p_root#>>'{project,2,account_id}' IS DISTINCT FROM account_id) THEN
            RAISE EXCEPTION 'selector move external output scope differs' USING ERRCODE='42501';
        END IF;
        audit_row.event_type:='iam.resource_metadata.access_labels_updated';
        payload:=jsonb_build_object('actor',p_actor,'resource_type',dotted);
    END IF;
    IF coalesce(account_id,'')='' OR account_id ~ '[:#*[:space:][:cntrl:]]' THEN
        RAISE EXCEPTION 'selector move output tenant absent' USING ERRCODE='42501';
    END IF;
    IF dotted<>'iam.account' THEN payload:=payload||jsonb_build_object('account_id',account_id);END IF;
    audit_row.id:=p_audit;
    audit_row.tenant_account_id:=account_id;
    audit_row.event_payload:=payload||jsonb_build_object('resource_id',resource_id,'changed_fields',jsonb_build_array('access_labels'));
    audit_row.status:='pending';
    audit_row.attempts:=0;
    audit_row.created_at:=transaction_timestamp();
    audit_row.next_attempt_at:=audit_row.created_at;
    reconcile_row.id:=p_reconcile;
    reconcile_row.object_type:=dotted;
    reconcile_row.object_id:=resource_id;
    reconcile_row.event_type:='mirror.upsert';
    reconcile_row.created_at:=audit_row.created_at;
    reconcile_row.attempt_count:=0;
    RETURN jsonb_build_object('audit',to_jsonb(audit_row),'reconcile',to_jsonb(reconcile_row));
END;
$outputs$;
-- +goose StatementEnd

-- У роли без привязок сам перенос предиката не оставляет старых выдач.
-- Перепись дополнительно ищет изменившиеся селекторы других ролей. Только
-- отсутствие всех таких источников доказывает пустую добавку к prior_facts.
-- Непустую перепись нельзя заменять результатом проверки отдельного кортежа.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_root_carriers_v1(
    p_role text,p_root jsonb,p_labels jsonb,p_rows integer,p_reads integer
) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $carriers$
DECLARE
    census jsonb;
    used_rows integer:=1;
    used_reads integer:=1;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF coalesce(p_role,'')='' OR p_rows IS NULL OR p_rows NOT BETWEEN 2 AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN 2 AND 4096 THEN
        RAISE EXCEPTION 'selector move carrier proof budget exhausted' USING ERRCODE='54000';
    END IF;
    IF EXISTS (SELECT FROM ONLY kaname.access_bindings b WHERE b.role_id=p_role) THEN
        RETURN jsonb_build_object('empty',false,'rows',used_rows,'reads',used_reads);
    END IF;
    census:=kaname._authority_metadata_access_label_carrier_census_v1(p_root->>'root_type',
        p_root#>'{physical,2}',p_labels,p_rows-used_rows,p_reads-used_reads,p_rows-used_rows);
    used_rows:=used_rows+(census->>'logical_rows')::integer+(census->>'work')::integer;
    used_reads:=used_reads+(census->>'logical_reads')::integer;
    IF used_rows IS NULL OR used_rows NOT BETWEEN 1 AND p_rows OR used_reads IS NULL OR used_reads NOT BETWEEN 2 AND p_reads
        OR jsonb_typeof(census->'states') IS DISTINCT FROM 'array'
        OR jsonb_typeof(census->'binding_ids') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'selector move carrier census exceeds reservation' USING ERRCODE='54000';
    END IF;
    RETURN jsonb_build_object('empty',census->'states'='[]'::jsonb AND census->'binding_ids'='[]'::jsonb,
        'rows',used_rows,'reads',used_reads);
END;
$carriers$;
-- +goose StatementEnd

-- Получает только результат owner prepare_checks до создания единственной
-- sequence. Ограждения, два идентификатора и прежние незавершённые факты
-- принадлежат конкретному корню даже при сужении списка на финальных часах.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_root_outputs_hold_v1(
    p_frozen jsonb,p_rows integer,p_reads integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $hold$
DECLARE
    proof jsonb;
    roots jsonb:=p_frozen#>'{copies,roots}';
    item record;
    root jsonb;
    old_row jsonb;
    dotted text;
    v_root_id text;
    table_name text;
    rel regclass;
    invoker oid;
    outputs jsonb;
    account_id text;
    epochs text[];
    epoch text;
    v_generation uuid;
    previous_labels jsonb;
    prior_facts jsonb;
    fact_count integer;
    check_empty boolean;
    carriers jsonb;
    receipt jsonb;
    coordinates text[]:=ARRAY[]::text[];
    receipts jsonb[]:=ARRAY[]::jsonb[];
    used_bytes bigint:=2;
    used_rows integer:=16;
    used_reads integer:=14;
BEGIN
    proof:=kaname._authority_role_move_attestation_v1();
    IF p_frozen->>'nonce' IS DISTINCT FROM proof->>'nonce'
        OR p_frozen->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid'
        OR p_frozen->>'prepared_at' IS DISTINCT FROM proof->>'decision_at'
        OR p_frozen#>'{copies,actor}' IS DISTINCT FROM p_frozen->'actor'
        OR p_frozen#>'{copies,backend_pid}' IS DISTINCT FROM to_jsonb(pg_backend_pid())
        OR p_frozen#>>'{copies,txid}' IS DISTINCT FROM pg_current_xact_id_if_assigned()::text
        OR jsonb_typeof(roots) IS DISTINCT FROM 'object' OR octet_length(p_frozen::text)>8388608
        OR kaname._authority_sequence_store_v3() IS NOT NULL THEN
        RAISE EXCEPTION 'selector move outputs require prefinal owner capture' USING ERRCODE='42501';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
        RAISE EXCEPTION 'selector move output reservation budget exhausted' USING ERRCODE='54000';
    END IF;
    invoker:=(proof->>'invoker_oid')::oid;
    LOCK TABLE ONLY kaname.audit_outbox, ONLY kaname.resource_reconcile_outbox,
        ONLY kaname.authority_binding_epoch, ONLY kaname.authority_policy_epoch,
        ONLY kaname.authority_access_label_dirty_root, ONLY kaname.authority_access_label_dirty_fact
        IN ROW EXCLUSIVE MODE NOWAIT;
    IF current_setting('session_replication_role') NOT IN ('origin','local')
        OR EXISTS (SELECT FROM pg_catalog.pg_class c
            WHERE c.oid IN ('kaname.audit_outbox'::regclass,'kaname.resource_reconcile_outbox'::regclass,
                'kaname.authority_binding_epoch'::regclass,'kaname.authority_policy_epoch'::regclass,
                'kaname.authority_access_label_dirty_root'::regclass,'kaname.authority_access_label_dirty_fact'::regclass)
            AND (c.relowner<>current_user::regrole OR c.relkind<>'r' OR c.relpersistence<>'p'
                OR c.relrowsecurity OR c.relforcerowsecurity OR c.relhasrules OR c.relispartition
                OR EXISTS(SELECT FROM pg_inherits i WHERE i.inhparent=c.oid OR i.inhrelid=c.oid)))
        OR NOT has_table_privilege(invoker,'kaname.audit_outbox','INSERT')
        OR NOT has_table_privilege(invoker,'kaname.resource_reconcile_outbox','INSERT')
        OR NOT has_sequence_privilege(invoker,'kaname.resource_reconcile_outbox_id_seq','USAGE,UPDATE')
        OR to_regclass(pg_get_serial_sequence('kaname.resource_reconcile_outbox','id'))
            IS DISTINCT FROM 'kaname.resource_reconcile_outbox_id_seq'::regclass
        OR NOT EXISTS (SELECT FROM pg_attribute a WHERE a.attrelid='kaname.resource_reconcile_outbox'::regclass
            AND a.attname='id' AND NOT a.attisdropped AND a.attidentity='a' AND a.atttypid='bigint'::regtype)
        OR EXISTS (SELECT FROM (VALUES
            ('kaname.audit_outbox'::regclass,'authority_audit_id_guard_v2','kaname.authority_audit_id_guard_v2()'::regprocedure),
            ('kaname.resource_reconcile_outbox'::regclass,'authority_reconcile_id_guard_v2','kaname.authority_reconcile_id_guard_v2()'::regprocedure)
        ) g(relid,name,fn) WHERE NOT EXISTS (SELECT FROM pg_trigger t JOIN pg_attribute a
            ON a.attrelid=t.tgrelid AND a.attname='id' AND NOT a.attisdropped
            WHERE t.tgrelid=g.relid AND t.tgname=g.name AND t.tgfoid=g.fn AND t.tgtype=23
            AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal AND t.tgqual IS NULL
            AND t.tgnargs=0 AND t.tgattr::text=a.attnum::text)) THEN
        RAISE EXCEPTION 'selector move output storage or original privileges differ' USING ERRCODE='42501';
    END IF;
    -- Epoch '*' стабилизирует классификацию зеркал по producer_source_receipt.
    PERFORM FROM ONLY kaname.authority_policy_epoch e WHERE e.key='*' FOR UPDATE OF e NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'selector move policy root disappeared' USING ERRCODE='40001';END IF;
    PERFORM FROM ONLY kaname.authority_binding_epoch e WHERE e.scope='' FOR UPDATE OF e NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'selector move binding root disappeared' USING ERRCODE='40001';END IF;
    check_empty:=NOT EXISTS (SELECT FROM ONLY kaname.access_bindings b WHERE b.role_id=p_frozen->>'role_id');
    IF check_empty THEN
        -- Удерживаем отсутствие привязки и кандидата, в том числе изменение
        -- правил чужой роли или перенос проекта в область этой роли.
        LOCK TABLE ONLY kaname.access_bindings, ONLY kaname.roles, ONLY kaname.projects IN SHARE MODE NOWAIT;
    END IF;
    FOR item IN SELECT * FROM jsonb_each(roots) ORDER BY key COLLATE "C" LOOP
        -- Включает точечные проверки источников, запись и проверку результатов
        -- аудита, очереди и журнала. Переменная часть зависит от прежних фактов.
        used_rows:=used_rows+32;
        used_reads:=used_reads+32;
        IF used_rows>p_rows OR used_reads>p_reads THEN
            RAISE EXCEPTION 'selector move per-root output budget exhausted' USING ERRCODE='54000';
        END IF;
        root:=item.value;
        old_row:=root#>'{physical,2}';
        dotted:=root->>'root_type';
        v_root_id:=root->>'root_id';
        table_name:=CASE dotted WHEN 'iam.account' THEN 'accounts' WHEN 'iam.project' THEN 'projects'
            WHEN 'iam.serviceAccount' THEN 'service_accounts' ELSE 'resource_mirror' END;
        IF item.key IS DISTINCT FROM dotted||':'||v_root_id THEN
            RAISE EXCEPTION 'selector move output coordinate differs' USING ERRCODE='42501';
        END IF;
        -- SUE удерживает также форму наследования, не блокируя чужой ROW EXCLUSIVE.
        EXECUTE format('LOCK TABLE ONLY kaname.%I IN SHARE UPDATE EXCLUSIVE MODE NOWAIT',table_name);
        EXECUTE format('LOCK TABLE ONLY kaname.%I IN ROW EXCLUSIVE MODE NOWAIT',table_name);
        rel:=to_regclass('kaname.'||table_name);
        IF NOT has_table_privilege(invoker,rel,'SELECT') OR NOT has_column_privilege(invoker,rel,'access_labels','UPDATE')
            OR NOT EXISTS (SELECT FROM pg_class c WHERE c.oid=rel AND c.relowner=current_user::regrole
                AND c.relkind='r' AND c.relpersistence='p'
                AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relhasrules OR c.relispartition)
                AND NOT EXISTS(SELECT FROM pg_inherits i WHERE i.inhparent=c.oid OR i.inhrelid=c.oid))
            OR NOT EXISTS (SELECT FROM pg_trigger t WHERE t.tgrelid=rel AND t.tgname='access_labels_immutable'
                AND t.tgfoid='kaname.access_labels_immutable_v1()'::regprocedure AND t.tgtype=23
                AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal AND t.tgnargs=0 AND t.tgqual IS NULL AND t.tgattr::text='')
            OR NOT EXISTS (SELECT FROM pg_trigger t WHERE t.tgrelid=rel AND t.tgname='access_labels_000_commit_freshness'
                AND t.tgfoid='kaname._authority_metadata_access_label_freshness_v1()'::regprocedure
                AND t.tgtype=17 AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal AND t.tgnargs=0 AND t.tgattr::text=''
                AND t.tgconstraint=0 AND NOT t.tgdeferrable AND NOT t.tginitdeferred
                AND pg_get_triggerdef(t.oid) LIKE '% WHEN ((old.access_labels IS DISTINCT FROM new.access_labels)) EXECUTE FUNCTION %') THEN
            RAISE EXCEPTION 'selector move root write custody differs' USING ERRCODE='42501';
        END IF;
        IF table_name='resource_mirror' THEN
            -- Проверки двух фактических триггеров, регистрации и оба чтения
            -- при завершении входят в тот же бюджет, что и IAM journal.
            used_rows:=used_rows+16;used_reads:=used_reads+16;
            IF used_rows>p_rows OR used_reads>p_reads THEN
                RAISE EXCEPTION 'selector move registration output budget exhausted' USING ERRCODE='54000';
            END IF;
            IF NOT pg_try_advisory_xact_lock(hashtextextended('kaname.resource_registration_writers',0)) THEN
                RAISE EXCEPTION 'selector move mirror registration writer busy' USING ERRCODE='40001';
            END IF;
            IF EXISTS(SELECT FROM (VALUES ('resource_mirror_keeps_the_bound_project',23),
                ('resource_mirror_binds_effective_registration',21)) g(name,kind)
                WHERE NOT EXISTS(SELECT FROM pg_trigger t WHERE t.tgrelid=rel AND t.tgname=g.name
                    AND t.tgfoid='kaname.resource_mirror_keeps_the_bound_project()'::regprocedure AND t.tgtype=g.kind
                    AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal AND t.tgnargs=0 AND t.tgqual IS NULL
                    AND t.tgattr::text='' AND t.tgconstraint=0 AND NOT t.tgdeferrable AND NOT t.tginitdeferred)) THEN
                RAISE EXCEPTION 'selector move registration row guards differ' USING ERRCODE='42501';
            END IF;
        END IF;
        IF kaname._authority_metadata_root_state_v1(dotted,v_root_id,false) IS DISTINCT FROM root->'physical' THEN
            RAISE EXCEPTION 'selector move physical root changed before output reserve' USING ERRCODE='40001';
        END IF;
        outputs:=kaname._authority_role_move_root_outputs_v1(root,p_frozen->'actor',
            'evt_'||substr(replace(gen_random_uuid()::text,'-',''),1,22),nextval('kaname.resource_reconcile_outbox_id_seq'));
        account_id:=outputs#>>'{audit,tenant_account_id}';
        IF NOT pg_try_advisory_xact_lock(1262569298,hashtext(outputs#>>'{audit,id}'))
            OR NOT pg_try_advisory_xact_lock(1262569299,hashtext(outputs#>>'{reconcile,id}')) THEN
            RAISE EXCEPTION 'selector move output identifier busy' USING ERRCODE='40001';
        END IF;
        IF EXISTS(SELECT FROM ONLY kaname.audit_outbox a WHERE a.id=outputs#>>'{audit,id}')
            OR EXISTS(SELECT FROM ONLY kaname.resource_reconcile_outbox r WHERE r.id=(outputs#>>'{reconcile,id}')::bigint) THEN
            RAISE EXCEPTION 'selector move output identifier occupied' USING ERRCODE='40001';
        END IF;
        IF kaname.authority_binding_epoch_scope(table_name,old_row) IS DISTINCT FROM account_id THEN
            RAISE EXCEPTION 'selector move binding epoch differs from root tenant' USING ERRCODE='42501';
        END IF;
        PERFORM FROM ONLY kaname.authority_binding_epoch e WHERE e.scope=account_id FOR UPDATE OF e NOWAIT;
        IF NOT FOUND THEN RAISE EXCEPTION 'selector move tenant epoch absent' USING ERRCODE='40001';END IF;
        epochs:=kaname.authority_policy_keys(table_name,old_row);
        IF cardinality(epochs) NOT BETWEEN 1 AND 4 OR epochs IS NULL OR array_position(epochs,NULL::text) IS NOT NULL
            OR epochs IS DISTINCT FROM kaname.authority_policy_keys(table_name,jsonb_set(old_row,'{access_labels}',root->'new_access_labels',false)) THEN
            RAISE EXCEPTION 'selector move policy epochs differ' USING ERRCODE='42501';
        END IF;
        FOR epoch IN SELECT DISTINCT x COLLATE "C" FROM unnest(epochs) x ORDER BY 1 LOOP
            PERFORM FROM ONLY kaname.authority_policy_epoch e WHERE e.key=epoch FOR UPDATE OF e NOWAIT;
            IF NOT FOUND THEN RAISE EXCEPTION 'selector move policy epoch absent' USING ERRCODE='40001';END IF;
        END LOOP;
        -- В отличие от однокорневого metadata writer у роли нет его stashed
        -- receipt. OLD и registration уже удержаны ролью для этого ключа.
        SELECT r.generation,r.new_labels INTO v_generation,previous_labels
        FROM ONLY kaname.authority_access_label_dirty_root r WHERE r.root_type=dotted AND r.root_id=v_root_id FOR UPDATE OF r NOWAIT;
        prior_facts:='[]'::jsonb;
        IF FOUND THEN
            IF previous_labels IS DISTINCT FROM old_row->'access_labels' THEN
                RAISE EXCEPTION 'selector move prior generation differs from root' USING ERRCODE='40001';
            END IF;
            SELECT count(*)::integer,coalesce(jsonb_agg(to_jsonb(f) ORDER BY f.object_type COLLATE "C",f.object_id COLLATE "C",
                f.relation COLLATE "C",f.subject COLLATE "C"),'[]'::jsonb) INTO fact_count,prior_facts
            FROM (SELECT d.object_type,d.object_id,d.relation,d.subject FROM ONLY kaname.authority_access_label_dirty_fact d
                WHERE d.root_type=dotted AND d.root_id=v_root_id AND d.generation=v_generation
                LIMIT p_rows-used_rows+1 FOR UPDATE OF d NOWAIT) f;
            -- Захват, сверка до удаления, перенос и финальная сверка фактов.
            used_rows:=used_rows+4*fact_count;
            IF used_rows>p_rows THEN RAISE EXCEPTION 'selector move prior fact budget exhausted' USING ERRCODE='54000';END IF;
        END IF;
        receipt:=outputs||jsonb_build_object('binding_epoch',account_id,'policy_epochs',epochs,'prior_generation',v_generation,'prior_facts',prior_facts);
        IF check_empty THEN
            carriers:=kaname._authority_role_move_root_carriers_v1(p_frozen->>'role_id',root,root->'new_access_labels',
                p_rows-used_rows,p_reads-used_reads);
            used_rows:=used_rows+(carriers->>'rows')::integer;
            used_reads:=used_reads+(carriers->>'reads')::integer;
            IF carriers->'empty'='true'::jsonb THEN
                -- Повторная проверка на фактической финальной карте оплачена
                -- здесь. При собственной записи после подготовки она может отказать.
                carriers:=jsonb_build_object('rows',greatest(8,(carriers->>'rows')::integer),
                    'reads',greatest(4,(carriers->>'reads')::integer));
                used_rows:=used_rows+(carriers->>'rows')::integer;
                used_reads:=used_reads+(carriers->>'reads')::integer;
                receipt:=receipt||jsonb_build_object('empty_carriers',carriers);
            END IF;
            IF used_rows>p_rows OR used_reads>p_reads THEN
                RAISE EXCEPTION 'selector move carrier replay budget exhausted' USING ERRCODE='54000';
            END IF;
        END IF;
        used_bytes:=used_bytes+octet_length(item.key)+octet_length(receipt::text)+8;
        IF used_bytes>8388608 THEN RAISE EXCEPTION 'selector move output receipt exceeds byte budget' USING ERRCODE='54000';END IF;
        coordinates:=array_append(coordinates,item.key);
        receipts:=array_append(receipts,receipt);
    END LOOP;
    SELECT coalesce(jsonb_object_agg(u.coord,u.receipt),'{}'::jsonb) INTO roots FROM unnest(coordinates,receipts) u(coord,receipt)
    HAVING count(*)=count(DISTINCT u.receipt#>>'{audit,id}') AND count(*)=count(DISTINCT u.receipt#>>'{reconcile,id}');
    IF NOT FOUND THEN RAISE EXCEPTION 'duplicate selector move output identifier' USING ERRCODE='40001';END IF;
    RETURN jsonb_build_object('roots',roots,'rows',used_rows,'reads',used_reads);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'selector move output reservation busy' USING ERRCODE='40001';
END;
$hold$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure; recipient record;
BEGIN
    FOREACH fn IN ARRAY ARRAY[
        'kaname._authority_role_move_root_outputs_v1(jsonb,jsonb,text,bigint)'::regprocedure,
        'kaname._authority_role_move_root_carriers_v1(text,jsonb,jsonb,integer,integer)'::regprocedure,
        'kaname._authority_role_move_root_outputs_hold_v1(jsonb,integer,integer)'::regprocedure
    ] LOOP
        FOR recipient IN SELECT DISTINCT a.grantee,r.rolname FROM pg_proc p
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner
        LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
                CASE WHEN recipient.grantee=0 THEN 'PUBLIC' ELSE format('%I',recipient.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_role_move_root_outputs_hold_v1(jsonb,integer,integer);
DROP FUNCTION kaname._authority_role_move_root_carriers_v1(text,jsonb,jsonb,integer,integer);
DROP FUNCTION kaname._authority_role_move_root_outputs_v1(jsonb,jsonb,text,bigint);
