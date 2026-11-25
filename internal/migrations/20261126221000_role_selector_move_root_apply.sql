-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Аналог обычной metadata-проверки для регистрации, которую удержала роль.
-- Изменение только access_labels не создаёт первую привязку зеркала.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_root_registration_v1(p_root jsonb) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $registration$
DECLARE
    v_dotted text:=p_root->>'root_type';
    root_id text:=p_root->>'root_id';
    model text:=p_root#>>'{catalog,2,object_type}';
    catalog_row jsonb;
    verb_row jsonb;
    binding_row jsonb;
    scopes jsonb;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF coalesce(model,'')='' OR coalesce(v_dotted,'')='' OR split_part(v_dotted,'.',1)='iam' OR coalesce(root_id,'')='' THEN
        RAISE EXCEPTION 'selector move registration coordinate missing' USING ERRCODE='42501';
    END IF;
    PERFORM kaname._authority_resource_preheld_key_v2(1262569300,jsonb_build_array(model,root_id)::text,false);
    SELECT jsonb_build_array(c.xmin::text,c.ctid::text,to_jsonb(c)) INTO catalog_row FROM ONLY kaname.catalog_resource c
    WHERE c.dotted=v_dotted;
    SELECT jsonb_build_array(v.xmin::text,v.ctid::text,to_jsonb(v)) INTO verb_row FROM ONLY kaname.catalog_verb v
    WHERE v.module=catalog_row#>>'{2,module}' AND v.resource=catalog_row#>>'{2,resource}' AND v.verb='update';
    SELECT jsonb_build_array(b.xmin::text,b.ctid::text,to_jsonb(b)) INTO binding_row
    FROM ONLY kaname.object_project_binding b WHERE b.object_type=model AND b.object_id=root_id;
    SELECT coalesce(jsonb_agg(s.state),'[]'::jsonb) INTO scopes FROM (
        SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r)) AS state FROM ONLY kaname.resource_registration_scope r
        WHERE r.object_type=model AND r.object_id=root_id LIMIT 2
    ) s;
    IF catalog_row IS DISTINCT FROM p_root->'catalog' OR verb_row IS DISTINCT FROM p_root->'root_update_verb'
        OR coalesce(binding_row,'null'::jsonb) IS DISTINCT FROM p_root->'binding'
        OR scopes IS DISTINCT FROM p_root->'registration_scopes' THEN
        RAISE EXCEPTION 'selector move held registration changed' USING ERRCODE='40001';
    END IF;
END;
$registration$;
-- +goose StatementEnd

-- Единственная активная строка существует лишь внутри закрытой функции
-- записи. Триггер сверяет настоящий физический OLD и полные OLD/NEW.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_root_trigger_v1(
    p_rel oid,p_old jsonb,p_new jsonb,p_xmin text,p_ctid text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $trigger$
DECLARE
    header jsonb;
    active jsonb;
    command jsonb;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    header:=kaname._authority_sequence_header_v3();
    IF header->>'family' IS DISTINCT FROM 'role' THEN RETURN NULL;END IF;
    IF pg_trigger_depth()<>1 OR jsonb_typeof(header->'selected') IS DISTINCT FROM 'array'
        OR coalesce(header#>>'{frozen,mode}','') NOT IN ('selector_move','access_label_transition') THEN
        RAISE EXCEPTION 'role has no active selector move root' USING ERRCODE='42501';
    END IF;
    SELECT s.frozen->'selector_move_active',s.frozen#>ARRAY['selector_move_decision','commands',
        s.frozen#>>'{selector_move_active,index}'] INTO active,command
    FROM pg_temp.kaname_authority_sequence_program s WHERE s.singleton AND s.nonce=(header->>'nonce')::uuid
        AND s.family='role' AND s.frozen->>'kind'='role.mutation'
        AND s.frozen#>'{selector_move_approved,nonce}'=header->'nonce';
    IF jsonb_typeof(active) IS DISTINCT FROM 'object' OR jsonb_typeof(command) IS DISTINCT FROM 'object'
        OR command->'physical' IS DISTINCT FROM jsonb_build_array(p_xmin,p_ctid,p_old)
        OR p_rel IS DISTINCT FROM to_regclass('kaname.'||(command->>'table'))::oid
        OR active->'old' IS DISTINCT FROM p_old OR active->'new' IS DISTINCT FROM p_new
        OR p_new IS DISTINCT FROM jsonb_set(p_old,'{access_labels}',command->'access_labels',false)
        OR active#>>'{freshness,root_type}' IS DISTINCT FROM command->>'root_type'
        OR active#>>'{freshness,root_id}' IS DISTINCT FROM command->>'root_id' THEN
        RAISE EXCEPTION 'selector move trigger root differs from active physical command' USING ERRCODE='42501';
    END IF;
    RETURN active;
END;
$trigger$;
-- +goose StatementEnd

-- Проверяет все выбранные команды до первого UPDATE. Для непустого набора
-- затронутых привязок требуется полный сертификат удержанных выходов.
-- Никаких SQL-имён, образов строк и идентификаторов событий от вызывающего нет.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_roots_write_v1() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $write$
<<root_write>>
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    program jsonb:=kaname._authority_sequence_store_v3();
    frozen jsonb:=program->'frozen';
    decision jsonb:=frozen->'selector_move_decision';
    commands jsonb:=decision->'commands';
    nonce uuid:=(proof->>'nonce')::uuid;
    invoker oid:=(proof->>'invoker_oid')::oid;
    item record;
    accepted jsonb;
    command jsonb;
    coord text;
    source_table text;
    rel regclass;
    held jsonb;
    outputs jsonb;
    empty_proof jsonb;
    old_row jsonb;
    new_row jsonb;
    physical jsonb;
    active jsonb;
    receipts jsonb[]:=ARRAY[]::jsonb[];
    actual jsonb;
    after_physical jsonb;
    completed jsonb[]:=ARRAY[]::jsonb[];
    journal_id bigint;
    audit_row kaname.audit_outbox;
    reconcile_row kaname.resource_reconcile_outbox;
    n integer;
    bytes bigint:=2;
BEGIN
    IF program->>'family' IS DISTINCT FROM 'role' OR frozen->>'kind' IS DISTINCT FROM 'role.mutation'
        OR coalesce(program->>'frozen_mode','') NOT IN ('selector_move','access_label_transition')
        OR jsonb_typeof(program->'selected') IS DISTINCT FROM 'array'
        OR jsonb_typeof(commands) IS DISTINCT FROM 'array' OR decision->'role_id' IS DISTINCT FROM frozen#>'{selector_move,role_id}'
        OR decision->'actor' IS DISTINCT FROM frozen#>'{selector_move,actor}'
        OR (decision->>'decision_at')::timestamptz IS DISTINCT FROM (proof->>'decision_at')::timestamptz
        OR program->'decision_at' IS DISTINCT FROM proof->'decision_at'
        OR frozen->'selector_move_approved' IS DISTINCT FROM jsonb_build_object('nonce',proof->'nonce',
            'decision_at',proof->'decision_at','role_id',decision->'role_id','actor',decision->'actor')
        OR frozen ?| ARRAY['selector_move_active','selector_move_roots_completed','selector_move_written']
        OR EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_effects e WHERE e.registered OR e.claimed OR e.consumed) THEN
        RAISE EXCEPTION 'selector move root writer requires the untouched approved role decision' USING ERRCODE='42501';
    END IF;
    IF program->>'frozen_mode'='access_label_transition' THEN
        accepted:=frozen->'access_label_method_authorized';
        IF accepted->>'result' IS DISTINCT FROM 'allow' OR accepted->>'contract' IS DISTINCT FROM 'RequireRole/v1'
            OR accepted->>'operation' IS DISTINCT FROM 'role.update'
            OR accepted->'role_id' IS DISTINCT FROM decision->'role_id' OR accepted->'actor' IS DISTINCT FROM decision->'actor'
            OR accepted->'mode' IS DISTINCT FROM frozen#>'{access_label_scope_census,mode}'
            OR accepted->'new_digest' IS DISTINCT FROM frozen#>'{access_label_transition,new_digest}'
            OR accepted->'decision_at' IS DISTINCT FROM proof->'decision_at' OR accepted->'nonce' IS DISTINCT FROM proof->'nonce'
            OR accepted->'transaction_id' IS DISTINCT FROM proof->'transaction_id' OR accepted->'backend' IS DISTINCT FROM proof->'backend' THEN
            RAISE EXCEPTION 'selector move role projection method approval missing' USING ERRCODE='42501';
        END IF;
    END IF;
    FOR item IN SELECT value,ordinality FROM jsonb_array_elements(commands) WITH ORDINALITY LOOP
        command:=item.value;
        coord:=(command->>'root_type')||':'||(command->>'root_id');
        held:=frozen#>ARRAY['selector_move','copies','roots',coord];
        outputs:=frozen#>ARRAY['selector_move_outputs',coord];
        physical:=command->'physical'; old_row:=physical->2;
        source_table:=CASE command->>'root_type' WHEN 'iam.account' THEN 'accounts' WHEN 'iam.project' THEN 'projects'
            WHEN 'iam.serviceAccount' THEN 'service_accounts' ELSE 'resource_mirror' END;
        rel:=to_regclass('kaname.'||source_table);
        IF command->>'table' IS DISTINCT FROM source_table OR command->'root_id' IS DISTINCT FROM held->'root_id'
            OR command->'root_type' IS DISTINCT FROM held->'root_type' OR physical IS DISTINCT FROM held->'physical'
            OR kaname.access_labels_valid_v1(command->'access_labels') IS DISTINCT FROM true
            OR ((held->'new_access_labels') @> (command->'access_labels')) IS DISTINCT FROM true
            OR ((command->'access_labels') @> (old_row->'access_labels')) IS DISTINCT FROM true
            OR command->'access_labels' IS NOT DISTINCT FROM old_row->'access_labels'
            OR NOT has_table_privilege(invoker,rel,'SELECT') OR NOT has_column_privilege(invoker,rel,'access_labels','UPDATE')
            OR NOT has_table_privilege(invoker,'kaname.audit_outbox','INSERT')
            OR NOT has_table_privilege(invoker,'kaname.resource_reconcile_outbox','INSERT')
            OR outputs->'binding_epoch' IS DISTINCT FROM outputs#>'{audit,tenant_account_id}'
            OR (outputs-ARRAY['binding_epoch','policy_epochs','prior_generation','prior_facts','empty_carriers'])
                IS DISTINCT FROM kaname._authority_role_move_root_outputs_v1(held,decision->'actor',
                    outputs#>>'{audit,id}',(outputs#>>'{reconcile,id}')::bigint) THEN
            RAISE EXCEPTION 'selector move output escaped frozen root or original privileges' USING ERRCODE='42501';
        END IF;
        -- Положительное свидетельство сформировано переписью до часов.
        IF jsonb_typeof(outputs->'empty_carriers') IS DISTINCT FROM 'object' THEN
            RAISE EXCEPTION 'selector move requires retained-fact coverage for affected bindings' USING ERRCODE='42501';
        END IF;
        empty_proof:=kaname._authority_role_move_root_carriers_v1(decision->>'role_id',held,command->'access_labels',
            (outputs#>>'{empty_carriers,rows}')::integer,(outputs#>>'{empty_carriers,reads}')::integer);
        IF empty_proof->'empty' IS DISTINCT FROM 'true'::jsonb THEN
            RAISE EXCEPTION 'selector move carrier set changed after reservation' USING ERRCODE='40001';
        END IF;
        new_row:=jsonb_set(old_row,'{access_labels}',command->'access_labels',false);
        journal_id:=NULL;
        IF source_table<>'resource_mirror' THEN
            accepted:=jsonb_build_object('table',source_table,'operation','UPDATE','when','AFTER','old',old_row,'new',new_row);
            SELECT e.reserved_id INTO STRICT journal_id FROM pg_temp.kaname_authority_sequence_effects e
            WHERE e.nonce=root_write.nonce AND e.table_name='resource_journal' AND e.selected AND NOT (e.registered OR e.claimed OR e.consumed)
                AND e.origin_digest=sha256(convert_to(accepted::text,'UTF8')) AND e.origin=accepted;
        ELSE
            PERFORM kaname._authority_role_move_root_registration_v1(held);
        END IF;
        active:=jsonb_build_object('index',item.ordinality-1,'old',old_row,'new',new_row,'journal_id',journal_id,
            'freshness',jsonb_build_object('root_type',command->'root_type','root_id',command->'root_id',
                'prior_generation',outputs->'prior_generation','facts',outputs->'prior_facts'));
        bytes:=bytes+octet_length(active::text)+1;
        IF bytes>16777216 THEN RAISE EXCEPTION 'selector move final root receipts exceed byte budget' USING ERRCODE='54000';END IF;
        receipts:=array_append(receipts,active);
    END LOOP;
    FOREACH active IN ARRAY receipts LOOP
        command:=commands->((active->>'index')::integer);
        coord:=(command->>'root_type')||':'||(command->>'root_id');
        outputs:=frozen#>ARRAY['selector_move_outputs',coord];
        physical:=command->'physical';
        UPDATE pg_temp.kaname_authority_sequence_program s SET frozen=s.frozen||jsonb_build_object('selector_move_active',active)
        WHERE s.singleton AND s.nonce=root_write.nonce AND s.family='role' AND s.frozen=root_write.frozen;
        IF NOT FOUND THEN RAISE EXCEPTION 'selector move root already armed' USING ERRCODE='42501';END IF;
        IF command->>'table'='resource_mirror' THEN
            UPDATE ONLY kaname.resource_mirror AS r SET access_labels=command->'access_labels'
            WHERE r.object_type=command->>'root_type' AND r.object_id=command->>'root_id'
                AND r.xmin::text=physical->>0 AND r.ctid::text=physical->>1 AND to_jsonb(r)=physical->2
            RETURNING jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r)) INTO after_physical;
        ELSE
            EXECUTE format('UPDATE ONLY kaname.%I AS r SET access_labels=$1
                WHERE r.id=$2 AND r.xmin::text=$3 AND r.ctid::text=$4 AND to_jsonb(r)=$5
                RETURNING jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r))',command->>'table')
            INTO after_physical USING command->'access_labels',command->>'root_id',physical->>0,physical->>1,physical->2;
        END IF;
        GET DIAGNOSTICS n=ROW_COUNT;
        IF n<>1 OR after_physical->2 IS DISTINCT FROM active->'new' THEN
            RAISE EXCEPTION 'selector move physical root changed before write' USING ERRCODE='40001';
        END IF;
        IF NOT EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_program s WHERE s.singleton AND s.nonce=root_write.nonce
            AND s.frozen->'selector_move_active'=active||jsonb_build_object('installed',root_write.nonce)) THEN
            RAISE EXCEPTION 'selector move generation was not installed' USING ERRCODE='42501';
        END IF;
        IF active->>'journal_id' IS NOT NULL AND NOT EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_effects e
            WHERE e.nonce=root_write.nonce AND e.table_name='resource_journal' AND e.reserved_id=(active->>'journal_id')::bigint
            AND e.selected AND e.registered AND e.claimed AND e.consumed) THEN
            RAISE EXCEPTION 'selector move root journal was not consumed' USING ERRCODE='42501';
        END IF;
        audit_row:=jsonb_populate_record(NULL::kaname.audit_outbox,outputs->'audit');
        INSERT INTO kaname.audit_outbox AS a
            (id,event_type,tenant_account_id,event_payload,status,attempts,created_at,next_attempt_at,sent_at,last_error)
        VALUES(audit_row.id,audit_row.event_type,audit_row.tenant_account_id,audit_row.event_payload,audit_row.status,
            audit_row.attempts,audit_row.created_at,audit_row.next_attempt_at,audit_row.sent_at,audit_row.last_error)
        RETURNING to_jsonb(a) INTO actual;
        IF actual IS DISTINCT FROM outputs->'audit' THEN RAISE EXCEPTION 'selector move audit output changed' USING ERRCODE='42501';END IF;
        reconcile_row:=jsonb_populate_record(NULL::kaname.resource_reconcile_outbox,outputs->'reconcile');
        INSERT INTO kaname.resource_reconcile_outbox AS r
            (id,object_type,object_id,event_type,created_at,sent_at,last_error,attempt_count)
        OVERRIDING SYSTEM VALUE VALUES(reconcile_row.id,reconcile_row.object_type,reconcile_row.object_id,reconcile_row.event_type,
            reconcile_row.created_at,reconcile_row.sent_at,reconcile_row.last_error,reconcile_row.attempt_count)
        RETURNING to_jsonb(r) INTO actual;
        IF actual IS DISTINCT FROM outputs->'reconcile' THEN RAISE EXCEPTION 'selector move reconcile output changed' USING ERRCODE='42501';END IF;
        completed:=array_append(completed,jsonb_build_object('version',after_physical-2,'journal_id',active->'journal_id'));
        UPDATE pg_temp.kaname_authority_sequence_program s SET frozen=s.frozen-'selector_move_active'
        WHERE s.singleton AND s.nonce=root_write.nonce AND s.frozen->'selector_move_active'=active||jsonb_build_object('installed',root_write.nonce);
        IF NOT FOUND THEN RAISE EXCEPTION 'selector move root state changed' USING ERRCODE='42501';END IF;
    END LOOP;
    UPDATE pg_temp.kaname_authority_sequence_program s SET frozen=s.frozen||jsonb_build_object(
        'selector_move_written',to_jsonb(completed),'selector_move_roots_completed',cardinality(completed))
    WHERE s.singleton AND s.nonce=root_write.nonce AND s.family='role' AND s.frozen=root_write.frozen;
    IF NOT FOUND THEN RAISE EXCEPTION 'selector move root outputs already completed' USING ERRCODE='42501';END IF;
END;
$write$;
-- +goose StatementEnd

-- Повторное чтение перед COMMIT обнаруживает изменение результата той же
-- транзакцией после возврата писателя. Внешние транзакции ждут удержанных ключей.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_roots_complete_v1() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $complete$
DECLARE
    program jsonb:=kaname._authority_sequence_store_v3();
    frozen jsonb:=program->'frozen';
    commands jsonb:=frozen#>'{selector_move_decision,commands}';
    item record;
    v_nonce uuid:=(program->>'nonce')::uuid;
    dotted text;
    v_id text;
    coord text;
    expected jsonb;
    outputs jsonb;
    state jsonb;
    actual jsonb;
    facts jsonb;
    expected_journal bigint;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF NOT (frozen ? 'selector_move') THEN RETURN;END IF;
    IF program->>'family' IS DISTINCT FROM 'role' OR jsonb_typeof(commands) IS DISTINCT FROM 'array'
        OR frozen ? 'selector_move_active' THEN
        RAISE EXCEPTION 'selector move root program incomplete at commit' USING ERRCODE='42501';
    END IF;
    IF commands='[]'::jsonb THEN RETURN;END IF;
    IF jsonb_typeof(frozen->'selector_move_written') IS DISTINCT FROM 'array'
        OR jsonb_array_length(frozen->'selector_move_written')<>jsonb_array_length(commands)
        OR frozen->'selector_move_roots_completed' IS DISTINCT FROM to_jsonb(jsonb_array_length(commands)) THEN
        RAISE EXCEPTION 'selector move root receipts absent at commit' USING ERRCODE='42501';
    END IF;
    FOR item IN SELECT c.value AS cmd,c.ordinality AS ord FROM jsonb_array_elements(commands) WITH ORDINALITY c LOOP
        dotted:=item.cmd->>'root_type';v_id:=item.cmd->>'root_id';coord:=dotted||':'||v_id;
        outputs:=frozen#>ARRAY['selector_move_outputs',coord];
        state:=frozen->'selector_move_written'->(item.ord::integer-1);
        expected:=jsonb_set(item.cmd#>'{physical,2}','{access_labels}',item.cmd->'access_labels',false);
        IF kaname._authority_metadata_root_state_v1(dotted,v_id,false) IS DISTINCT FROM
            ((state->'version')||jsonb_build_array(expected)) THEN
            RAISE EXCEPTION 'selector move copied root changed before commit' USING ERRCODE='40001';
        END IF;
        SELECT to_jsonb(a) INTO actual FROM ONLY kaname.audit_outbox a WHERE a.id=outputs#>>'{audit,id}';
        IF actual IS DISTINCT FROM outputs->'audit' THEN RAISE EXCEPTION 'selector move committed audit differs' USING ERRCODE='42501';END IF;
        SELECT to_jsonb(r) INTO actual FROM ONLY kaname.resource_reconcile_outbox r WHERE r.id=(outputs#>>'{reconcile,id}')::bigint;
        IF actual IS DISTINCT FROM outputs->'reconcile' THEN RAISE EXCEPTION 'selector move committed reconcile differs' USING ERRCODE='42501';END IF;
        expected_journal:=(state->>'journal_id')::bigint;
        IF item.cmd->>'table'<>'resource_mirror' THEN
            IF NOT EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_effects e JOIN ONLY kaname.resource_journal j
                ON j.sequence_no=e.reserved_id WHERE e.nonce=v_nonce AND e.table_name='resource_journal' AND e.selected
                AND e.registered AND e.claimed AND e.consumed AND e.reserved_id=expected_journal
                AND (to_jsonb(j)-'sequence_no')=e.row_value) THEN
                RAISE EXCEPTION 'selector move committed journal differs' USING ERRCODE='42501';
            END IF;
        ELSE
            IF expected_journal IS NOT NULL THEN RAISE EXCEPTION 'selector move mirror claimed an IAM journal' USING ERRCODE='42501';END IF;
            PERFORM kaname._authority_role_move_root_registration_v1(frozen#>ARRAY['selector_move','copies','roots',coord]);
        END IF;
        SELECT jsonb_build_object('generation',r.generation,'labels',r.new_labels) INTO actual
        FROM ONLY kaname.authority_access_label_dirty_root r WHERE r.root_type=dotted AND r.root_id=v_id;
        IF outputs->'prior_facts'='[]'::jsonb THEN
            IF actual IS NOT NULL THEN RAISE EXCEPTION 'unexpected selector move generation at commit' USING ERRCODE='42501';END IF;
        ELSE
            IF actual IS DISTINCT FROM jsonb_build_object('generation',v_nonce,'labels',item.cmd->'access_labels') THEN
                RAISE EXCEPTION 'selector move committed generation differs' USING ERRCODE='42501';
            END IF;
            SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.object_type COLLATE "C",t.object_id COLLATE "C",
                t.relation COLLATE "C",t.subject COLLATE "C"),'[]'::jsonb) INTO facts FROM (
                SELECT d.object_type,d.object_id,d.relation,d.subject FROM ONLY kaname.authority_access_label_dirty_fact d
                WHERE d.root_type=dotted AND d.root_id=v_id AND d.generation=v_nonce LIMIT jsonb_array_length(outputs->'prior_facts')+1
            ) t;
            IF facts IS DISTINCT FROM outputs->'prior_facts' THEN RAISE EXCEPTION 'selector move committed dirty facts differ' USING ERRCODE='42501';END IF;
        END IF;
    END LOOP;
END;
$complete$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure; recipient record;
BEGIN
    FOREACH fn IN ARRAY ARRAY[
        'kaname._authority_role_move_root_registration_v1(jsonb)'::regprocedure,
        'kaname._authority_role_move_root_trigger_v1(oid,jsonb,jsonb,text,text)'::regprocedure,
        'kaname._authority_role_move_roots_write_v1()'::regprocedure,
        'kaname._authority_role_move_roots_complete_v1()'::regprocedure
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
DROP FUNCTION kaname._authority_role_move_roots_complete_v1();
DROP FUNCTION kaname._authority_role_move_roots_write_v1();
DROP FUNCTION kaname._authority_role_move_root_trigger_v1(oid,jsonb,jsonb,text,text);
DROP FUNCTION kaname._authority_role_move_root_registration_v1(jsonb);
