-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Из подписанного решения и удержанного снимка восстанавливаем одну команду.
-- Аргументы вызывающего кода не участвуют в выборе строк или ID.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_command_v1()
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $command$
DECLARE
    proof jsonb;
    header jsonb;
    prepared jsonb;
    retained jsonb;
    old_row jsonb;
    new_row jsonb;
    physical jsonb;
    v_group text;
    v_account text;
    actor jsonb;
    question jsonb;
    freshness jsonb;
    approved jsonb;
    staged_at timestamptz;
    decided_at timestamptz;
    audit_id text;
    audit_row jsonb;
    reconcile_row jsonb;
    changed_fields jsonb;
    maximum jsonb;
    chosen jsonb;
    discarded jsonb;
    origin jsonb;
    slot jsonb;
    journal_row jsonb;
    effect record;
    versions jsonb;
    installed jsonb;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    SELECT x.proof,x.header INTO STRICT proof,header FROM kaname._authority_sequence_probe_v3() x;
    IF proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'writer_contract' IS DISTINCT FROM '2'
        OR proof->>'purpose' IS DISTINCT FROM 'decision' OR proof->>'consumer_abi' IS DISTINCT FROM '2'
        OR proof->>'consumer_profile' IS DISTINCT FROM 'full' OR proof->>'consumer_finalized' IS DISTINCT FROM 'true'
        OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
        OR header->>'family' IS DISTINCT FROM 'metadata' OR header#>>'{frozen,mode}' IS DISTINCT FROM 'group_access_labels'
        OR header->'maximum_count' IS DISTINCT FROM '1'::jsonb OR header->'selected_count' IS DISTINCT FROM '1'::jsonb THEN
        RAISE EXCEPTION 'group metadata command requires final signed singleton' USING ERRCODE='42501';
    END IF;
    SELECT p.staged_decision_at,p.decision_at,p.frozen->'access_label_approved_at',
        p.frozen#>'{access_label_authority,actor}',p.frozen->'group_update_question',
        p.frozen->'access_label_freshness',p.frozen->'access_label_root_physical',
        p.frozen->>'access_label_audit_id',p.frozen->'group_audit',p.frozen->'group_reconcile',
        p.maximum,p.selected,p.unselected,p.frozen->'access_label_freshness_installed',p.frozen->'group_consumed'
    INTO staged_at,decided_at,approved,actor,question,freshness,physical,audit_id,audit_row,reconcile_row,
        maximum,chosen,discarded,installed,versions
    FROM pg_temp.kaname_authority_sequence_program p
    WHERE p.singleton AND p.nonce=(proof->>'nonce')::uuid AND p.family='metadata'
        AND p.frozen->>'mode'='group_access_labels' AND p.frozen->>'kind'='metadata.access_labels';
    IF NOT FOUND OR staged_at IS NULL OR NOT isfinite(staged_at) OR decided_at IS NULL OR NOT isfinite(decided_at)
        OR decided_at<=staged_at OR to_jsonb(decided_at) IS DISTINCT FROM proof->'decision_at'
        OR approved IS DISTINCT FROM to_jsonb(decided_at)
        OR (installed IS NOT NULL AND installed IS DISTINCT FROM proof->'nonce') THEN
        RAISE EXCEPTION 'group metadata command decision or freshness marker differs' USING ERRCODE='42501';
    END IF;

    prepared:=kaname._authority_metadata_access_label_stashed_v1();
    retained:=prepared->'retention';
    old_row:=retained->'old_row';
    new_row:=retained->'new_row';
    v_group:=old_row->>'id';
    v_account:=old_row->>'account_id';
    IF coalesce(v_group,'') COLLATE "C" !~ '^grp[a-zA-Z0-9_-]{1,61}$'
        OR coalesce(v_account,'') COLLATE "C" !~ '^acc[a-zA-Z0-9_-]{1,61}$'
        OR coalesce(proof->>'mode','') NOT IN ('accounts','global')
        OR (proof->>'mode'='accounts' AND (proof->'accounts' ? v_account) IS DISTINCT FROM true)
        OR prepared#>'{root,root_coordinate}' IS DISTINCT FROM jsonb_build_array('iam.group',v_group)
        OR prepared#>>'{root,root_account}' IS DISTINCT FROM v_account
        OR retained->>'root_type' IS DISTINCT FROM 'iam.group' OR retained->>'root_id' IS DISTINCT FROM v_group
        OR retained->>'root_model' IS DISTINCT FROM 'iam_group' OR retained->>'root_source_kind' IS DISTINCT FROM '30'
        OR coalesce(physical->>'xmin','')='' OR coalesce(physical->>'ctid','')=''
        OR physical IS DISTINCT FROM jsonb_build_object('table','groups','id',v_group,
            'xmin',physical->>'xmin','ctid',physical->>'ctid')
        OR physical IS DISTINCT FROM retained->'root_physical'
        OR prepared#>'{root,root_state}' IS DISTINCT FROM jsonb_build_array(physical->'xmin',physical->'ctid',old_row)
        OR jsonb_typeof(new_row) IS DISTINCT FROM 'object'
        OR (old_row-ARRAY['name','description','labels','access_labels']) IS DISTINCT FROM
            (new_row-ARRAY['name','description','labels','access_labels'])
        OR jsonb_typeof(new_row->'name') IS DISTINCT FROM 'string'
        OR jsonb_typeof(new_row->'description') IS DISTINCT FROM 'string'
        OR jsonb_typeof(new_row->'labels') IS DISTINCT FROM 'object'
        OR kaname.access_labels_valid_v1(new_row->'access_labels') IS DISTINCT FROM true
        OR new_row->'access_labels' IS NOT DISTINCT FROM old_row->'access_labels'
        OR freshness->>'root_type' IS DISTINCT FROM 'iam.group' OR freshness->>'root_id' IS DISTINCT FROM v_group
        OR freshness->'old_labels' IS DISTINCT FROM old_row->'access_labels'
        OR freshness->'new_labels' IS DISTINCT FROM new_row->'access_labels'
        OR coalesce(actor->>'type','') NOT IN ('user','service_account') OR coalesce(actor->>'id','')=''
        OR octet_length(actor->>'id')>16384 OR actor->>'id' ~ '[:#*[:space:][:cntrl:]]'
        OR actor IS DISTINCT FROM jsonb_build_object('type',actor->>'type','id',actor->>'id')
        OR question IS DISTINCT FROM jsonb_build_object('subject',(actor->>'type')||':'||(actor->>'id'),
            'relation','v_update','object_type','iam_group','object_id',v_group)
        OR question IS DISTINCT FROM retained->'update_question' OR question IS DISTINCT FROM prepared#>'{root,update_question}' THEN
        RAISE EXCEPTION 'group metadata command differs from held actor scope or root' USING ERRCODE='42501';
    END IF;

    SELECT jsonb_agg(k ORDER BY n) INTO changed_fields
    FROM unnest(ARRAY['name','description','labels','access_labels']) WITH ORDINALITY fields(k,n)
    WHERE old_row->k IS DISTINCT FROM new_row->k;
    IF coalesce(audit_id,'') COLLATE "C" !~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$'
        OR audit_row IS DISTINCT FROM jsonb_build_object('id',audit_id,'event_type','iam.group.updated',
            'tenant_account_id',v_account,'event_payload',jsonb_build_object('actor',actor->>'id','account_id',v_account,
                'resource_type','group','resource_id',v_group,'changed_fields',changed_fields),
            'status','pending','attempts',0,'created_at',transaction_timestamp(),'next_attempt_at',transaction_timestamp(),
            'sent_at',NULL,'last_error',NULL)
        OR jsonb_typeof(reconcile_row->'id') IS DISTINCT FROM 'number'
        OR coalesce(reconcile_row->>'id','') !~ '^[1-9][0-9]{0,18}$'
        OR (reconcile_row->>'id')::numeric>9223372036854775807
        OR reconcile_row IS DISTINCT FROM jsonb_build_object('id',reconcile_row->'id','object_type','iam.group',
            'object_id',v_group,'event_type','mirror.upsert','created_at',transaction_timestamp(),
            'sent_at',NULL,'last_error',NULL,'attempt_count',0) THEN
        RAISE EXCEPTION 'group metadata audit or reconcile reservation differs' USING ERRCODE='42501';
    END IF;
    -- Единственное место в maximum и selected должно принадлежать одному AFTER UPDATE.
    -- LIMIT 2 отличает как лишнюю строку, так и подмену одноэлементного счётчика.
    BEGIN
        SELECT e.* INTO STRICT effect FROM pg_temp.kaname_authority_sequence_effects e LIMIT 2;
    EXCEPTION WHEN no_data_found OR too_many_rows THEN
        RAISE EXCEPTION 'group metadata journal is not a singleton' USING ERRCODE='42501';
    END;
    origin:=jsonb_build_object('table','groups','operation','UPDATE','when','AFTER','old',old_row,'new',new_row);
    journal_row:=jsonb_build_object('resource_kind','iam_group','resource_id',v_group,
        'project_id',kaname.resource_journal_project('iam_group',new_row),'scope',kaname.resource_journal_scope('iam_group',new_row),
        'event_type','UPDATED','payload',jsonb_build_object('id',v_group));
    slot:=jsonb_build_object('table','resource_journal','origin',origin,'ordinal',1,'row',journal_row,
        'stamp','transaction','reserved_id',effect.reserved_id);
    journal_row:=journal_row||jsonb_build_object('created_at',transaction_timestamp());
    IF effect.nonce IS DISTINCT FROM (proof->>'nonce')::uuid OR effect.ordinal IS DISTINCT FROM 1
        OR effect.table_name IS DISTINCT FROM 'resource_journal' OR effect.selected IS DISTINCT FROM true
        OR effect.reserved_id IS NULL OR effect.reserved_id<=0 OR effect.origin IS DISTINCT FROM origin
        OR effect.origin_digest IS DISTINCT FROM sha256(convert_to(origin::text,'UTF8'))
        OR effect.row_digest IS DISTINCT FROM sha256(convert_to(journal_row::text,'UTF8'))
        OR effect.row_value IS DISTINCT FROM journal_row OR maximum IS DISTINCT FROM jsonb_build_array(slot)
        OR chosen IS DISTINCT FROM jsonb_build_array(slot||jsonb_build_object('row',journal_row))
        OR discarded IS DISTINCT FROM '[]'::jsonb
        OR effect.registered IS DISTINCT FROM effect.consumed OR effect.claimed IS DISTINCT FROM effect.consumed THEN
        RAISE EXCEPTION 'group metadata selected journal differs from held command' USING ERRCODE='42501';
    END IF;
    IF versions IS NOT NULL AND (NOT effect.consumed OR installed IS NULL OR jsonb_typeof(versions) IS DISTINCT FROM 'object'
        OR NOT (versions ?& ARRAY['group','audit','reconcile','journal'])
        OR versions-ARRAY['group','audit','reconcile','journal'] IS DISTINCT FROM '{}'::jsonb) THEN
        RAISE EXCEPTION 'group metadata consumption marker differs' USING ERRCODE='42501';
    END IF;
    RETURN jsonb_build_object('nonce',proof->'nonce','id',v_group,'account_id',v_account,'old',old_row,'new',new_row,
        'physical',physical,'audit_row',audit_row,'reconcile_row',reconcile_row,
        'journal_row',journal_row||jsonb_build_object('sequence_no',effect.reserved_id),
        'phase',CASE WHEN versions IS NULL THEN 'pending' ELSE 'consumed' END,'versions',versions,
        'journal_consumed',effect.consumed,'freshness_installed',installed IS NOT NULL);
END;
$command$;
-- +goose StatementEnd

-- Четыре чтения по зарезервированным первичным ключам. Для проверки до COMMIT
-- сохраняем версии строк: повторный UPDATE с теми же значениями меняет ctid.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_output_versions_v1(p_command jsonb)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $versions$
DECLARE
    root_version jsonb;
    audit_version jsonb;
    reconcile_version jsonb;
    journal_version jsonb;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    SELECT jsonb_build_array(g.xmin::text,g.ctid::text) INTO root_version FROM ONLY kaname.groups g
    WHERE g.id=p_command->>'id' AND to_jsonb(g)=p_command->'new';
    IF root_version IS NULL OR root_version=jsonb_build_array(p_command#>'{physical,xmin}',p_command#>'{physical,ctid}') THEN
        RAISE EXCEPTION 'group metadata physical NEW differs' USING ERRCODE='40001';
    END IF;
    SELECT jsonb_build_array(a.xmin::text,a.ctid::text) INTO audit_version FROM ONLY kaname.audit_outbox a
    WHERE a.id=p_command#>>'{audit_row,id}' AND to_jsonb(a)=p_command->'audit_row';
    SELECT jsonb_build_array(r.xmin::text,r.ctid::text) INTO reconcile_version FROM ONLY kaname.resource_reconcile_outbox r
    WHERE r.id=(p_command#>>'{reconcile_row,id}')::bigint AND to_jsonb(r)=p_command->'reconcile_row';
    SELECT jsonb_build_array(j.xmin::text,j.ctid::text) INTO journal_version FROM ONLY kaname.resource_journal j
    WHERE j.sequence_no=(p_command#>>'{journal_row,sequence_no}')::bigint AND to_jsonb(j)=p_command->'journal_row';
    IF audit_version IS NULL OR reconcile_version IS NULL OR journal_version IS NULL THEN
        RAISE EXCEPTION 'group metadata reserved audit reconcile or journal missing or changed' USING ERRCODE='42501';
    END IF;
    RETURN jsonb_build_object('group',root_version,'audit',audit_version,'reconcile',reconcile_version,'journal',journal_version);
END;
$versions$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_consume_v1(p_root_version jsonb)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $consume$
DECLARE
    command jsonb;
    versions jsonb;
    affected integer;
BEGIN
    command:=kaname._authority_metadata_group_command_v1();
    IF command->>'phase' IS DISTINCT FROM 'pending' OR command->'journal_consumed' IS DISTINCT FROM 'true'::jsonb
        OR command->'freshness_installed' IS DISTINCT FROM 'true'::jsonb THEN
        RAISE EXCEPTION 'group metadata command already consumed or incomplete' USING ERRCODE='42501';
    END IF;
    versions:=kaname._authority_metadata_group_output_versions_v1(command);
    -- Сравниваем непосредственно с RETURNING первого физического UPDATE.
    IF p_root_version IS DISTINCT FROM versions->'group' THEN
        RAISE EXCEPTION 'group metadata RETURNING row version differs' USING ERRCODE='40001';
    END IF;
    UPDATE pg_temp.kaname_authority_sequence_program p SET frozen=jsonb_set(p.frozen,'{group_consumed}',versions)
    WHERE p.singleton AND p.nonce=(command->>'nonce')::uuid AND p.family='metadata' AND p.frozen_mode='group_access_labels'
        AND p.frozen->'access_label_freshness_installed'=command->'nonce' AND NOT (p.frozen ? 'group_consumed');
    GET DIAGNOSTICS affected=ROW_COUNT;
    IF affected<>1 THEN
        RAISE EXCEPTION 'group metadata command was not consumed exactly once' USING ERRCODE='42501';
    END IF;
END;
$consume$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_complete_v1()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $complete$
DECLARE
    command jsonb;
BEGIN
    command:=kaname._authority_metadata_group_command_v1();
    IF command->>'phase' IS DISTINCT FROM 'consumed' THEN
        RAISE EXCEPTION 'group metadata command is incomplete at commit' USING ERRCODE='42501';
    END IF;
    IF command->'versions' IS DISTINCT FROM kaname._authority_metadata_group_output_versions_v1(command) THEN
        RAISE EXCEPTION 'group metadata consumed row versions changed before commit' USING ERRCODE='40001';
    END IF;
END;
$complete$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE
    fn regprocedure;
    recipient record;
BEGIN
    FOREACH fn IN ARRAY ARRAY[
        'kaname._authority_metadata_group_command_v1()'::regprocedure,
        'kaname._authority_metadata_group_output_versions_v1(jsonb)'::regprocedure,
        'kaname._authority_metadata_group_consume_v1(jsonb)'::regprocedure,
        'kaname._authority_metadata_group_complete_v1()'::regprocedure
    ] LOOP
        FOR recipient IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
            WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
                CASE WHEN recipient.grantee=0 THEN 'PUBLIC' ELSE quote_ident(recipient.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_metadata_group_complete_v1();
DROP FUNCTION kaname._authority_metadata_group_consume_v1(jsonb);
DROP FUNCTION kaname._authority_metadata_group_output_versions_v1(jsonb);
DROP FUNCTION kaname._authority_metadata_group_command_v1();
