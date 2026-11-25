-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- До финального времени решения удерживаем имя, источники apply и прежнее
-- поколение. Журнал, аудит и пересчёт привязаны к одному OLD/NEW.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_compile_reserve_v1(
    p_desired jsonb,p_audit text,p_actor_type text,p_actor_id text,
    p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $reserve$
DECLARE
    proof jsonb;
    source_program jsonb;
    compiled jsonb;
    physical jsonb;
    old_row jsonb;
    new_row jsonb;
    v_group text;
    v_account text;
    changed_fields jsonb;
    carry jsonb;
    freshness jsonb;
    origin jsonb;
    journal_row jsonb;
    frozen_program jsonb;
    stamp timestamptz:=transaction_timestamp();
    reconcile_id bigint;
    used_rows integer:=4;
    used_reads integer:=8;
    used_work integer:=1;
    union_input_count integer;
    reserve_reads integer;
    affected integer;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
        OR p_work IS NULL OR p_work NOT BETWEEN used_work AND 400000 THEN
        RAISE EXCEPTION 'group metadata reserve budget invalid' USING ERRCODE='54000';
    END IF;
    proof:=kaname.authority_protocol_attestation();
    IF current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
        OR proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'purpose' IS DISTINCT FROM 'decision'
        OR proof->>'writer_contract' IS DISTINCT FROM '2'
        OR coalesce(p_audit,'') COLLATE "C" !~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$' THEN
        RAISE EXCEPTION 'group metadata reserve needs the signed resource writer' USING ERRCODE='42501';
    END IF;
    IF NOT coalesce(has_table_privilege((proof->>'invoker_oid')::oid,'kaname.audit_outbox','INSERT')
        AND has_table_privilege((proof->>'invoker_oid')::oid,'kaname.resource_reconcile_outbox','INSERT')
        AND has_sequence_privilege((proof->>'invoker_oid')::oid,'kaname.resource_reconcile_outbox_id_seq','USAGE,UPDATE'),false) THEN
        RAISE EXCEPTION 'group metadata reserve lacks original outbox privileges' USING ERRCODE='42501';
    END IF;
    source_program:=kaname._authority_metadata_group_compile_sources_v1(
        p_desired,p_actor_type,p_actor_id,p_rows-used_rows,p_reads-used_reads,p_work-used_work);
    used_rows:=used_rows+(source_program->>'rows')::integer;
    used_reads:=used_reads+(source_program->>'reads')::integer;
    used_work:=used_work+(source_program->>'work')::integer;
    compiled:=source_program->'compiled';
    old_row:=compiled->'old_row';
    new_row:=compiled->'new_row';
    physical:=compiled->'root_physical';
    v_group:=compiled#>>'{receipt,root_id}';
    v_account:=old_row->>'account_id';
    IF compiled#>>'{receipt,root_type}' IS DISTINCT FROM 'iam.group'
        OR coalesce(v_group,'')='' OR coalesce(v_account,'')=''
        OR physical->>'table' IS DISTINCT FROM 'groups' OR physical->>'id' IS DISTINCT FROM v_group
        OR new_row->>'account_id' IS DISTINCT FROM v_account
        OR new_row->>'id' IS DISTINCT FROM v_group OR old_row->>'id' IS DISTINCT FROM v_group
        OR (old_row-ARRAY['name','description','labels','access_labels']) IS DISTINCT FROM
           (new_row-ARRAY['name','description','labels','access_labels'])
        OR old_row->'access_labels' IS NOT DISTINCT FROM new_row->'access_labels' THEN
        RAISE EXCEPTION 'group metadata reserve receipt differs' USING ERRCODE='42501';
    END IF;
    IF old_row->'name' IS DISTINCT FROM new_row->'name' THEN
        -- Сериализуем проверку отсутствующего имени с обычным Group lifecycle.
        LOCK TABLE ONLY kaname.groups IN SHARE ROW EXCLUSIVE MODE NOWAIT;
        PERFORM id FROM ONLY kaname.groups
        WHERE account_id=v_account AND name=new_row->>'name' AND id<>v_group;
        IF FOUND THEN
            RAISE unique_violation USING CONSTRAINT='groups_account_name_unique',
                MESSAGE='group name already exists in account';
        END IF;
        used_rows:=used_rows+1;
        used_reads:=used_reads+1;
    END IF;
    LOCK TABLE kaname.audit_outbox,kaname.resource_journal,kaname.resource_reconcile_outbox IN ROW EXCLUSIVE MODE;
    PERFORM pg_advisory_xact_lock(1262569298,hashtext(p_audit));
    PERFORM id FROM ONLY kaname.audit_outbox WHERE id=p_audit FOR UPDATE;
    IF FOUND THEN
        RAISE EXCEPTION 'group audit id already used' USING ERRCODE='40001';
    END IF;
    reconcile_id:=nextval('kaname.resource_reconcile_outbox_id_seq');
    IF reconcile_id<=0 THEN
        RAISE EXCEPTION 'group reconcile sequence exhausted' USING ERRCODE='P1034';
    END IF;
    -- Без строки на этом ID FOR UPDATE сам по себе не защищает от вставки.
    IF NOT pg_try_advisory_xact_lock(1262569299,hashtext(reconcile_id::text)) THEN
        RAISE EXCEPTION 'group reconcile id busy; restage required' USING ERRCODE='40001';
    END IF;
    PERFORM id FROM ONLY kaname.resource_reconcile_outbox WHERE id=reconcile_id FOR UPDATE;
    IF FOUND THEN
        RAISE EXCEPTION 'group reconcile id already used' USING ERRCODE='40001';
    END IF;
    carry:=kaname._authority_metadata_access_label_carry_v1(
        'iam.group',v_group,old_row->'access_labels',p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(carry->>'rows')::integer;
    used_reads:=used_reads+(carry->>'reads')::integer;
    union_input_count:=jsonb_array_length(compiled#>'{receipt,facts}')+jsonb_array_length(carry->'prior_facts');
    IF union_input_count IS NULL OR used_rows IS NULL OR used_rows+union_input_count>p_rows
        OR used_reads IS NULL OR used_reads>p_reads OR used_work IS NULL OR used_work+2*union_input_count>p_work THEN
        RAISE EXCEPTION 'group metadata freshness reserve budget exceeded' USING ERRCODE='54000';
    END IF;
    SELECT jsonb_build_object('root_type','iam.group','root_id',v_group,
        'old_labels',old_row->'access_labels','new_labels',new_row->'access_labels',
        'prior_generation',carry->'prior_generation',
        'facts',coalesce(jsonb_agg(fact ORDER BY fact::text COLLATE "C"),'[]'::jsonb))
    INTO freshness FROM (
        SELECT value AS fact FROM jsonb_array_elements(compiled#>'{receipt,facts}')
        UNION SELECT value AS fact FROM jsonb_array_elements(carry->'prior_facts')
    ) q;
    used_rows:=used_rows+jsonb_array_length(freshness->'facts');
    used_work:=used_work+union_input_count+jsonb_array_length(freshness->'facts');
    origin:=jsonb_build_object('table','groups','operation','UPDATE','when','AFTER','old',old_row,'new',new_row);
    journal_row:=jsonb_build_object('resource_kind','iam_group','resource_id',v_group,
        'project_id',kaname.resource_journal_project('iam_group',new_row),
        'scope',kaname.resource_journal_scope('iam_group',new_row),
        'event_type','UPDATED','payload',jsonb_build_object('id',v_group));
    reserve_reads:=kaname._authority_sequence_reserve_v3('metadata',
        jsonb_build_array(jsonb_build_object('table','resource_journal','origin',origin,
            'ordinal',1,'row',journal_row,'stamp','transaction')),least(16,p_reads-used_reads));
    used_reads:=used_reads+reserve_reads;
    IF used_reads IS NULL OR used_reads>p_reads THEN
        RAISE EXCEPTION 'group metadata journal reserve budget exceeded' USING ERRCODE='54000';
    END IF;
    SELECT jsonb_agg(k ORDER BY n) INTO changed_fields
    FROM unnest(ARRAY['name','description','labels','access_labels']) WITH ORDINALITY fields(k,n)
    WHERE old_row->k IS DISTINCT FROM new_row->k;
    frozen_program:=jsonb_build_object('kind','metadata.access_labels','mode','group_access_labels',
        'access_label_authority',source_program->'authority','access_label_requirements',source_program->'requirements',
        'access_label_freshness',freshness,'access_label_root_physical',physical,
        'access_label_freshness_proofs',jsonb_build_object('candidate_facts',compiled#>'{receipt,facts}',
            'prior_facts',carry->'prior_facts','retention',compiled->'retention'),
        'access_label_audit_id',p_audit,'group_update_question',compiled->'update_question',
        'group_audit',jsonb_build_object('id',p_audit,'event_type','iam.group.updated','tenant_account_id',v_account,
            'event_payload',jsonb_build_object('actor',p_actor_id,'account_id',v_account,
                'resource_type','group','resource_id',v_group,'changed_fields',changed_fields),
            'status','pending','attempts',0,'created_at',stamp,'next_attempt_at',stamp,'sent_at',NULL,'last_error',NULL),
        'group_reconcile',jsonb_build_object('id',reconcile_id,'event_type','mirror.upsert',
            'object_type','iam.group','object_id',v_group,'created_at',stamp,'attempt_count',0,'sent_at',NULL,'last_error',NULL));
    IF octet_length(frozen_program::text)>67108864 THEN
        RAISE EXCEPTION 'group metadata frozen receipt too large' USING ERRCODE='54000';
    END IF;
    UPDATE pg_temp.kaname_authority_sequence_program p SET frozen=frozen_program,frozen_mode='group_access_labels'
    WHERE p.singleton AND p.nonce=(proof->>'nonce')::uuid AND p.family='metadata'
        AND p.staged_decision_at=(proof->>'decision_at')::timestamptz
        AND p.frozen='{}'::jsonb AND p.frozen_mode IS NULL AND p.selected_count IS NULL;
    GET DIAGNOSTICS affected=ROW_COUNT;
    IF affected<>1 THEN
        RAISE EXCEPTION 'group metadata verified command was not frozen once' USING ERRCODE='42501';
    END IF;
    RETURN jsonb_build_object('rows',used_rows,'reads',used_reads,'work',used_work);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'group metadata reserve busy; restage required' USING ERRCODE='40001';
END;
$reserve$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE
    fn regprocedure:='kaname._authority_metadata_group_compile_reserve_v1(jsonb,text,text,text,integer,integer,integer)'::regprocedure;
    grantee record;
BEGIN
    FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
        WHERE p.oid=fn AND a.grantee<>p.proowner
    LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
            CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE quote_ident(grantee.rolname) END);
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_metadata_group_compile_reserve_v1(jsonb,text,text,text,integer,integer,integer);
