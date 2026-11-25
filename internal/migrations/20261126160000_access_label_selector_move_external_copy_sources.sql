-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Предфинальный шаг писателя роли. Выбор цели по правилам, объектное право
-- update и проверка источников apply на decision_at принадлежат общей программе.
-- У каждого зеркала собственная квитанция, пригодная для нескольких копий за транзакцию.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_external_copy_sources_hold_v1(
    p_root_type text, p_root_id text, p_expected jsonb, p_access_labels jsonb,
    p_actor_type text, p_actor_id text, p_rows integer, p_reads integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    physical jsonb;
    old_row jsonb;
    old_access jsonb;
    catalog_state jsonb;
    verb_state jsonb;
    account_state jsonb;
    project_state jsonb;
    binding_state jsonb;
    registration_states jsonb;
    model_type text;
    v_account text;
    v_project text;
    delta record;
    definition record;
    requirements jsonb:='[]';
    sources jsonb;
    -- Семь отношений, три триггера постоянной привязки, ключ и точечные чтения.
    -- На предикат регистрации достаточно двух строк: при составном PK лишь
    -- одна из них может точно совпасть с парой (проект, аккаунт) зеркала.
    used_rows integer:=19;
    used_reads integer:=11;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF current_setting('transaction_isolation') IS DISTINCT FROM 'read committed' THEN
        RAISE EXCEPTION 'external copy hold requires READ COMMITTED' USING ERRCODE='25001';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
        RAISE EXCEPTION 'external copy source budget exhausted' USING ERRCODE='54000';
    END IF;
    IF kaname._authority_access_label_dirty_root_type_valid_v1(p_root_type) IS DISTINCT FROM true
        OR split_part(p_root_type,'.',1)='iam' OR coalesce(p_root_id,'')=''
        OR octet_length(p_root_id)>16384 OR p_root_id ~ '[:#*[:space:][:cntrl:]]'
        OR jsonb_typeof(p_expected) IS DISTINCT FROM 'array'
        OR kaname.access_labels_valid_v1(p_access_labels) IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'invalid external copy coordinate or labels' USING ERRCODE='42501';
    END IF;

    LOCK TABLE ONLY kaname.catalog_resource, ONLY kaname.catalog_verb,
        ONLY kaname.resource_mirror, ONLY kaname.accounts, ONLY kaname.projects IN ROW SHARE MODE NOWAIT;
    -- ROW EXCLUSIVE допускает писателей других привязок и удерживает DDL
    -- триггеров. Пустой результат по привязке защитит общий ключ регистрации.
    LOCK TABLE ONLY kaname.object_project_binding IN ROW EXCLUSIVE MODE NOWAIT;
    -- У сохранённых областей нет guard по (model,id). Даже новая строка
    -- с чужим аккаунтом должна конфликтовать до завершения копирования.
    LOCK TABLE ONLY kaname.resource_registration_scope IN SHARE MODE NOWAIT;
    IF EXISTS (SELECT FROM pg_catalog.pg_class c WHERE c.oid IN
        ('kaname.catalog_resource'::regclass,'kaname.catalog_verb'::regclass,'kaname.resource_mirror'::regclass,
         'kaname.accounts'::regclass,'kaname.projects'::regclass,'kaname.object_project_binding'::regclass,
         'kaname.resource_registration_scope'::regclass)
        AND (c.relkind<>'r' OR c.relpersistence<>'p' OR c.relrowsecurity OR c.relforcerowsecurity
            OR c.relispartition OR c.relhassubclass OR c.relhasrules
            OR EXISTS (SELECT FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid))) THEN
        RAISE EXCEPTION 'external copy source relation shape differs' USING ERRCODE='42501';
    END IF;
    IF current_setting('session_replication_role') NOT IN ('origin','local')
        OR EXISTS (SELECT FROM (VALUES
            ('authority_registration_binding_guard_v2','authority_registration_binding_guard_v2',23),
            ('object_project_binding_is_permanent','object_project_binding_is_permanent',27),
            ('object_project_binding_is_not_truncated','object_project_binding_is_permanent',34)
        ) g(name,fn,kind) WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_trigger t
            WHERE t.tgrelid='kaname.object_project_binding'::regclass AND t.tgname=g.name
                AND t.tgfoid=to_regprocedure('kaname.'||g.fn||'()') AND t.tgtype=g.kind
                AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal AND t.tgqual IS NULL
                AND t.tgnargs=0 AND t.tgattr::text='' AND t.tgconstraint=0
                AND NOT t.tgdeferrable AND NOT t.tginitdeferred
                AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL)) THEN
        RAISE EXCEPTION 'external copy registration guard unavailable' USING ERRCODE='42501';
    END IF;
    SELECT jsonb_build_array(c.xmin::text,c.ctid::text,to_jsonb(c)),c.object_type
        INTO catalog_state,model_type FROM ONLY kaname.catalog_resource c
        WHERE c.dotted=p_root_type AND c.module||'.'||c.resource=c.dotted AND c.live AND c.module<>'iam'
            AND c.object_type COLLATE "C" ~ '^[a-z][a-z0-9_]*$'
            AND c.object_type NOT IN ('iam_grant_scope','iam_grant_role','iam_grant_access_label')
        FOR SHARE OF c NOWAIT;
    SELECT jsonb_build_array(v.xmin::text,v.ctid::text,to_jsonb(v)) INTO verb_state
        FROM ONLY kaname.catalog_verb v WHERE v.module=catalog_state#>>'{2,module}'
            AND v.resource=catalog_state#>>'{2,resource}' AND v.verb='update' AND v.live AND v.per_object
        FOR SHARE OF v NOWAIT;
    IF verb_state IS NULL THEN
        RAISE EXCEPTION 'external copy live object update unavailable' USING ERRCODE='42501';
    END IF;
    IF NOT pg_try_advisory_xact_lock_shared(1262569300,hashtext(jsonb_build_array(model_type,p_root_id)::text)) THEN
        RAISE EXCEPTION 'external copy registration binding busy' USING ERRCODE='40001';
    END IF;
    SELECT jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) INTO physical
        FROM ONLY kaname.resource_mirror m WHERE m.object_type=p_root_type AND m.object_id=p_root_id
        FOR UPDATE OF m NOWAIT;
    IF physical IS NULL OR physical IS DISTINCT FROM p_expected THEN
        RAISE EXCEPTION 'external copy mirror changed before capture' USING ERRCODE='40001';
    END IF;
    old_row:=physical->2;
    old_access:=old_row->'access_labels';
    IF kaname.access_labels_valid_v1(old_access) IS DISTINCT FROM true
        OR jsonb_typeof(old_row->'labels') IS DISTINCT FROM 'object'
        OR NOT (p_access_labels @> old_access) OR p_access_labels=old_access THEN
        RAISE EXCEPTION 'external selector move must only add protected copies' USING ERRCODE='42501';
    END IF;
    v_project:=nullif(old_row->>'parent_project_id','');
    IF v_project IS NOT NULL THEN
        SELECT jsonb_build_array(p.xmin::text,p.ctid::text,to_jsonb(p)) INTO project_state
            FROM ONLY kaname.projects p WHERE p.id=v_project FOR SHARE OF p NOWAIT;
    END IF;
    v_account:=coalesce(nullif(old_row->>'parent_account_id',''),project_state#>>'{2,account_id}');
    SELECT jsonb_build_array(a.xmin::text,a.ctid::text,to_jsonb(a)) INTO account_state
        FROM ONLY kaname.accounts a WHERE a.id=v_account FOR SHARE OF a NOWAIT;
    IF account_state IS NULL OR v_account COLLATE "C" !~ '^acc[a-zA-Z0-9_-]{1,61}$'
        OR (v_project IS NOT NULL AND (project_state#>>'{2,account_id}' IS DISTINCT FROM v_account
            OR v_project COLLATE "C" !~ '^prj[a-zA-Z0-9_-]{1,61}$')) THEN
        RAISE EXCEPTION 'external copy owner scope unavailable' USING ERRCODE='42501';
    END IF;
    SELECT jsonb_build_array(b.xmin::text,b.ctid::text,to_jsonb(b)) INTO binding_state
        FROM ONLY kaname.object_project_binding b WHERE b.object_type=model_type AND b.object_id=p_root_id FOR SHARE OF b NOWAIT;
    SELECT coalesce(jsonb_agg(s.state),'[]'::jsonb) INTO registration_states FROM (
        SELECT jsonb_build_array(s.xmin::text,s.ctid::text,to_jsonb(s)) AS state
        FROM ONLY kaname.resource_registration_scope s WHERE s.object_type=model_type AND s.object_id=p_root_id LIMIT 2
    ) s;
    IF (binding_state IS NOT NULL AND binding_state#>>'{2,project_id}' IS DISTINCT FROM v_project)
        OR EXISTS (SELECT FROM jsonb_array_elements(registration_states) s
            WHERE s#>>'{2,project_id}' IS DISTINCT FROM coalesce(v_project,'')
                OR s#>>'{2,account_id}' IS DISTINCT FROM v_account) THEN
        RAISE EXCEPTION 'external copy registered scope differs from mirror' USING ERRCODE='42501';
    END IF;

    -- SHARE удерживает и отсутствие второго применимого определения.
    -- Канонический helper сверяет физическую редакцию и допустимое значение.
    used_rows:=used_rows+(SELECT count(*) FROM jsonb_object_keys(p_access_labels))
        +(SELECT count(*) FROM jsonb_object_keys(old_access));
    IF used_rows>p_rows THEN
        RAISE EXCEPTION 'external copy source budget exhausted' USING ERRCODE='54000';
    END IF;
    PERFORM kaname._authority_role_move_copy_registry_hold_v1();
    FOR delta IN SELECT n.key,n.value FROM jsonb_each_text(p_access_labels) n
        WHERE NOT (old_access ? n.key) ORDER BY n.key COLLATE "C"
    LOOP
        IF to_jsonb(delta.value) IS DISTINCT FROM (old_row->'labels'->delta.key) THEN
            RAISE EXCEPTION 'external copy differs from ordinary label' USING ERRCODE='42501';
        END IF;
        used_rows:=used_rows+CASE WHEN v_project IS NULL THEN 4 ELSE 5 END;
        used_reads:=used_reads+3;
        IF used_rows>p_rows OR used_reads>p_reads THEN
            RAISE EXCEPTION 'external copy definition budget exhausted' USING ERRCODE='54000';
        END IF;
        BEGIN
            SELECT d.id,d.scope_kind,d.scope_id,d.revision,d.xmin::text AS row_xmin,d.ctid::text AS row_ctid
                INTO STRICT definition
                FROM (VALUES ('cluster','cluster_root'),('account',v_account),('project',v_project)) s(kind,id)
                JOIN ONLY kaname.authority_access_label_definition d ON d.scope_kind=s.kind AND d.scope_id=s.id
                WHERE d.module=catalog_state#>>'{2,module}' AND d.resource=catalog_state#>>'{2,resource}'
                    AND d.label_key=delta.key LIMIT 2;
        EXCEPTION WHEN no_data_found OR too_many_rows THEN
            RAISE EXCEPTION 'external copy requires one applicable definition' USING ERRCODE='42501';
        END;
        IF kaname.authority_access_label_definition_hold_v1(definition.scope_kind,definition.scope_id,
            catalog_state#>>'{2,module}',catalog_state#>>'{2,resource}',delta.key,definition.id,
            definition.revision,definition.row_xmin,definition.row_ctid,delta.value) IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'external copy value or definition generation rejected' USING ERRCODE='42501';
        END IF;
        requirements:=requirements||jsonb_build_array(jsonb_build_object('key',delta.key,'old_value',NULL,
            'new_value',delta.value,'definition_id',definition.id,'scope_kind',definition.scope_kind,
            'scope_id',definition.scope_id,'revision',definition.revision,
            'row_xmin',definition.row_xmin,'row_ctid',definition.row_ctid));
    END LOOP;
    sources:=kaname._authority_resource_access_label_sources_hold_v1(p_actor_type,p_actor_id,
        requirements,p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(sources->>'rows')::integer;
    used_reads:=used_reads+(sources->>'reads')::integer;
    IF used_rows IS NULL OR used_rows>p_rows OR used_reads IS NULL OR used_reads>p_reads THEN
        RAISE EXCEPTION 'external copy source budget exhausted' USING ERRCODE='54000';
    END IF;
    RETURN jsonb_build_object('root_type',p_root_type,'root_id',p_root_id,'physical',physical,
        'new_access_labels',p_access_labels,'requirements',requirements,'authority',sources,
        'catalog',catalog_state,'root_update_verb',verb_state,'account',account_state,'project',project_state,
        'binding',binding_state,'registration_scopes',registration_states,'rows',used_rows,'reads',used_reads);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'external copy source busy' USING ERRCODE='40001';
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE
    signature constant regprocedure:='kaname._authority_role_move_external_copy_sources_hold_v1(text,text,jsonb,jsonb,text,text,integer,integer)'::regprocedure;
    grantee record;
BEGIN
    FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
        WHERE p.oid=signature AND a.grantee<>p.proowner
    LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',signature,
            CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_role_move_external_copy_sources_hold_v1(text,text,jsonb,jsonb,text,text,integer,integer);
