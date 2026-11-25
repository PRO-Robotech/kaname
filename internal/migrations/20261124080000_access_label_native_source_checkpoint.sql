-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Закрытое чтение источника apply и сверка точной ролевой проекции.

-- +goose Up
SELECT kaname.authority_protocol_drain();

-- Источник проверяет одну известную привязку по точным идентификаторам.
-- Внешний координатор получает актёра и источник из подтверждённого снимка,
-- удерживает ревизии и передаёт время окончательного решения после ожиданий.
-- Отрицательный ответ относится только к этой привязке. Предел чтения и
-- рассогласование проекции завершаются ошибкой, отдельно от решения о доступе.
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_access_label_source_check_v1(
    p_actor_type text, p_actor_id text,
    p_scope_kind text, p_scope_id text, p_definition uuid,
    p_binding_id text, p_recipient_type text, p_recipient_id text,
    p_rule_fp text, p_decision_at timestamptz, p_rows integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    source_found boolean;
    rules_bytes integer;
    compiled_count integer;
    origin_current boolean;
    -- По точным ключам: actor, definition, binding, subject, role, origin,
    -- membership и group. Для прямого получателя это безопасный overcharge.
    source_rows constant integer := 8;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF current_setting('transaction_isolation')<>'read committed' THEN
        RAISE EXCEPTION 'native access label source requires READ COMMITTED'
            USING ERRCODE='25001';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN source_rows AND 100000 THEN
        RAISE EXCEPTION 'native access label source row budget is absent'
            USING ERRCODE='54000';
    END IF;
    IF p_actor_type IS NULL OR p_actor_type NOT IN ('user','service_account')
       OR coalesce(p_actor_id,'')='' OR p_actor_id ~ '[*#:]'
       OR p_recipient_type IS NULL OR p_recipient_type NOT IN ('user','service_account','group')
       OR coalesce(p_recipient_id,'')='' OR p_recipient_id ~ '[*#:]'
       OR coalesce(p_binding_id,'')='' OR p_decision_at IS NULL OR NOT isfinite(p_decision_at)
       OR p_definition IS NULL OR p_definition='00000000-0000-0000-0000-000000000000'::uuid
       OR p_rule_fp IS NULL OR p_rule_fp COLLATE "C" !~ '^[0-9a-f]{64}$'
       OR p_scope_kind IS NULL OR p_scope_kind NOT IN ('cluster','account','project')
       OR coalesce(p_scope_id,'')='' THEN
        RAISE EXCEPTION 'invalid exact access label source question'
            USING ERRCODE='23514';
    END IF;

    -- Вся положительная цепочка и сверка authored origin читаются одним
    -- оператором. Нет relation_fact, admin, wildcard или наследования scope.
    WITH source AS MATERIALIZED (
        SELECT r.rules,octet_length(r.rules::text) AS bytes
        FROM kaname.access_bindings b
        JOIN kaname.access_binding_subjects s ON s.binding_id=b.id
            AND s.subject_type=p_recipient_type AND s.subject_id=p_recipient_id
            AND s.resource_type=p_scope_kind AND s.resource_id=p_scope_id
        JOIN kaname.roles r ON r.id=b.role_id AND r.live
        JOIN kaname.authority_role_access_label_rule a ON a.role_id=r.id
            AND a.rule_fp=p_rule_fp AND a.definition_id=p_definition
        JOIN kaname.authority_access_label_definition d ON d.id=a.definition_id
            AND d.scope_kind=p_scope_kind AND d.scope_id=p_scope_id
        WHERE b.id=p_binding_id AND b.resource_type=p_scope_kind AND b.resource_id=p_scope_id
            AND b.status='ACTIVE' AND b.revoked_at IS NULL AND b.grant_capability_version=1
            AND (b.expires_at IS NULL OR b.expires_at>p_decision_at)
            AND ((jsonb_typeof(b.target)='object' AND NOT (b.target ? 'resources'))
                OR b.target->'resources'='[]'::jsonb)
            AND ((p_actor_type='user' AND EXISTS(SELECT 1 FROM kaname.users u WHERE u.id=p_actor_id AND u.email_verified_at IS NOT NULL))
                OR (p_actor_type='service_account' AND EXISTS(
                    SELECT 1 FROM kaname.service_accounts u WHERE u.id=p_actor_id AND u.enabled)))
            AND ((p_recipient_type=p_actor_type AND p_recipient_id=p_actor_id)
                OR (p_recipient_type='group' AND EXISTS(
                    SELECT 1 FROM kaname.group_members m JOIN kaname.groups g ON g.id=m.group_id
                    WHERE m.group_id=p_recipient_id AND m.member_type=p_actor_type AND m.member_id=p_actor_id)))
    ), compiled AS MATERIALIZED (
        -- Compiler сам ограничивает 64 rules * 256 origins и 1024 permissions.
        -- Сверх оставшегося бюджета читается sentinel; положительный origin
        -- в усечённом наборе никогда не даёт true.
        SELECT c.rule_fp,c.definition_id FROM source s
        CROSS JOIN LATERAL kaname.authority_access_label_role_compile_v1(
            CASE WHEN s.bytes<=8388608 THEN s.rules ELSE '[]'::jsonb END) c
        LIMIT least(16384,p_rows-source_rows)+1
    )
    SELECT EXISTS(SELECT 1 FROM source),
        coalesce((SELECT s.bytes FROM source s),0),
        (SELECT count(*)::integer FROM compiled),
        EXISTS(SELECT 1 FROM compiled c WHERE c.rule_fp=p_rule_fp AND c.definition_id=p_definition)
    INTO source_found,rules_bytes,compiled_count,origin_current;

    IF rules_bytes>8388608 OR compiled_count>16384 OR source_rows+compiled_count>p_rows THEN
        RAISE EXCEPTION 'native access label source bound exceeded' USING ERRCODE='54000';
    END IF;
    IF source_found AND NOT origin_current THEN
        RAISE EXCEPTION 'native access label stored origin differs from current role'
            USING ERRCODE='40001';
    END IF;
    RETURN jsonb_build_object('allowed',source_found AND origin_current,
        'rows',source_rows+compiled_count,'reads',2);
END;
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_access_label_role_projection_matches_v1(p_role_id text,p_rows integer)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    live_role boolean;
    compiled_count integer;
    persisted_count integer;
    row_count integer;
    exact_match boolean;
    role_bytes integer;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF coalesce(p_role_id,'')='' THEN
        RAISE EXCEPTION 'access label projection checkpoint requires a role' USING ERRCODE='23514';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN 1 AND 100000 THEN
        RAISE EXCEPTION 'access label projection checkpoint budget is absent' USING ERRCODE='54000';
    END IF;
    -- OLD/NEW здесь не аргументы вызывающего. Сверяются правила читаемой роли
    -- и обе стороны сохранённой проекции в одном снимке PostgreSQL.
    WITH authored AS MATERIALIZED (
        SELECT r.rules,octet_length(r.rules::text) AS bytes
        FROM kaname.roles r WHERE r.id=p_role_id AND r.live
    ), compiled AS MATERIALIZED (
        SELECT c.rule_fp,c.definition_id FROM authored r
        CROSS JOIN LATERAL kaname.authority_access_label_role_compile_v1(
            CASE WHEN r.bytes<=8388608 THEN r.rules ELSE '[]'::jsonb END) c
        LIMIT least(16384,p_rows-1)+1
    ), persisted AS MATERIALIZED (
        SELECT p.rule_fp,p.definition_id FROM kaname.authority_role_access_label_rule p
        WHERE p.role_id=p_role_id LIMIT least(16384,p_rows-1)+1
    ), difference AS (
        (SELECT rule_fp,definition_id FROM compiled EXCEPT SELECT rule_fp,definition_id FROM persisted)
        UNION ALL
        (SELECT rule_fp,definition_id FROM persisted EXCEPT SELECT rule_fp,definition_id FROM compiled)
    )
    SELECT EXISTS(SELECT 1 FROM authored),coalesce((SELECT bytes FROM authored),0),
        (SELECT count(*)::integer FROM compiled),(SELECT count(*)::integer FROM persisted),
        NOT EXISTS(SELECT 1 FROM difference)
    INTO live_role,role_bytes,compiled_count,persisted_count,exact_match;
    row_count:=1+compiled_count+persisted_count;
    IF role_bytes>8388608 OR compiled_count>16384 OR persisted_count>16384 OR row_count>p_rows THEN
        RAISE EXCEPTION 'access label projection checkpoint budget exceeded' USING ERRCODE='54000';
    END IF;
    RETURN jsonb_build_object('matches',live_role AND exact_match,'rows',row_count,'reads',2);
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
DECLARE
    signature text;
    grantee record;
BEGIN
    FOREACH signature IN ARRAY ARRAY[
        'kaname.authority_access_label_source_check_v1(text,text,text,text,uuid,text,text,text,text,timestamptz,integer)',
        'kaname.authority_access_label_role_projection_matches_v1(text,integer)'
    ] LOOP
        FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
            WHERE p.oid=to_regprocedure(signature) AND a.grantee<>p.proowner
        LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',signature,
                CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
        END LOOP;
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $access_label_native_sources$
DECLARE
    item record;
    replacement jsonb;
    fn regprocedure;
    old_body text;
    new_body text;
    definition text;
    needle text;
BEGIN
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние перед изменением чтения источника доступа' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
         (
            '_authority_crud_storage_v3()',
            '8bd9cb6998c20e827881bd5aa9dd6e0398e72470fb20e6e859d3934d7d24995f',
            '7b35d2f4b1997ffca2b4fe6f89988a1d163e750c5ee7fa3fa505aeeffbce8139',
            $patch$[
  [
    " ('authority_access_label_role_projection_apply_v1(jsonb,text,text)','8354841ae2bd79b3fe23fa6bec9aa0d04007384df6354302814b9f2696d60362',false,'v',true,'private'),",
    " ('authority_access_label_role_projection_apply_v1(jsonb,text,text)','8354841ae2bd79b3fe23fa6bec9aa0d04007384df6354302814b9f2696d60362',false,'v',true,'private'),\n ('authority_access_label_source_check_v1(text,text,text,text,uuid,text,text,text,text,timestamptz,integer)','282382e8b48680378f219ab1ae787d36125d4a4f8f8b69c08fbc003940e65639',false,'v',true,'private'),\n ('authority_access_label_role_projection_matches_v1(text,integer)','044de8f3215cefde7b41313278c3e2726142d50bd078cd3b86f423b3f1a71fa3',false,'s',true,'private'),"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_full_contract_storage_v3()',
            '80a047f340b7757682022c6eb609db828b65d3fb30fde46f45f2ab111eebd6e9',
            '192ff1f85511ffa1f6dadd37da3106a595e4024252e04051a06ab481584cd0f2',
            $patch$[
  [
    "8bd9cb6998c20e827881bd5aa9dd6e0398e72470fb20e6e859d3934d7d24995f",
    "7b35d2f4b1997ffca2b4fe6f89988a1d163e750c5ee7fa3fa505aeeffbce8139"
  ]
]$patch$::jsonb
        )    ) AS changes(signature, before_sha, after_sha, substitutions) LOOP
        fn := pg_catalog.to_regprocedure('kaname.' || item.signature);
        IF fn IS NULL THEN RAISE EXCEPTION 'функция % для миграции отсутствует', item.signature USING ERRCODE='55000';END IF;
        SELECT p.prosrc INTO STRICT old_body FROM pg_catalog.pg_proc p WHERE p.oid=fn;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(old_body,'UTF8')),'hex') IS DISTINCT FROM item.before_sha THEN
            RAISE EXCEPTION 'исходное тело функции % не соответствует этой миграции', item.signature USING ERRCODE='55000';
        END IF;
        new_body := old_body;
        FOR replacement IN SELECT value FROM pg_catalog.jsonb_array_elements(item.substitutions) LOOP
            needle := replacement->>0;
            IF length(new_body)-length(replace(new_body,needle,'')) IS DISTINCT FROM length(needle) THEN
                RAISE EXCEPTION 'фрагмент тела функции % не уникален', item.signature USING ERRCODE='55000';
            END IF;
            new_body := replace(new_body,needle,replacement->>1);
        END LOOP;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(new_body,'UTF8')),'hex') IS DISTINCT FROM item.after_sha THEN
            RAISE EXCEPTION 'расчётное тело функции % изменилось', item.signature USING ERRCODE='55000';
        END IF;
        -- PostgreSQL восстанавливает сигнатуру и настройки, CREATE OR REPLACE
        -- сохраняет owner/ACL. Меняется ровно одно полное тело с известным SHA.
        definition := pg_catalog.pg_get_functiondef(fn);
        IF length(definition)-length(replace(definition,old_body,'')) IS DISTINCT FROM length(old_body) THEN
            RAISE EXCEPTION 'определение функции % не содержит единственного исходного тела', item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,old_body,new_body);
        IF (SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex')
            FROM pg_catalog.pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.after_sha THEN
            RAISE EXCEPTION 'установленное тело функции % не совпадает с расчётным', item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние после обновления образов доступа' USING ERRCODE='55000';
    END IF;
END
$access_label_native_sources$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();

-- +goose StatementBegin
DO $access_label_native_sources$
DECLARE
    item record;
    replacement jsonb;
    fn regprocedure;
    old_body text;
    new_body text;
    definition text;
    needle text;
BEGIN
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние перед изменением чтения источника доступа' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
         (
            '_authority_full_contract_storage_v3()',
            '192ff1f85511ffa1f6dadd37da3106a595e4024252e04051a06ab481584cd0f2',
            '80a047f340b7757682022c6eb609db828b65d3fb30fde46f45f2ab111eebd6e9',
            $patch$[
  [
    "7b35d2f4b1997ffca2b4fe6f89988a1d163e750c5ee7fa3fa505aeeffbce8139",
    "8bd9cb6998c20e827881bd5aa9dd6e0398e72470fb20e6e859d3934d7d24995f"
  ]
]$patch$::jsonb
        ),
        (
            '_authority_crud_storage_v3()',
            '7b35d2f4b1997ffca2b4fe6f89988a1d163e750c5ee7fa3fa505aeeffbce8139',
            '8bd9cb6998c20e827881bd5aa9dd6e0398e72470fb20e6e859d3934d7d24995f',
            $patch$[
  [
    " ('authority_access_label_role_projection_apply_v1(jsonb,text,text)','8354841ae2bd79b3fe23fa6bec9aa0d04007384df6354302814b9f2696d60362',false,'v',true,'private'),\n ('authority_access_label_source_check_v1(text,text,text,text,uuid,text,text,text,text,timestamptz,integer)','282382e8b48680378f219ab1ae787d36125d4a4f8f8b69c08fbc003940e65639',false,'v',true,'private'),\n ('authority_access_label_role_projection_matches_v1(text,integer)','044de8f3215cefde7b41313278c3e2726142d50bd078cd3b86f423b3f1a71fa3',false,'s',true,'private'),",
    " ('authority_access_label_role_projection_apply_v1(jsonb,text,text)','8354841ae2bd79b3fe23fa6bec9aa0d04007384df6354302814b9f2696d60362',false,'v',true,'private'),"
  ]
]$patch$::jsonb
        )    ) AS changes(signature, before_sha, after_sha, substitutions) LOOP
        fn := pg_catalog.to_regprocedure('kaname.' || item.signature);
        IF fn IS NULL THEN RAISE EXCEPTION 'функция % для миграции отсутствует', item.signature USING ERRCODE='55000';END IF;
        SELECT p.prosrc INTO STRICT old_body FROM pg_catalog.pg_proc p WHERE p.oid=fn;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(old_body,'UTF8')),'hex') IS DISTINCT FROM item.before_sha THEN
            RAISE EXCEPTION 'исходное тело функции % не соответствует этой миграции', item.signature USING ERRCODE='55000';
        END IF;
        new_body := old_body;
        FOR replacement IN SELECT value FROM pg_catalog.jsonb_array_elements(item.substitutions) LOOP
            needle := replacement->>0;
            IF length(new_body)-length(replace(new_body,needle,'')) IS DISTINCT FROM length(needle) THEN
                RAISE EXCEPTION 'фрагмент тела функции % не уникален', item.signature USING ERRCODE='55000';
            END IF;
            new_body := replace(new_body,needle,replacement->>1);
        END LOOP;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(new_body,'UTF8')),'hex') IS DISTINCT FROM item.after_sha THEN
            RAISE EXCEPTION 'расчётное тело функции % изменилось', item.signature USING ERRCODE='55000';
        END IF;
        -- PostgreSQL восстанавливает сигнатуру и настройки, CREATE OR REPLACE
        -- сохраняет owner/ACL. Меняется ровно одно полное тело с известным SHA.
        definition := pg_catalog.pg_get_functiondef(fn);
        IF length(definition)-length(replace(definition,old_body,'')) IS DISTINCT FROM length(old_body) THEN
            RAISE EXCEPTION 'определение функции % не содержит единственного исходного тела', item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,old_body,new_body);
        IF (SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex')
            FROM pg_catalog.pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.after_sha THEN
            RAISE EXCEPTION 'установленное тело функции % не совпадает с расчётным', item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние после обновления образов доступа' USING ERRCODE='55000';
    END IF;
END
$access_label_native_sources$;
-- +goose StatementEnd

DROP FUNCTION kaname.authority_access_label_role_projection_matches_v1(text,integer);
DROP FUNCTION kaname.authority_access_label_source_check_v1(text,text,text,text,uuid,text,text,text,text,timestamptz,integer);
