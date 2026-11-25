-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Закрытая подготовка проекции; принимающий runtime writer ещё не включён.

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_access_label_role_compile_v1(p_rules jsonb)
RETURNS TABLE(rule_fp text, definition_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    rule jsonb;
    child jsonb;
    names text[];
    canonical_names text;
    fingerprint text;
    projected jsonb := '[]'::jsonb;
    permission_count integer;
    has_apply boolean := false;
    -- strings.TrimSpace из domain.NormalizeVerb; сама принимаемая форма
    -- остаётся ровно ["apply"], а не её нормализованным написанием.
    whitespace constant text := U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000';
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF jsonb_typeof(p_rules) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'role rules must be an array' USING ERRCODE='23514';
    END IF;
    IF jsonb_array_length(p_rules)>64 THEN
        RAISE EXCEPTION 'role rules exceed 64' USING ERRCODE='23514';
    END IF;
    -- Узкий compiler не становится новым валидатором прежних ролей. Сначала
    -- ищем только явный apply, включая запрещённую вложенную форму; без него
    -- множество пусто и legacy selectors/codec вообще не переоцениваются.
    FOR rule IN SELECT value FROM jsonb_array_elements(p_rules) LOOP
        IF rule->>'module'='iam' AND rule->'resources' ? 'accessLabel'
           AND jsonb_typeof(rule->'verbs')='array' THEN
            IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(rule->'verbs') v
                WHERE lower(btrim(v.value,whitespace))='apply') THEN
                has_apply:=true;
            END IF;
        END IF;
        IF jsonb_typeof(rule->'children')='array' THEN
            FOR child IN SELECT value FROM jsonb_array_elements(rule->'children') LOOP
                IF coalesce(nullif(child->>'module',''),rule->>'module')='iam'
                   AND child->'resources' ? 'accessLabel' AND jsonb_typeof(child->'verbs')='array' THEN
                    IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(child->'verbs') v
                        WHERE lower(btrim(v.value,whitespace))='apply') THEN
                        RAISE EXCEPTION 'access label apply must be top-level' USING ERRCODE='23514';
                    END IF;
                END IF;
            END LOOP;
        END IF;
    END LOOP;
    IF NOT has_apply THEN RETURN; END IF;
    IF kaname.iam_rules_valid(p_rules) IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'invalid role rules for access label projection' USING ERRCODE='23514';
    END IF;

    -- Общий предел CompileRules применяется ДО выделения управляющих пар.
    -- Как в Go: только верхний уровень, без label/creator arms; '*' остаётся
    -- символом. DISTINCT учитывает общие permissions разных исходных правил.
    SELECT count(*) INTO permission_count FROM (
        SELECT DISTINCT ((r.value->>'module')||'.'||res.value||'.'||name.value||'.'||verb.value) COLLATE "C" AS permission
        FROM jsonb_array_elements(p_rules) r
        CROSS JOIN LATERAL jsonb_array_elements_text(r.value->'resources') res
        CROSS JOIN LATERAL jsonb_array_elements_text(r.value->'verbs') verb
        CROSS JOIN LATERAL jsonb_array_elements_text(CASE
            WHEN jsonb_typeof(r.value->'resource_names')='array'
                 AND jsonb_array_length(r.value->'resource_names')>0 THEN r.value->'resource_names'
            ELSE '["*"]'::jsonb END) name
        WHERE coalesce(r.value->'created_by_subject','false'::jsonb)<>'true'::jsonb
          AND coalesce(r.value->'match_labels','null'::jsonb)='null'::jsonb
          AND coalesce(r.value->'match_access_labels','null'::jsonb)='null'::jsonb
        LIMIT 1025
    ) permissions;
    IF permission_count>1024 THEN
        RAISE EXCEPTION 'compiled role permissions exceed 1024' USING ERRCODE='23514';
    END IF;

    FOR rule IN SELECT value FROM jsonb_array_elements(p_rules) LOOP
        IF rule->>'module'<>'iam' OR NOT (rule->'resources' ? 'accessLabel')
           OR NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(rule->'verbs') v
               WHERE lower(btrim(v.value,whitespace))='apply') THEN
            CONTINUE;
        END IF;
        -- Закрытый snake_case codec. Даже пустые дополнительные selectors,
        -- children и metadata не отбрасываются при вычислении fingerprint.
        IF rule-ARRAY['module','resources','verbs','resource_names']<>'{}'::jsonb
           OR rule->'resources'<>'["accessLabel"]'::jsonb OR rule->'verbs'<>'["apply"]'::jsonb
           OR jsonb_typeof(rule->'resource_names') IS DISTINCT FROM 'array' THEN
            RAISE EXCEPTION 'access label apply requires a dedicated named rule' USING ERRCODE='23514';
        END IF;
        IF jsonb_array_length(rule->'resource_names') NOT BETWEEN 1 AND 256
           OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(rule->'resource_names') n
               WHERE n.value COLLATE "C" !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                  OR n.value='00000000-0000-0000-0000-000000000000') THEN
            RAISE EXCEPTION 'access label apply requires canonical definition UUIDs' USING ERRCODE='23514';
        END IF;
        SELECT array_agg(n.value ORDER BY n.value COLLATE "C"),
               '['||string_agg(to_json(n.value)::text,',' ORDER BY n.value COLLATE "C")||']'
        INTO names,canonical_names
        FROM (SELECT DISTINCT value COLLATE "C" AS value FROM jsonb_array_elements_text(rule->'resource_names')) n;
        -- Это JSON encoding/json для domain.Rule, НЕ jsonb::text и НЕ
        -- Rule.Fingerprint(): grantRuleFingerprint имеет отдельный wire image.
        fingerprint:=encode(sha256(convert_to(
            '{"Module":"iam","Resources":["accessLabel"],"Verbs":["apply"],"ResourceNames":'
            ||canonical_names||',"MatchLabels":null,"Children":null,"CreatedBySubject":false}',
            'UTF8')),'hex');
        projected:=projected||(SELECT jsonb_agg(jsonb_build_array(fingerprint,n)) FROM unnest(names) n);
    END LOOP;
    RETURN QUERY SELECT DISTINCT (e.value->>0) COLLATE "C",(e.value->>1)::uuid
        FROM jsonb_array_elements(projected) e ORDER BY 1,2;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_access_label_role_prepare_v1(p_rules jsonb)
RETURNS TABLE(rule_fp text, definition_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE projected jsonb; wanted uuid; definition record;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF current_setting('transaction_isolation')<>'read committed' THEN
        RAISE EXCEPTION 'access label preparation requires READ COMMITTED' USING ERRCODE='25001';
    END IF;
    -- Для NEW будущий writer передаёт rules из собственной frozen программы
    -- ДО final clock, включая Create ещё не существующей роли; для OLD —
    -- удержанные фактические roles.rules. JSON вызывающего не доказывает
    -- entitlement. Эта функция не принимает решение, не пишет проекцию и не
    -- открывает runtime вход. Результат действует только в этой транзакции.
    SELECT coalesce(jsonb_agg(jsonb_build_array(c.rule_fp,c.definition_id)),'[]'::jsonb)
        INTO projected FROM kaname.authority_access_label_role_compile_v1(p_rules) c;
    -- Одна блокировка на UUID в общем порядке, независимо от числа origins.
    FOR wanted IN SELECT DISTINCT (e.value->>1)::uuid FROM jsonb_array_elements(projected) e ORDER BY 1 LOOP
        SELECT d.scope_kind,d.scope_id,d.module,d.resource,d.label_key,d.id,d.revision,
               d.xmin::text AS row_xmin,d.ctid::text AS row_ctid
        INTO definition FROM kaname.authority_access_label_definition d WHERE d.id=wanted;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'access label definition is unavailable' USING ERRCODE='23503';
        END IF;
        IF NOT kaname.authority_access_label_definition_hold_v1(
            definition.scope_kind,definition.scope_id,definition.module,definition.resource,
            definition.label_key,definition.id,definition.revision,definition.row_xmin,definition.row_ctid,NULL) THEN
            RAISE EXCEPTION 'access label definition changed during preparation' USING ERRCODE='40001';
        END IF;
    END LOOP;
    RETURN QUERY SELECT e.value->>0,(e.value->>1)::uuid FROM jsonb_array_elements(projected) e ORDER BY 1,2;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
DECLARE signature text; grantee record;
BEGIN
    FOREACH signature IN ARRAY ARRAY[
        'authority_access_label_role_compile_v1(jsonb)',
        'authority_access_label_role_prepare_v1(jsonb)'
    ] LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',signature);
        FOR grantee IN SELECT DISTINCT r.rolname FROM pg_proc p
            CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_roles r ON r.oid=a.grantee
            WHERE p.oid=to_regprocedure('kaname.'||signature) AND a.grantee<>p.proowner
        LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM %I',signature,grantee.rolname);
        END LOOP;
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname.authority_access_label_role_prepare_v1(jsonb);
DROP FUNCTION kaname.authority_access_label_role_compile_v1(jsonb);
