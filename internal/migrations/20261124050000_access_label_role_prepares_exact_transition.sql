-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Private payload точного перехода роли. Admission и запись принадлежат
-- внешнему owner compiler; этот примитив не выдаёт entitlement.

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_access_label_role_transition_prepare_v1(
    p_old jsonb, p_new jsonb, p_rows integer, p_reads integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    wanted_role_id text;
    actual_old jsonb;
    old_xmin text;
    old_ctid text;
    old_projection jsonb := '[]'::jsonb;
    new_projection jsonb := '[]'::jsonb;
    actual_projection jsonb;
    definitions jsonb;
    wanted uuid;
    definition record;
    used_rows integer := 1;
    used_reads integer := 4;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF current_setting('transaction_isolation')<>'read committed' THEN
        RAISE EXCEPTION 'access label transition requires READ COMMITTED' USING ERRCODE='25001';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN 1 AND 100000
       OR p_reads IS NULL OR p_reads NOT BETWEEN 4 AND 4096 THEN
        RAISE EXCEPTION 'access label transition budget is absent' USING ERRCODE='54000';
    END IF;
    -- SQL NULL обозначает отсутствующую сторону, JSON null не является строкой.
    IF (p_old IS NULL AND p_new IS NULL)
       OR (p_old IS NOT NULL AND jsonb_typeof(p_old) IS DISTINCT FROM 'object')
       OR (p_new IS NOT NULL AND jsonb_typeof(p_new) IS DISTINCT FROM 'object') THEN
        RAISE EXCEPTION 'access label transition requires exact role images' USING ERRCODE='23514';
    END IF;
    IF coalesce(octet_length(p_old::text),0)::bigint+coalesce(octet_length(p_new::text),0)>67108864 THEN
        RAISE EXCEPTION 'access label transition image bound exceeded' USING ERRCODE='54000';
    END IF;
    wanted_role_id:=coalesce(p_old->>'id',p_new->>'id');
    IF coalesce(wanted_role_id,'')=''
       OR (p_old IS NOT NULL AND (p_old->'id' IS DISTINCT FROM to_jsonb(wanted_role_id)))
       OR (p_new IS NOT NULL AND (p_new->'id' IS DISTINCT FROM to_jsonb(wanted_role_id))) THEN
        RAISE EXCEPTION 'access label transition role identity differs' USING ERRCODE='23514';
    END IF;
    -- Полный NEW поступает из owner compiler. Не достраиваем отсутствующие
    -- поля и не отбрасываем неизвестные поля вызывающего.
    IF p_new IS NOT NULL AND p_new IS DISTINCT FROM
       to_jsonb(jsonb_populate_record(NULL::kaname.roles,p_new)) THEN
        RAISE EXCEPTION 'access label transition NEW is not a full role row' USING ERRCODE='23514';
    END IF;

    -- Никаких поздних глобальных upgrades: разные роли не сериализуются.
    -- Единственный admitting writer использует тот же owner role row lock.
    -- Для Create отсутствие подтверждает outer program; конфликт с конкурентным
    -- Create окончательно отклоняет actual INSERT с UNIQUE(id).
    LOCK TABLE kaname.roles IN ROW SHARE MODE;
    LOCK TABLE kaname.authority_role_access_label_rule IN ROW EXCLUSIVE MODE;
    SELECT to_jsonb(r),r.xmin::text,r.ctid::text
        INTO actual_old,old_xmin,old_ctid FROM kaname.roles r
        WHERE r.id=wanted_role_id FOR UPDATE OF r;
    IF actual_old IS DISTINCT FROM p_old THEN
        RAISE EXCEPTION 'access label transition OLD differs from stored role' USING ERRCODE='40001';
    END IF;

    IF p_old IS NOT NULL THEN
        SELECT coalesce(jsonb_agg(jsonb_build_array(c.rule_fp,c.definition_id)
            ORDER BY c.rule_fp COLLATE "C",c.definition_id),'[]'::jsonb)
        INTO old_projection FROM kaname.authority_access_label_role_compile_v1(p_old->'rules') c;
    END IF;
    IF p_new IS NOT NULL THEN
        SELECT coalesce(jsonb_agg(jsonb_build_array(c.rule_fp,c.definition_id)
            ORDER BY c.rule_fp COLLATE "C",c.definition_id),'[]'::jsonb)
        INTO new_projection FROM kaname.authority_access_label_role_compile_v1(p_new->'rules') c;
    END IF;
    -- 64 rules * 256 names ограничивают число origins, даже когда одни и те
    -- же permissions повторяются в разных правилах. Программа входит в rows.
    used_rows:=used_rows+jsonb_array_length(old_projection)+jsonb_array_length(new_projection);
    IF jsonb_array_length(old_projection)>16384 OR jsonb_array_length(new_projection)>16384
       OR used_rows>p_rows THEN
        RAISE EXCEPTION 'access label transition projection budget exceeded' USING ERRCODE='54000';
    END IF;
    SELECT coalesce(jsonb_agg(jsonb_build_array(s.rule_fp,s.definition_id)
        ORDER BY s.rule_fp COLLATE "C",s.definition_id),'[]'::jsonb)
    INTO actual_projection FROM (
        SELECT q.rule_fp,q.definition_id FROM kaname.authority_role_access_label_rule q
        WHERE q.role_id=wanted_role_id ORDER BY q.rule_fp COLLATE "C",q.definition_id
        LIMIT least(16384,p_rows-used_rows)+1 FOR UPDATE OF q
    ) s;
    used_rows:=used_rows+jsonb_array_length(actual_projection);
    IF used_rows>p_rows OR jsonb_array_length(actual_projection)>16384 THEN
        RAISE EXCEPTION 'access label transition stored projection budget exceeded' USING ERRCODE='54000';
    END IF;
    -- Обе стороны отсортированы и уникальны: равенство проверяет недостающие
    -- И лишние origins, включая пустой OLD и роль без apply.
    IF actual_projection IS DISTINCT FROM old_projection THEN
        RAISE EXCEPTION 'access label transition stored projection differs from OLD' USING ERRCODE='40001';
    END IF;

    -- Не вызываем старый prepare отдельно для OLD/NEW: пересекающиеся UUID
    -- блокируются ровно один раз, в одном полном порядке для их объединения.
    SELECT coalesce(jsonb_agg(d.id ORDER BY d.id),'[]'::jsonb) INTO definitions FROM (
        SELECT DISTINCT (e.value->>1)::uuid AS id
        FROM jsonb_array_elements(old_projection||new_projection) e ORDER BY 1 LIMIT 2049
    ) d;
    IF jsonb_array_length(definitions)>2048
       OR used_reads+2*jsonb_array_length(definitions)>p_reads
       OR used_rows+2*jsonb_array_length(definitions)>p_rows THEN
        RAISE EXCEPTION 'access label transition definition budget exceeded' USING ERRCODE='54000';
    END IF;
    FOR wanted IN SELECT value::uuid FROM jsonb_array_elements_text(definitions) ORDER BY value::uuid LOOP
        SELECT d.scope_kind,d.scope_id,d.module,d.resource,d.label_key,d.id,d.revision,
               d.xmin::text AS row_xmin,d.ctid::text AS row_ctid
        INTO definition FROM kaname.authority_access_label_definition d WHERE d.id=wanted;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'access label transition definition is unavailable' USING ERRCODE='23503';
        END IF;
        IF NOT kaname.authority_access_label_definition_hold_v1(
            definition.scope_kind,definition.scope_id,definition.module,definition.resource,
            definition.label_key,definition.id,definition.revision,definition.row_xmin,definition.row_ctid,NULL) THEN
            RAISE EXCEPTION 'access label transition definition revision changed' USING ERRCODE='40001';
        END IF;
        used_reads:=used_reads+2;
        used_rows:=used_rows+2;
    END LOOP;
    RETURN jsonb_build_object('role_id',wanted_role_id,'old_row',p_old,'new_row',p_new,
        'old_digest',encode(sha256(convert_to(p_old::text,'UTF8')),'hex'),
        'new_digest',encode(sha256(convert_to(p_new::text,'UTF8')),'hex'),
        'old_xmin',old_xmin,'old_ctid',old_ctid,
        'old_projection',old_projection,'new_projection',new_projection,
        'rows',used_rows,'reads',used_reads);
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
DECLARE grantee record;
BEGIN
    REVOKE ALL ON FUNCTION kaname.authority_access_label_role_transition_prepare_v1(jsonb,jsonb,integer,integer) FROM PUBLIC;
    FOR grantee IN SELECT DISTINCT r.rolname FROM pg_proc p
        CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_roles r ON r.oid=a.grantee
        WHERE p.oid='kaname.authority_access_label_role_transition_prepare_v1(jsonb,jsonb,integer,integer)'::regprocedure
          AND a.grantee<>p.proowner
    LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION kaname.authority_access_label_role_transition_prepare_v1(jsonb,jsonb,integer,integer) FROM %I',grantee.rolname);
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname.authority_access_label_role_transition_prepare_v1(jsonb,jsonb,integer,integer);
