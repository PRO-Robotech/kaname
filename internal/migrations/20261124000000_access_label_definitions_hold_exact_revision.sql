-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();
LOCK TABLE kaname.authority_access_label_definition, kaname.authority_access_label_value
    IN ACCESS EXCLUSIVE MODE;

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_access_label_definition_revision_v1() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF TG_OP = 'INSERT' THEN
        IF NEW.revision IS DISTINCT FROM 1 THEN
            RAISE EXCEPTION 'новое определение accessLabels начинается с редакции 1' USING ERRCODE='23514';
        END IF;
    ELSE
        IF ROW(NEW.id, NEW.scope_kind, NEW.scope_id, NEW.module, NEW.resource, NEW.label_key)
           IS DISTINCT FROM ROW(OLD.id, OLD.scope_kind, OLD.scope_id, OLD.module, OLD.resource, OLD.label_key) THEN
            RAISE EXCEPTION 'координаты определения accessLabels неизменяемы' USING ERRCODE='23514';
        END IF;
        IF NEW.revision IS DISTINCT FROM OLD.revision AND NEW.revision IS DISTINCT FROM OLD.revision + 1 THEN
            RAISE EXCEPTION 'редакция определения accessLabels должна увеличиться на 1' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_access_label_value_revision_v1() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    affected uuid;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF TG_OP = 'UPDATE' THEN
        IF NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'значение accessLabels меняется снятием и добавлением' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    affected := CASE WHEN TG_OP = 'INSERT' THEN NEW.definition_id ELSE OLD.definition_id END;
    -- Дельта списка значений и новая редакция видны в одном commit.
    -- AFTER не повышает редакцию при INSERT ON CONFLICT DO NOTHING.
    UPDATE kaname.authority_access_label_definition d SET revision=d.revision+1 WHERE d.id=affected;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'определение значения accessLabels отсутствует' USING ERRCODE='23503';
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_access_label_no_truncate_v1() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'реестр accessLabels изменяется по определениям' USING ERRCODE='42501';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER access_label_definition_revision BEFORE INSERT OR UPDATE
    ON kaname.authority_access_label_definition FOR EACH ROW
    EXECUTE FUNCTION kaname.authority_access_label_definition_revision_v1();
CREATE TRIGGER access_label_value_immutable BEFORE UPDATE
    ON kaname.authority_access_label_value FOR EACH ROW
    EXECUTE FUNCTION kaname.authority_access_label_value_revision_v1();
CREATE TRIGGER access_label_value_revision AFTER INSERT OR DELETE
    ON kaname.authority_access_label_value FOR EACH ROW
    EXECUTE FUNCTION kaname.authority_access_label_value_revision_v1();
CREATE TRIGGER access_label_definition_no_truncate BEFORE TRUNCATE
    ON kaname.authority_access_label_definition FOR EACH STATEMENT
    EXECUTE FUNCTION kaname.authority_access_label_no_truncate_v1();
CREATE TRIGGER access_label_value_no_truncate BEFORE TRUNCATE
    ON kaname.authority_access_label_value FOR EACH STATEMENT
    EXECUTE FUNCTION kaname.authority_access_label_no_truncate_v1();

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_access_label_definition_hold_v1(
    p_scope_kind text, p_scope_id text, p_module text, p_resource text, p_key text,
    p_id uuid, p_revision bigint, p_xmin text, p_ctid text, p_value text
) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'проверка редакции accessLabels требует READ COMMITTED' USING ERRCODE='25001';
    END IF;
    -- Область вычисляет доверенный вызывающий из источников цели. Проверяем
    -- всю координату и поколение строки, включая удаление с повторной вставкой.
    PERFORM 1 FROM kaname.authority_access_label_definition d
    WHERE d.id=p_id AND d.scope_kind=p_scope_kind AND d.scope_id=p_scope_id
      AND d.module=p_module AND d.resource=p_resource AND d.label_key=p_key
      AND d.revision=p_revision AND d.xmin::text=p_xmin AND d.ctid::text=p_ctid
    FOR SHARE OF d;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    -- Блокировка определения удерживается до конца транзакции. Изменение
    -- любого значения конфликтует с ней при повышении редакции.
    RETURN p_value IS NULL OR EXISTS (
        SELECT 1 FROM kaname.authority_access_label_value v
        WHERE v.definition_id=p_id AND v.label_value=p_value
    );
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
        'authority_access_label_definition_revision_v1()',
        'authority_access_label_value_revision_v1()',
        'authority_access_label_no_truncate_v1()',
        'authority_access_label_definition_hold_v1(text,text,text,text,text,uuid,bigint,text,text,text)'
    ] LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',signature);
        FOR grantee IN
            SELECT DISTINCT r.rolname FROM pg_proc p
            CROSS JOIN LATERAL aclexplode(p.proacl) a
            JOIN pg_roles r ON r.oid=a.grantee
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
LOCK TABLE kaname.authority_access_label_definition, kaname.authority_access_label_value
    IN ACCESS EXCLUSIVE MODE;
DROP TRIGGER access_label_definition_no_truncate ON kaname.authority_access_label_definition;
DROP TRIGGER access_label_definition_revision ON kaname.authority_access_label_definition;
DROP TRIGGER access_label_value_no_truncate ON kaname.authority_access_label_value;
DROP TRIGGER access_label_value_immutable ON kaname.authority_access_label_value;
DROP TRIGGER access_label_value_revision ON kaname.authority_access_label_value;
DROP FUNCTION kaname.authority_access_label_definition_hold_v1(text,text,text,text,text,uuid,bigint,text,text,text);
DROP FUNCTION kaname.authority_access_label_no_truncate_v1();
DROP FUNCTION kaname.authority_access_label_value_revision_v1();
DROP FUNCTION kaname.authority_access_label_definition_revision_v1();
