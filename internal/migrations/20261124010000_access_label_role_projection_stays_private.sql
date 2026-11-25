-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Только хранение явного apply для UUID определения. Выдача и чтение
-- полномочий не включаются: принимающий атомарный writer появится отдельно.

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

CREATE TABLE kaname.authority_role_access_label_rule (
    role_id text NOT NULL,
    rule_fp text NOT NULL,
    definition_id uuid NOT NULL,
    CONSTRAINT authority_role_access_label_rule_pk PRIMARY KEY (role_id, rule_fp, definition_id),
    CONSTRAINT authority_role_access_label_rule_fp CHECK (rule_fp COLLATE "C" ~ '^[0-9a-f]{64}$'),
    -- RESTRICT сохраняет необходимость явного отзыва будущим writer.
    -- CASCADE вызвал бы закрытый statement guard даже без дочерних строк
    -- и тем самым запретил бы обычное удаление ранее существовавших ролей.
    CONSTRAINT authority_role_access_label_rule_owner FOREIGN KEY (role_id)
        REFERENCES kaname.roles (id) ON DELETE RESTRICT,
    CONSTRAINT authority_role_access_label_rule_definition FOREIGN KEY (definition_id)
        REFERENCES kaname.authority_access_label_definition (id) ON DELETE RESTRICT
);
CREATE INDEX authority_role_access_label_rule_definition_idx
    ON kaname.authority_role_access_label_rule (definition_id);

COMMENT ON TABLE kaname.authority_role_access_label_rule IS
    'Только явное apply: роль, fingerprint исходного правила и UUID определения. Область принадлежит неизменяемому определению; edit и wildcard здесь не представлены. Запись закрыта до отдельного атомарного writer.';

-- Statement guard отвергает также пустые DML и TRUNCATE. Ни owner, ни
-- compatibility, ни произвольный GUC не создают принимающего пути.
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_role_access_label_rule_closed_v1() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'access label role projection requires a protected writer'
        USING ERRCODE = '42501';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER authority_role_access_label_rule_closed
    BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON kaname.authority_role_access_label_rule
    FOR EACH STATEMENT EXECUTE FUNCTION kaname.authority_role_access_label_rule_closed_v1();

-- Префикс authority_ сохраняет приватность при повторном runtime regrant.
-- Убираем также ACL, полученные через ALTER DEFAULT PRIVILEGES.
-- +goose StatementBegin
DO $$
DECLARE item record;
BEGIN
    FOR item IN
        SELECT DISTINCT a.grantee, r.rolname
        FROM pg_catalog.pg_class c
        CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(c.relacl, pg_catalog.acldefault('r', c.relowner))) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid = a.grantee
        WHERE c.oid = 'kaname.authority_role_access_label_rule'::regclass AND a.grantee <> c.relowner
    LOOP
        IF item.grantee = 0 THEN
            REVOKE ALL ON kaname.authority_role_access_label_rule FROM PUBLIC;
        ELSE
            EXECUTE format('REVOKE ALL ON kaname.authority_role_access_label_rule FROM %I', item.rolname);
        END IF;
    END LOOP;
    FOR item IN
        SELECT DISTINCT a.grantee, r.rolname
        FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid = a.grantee
        WHERE p.oid = 'kaname.authority_role_access_label_rule_closed_v1()'::regprocedure AND a.grantee <> p.proowner
    LOOP
        IF item.grantee = 0 THEN
            REVOKE ALL ON FUNCTION kaname.authority_role_access_label_rule_closed_v1() FROM PUBLIC;
        ELSE
            EXECUTE format('REVOKE ALL ON FUNCTION kaname.authority_role_access_label_rule_closed_v1() FROM %I', item.rolname);
        END IF;
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
-- Новая private таблица намеренно не добавлена в старый protocol census:
-- до admitting writer она не является источником действующих решений.
-- Проверка непустоты защищена собственным relation lock, включая будущий DML.
LOCK TABLE kaname.authority_role_access_label_rule IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM kaname.authority_role_access_label_rule) THEN
        RAISE EXCEPTION 'Сначала отзовите сохранённые полномочия accessLabels'
            USING ERRCODE = '55000';
    END IF;
END;
$$;
-- +goose StatementEnd
DROP TABLE kaname.authority_role_access_label_rule;
DROP FUNCTION kaname.authority_role_access_label_rule_closed_v1();
