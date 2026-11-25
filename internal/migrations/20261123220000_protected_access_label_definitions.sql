-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Одноимённые ключи разных областей имеют разные идентификаторы. Тип
-- выводится из записи каталога; снятие типа не удаляет его определения.
CREATE TABLE kaname.authority_access_label_definition (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    module text NOT NULL,
    resource text NOT NULL,
    label_key text NOT NULL CHECK (label_key ~ '^[a-z][-_./@a-z0-9]{0,62}$'),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    CONSTRAINT authority_access_label_scope CHECK (
        (scope_kind = 'cluster' AND scope_id = 'cluster_root')
        OR (scope_kind = 'account' AND scope_id ~ '^acc[a-zA-Z0-9_-]{1,61}$')
        OR (scope_kind = 'project' AND scope_id ~ '^prj[a-zA-Z0-9_-]{1,61}$')
    ),
    CONSTRAINT authority_access_label_coordinate UNIQUE (scope_kind, scope_id, module, resource, label_key),
    CONSTRAINT authority_access_label_catalog FOREIGN KEY (module, resource)
        REFERENCES kaname.catalog_resource (module, resource)
);

CREATE TABLE kaname.authority_access_label_value (
    definition_id uuid NOT NULL REFERENCES kaname.authority_access_label_definition (id),
    label_value text NOT NULL CHECK (octet_length(label_value) <= 63),
    PRIMARY KEY (definition_id, label_value)
);

-- Обычный runtime не получает права менять или читать реестр напрямую.
-- Учитываем в том числе grant, выданный настройкой ALTER DEFAULT PRIVILEGES.
-- +goose StatementBegin
DO $$
DECLARE item record;
BEGIN
    FOR item IN
        SELECT DISTINCT c.relname, a.grantee, r.rolname
        FROM pg_catalog.pg_class c
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            coalesce(c.relacl, pg_catalog.acldefault('r', c.relowner))
        ) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid = a.grantee
        WHERE c.oid IN (
            'kaname.authority_access_label_definition'::regclass,
            'kaname.authority_access_label_value'::regclass
        ) AND a.grantee <> c.relowner
    LOOP
        IF item.grantee = 0 THEN
            EXECUTE format('REVOKE ALL ON TABLE kaname.%I FROM PUBLIC', item.relname);
        ELSE
            EXECUTE format('REVOKE ALL ON TABLE kaname.%I FROM %I', item.relname, item.rolname);
        END IF;
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
LOCK TABLE kaname.authority_access_label_definition, kaname.authority_access_label_value
    IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM kaname.authority_access_label_definition) THEN
        RAISE EXCEPTION 'Сначала обработайте сохранённые определения accessLabels'
            USING ERRCODE = '55000';
    END IF;
END;
$$;
-- +goose StatementEnd
DROP TABLE kaname.authority_access_label_value;
DROP TABLE kaname.authority_access_label_definition;
