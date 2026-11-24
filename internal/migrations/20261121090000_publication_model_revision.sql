-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Приёмка #1142: docs/engineering/acceptance/live-business-catalog-publication.md
--
-- Текст проходит композицию и допуск до записи. Каталог, история части и
-- ревизия модели фиксируются одной транзакцией под общим замком каталога.

-- +goose Up
CREATE TABLE kaname.publication_model_revision (
    revision bigint NOT NULL,
    model_text bytea NOT NULL,
    digest text NOT NULL,
    catalog_id text NOT NULL,
    published_at timestamp with time zone NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT publication_model_revision_pkey PRIMARY KEY (revision),
    CONSTRAINT publication_model_revision_positive CHECK (revision > 0),
    CONSTRAINT publication_model_revision_text_size CHECK (octet_length(model_text) BETWEEN 1 AND 8388608),
    CONSTRAINT publication_model_revision_catalog_id_shape CHECK (catalog_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT publication_model_revision_digest_matches_text
        CHECK (digest = 'sha256:' || encode(sha256(model_text), 'hex'))
);

COMMENT ON TABLE kaname.publication_model_revision IS 'Неизменяемый журнал допущенных моделей публикации. Номер назначается под общим замком каталога, без sequence; откат не расходует номер. kaname#981.';
COMMENT ON COLUMN kaname.publication_model_revision.model_text IS 'Точные байты собранного и допущенного текста модели. kaname#981.';
COMMENT ON COLUMN kaname.publication_model_revision.digest IS 'SHA-256 точных байтов model_text, сверяемый ограничением таблицы. kaname#981.';
COMMENT ON COLUMN kaname.publication_model_revision.catalog_id IS 'SHA-256 канонического каталога, допущенного вместе с этой редакцией. Изменение каталога после публикации не создаёт новый допуск. kaname#1142.';

ALTER TABLE kaname.publication_model_revision
    ALTER COLUMN model_text SET STATISTICS 0,
    ALTER COLUMN digest SET STATISTICS 0,
    ALTER COLUMN catalog_id SET STATISTICS 0;

-- +goose StatementBegin
CREATE FUNCTION kaname.publication_model_revision_refuses_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'publication model revision is immutable: % is refused', TG_OP
        USING ERRCODE = 'restrict_violation',
              CONSTRAINT = 'publication_model_revision_is_immutable',
              TABLE = 'publication_model_revision',
              SCHEMA = 'kaname';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER publication_model_revision_is_immutable
    BEFORE UPDATE OR DELETE OR TRUNCATE ON kaname.publication_model_revision
    FOR EACH STATEMENT EXECUTE FUNCTION kaname.publication_model_revision_refuses_mutation();

-- Права на новую таблицу нужны уже допущенным ролям при обновлении схемы.
-- Источник — прямая выдача owner на каталог глаголов, только для runtime LOGIN.
-- При свежем запуске эти права выдаёт штатная authority_protocol_grant_runtime.
-- +goose StatementBegin
DO $$
DECLARE runtime_name name;
BEGIN
    FOR runtime_name IN
        SELECT DISTINCT r.rolname
        FROM pg_catalog.pg_class c
        CROSS JOIN LATERAL aclexplode(c.relacl) acl
        JOIN pg_catalog.pg_roles r ON r.oid = acl.grantee
        WHERE c.oid = 'kaname.catalog_verb'::regclass
          AND acl.grantor = c.relowner AND acl.privilege_type = 'INSERT'
          AND r.oid <> c.relowner AND r.rolcanlogin
          AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR r.rolinherit)
          AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member = r.oid)
          AND has_table_privilege(r.oid, c.oid, 'SELECT')
    LOOP
        EXECUTE format('GRANT SELECT, INSERT ON kaname.module_part_revision, kaname.publication_model_revision TO %I', runtime_name);
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- +goose Down
LOCK TABLE kaname.publication_model_revision IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM kaname.publication_model_revision) THEN
        RAISE EXCEPTION 'cannot downgrade while published model revisions exist';
    END IF;
END;
$$;
-- +goose StatementEnd
DROP TABLE kaname.publication_model_revision;
DROP FUNCTION kaname.publication_model_revision_refuses_mutation();
