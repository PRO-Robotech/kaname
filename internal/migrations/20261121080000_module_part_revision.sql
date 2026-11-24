-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Приёмка #1142: docs/engineering/acceptance/live-business-catalog-publication.md
--
-- История начинается с первой публикации. Прежняя применённая пара
-- catalog_module не подтверждает публикацию документа и остаётся в каталоге.

-- +goose Up
CREATE TABLE kaname.module_part_revision (
    module text NOT NULL,
    revision bigint NOT NULL,
    digest text NOT NULL,
    document bytea NOT NULL,
    published_at timestamp with time zone NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT module_part_revision_pkey PRIMARY KEY (module, revision),
    CONSTRAINT module_part_revision_module_fkey FOREIGN KEY (module)
        REFERENCES kaname.catalog_module (module) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT module_part_revision_positive CHECK (revision > 0),
    CONSTRAINT module_part_revision_digest_form CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT module_part_revision_document_size CHECK (octet_length(document) BETWEEN 1 AND 8388608)
);

CREATE INDEX module_part_revision_window_idx
    ON kaname.module_part_revision (module, published_at);

COMMENT ON TABLE kaname.module_part_revision IS 'История принятых публикаций частей модулей. Снятие модуля сохраняет историю. kaname#981.';
COMMENT ON COLUMN kaname.module_part_revision.document IS 'Исходные байты проверенного документа. Настраиваемый потолок размера проверяется до разбора. kaname#981.';
COMMENT ON COLUMN kaname.module_part_revision.digest IS 'SHA-256 канонической формы документа, вычисленный загрузчиком манифестов. kaname#981.';
COMMENT ON COLUMN kaname.module_part_revision.published_at IS 'Момент записи новой ревизии по часам PostgreSQL. kaname#981.';

-- Отпечаток и тело читаются по ключу редакции. Содержимое документа
-- и его отпечаток не собираются в статистику планировщика.
ALTER TABLE kaname.module_part_revision
    ALTER COLUMN digest SET STATISTICS 0,
    ALTER COLUMN document SET STATISTICS 0;

-- +goose StatementBegin
CREATE FUNCTION kaname.module_part_revision_refuses_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'module part revision is immutable: % is refused', TG_OP
        USING ERRCODE = 'restrict_violation',
              CONSTRAINT = 'module_part_revision_is_immutable',
              TABLE = 'module_part_revision',
              SCHEMA = 'kaname';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER module_part_revision_is_immutable
    BEFORE UPDATE OR DELETE OR TRUNCATE ON kaname.module_part_revision
    FOR EACH STATEMENT EXECUTE FUNCTION kaname.module_part_revision_refuses_mutation();

-- +goose Down
-- Замок исключает публикацию между проверкой истории и удалением таблицы.
LOCK TABLE kaname.module_part_revision IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM kaname.module_part_revision) THEN
        RAISE EXCEPTION 'cannot downgrade while published module part revisions exist';
    END IF;
END;
$$;
-- +goose StatementEnd
DROP TABLE kaname.module_part_revision;
DROP FUNCTION kaname.module_part_revision_refuses_mutation();
