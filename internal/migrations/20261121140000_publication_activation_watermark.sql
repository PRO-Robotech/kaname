-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Приёмка #1142: docs/engineering/acceptance/live-business-catalog-publication.md
-- PRO-Robotech/kaname#1142. Только владелец фиксирует завершённую активацию.

-- +goose Up
CREATE TABLE kaname.authority_publication_activation (
    singleton boolean NOT NULL DEFAULT true,
    revision bigint NOT NULL,
    manual_hold boolean NOT NULL DEFAULT false,
    CONSTRAINT authority_publication_activation_pkey PRIMARY KEY (singleton),
    CONSTRAINT authority_publication_activation_singleton CHECK (singleton),
    CONSTRAINT authority_publication_activation_revision_positive CHECK (revision > 0),
    CONSTRAINT authority_publication_activation_revision_fkey FOREIGN KEY (revision)
        REFERENCES kaname.publication_model_revision(revision)
);
COMMENT ON TABLE kaname.authority_publication_activation IS 'Последняя завершённая владельцем активация публикации и ручной запрет автоматического продолжения. kaname#1142.';
REVOKE ALL ON kaname.authority_publication_activation FROM PUBLIC;
-- Удаляем также возможные выдачи через default privileges. Последующая штатная
-- выдача runtime исключает DML таблиц authority_; чтение watermark не даёт допуск.
-- +goose StatementBegin
DO $$
DECLARE grantee record;
BEGIN
    FOR grantee IN
        SELECT DISTINCT r.rolname FROM pg_catalog.pg_class c
        CROSS JOIN LATERAL aclexplode(c.relacl) a
        JOIN pg_catalog.pg_roles r ON r.oid = a.grantee
        WHERE c.oid = 'kaname.authority_publication_activation'::regclass AND a.grantee <> c.relowner
    LOOP
        EXECUTE format('REVOKE ALL ON kaname.authority_publication_activation FROM %I', grantee.rolname);
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._publication_activation_watermark_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    PERFORM kaname.authority_protocol_require_drain();
    IF TG_TABLE_SCHEMA <> 'kaname' OR TG_TABLE_NAME <> 'authority_publication_activation'
       OR TG_WHEN <> 'BEFORE' OR TG_LEVEL <> 'ROW' OR TG_OP NOT IN ('INSERT', 'UPDATE') THEN
        RAISE EXCEPTION 'publication activation watermark cannot be removed' USING ERRCODE='42501';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.revision < OLD.revision THEN
            RAISE EXCEPTION 'publication activation watermark cannot move backwards' USING ERRCODE='55000';
        END IF;
        -- Закрытие владельца может застать ещё не активированную публикацию.
        -- Только установка hold на той же отметке не требует активной головы.
        IF NEW.revision = OLD.revision AND NEW.manual_hold AND NOT OLD.manual_hold THEN
            RETURN NEW;
        END IF;
    END IF;
    IF NEW.manual_hold OR NOT EXISTS (
        SELECT 1 FROM kaname.publication_model_revision p
        JOIN kaname.authority_semantic_identity a ON a.singleton
        WHERE p.revision = NEW.revision
          AND NOT EXISTS (SELECT 1 FROM kaname.publication_model_revision newer WHERE newer.revision > p.revision)
          AND a.phase = 'active' AND p.digest = 'sha256:' || a.model_id AND p.catalog_id = a.catalog_id
          AND kaname.authority_full_contract_validate_v3(a.model_id, a.catalog_id, a.projector_version)
    ) THEN
        RAISE EXCEPTION 'publication activation watermark requires exact active head' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION kaname._publication_activation_watermark_guard() FROM PUBLIC;
CREATE TRIGGER publication_activation_watermark_requires_owner
    BEFORE INSERT OR UPDATE OR DELETE ON kaname.authority_publication_activation
    FOR EACH ROW EXECUTE FUNCTION kaname._publication_activation_watermark_guard();
CREATE TRIGGER publication_activation_watermark_refuses_truncate
    BEFORE TRUNCATE ON kaname.authority_publication_activation
    FOR EACH STATEMENT EXECUTE FUNCTION kaname._publication_activation_watermark_guard();

-- Ручное закрытие явно отличимо от transition, установленного публикацией.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_close() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    PERFORM kaname.authority_protocol_require_drain();
    PERFORM 1 FROM kaname.authority_writer_protocol WHERE singleton FOR UPDATE;
    UPDATE kaname.authority_semantic_identity SET phase='transition' WHERE singleton AND phase<>'uninitialized';
    UPDATE kaname.authority_publication_activation SET manual_hold=true WHERE singleton AND NOT manual_hold;
END;
$$;
-- +goose StatementEnd

-- +goose Down
LOCK TABLE kaname.authority_publication_activation IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM kaname.authority_publication_activation) THEN
        RAISE EXCEPTION 'cannot downgrade after a publication activation';
    END IF;
END;
$$;
-- +goose StatementEnd
-- Восстановить контракт close перед удалением состояния публикаций.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_close() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    PERFORM kaname.authority_protocol_require_drain();
    PERFORM 1 FROM kaname.authority_writer_protocol WHERE singleton FOR UPDATE;
    UPDATE kaname.authority_semantic_identity SET phase='transition' WHERE singleton AND phase<>'uninitialized';
END;
$$;
-- +goose StatementEnd
DROP TABLE kaname.authority_publication_activation;
DROP FUNCTION kaname._publication_activation_watermark_guard();
