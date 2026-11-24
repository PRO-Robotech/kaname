-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Приёмка #1142: docs/engineering/acceptance/live-business-catalog-publication.md
-- PRO-Robotech/kaname#1142. Редакция модели может смениться при прежних отпечатках модели и каталога.
-- Подтверждение владельца относится только к уже активированной редакции.

-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION kaname._publication_revision_authority_guard() RETURNS trigger
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; invoker oid; owner_oid oid;
BEGIN
    IF TG_TABLE_SCHEMA <> 'kaname' OR TG_TABLE_NAME NOT IN ('publication_model_revision', 'module_part_revision')
       OR TG_LEVEL <> 'ROW' OR TG_OP <> 'INSERT'
       OR (TG_TABLE_NAME = 'module_part_revision' AND TG_WHEN <> 'BEFORE') THEN
        RAISE EXCEPTION 'invalid authority guard context for publication revision' USING ERRCODE = '42501';
    END IF;
    IF TG_WHEN = 'BEFORE' THEN
        IF NOT EXISTS (SELECT 1 FROM kaname.publication_model_revision) THEN
            -- SECURITY DEFINER не доказывает личность вызывающего через
            -- current_user. Используется тот же реальный invoker, что в attestation.
            SELECT oid INTO STRICT invoker FROM pg_catalog.pg_roles
            WHERE rolname = coalesce(nullif(current_setting('role'), 'none'), session_user);
            SELECT relowner INTO STRICT owner_oid FROM pg_catalog.pg_class
            WHERE oid = 'kaname.authority_writer_protocol'::regclass;
            IF invoker IS DISTINCT FROM owner_oid THEN
                RAISE EXCEPTION 'first publication requires migration owner' USING ERRCODE = '42501';
            END IF;
            PERFORM kaname.authority_protocol_require_drain();
            IF TG_TABLE_NAME = 'publication_model_revision' AND NEW.revision <> 1 THEN
                RAISE EXCEPTION 'first publication requires revision one' USING ERRCODE = '42501';
            END IF;
            RETURN NEW;
        END IF;
        proof := kaname._authority_protocol_attestation_v1_body();
        IF proof->>'mode' IS DISTINCT FROM 'global'
           OR proof->>'purpose' IS DISTINCT FROM 'participant'
           OR proof->>'kind' IS DISTINCT FROM 'catalog' THEN
            RAISE EXCEPTION 'publication revision requires the catalog writer admission' USING ERRCODE = '42501';
        END IF;
        RETURN NEW;
    END IF;
    IF EXISTS (SELECT 1 FROM kaname.authority_bundle_handoff WHERE singleton) THEN
        UPDATE kaname.authority_semantic_identity
        SET phase = 'transition'
        WHERE singleton AND phase IN ('prepared', 'active');
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION kaname._publication_revision_authority_guard() FROM PUBLIC;
-- +goose StatementBegin
DO $$
DECLARE grantee record;
BEGIN
    FOR grantee IN
        SELECT DISTINCT r.rolname
        FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
        JOIN pg_roles r ON r.oid = a.grantee
        WHERE p.oid = 'kaname._publication_revision_authority_guard()'::regprocedure
          AND a.grantee <> p.proowner
    LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION kaname._publication_revision_authority_guard() FROM %I', grantee.rolname);
    END LOOP;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER publication_revision_requires_catalog_admission
    BEFORE INSERT ON kaname.publication_model_revision
    FOR EACH ROW EXECUTE FUNCTION kaname._publication_revision_authority_guard();

CREATE TRIGGER module_part_revision_requires_catalog_admission
    BEFORE INSERT ON kaname.module_part_revision
    FOR EACH ROW EXECUTE FUNCTION kaname._publication_revision_authority_guard();

-- До фиксации публикация ещё пишет аудит под исходным допуском.
CREATE CONSTRAINT TRIGGER publication_revision_closes_authority
    AFTER INSERT ON kaname.publication_model_revision
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION kaname._publication_revision_authority_guard();

-- +goose Down
DROP TRIGGER publication_revision_closes_authority ON kaname.publication_model_revision;
DROP TRIGGER module_part_revision_requires_catalog_admission ON kaname.module_part_revision;
DROP TRIGGER publication_revision_requires_catalog_admission ON kaname.publication_model_revision;
DROP FUNCTION kaname._publication_revision_authority_guard();
