-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SET LOCAL lock_timeout = '5s';
-- +goose StatementBegin
DO $$
DECLARE
    active kaname.authority_semantic_identity%ROWTYPE;
    contract integer;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    SELECT required_contract INTO STRICT contract FROM kaname.authority_writer_contract WHERE singleton;
    IF contract = 1 THEN
        PERFORM kaname.authority_installation_enter_v2('catalog');
    ELSIF contract = 2 THEN
        -- Владелец меняет установленный каталог через штатную admission.
        -- Следующий bundle всё равно должен быть подготовлен отдельно.
        SELECT * INTO STRICT active FROM kaname.authority_semantic_identity WHERE singleton;
        PERFORM kaname.authority_installation_enter_v3('catalog',active.model_id,active.catalog_id,active.projector_version);
    ELSE
        RAISE EXCEPTION 'неизвестный контракт каталога accessLabels' USING ERRCODE='P1036';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('kaname.resource_registration_writers',0));
    PERFORM pg_advisory_xact_lock(hashtext('kaname.module_catalog'));
    PERFORM 1 FROM kaname.catalog_module WHERE module='iam' AND live FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'модуль IAM для accessLabels не установлен' USING ERRCODE='P1036';
    END IF;
END;
$$;
-- +goose StatementEnd

INSERT INTO kaname.catalog_resource (module, resource, dotted, object_type) VALUES ('iam', 'accessLabel', 'iam.accessLabel', 'iam_grant_access_label');
INSERT INTO kaname.catalog_verb (module, resource, verb, per_object) VALUES ('iam', 'accessLabel', 'apply', false);

-- У авторской координаты нет экземпляров, включая прямую запись зеркала.
ALTER TABLE kaname.resource_mirror ADD CONSTRAINT resource_mirror_access_label_authoring_only
    CHECK (object_type <> 'iam_grant_access_label');

-- +goose Down
SET LOCAL lock_timeout = '5s';
-- +goose StatementBegin
DO $$
DECLARE
    active kaname.authority_semantic_identity%ROWTYPE;
    contract integer;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    SELECT required_contract INTO STRICT contract FROM kaname.authority_writer_contract WHERE singleton;
    IF contract = 1 THEN
        PERFORM kaname.authority_installation_enter_v2('catalog');
    ELSIF contract = 2 THEN
        SELECT * INTO STRICT active FROM kaname.authority_semantic_identity WHERE singleton;
        PERFORM kaname.authority_installation_enter_v3('catalog',active.model_id,active.catalog_id,active.projector_version);
    ELSE
        RAISE EXCEPTION 'неизвестный контракт каталога accessLabels' USING ERRCODE='P1036';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('kaname.resource_registration_writers',0));
    PERFORM pg_advisory_xact_lock(hashtext('kaname.module_catalog'));
    PERFORM 1 FROM kaname.catalog_module WHERE module='iam' AND live FOR UPDATE;
    IF NOT FOUND OR EXISTS (SELECT 1 FROM kaname.role_rule_ref WHERE module='iam' AND resource='accessLabel')
        OR EXISTS (SELECT 1 FROM kaname.authority_role_access_label_rule) THEN
        RAISE EXCEPTION 'координата accessLabels используется' USING ERRCODE='55000';
    END IF;
END;
$$;
-- +goose StatementEnd

DELETE FROM kaname.catalog_verb WHERE module='iam' AND resource='accessLabel' AND verb='apply';
DELETE FROM kaname.catalog_resource WHERE module='iam' AND resource='accessLabel' AND object_type='iam_grant_access_label';
ALTER TABLE kaname.resource_mirror DROP CONSTRAINT resource_mirror_access_label_authoring_only;
