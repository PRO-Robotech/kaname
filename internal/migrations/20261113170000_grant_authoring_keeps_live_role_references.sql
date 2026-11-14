-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1034: авторинг и lifecycle; ни одна привязка не получает version=1.
-- +goose Up
-- Приёмка: docs/engineering/acceptance/role-rights-stay-within-what-is-named.md
-- kaname#1034: защита полного действия выдачи и сохранение прежних строк при накате (ESC-32).
SET LOCAL lock_timeout='10s';
INSERT INTO kaname.catalog_verb(module,resource,verb,per_object)
 VALUES('iam','role','bind',false) ON CONFLICT(module,resource,verb) DO NOTHING;

-- +goose StatementBegin
CREATE FUNCTION kaname.retire_role_grant_authoring() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF OLD.live AND NOT NEW.live THEN
   DELETE FROM kaname.role_create_binding_rule WHERE role_id=NEW.id;
   DELETE FROM kaname.role_bind_role_rule WHERE role_id=NEW.id OR bound_role_id=NEW.id;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER retire_role_grant_authoring AFTER UPDATE OF live ON kaname.roles
 FOR EACH ROW EXECUTE FUNCTION kaname.retire_role_grant_authoring();

-- +goose StatementBegin
CREATE FUNCTION kaname.retire_catalog_grant_authoring() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE withdrawn boolean;
BEGIN
 IF TG_OP='DELETE' THEN withdrawn:=OLD.live;
 ELSE withdrawn:=OLD.live AND NOT NEW.live; END IF;
 IF withdrawn AND OLD.module='iam' THEN
  IF OLD.resource='accessBinding' AND OLD.verb='create' THEN
   DELETE FROM kaname.role_create_binding_rule;
  ELSIF OLD.resource='role' AND OLD.verb='bind' THEN
   DELETE FROM kaname.role_bind_role_rule;
  END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER retire_catalog_grant_authoring AFTER UPDATE OF live OR DELETE ON kaname.catalog_verb
 FOR EACH ROW EXECUTE FUNCTION kaname.retire_catalog_grant_authoring();

-- +goose Down
SET LOCAL lock_timeout='10s';
LOCK TABLE kaname.role_create_binding_rule,kaname.role_bind_role_rule,kaname.role_rule_ref IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM kaname.role_create_binding_rule)
 OR EXISTS(SELECT 1 FROM kaname.role_bind_role_rule)
 OR EXISTS(SELECT 1 FROM kaname.role_rule_ref WHERE module='iam' AND resource='role' AND verb='bind') THEN
  RAISE EXCEPTION 'grant authoring remains in use';
 END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER retire_catalog_grant_authoring ON kaname.catalog_verb;
DROP FUNCTION kaname.retire_catalog_grant_authoring();
DROP TRIGGER retire_role_grant_authoring ON kaname.roles;
DROP FUNCTION kaname.retire_role_grant_authoring();
DELETE FROM kaname.catalog_verb WHERE module='iam' AND resource='role' AND verb='bind';
