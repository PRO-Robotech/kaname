-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Приёмка: docs/engineering/acceptance/grant-authority-matches-the-whole-effect.md §8.3.
-- Канонический command VIEW требует INSERT отдельно от таблиц relkind r/p.
-- Ни сам VIEW, ни его SECURITY INVOKER trigger не являются разрешением записи:
-- strict attestation/purpose и область проверяются прежними guards зеркала/каталога.

-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_grant_runtime(p_runtime regrole) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE target record; migration_owner oid; runtime_name text;
BEGIN
 SELECT rolname INTO STRICT runtime_name FROM pg_catalog.pg_roles WHERE oid=p_runtime::oid;
 SELECT relowner INTO migration_owner FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass;
 IF (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)<>migration_owner THEN RAISE EXCEPTION 'runtime grants require migration owner' USING ERRCODE='42501'; END IF;
 IF p_runtime::oid=migration_owner OR pg_has_role(p_runtime,migration_owner,'MEMBER')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=p_runtime::oid)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE oid=p_runtime::oid AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='kaname' AND (nspowner<>migration_owner OR has_schema_privilege(p_runtime,oid,'CREATE')))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_database WHERE datname=current_database() AND datdba=p_runtime::oid)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kaname' AND (pg_has_role(p_runtime,c.relowner,'MEMBER') OR (c.relkind IN ('r','p') AND has_table_privilege(p_runtime,c.oid,'TRIGGER'))))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc f JOIN pg_catalog.pg_namespace n ON n.oid=f.pronamespace WHERE n.nspname='kaname' AND pg_has_role(p_runtime,f.proowner,'MEMBER')) THEN
  RAISE EXCEPTION 'runtime must be separate from migration ownership and DDL authority' USING ERRCODE='42501';
 END IF;
 EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I',current_database(),runtime_name);
 EXECUTE format('GRANT USAGE ON SCHEMA kaname TO %I',runtime_name);
 EXECUTE format('GRANT SELECT ON ALL TABLES IN SCHEMA kaname TO %I',runtime_name);
 -- Полная команда регистрации остаётся SECURITY INVOKER и проходит guards зеркала.
 EXECUTE format('GRANT INSERT ON TABLE kaname.resource_registration_command TO %I',runtime_name);
 FOR target IN SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kaname' AND c.relkind IN ('r','p') AND left(c.relname,10)<>'authority_' AND c.relname<>'goose_db_version' LOOP
  EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE,TRUNCATE ON TABLE kaname.%I TO %I',target.relname,runtime_name);
 END LOOP;
 EXECUTE format('REVOKE ALL ON TABLE kaname.authority_writer_protocol,kaname.authority_semantic_identity,kaname.authority_bundle_handoff FROM %I',runtime_name);
 EXECUTE format('GRANT SELECT ON TABLE kaname.authority_semantic_identity TO %I',runtime_name);
 EXECUTE format('GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA kaname TO %I',runtime_name);
 IF has_table_privilege(p_runtime,'kaname.authority_bundle_handoff','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
 OR has_table_privilege(p_runtime,'kaname.authority_writer_protocol','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
 OR has_table_privilege(p_runtime,'kaname.authority_semantic_identity','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER') THEN
  RAISE EXCEPTION 'runtime retains authority metadata mutation privileges' USING ERRCODE='42501';
 END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$
DECLARE target record; runtime_name text;
BEGIN
 -- Только обычный LOGIN с прямым INSERT на зеркало от владельца протокола.
 -- Принадлежность к чужой роли или DDL-полномочия не признаются runtime-профилем.
 FOR target IN
  SELECT DISTINCT r.oid FROM pg_catalog.pg_roles r
  JOIN pg_catalog.pg_class m ON m.oid='kaname.resource_mirror'::regclass
  CROSS JOIN LATERAL pg_catalog.aclexplode(m.relacl) a
  JOIN pg_catalog.pg_class p ON p.oid='kaname.authority_writer_protocol'::regclass
  WHERE a.grantee=r.oid AND a.grantor=p.relowner AND a.privilege_type='INSERT'
   AND r.rolcanlogin AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole
       OR r.rolreplication OR r.rolbypassrls OR r.rolinherit)
   AND r.oid<>p.relowner AND NOT pg_has_role(r.oid,p.relowner,'MEMBER')
   AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=r.oid)
  ORDER BY r.oid
 LOOP
  -- Удалённая роль не превращается в PUBLIC и не обрывает обновление остальных.
  SELECT rolname INTO runtime_name FROM pg_catalog.pg_roles WHERE oid=target.oid;
  IF runtime_name IS NULL THEN CONTINUE; END IF;
  BEGIN
   EXECUTE format('GRANT INSERT ON TABLE kaname.resource_registration_command TO %I',runtime_name);
  EXCEPTION WHEN undefined_object THEN
   -- Конкурентный DROP ROLE: выдавать полномочие уже некому.
   IF EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE oid=target.oid) THEN RAISE; END IF;
  END;
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
-- Возвращаем точное тело предшественника 1900 и снимаем INSERT только с того же
-- protocol-runtime профиля. SELECT и посторонние custom grantees сохраняются.
-- Если роль этого профиля имела custom INSERT ещё до Up, после Down владелец
-- должен восстановить его явно: точное восстановление исторического ACL не обещается.
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_grant_runtime(p_runtime regrole) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE target record; migration_owner oid; runtime_name text;
BEGIN
 SELECT rolname INTO STRICT runtime_name FROM pg_catalog.pg_roles WHERE oid=p_runtime::oid;
 SELECT relowner INTO migration_owner FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass;
 IF (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)<>migration_owner THEN RAISE EXCEPTION 'runtime grants require migration owner' USING ERRCODE='42501'; END IF;
 IF p_runtime::oid=migration_owner OR pg_has_role(p_runtime,migration_owner,'MEMBER')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=p_runtime::oid)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE oid=p_runtime::oid AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='kaname' AND (nspowner<>migration_owner OR has_schema_privilege(p_runtime,oid,'CREATE')))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_database WHERE datname=current_database() AND datdba=p_runtime::oid)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kaname' AND (pg_has_role(p_runtime,c.relowner,'MEMBER') OR (c.relkind IN ('r','p') AND has_table_privilege(p_runtime,c.oid,'TRIGGER'))))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc f JOIN pg_catalog.pg_namespace n ON n.oid=f.pronamespace WHERE n.nspname='kaname' AND pg_has_role(p_runtime,f.proowner,'MEMBER')) THEN
  RAISE EXCEPTION 'runtime must be separate from migration ownership and DDL authority' USING ERRCODE='42501';
 END IF;
 EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I',current_database(),runtime_name);
 EXECUTE format('GRANT USAGE ON SCHEMA kaname TO %I',runtime_name);
 EXECUTE format('GRANT SELECT ON ALL TABLES IN SCHEMA kaname TO %I',runtime_name);
 FOR target IN SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kaname' AND c.relkind IN ('r','p') AND left(c.relname,10)<>'authority_' AND c.relname<>'goose_db_version' LOOP
  EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE,TRUNCATE ON TABLE kaname.%I TO %I',target.relname,runtime_name);
 END LOOP;
 EXECUTE format('REVOKE ALL ON TABLE kaname.authority_writer_protocol,kaname.authority_semantic_identity,kaname.authority_bundle_handoff FROM %I',runtime_name);
 EXECUTE format('GRANT SELECT ON TABLE kaname.authority_semantic_identity TO %I',runtime_name);
 EXECUTE format('GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA kaname TO %I',runtime_name);
 IF has_table_privilege(p_runtime,'kaname.authority_bundle_handoff','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
 OR has_table_privilege(p_runtime,'kaname.authority_writer_protocol','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
 OR has_table_privilege(p_runtime,'kaname.authority_semantic_identity','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER') THEN
  RAISE EXCEPTION 'runtime retains authority metadata mutation privileges' USING ERRCODE='42501';
 END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$
DECLARE target record; runtime_name text;
BEGIN
 -- Только обычный LOGIN с прямым INSERT на зеркало от владельца протокола.
 -- Принадлежность к чужой роли или DDL-полномочия не признаются runtime-профилем.
 FOR target IN
  SELECT DISTINCT r.oid FROM pg_catalog.pg_roles r
  JOIN pg_catalog.pg_class m ON m.oid='kaname.resource_mirror'::regclass
  CROSS JOIN LATERAL pg_catalog.aclexplode(m.relacl) a
  JOIN pg_catalog.pg_class p ON p.oid='kaname.authority_writer_protocol'::regclass
  WHERE a.grantee=r.oid AND a.grantor=p.relowner AND a.privilege_type='INSERT'
   AND r.rolcanlogin AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole
       OR r.rolreplication OR r.rolbypassrls OR r.rolinherit)
   AND r.oid<>p.relowner AND NOT pg_has_role(r.oid,p.relowner,'MEMBER')
   AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=r.oid)
  ORDER BY r.oid
 LOOP
  -- Удалённая роль не превращается в PUBLIC и не обрывает обновление остальных.
  SELECT rolname INTO runtime_name FROM pg_catalog.pg_roles WHERE oid=target.oid;
  IF runtime_name IS NULL THEN CONTINUE; END IF;
  BEGIN
   EXECUTE format('REVOKE INSERT ON TABLE kaname.resource_registration_command FROM %I',runtime_name);
  EXCEPTION WHEN undefined_object THEN
   -- Конкурентный DROP ROLE: выдавать полномочие уже некому.
   IF EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE oid=target.oid) THEN RAISE; END IF;
  END;
 END LOOP;
END $$;
-- +goose StatementEnd
