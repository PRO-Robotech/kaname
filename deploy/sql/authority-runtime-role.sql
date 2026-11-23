-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1034: admin bootstrap, не goose. Имена — параметры psql, пароль извне.
-- psql -v runtime_role=... -v migration_role=... -f authority-runtime-role.sql
\set ON_ERROR_STOP on
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT', :'runtime_role')
WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=:'runtime_role')
\gexec
BEGIN;
SELECT format('SET LOCAL ROLE %I', :'migration_role')
\gexec
SELECT kaname.authority_protocol_grant_runtime(to_regrole(format('%I', :'runtime_role')));
-- /readyz читает только применённую версию. История миграций
-- остаётся доступной runtime только по двум колонкам, без записи.
SET LOCAL search_path = kaname, public;
GRANT SELECT (version_id, is_applied) ON TABLE goose_db_version TO :"runtime_role";
COMMIT;
