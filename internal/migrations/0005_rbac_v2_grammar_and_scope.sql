-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0005_rbac_v2_grammar_and_scope.sql — RBAC v2 grammar + scope.
--
-- Three steps inside one goose transaction so a failing CHECK aborts
-- everything (ban #10 — DB-level invariants):
--
--   1. Snapshot roles + access_bindings to `_pre_rbac_v2_*` backup tables
--      (TRUNCATE-then-INSERT so re-run is idempotent without duplicates).
--   2. Promote 3-segment role.permissions to canonical 4-segment
--      (`M.R.V` → `M.R.*.V`); leave already-4-segment rows untouched.
--   3. Swap `iam_permissions_valid()` to the v2 (strict 4-segment) regex
--      AND re-attach the `roles_permissions_valid` CHECK so any
--      un-promotable row trips it and rolls the whole migration back.
--   4. Add `access_bindings.scope SMALLINT NOT NULL CHECK IN (1,2,3)` with
--      backfill from `resource_type`.
--
-- Idempotent: re-running after a DELETE on goose_db_version completes
-- without duplicating backup rows or column-add errors.

-- +goose Up
-- +goose StatementBegin

-- Backup tables: drop+recreate so the column shape always mirrors the
-- current source table (idempotent re-run safe: a previous run's backup
-- could be missing later-added columns like `scope`).
DROP TABLE IF EXISTS kacho_iam._pre_rbac_v2_roles;
DROP TABLE IF EXISTS kacho_iam._pre_rbac_v2_access_bindings;
CREATE TABLE kacho_iam._pre_rbac_v2_roles (LIKE kacho_iam.roles INCLUDING DEFAULTS);
CREATE TABLE kacho_iam._pre_rbac_v2_access_bindings (LIKE kacho_iam.access_bindings INCLUDING DEFAULTS);

INSERT INTO kacho_iam._pre_rbac_v2_roles SELECT * FROM kacho_iam.roles;
INSERT INTO kacho_iam._pre_rbac_v2_access_bindings SELECT * FROM kacho_iam.access_bindings;

-- Drop the old CHECK so we can replace the function + re-attach the
-- constraint atomically.  (CHECK references functions by name and would
-- block CREATE OR REPLACE on `iam_permissions_valid()` if left attached.)
ALTER TABLE kacho_iam.roles DROP CONSTRAINT IF EXISTS roles_permissions_valid;

-- v2 validator — strict 4-segment grammar `module.resource.resourceName.verb`
-- (each segment is `[a-zA-Z][a-zA-Z0-9_-]*` or `[a-zA-Z0-9_-]+` for
-- resourceName, or literal `*`; verb segment additionally limits leading
-- letter to lowercase).
CREATE OR REPLACE FUNCTION kacho_iam.iam_permissions_valid(perms jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
AS $$
DECLARE
    v text;
    -- module       : lowercase identifier (or `*`)
    -- resource     : starts lowercase, camelCase allowed (or `*`)
    -- resourceName : alphanumeric + dash/underscore (or `*`)
    -- verb         : starts lowercase, camelCase allowed (or `*`)
    re text := '^(\*|[a-z][a-z0-9-]*)\.(\*|[a-z][a-zA-Z0-9_-]*)\.(\*|[a-zA-Z0-9_-]+)\.(\*|[a-z][a-zA-Z0-9_-]*)$';
BEGIN
    IF perms IS NULL THEN RETURN false; END IF;
    IF jsonb_typeof(perms) <> 'array' THEN RETURN false; END IF;
    IF jsonb_array_length(perms) = 0 THEN RETURN false; END IF;
    IF jsonb_array_length(perms) > 256 THEN RETURN false; END IF;
    FOR v IN SELECT value::text FROM jsonb_array_elements_text(perms) LOOP
        IF v !~ re THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
END;
$$;

-- Promote 3-segment → 4-segment in-place. 4-seg rows passthrough; rows
-- with array_length other than 3 or 4 stay as-is (the re-attached CHECK
-- below will trip and roll back the migration if any malformed row exists).
UPDATE kacho_iam.roles SET permissions = (
    SELECT jsonb_agg(
        CASE
            WHEN array_length(string_to_array(p, '.'), 1) = 3
                THEN split_part(p, '.', 1) || '.' || split_part(p, '.', 2) || '.*.' || split_part(p, '.', 3)
            ELSE p
        END
    )
    FROM jsonb_array_elements_text(permissions) p
)
WHERE permissions IS NOT NULL AND jsonb_array_length(permissions) > 0;

-- Re-attach the CHECK with the v2 validator. If any row still violates,
-- the entire transaction (goose-wrapped) aborts → migration not recorded
-- → operator can fix and re-run.
ALTER TABLE kacho_iam.roles
    ADD CONSTRAINT roles_permissions_valid
    CHECK (kacho_iam.iam_permissions_valid(permissions));

-- access_bindings.scope SMALLINT — CLUSTER=1 / ACCOUNT=2 / PROJECT=3.
-- DO block so re-run does not error on duplicate column.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'kacho_iam'
          AND table_name   = 'access_bindings'
          AND column_name  = 'scope'
    ) THEN
        ALTER TABLE kacho_iam.access_bindings ADD COLUMN scope SMALLINT;
    END IF;
END $$;

-- Backfill scope from resource_type. Legacy resource-type names map to their
-- current equivalents; per-domain resource_types collapse to PROJECT
-- (the smallest scope tier).
UPDATE kacho_iam.access_bindings SET scope = CASE resource_type
    WHEN 'cluster'      THEN 1::smallint
    WHEN 'organization' THEN 1::smallint
    WHEN 'account'      THEN 2::smallint
    WHEN 'cloud'        THEN 2::smallint
    WHEN 'project'      THEN 3::smallint
    WHEN 'folder'       THEN 3::smallint
    ELSE 3::smallint
END
WHERE scope IS NULL;

ALTER TABLE kacho_iam.access_bindings ALTER COLUMN scope SET NOT NULL;

ALTER TABLE kacho_iam.access_bindings DROP CONSTRAINT IF EXISTS access_bindings_scope_ck;
ALTER TABLE kacho_iam.access_bindings
    ADD CONSTRAINT access_bindings_scope_ck CHECK (scope IN (1, 2, 3));

CREATE INDEX IF NOT EXISTS access_bindings_scope_idx
    ON kacho_iam.access_bindings(scope, resource_type);

-- BEFORE INSERT trigger — if the writer omits `scope`, derive it from
-- `resource_type` using the same table as the backfill above. This keeps
-- existing callers working (the existing repo Insert SQL does not yet pass
-- scope) and serves as a defence-in-depth safety net afterwards.
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kacho_iam.access_bindings_scope_default() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.scope IS NULL THEN
        NEW.scope := CASE NEW.resource_type
            WHEN 'cluster'      THEN 1::smallint
            WHEN 'organization' THEN 1::smallint
            WHEN 'account'      THEN 2::smallint
            WHEN 'cloud'        THEN 2::smallint
            WHEN 'project'      THEN 3::smallint
            WHEN 'folder'       THEN 3::smallint
            ELSE 3::smallint
        END;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS access_bindings_scope_default_trg ON kacho_iam.access_bindings;
CREATE TRIGGER access_bindings_scope_default_trg
    BEFORE INSERT ON kacho_iam.access_bindings
    FOR EACH ROW EXECUTE FUNCTION kacho_iam.access_bindings_scope_default();
-- +goose StatementEnd
