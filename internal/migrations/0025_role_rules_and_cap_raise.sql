-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- RBAC rules-model 2026 — authored-policy roles.rules column + cap raise.
--
-- Adds the authored-policy column roles.rules (JSONB), a within-DB shape CHECK
-- iam_rules_valid (the DB-level parity of domain.Rules.Validate — ban #10), and
-- a cap-raise of the compiled-permission validator iam_permissions_valid from
-- 256 → 1024 in LOCKSTEP with the domain (domain.MaxCompiledPermissions=1024)
-- and the proto (size) bound.
--
-- WITHIN-SERVICE INVARIANTS — DB-level only (ban #10):
--   * roles.rules JSONB NOT NULL DEFAULT '[]' — legacy permissions-only roles
--     read back rules='[]' (back-compat; the backfill is a later migration, NOT here).
--   * CHECK roles_rules_valid (iam_rules_valid(rules)) — a direct INSERT/UPDATE
--     that bypasses the use-case still cannot persist a malformed rules array
--     (direct-INSERT parity). Shape mirrors domain.Rule.Validate:
--       - rules is a JSON array, cardinality ≤64 (empty '[]' allowed for legacy);
--       - each element is an object with non-empty string arrays modules/resources/
--         verbs, each 1..16 elements;
--       - optional resource_names (array ≤256) XOR match_labels (object 1..16);
--       - both selectors present → reject.
--     The fine-grained wildcard/feed-gate/grammar policy stays in the use-case +
--     domain (it needs the system-context flag + the feed-registry); the DB CHECK
--     pins the structural shape so a hand-written INSERT cannot store garbage.
--   * iam_permissions_valid cap 256→1024 (CREATE OR REPLACE) — the 4-segment
--     grammar regex is UNCHANGED; only the cardinality bound is raised so the
--     compiled set derived from rules (CompileRules ≤1024) passes the CHECK.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kacho_iam.iam_rules_valid(rules jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
AS $$
DECLARE
    rule       jsonb;
    arr        jsonb;
    has_names  boolean;
    has_labels boolean;
BEGIN
    IF rules IS NULL THEN RETURN false; END IF;
    IF jsonb_typeof(rules) <> 'array' THEN RETURN false; END IF;
    -- Empty array is valid (legacy permissions-only role; back-compat).
    IF jsonb_array_length(rules) = 0 THEN RETURN true; END IF;
    IF jsonb_array_length(rules) > 64 THEN RETURN false; END IF;

    FOR rule IN SELECT value FROM jsonb_array_elements(rules) LOOP
        IF jsonb_typeof(rule) <> 'object' THEN RETURN false; END IF;

        -- modules / resources / verbs: required non-empty string arrays, 1..16.
        FOR arr IN SELECT rule -> k FROM (VALUES ('modules'), ('resources'), ('verbs')) AS t(k) LOOP
            IF arr IS NULL OR jsonb_typeof(arr) <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(arr) < 1 OR jsonb_array_length(arr) > 16 THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(arr) e WHERE jsonb_typeof(e) <> 'string') THEN
                RETURN false;
            END IF;
        END LOOP;

        has_names  := (rule ? 'resource_names') AND jsonb_typeof(rule -> 'resource_names') <> 'null';
        has_labels := (rule ? 'match_labels')   AND jsonb_typeof(rule -> 'match_labels')   <> 'null';

        -- resource_names XOR match_labels (both → reject).
        IF has_names AND has_labels THEN RETURN false; END IF;

        IF has_names THEN
            IF jsonb_typeof(rule -> 'resource_names') <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'resource_names') > 256 THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(rule -> 'resource_names') e
                       WHERE jsonb_typeof(e) <> 'string') THEN
                RETURN false;
            END IF;
        END IF;

        IF has_labels THEN
            IF jsonb_typeof(rule -> 'match_labels') <> 'object' THEN RETURN false; END IF;
            -- non-empty when set, ≤16 keys.
            IF (SELECT count(*) FROM jsonb_object_keys(rule -> 'match_labels')) NOT BETWEEN 1 AND 16 THEN
                RETURN false;
            END IF;
        END IF;
    END LOOP;

    RETURN true;
END;
$$;
-- +goose StatementEnd

ALTER TABLE kacho_iam.roles
    ADD COLUMN rules jsonb NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE kacho_iam.roles
    ADD CONSTRAINT roles_rules_valid CHECK (kacho_iam.iam_rules_valid(rules));

-- Label-only rules-roles: a role whose rules are ALL ARM_LABELS compiles
-- to an EMPTY compiled-permission set (matchLabels is NOT compiled).
-- The baseline roles_permissions_valid CHECK (0001) required a NON-empty
-- permissions array via iam_permissions_valid (length 0 → false), which falsely
-- blocked a valid label-only role. Replace it with a two-column CHECK that allows
-- an EMPTY permissions array ONLY when rules is non-empty (a rules-role); a LEGACY
-- permissions-only role (rules='[]') must still carry ≥1 valid permission. A
-- non-empty permissions set is validated by the 4-seg grammar + cap in both cases.
-- (within-DB invariant, ban #10 — DB parity of domain.Role.Validate/ValidateCompiled.)
ALTER TABLE kacho_iam.roles
    DROP CONSTRAINT roles_permissions_valid;

ALTER TABLE kacho_iam.roles
    ADD CONSTRAINT roles_permissions_valid CHECK (
        (jsonb_array_length(permissions) = 0 AND jsonb_array_length(rules) > 0)
        OR kacho_iam.iam_permissions_valid(permissions)
    );

-- Cap-raise 256→1024 (grammar regex unchanged). CREATE OR REPLACE keeps the
-- attached CHECK roles_permissions_valid valid (same signature).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kacho_iam.iam_permissions_valid(perms jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
AS $$
DECLARE
    v text;
    -- module.resource.resourceName.verb (4-segment RBAC v2 grammar, unchanged).
    re text := '^(\*|[a-z][a-z0-9-]*)\.(\*|[a-z][a-zA-Z0-9_-]*)\.(\*|[a-zA-Z0-9_-]+)\.(\*|[a-z][a-zA-Z0-9_-]*)$';
BEGIN
    IF perms IS NULL THEN RETURN false; END IF;
    IF jsonb_typeof(perms) <> 'array' THEN RETURN false; END IF;
    IF jsonb_array_length(perms) = 0 THEN RETURN false; END IF;
    IF jsonb_array_length(perms) > 1024 THEN RETURN false; END IF;
    FOR v IN SELECT value::text FROM jsonb_array_elements_text(perms) LOOP
        IF v !~ re THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
END;
$$;
-- +goose StatementEnd

-- +goose Down

-- Restore the baseline single-column roles_permissions_valid CHECK (0001).
-- NOTE: rolling back with any label-only role present (empty permissions + non-empty
-- rules) will fail the restored CHECK — those rows must be removed first.
ALTER TABLE kacho_iam.roles DROP CONSTRAINT IF EXISTS roles_permissions_valid;
ALTER TABLE kacho_iam.roles
    ADD CONSTRAINT roles_permissions_valid CHECK (kacho_iam.iam_permissions_valid(permissions));

ALTER TABLE kacho_iam.roles DROP CONSTRAINT IF EXISTS roles_rules_valid;
ALTER TABLE kacho_iam.roles DROP COLUMN IF EXISTS rules;
DROP FUNCTION IF EXISTS kacho_iam.iam_rules_valid(jsonb);

-- Restore the 256 cap on iam_permissions_valid.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kacho_iam.iam_permissions_valid(perms jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
AS $$
DECLARE
    v text;
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
-- +goose StatementEnd
