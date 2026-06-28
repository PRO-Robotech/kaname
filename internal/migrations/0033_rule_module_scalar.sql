-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- RBAC rules-model 2026 — Rule.modules (array) → Rule.module (scalar).
--
-- Rule.modules (repeated) → Rule.module (scalar): exactly ONE module per rule.
-- The proto field `modules` (array) is tombstoned; the domain Rule carries a
-- scalar Module. This migration brings the stored roles.rules JSONB and the
-- within-DB shape CHECK (ban #10) into the new scalar form, for ALL roles
-- (system + custom). It runs AFTER 0031 (which re-seeds system roles with the
-- ARRAY `modules:["x"]` form) — 0033 transforms 0031's array output into scalar.
--
-- DATA REWRITE: each rule `{"modules":[m1,...,mN], ...}` becomes N
-- rules `{"module":mK, ...same resources/verbs/resource_names/match_labels}`, the
-- `modules` key dropped. On live data N=1 always (verified, every rule already
-- carries a single-element modules array) so the rewrite is a pure
-- `modules:[m] → module:m` rename per rule; the defensive N→N split covers the
-- theoretical multi-module case (not reachable on live).
--
-- IDEMPOTENT: a rule already in the scalar shape (`module` present, no
-- `modules`) is passed through unchanged — re-running 0033 Up on scalar rows is a
-- no-op (safe for goose re-apply / kind double-bootstrap).
--
-- ORDER: the array-shape CHECK constraint roles_rules_valid (calling the
-- OLD array-form iam_rules_valid) would reject the scalar rows mid-rewrite. So the
-- constraint is DROPPED, the rows are rewritten, the function is replaced with the
-- scalar-form validator, and the SAME-named constraint is re-added — all in one
-- transaction. The end state is the scalar-only CHECK active (within-DB parity,
-- ban #10): a direct INSERT of the old array `modules` form, or a rule with no
-- `module`, is rejected on the DB level.

-- (1) Drop the array-form CHECK so the in-tx scalar rewrite is not blocked.
ALTER TABLE kacho_iam.roles DROP CONSTRAINT IF EXISTS roles_rules_valid;

-- (2) Rewrite every roles.rules row: split each rule over its modules array into
-- one scalar-module rule per module, dropping the modules key; pass through rules
-- already in scalar form unchanged (idempotent). NULL/empty rules left as-is.
-- +goose StatementBegin
DO $$
DECLARE
    r          record;
    rule       jsonb;
    new_rules  jsonb;
    base       jsonb;
    m          jsonb;
BEGIN
    FOR r IN SELECT id, rules FROM kacho_iam.roles
              WHERE rules IS NOT NULL
                AND jsonb_typeof(rules) = 'array'
                AND jsonb_array_length(rules) > 0
    LOOP
        new_rules := '[]'::jsonb;
        FOR rule IN SELECT value FROM jsonb_array_elements(r.rules) LOOP
            IF rule ? 'module' AND NOT (rule ? 'modules') THEN
                -- already scalar — pass through (idempotent).
                new_rules := new_rules || jsonb_build_array(rule);
            ELSIF rule ? 'modules' AND jsonb_typeof(rule -> 'modules') = 'array' THEN
                -- strip the modules key from the rest of the rule, then emit one
                -- scalar-module rule per element (N=1 on live → simple rename).
                base := rule - 'modules';
                FOR m IN SELECT value FROM jsonb_array_elements(rule -> 'modules') LOOP
                    new_rules := new_rules || jsonb_build_array(base || jsonb_build_object('module', m));
                END LOOP;
            ELSE
                -- malformed (neither shape) — leave verbatim; the re-added CHECK
                -- below will reject it loudly rather than silently mangle it.
                new_rules := new_rules || jsonb_build_array(rule);
            END IF;
        END LOOP;
        UPDATE kacho_iam.roles SET rules = new_rules WHERE id = r.id;
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- (3) Replace iam_rules_valid with the scalar-`module` validator (same signature,
-- so the re-added constraint binds to it). Shape mirrors domain.Rule.Validate's
-- structural part: module is a required non-empty string; resources/verbs are
-- required non-empty string arrays 1..16; resource_names XOR match_labels.
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

        -- module: required, non-empty string scalar. The array `modules` key is
        -- NO LONGER valid.
        IF NOT (rule ? 'module') THEN RETURN false; END IF;
        IF jsonb_typeof(rule -> 'module') <> 'string' THEN RETURN false; END IF;
        IF length(rule ->> 'module') < 1 THEN RETURN false; END IF;

        -- resources / verbs: required non-empty string arrays, 1..16.
        FOR arr IN SELECT rule -> k FROM (VALUES ('resources'), ('verbs')) AS t(k) LOOP
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
            IF (SELECT count(*) FROM jsonb_object_keys(rule -> 'match_labels')) NOT BETWEEN 1 AND 16 THEN
                RETURN false;
            END IF;
        END IF;
    END LOOP;

    RETURN true;
END;
$$;
-- +goose StatementEnd

-- (4) Re-add the SAME-named CHECK constraint (now binding to the scalar validator).
ALTER TABLE kacho_iam.roles
    ADD CONSTRAINT roles_rules_valid CHECK (kacho_iam.iam_rules_valid(rules));

-- +goose Down

-- Reverse, symmetric order: drop constraint → rewrite rows back to single-element
-- modules array (closed-default — scalar `module:m` → `modules:[m]` per rule, Q2:
-- Down does NOT synthetically re-merge distinct scalar rules into one multi-module
-- rule; the merge is ambiguous by design) → restore the array-form validator →
-- re-add the constraint. On live N=1 the Up→Down→Up round-trip is semantically
-- identical (single-element-array ↔ scalar).
ALTER TABLE kacho_iam.roles DROP CONSTRAINT IF EXISTS roles_rules_valid;

-- +goose StatementBegin
DO $$
DECLARE
    r          record;
    rule       jsonb;
    new_rules  jsonb;
    base       jsonb;
BEGIN
    FOR r IN SELECT id, rules FROM kacho_iam.roles
              WHERE rules IS NOT NULL
                AND jsonb_typeof(rules) = 'array'
                AND jsonb_array_length(rules) > 0
    LOOP
        new_rules := '[]'::jsonb;
        FOR rule IN SELECT value FROM jsonb_array_elements(r.rules) LOOP
            IF rule ? 'modules' AND NOT (rule ? 'module') THEN
                new_rules := new_rules || jsonb_build_array(rule);
            ELSIF rule ? 'module' THEN
                base := rule - 'module';
                new_rules := new_rules
                    || jsonb_build_array(base || jsonb_build_object('modules', jsonb_build_array(rule -> 'module')));
            ELSE
                new_rules := new_rules || jsonb_build_array(rule);
            END IF;
        END LOOP;
        UPDATE kacho_iam.roles SET rules = new_rules WHERE id = r.id;
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- Restore the array-form iam_rules_valid (pre-0033 / 0025 shape).
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
    IF jsonb_array_length(rules) = 0 THEN RETURN true; END IF;
    IF jsonb_array_length(rules) > 64 THEN RETURN false; END IF;

    FOR rule IN SELECT value FROM jsonb_array_elements(rules) LOOP
        IF jsonb_typeof(rule) <> 'object' THEN RETURN false; END IF;

        FOR arr IN SELECT rule -> k FROM (VALUES ('modules'), ('resources'), ('verbs')) AS t(k) LOOP
            IF arr IS NULL OR jsonb_typeof(arr) <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(arr) < 1 OR jsonb_array_length(arr) > 16 THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(arr) e WHERE jsonb_typeof(e) <> 'string') THEN
                RETURN false;
            END IF;
        END LOOP;

        has_names  := (rule ? 'resource_names') AND jsonb_typeof(rule -> 'resource_names') <> 'null';
        has_labels := (rule ? 'match_labels')   AND jsonb_typeof(rule -> 'match_labels')   <> 'null';

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
    ADD CONSTRAINT roles_rules_valid CHECK (kacho_iam.iam_rules_valid(rules));
