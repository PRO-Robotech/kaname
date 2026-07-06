-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0050_principal_subject_ref_before_delete.sql — close the DELETE side of the
-- within-service subject reference (hard-rule #10), symmetric to migration 0049's
-- INSERT-side probe.
--
-- A binding grants to 1..N subjects (RBAC rules-model, migration 0028). subjects[0]
-- is projected onto access_bindings.(subject_type, subject_id); subjects[1..N] live
-- ONLY in the access_binding_subjects child table — each an INDEPENDENT grantee with
-- its own emitted FGA tuple lineage. Migration 0049 added an INSERT/UPDATE
-- FOR KEY SHARE probe (subject_ref_exists) so a binding can never reference a
-- non-existent principal. But the DELETE side of the referent tables (users /
-- service_accounts / groups) only ever probed access_bindings.subject_id (= the
-- LEGACY subjects[0] projection): a principal referenced ONLY as subjects[1..N]
-- could be hard-deleted, orphaning the within-service reference and leaving a
-- PHANTOM authz grant to the deleted principal in the FGA ledger (CWE-362 on the
-- concurrent delete-vs-add-subject path).
--
-- The documented substitute for a polymorphic FK (subject_id selects one of three
-- tables by subject_type, so no single REFERENCES target exists) is a trigger. This
-- is the delete-side mirror of 0049: a BEFORE DELETE row trigger on each referent
-- table that RAISEs 23503 (→ FailedPrecondition) when the row being deleted is still
-- referenced by ANY access_binding_subjects row (any ordinal, subjects[0..N]).
--
-- RACE CLOSURE (why this is required beyond the software NOT EXISTS guard): a plain
-- `DELETE ... WHERE NOT EXISTS(access_binding_subjects …)` evaluates its qualifier on
-- a stale READ COMMITTED snapshot and does NOT re-check it after blocking on a
-- concurrent inserter's FOR KEY SHARE lock (a lock-only conflict yields no new tuple
-- version → no EvalPlanQual re-qualification). The BEFORE DELETE trigger fires AFTER
-- the delete has taken the referent row's exclusive lock, and its EXISTS runs a FRESH
-- snapshot — so it observes any add-subject that committed while the delete waited,
-- and the two paths serialize on the referent row-lock exactly like a real FK. The
-- software guard in the repo (extended to access_binding_subjects) is retained only
-- for the fast common-case reject + canonical error text; this trigger is the
-- authoritative invariant.
--
-- This is a NEW internal migration for a within-service invariant. It changes no
-- wire contract (no proto/gen/REST/public-field change): enforcement is entirely
-- DB-side. The repo maps SQLSTATE 23503 → ErrFailedPrecondition via
-- iamerr.WrapPgErr, and the RAISE tags CONSTRAINT = 'access_binding_subjects_subject_ref'
-- so the wrapper yields the canonical "<Resource> <id> has active access bindings and
-- cannot be deleted" text (no pgx/schema leak).

-- +goose Up
-- +goose StatementBegin

-- principal_not_referenced_as_subject() — shared BEFORE DELETE trigger for the three
-- referent tables (users / service_accounts / groups). TG_ARGV[0] carries the
-- subject_type discriminator the row's table maps to ('user' / 'service_account' /
-- 'group'). The DELETE already holds an exclusive lock on OLD (taken before BEFORE
-- ROW triggers fire), so a concurrent access_binding_subjects INSERT — which takes
-- FOR KEY SHARE on this same row via subject_ref_exists (0049) — cannot commit a new
-- reference while the delete is in flight; and any reference committed earlier is
-- visible to this fresh-snapshot EXISTS. RAISEs 23503 (→ FailedPrecondition) when a
-- reference exists.
CREATE FUNCTION kacho_iam.principal_not_referenced_as_subject() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM kacho_iam.access_binding_subjects
         WHERE subject_type = TG_ARGV[0]
           AND subject_id   = OLD.id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE    = '23503',
            CONSTRAINT = 'access_binding_subjects_subject_ref',
            MESSAGE    = format('%s %s is referenced by an access binding subject and cannot be deleted',
                                TG_ARGV[0], OLD.id);
    END IF;
    RETURN OLD;
END;
$$;

-- +goose StatementEnd
-- +goose StatementBegin

DROP TRIGGER IF EXISTS users_subject_ref_before_delete_trg ON kacho_iam.users;
CREATE TRIGGER users_subject_ref_before_delete_trg
    BEFORE DELETE ON kacho_iam.users
    FOR EACH ROW
    EXECUTE FUNCTION kacho_iam.principal_not_referenced_as_subject('user');

-- +goose StatementEnd
-- +goose StatementBegin

DROP TRIGGER IF EXISTS service_accounts_subject_ref_before_delete_trg ON kacho_iam.service_accounts;
CREATE TRIGGER service_accounts_subject_ref_before_delete_trg
    BEFORE DELETE ON kacho_iam.service_accounts
    FOR EACH ROW
    EXECUTE FUNCTION kacho_iam.principal_not_referenced_as_subject('service_account');

-- +goose StatementEnd
-- +goose StatementBegin

DROP TRIGGER IF EXISTS groups_subject_ref_before_delete_trg ON kacho_iam.groups;
CREATE TRIGGER groups_subject_ref_before_delete_trg
    BEFORE DELETE ON kacho_iam.groups
    FOR EACH ROW
    EXECUTE FUNCTION kacho_iam.principal_not_referenced_as_subject('group');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS groups_subject_ref_before_delete_trg ON kacho_iam.groups;

-- +goose StatementEnd
-- +goose StatementBegin

DROP TRIGGER IF EXISTS service_accounts_subject_ref_before_delete_trg ON kacho_iam.service_accounts;

-- +goose StatementEnd
-- +goose StatementBegin

DROP TRIGGER IF EXISTS users_subject_ref_before_delete_trg ON kacho_iam.users;

-- +goose StatementEnd
-- +goose StatementBegin

DROP FUNCTION IF EXISTS kacho_iam.principal_not_referenced_as_subject();

-- +goose StatementEnd
