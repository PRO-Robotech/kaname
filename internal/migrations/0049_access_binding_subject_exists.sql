-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0049_access_binding_subject_exists.sql — close the access_bindings.subject_id
-- within-service reference at the DB level (hard-rule #10).
--
-- The (subject_type, subject_id) pair on access_bindings (and its
-- access_binding_subjects child rows, migration 0028) referenced a user /
-- service_account / group in the SAME database, but carried ONLY a CHECK on the
-- subject_type enum — NO existence enforcement of subject_id. Unlike
-- group_members (whose member existence is held by the
-- group_members_member_exists() BEFORE-INSERT trigger, 0001), a binding could be
-- written for a principal that does not exist:
--   (a) phantom grant — INSERT a binding with subject_id='usr-typo' referencing
--       no user; the row (and its emitted FGA tuple) pollutes the authz ledger
--       with a grant to a non-existent principal;
--   (b) delete-vs-create race — User.Delete passes its NOT EXISTS(access_bindings
--       WHERE subject_id=$user) CAS guard while a concurrent AccessBinding.Create
--       inserts a binding for that same user; with no shared lock both commit and
--       leave a dangling binding for a just-deleted user (hard-rule #10, CWE-362).
--
-- A single real FK cannot express this — subject_id is polymorphic (one of three
-- tables selected by subject_type), so there is no single REFERENCES target. The
-- documented substitute for a polymorphic FK is a BEFORE INSERT/UPDATE trigger
-- that probes the referent with a LOCKING read (SELECT … FOR KEY SHARE) — the
-- same row-lock a real FK's child INSERT takes. That lock is what closes race
-- (b): it serializes the binding INSERT against a concurrent DELETE of the
-- referenced principal, so whichever commits second observes the other's effect
-- (the delete's NOT EXISTS re-qualifies against the committed binding → 0 rows;
-- or the insert's probe finds the row gone → 23503). A plain snapshot
-- SELECT EXISTS (as group_members historically used) does NOT lock and therefore
-- does NOT close the race — this migration also upgrades that older trigger.
--
-- FK semantics on UPDATE: the probe is skipped when (subject_type, subject_id) is
-- unchanged, so status transitions / label updates / deletion-protection toggles
-- on an existing binding never re-validate the subject (mirrors a real FK, which
-- only re-checks when the referencing columns change). Only INSERTs and
-- subject-changing UPDATEs are enforced.
--
-- This is a NEW internal migration for a within-service invariant. It changes no
-- wire contract (no proto/gen/REST/public-field change): the enforcement is
-- entirely DB-side; the repo already maps SQLSTATE 23503 → ErrFailedPrecondition
-- via iamerr.WrapPgErr (23503 → FailedPrecondition), so a rejected phantom grant
-- surfaces as FAILED_PRECONDITION exactly like the group_members / role FKs.

-- +goose Up
-- +goose StatementBegin

-- subject_ref_exists() — shared BEFORE INSERT/UPDATE trigger for BOTH
-- access_bindings and access_binding_subjects (identical (subject_type,
-- subject_id) columns). Probes the referent table selected by subject_type with
-- FOR KEY SHARE so a concurrent DELETE of the principal serializes against the
-- write (polymorphic-FK substitute). Raises 23503 (→ FailedPrecondition) when the
-- subject does not exist, 23514 (→ InvalidArgument) for an unknown subject_type
-- (defense in depth alongside the existing subject_type CHECK).
CREATE FUNCTION kacho_iam.subject_ref_exists() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- FK semantics: skip re-validation when the subject reference is unchanged
    -- on UPDATE (status/label/protection mutations must not re-probe the subject).
    IF TG_OP = 'UPDATE'
       AND NEW.subject_type = OLD.subject_type
       AND NEW.subject_id   = OLD.subject_id THEN
        RETURN NEW;
    END IF;

    IF NEW.subject_type = 'user' THEN
        PERFORM 1 FROM kacho_iam.users
            WHERE id = NEW.subject_id FOR KEY SHARE;
    ELSIF NEW.subject_type = 'service_account' THEN
        PERFORM 1 FROM kacho_iam.service_accounts
            WHERE id = NEW.subject_id FOR KEY SHARE;
    ELSIF NEW.subject_type = 'group' THEN
        PERFORM 1 FROM kacho_iam.groups
            WHERE id = NEW.subject_id FOR KEY SHARE;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = format('Illegal argument subject_type %s', NEW.subject_type);
    END IF;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503',
            MESSAGE = format('%s %s not found', NEW.subject_type, NEW.subject_id);
    END IF;
    RETURN NEW;
END;
$$;

-- +goose StatementEnd
-- +goose StatementBegin

DROP TRIGGER IF EXISTS access_bindings_subject_exists_trg ON kacho_iam.access_bindings;
CREATE TRIGGER access_bindings_subject_exists_trg
    BEFORE INSERT OR UPDATE ON kacho_iam.access_bindings
    FOR EACH ROW
    EXECUTE FUNCTION kacho_iam.subject_ref_exists();

-- +goose StatementEnd
-- +goose StatementBegin

DROP TRIGGER IF EXISTS access_binding_subjects_subject_exists_trg ON kacho_iam.access_binding_subjects;
CREATE TRIGGER access_binding_subjects_subject_exists_trg
    BEFORE INSERT OR UPDATE ON kacho_iam.access_binding_subjects
    FOR EACH ROW
    EXECUTE FUNCTION kacho_iam.subject_ref_exists();

-- +goose StatementEnd
-- +goose StatementBegin

-- Upgrade the existing group_members existence trigger (0001) from a snapshot
-- SELECT EXISTS to a FOR KEY SHARE locking probe, so the member-delete-vs-add
-- race (finding-7 / CWE-362) serializes the same way. Behaviour is otherwise
-- identical (23503 when the member does not exist; 23514 for an unknown
-- member_type). CREATE OR REPLACE keeps the trigger binding intact.
CREATE OR REPLACE FUNCTION kacho_iam.group_members_member_exists() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.member_type = OLD.member_type
       AND NEW.member_id   = OLD.member_id THEN
        RETURN NEW;
    END IF;

    IF NEW.member_type = 'user' THEN
        PERFORM 1 FROM kacho_iam.users
            WHERE id = NEW.member_id FOR KEY SHARE;
    ELSIF NEW.member_type = 'service_account' THEN
        PERFORM 1 FROM kacho_iam.service_accounts
            WHERE id = NEW.member_id FOR KEY SHARE;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = format('Illegal argument member_type %s', NEW.member_type);
    END IF;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503',
            MESSAGE = format('%s %s not found', NEW.member_type, NEW.member_id);
    END IF;
    RETURN NEW;
END;
$$;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS access_binding_subjects_subject_exists_trg ON kacho_iam.access_binding_subjects;

-- +goose StatementEnd
-- +goose StatementBegin

DROP TRIGGER IF EXISTS access_bindings_subject_exists_trg ON kacho_iam.access_bindings;

-- +goose StatementEnd
-- +goose StatementBegin

DROP FUNCTION IF EXISTS kacho_iam.subject_ref_exists();

-- +goose StatementEnd
-- +goose StatementBegin

-- Restore the original snapshot-EXISTS group_members trigger function (0001).
CREATE OR REPLACE FUNCTION kacho_iam.group_members_member_exists() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    found bool;
BEGIN
    IF NEW.member_type = 'user' THEN
        SELECT EXISTS(SELECT 1 FROM kacho_iam.users WHERE id = NEW.member_id) INTO found;
    ELSIF NEW.member_type = 'service_account' THEN
        SELECT EXISTS(SELECT 1 FROM kacho_iam.service_accounts WHERE id = NEW.member_id) INTO found;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = format('Illegal argument member_type %s', NEW.member_type);
    END IF;
    IF NOT found THEN
        RAISE EXCEPTION USING ERRCODE = '23503',
            MESSAGE = format('%s %s not found', NEW.member_type, NEW.member_id);
    END IF;
    RETURN NEW;
END;
$$;

-- +goose StatementEnd
