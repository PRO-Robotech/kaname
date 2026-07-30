-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0072_access_binding_role_assignable.sql — a binding may only carry a role that is
-- assignable on its scope, enforced where every writer must pass.
--
-- WHY THE DATABASE AND NOT THE SERVICE. The rule ("a custom role belongs to the
-- account that defined it and may be bound only inside it") had exactly ONE
-- enforcement point: the AccessBinding create path. It is not the only writer of the
-- table — the user-invitation flow builds a binding from a caller-supplied role and
-- inserts it directly, and two seed paths insert with hard-coded system roles. So the
-- invariant held on one of four paths and was, in effect, optional: an invitation
-- naming a role defined by ANOTHER account created a binding on it.
--
-- What that costs the role's owner is not access — the binding's scope belongs to the
-- inviter, so the role's verbs only ever materialise over the inviter's own objects —
-- it is the role's LIFECYCLE. access_bindings.role_id is ON DELETE RESTRICT, so the
-- foreign binding pins the role for ever: its owner gets "role is in use by access
-- bindings" on delete, while the listing that would show them why filters that row out
-- (it lives in a scope they hold no authority over). A refusal with no attributable
-- cause, and no way to clear it.
--
-- Placing the check here closes it for every writer that exists and every writer that
-- will exist, which is the point: the service-level gate is being kept (it produces
-- the actionable message and the hide-existence collapse), and the invitation path is
-- being taught the same gate in the same change — but neither is what makes the rule
-- unavoidable.
--
-- THE RULE, mirrored from domain.IsRoleAssignableInAccount:
--   * a SYSTEM role is assignable anywhere;
--   * a custom account-role is assignable on ITS OWN account, and on a project nested
--     in that account (the single hierarchy-down case);
--   * a custom project-role is assignable on ITS OWN project only;
--   * anything else — including any custom role on a cluster scope — is refused.
--   * a scope this service does not own (a resource_type that is neither account nor
--     project) is NOT judged here: the owning service decides, and guessing would
--     refuse valid cross-domain bindings.
--
-- SQLSTATE 23514 (check_violation) → INVALID_ARGUMENT through the service's mapper.
-- The service-level gate answers FAILED_PRECONDITION with an actionable message and
-- runs first, so this code is what a caller sees only when a writer skipped the gate —
-- i.e. exactly when something is wrong in the service, not in the request.

-- +goose Up
-- +goose StatementBegin

CREATE FUNCTION kacho_iam.access_binding_role_assignable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    r_is_system  boolean;
    r_account_id text;
    r_project_id text;
    scope_account text;
BEGIN
    -- Unchanged reference on UPDATE → nothing to re-judge (FK semantics; a status or
    -- label mutation must not re-probe the role).
    IF TG_OP = 'UPDATE'
       AND NEW.role_id       = OLD.role_id
       AND NEW.resource_type = OLD.resource_type
       AND NEW.resource_id   = OLD.resource_id THEN
        RETURN NEW;
    END IF;

    SELECT is_system, coalesce(account_id, ''), coalesce(project_id, '')
      INTO r_is_system, r_account_id, r_project_id
      FROM kacho_iam.roles
     WHERE id = NEW.role_id
     FOR KEY SHARE;

    -- No such role: the role_id foreign key is the authority on that, and it is
    -- DEFERRABLE, so it reports at COMMIT. Saying anything here would pre-empt it
    -- with a different code.
    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF r_is_system THEN
        RETURN NEW;
    END IF;

    IF NEW.resource_type = 'account' THEN
        IF r_account_id = NEW.resource_id THEN
            RETURN NEW;
        END IF;
    ELSIF NEW.resource_type = 'project' THEN
        IF r_project_id = NEW.resource_id THEN
            RETURN NEW;
        END IF;
        -- Hierarchy-down: an account-tier role on a project nested in ITS OWN account.
        IF r_project_id = '' AND r_account_id <> '' THEN
            SELECT account_id INTO scope_account
              FROM kacho_iam.projects
             WHERE id = NEW.resource_id;
            IF FOUND AND scope_account = r_account_id THEN
                RETURN NEW;
            END IF;
        END IF;
    ELSE
        -- A scope owned by another service. Not this trigger's judgement; the cluster
        -- scope reaches here too and falls through to the refusal below, which is
        -- correct — no custom role is assignable on it.
        IF NEW.resource_type <> 'cluster' THEN
            RETURN NEW;
        END IF;
    END IF;

    RAISE EXCEPTION USING ERRCODE = '23514',
        MESSAGE = format(
            'role %s is not assignable on %s:%s',
            NEW.role_id, NEW.resource_type, NEW.resource_id);
END;
$$;

-- +goose StatementEnd
-- +goose StatementBegin

DROP TRIGGER IF EXISTS access_bindings_role_assignable_trg ON kacho_iam.access_bindings;
CREATE TRIGGER access_bindings_role_assignable_trg
    BEFORE INSERT OR UPDATE ON kacho_iam.access_bindings
    FOR EACH ROW
    EXECUTE FUNCTION kacho_iam.access_binding_role_assignable();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS access_bindings_role_assignable_trg ON kacho_iam.access_bindings;
-- +goose StatementEnd
-- +goose StatementBegin
DROP FUNCTION IF EXISTS kacho_iam.access_binding_role_assignable();
-- +goose StatementEnd
