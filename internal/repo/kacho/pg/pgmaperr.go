// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// pgmaperr.go — SQLSTATE → sentinel bridge (the pgx-aware half of error
// mapping). This lives in the repo/pg ADAPTER layer, not in internal/errors,
// so the pgx dependency (github.com/jackc/pgx/v5/pgconn) stays out of the pure
// sentinel package that ~40 use-case/handler files import (architecture.md
// dependency-rule: use-case/domain must not pull pgx into their build closure).
//
// internal/errors keeps ONLY the pgx-free sentinel family + Wrapf/StripSentinel;
// the constraint-name-aware canonical Kachō text mapping (uniqueText/fkText/…)
// belongs to the adapter that owns the DB constraints and is applied here via
// mapErr (maperr.go).

import (
	stderrors "errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// wrapPgErr — SQLSTATE → ErrXxx mapping point, constraint-name aware. The
// constraint-name aware text mapping yields the canonical Kachō messages:
//
//	accounts_name_unique        → ErrAlreadyExists "Account with name %s already exists"
//	accounts_owner_fk           → ErrFailedPrecondition "User %s not found"
//	accounts_name_check         → ErrInvalidArg ...regex...
//	projects_account_fk (FK→accounts on INSERT project)        → ErrFailedPrecondition
//	projects_account_fk (FK←projects on DELETE account, 23503) → ErrFailedPrecondition "Account %s contains projects and cannot be deleted"
//
// The `kindHint` / `idHint` parameters supply context known only to the
// caller (passed in for the canonical Kachō text). When hints are empty we fall back
// to generic text.
func wrapPgErr(err error, kindHint, idHint string) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if !stderrors.As(err, &pgErr) {
		return err
	}
	switch pgErr.Code {
	case "23505": // unique_violation
		return iamerr.Wrapf(iamerr.ErrAlreadyExists, "%s", uniqueText(pgErr, kindHint, idHint))
	case "23503": // foreign_key_violation
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition, "%s", fkText(pgErr, kindHint, idHint))
	case "23514": // check_violation
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", checkText(pgErr))
	case "23502": // not_null_violation
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", notNullText(pgErr))
	case "23P01": // exclusion_violation
		// No EXCLUDE constraints in kacho_iam today; map generically WITHOUT
		// pgErr.Message (which would leak the constraint/range to the client).
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition, "resource conflicts with an existing reservation")
	case "40001": // serialization_failure
		// A transient write-write serialization conflict — the transaction can
		// succeed on retry. gRPC ABORTED is the idiomatic "retry the transaction"
		// code (FAILED_PRECONDITION would tell a well-behaved client NOT to retry,
		// contradicting the retryable nature). Unreachable under the current
		// READ COMMITTED regime (within-service invariants use single-statement
		// CAS / advisory locks / triggers, none of which raise 40001); mapped
		// correctly so a future SERIALIZABLE path surfaces a retryable code.
		return iamerr.Wrapf(iamerr.ErrAborted, "serialization conflict, retry")
	}
	// connection family 08xxx
	if strings.HasPrefix(pgErr.Code, "08") {
		return iamerr.Wrapf(iamerr.ErrUnavailable, "database unavailable")
	}
	// Unmapped SQLSTATE — never return the raw *pgconn.PgError: its Error()
	// carries table/constraint/column/SQLSTATE and would surface verbatim as the
	// gRPC INTERNAL message (data-integrity.md: no pgx leak, fixed INTERNAL text).
	// A new constraint that should produce a tenant-facing message must be added
	// to the constraint-aware switches above.
	return iamerr.Wrapf(iamerr.ErrInternal, "database error")
}

func uniqueText(pgErr *pgconn.PgError, kindHint, idHint string) string {
	switch pgErr.ConstraintName {
	case "accounts_name_unique":
		return fmt.Sprintf("Account with name %s already exists", idHint)
	case "users_external_id_unique",
		// users_active_external_id_uniq — migration 0011's global partial
		// UNIQUE on (external_id) WHERE invite_status='ACTIVE'. A lost
		// concurrent-bootstrap race (two first-logins for the same Kratos sub)
		// hits this 23505; map it to the canonical text so the raw pgx
		// constraint name never leaks (data-integrity.md).
		"users_active_external_id_uniq":
		return "User with external_id already exists"
	case "projects_account_name_unique":
		return fmt.Sprintf("Project with name %s already exists", idHint)
	case "service_accounts_account_name_unique":
		return fmt.Sprintf("ServiceAccount with name %s already exists", idHint)
	case "groups_account_name_unique":
		return fmt.Sprintf("Group with name %s already exists", idHint)
	case "roles_custom_unique", "roles_system_unique":
		return fmt.Sprintf("Role with name %s already exists", idHint)
	case "access_bindings_unique",
		"access_bindings_active_grant_uniq":
		// idHint = "<subject_id>|<resource_type>:<resource_id>" — composed
		// by the access_binding repo Insert (only caller that has subject /
		// resource handy). Falls back to a generic message otherwise.
		if idHint != "" {
			if subj, scope, ok := strings.Cut(idHint, "|"); ok {
				return fmt.Sprintf("these permissions are already granted to %s on %s", subj, scope)
			}
			return fmt.Sprintf("these permissions are already granted to %s", idHint)
		}
		return "AccessBinding already exists"
	}
	if kindHint != "" && idHint != "" {
		return fmt.Sprintf("%s %s already exists", kindHint, idHint)
	}
	// Unmapped UNIQUE constraint — generic text; never leak pgErr.Message
	// (it embeds the constraint name → schema reconnaissance).
	return "resource with these attributes already exists"
}

func fkText(pgErr *pgconn.PgError, kindHint, idHint string) string {
	switch pgErr.ConstraintName {
	case "accounts_owner_fk":
		return fmt.Sprintf("User %s not found", idHint)
	case "projects_account_fk":
		// Direction-sensitive:
		//   INSERT project with non-existent account_id → "Account <id> not found"
		//   DELETE account with dangling projects       → "Account <id> contains projects and cannot be deleted"
		// kindHint decides: "Account.Delete" → reverse direction; otherwise INSERT-side.
		if kindHint == "Account.Delete" {
			return fmt.Sprintf("Account %s contains projects and cannot be deleted", idHint)
		}
		return fmt.Sprintf("Account %s not found", idHint)
	case "service_accounts_account_fk":
		if kindHint == "Account.Delete" {
			return fmt.Sprintf("Account %s contains service accounts and cannot be deleted", idHint)
		}
		return fmt.Sprintf("Account %s not found", idHint)
	case "groups_account_fk":
		if kindHint == "Account.Delete" {
			return fmt.Sprintf("Account %s contains groups and cannot be deleted", idHint)
		}
		return fmt.Sprintf("Account %s not found", idHint)
	case "roles_account_fk":
		if kindHint == "Account.Delete" {
			return fmt.Sprintf("Account %s contains custom roles and cannot be deleted", idHint)
		}
		return fmt.Sprintf("Account %s not found", idHint)
	case "group_members_group_fk":
		return fmt.Sprintf("Group %s not found", idHint)
	case "access_bindings_role_fk":
		// Direction-sensitive:
		//   INSERT binding with a non-existent role_id → "Role <id> not found"
		//   DELETE role still referenced by ANY binding row (23503) → A-16 text.
		// The FK RESTRICT fires on ANY child row regardless of its status (ACTIVE
		// or a soft-revoked-but-not-purged row from TransitionStatus), so the text
		// is deliberately NOT qualified with "active" — AccessBindingService.Delete
		// is a HARD delete (purges the row) which is what clears the precondition.
		if kindHint == "Role.Delete" {
			return "role is in use by access bindings"
		}
		return fmt.Sprintf("Role %s not found", idHint)
	case "access_binding_conditions_condition_fk":
		// Direction-sensitive (migration 0048 — DB-level Condition reference):
		//   INSERT attach row with a non-existent condition_id → "Condition <id> not found"
		//   DELETE Condition still referenced by ANY attach row (23503 RESTRICT) → in-use text.
		// ConditionsCRUDService.Delete passes kindHint "Condition.Delete"; this
		// FK is what closes the delete-vs-attach TOCTOU (the software refcheck is
		// only a best-effort early message).
		if kindHint == "Condition.Delete" {
			return "condition is in use by access bindings"
		}
		return fmt.Sprintf("Condition %s not found", idHint)
	case "access_binding_subjects_subject_ref":
		// Migration 0050 BEFORE DELETE trigger on users/service_accounts/groups: a
		// principal still referenced as a subjects[0..N] grantee
		// (access_binding_subjects) cannot be hard-deleted (SEC r8, hard-rule #10).
		// The trigger is the race backstop for the concurrent add-subject-vs-delete
		// window the software NOT EXISTS guard (a stale snapshot) cannot close; the
		// common case is already rejected with the same text by the guard's probe.
		// kindHint = "<Resource>.Delete" (set by the repo Delete) → canonical text.
		res := strings.TrimSuffix(kindHint, ".Delete")
		if res == "" {
			res = "Principal"
		}
		return fmt.Sprintf("%s %s has active access bindings and cannot be deleted", res, idHint)
	}
	// Unmapped FK — generic text; never leak pgErr.Detail/Message (they embed
	// the referenced table/column/value → schema reconnaissance).
	return "referenced resource not found or still in use"
}

func checkText(pgErr *pgconn.PgError) string {
	switch pgErr.ConstraintName {
	case "accounts_name_check":
		return "Illegal argument name: must match ^[a-z][-a-z0-9]{2,62}$"
	case "accounts_description_check", "projects_description_check", "groups_description_check",
		"service_accounts_description_check", "roles_description_check":
		return "Illegal argument description: length must be <=256"
	case "accounts_labels_valid", "projects_labels_valid", "groups_labels_valid":
		return "Illegal argument labels: invalid key/value format or cardinality"
	case "projects_name_check", "service_accounts_name_check", "groups_name_check":
		return "Illegal argument name: must match ^[a-z][-a-z0-9]{2,62}$"
	case "roles_custom_name_check":
		return "Illegal argument name: must match ^[a-z][a-z0-9_]{0,40}$ (custom role)"
	case "roles_system_name_check":
		return "Illegal argument name: must match ^roles/[a-z]+\\.[a-z]+$ (system role)"
	case "users_email_check":
		return "Illegal argument email: invalid format"
	case "users_display_name_check":
		return "Illegal argument display_name: length must be <=128"
	case "users_external_id_check":
		return "Illegal argument external_id: length must be 1..256"
	}
	// Unmapped CHECK — generic InvalidArgument text; never leak pgErr.Message
	// (it embeds the constraint expression/name → schema reconnaissance).
	return "Illegal argument: value violates a constraint"
}

// notNullText — client-facing text for 23502 (not_null_violation). The raw
// pgErr.ColumnName is deliberately NOT echoed: it is an internal schema
// identifier that differs from the public proto field name and aids schema
// reconnaissance (data-integrity.md: no pgx leak). A 23502 reaching the DB is
// normally caught earlier by domain validation, so a generic message suffices.
func notNullText(_ *pgconn.PgError) string {
	return "a required field is missing"
}
