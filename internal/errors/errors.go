// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package errors — sentinel errors for kacho-iam + SQLSTATE → service.Err*
// bridge.
//
// Every use-case returns a sentinel-family error (ErrNotFound /
// ErrAlreadyExists / ErrFailedPrecondition / ErrInvalidArg / ErrInternal /
// ErrUnavailable / ErrPermissionDenied / ErrUnauthenticated); the handler
// layer maps to a gRPC code via status.Code(...). The within-service
// invariant forbids software-precheck for within-service refs — the only way to
// detect a within-service violation is to catch the SQLSTATE from pgx
// through WrapPgErr and wrap it in the appropriate sentinel.
package errors

import (
	stderrors "errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// Sentinel error family (parity with kacho-vpc/service.Err*).
var (
	ErrNotFound           = stderrors.New("not found")
	ErrAlreadyExists      = stderrors.New("already exists")
	ErrFailedPrecondition = stderrors.New("failed precondition")
	ErrInvalidArg         = stderrors.New("invalid argument")
	ErrInternal           = stderrors.New("internal")
	ErrUnavailable        = stderrors.New("unavailable")
	// ErrPermissionDenied — caller is authenticated but lacks the required
	// permission / is not the designated actor (e.g. JitPending
	// non-designated-approver, ComplianceReport FGA gate). Maps to gRPC
	// PERMISSION_DENIED.
	ErrPermissionDenied = stderrors.New("permission denied")
	// ErrUnauthenticated — caller's token does not satisfy the required
	// authentication assurance (step-up acr). Maps to gRPC UNAUTHENTICATED.
	ErrUnauthenticated = stderrors.New("unauthenticated")

	// ErrSelfRevoke — caller tries to revoke its own cluster admin grant
	// (self-protection). Maps to gRPC FAILED_PRECONDITION with
	// the Kachō text "cannot revoke own cluster admin grant".
	//
	// CHECK constraint cannot express this (constraint doesn't know caller —
	// runtime-property), so the guard lives in the SQL WHERE-clause of
	// the CAS UPDATE in ClusterAdminGrantWriter.Revoke.
	ErrSelfRevoke = stderrors.New("self revoke forbidden")

	// ErrLastAdmin — caller tries to revoke the last remaining active
	// cluster admin (lock-out protection). Maps to gRPC
	// FAILED_PRECONDITION with the Kachō text "cannot revoke last active
	// cluster admin".
	//
	// Implemented via single-statement CAS UPDATE with subquery
	// `(SELECT count(*) FROM cluster_admin_grants WHERE granted_until IS NULL) > 1`
	// — atomic, no separate SELECT-then-UPDATE race window.
	ErrLastAdmin = stderrors.New("last admin revoke forbidden")
)

// Wrapf — standard fmt.Errorf-style wrapper with an explicit sentinel. Use
// in use-cases: `return errors.Wrapf(errors.ErrNotFound, "Account %s not found", id)`.
func Wrapf(sentinel error, format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{sentinel}, args...)...)
}

// StripSentinel — extracts the "useful" part of the message (after
// "sentinel: ") so the handler layer can show the client the canonical Kachō text
// without the internal prefix (parity with
// kacho-vpc/internal/handler/mapping.go::stripSentinel).
func StripSentinel(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	for _, s := range []error{ErrNotFound, ErrAlreadyExists, ErrFailedPrecondition, ErrInvalidArg, ErrInternal, ErrUnavailable, ErrPermissionDenied, ErrUnauthenticated, ErrSelfRevoke, ErrLastAdmin} {
		prefix := s.Error() + ": "
		if rest, ok := strings.CutPrefix(msg, prefix); ok {
			return rest
		}
	}
	return msg
}

// WrapPgErr — SQLSTATE → ErrXxx mapping point, constraint-name aware. The
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
func WrapPgErr(err error, kindHint, idHint string) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if !stderrors.As(err, &pgErr) {
		return err
	}
	switch pgErr.Code {
	case "23505": // unique_violation
		return Wrapf(ErrAlreadyExists, "%s", uniqueText(pgErr, kindHint, idHint))
	case "23503": // foreign_key_violation
		return Wrapf(ErrFailedPrecondition, "%s", fkText(pgErr, kindHint, idHint))
	case "23514": // check_violation
		return Wrapf(ErrInvalidArg, "%s", checkText(pgErr, kindHint))
	case "23502": // not_null_violation
		return Wrapf(ErrInvalidArg, "%s", notNullText(pgErr))
	case "23P01": // exclusion_violation
		// No EXCLUDE constraints in kacho_iam today; map generically WITHOUT
		// pgErr.Message (which would leak the constraint/range to the client).
		return Wrapf(ErrFailedPrecondition, "resource conflicts with an existing reservation")
	case "40001": // serialization_failure
		return Wrapf(ErrFailedPrecondition, "serialization failure (retry)")
	}
	// connection family 08xxx
	if strings.HasPrefix(pgErr.Code, "08") {
		return Wrapf(ErrUnavailable, "database unavailable")
	}
	// Unmapped SQLSTATE — never return the raw *pgconn.PgError: its Error()
	// carries table/constraint/column/SQLSTATE and would surface verbatim as the
	// gRPC INTERNAL message (data-integrity.md: no pgx leak, fixed INTERNAL text).
	// A new constraint that should produce a tenant-facing message must be added
	// to the constraint-aware switches above.
	return Wrapf(ErrInternal, "database error")
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
	}
	// Unmapped FK — generic text; never leak pgErr.Detail/Message (they embed
	// the referenced table/column/value → schema reconnaissance).
	return "referenced resource not found or still in use"
}

func checkText(pgErr *pgconn.PgError, kindHint string) string {
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
	_ = kindHint
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
