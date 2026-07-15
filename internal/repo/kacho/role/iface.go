// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package role — CQRS port-iface'ы для kacho_iam.roles.
package role

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

type ReaderIface interface {
	Get(ctx context.Context, id domain.RoleID) (domain.Role, error)

	// GetWithVersion returns the role plus its optimistic-concurrency token.
	// roles has NO version column (like access_bindings), so the token is the
	// row's `xmin::text` snapshot (the read-modify-write OCC pattern without a
	// version column). The token is opaque to the caller: Role.Update reads it in
	// the sync request-path, echoes it into UpdateCAS in the worker-tx, and a
	// mismatch (a concurrent Role.Update bumped xmin) is rejected by UpdateCAS
	// with ErrFailedPrecondition. Not-found → ErrNotFound (verbatim Get text).
	GetWithVersion(ctx context.Context, id domain.RoleID) (domain.Role, string, error)
	// List — может фильтровать по is_system и/или account_id.
	List(ctx context.Context, filter ListFilter) ([]domain.Role, string, error)
	// ListAssignable — roles valid for binding on (resourceType, resourceID)
	// per the assignability matrix: system roles always; account-scoped
	// custom only on its own account; project-scoped custom only on its own
	// project; cluster ⇒ system only. The predicate is encoded in the SQL WHERE
	// (mirror of domain.IsRoleAssignable) so keyset pagination is correct
	// across the filtered set. resourceType is one of account|project|cluster
	// (caller validates the whitelist + id format first).
	ListAssignable(ctx context.Context, resourceType, resourceID string, filter ListFilter) ([]domain.Role, string, error)
}

type WriterIface interface {
	// Insert — только custom-role. System-роли
	// создаются миграцией; попытка Insert с is_system=true в use-case'е →
	// InvalidArgument до repo (см. role-RPC handler).
	Insert(ctx context.Context, r domain.Role) (domain.Role, error)
	Update(ctx context.Context, r domain.Role, updateMask []string) (domain.Role, error)

	// UpdateCAS is Update guarded by an xmin OCC token. It runs a
	// single-statement `UPDATE roles SET … WHERE id=$id AND xmin::text=$expected
	// RETURNING …`: the row-lock serializes concurrent Role.Updates, so the loser
	// reads the SAME expected version, finds xmin bumped, matches 0 rows →
	// ErrFailedPrecondition (the caller's whole writer-tx — UPDATE + the FGA
	// reconcile fan-out — rolls back together, ban #10). expectedVersion=="" skips
	// the predicate (unconditional last-writer Update — back-compat for callers
	// that do not read a token). 0 rows with a non-empty token ⇒ either the row
	// moved concurrently or it no longer exists → ErrFailedPrecondition.
	UpdateCAS(ctx context.Context, r domain.Role, updateMask []string, expectedVersion string) (domain.Role, error)
	// Delete — system-role нельзя удалять → use-case
	// возвращает FailedPrecondition до похода в БД. Custom с активными bindings —
	// FK RESTRICT (`access_bindings_role_fk`) → SQLSTATE 23503 → FailedPrecondition.
	Delete(ctx context.Context, id domain.RoleID) error

	// ReplaceRuleSelectors syncs kacho_iam.role_rule_selectors with the role's
	// UNIFIED materializing rules: ARM_ANCHOR
	// (all) + ARM_NAMES + ARM_LABELS. It DELETEs the role's current selector rows and
	// INSERTs one per materializing rule (keyed by rule_fp), inside the caller's
	// writer-tx (atomic with the role INSERT/UPDATE, ban #10) — so a removed/edited
	// rule drops/replaces its selector together with the rules change. The
	// reconciler's fast-path + sweep JOIN this table to find which bindings a
	// mirror-change event affects (forward-materialization). A legacy
	// permissions-only role clears its selectors (DELETE then no INSERT). Idempotent
	// re-sync (same rules → same set).
	ReplaceRuleSelectors(ctx context.Context, roleID domain.RoleID, selectors []domain.RuleSelector) error
}

type ListFilter struct {
	PageSize  int32
	PageToken string
	Filter    string
	// AccountID — scope the catalog to a single Account: the result is system
	// roles (always — catalog floor) PLUS the custom roles of THIS Account; a
	// foreign Account's custom roles are excluded at the SQL layer. Empty → no
	// Account scope.
	AccountID domain.AccountID
	IsSystem  *bool // nil = both
	// VisibleIDs — per-object visibility push-down. When non-nil
	// the result is constrained to `is_system OR id = ANY(VisibleIDs)` AT THE SQL
	// LAYER, so keyset (created_at,id) pagination is dense over the FILTERED set
	// (no leaky/short pages). System roles bypass the constraint (tenant-wide
	// reference catalog floor); only custom roles are filtered per-object. The set
	// is supplied by the use-case from FGA ListObjects(subject,"viewer","iam_role")
	// (the `viewer` tier cascades from account-tier, so a role's creator /
	// account-admin resolves their own roles — consistent with account/project List).
	// A non-nil empty slice means "no custom roles visible" (system-only result).
	VisibleIDs []string
}
