// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"fmt"
	"time"

	"go.uber.org/multierr"
)

// Role — multi-scope. Exactly one scope field is non-NULL:
//   - is_system=true + ClusterID set: system role (`kacho-system.admin`, ...).
//   - is_system=false + AccountID set: account-scoped custom role.
//   - is_system=false + ProjectID set: project-scoped custom role.
//
// Enforced by DB CHECK `roles_scope_xor` + a partial UNIQUE per scope.
// Domain.Validate duplicates the CHECK to give friendly errors before
// reaching the DB. (The legacy B2B-tenant role scope was removed; a custom
// role is scoped to exactly one of {account, project}.)
type Role struct {
	ID          RoleID
	ClusterID   ClusterID // set for system role
	AccountID   AccountID // set for account-scoped custom
	ProjectID   ProjectID // set for project-scoped custom
	Name        RoleName
	Description Description
	// Rules — authored policy (RBAC rules-model 2026). Source of truth + public
	// API surface. Compiled into Permissions (internal, FGA-emit) by CompileRules.
	Rules Rules
	// Permissions — INTERNAL compiled form (anchor/names arms; match_labels NOT
	// compiled). Derived from Rules via CompileRules; NOT a public API field for
	// rules-roles. Legacy permissions-only roles (no Rules) keep their stored set.
	Permissions Permissions
	IsSystem    bool
	CreatedAt   time.Time
	// CreatedByUserID — authoring principal (governance/audit). Optional.
	CreatedByUserID UserID
	// UpdatedAt — last-mutation timestamp. Zero until first Update.
	UpdatedAt time.Time
	// Labels — tenant-facing метки САМОГО ресурса Role (НЕ путать с
	// Rule.MatchLabels, отбирающим объекты под грантом). Делают Role
	// label-selectable наравне с account/project (ARM_LABELS-грант на iam.role →
	// v_list по `labels @> matchLabels`; List фильтрует viewer ∪ v_list).
	Labels Labels
}

// Validate — multi-scope XOR formula + rules/permissions.
//
// A role is valid when EITHER it carries authored Rules (the rules-model 2026
// authority) OR a legacy compiled Permissions set (back-compat read of
// pre-rules roles).
//
// When Rules is set (a rules-role) it is validated through Rules.Validate
// (system-context = IsSystem) and the compiled Permissions projection is validated
// for the 4-seg grammar + cap ONLY — NOT the ≥1 lower bound (ValidateCompiled): a
// label-only role (all rules ARM_LABELS) compiles to an EMPTY permission set by
// design and must be accepted. The ≥1 floor is retained for the LEGACY
// permissions-only path (no Rules) so a degenerate legacy role with an
// empty set cannot exist.
func (r Role) Validate() error {
	var errs error
	errs = multierr.Append(errs, r.Name.Validate())
	errs = multierr.Append(errs, r.Description.Validate())
	errs = multierr.Append(errs, r.Labels.Validate())
	if len(r.Rules) > 0 {
		errs = multierr.Append(errs, r.Rules.Validate(r.IsSystem))
		// Rules-role: the compiled set may legitimately be empty (label-only).
		errs = multierr.Append(errs, r.Permissions.ValidateCompiled())
	} else {
		// Legacy permissions-only role: must carry ≥1 permission.
		errs = multierr.Append(errs, r.Permissions.Validate())
	}

	clusterSet := r.ClusterID != ""
	accountSet := r.AccountID != ""
	projectSet := r.ProjectID != ""

	if r.IsSystem {
		// system: cluster_id only; the rest empty.
		if !clusterSet || accountSet || projectSet {
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument: system role must have only cluster_id set"))
		}
	} else {
		// custom: cluster_id IS NULL, and exactly one of {account, project}.
		if clusterSet {
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument: custom role must not have cluster_id"))
		}
		set := 0
		if accountSet {
			set++
		}
		if projectSet {
			set++
		}
		if set != 1 {
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument: custom role must have exactly one of (account_id, project_id) set"))
		}
	}
	return errs
}
