// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/dto"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"

	_ "github.com/PRO-Robotech/kacho/services/iam/internal/dto/toproto"
)

// auditTenantAccountID derives the Account scope for the audit_outbox
// tenant_account_id column from an AccessBinding. For account-scoped bindings
// the resource itself IS the account; for project / cluster / cross-service
// scopes it is left empty (NULL in audit_outbox) — the binding_id + resource_*
// fields in the event_payload already make the event fully queryable, and
// resolving a project's owning account would require an extra read on the
// compliance path. Tenant scoping is a best-effort query convenience, not a
// correctness requirement.
func auditTenantAccountID(b domain.AccessBinding) string {
	if b.ResourceType == "account" {
		return b.ResourceID
	}
	return ""
}

func marshalAB(b domain.AccessBinding) (*anypb.Any, error) {
	var dst *iamv1.AccessBinding
	if err := dto.Transfer(dto.FromTo(b, &dst)); err != nil {
		return nil, fmt.Errorf("dto.Transfer AccessBinding: %w", err)
	}
	return anypb.New(dst)
}

// labelsFromProto converts a protobuf own-resource label map into domain.Labels
// (parity with account/serviceAccount/user/role handlers). nil/empty → empty
// (non-nil) map. Maps the binding's OWN labels (Create/UpdateAccessBindingRequest.labels)
// — making the AccessBinding label-selectable (D-6).
func labelsFromProto(m map[string]string) domain.Labels {
	if len(m) == 0 {
		return domain.Labels{}
	}
	out := make(domain.Labels, len(m))
	for k, v := range m {
		out[domain.LabelKey(k)] = domain.LabelVal(v)
	}
	return out
}

// vlistVisibleBindingIDs resolves the principal's `viewer ∪ v_list` visible-set on
// iam_access_binding (D-6 catalog-видимость label-selectable binding'ов). Returns
// (set, ok): ok=false when the resolver is unwired (no RelationQueries) — callers
// then rely solely on the self/granted floor. Fail-closed: a FGA ListObjects error
// on ANY relation → UNAVAILABLE (never an unfiltered leak, never an owner-only
// fallback; parity with role.List D-47 / security.md). An anonymous / empty-subject
// principal yields an empty set (default-deny).
func vlistVisibleBindingIDs(ctx context.Context, rq clients.RelationQueries) (map[string]bool, bool, error) {
	if rq == nil {
		return nil, false, nil
	}
	subject, ok := authzguard.PrincipalSubject(ctx) // fail-closed: anon / empty / unknown → ""
	if !ok {
		return map[string]bool{}, true, nil
	}
	visible := map[string]bool{}
	for _, relation := range []string{"viewer", "v_list"} {
		ids, err := rq.ListObjects(ctx, subject, relation, "iam_access_binding", nil, 0)
		if err != nil {
			return nil, true, shared.MapRepoErr(iamerr.ErrUnavailable)
		}
		for _, id := range ids {
			visible[id] = true
		}
	}
	return visible, true, nil
}

// requireGrantAuthority — package-level function shared by Create and Delete.
// Verifies the calling principal is authorised to create or delete an
// AccessBinding on the given grant scope.
//
// Authority is granted when EITHER holds:
//   - the principal owns the owning Account (bootstrap path — every Account
//     owner can administer their own tree), OR
//   - the principal holds an FGA `admin` relation on the scope object
//     (delegated administration — an account-admin who is not the owner can
//     still grant roles within their scope).
//
// This replaces the old owner-only `requireOwnerOfResource` plus an
// identity-equality self-grant guard, which together blocked owners from
// granting roles to other users (peer-access, matrix model 4).
func requireGrantAuthority(ctx context.Context, repo Repo, relations clients.RelationStore, resourceType, resourceID string) error {
	// Path 0 — cluster-admin short-circuit (RBAC explicit-model 2026 P5, D-9 / КФ-2).
	// After the access-cascade is contracted a cluster-admin no longer holds an
	// account/project-tier admin-tuple, so the ordinary owner/FGA-admin paths below
	// would deny them. The flat super-gate (cluster:…#system_admin) keeps a
	// cluster-admin able to grant on ANY scope (D-06 — foreign account) and to manage
	// the binding objects themselves (D-07 — iam_access_binding). Additive: it runs
	// ALONGSIDE the existing paths, not instead of them. nil-safe via the guard inside
	// IsClusterAdmin (unwired relations → false → fall through).
	if relations != nil && authzguard.IsClusterAdmin(ctx, relations) {
		return nil
	}

	var ownerUserID string
	// The owner-path resolves the owning Account via the DB reader. It is only
	// relevant for the hierarchy scope-types (account/project); for every other
	// object-type (cluster / leaf FGA object like compute.instance) authority is
	// granted ONLY by the FGA admin path below, so the reader is not needed. Skip
	// it entirely when repo is nil — callers that authorize purely through FGA
	// (ExpandAccess on a leaf object via delegated admin) wire only the
	// RelationStore. ListByScope/Create/Delete always wire a non-nil repo, so
	// this nil-guard does not weaken any existing caller.
	if repo != nil && (resourceType == "account" || resourceType == "project") {
		rd, err := repo.Reader(ctx)
		if err != nil {
			return shared.MapRepoErr(err)
		}
		defer func() { _ = rd.Rollback(ctx) }()

		switch resourceType {
		case "account":
			acct, gerr := rd.Accounts().Get(ctx, domain.AccountID(resourceID))
			if gerr != nil {
				return shared.MapRepoErr(gerr)
			}
			ownerUserID = string(acct.OwnerUserID)
		case "project":
			proj, gerr := rd.Projects().Get(ctx, domain.ProjectID(resourceID))
			if gerr != nil {
				return shared.MapRepoErr(gerr)
			}
			acct, gerr := rd.Accounts().Get(ctx, proj.AccountID)
			if gerr != nil {
				return shared.MapRepoErr(gerr)
			}
			ownerUserID = string(acct.OwnerUserID)
		}
	}
	// Non-hierarchy scopes (cluster / org / cross-service / leaf FGA objects like
	// compute.instance) have no DB-side "owner": authority is granted ONLY by the
	// FGA admin/system_admin path below (e.g. cluster admins hold `system_admin`
	// on cluster:cluster_kacho_root). No owner-fallback path — ownerUserID stays
	// empty so only Path 2 can authorize them.

	// Path 1 — owner of the owning Account.
	if ownerUserID != "" && authzguard.IsSelf(ctx, ownerUserID) {
		return nil
	}

	// Path 2 — delegated admin: principal holds `admin` on the scope object in FGA.
	// We call fgaHoldsScopeAdmin (NOT fgaHoldsAdmin) here: Path 0 above ALREADY ran
	// the cluster-admin short-circuit (IsClusterAdmin) and missed, so re-checking it
	// inside fgaHoldsAdmin would be a redundant identical FGA round-trip (#9). The
	// scope-only variant performs just the per-scope admin-tuple Check.
	if fgaHoldsScopeAdmin(ctx, relations, resourceType, resourceID) {
		return nil
	}

	return authzguard.PermissionDenied()
}

// fgaAdminObject builds the canonical FGA object string for an authority Check
// (`<lower-type>:<id>`). Centralised so every grant/read-authority gate targets
// the SAME object — the prior per-site copies disagreed on id casing.
func fgaAdminObject(resourceType, resourceID string) string {
	return fmt.Sprintf("%s:%s", strings.ToLower(resourceType), resourceID)
}

// fgaHoldsAdmin reports whether the ctx principal holds delegated-admin authority
// on the scope object: EITHER it is a cluster-admin (flat super-gate) OR it holds
// the FGA `admin` relation on the scope object. This is the entry-point for the
// DIRECT call-sites (ListSubjectPrivileges, D-07) that have NOT already run the
// cluster-admin short-circuit. requireGrantAuthority does NOT use this — it ran
// Path 0 (IsClusterAdmin) itself and calls fgaHoldsScopeAdmin to avoid a redundant
// cluster-admin Check (#9).
//
// Fail-closed: false when the FGA client is unwired (unit tests / degraded mode),
// the caller is anonymous, or the principal id is empty.
func fgaHoldsAdmin(ctx context.Context, relations clients.RelationStore, resourceType, resourceID string) bool {
	if relations == nil || authzguard.IsAnonymous(ctx) {
		return false
	}
	// Cluster-admin short-circuit (RBAC explicit-model 2026 P5, D-9 / КФ-2): the
	// flat super-gate covers the direct fgaHoldsAdmin call-sites (ListSubjectPrivileges,
	// D-07) so a cluster-admin retains delegated-admin visibility after the
	// access-cascade is contracted. Checked before the per-scope admin tuple.
	if authzguard.IsClusterAdmin(ctx, relations) {
		return true
	}
	return fgaHoldsScopeAdmin(ctx, relations, resourceType, resourceID)
}

// fgaHoldsScopeAdmin reports whether the ctx principal holds the FGA `admin`
// relation on the scope object — the per-scope admin-tuple Check ONLY (no
// cluster-admin short-circuit). Used by requireGrantAuthority's Path 2, which has
// already evaluated the cluster-admin super-gate in Path 0 (#9 — avoids a duplicate
// cluster-admin round-trip). Fail-closed: false when FGA is unwired, the caller is
// anonymous / unknown-type, or the Check errors.
func fgaHoldsScopeAdmin(ctx context.Context, relations clients.RelationStore, resourceType, resourceID string) bool {
	if relations == nil {
		return false
	}
	subject, ok := authzguard.PrincipalSubject(ctx) // fail-closed: anon / empty / unknown → ""
	if !ok {
		return false
	}
	allowed, err := relations.Check(ctx, subject, "admin", fgaAdminObject(resourceType, resourceID))
	return err == nil && allowed
}

// requireGrantAuthorityViaCreate — shim allowing CreateAccessBindingUseCase to
// call the package-level requireGrantAuthority without exposing its fields.
func (u *CreateAccessBindingUseCase) requireGrantAuthority(ctx context.Context, resourceType, resourceID string) error {
	return requireGrantAuthority(ctx, u.repo, u.relations, resourceType, resourceID)
}

// validateGlobalAllSelector enforces the Q-2 GLOBAL+all policy (RBAC explicit-model
// 2026 P5, A-05/A-05b/A-05c) SYNC on the Create request path:
//
//   - GLOBAL == the cluster scope (resource_type == "cluster"; there is no separate
//     GLOBAL tier in the proto/domain enum — cluster:cluster_kacho_root IS the
//     cluster-wide anchor).
//   - A role with an ARM_ANCHOR (selector=all) rule bound at GLOBAL would require
//     per-object materialization over the WHOLE cluster — forbidden for an ordinary
//     role (A-05). The single exception is THE system cluster-admin role (pinned id,
//     `*.*.*`), whose GLOBAL+all binding is the D-9 cluster-relation, not per-object
//     (A-05c). The `owner` role shares the `*.*.*` shape but is matched out by id
//     (#8), so an owner@GLOBAL+all binding is rejected like any other ordinary role.
//   - GLOBAL + names/labels (no ARM_ANCHOR rule) is finite and legal (A-05b).
//
// Only triggers for the cluster scope: account/project-scoped ARM_ANCHOR bindings
// materialize within a bounded scope and are unaffected. A non-cluster role read
// error is mapped through shared.MapRepoErr (a missing role keeps its existing
// FAILED_PRECONDITION contract via the worker — this gate stays silent on
// not-found, returning it so doCreate's role-read produces the canonical text).
func (u *CreateAccessBindingUseCase) validateGlobalAllSelector(ctx context.Context, b domain.AccessBinding) error {
	if strings.ToLower(string(b.ResourceType)) != "cluster" {
		return nil // GLOBAL gate applies only to the cluster (GLOBAL) scope.
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	role, err := rd.Roles().Get(ctx, b.RoleID)
	if err != nil {
		// A missing/mis-read role is NOT this gate's concern — let doCreate's
		// in-tx role-read raise the canonical FAILED_PRECONDITION ("Role … not
		// found") so the contract is unchanged. Returning nil here lets Create
		// proceed to the worker which surfaces the proper error.
		return nil
	}
	// A rules-role with an ARM_ANCHOR (selector=all) rule, that is NOT the system
	// cluster-admin role, cannot be bound at GLOBAL.
	if role.Rules.HasAnchorRule() && !role.IsClusterAdminRole() {
		return status.Error(codes.InvalidArgument,
			"GLOBAL scope requires names or labels selector for non-cluster-admin roles")
	}
	return nil
}
