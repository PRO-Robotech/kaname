// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// get.go — GetRoleUseCase.
//
// The Role catalog has TWO visibility layers:
//   - SYSTEM roles (is_system) are the tenant-wide reference catalog floor: every
//     authenticated caller may Get them (deterministic seed ids, not tenant-secret).
//     They are NOT subject to the per-object filter — RoleService.Get stays
//     <exempt> in proto so a system-role Get always passes the interceptor.
//   - CUSTOM roles are tenant-secret. Get enforces per-object via the SAME FGA
//     ListObjects(subject,"viewer","iam_role") set that drives RoleService.List
//     (read==enforce, single source of truth — resolveVisibleRoleIDs). The
//     `viewer` tier cascades from the account tier so a role's creator /
//     account-admin resolves their own roles; a custom role the caller has no
//     viewer grant on (incl. a foreign account's role) → NOT_FOUND "Role <id> not
//     found" (NOT PermissionDenied — no existence leak). This makes
//     {role: Get(role) success} == {role: role ∈ List} for custom roles (parity).
//
// Why enforce in the use-case (not the interceptor): the RPC must stay <exempt>
// so system-role Get passes for every caller; the custom-role gate therefore
// lives here, mirroring list.go.
//
// Fail-closed (security.md): a nil FGA port or an FGA error on a CUSTOM
// role Get → Unavailable; the role body (rules[] — a snapshot of another
// account's policy) is NEVER returned on the deny/error path.

import (
	"context"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

type GetRoleUseCase struct {
	repo Repo
	// relationQueries — FGA ListObjects port resolving the caller's readable-role
	// (`viewer` tier) set on iam_role. Required for CUSTOM-role Get; when nil
	// a custom-role Get fails closed (Unavailable). System-role Get never needs it.
	relationQueries clients.RelationQueries
}

func NewGetRoleUseCase(r Repo) *GetRoleUseCase {
	return &GetRoleUseCase{repo: r}
}

// WithRelationStore wires the FGA ListObjects client used to enforce per-object
// visibility of CUSTOM roles (read==enforce with RoleService.List). Mirrors
// ListRolesUseCase.WithRelationStore. Without it, a custom-role Get fails closed.
func (u *GetRoleUseCase) WithRelationStore(relations clients.RelationQueries) *GetRoleUseCase {
	u.relationQueries = relations
	return u
}

func (u *GetRoleUseCase) Execute(ctx context.Context, id domain.RoleID) (domain.Role, error) {
	// malformed id → sync InvalidArgument first (before repo/FGA work).
	if err := shared.ValidateResourceID(string(id), domain.PrefixRole, "role"); err != nil {
		return domain.Role{}, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return domain.Role{}, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	out, err := rd.Roles().Get(ctx, id)
	if err != nil {
		return domain.Role{}, shared.MapRepoErr(err)
	}

	// System roles are the tenant-wide catalog floor — served to every
	// authenticated caller, exempt from the per-object filter.
	if out.IsSystem {
		return out, nil
	}

	// CUSTOM role → per-object enforce via the SAME FGA grant-set as List.
	// id ∉ set → NOT_FOUND (no existence leak); FGA error/nil port → Unavailable
	// (fail-closed). The role body is returned ONLY when the caller is granted.
	principal := operations.PrincipalFromContext(ctx)
	visible, err := resolveVisibleRoleIDs(ctx, u.relationQueries, principal)
	if err != nil {
		return domain.Role{}, err // already a fail-closed Unavailable status
	}
	for _, vid := range visible {
		if vid == string(id) {
			return out, nil
		}
	}
	// Ungranted custom role: same NOT_FOUND text as a non-existent role — the
	// caller cannot distinguish "exists but not yours" from "does not exist".
	return domain.Role{}, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrNotFound, "Role %s not found", id))
}
