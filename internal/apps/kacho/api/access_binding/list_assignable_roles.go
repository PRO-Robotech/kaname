// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// list_assignable_roles.go — ListAssignableRolesUseCase
// (RPC AccessBindingService.ListAssignableRoles).
//
// Sync read returning the roles VALID for binding on a (resource_type,
// resource_id), each annotated with a server-computed scope_group. The
// validity predicate is the single source of truth domain.IsRoleAssignable
// — encoded in the repo WHERE filter (Reader.ListAssignable) so the
// assignable-set returned here is exactly the set AccessBinding.Create accepts.
//
// Order of sync steps (api-conventions / D-5 / D-6 / D-7), mirroring
// ListByScope + ListSubjectPrivileges:
//  1. resource_type whitelist (account|project|cluster) → InvalidArgument.
//  2. resource_id format ↔ type validation → InvalidArgument (FIRST repo-less
//     statement; cluster singleton guard).
//  3. anti-anonymous guard → Unauthenticated/PermissionDenied (catalog floor;
//     the precise grant-authority policy is authoritative in-handler).
//  4. resource existence resolve + authz via requireGrantAuthority — owner of
//     the owning Account/Project OR FGA admin on the scope object; a
//     well-formed-but-missing account/project surfaces NotFound (D-7).
//  5. repo read filtered by IsRoleAssignable, keyset (created_at,id) paginated.
//  6. map each domain.Role → domain.AssignableRole with ScopeGroupOf.

import (
	"log/slog"

	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	reporole "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
)

type ListAssignableRolesUseCase struct {
	repo      Repo
	relations clients.RelationStore
	logger    *slog.Logger
}

func NewListAssignableRolesUseCase(r Repo) *ListAssignableRolesUseCase {
	return &ListAssignableRolesUseCase{repo: r}
}

// WithRelationStore wires the FGA client so the delegated-admin grant-authority
// path (and the cluster-scope authority, which has no DB owner) resolves. When
// unset (nil) the use-case falls back to owner-only authority and denies the
// FGA path — same contract as ListByScope.
func (u *ListAssignableRolesUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *ListAssignableRolesUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

func (u *ListAssignableRolesUseCase) Execute(ctx context.Context, resourceType, resourceID string, f reporole.ListFilter) ([]domain.AssignableRole, string, error) {
	// 1+2. resource_type whitelist + resource_id↔type format — FIRST statements
	// (D-6), before any repo touch.
	if err := validateAssignableResource(resourceType, resourceID); err != nil {
		return nil, "", err
	}

	// 3. Anti-anonymous (catalog is the cluster-floor; this handler is the
	// authoritative policy — same pattern as ListByScope / Create).
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, "", err
	}

	// 4. Existence resolve + grant-authority. requireGrantAuthority reads the
	// owning Account/Project (a well-formed-but-missing one → NotFound via
	// repo.Get) and checks owner OR FGA admin on the scope object — the SAME
	// gate as Create on this resource (D-5: who may grant == who may see the
	// assignable palette).
	if err := requireGrantAuthority(ctx, u.repo, u.relations, resourceType, resourceID); err != nil {
		return nil, "", err
	}

	// 5. Filtered, keyset-paginated repo read (predicate in SQL — D-2).
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	roles, next, err := rd.Roles().ListAssignable(ctx, resourceType, resourceID, f)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}

	// 6. Project → AssignableRole with server-computed scope_group (D-4).
	out := make([]domain.AssignableRole, 0, len(roles))
	for _, r := range roles {
		out = append(out, domain.AssignableRole{
			RoleID:      r.ID,
			Name:        r.Name,
			Description: r.Description,
			IsSystem:    r.IsSystem,
			ScopeGroup:  domain.ScopeGroupOf(r),
			CreatedAt:   r.CreatedAt,
		})
	}
	return out, next, nil
}

// validateAssignableResource enforces D-6: resource_type ∈ {account, project,
// cluster} and resource_id matches the type (account⇒acc-, project⇒prj-,
// cluster⇒exactly cluster_kacho_root). All errors are sync InvalidArgument.
func validateAssignableResource(resourceType, resourceID string) error {
	switch resourceType {
	case "account":
		return shared.ValidateResourceID(resourceID, domain.PrefixAccount, "account")
	case "project":
		return shared.ValidateResourceID(resourceID, domain.PrefixProject, "project")
	case "cluster":
		if resourceID != domain.ClusterSingletonID {
			return status.Errorf(codes.InvalidArgument,
				"Illegal argument resource_id (expected %s)", domain.ClusterSingletonID)
		}
		return nil
	default:
		return status.Error(codes.InvalidArgument,
			"Illegal argument resource_type (allowed: account|project|cluster)")
	}
}
