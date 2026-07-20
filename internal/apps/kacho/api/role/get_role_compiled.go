// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// get_role_compiled.go — redesign-2026 F5 (IAM-1-13). GetRoleCompiledUseCase reads
// a Role's COMPILED permission projection (`module.resource.resourceName.verb`) that
// backs FGA emission. This is the INTERNAL half of the two-projection contract: the
// public RoleService.Get/List expose only authored `rules[]` (compiled `permissions`
// is never on the public surface), while InternalIAMService.GetRoleCompiled (:9091)
// serves the compiled set for admin-tooling / authz debugging. A label-only role
// (all rules ARM_LABELS) compiles to an empty set — returned as empty, not an error.

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

type GetRoleCompiledUseCase struct {
	repo Repo
}

func NewGetRoleCompiledUseCase(r Repo) *GetRoleCompiledUseCase {
	return &GetRoleCompiledUseCase{repo: r}
}

// Execute returns the role's compiled permission strings. malformed id → sync
// InvalidArgument (before repo work); well-formed-but-missing → NotFound (verbatim
// "Role <id> not found" via the repo). No pgx/SQL text leaks (shared.MapRepoErr).
func (u *GetRoleCompiledUseCase) Execute(ctx context.Context, id domain.RoleID) ([]string, error) {
	if err := shared.ValidateResourceID(string(id), domain.PrefixRole, "role"); err != nil {
		return nil, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	out, err := rd.Roles().Get(ctx, id)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	perms := make([]string, 0, len(out.Permissions))
	for _, p := range out.Permissions {
		perms = append(perms, string(p))
	}
	return perms, nil
}
