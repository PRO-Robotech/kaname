// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package project

// delete.go — DeleteProjectUseCase. Future: peer-callback'и для проверки
// «нет ресурсов в Project'е» (vpc/compute/loadbalancer ссылаются на project_id);
// пока — просто DELETE FROM projects.

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

type DeleteProjectUseCase struct {
	repo    Repo
	opsRepo operations.Repo
}

func NewDeleteProjectUseCase(r Repo, opsRepo operations.Repo) *DeleteProjectUseCase {
	return &DeleteProjectUseCase{repo: r, opsRepo: opsRepo}
}

func (u *DeleteProjectUseCase) Execute(ctx context.Context, id domain.ProjectID) (*operations.Operation, error) {
	// Anti-anon + ownership check.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if err := shared.ValidateResourceID(string(id), domain.PrefixProject, "project"); err != nil {
		return nil, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	proj, err := rd.Projects().Get(ctx, id)
	if err != nil {
		_ = rd.Rollback(ctx)
		return nil, shared.MapRepoErr(err)
	}
	acct, err := rd.Accounts().Get(ctx, proj.AccountID)
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	if err := authzguard.RequireOwnerMatchesPrincipal(ctx, string(acct.OwnerUserID)); err != nil {
		return nil, err
	}

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Delete project %s", id),
		// account_id from the loaded project (proj.AccountID in scope) → the
		// account-scoped module list surfaces this Delete op (D-8).
		&iamv1.DeleteProjectMetadata{ProjectId: string(id), AccountId: string(proj.AccountID)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}

	actor := authzguard.PrincipalUserID(ctx)
	accountID := string(proj.AccountID)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doDelete(ctx, id, actor, accountID)
	})
	return &op, nil
}

func (u *DeleteProjectUseCase) doDelete(ctx context.Context, id domain.ProjectID, actor, accountID string) (*anypb.Any, error) {
	if err := shared.DoWithWriteTxVoid(ctx, u.repo,
		func(ctx context.Context, w Writer) error {
			if derr := w.ProjectsW().Delete(ctx, id); derr != nil {
				return derr
			}
			return w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventProjectDeleted,
				TenantAccountID: accountID,
				Payload: map[string]any{
					"actor":         actor,
					"resource_type": "project",
					"resource_id":   string(id),
					"account_id":    accountID,
				},
			})
		}); err != nil {
		return nil, err
	}
	return anypb.New(&emptypb.Empty{})
}
