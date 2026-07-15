// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// delete.go — DeleteRoleUseCase. System-role → FailedPrecondition
// "system role cannot be deleted". Custom с активными bindings → atomic CAS
// в repo.Delete (ban #10 — within-service инвариант на DB-уровне).

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

type DeleteRoleUseCase struct {
	repo    Repo
	opsRepo operations.Repo
}

func NewDeleteRoleUseCase(r Repo, opsRepo operations.Repo) *DeleteRoleUseCase {
	return &DeleteRoleUseCase{repo: r, opsRepo: opsRepo}
}

func (u *DeleteRoleUseCase) Execute(ctx context.Context, id domain.RoleID) (*operations.Operation, error) {
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if err := shared.ValidateResourceID(string(id), domain.PrefixRole, "role"); err != nil {
		return nil, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	role, err := rd.Roles().Get(ctx, id)
	if err != nil {
		_ = rd.Rollback(ctx)
		return nil, shared.MapRepoErr(err)
	}
	// System roles are not deletable (handled in writer); custom roles —
	// требуют ownership на account.
	if role.AccountID != "" {
		acct, err := rd.Accounts().Get(ctx, role.AccountID)
		_ = rd.Rollback(ctx)
		if err != nil {
			return nil, shared.MapRepoErr(err)
		}
		if err := authzguard.RequireOwnerMatchesPrincipal(ctx, string(acct.OwnerUserID)); err != nil {
			return nil, err
		}
	} else {
		// System role: any user может попытаться удалить — writer вернет
		// FailedPrecondition. Защищаемся anti-anon (уже выше).
		_ = rd.Rollback(ctx)
	}
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Delete role %s", id),
		&iamv1.DeleteRoleMetadata{RoleId: string(id)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	actor := authzguard.PrincipalUserID(ctx)
	accountID := string(role.AccountID)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doDelete(ctx, id, actor, accountID)
	})
	return &op, nil
}

func (u *DeleteRoleUseCase) doDelete(ctx context.Context, id domain.RoleID, actor, accountID string) (*anypb.Any, error) {
	if err := shared.DoWithWriteTxVoid(ctx, u.repo,
		func(ctx context.Context, w Writer) error {
			if derr := w.RolesW().Delete(ctx, id); derr != nil {
				return derr
			}
			return w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventRoleDeleted,
				TenantAccountID: accountID,
				Payload: map[string]any{
					"actor":         actor,
					"resource_type": "role",
					"resource_id":   string(id),
					"account_id":    accountID,
				},
			})
		}); err != nil {
		return nil, err
	}
	return anypb.New(&emptypb.Empty{})
}
