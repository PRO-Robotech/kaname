// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package user

// delete.go — DeleteUserUseCase.
//
// FK SQLSTATE 23503 на accounts_owner_fk → FailedPrecondition
// "User <id> owns accounts and cannot be deleted" (через mapErr/errors/fkText).
// GroupMember + AccessBinding — soft-ref (нет FK), но atomic DELETE WHERE NOT EXISTS
// в user_repo.Delete ловит их (within-service refs защищены на DB-уровне).

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

type DeleteUserUseCase struct {
	repo    Repo
	opsRepo operations.Repo
}

func NewDeleteUserUseCase(r Repo, opsRepo operations.Repo) *DeleteUserUseCase {
	return &DeleteUserUseCase{repo: r, opsRepo: opsRepo}
}

func (uc *DeleteUserUseCase) Execute(ctx context.Context, id domain.UserID) (*operations.Operation, error) {
	// Sync 1: format validation (cheap, no DB / no leak).
	if err := shared.ValidateResourceID(string(id), domain.PrefixUser, "user"); err != nil {
		return nil, err
	}
	// Anti-anon + self-delete-only OR account-owner-delete.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	// Load user → determine if same as principal OR principal owns user's account.
	rd, err := uc.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	target, err := rd.Users().Get(ctx, id)
	if err != nil {
		_ = rd.Rollback(ctx)
		return nil, shared.MapRepoErr(err)
	}
	// Self-delete всегда разрешен.
	if !authzguard.IsSelf(ctx, string(target.ID)) {
		// Иначе: owner аккаунта может удалить user в своем аккаунте.
		if target.AccountID == "" {
			_ = rd.Rollback(ctx)
			return nil, authzguard.PermissionDenied()
		}
		acct, err := rd.Accounts().Get(ctx, target.AccountID)
		if err != nil {
			_ = rd.Rollback(ctx)
			return nil, shared.MapRepoErr(err)
		}
		_ = rd.Rollback(ctx)
		if err := authzguard.RequireOwnerMatchesPrincipal(ctx, string(acct.OwnerUserID)); err != nil {
			return nil, err
		}
	} else {
		_ = rd.Rollback(ctx)
	}
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Delete user %s", id),
		// account_id from the loaded target (target.AccountID; "" for account-less
		// users → corelib writes SQL NULL → excluded from account-scoped list, D-8).
		&iamv1.DeleteUserMetadata{UserId: string(id), AccountId: string(target.AccountID)},
	)
	if err != nil {
		return nil, err
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	actor := authzguard.PrincipalUserID(ctx)
	accountID := string(target.AccountID)
	operations.Run(ctx, uc.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return uc.doDelete(ctx, id, actor, accountID)
	})
	return &op, nil
}

func (uc *DeleteUserUseCase) doDelete(ctx context.Context, id domain.UserID, actor, accountID string) (*anypb.Any, error) {
	if err := shared.DoWithWriteTxVoid(ctx, uc.repo,
		func(ctx context.Context, w Writer) error {
			if derr := w.UsersW().Delete(ctx, id); derr != nil {
				return derr
			}
			ev := service.AuditEvent{
				EventType: auditEventUserDeleted,
				Payload: map[string]any{
					"actor":         actor,
					"resource_type": "user",
					"resource_id":   string(id),
				},
			}
			if accountID != "" {
				ev.TenantAccountID = accountID
				ev.Payload["account_id"] = accountID
			}
			return w.EmitAuditEvent(ctx, ev)
		}); err != nil {
		return nil, err
	}
	return anypb.New(&emptypb.Empty{})
}
