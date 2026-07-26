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
	// Deleting SOMEONE ELSE is decided by the MODEL: the api-gateway Checks
	// `v_delete@iam_user:<user_id>` before iam is dialed. The former in-service
	// owner-equality check against the owning account's owner_user_id re-decided
	// that from a DB column — denying owner-granted delegates and every machine
	// principal (security.md «Авторизация живёт в МОДЕЛИ, а не в самодельных
	// проверках»).
	//
	// Two decisions deliberately kept, both narrower than the removed guard and
	// both pre-existing: self-delete is always permitted, and an ACCOUNT-LESS
	// user is self-delete-only — it sits in no account, so there is no scope an
	// AccessBinding could be written against and no per-object grant to resolve.
	if !authzguard.IsSelf(ctx, string(target.ID)) && target.AccountID == "" {
		_ = rd.Rollback(ctx)
		return nil, authzguard.PermissionDenied()
	}
	_ = rd.Rollback(ctx)
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
