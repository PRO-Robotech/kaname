// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service_account

// delete.go — DeleteServiceAccountUseCase.
// AccessBinding и GroupMember refs — soft-ref на subject_id, проверяются
// атомарно в repo через DELETE WHERE NOT EXISTS (запрет #10).

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

type DeleteServiceAccountUseCase struct {
	repo    Repo
	opsRepo operations.Repo
}

func NewDeleteServiceAccountUseCase(r Repo, opsRepo operations.Repo) *DeleteServiceAccountUseCase {
	return &DeleteServiceAccountUseCase{repo: r, opsRepo: opsRepo}
}

func (u *DeleteServiceAccountUseCase) Execute(ctx context.Context, id domain.ServiceAccountID) (*operations.Operation, error) {
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if err := shared.ValidateResourceID(string(id), domain.PrefixServiceAccount, "service account"); err != nil {
		return nil, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// WHO may delete this service account is decided by the MODEL: the
	// api-gateway Checks `v_delete@iam_service_account:<service_account_id>`
	// before iam is dialed (security.md «Авторизация живёт в МОДЕЛИ, а не в
	// самодельных проверках»). The read below is existence/metadata only.
	sa, err := rd.ServiceAccounts().Get(ctx, id)
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Delete service account %s", id),
		// account_id from the loaded SA (sa.AccountID) → account-scoped list.
		&iamv1.DeleteServiceAccountMetadata{ServiceAccountId: string(id), AccountId: string(sa.AccountID)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	actor := authzguard.PrincipalUserID(ctx)
	accountID := string(sa.AccountID)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doDelete(ctx, id, actor, accountID)
	})
	return &op, nil
}

func (u *DeleteServiceAccountUseCase) doDelete(ctx context.Context, id domain.ServiceAccountID, actor, accountID string) (*anypb.Any, error) {
	if err := shared.DoWithWriteTxVoid(ctx, u.repo,
		func(ctx context.Context, w Writer) error {
			if derr := w.ServiceAccountsW().Delete(ctx, id); derr != nil {
				return derr
			}
			// Симметрия созданию (kacho#2055): создание со-коммитит событие
			// реконсайла, которым материализуется пообъектный кортеж владельца,
			// — снятие обязано со-коммитить ОТЗЫВ в ту же writer-tx. Каскад
			// `ON DELETE` его не заменяет: он ключуется по идентификатору
			// ПРИВЯЗКИ, а не снятого объекта. Воркер на событие зовёт
			// `ReconcileObject`, а тот на отсутствующем объекте получает пустой
			// желаемый набор — что и есть отзыв.
			if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventDelete, "iam.serviceAccount", string(id)); rerr != nil {
				return rerr
			}
			return w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventServiceAccountDeleted,
				TenantAccountID: accountID,
				Payload: map[string]any{
					"actor":         actor,
					"resource_type": "service_account",
					"resource_id":   string(id),
					"account_id":    accountID,
				},
			})
		}); err != nil {
		return nil, err
	}
	return anypb.New(&emptypb.Empty{})
}
