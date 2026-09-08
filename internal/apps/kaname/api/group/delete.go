// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package group

// delete.go — DeleteGroupUseCase.
// group_members → CASCADE на group_id. AccessBinding subject_id — soft-ref,
// ловится атомарным DELETE WHERE NOT EXISTS в group_repo.Delete (within-service
// инвариант на DB-уровне, не software check-then-act).

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

type DeleteGroupUseCase struct {
	repo    Repo
	opsRepo operations.Repo
}

func NewDeleteGroupUseCase(r Repo, opsRepo operations.Repo) *DeleteGroupUseCase {
	return &DeleteGroupUseCase{repo: r, opsRepo: opsRepo}
}

func (u *DeleteGroupUseCase) Execute(ctx context.Context, id domain.GroupID) (*operations.Operation, error) {
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if err := shared.ValidateResourceID(string(id), domain.PrefixGroup, "group"); err != nil {
		return nil, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// WHO may delete this group is decided by the MODEL: the api-gateway Checks
	// `v_delete@iam_group:<id>` before iam is dialed (security.md «Авторизация
	// живёт в МОДЕЛИ»). The read below is existence/metadata only, not authz.
	g, err := rd.Groups().Get(ctx, id)
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Delete group %s", id),
		// account_id from the loaded group (g.AccountID) → account-scoped list.
		&iamv1.DeleteGroupMetadata{GroupId: string(id), AccountId: string(g.AccountID)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	actor := authzguard.PrincipalUserID(ctx)
	accountID := string(g.AccountID)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doDelete(ctx, id, actor, accountID)
	})
	return &op, nil
}

func (u *DeleteGroupUseCase) doDelete(ctx context.Context, id domain.GroupID, actor, accountID string) (*anypb.Any, error) {
	if err := shared.DoWithWriteTxVoid(ctx, u.repo,
		func(ctx context.Context, w Writer) error {
			if derr := w.GroupsW().Delete(ctx, id); derr != nil {
				return derr
			}
			// Симметрия созданию (kacho#2055): создание со-коммитит событие
			// реконсайла, которым материализуется пообъектный кортеж владельца,
			// — снятие обязано со-коммитить ОТЗЫВ в ту же writer-tx. Каскад
			// `ON DELETE` его не заменяет: он ключуется по идентификатору
			// ПРИВЯЗКИ, а не снятого объекта. Воркер на событие зовёт
			// `ReconcileObject`, а тот на отсутствующем объекте получает пустой
			// желаемый набор — что и есть отзыв.
			if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventDelete, "iam.group", string(id)); rerr != nil {
				return rerr
			}
			return w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventGroupDeleted,
				TenantAccountID: accountID,
				Payload: map[string]any{
					"actor":         actor,
					"resource_type": "group",
					"resource_id":   string(id),
					"account_id":    accountID,
				},
			})
		}); err != nil {
		return nil, err
	}
	return anypb.New(&emptypb.Empty{})
}
