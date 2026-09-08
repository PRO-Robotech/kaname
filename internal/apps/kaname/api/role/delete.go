// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
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
	// System roles are not deletable — the writer returns FailedPrecondition
	// (resource STATE, not authz). WHO may delete a custom role is decided by
	// the MODEL: the api-gateway Checks `v_delete@iam_role:<role_id>` before iam
	// is dialed. The former in-service owner-equality check against the owning
	// account's owner_user_id re-decided that more coarsely and could never be
	// satisfied by a machine principal — security.md «Авторизация живёт в
	// МОДЕЛИ, а не в самодельных проверках».
	_ = rd.Rollback(ctx)
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
			// Симметрия созданию (kacho#2055): создание со-коммитит событие
			// реконсайла, которым материализуется пообъектный кортеж владельца,
			// — снятие обязано со-коммитить ОТЗЫВ в ту же writer-tx. Каскад
			// `ON DELETE` его не заменяет: он ключуется по идентификатору
			// ПРИВЯЗКИ, а не снятого объекта, поэтому кортеж на снятой роли
			// доживал до ближайшего периодического прохода. Воркер на событие
			// зовёт `ReconcileObject`, а тот на отсутствующем объекте получает
			// пустой желаемый набор — что и есть отзыв.
			if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventDelete, "iam.role", string(id)); rerr != nil {
				return rerr
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
