// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package user

// update.go — UpdateUserUseCase (новый публичный UpdateUser RPC, T3.3 D-1a).
//
// Единственное mutable поле User через этот Update — `labels` (tenant-facing
// метки, делающие User label-selectable). Identity-поля hard-immutable:
// `external_id` (IdP `sub`) и его camelCase-алиас — их наличие в update_mask →
// sync INVALID_ARGUMENT "external_id is immutable after User.Create" (первым
// стейтментом, до writer-tx). Мутация async → Operation (как все мутации).
//
// Изменение labels co-commit'ит reconcile-event на own-resource label-change в той
// же writer-tx (запрет #10) — reconciler ре-оценивает iam.user selector-биндинги
// (label add → грант появляется; label remove/change → eager fall-out), iam-direct
// аналог mirror-change-триггера.

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// UpdateUserInput — вход UpdateUser. `Labels` — единственное mutable-поле
// (flat-форма request'а несет только его). identity-поля User (external_id и пр.)
// в request не переносятся: их единственный путь — `update_mask`, где они
// reject'атся как hard-immutable.
type UpdateUserInput struct {
	ID         domain.UserID
	Labels     domain.Labels
	UpdateMask []string
}

// userMutableFields — поля, допустимые в update_mask UpdateUser.
var userMutableFields = map[string]struct{}{
	"labels": {},
}

// userImmutableFields — hard-immutable identity-поля: их наличие в update_mask →
// INVALID_ARGUMENT с per-field сообщением (паритет с остальными ресурсами).
var userImmutableFields = map[string]string{
	"external_id": "external_id is immutable after User.Create",
	"externalId":  "external_id is immutable after User.Create",
	"id":          "id is immutable after User.Create",
	"account_id":  "account_id is immutable after User.Create",
	"accountId":   "account_id is immutable after User.Create",
	"email":       "email is immutable after User.Create",
	"created_at":  "created_at is immutable after User.Create",
	"createdAt":   "created_at is immutable after User.Create",
}

type UpdateUserUseCase struct {
	repo    Repo
	opsRepo operations.Repo
}

func NewUpdateUserUseCase(r Repo, opsRepo operations.Repo) *UpdateUserUseCase {
	return &UpdateUserUseCase{repo: r, opsRepo: opsRepo}
}

func (u *UpdateUserUseCase) Execute(ctx context.Context, in UpdateUserInput) (*operations.Operation, error) {
	// malformed id → sync INVALID_ARGUMENT первым стейтментом.
	if err := shared.ValidateResourceID(string(in.ID), domain.PrefixUser, "user"); err != nil {
		return nil, err
	}
	// update_mask discipline: immutable identity-поле → INVALID_ARGUMENT; unknown →
	// INVALID_ARGUMENT; пустой mask = full-PATCH над mutable labels.
	if err := shared.ValidateUpdateMask(in.UpdateMask, userMutableFields, userImmutableFields); err != nil {
		return nil, err
	}

	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	current, err := rd.Users().Get(ctx, in.ID)
	if err != nil {
		_ = rd.Rollback(ctx)
		return nil, shared.MapRepoErr(err)
	}
	acct, err := rd.Accounts().Get(ctx, current.AccountID)
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if err := authzguard.RequireOwnerMatchesPrincipal(ctx, string(acct.OwnerUserID)); err != nil {
		return nil, err
	}

	// Определяем применяемый labels-набор. labels применяются, только если mask их
	// разрешает (или пустой mask = full-PATCH). immutable identity-поля тела не
	// применяются ни при каком mask.
	target := current
	var changed []string
	if newLabels, apply := shared.ResolveLabelsUpdate(in.UpdateMask, in.Labels); apply && !shared.LabelsEqual(newLabels, current.Labels) {
		target.Labels = newLabels
		changed = append(changed, "labels")
	}
	if err := target.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}

	actor := authzguard.PrincipalUserID(ctx)

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Update user %s", in.ID),
		// account_id from the loaded user → account-scoped operation listing.
		&iamv1.UpdateUserMetadata{UserId: string(in.ID), AccountId: string(current.AccountID)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	labelsCopy := target.Labels
	changedCopy := append([]string{}, changed...)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doUpdate(ctx, in.ID, labelsCopy, actor, changedCopy)
	})
	return &op, nil
}

func (u *UpdateUserUseCase) doUpdate(ctx context.Context, id domain.UserID, labels domain.Labels, actor string, changed []string) (*anypb.Any, error) {
	updated, err := shared.DoWithWriteTx(ctx, u.repo,
		func(ctx context.Context, w Writer) (domain.User, error) {
			if len(changed) == 0 {
				// Нечего применять (labels не изменились) — read-back актуального row.
				rd := w.Users()
				return rd.Get(ctx, id)
			}
			upd, uerr := w.UsersW().UpdateLabels(ctx, id, labels)
			if uerr != nil {
				return domain.User{}, uerr
			}
			if aerr := w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventUserUpdated,
				TenantAccountID: string(upd.AccountID),
				Payload: map[string]any{
					"actor":          actor,
					"resource_type":  "user",
					"resource_id":    string(upd.ID),
					"account_id":     string(upd.AccountID),
					"changed_fields": changed,
				},
			}); aerr != nil {
				return domain.User{}, aerr
			}
			// Own-resource label-change co-commit reconcile-триггер в ЭТОЙ writer-tx
			// (запрет #10): reconciler ре-оценит iam.user selector-биндинги (≤2s) —
			// label add → грант появляется, label remove/change → eager fall-out.
			if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.user", string(upd.ID)); rerr != nil {
				return domain.User{}, rerr
			}
			return upd, nil
		})
	if err != nil {
		return nil, err
	}
	return marshalUser(updated)
}
