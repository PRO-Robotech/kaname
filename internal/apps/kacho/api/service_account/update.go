// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service_account

// update.go — UpdateServiceAccountUseCase. account_id immutable.

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

type UpdateServiceAccountInput struct {
	ID          domain.ServiceAccountID
	Name        *domain.SvcAccountName
	Description *domain.Description
	Labels      domain.Labels
	UpdateMask  []string
}

var saMutableFields = map[string]struct{}{
	"name":        {},
	"description": {},
	"labels":      {},
}

var saImmutableFields = map[string]string{
	"account_id": "account_id is immutable after ServiceAccount.Create",
	"accountId":  "account_id is immutable after ServiceAccount.Create",
	"id":         "id is immutable after ServiceAccount.Create",
	"created_at": "created_at is immutable after ServiceAccount.Create",
	"createdAt":  "created_at is immutable after ServiceAccount.Create",
}

type UpdateServiceAccountUseCase struct {
	repo    Repo
	opsRepo operations.Repo
}

func NewUpdateServiceAccountUseCase(r Repo, opsRepo operations.Repo) *UpdateServiceAccountUseCase {
	return &UpdateServiceAccountUseCase{repo: r, opsRepo: opsRepo}
}

func (u *UpdateServiceAccountUseCase) Execute(ctx context.Context, in UpdateServiceAccountInput) (*operations.Operation, error) {
	if err := shared.ValidateResourceID(string(in.ID), domain.PrefixServiceAccount, "service account"); err != nil {
		return nil, err
	}
	if err := shared.ValidateUpdateMask(in.UpdateMask, saMutableFields, saImmutableFields); err != nil {
		return nil, err
	}

	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	current, err := rd.ServiceAccounts().Get(ctx, in.ID)
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

	target := current
	var changed []string
	if in.Name != nil && shared.MaskAllows(in.UpdateMask, "name") && *in.Name != current.Name {
		target.Name = *in.Name
		changed = append(changed, "name")
	}
	if in.Description != nil && shared.MaskAllows(in.UpdateMask, "description") && *in.Description != current.Description {
		target.Description = *in.Description
		changed = append(changed, "description")
	}
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
		fmt.Sprintf("Update service account %s", in.ID),
		// account_id from the loaded SA (current.AccountID) → account-scoped list (D-8).
		&iamv1.UpdateServiceAccountMetadata{ServiceAccountId: string(in.ID), AccountId: string(current.AccountID)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	maskCopy := append([]string{}, in.UpdateMask...)
	changedCopy := append([]string{}, changed...)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doUpdate(ctx, target, maskCopy, actor, changedCopy)
	})
	return &op, nil
}

func (u *UpdateServiceAccountUseCase) doUpdate(ctx context.Context, sa domain.ServiceAccount, mask []string, actor string, changed []string) (*anypb.Any, error) {
	updated, err := shared.DoWithWriteTx(ctx, u.repo,
		func(ctx context.Context, w Writer) (domain.ServiceAccount, error) {
			upd, uerr := w.ServiceAccountsW().Update(ctx, sa, mask)
			if uerr != nil {
				return domain.ServiceAccount{}, uerr
			}
			if len(changed) == 0 {
				return upd, nil
			}
			if aerr := w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventServiceAccountUpdated,
				TenantAccountID: string(upd.AccountID),
				Payload: map[string]any{
					"actor":          actor,
					"resource_type":  "service_account",
					"resource_id":    string(upd.ID),
					"account_id":     string(upd.AccountID),
					"changed_fields": changed,
				},
			}); aerr != nil {
				return domain.ServiceAccount{}, aerr
			}
			// Изменение labels может изменить membership iam-direct селектора
			// (правило, матчащее SA по меткам). Co-commit reconcile-триггер в ЭТОЙ
			// writer-tx (паритет с project/account Update) — reconciler ре-оценит
			// затронутые iam.serviceAccount selector-биндинги (≤2s) вместо ожидания
			// периодического sweep. Только при изменении labels.
			if labelsChanged(changed) {
				if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.serviceAccount", string(upd.ID)); rerr != nil {
					return domain.ServiceAccount{}, rerr
				}
			}
			return upd, nil
		})
	if err != nil {
		return nil, err
	}
	return marshalSA(updated)
}

// labelsChanged reports whether the changed-fields set includes labels (the only
// field that can flip iam-direct selector membership).
func labelsChanged(changed []string) bool {
	for _, c := range changed {
		if c == "labels" {
			return true
		}
	}
	return false
}
