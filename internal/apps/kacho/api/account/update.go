// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package account

// update.go — UpdateAccountUseCase.
//
// UpdateMask discipline (единая для всех ресурсов):
//   - unknown field           → sync InvalidArgument
//   - hard-immutable
//     `owner_user_id`         → sync InvalidArgument
//                               "owner_user_id is immutable after Account.Create"
//   - mask пустой             → full-PATCH (mutable поля принимаются из body;
//                               immutable из body silent-ignore)
//   - mask содержит mutable   → применяется и валидируется

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// UpdateAccountInput — payload use-case'а. Содержит id + новый body + mask.
type UpdateAccountInput struct {
	ID          domain.AccountID
	Name        *domain.AccountName // nil → не применять (если в mask нет)
	Description *domain.Description
	Labels      domain.Labels // nil → не применять (если в mask нет)
	// OwnerUserID нельзя менять: hard-immutable. Если попало в mask → 400.
	UpdateMask []string
}

// Account-mutable fields exposed via UpdateMask.
var accountMutableFields = map[string]struct{}{
	"name":        {},
	"description": {},
	"labels":      {},
}

// accountImmutableFields — fields, которые если в update_mask → InvalidArgument.
var accountImmutableFields = map[string]string{
	// camelCase contract text (api-conventions.md JSON surface); both mask forms
	// map to the same message. ownerUserId is output-only derived-from-caller (F1)
	// — immutable after Create.
	"owner_user_id": "ownerUserId is immutable after Account.Create",
	"ownerUserId":   "ownerUserId is immutable after Account.Create",
	"id":            "id is immutable after Account.Create",
	"created_at":    "createdAt is immutable after Account.Create",
	"createdAt":     "createdAt is immutable after Account.Create",
}

// UpdateAccountUseCase.
type UpdateAccountUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// Optional OpenFGA client for the defense-in-depth scope-relation
	// authority check. When nil, the guard falls back to owner-only
	// (fail-closed).
	relations clients.RelationStore
	logger    *slog.Logger
}

// NewUpdateAccountUseCase.
func NewUpdateAccountUseCase(r Repo, opsRepo operations.Repo) *UpdateAccountUseCase {
	return &UpdateAccountUseCase{repo: r, opsRepo: opsRepo}
}

// WithRelationStore wires the scope-relation authority checker.
func (u *UpdateAccountUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *UpdateAccountUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

// Execute — sync validate mask + load current + apply diff + create Operation +
// запуск worker'а doUpdate.
func (u *UpdateAccountUseCase) Execute(ctx context.Context, in UpdateAccountInput) (*operations.Operation, error) {
	// Anti-anon + ownership check.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if err := shared.ValidateResourceID(string(in.ID), domain.PrefixAccount, "account"); err != nil {
		return nil, err
	}
	if err := shared.ValidateUpdateMask(in.UpdateMask, accountMutableFields, accountImmutableFields); err != nil {
		return nil, err
	}

	// Загружаем текущий state (для построения diff'а; sync read — допустимо тут,
	// NotFound если row не существует — по контракту error-format Kachō).
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	current, err := rd.Accounts().Get(ctx, in.ID)
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Defense-in-depth scope-relation authority check. Authority = Account
	// owner OR FGA `editor`/`admin` relation on `account:<id>`. Replaces the
	// legacy owner-equality guard, which double-gated an account-editor that
	// the api-gateway FGA Check had already allowed.
	if err := authzguard.RequireScopeRelation(ctx, u.relations,
		"account", string(in.ID), string(current.OwnerUserID),
		authzguard.MutateRelations...); err != nil {
		return nil, err
	}

	// Применяем mask (full-PATCH если mask пустой; иначе только поля из mask).
	// changed — set of mutable fields whose value actually differs from current;
	// drives the audit `changed_fields` payload + emit-per-committed-change
	// (a no-op update that changes nothing emits no audit row).
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

	// Re-validate (domain.Validate на каждой границе).
	if err := target.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}

	// Capture the verified caller sync for the audit actor (anti-spoofing).
	actor := authzguard.PrincipalUserID(ctx)

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Update account %s", in.ID),
		&iamv1.UpdateAccountMetadata{AccountId: string(in.ID)},
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

func (u *UpdateAccountUseCase) doUpdate(ctx context.Context, a domain.Account, mask []string, actor string, changed []string) (*anypb.Any, error) {
	updated, err := shared.DoWithWriteTx(ctx, u.repo,
		func(ctx context.Context, w Writer) (domain.Account, error) {
			upd, uerr := w.AccountsW().Update(ctx, a, mask)
			if uerr != nil {
				return domain.Account{}, uerr
			}
			// Emit-per-committed-change: only emit when a mutable field actually
			// changed (no-op update commits nothing → no audit row, 5.2-41).
			if len(changed) == 0 {
				return upd, nil
			}
			if aerr := w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventAccountUpdated,
				TenantAccountID: string(upd.ID),
				Payload: map[string]any{
					"actor":          actor,
					"resource_type":  "account",
					"resource_id":    string(upd.ID),
					"changed_fields": changed,
				},
			}); aerr != nil {
				return domain.Account{}, aerr
			}
			// T3/Q2: an account LABEL change can flip iam-direct selector membership
			// (an iam.account selector matching by labels). Co-commit a reconcile
			// trigger (parity with the γ-Q1 mirror-change trigger) so the reconciler
			// re-evaluates affected iam.account selector bindings (≤2s). labels-only.
			if accountLabelsChanged(changed) {
				if rerr := w.EmitReconcileEvent(ctx, "mirror.upsert", "iam.account", string(upd.ID)); rerr != nil {
					return domain.Account{}, rerr
				}
			}
			return upd, nil
		})
	if err != nil {
		return nil, err
	}
	return marshalAccount(updated)
}

// accountLabelsChanged reports whether "labels" is among the changed fields of
// an Account.Update — the only change that flips iam-direct selector membership
// (T3/Q2).
func accountLabelsChanged(changed []string) bool {
	for _, f := range changed {
		if f == "labels" {
			return true
		}
	}
	return false
}
