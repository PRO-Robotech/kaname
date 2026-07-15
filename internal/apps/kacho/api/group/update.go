// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package group

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

type UpdateGroupInput struct {
	ID          domain.GroupID
	Name        *domain.GroupName
	Description *domain.Description
	Labels      domain.Labels
	UpdateMask  []string
}

var groupMutableFields = map[string]struct{}{
	"name":        {},
	"description": {},
	"labels":      {},
}

var groupImmutableFields = map[string]string{
	"account_id": "account_id is immutable after Group.Create",
	"accountId":  "account_id is immutable after Group.Create",
	"id":         "id is immutable after Group.Create",
	"created_at": "created_at is immutable after Group.Create",
	"createdAt":  "created_at is immutable after Group.Create",
}

type UpdateGroupUseCase struct {
	repo    Repo
	opsRepo operations.Repo
}

func NewUpdateGroupUseCase(r Repo, opsRepo operations.Repo) *UpdateGroupUseCase {
	return &UpdateGroupUseCase{repo: r, opsRepo: opsRepo}
}

func (u *UpdateGroupUseCase) Execute(ctx context.Context, in UpdateGroupInput) (*operations.Operation, error) {
	if err := shared.ValidateResourceID(string(in.ID), domain.PrefixGroup, "group"); err != nil {
		return nil, err
	}
	if err := shared.ValidateUpdateMask(in.UpdateMask, groupMutableFields, groupImmutableFields); err != nil {
		return nil, err
	}

	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	current, err := rd.Groups().Get(ctx, in.ID)
	if err != nil {
		_ = rd.Rollback(ctx)
		return nil, shared.MapRepoErr(err)
	}
	// Ownership check на group.account.
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
		fmt.Sprintf("Update group %s", in.ID),
		// account_id from the loaded group (current.AccountID) → account-scoped list (D-8).
		&iamv1.UpdateGroupMetadata{GroupId: string(in.ID), AccountId: string(current.AccountID)},
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

func (u *UpdateGroupUseCase) doUpdate(ctx context.Context, g domain.Group, mask []string, actor string, changed []string) (*anypb.Any, error) {
	updated, err := shared.DoWithWriteTx(ctx, u.repo,
		func(ctx context.Context, w Writer) (domain.Group, error) {
			upd, uerr := w.GroupsW().Update(ctx, g, mask)
			if uerr != nil {
				return domain.Group{}, uerr
			}
			if len(changed) == 0 {
				return upd, nil
			}
			if aerr := w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventGroupUpdated,
				TenantAccountID: string(upd.AccountID),
				Payload: map[string]any{
					"actor":          actor,
					"resource_type":  "group",
					"resource_id":    string(upd.ID),
					"account_id":     string(upd.AccountID),
					"changed_fields": changed,
				},
			}); aerr != nil {
				return domain.Group{}, aerr
			}
			return upd, nil
		})
	if err != nil {
		return nil, err
	}
	return marshalGroup(updated)
}
