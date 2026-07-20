// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package project

// update.go — UpdateProjectUseCase. account_id — hard-immutable.
// description/name/labels — mutable.

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

type UpdateProjectInput struct {
	ID          domain.ProjectID
	Name        *domain.ProjectName
	Description *domain.Description
	Labels      domain.Labels
	UpdateMask  []string
}

var projectMutableFields = map[string]struct{}{
	"name":        {},
	"description": {},
	"labels":      {},
}

var projectImmutableFields = map[string]string{
	// camelCase contract text (api-conventions.md JSON surface); both mask
	// forms map to the same message. accountId is hard-immutable — there is no
	// Move RPC, so cross-account transfer is absent by construction (F3).
	"account_id": "accountId is immutable after Project.Create",
	"accountId":  "accountId is immutable after Project.Create",
	"id":         "id is immutable after Project.Create",
	"created_at": "createdAt is immutable after Project.Create",
	"createdAt":  "createdAt is immutable after Project.Create",
}

type UpdateProjectUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// Optional OpenFGA client for the defense-in-depth scope-relation
	// authority check. When nil, the guard falls back to owner-only
	// (fail-closed).
	relations clients.RelationStore
	logger    *slog.Logger
}

func NewUpdateProjectUseCase(r Repo, opsRepo operations.Repo) *UpdateProjectUseCase {
	return &UpdateProjectUseCase{repo: r, opsRepo: opsRepo}
}

// WithRelationStore wires the scope-relation authority checker.
func (u *UpdateProjectUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *UpdateProjectUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

func (u *UpdateProjectUseCase) Execute(ctx context.Context, in UpdateProjectInput) (*operations.Operation, error) {
	if err := shared.ValidateResourceID(string(in.ID), domain.PrefixProject, "project"); err != nil {
		return nil, err
	}
	// Anti-anon + ownership check.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if err := shared.ValidateUpdateMask(in.UpdateMask, projectMutableFields, projectImmutableFields); err != nil {
		return nil, err
	}

	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	current, err := rd.Projects().Get(ctx, in.ID)
	if err != nil {
		_ = rd.Rollback(ctx)
		return nil, shared.MapRepoErr(err)
	}
	acct, err := rd.Accounts().Get(ctx, current.AccountID)
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Defense-in-depth scope-relation authority check. Authority = Account
	// owner OR FGA `editor`/`admin` relation on `project:<id>`. Replaces the
	// legacy owner-equality guard, which double-gated a project-editor that
	// the api-gateway FGA Check had already allowed.
	if err := authzguard.RequireScopeRelation(ctx, u.relations,
		"project", string(in.ID), string(acct.OwnerUserID),
		authzguard.MutateRelations...); err != nil {
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
		fmt.Sprintf("Update project %s", in.ID),
		// account_id from the loaded project (current.AccountID is in scope and
		// validated for authz above) → account-scoped module list (D-8).
		&iamv1.UpdateProjectMetadata{ProjectId: string(in.ID), AccountId: string(current.AccountID)},
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

func (u *UpdateProjectUseCase) doUpdate(ctx context.Context, p domain.Project, mask []string, actor string, changed []string) (*anypb.Any, error) {
	updated, err := shared.DoWithWriteTx(ctx, u.repo,
		func(ctx context.Context, w Writer) (domain.Project, error) {
			upd, uerr := w.ProjectsW().Update(ctx, p, mask)
			if uerr != nil {
				return domain.Project{}, uerr
			}
			if len(changed) == 0 {
				return upd, nil
			}
			if aerr := w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventProjectUpdated,
				TenantAccountID: string(upd.AccountID),
				Payload: map[string]any{
					"actor":          actor,
					"resource_type":  "project",
					"resource_id":    string(upd.ID),
					"account_id":     string(upd.AccountID),
					"changed_fields": changed,
				},
			}); aerr != nil {
				return domain.Project{}, aerr
			}
			// T3/Q2: a project LABEL change can flip iam-direct selector membership
			// (a selector matching the project by labels). Co-commit a reconcile
			// trigger in THIS writer-tx (parity with the γ-Q1 mirror-change trigger)
			// so the reconciler re-evaluates affected iam.project selector bindings
			// (≤2s) instead of waiting for the periodic sweep. Only on a labels
			// change — name/description do not affect selector membership.
			if labelsChanged(changed) {
				if rerr := w.EmitReconcileEvent(ctx, "mirror.upsert", "iam.project", string(upd.ID)); rerr != nil {
					return domain.Project{}, rerr
				}
			}
			return upd, nil
		})
	if err != nil {
		return nil, err
	}
	return marshalProject(updated)
}
