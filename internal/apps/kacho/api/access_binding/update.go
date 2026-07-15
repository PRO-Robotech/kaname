// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// update.go — UpdateAccessBindingUseCase.
//
// AccessBinding is otherwise immutable (Delete+Create). The mutable set is
// {deletion_protection, labels} (T3.3-IMM-01): an owner / admin clears
// deletion_protection (`update_mask=["deletion_protection"]`) so a protected binding
// can subsequently be deleted (C-02 → C-03 flow), AND sets own-resource `labels`
// (tenant-facing метки делают binding label-selectable, D-6). Any OTHER mask path
// (role_id / subject / scope / resource_*) → sync INVALID_ARGUMENT (immutable set NOT
// weakened). Async (Operation), like the other mutations. update_mask discipline
// (api-conventions.md):
//   - mask with an UNKNOWN / immutable field → sync INVALID_ARGUMENT.
//   - empty mask → full-object PATCH over the mutable fields from the body.
//   - mask with `deletion_protection` / `labels` → applied.

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// fieldDeletionProtection / fieldLabels — the mutable AccessBinding fields (T3.3-IMM-01).
const (
	fieldDeletionProtection = "deletion_protection"
	fieldLabels             = "labels"
)

// abMutableFields — allowed update_mask fields for AccessBinding (T3.3-IMM-01).
var abMutableFields = map[string]struct{}{
	fieldDeletionProtection: {},
	fieldLabels:             {},
}

// abImmutableFields — per-field immutability messages for the historically-immutable
// AccessBinding identity/grant fields (role_id, subjects, scope, resource_*).
var abImmutableFields = map[string]string{
	"role_id":       "role_id is immutable after AccessBinding.Create",
	"roleId":        "role_id is immutable after AccessBinding.Create",
	"subject_type":  "subject_type is immutable after AccessBinding.Create",
	"subjectType":   "subject_type is immutable after AccessBinding.Create",
	"subject_id":    "subject_id is immutable after AccessBinding.Create",
	"subjectId":     "subject_id is immutable after AccessBinding.Create",
	"subjects":      "subjects is immutable after AccessBinding.Create",
	"resource_type": "resource_type is immutable after AccessBinding.Create",
	"resourceType":  "resource_type is immutable after AccessBinding.Create",
	"resource_id":   "resource_id is immutable after AccessBinding.Create",
	"resourceId":    "resource_id is immutable after AccessBinding.Create",
	"scope_ref":     "scope is immutable after AccessBinding.Create",
	"scopeRef":      "scope is immutable after AccessBinding.Create",
	"id":            "id is immutable after AccessBinding.Create",
}

type UpdateAccessBindingUseCase struct {
	repo      Repo
	opsRepo   operations.Repo
	relations clients.RelationStore
	logger    *slog.Logger
}

func NewUpdateAccessBindingUseCase(r Repo, opsRepo operations.Repo) *UpdateAccessBindingUseCase {
	return &UpdateAccessBindingUseCase{repo: r, opsRepo: opsRepo}
}

// WithRelationStore wires the OpenFGA RelationStore used by requireGrantAuthority
// (delegated-admin authority path), mirroring Create/Delete.
func (u *UpdateAccessBindingUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *UpdateAccessBindingUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

// Execute — sync validate (id + update_mask discipline + grant-authority) →
// Operation → worker (deletion_protection + labels в одной writer-tx).
// AB mutable set = {deletion_protection, labels} (T3.3-IMM-01).
func (u *UpdateAccessBindingUseCase) Execute(ctx context.Context, id domain.AccessBindingID, mask []string, deletionProtection bool, labels domain.Labels) (*operations.Operation, error) {
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if err := shared.ValidateResourceID(string(id), domain.PrefixAccessBinding, "access binding"); err != nil {
		return nil, err
	}
	// update_mask discipline (T3.3-IMM-01): {deletion_protection, labels} mutable;
	// any immutable identity/grant field → per-field INVALID_ARGUMENT; unknown →
	// INVALID_ARGUMENT. Empty mask → full-object PATCH over the mutable fields.
	if err := shared.ValidateUpdateMask(mask, abMutableFields, abImmutableFields); err != nil {
		return nil, err
	}

	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	binding, err := rd.AccessBindings().Get(ctx, id)
	_ = rd.Rollback(ctx)
	if err != nil {
		if stderrors.Is(err, iamerr.ErrNotFound) {
			// Existence-leak parity with Delete: a non-existent binding → PermissionDenied.
			return nil, authzguard.PermissionDenied()
		}
		// Any OTHER Get failure (transient DB fault: statement-timeout, conn
		// reset, ...) is NOT existence-hiding — it must map to its real,
		// retriable/terminal gRPC code (shared.MapRepoErr), not the
		// non-retriable PermissionDenied a client would never retry.
		return nil, shared.MapRepoErr(err)
	}
	// Same grant-authority gate as Create/Delete (owner-of-account OR FGA admin on
	// the scope): only a grant authority may mutate the binding.
	if err := requireGrantAuthority(ctx, u.repo, u.relations,
		string(binding.ResourceType), binding.ResourceID); err != nil {
		return nil, err
	}

	// Resolve the applied mutable set against the mask (empty mask = full-PATCH).
	applyDP := shared.MaskAllows(mask, fieldDeletionProtection)
	// proto3-map не несет presence: пустой `labels:{}` и отсутствующий labels
	// неотличимы (оба nil), поэтому очистку выражает только "labels" в update_mask.
	newLabels, applyLabels := shared.ResolveLabelsUpdate(mask, labels)
	labelsChanged := applyLabels && !shared.LabelsEqual(newLabels, binding.Labels)

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Update access binding %s", id),
		&iamv1.UpdateAccessBindingMetadata{AccessBindingId: string(id), AccountId: auditTenantAccountID(binding)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	labelsCopy := newLabels
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doUpdate(ctx, id, applyDP, deletionProtection, labelsChanged, labelsCopy)
	})
	return &op, nil
}

func (u *UpdateAccessBindingUseCase) doUpdate(ctx context.Context, id domain.AccessBindingID, applyDP, deletionProtection, labelsChanged bool, labels domain.Labels) (*anypb.Any, error) {
	updated, err := shared.DoWithWriteTx(ctx, u.repo,
		func(ctx context.Context, w Writer) (domain.AccessBinding, error) {
			out, derr := w.AccessBindings().Get(ctx, id)
			if derr != nil {
				return domain.AccessBinding{}, derr
			}
			if applyDP {
				out, derr = w.AccessBindingsW().SetDeletionProtection(ctx, id, deletionProtection)
				if derr != nil {
					return domain.AccessBinding{}, derr
				}
			}
			if labelsChanged {
				out, derr = w.AccessBindingsW().UpdateLabels(ctx, id, labels)
				if derr != nil {
					return domain.AccessBinding{}, derr
				}
				// T3.3 / D-6: own-resource label change may flip iam-direct selector
				// membership (a rule selecting iam.accessBinding by label). Co-commit a
				// reconcile-event in THIS writer-tx (ban #10, parity with user/SA/role
				// Update) so the reconciler re-evaluates the affected iam.accessBinding
				// selector bindings (≤2s): label add → grant appears, label remove/change
				// → eager fall-out. Only on a labels change.
				if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.accessBinding", string(id)); rerr != nil {
					return domain.AccessBinding{}, rerr
				}
			}
			return out, nil
		})
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	return marshalAB(updated)
}
