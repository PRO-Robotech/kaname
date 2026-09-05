// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
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
// AccessBinding identity/grant fields (role_id, subjects, scope-anchor). The
// scope-anchor is the dotted scopeType/scopeId (redesign-2026 F7); the legacy
// resource_type/resource_id/scope_ref names are kept mapped defensively so a stale
// client still gets the immutable-switch text rather than a generic "unknown field".
var abImmutableFields = map[string]string{
	"role_id":       "roleId is immutable after AccessBinding.Create",
	"roleId":        "roleId is immutable after AccessBinding.Create",
	"subject_type":  "subjectType is immutable after AccessBinding.Create",
	"subjectType":   "subjectType is immutable after AccessBinding.Create",
	"subject_id":    "subjectId is immutable after AccessBinding.Create",
	"subjectId":     "subjectId is immutable after AccessBinding.Create",
	"subjects":      "subjects is immutable after AccessBinding.Create",
	"scope_type":    "scopeType is immutable after AccessBinding.Create",
	"scopeType":     "scopeType is immutable after AccessBinding.Create",
	"scope_id":      "scopeId is immutable after AccessBinding.Create",
	"scopeId":       "scopeId is immutable after AccessBinding.Create",
	"resource_type": "scopeType is immutable after AccessBinding.Create",
	"resourceType":  "scopeType is immutable after AccessBinding.Create",
	"resource_id":   "scopeId is immutable after AccessBinding.Create",
	"resourceId":    "scopeId is immutable after AccessBinding.Create",
	"scope_ref":     "scopeType is immutable after AccessBinding.Create",
	"scopeRef":      "scopeType is immutable after AccessBinding.Create",
	"id":            "id is immutable after AccessBinding.Create",
}

// ObjectForwardReconciler — narrow post-commit port: re-materialize the per-object
// access of ONE iam-native object across the bindings whose selectors match it.
//
// Deliberately NOT the package's SelectorReconciler (create.go): that port carries the
// binding-membership passes and the nothing-stale object entry point, none of which this
// path may use — a label-clear on an EXISTING binding must go through the guard-bearing
// forward (see doUpdate). It declares only the one method this path calls; the FULL
// ReconcileObject is driven by the reconcile worker off the co-committed event, never
// through here. Implemented by reconcile.Reconciler (the SAME single materialization
// path the reconcile worker and the cross-service RegisterResource drive). nil-safe:
// when unwired, the co-committed reconcile event + the periodic sweep remain the
// at-least-once backstop.
type ObjectForwardReconciler interface {
	// ReconcileObjectForward is the ADDITIVE forward fast-path for one object: it
	// materializes ONLY that object's per-object tuples across the matching bindings
	// while holding NO advisory lock at all (neither EXCLUSIVE nor SHARE, no O(scope)
	// recompute). It transparently
	// delegates to the FULL ReconcileObject when the object already has members
	// (delete-stale guard) — which is the branch a REVOCATION takes.
	ReconcileObjectForward(ctx context.Context, objectType, objectID string) error
}

type UpdateAccessBindingUseCase struct {
	repo      Repo
	opsRepo   operations.Repo
	relations clients.RelationStore
	// Optional post-commit per-object materializer. A LABEL change flips iam-direct
	// selector membership, so the object must be re-materialized; nil-safe, the
	// co-committed reconcile event + periodic sweep remain the backstop.
	reconciler ObjectForwardReconciler
	logger     *slog.Logger
}

func NewUpdateAccessBindingUseCase(r Repo, opsRepo operations.Repo) *UpdateAccessBindingUseCase {
	return &UpdateAccessBindingUseCase{repo: r, opsRepo: opsRepo}
}

// WithObjectReconciler wires the post-commit per-object materializer used on a LABEL
// change (parity with the cross-service RegisterResource re-register path — see
// doUpdate). Optional; nil keeps the queue-only behaviour. It takes no logger on
// purpose: WithRelationStore already supplies one, and a second setter carrying it
// would silently nil it whenever the two are wired in the other order.
func (u *UpdateAccessBindingUseCase) WithObjectReconciler(r ObjectForwardReconciler) *UpdateAccessBindingUseCase {
	u.reconciler = r
	return u
}

// WithRelationStore wires the door to the rights decision used by requireGrantAuthority
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

// doUpdate applies the mutation in one writer-tx and, when the change can flip
// iam-direct selector membership (a LABEL change), re-materializes the object.
//
// WHY THE IN-PROCESS PASS. iam.accessBinding is label-selectable (feed_registry.go), and
// the iam-direct matcher probes `kacho_iam.access_bindings.labels` — so a binding is
// itself an OBJECT another binding's ARM_LABELS selector may match, and clearing a
// matching label is a REVOCATION of that other grant. Its cross-service twin gets that
// for free: vpc/compute/nlb re-call InternalIAMService.RegisterResource on a label
// update, and RegisterResource runs ReconcileObjectForward in-process — the forward's
// delete-stale guard sees the object already has members, hands it to the FULL
// ReconcileObject, and the stale grant dies there. The iam-native path had no such pass:
// it enqueued a resource_reconcile_outbox event and returned, which made revoke latency
// the DEPTH OF THE GLOBAL RECONCILE QUEUE. That queue is strictly FIFO and drained by a
// single worker at ~5 events/s, each event a FULL O(scope) recompute, while the e2e
// suite produces 5-8 events/s — so it runs a multi-minute backlog. Measured on the stand
// for the sibling iam.project path: the label-clear event was enqueued at 19:59:18.97 and
// drained at 20:06:49.82 (7m30s); the tuple survived until the 30s periodic sweep reached
// that binding at 20:00:23, 65s after the clear, long past any client budget.
//
// NOT the create-path's entry point. create.go deliberately uses ReconcileObjectForwardNoStale,
// which SKIPS the delete-stale guard because the id was minted in the tx that just
// committed — precisely the branch that cannot revoke. An existing binding must take the
// guard-bearing ReconcileObjectForward.
//
// OFF THE done-PATH (ban #9). The pass is scheduled detached: Operation.done reports that
// the binding row is durable, never that its tuples converged. The co-committed reconcile
// event above and the periodic sweep stay the at-least-once backstop, so this changes WHEN
// the revoke is observed, not WHETHER it happens.
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
	// Label change ⇒ selector membership may have flipped ⇒ re-materialize this ONE
	// object now instead of waiting out the FIFO reconcile queue (see the doc above).
	// ReconcileObjectForward is the same entry point the cross-service register path
	// uses: its delete-stale guard finds the existing members and delegates to the FULL
	// ReconcileObject, which is what actually revokes a now-unmatched grant.
	if labelsChanged && u.reconciler != nil {
		oid := string(id)
		shared.GoPostCommit(ctx, u.logger, "access binding label re-materialization", func(ctx context.Context) {
			if rerr := u.reconciler.ReconcileObjectForward(ctx, "iam.accessBinding", oid); rerr != nil && u.logger != nil {
				u.logger.Error("access binding update: label re-materialization failed (reconcile event + sweep will retry)",
					"access_binding_id", oid, "err", rerr)
			}
		})
	}
	return marshalAB(updated)
}
