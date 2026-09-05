// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package account

// update.go — UpdateAccountUseCase.
//
// UpdateMask discipline (единая для всех ресурсов):
//   - unknown field           → sync InvalidArgument
//   - hard-immutable
//     `owner_user_id`         → sync InvalidArgument
//                               "ownerUserId is immutable after Account.Create"
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

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
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

// ObjectReconciler — narrow post-commit port: re-materialize the per-object access of
// ONE iam-native object across the bindings whose selectors match it. Implemented by
// reconcile.Reconciler (the SAME single materialization path the reconcile worker and
// the cross-service RegisterResource drive). nil-safe: when unwired, the co-committed
// reconcile event + the periodic sweep remain the at-least-once backstop.
type ObjectReconciler interface {
	// ReconcileObjectForward is the ADDITIVE forward fast-path for one object: it
	// materializes ONLY that object's per-object tuples across the matching bindings
	// while holding NO advisory lock at all (neither EXCLUSIVE nor SHARE, no O(scope)
	// recompute). It transparently
	// delegates to the FULL ReconcileObject when the object already has members
	// (delete-stale guard) — which is the branch a REVOCATION takes.
	ReconcileObjectForward(ctx context.Context, objectType, objectID string) error
	// ReconcileObject is the FULL EXCLUSIVE object-fan-out (async at-least-once backstop
	// — delete-stale / audit / sweep), driven by the reconcile worker off the
	// co-committed reconcile-outbox event.
	ReconcileObject(ctx context.Context, objectType, objectID string) error
}

// UpdateAccountUseCase.
type UpdateAccountUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// Optional door to the rights decision, used by the defense-in-depth
	// scope-relation authority check. When nil, the guard falls back to owner-only
	// (fail-closed).
	relations clients.RelationStore
	// Optional post-commit per-object materializer (same port the create-path uses).
	// A LABEL change flips iam-direct selector membership, so the object must be
	// re-materialized; nil-safe, the co-committed reconcile event + periodic sweep
	// remain the backstop.
	reconciler ObjectReconciler
	logger     *slog.Logger
}

// NewUpdateAccountUseCase.
func NewUpdateAccountUseCase(r Repo, opsRepo operations.Repo) *UpdateAccountUseCase {
	return &UpdateAccountUseCase{repo: r, opsRepo: opsRepo}
}

// WithObjectReconciler wires the post-commit per-object materializer used on a LABEL
// change (parity with the cross-service RegisterResource re-register path — see
// doUpdate). Optional; nil keeps the queue-only behaviour.
func (u *UpdateAccountUseCase) WithObjectReconciler(r ObjectReconciler) *UpdateAccountUseCase {
	u.reconciler = r
	return u
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

// doUpdate applies the mutation in one writer-tx and, when the change can flip
// iam-direct selector membership (a LABEL change), re-materializes the object.
//
// WHY THE IN-PROCESS PASS. iam.account is label-selectable, so clearing a matching
// label is a REVOCATION. Its cross-service twin gets that for free: vpc/compute/nlb
// re-call InternalIAMService.RegisterResource on a label update, and RegisterResource
// runs ReconcileObjectForward in-process — the forward's delete-stale guard sees the
// object already has members, hands it to the FULL ReconcileObject, and the stale grant
// dies there. The iam-native path had no such pass: it enqueued a
// resource_reconcile_outbox event and returned, which made revoke latency the DEPTH OF
// THE GLOBAL RECONCILE QUEUE. That queue is strictly FIFO and drained by a single
// worker at ~5 events/s, each event a FULL O(scope) recompute, while the e2e suite
// produces 5-8 events/s — so it runs a multi-minute backlog. Measured on the stand for
// the sibling iam.project path: the label-clear event was enqueued at 19:59:18.97 and
// drained at 20:06:49.82 (7m30s); the tuple survived until the 30s periodic sweep
// reached that binding at 20:00:23, 65s after the clear, long past any client budget.
//
// OFF THE done-PATH (ban #9). The pass is scheduled detached: Operation.done reports
// that the account row is durable, never that its tuples converged. The co-committed
// reconcile event above and the periodic sweep stay the at-least-once backstop, so this
// changes WHEN the revoke is observed, not WHETHER it happens.
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
	// Label change ⇒ selector membership may have flipped ⇒ re-materialize this ONE
	// object now instead of waiting out the FIFO reconcile queue (see the doc above).
	// ReconcileObjectForward is the same entry point the cross-service register path
	// uses: its delete-stale guard finds the existing members and delegates to the FULL
	// ReconcileObject, which is what actually revokes a now-unmatched grant.
	if accountLabelsChanged(changed) && u.reconciler != nil {
		id := string(updated.ID)
		shared.GoPostCommit(ctx, u.logger, "account label re-materialization", func(ctx context.Context) {
			if rerr := u.reconciler.ReconcileObjectForward(ctx, "iam.account", id); rerr != nil && u.logger != nil {
				u.logger.Error("account update: label re-materialization failed (reconcile event + sweep will retry)",
					"account_id", id, "err", rerr)
			}
		})
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
