// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service_account

// update.go — UpdateServiceAccountUseCase. account_id immutable.

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
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
	"account_id": "accountId is immutable after ServiceAccount.Create",
	"accountId":  "accountId is immutable after ServiceAccount.Create",
	"id":         "id is immutable after ServiceAccount.Create",
	"created_at": "createdAt is immutable after ServiceAccount.Create",
	"createdAt":  "createdAt is immutable after ServiceAccount.Create",
}

type UpdateServiceAccountUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// Optional post-commit per-object materializer (same port the create-path uses).
	// A LABEL change flips iam-direct selector membership, so the object must be
	// re-materialized; nil-safe, the co-committed reconcile event + periodic sweep
	// remain the backstop.
	reconciler ObjectReconciler
	logger     *slog.Logger
}

func NewUpdateServiceAccountUseCase(r Repo, opsRepo operations.Repo) *UpdateServiceAccountUseCase {
	return &UpdateServiceAccountUseCase{repo: r, opsRepo: opsRepo}
}

// WithObjectReconciler wires the post-commit per-object materializer used on a LABEL
// change (parity with the cross-service RegisterResource re-register path — see
// doUpdate). Optional; nil keeps the queue-only behaviour. The logger is used only to
// report a failed pass (the durable event + sweep still re-converge).
func (u *UpdateServiceAccountUseCase) WithObjectReconciler(r ObjectReconciler, logger *slog.Logger) *UpdateServiceAccountUseCase {
	u.reconciler = r
	u.logger = logger
	return u
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
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Anti-anon floor only. WHO may update this service account is decided by
	// the MODEL: the api-gateway Checks
	// `v_update@iam_service_account:<service_account_id>` before iam is dialed.
	// The former in-service owner-equality check against the owning account's
	// owner_user_id made managing service accounts unreachable for the very
	// automation principals they exist to serve — security.md «Авторизация живёт
	// в МОДЕЛИ, а не в самодельных проверках».
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
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

// doUpdate applies the mutation in one writer-tx and, when the change can flip
// iam-direct selector membership (a LABEL change), re-materializes the object.
//
// WHY THE IN-PROCESS PASS. iam.serviceAccount is label-selectable, so clearing a
// matching label is a REVOCATION. Its cross-service twin gets that for free:
// vpc/compute/nlb re-call InternalIAMService.RegisterResource on a label update, and
// RegisterResource runs ReconcileObjectForward in-process — the forward's delete-stale
// guard sees the object already has members, hands it to the FULL ReconcileObject, and
// the stale grant dies there. The iam-native path had no such pass: it enqueued a
// resource_reconcile_outbox event and returned, which made revoke latency the DEPTH OF
// THE GLOBAL RECONCILE QUEUE. That queue is strictly FIFO and drained by a single
// worker at ~5 events/s, each event a FULL O(scope) recompute, while the e2e suite
// produces 5-8 events/s — so it runs a multi-minute backlog. Measured on the stand for
// the sibling iam.project path: the label-clear event was enqueued at 19:59:18.97 and
// drained at 20:06:49.82 (7m30s); the tuple survived until the 30s periodic sweep
// reached that binding at 20:00:23, 65s after the clear, long past any client budget.
//
// OFF THE done-PATH (ban #9). The pass is scheduled detached: Operation.done reports
// that the service-account row is durable, never that its tuples converged. The
// co-committed reconcile event above and the periodic sweep stay the at-least-once
// backstop, so this changes WHEN the revoke is observed, not WHETHER it happens.
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
	// Label change ⇒ selector membership may have flipped ⇒ re-materialize this ONE
	// object now instead of waiting out the FIFO reconcile queue (see the doc above).
	// ReconcileObjectForward is the same entry point the cross-service register path
	// uses: its delete-stale guard finds the existing members and delegates to the FULL
	// ReconcileObject, which is what actually revokes a now-unmatched grant.
	if labelsChanged(changed) && u.reconciler != nil {
		id := string(updated.ID)
		shared.GoPostCommit(ctx, u.logger, "service account label re-materialization", func(ctx context.Context) {
			if rerr := u.reconciler.ReconcileObjectForward(ctx, "iam.serviceAccount", id); rerr != nil && u.logger != nil {
				u.logger.Error("service account update: label re-materialization failed (reconcile event + sweep will retry)",
					"service_account_id", id, "err", rerr)
			}
		})
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
