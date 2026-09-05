// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package group

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
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
	"account_id": "accountId is immutable after Group.Create",
	"accountId":  "accountId is immutable after Group.Create",
	"id":         "id is immutable after Group.Create",
	"created_at": "createdAt is immutable after Group.Create",
	"createdAt":  "createdAt is immutable after Group.Create",
}

type UpdateGroupUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// Optional post-commit per-object materializer (the SAME port the create-path
	// uses). A LABEL change flips iam-direct selector membership, so the object must
	// be re-materialized; nil-safe, the co-committed reconcile event + periodic sweep
	// remain the backstop.
	reconciler ObjectReconciler
	logger     *slog.Logger
}

func NewUpdateGroupUseCase(r Repo, opsRepo operations.Repo) *UpdateGroupUseCase {
	return &UpdateGroupUseCase{repo: r, opsRepo: opsRepo}
}

// WithObjectReconciler wires the post-commit per-object materializer used on a LABEL
// change (parity with the cross-service RegisterResource re-register path — see
// doUpdate). Optional; nil keeps the queue-only behaviour. The logger is used only to
// report a failed pass (the durable event + sweep still re-converge).
func (u *UpdateGroupUseCase) WithObjectReconciler(r ObjectReconciler, logger *slog.Logger) *UpdateGroupUseCase {
	u.reconciler = r
	u.logger = logger
	return u
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
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Anti-anon floor only. WHO may update this group is decided by the MODEL:
	// the api-gateway Checks `v_update@iam_group:<id>` before iam is dialed. The
	// former in-service owner-equality check against the owning account's
	// owner_user_id voided owner-granted delegation and could never be satisfied
	// by a machine principal — security.md «Авторизация живёт в МОДЕЛИ, а не в
	// самодельных проверках».
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

// doUpdate applies the mutation in one writer-tx and, when the change can flip
// iam-direct selector membership (a LABEL change), re-materializes the object through
// BOTH feeds — the durable co-committed reconcile event and the in-process pass.
//
// WHY A LABEL CHANGE IS A REVOCATION. iam.group is label-selectable: it is in
// domain.labelSelectableTypes, and the iam-direct scan spec probes kacho_iam.groups with
// `labels @> match_labels` (GIN index, migration 0041). So clearing a label that an
// ARM_LABELS grant matches un-matches the group from that grant — the per-object member
// row and its FGA tuples must GO. Its cross-service twin gets both feeds for free:
// vpc/compute/nlb re-call InternalIAMService.RegisterResource on a label update, and
// RegisterResource runs ReconcileObjectForward in-process — the forward's delete-stale
// guard sees the object already has members, hands it to the FULL ReconcileObject, and
// the stale grant dies there.
//
// WHAT THIS PATH WAS MISSING. Unlike Group.Create — which co-commits a reconcile event
// AND runs the forward post-commit — this update path did NEITHER. With no event there
// is no at-least-once queue behind the revoke at all: it converged only when the 30s
// periodic sweep (KACHO_IAM_RECONCILE_SWEEP_INTERVAL_MS) happened to reach the binding.
// And the event alone is not enough either, because it makes revoke latency the DEPTH OF
// THE GLOBAL RECONCILE QUEUE: that queue is strictly FIFO, drained by a single worker at
// ~5 events/s, each event a FULL O(scope) recompute, while the e2e suite produces
// 5-8 events/s — a multi-minute backlog. Measured on the stand for the sibling
// iam.project path: the label-clear event was enqueued at 19:59:18.97 and drained at
// 20:06:49.82 (7m30s); the tuple survived until the 30s sweep reached that binding at
// 20:00:23, 65s after the clear, long past any client budget. Hence both halves: the
// event is the durable backstop, the in-process pass is the accelerator in front of it.
//
// OFF THE done-PATH (ban #9). The in-process pass is scheduled detached: Operation.done
// reports that the group row is durable, never that its tuples converged. The
// co-committed reconcile event and the periodic sweep stay the at-least-once backstop,
// so this changes WHEN the revoke is observed, not WHETHER it happens.
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
			// Durable half. Co-committed in THIS writer-tx (ban #10) so the label write
			// and the re-materialization trigger are atomic: a crash after commit still
			// leaves the reconciler an at-least-once record that this group's selector
			// membership must be re-evaluated. Only on a labels change — no other
			// mutable field of a Group can flip an ARM_LABELS match.
			if labelsChanged(changed) {
				if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.group", string(upd.ID)); rerr != nil {
					return domain.Group{}, rerr
				}
			}
			return upd, nil
		})
	if err != nil {
		return nil, err
	}
	// Accelerator half. Re-materialize this ONE object now instead of waiting out the
	// FIFO reconcile queue (see the doc above). ReconcileObjectForward is the same entry
	// point the cross-service register path uses: its delete-stale guard finds the
	// existing members and delegates to the FULL ReconcileObject, which is what actually
	// revokes a now-unmatched grant. Detached (GoPostCommit) — never gates Operation.done.
	if labelsChanged(changed) && u.reconciler != nil {
		id := string(updated.ID)
		shared.GoPostCommit(ctx, u.logger, "group label re-materialization", func(ctx context.Context) {
			if rerr := u.reconciler.ReconcileObjectForward(ctx, "iam.group", id); rerr != nil && u.logger != nil {
				u.logger.Error("group update: label re-materialization failed (reconcile event + sweep will retry)",
					"group_id", id, "err", rerr)
			}
		})
	}
	return marshalGroup(updated)
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
