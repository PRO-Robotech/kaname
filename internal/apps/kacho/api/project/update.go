// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
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

func NewUpdateProjectUseCase(r Repo, opsRepo operations.Repo) *UpdateProjectUseCase {
	return &UpdateProjectUseCase{repo: r, opsRepo: opsRepo}
}

// WithObjectReconciler wires the post-commit per-object materializer used on a LABEL
// change (parity with the cross-service RegisterResource re-register path — see
// doUpdate). Optional; nil keeps the queue-only behaviour.
func (u *UpdateProjectUseCase) WithObjectReconciler(r ObjectReconciler) *UpdateProjectUseCase {
	u.reconciler = r
	return u
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

// doUpdate applies the mutation in one writer-tx and, when the change can flip
// iam-direct selector membership (a LABEL change), re-materializes the object.
//
// WHY THE IN-PROCESS PASS. iam.project is label-selectable, so clearing a matching
// label is a REVOCATION. Its cross-service twin gets that for free: vpc/compute/nlb
// re-call InternalIAMService.RegisterResource on a label update, and RegisterResource
// runs ReconcileObjectForward in-process — the forward's delete-stale guard sees the
// object already has members, hands it to the FULL ReconcileObject, and the stale grant
// dies there. The iam-native path had no such pass: it enqueued a
// resource_reconcile_outbox event and returned, which made revoke latency the DEPTH OF
// THE GLOBAL RECONCILE QUEUE. That queue is strictly FIFO and drained by a single
// worker at ~5 events/s, each event a FULL O(scope) recompute, while the e2e suite
// produces 5-8 events/s — so it runs a multi-minute backlog. Measured on the stand: the
// label-clear event was enqueued at 19:59:18.97 and drained at 20:06:49.82 (7m30s); the
// tuple survived until the 30s periodic sweep reached that binding at 20:00:23, 65s
// after the clear, long past any client budget.
//
// OFF THE done-PATH (ban #9). The pass is scheduled detached: Operation.done reports
// that the project row is durable, never that its tuples converged. The co-committed
// reconcile event above and the periodic sweep stay the at-least-once backstop, so this
// changes WHEN the revoke is observed, not WHETHER it happens.
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
	// Label change ⇒ selector membership may have flipped ⇒ re-materialize this ONE
	// object now instead of waiting out the FIFO reconcile queue (see the doc above).
	// ReconcileObjectForward is the same entry point the cross-service register path
	// uses: its delete-stale guard finds the existing members and delegates to the FULL
	// ReconcileObject, which is what actually revokes a now-unmatched grant.
	if labelsChanged(changed) && u.reconciler != nil {
		id := string(updated.ID)
		shared.GoPostCommit(ctx, u.logger, "project label re-materialization", func(ctx context.Context) {
			if rerr := u.reconciler.ReconcileObjectForward(ctx, "iam.project", id); rerr != nil && u.logger != nil {
				u.logger.Error("project update: label re-materialization failed (reconcile event + sweep will retry)",
					"project_id", id, "err", rerr)
			}
		})
	}
	return marshalProject(updated)
}
