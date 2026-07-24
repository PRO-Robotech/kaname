// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package group

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ObjectReconciler — narrow port (rbac-contract-a-fix, C-01b): SYNCHRONOUSLY
// materialize the per-object access of every binding whose selector matches a
// freshly-created iam-native object, right after Create commits. Under the flat
// OpenFGA model (Contract-A) the `<rel> from account` ACCESS cascade on iam leaf
// types is gone, so the owner's / account-admin's per-object admin/v_* tuple is
// materialized per-object by the reconciler — and the async event drain races a
// client that GETs the object right after the Operation reports done. The sync
// call closes that race. Implemented by reconcile.Reconciler (the SAME single
// materialization path the worker drives). nil-safe: when unwired the co-committed
// reconcile event + periodic sweep still materialize it, just not synchronously.
type ObjectReconciler interface {
	// ReconcileObjectForward is the ADDITIVE forward fast-path for the freshly-created
	// group-AS-OBJECT (iam.group): it materializes ONLY that new group's per-object
	// owner/admin tuples across the matching bindings under a SHARE advisory lock (no
	// EXCLUSIVE / O(scope) recompute), the throughput fix for the owner-tuple
	// materialization lag under a parallel group-create burst. It transparently delegates
	// to the FULL ReconcileObject if the object already has members (delete-stale guard).
	ReconcileObjectForward(ctx context.Context, objectType, objectID string) error
	// ReconcileObject is the FULL EXCLUSIVE object-fan-out (async at-least-once backstop —
	// delete-stale / audit / sweep), driven by the reconcile worker off the co-committed
	// reconcile-outbox event, not the create hot-path.
	ReconcileObject(ctx context.Context, objectType, objectID string) error
}

type CreateGroupUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// Optional FGA hierarchy-tuple writer. When non-nil, a successful Group
	// INSERT also writes `iam_group:<id>#account@account:<acc>` so FGA
	// `<rel> from account` cascades resolve for the per-RPC authz middleware
	// (object_type=iam_group scope_extractor).
	relations  clients.RelationStore
	reconciler ObjectReconciler // rbac-contract-a-fix — optional, nil-safe
	logger     *slog.Logger
}

func NewCreateGroupUseCase(r Repo, opsRepo operations.Repo) *CreateGroupUseCase {
	return &CreateGroupUseCase{repo: r, opsRepo: opsRepo}
}

// WithRelationStore wires the group→account hierarchy-tuple writer.
func (u *CreateGroupUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *CreateGroupUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

// WithObjectReconciler wires the post-commit synchronous per-object materializer
// (rbac-contract-a-fix, C-01b). nil-safe.
func (u *CreateGroupUseCase) WithObjectReconciler(r ObjectReconciler) *CreateGroupUseCase {
	u.reconciler = r
	return u
}

func (u *CreateGroupUseCase) Execute(ctx context.Context, g domain.Group) (*operations.Operation, error) {
	// Anti-anonymous guard.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if g.AccountID == "" {
		return nil, shared.InvalidArg("account_id", "account_id required")
	}
	if err := shared.ValidateResourceID(string(g.AccountID), domain.PrefixAccount, "account"); err != nil {
		return nil, err
	}
	if err := g.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}

	grpID := ids.NewID(domain.PrefixGroup)
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Create group %s", g.Name),
		// account_id denormalized (D-8) — surfaces in the account-scoped list.
		&iamv1.CreateGroupMetadata{GroupId: grpID, AccountId: string(g.AccountID)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	actor := authzguard.PrincipalUserID(ctx)
	g.ID = domain.GroupID(grpID)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doCreate(ctx, g, actor)
	})
	return &op, nil
}

func (u *CreateGroupUseCase) doCreate(ctx context.Context, g domain.Group, actor string) (*anypb.Any, error) {
	created, err := shared.DoWithWriteTx(ctx, u.repo,
		func(ctx context.Context, w Writer) (domain.Group, error) {
			inserted, ierr := w.GroupsW().Insert(ctx, g)
			if ierr != nil {
				return domain.Group{}, ierr
			}
			if aerr := w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventGroupCreated,
				TenantAccountID: string(inserted.AccountID),
				Payload: map[string]any{
					"actor":         actor,
					"resource_type": "group",
					"resource_id":   string(inserted.ID),
					"account_id":    string(inserted.AccountID),
					"name":          string(inserted.Name),
				},
			}); aerr != nil {
				return domain.Group{}, aerr
			}
			// FGA group→account hierarchy parent-pointer intent co-committed in the
			// SAME writer-tx (запрет #10). Under the FLAT OpenFGA model (Contract-A)
			// the `<rel> from account` ACCESS cascade on iam_group was removed, so this
			// `account:<acc>#account@iam_group:<id>` pointer is the hierarchy/ownership
			// lineage edge only — it no longer grants access. The owner's/creator's
			// actual access is materialized per-object by the reconciler (below).
			if ferr := w.EmitFGARelationWrite(ctx, []service.RelationTuple{
				{User: "account:" + string(inserted.AccountID), Relation: "account", Object: "iam_group:" + string(inserted.ID)},
			}); ferr != nil {
				return domain.Group{}, ferr
			}
			// rbac-contract-a-fix (forward-mat, C-01b): co-commit a reconcile event
			// in the SAME writer-tx (ban #10) so the reconciler materializes the
			// owner `*.*` per-object admin/v_* tuple on iam_group:<id> — the access
			// the flat model's removed `from account` cascade no longer derives.
			if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.group", string(inserted.ID)); rerr != nil {
				return domain.Group{}, rerr
			}
			return inserted, nil
		})
	if err != nil {
		return nil, err
	}

	// rbac-contract-a-fix (forward-mat, C-01b): SYNCHRONOUSLY materialize the
	// per-object access on the just-committed group so the owner / account-admin
	// per-object admin/v_* tuple is observable when the Operation reports done —
	// closing the GET-after-create race the async event drain would otherwise lose
	// under the flat model. Best-effort/non-fatal: the group is durably created and
	// the co-committed reconcile event + periodic sweep are the at-least-once
	// backstop. nil-safe.
	//
	// IAM-FMB throughput fix: the sync post-commit materialization takes the ADDITIVE
	// forward (ReconcileObjectForward, SHARE advisory lock, single-object — the group is
	// brand-new so there is NOTHING stale to delete) instead of the FULL EXCLUSIVE
	// ReconcileObject, whose per-binding advisory lock + O(scope) recompute serialized on
	// the SINGLE owner/account binding every group of an account shares → the owner-tuple
	// materialization lagged past the client read-your-writes retry budget under a parallel
	// group-create burst. The forward delegates to the FULL path on a re-materialization
	// with existing members (delete-stale guard); the FULL ReconcileObject REMAINS the
	// async at-least-once backstop, driven by the co-committed reconcile event.
	u.reconcileObject(ctx, "iam.group", string(created.ID))

	return marshalGroup(created)
}

// reconcileObject runs the post-commit synchronous per-object materialization via the
// ADDITIVE forward fast-path (nil-safe, non-fatal — logs and proceeds; the co-committed
// reconcile event + periodic sweep are the at-least-once backstop).
func (u *CreateGroupUseCase) reconcileObject(ctx context.Context, objectType, objectID string) {
	if u.reconciler == nil {
		return
	}
	if rerr := u.reconciler.ReconcileObjectForward(ctx, objectType, objectID); rerr != nil && u.logger != nil {
		u.logger.Error("group create: object forward reconcile failed (event/sweep will retry)",
			"object_type", objectType, "object_id", objectID, "err", rerr)
	}
}
