// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package project

// create.go — CreateProjectUseCase.
// Insert в kacho_iam.projects; FK projects_account_fk SQLSTATE 23503 →
// FailedPrecondition с verbatim "Account <id> not found";
// UNIQUE projects_account_name_unique → AlreadyExists.

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

// ObjectReconciler — narrow post-commit port (rbac-contract-a-fix, C-01b /
// issue #232): SYNCHRONOUSLY materialize the per-object access on a freshly-created
// iam-native object right after the create writer-tx commits. Under the flat OpenFGA
// model (Contract-A) the `<rel> from account` ACCESS cascade on iam leaf types is
// gone, so the owner's / account-admin's per-object admin/v_* tuple on project:<id>
// is materialized per-object by the reconciler — and the async event drain races a
// client that GETs the project right after the Operation reports done (iam-project
// newman `get-confirms` 403). The sync call closes that race. Implemented by
// reconcile.Reconciler (the SAME single materialization path the worker drives).
// nil-safe: when unwired the co-committed reconcile event + periodic sweep still
// materialize it, just not synchronously.
type ObjectReconciler interface {
	// ReconcileObjectForward is the ADDITIVE forward fast-path for the freshly-created
	// project-AS-OBJECT (iam.project): it materializes ONLY that new project's per-object
	// owner/admin tuples across the matching bindings under a SHARE advisory lock (no
	// EXCLUSIVE / O(scope) recompute), the throughput fix for the owner-tuple
	// materialization lag under a parallel project-create burst. It transparently delegates
	// to the FULL ReconcileObject if the object already has members (delete-stale guard).
	ReconcileObjectForward(ctx context.Context, objectType, objectID string) error
	// ReconcileObject is the FULL EXCLUSIVE object-fan-out (async at-least-once backstop —
	// delete-stale / audit / sweep), driven by the reconcile worker off the co-committed
	// reconcile-outbox event, not the create hot-path.
	ReconcileObject(ctx context.Context, objectType, objectID string) error
}

type CreateProjectUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// Optional OpenFGA hook. When wired, a freshly-created Project also gets
	// its `project:<id>#account@account:<account_id>` hierarchy tuple written
	// so FGA `viewer/editor/admin from account` cascades resolve — without it
	// the api-gateway per-RPC authz middleware can never authorise a
	// project-scoped Get/Update/Delete.
	relations  clients.RelationStore
	reconciler ObjectReconciler // rbac-contract-a-fix / #232 — optional, nil-safe
	logger     *slog.Logger
}

func NewCreateProjectUseCase(r Repo, opsRepo operations.Repo) *CreateProjectUseCase {
	return &CreateProjectUseCase{repo: r, opsRepo: opsRepo}
}

// WithRelationStore wires the project→account hierarchy-tuple writer.
func (u *CreateProjectUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *CreateProjectUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

// WithObjectReconciler wires the post-commit synchronous per-object materializer
// (rbac-contract-a-fix, C-01b / issue #232). nil-safe.
func (u *CreateProjectUseCase) WithObjectReconciler(r ObjectReconciler) *CreateProjectUseCase {
	u.reconciler = r
	return u
}

func (u *CreateProjectUseCase) Execute(ctx context.Context, p domain.Project) (*operations.Operation, error) {
	// Anti-anonymous: anonymous Project.Create в чужой Account.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if p.AccountID == "" {
		return nil, shared.InvalidArg("account_id", "account_id required")
	}
	if err := shared.ValidateResourceID(string(p.AccountID), domain.PrefixAccount, "account"); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}

	projID := ids.NewID(domain.PrefixProject)

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Create project %s", p.Name),
		// account_id denormalized into operations.account_id (D-8) so the
		// account-scoped module list surfaces this Project op. Non-first field —
		// corelib extractResourceID still picks project_id for resource_id.
		&iamv1.CreateProjectMetadata{ProjectId: projID, AccountId: string(p.AccountID)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}

	actor := authzguard.PrincipalUserID(ctx)
	p.ID = domain.ProjectID(projID)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doCreate(ctx, p, actor)
	})
	return &op, nil
}

func (u *CreateProjectUseCase) doCreate(ctx context.Context, p domain.Project, actor string) (*anypb.Any, error) {
	created, err := shared.DoWithWriteTx(ctx, u.repo,
		func(ctx context.Context, w Writer) (domain.Project, error) {
			inserted, ierr := w.ProjectsW().Insert(ctx, p)
			if ierr != nil {
				return domain.Project{}, ierr
			}
			// Durable audit_outbox row atomic with the INSERT (запрет #10).
			if aerr := w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventProjectCreated,
				TenantAccountID: string(inserted.AccountID),
				Payload: map[string]any{
					"actor":         actor,
					"resource_type": "project",
					"resource_id":   string(inserted.ID),
					"account_id":    string(inserted.AccountID),
					"name":          string(inserted.Name),
				},
			}); aerr != nil {
				return domain.Project{}, aerr
			}
			// FGA hierarchy parent-pointer intents co-committed in the SAME writer-tx
			// (запрет #10):
			//   account:<acc>#account@project:<id>            — project→account
			//     hierarchy ancestor pointer.
			//   cluster:cluster_kacho_root#cluster@project:<id> — SEC-L cluster
			//     pointer so `... or system_viewer from cluster` resolves.
			// These wire the project into the hierarchy (account/project remain
			// verb-bearing ancestors in the flat model). The owner's per-object
			// admin/v_* on project:<id> itself is MATERIALIZED by the reconciler (owner
			// `*.*` ARM_ANCHOR over iam.project, see the reconcile-event emit below),
			// not derived from a leaf `from account` cascade.
			if ferr := w.EmitFGARelationWrite(ctx, []service.RelationTuple{
				{User: "account:" + string(inserted.AccountID), Relation: "account", Object: "project:" + string(inserted.ID)},
				{User: "cluster:cluster_kacho_root", Relation: "cluster", Object: "project:" + string(inserted.ID)},
			}); ferr != nil {
				return domain.Project{}, ferr
			}
			// rbac-contract-a-fix (forward-mat, C-01b): co-commit a reconcile event
			// in the SAME writer-tx (ban #10) so the owner `*.*` (and any other
			// ARM_ANCHOR/ARM_NAMES) binding materializes its per-object admin/v_*
			// tuple on the brand-new project — observable on the change event (≤2s),
			// not only on the periodic sweep.
			if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.project", string(inserted.ID)); rerr != nil {
				return domain.Project{}, rerr
			}
			return inserted, nil
		})
	if err != nil {
		return nil, err
	}

	// rbac-contract-a-fix (forward-mat, C-01b / issue #232): SYNCHRONOUSLY materialize
	// the per-object access on the just-committed project so the owner / account-admin
	// per-object admin/v_* tuple is observable when the Operation reports done — closing
	// the GET-after-create race the async event drain would otherwise lose under the flat
	// model (iam-project newman `get-confirms` 403). The owner `*.*` ARM_ANCHOR over
	// iam.project finds this brand-new project (IAMDirectSelectorBindingsMatchingObject,
	// arm='anchor') and the reconciler's sync-FGA writer applies the admin tuple to
	// OpenFGA before this returns. Best-effort/non-fatal: the project is durably created
	// and the co-committed reconcile event + periodic sweep are the at-least-once
	// backstop. nil-safe.
	//
	// IAM-FMB throughput fix: the sync post-commit materialization takes the ADDITIVE
	// forward (ReconcileObjectForward, SHARE advisory lock, single-object — the project is
	// brand-new so there is NOTHING stale to delete) instead of the FULL EXCLUSIVE
	// ReconcileObject, whose per-binding advisory lock + O(scope) recompute serialized on
	// the SINGLE owner/account binding every project of an account shares → the owner-tuple
	// materialization lagged past the client read-your-writes retry budget under a parallel
	// project-create burst. The forward delegates to the FULL path on a re-materialization
	// with existing members (delete-stale guard); the FULL ReconcileObject REMAINS the
	// async at-least-once backstop, driven by the co-committed reconcile event.
	u.reconcileObject(ctx, "iam.project", string(created.ID))

	return marshalProject(created)
}

// reconcileObject runs the post-commit synchronous per-object materialization via the
// ADDITIVE forward fast-path (nil-safe, non-fatal — logs and proceeds; the co-committed
// reconcile event + periodic sweep are the at-least-once backstop).
func (u *CreateProjectUseCase) reconcileObject(ctx context.Context, objectType, objectID string) {
	if u.reconciler == nil {
		return
	}
	if rerr := u.reconciler.ReconcileObjectForward(ctx, objectType, objectID); rerr != nil && u.logger != nil {
		u.logger.Error("project create: object forward reconcile failed (event/sweep will retry)",
			"object_type", objectType, "object_id", objectID, "err", rerr)
	}
}
