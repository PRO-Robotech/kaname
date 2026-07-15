// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service_account

// create.go — CreateServiceAccountUseCase.

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
// materialize the per-object access of every binding whose selector matches the
// freshly-created iam_service_account, right after Create commits. The flat
// OpenFGA model dropped the `<rel> from account` ACCESS cascade on
// iam_service_account, so the per-object tuple is materialized per-object; the
// sync call closes the GET-after-create race the async drain would otherwise lose.
// Implemented by reconcile.Reconciler. nil-safe (reconcile event + sweep backstop).
type ObjectReconciler interface {
	ReconcileObject(ctx context.Context, objectType, objectID string) error
}

type CreateServiceAccountUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// Optional FGA hierarchy-tuple writer. Writes
	// `iam_service_account:<id>#account@account:<acc>` after a successful
	// INSERT so iam_service_account-scoped authz cascades resolve.
	relations  clients.RelationStore
	reconciler ObjectReconciler // rbac-contract-a-fix — optional, nil-safe
	logger     *slog.Logger
}

func NewCreateServiceAccountUseCase(r Repo, opsRepo operations.Repo) *CreateServiceAccountUseCase {
	return &CreateServiceAccountUseCase{repo: r, opsRepo: opsRepo}
}

// WithRelationStore wires the service-account→account hierarchy-tuple writer.
func (u *CreateServiceAccountUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *CreateServiceAccountUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

// WithObjectReconciler wires the post-commit synchronous per-object materializer
// (rbac-contract-a-fix, C-01b). nil-safe.
func (u *CreateServiceAccountUseCase) WithObjectReconciler(r ObjectReconciler) *CreateServiceAccountUseCase {
	u.reconciler = r
	return u
}

func (u *CreateServiceAccountUseCase) Execute(ctx context.Context, sa domain.ServiceAccount) (*operations.Operation, error) {
	// Anti-anonymous: anonymous ServiceAccount.Create would create a persistent backdoor.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if sa.AccountID == "" {
		return nil, shared.InvalidArg("account_id", "account_id required")
	}
	if err := shared.ValidateResourceID(string(sa.AccountID), domain.PrefixAccount, "account"); err != nil {
		return nil, err
	}
	if err := sa.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}

	saID := ids.NewID(domain.PrefixServiceAccount)
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Create service account %s", sa.Name),
		// account_id denormalized (D-8) — surfaces in the account-scoped list.
		&iamv1.CreateServiceAccountMetadata{ServiceAccountId: saID, AccountId: string(sa.AccountID)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	actor := authzguard.PrincipalUserID(ctx)
	sa.ID = domain.ServiceAccountID(saID)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doCreate(ctx, sa, actor)
	})
	return &op, nil
}

func (u *CreateServiceAccountUseCase) doCreate(ctx context.Context, sa domain.ServiceAccount, actor string) (*anypb.Any, error) {
	created, err := shared.DoWithWriteTx(ctx, u.repo,
		func(ctx context.Context, w Writer) (domain.ServiceAccount, error) {
			inserted, ierr := w.ServiceAccountsW().Insert(ctx, sa)
			if ierr != nil {
				return domain.ServiceAccount{}, ierr
			}
			if aerr := w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventServiceAccountCreated,
				TenantAccountID: string(inserted.AccountID),
				Payload: map[string]any{
					"actor":         actor,
					"resource_type": "service_account",
					"resource_id":   string(inserted.ID),
					"account_id":    string(inserted.AccountID),
					"name":          string(inserted.Name),
				},
			}); aerr != nil {
				return domain.ServiceAccount{}, aerr
			}
			// FGA service-account→account hierarchy parent-pointer intent co-committed
			// in the SAME writer-tx (запрет #10). Under the FLAT OpenFGA model
			// (Contract-A) the `<rel> from account` ACCESS cascade on
			// iam_service_account was removed, so this parent-pointer is the
			// hierarchy/ownership lineage edge only — it no longer grants access. The
			// owner's/creator's actual access is materialized per-object by the
			// reconciler (see the reconcile-event emit below).
			if ferr := w.EmitFGARelationWrite(ctx, []service.RelationTuple{
				{User: "account:" + string(inserted.AccountID), Relation: "account", Object: "iam_service_account:" + string(inserted.ID)},
			}); ferr != nil {
				return domain.ServiceAccount{}, ferr
			}
			// rbac-contract-a-fix (forward-mat, C-01b): co-commit a reconcile event in
			// the SAME writer-tx (ban #10) so the reconciler materializes the owner
			// `*.*` per-object admin/v_* tuple on iam_service_account:<id> — the access
			// the flat model's removed `from account` cascade no longer derives.
			if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.serviceAccount", string(inserted.ID)); rerr != nil {
				return domain.ServiceAccount{}, rerr
			}
			return inserted, nil
		})
	if err != nil {
		return nil, err
	}

	// rbac-contract-a-fix (forward-mat, C-01b): SYNCHRONOUSLY materialize the
	// per-object access on the just-committed service account so the owner /
	// account-admin per-object tuple is observable when the Operation reports done —
	// closing the GET-after-create race the async event drain would otherwise lose
	// under the flat model. Best-effort/non-fatal: the SA is durably created and the
	// co-committed reconcile event + periodic sweep are the at-least-once backstop.
	u.reconcileObject(ctx, "iam.serviceAccount", string(created.ID))

	return marshalSA(created)
}

// reconcileObject runs the post-commit synchronous per-object materialization
// (nil-safe, non-fatal — logs and proceeds; the reconcile event + sweep retry).
func (u *CreateServiceAccountUseCase) reconcileObject(ctx context.Context, objectType, objectID string) {
	if u.reconciler == nil {
		return
	}
	if rerr := u.reconciler.ReconcileObject(ctx, objectType, objectID); rerr != nil && u.logger != nil {
		u.logger.Error("service_account create: object reconcile failed (event/sweep will retry)",
			"object_type", objectType, "object_id", objectID, "err", rerr)
	}
}
