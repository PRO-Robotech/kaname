// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// create.go — CreateRoleUseCase. Только custom-role (system-role нельзя
// создать через API — только seed-миграция). Permissions проверяются
// domain.Permissions.Validate + DB CHECK roles_permissions_valid.

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
// freshly-created iam_role, right after Create commits. The flat OpenFGA model
// dropped the `<rel> from account` ACCESS cascade on iam_role, so the owner's /
// account-admin's per-object tuple is materialized per-object; the sync call
// closes the GET-after-create race the async drain would otherwise lose.
// Implemented by reconcile.Reconciler. nil-safe (the reconcile event + sweep are
// the at-least-once backstop).
type ObjectReconciler interface {
	ReconcileObject(ctx context.Context, objectType, objectID string) error
}

type CreateRoleUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// Optional FGA hierarchy-tuple writer. Writes
	// `iam_role:<id>#account@account:<acc>` after a successful custom-role
	// INSERT so iam_role-scoped authz cascades resolve (`admin from account`).
	// System roles are seeded via migration and never reach this path.
	relations  clients.RelationStore
	reconciler ObjectReconciler // rbac-contract-a-fix — optional, nil-safe
	logger     *slog.Logger
}

func NewCreateRoleUseCase(r Repo, opsRepo operations.Repo) *CreateRoleUseCase {
	return &CreateRoleUseCase{repo: r, opsRepo: opsRepo}
}

// WithRelationStore wires the role→account hierarchy-tuple writer.
func (u *CreateRoleUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *CreateRoleUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

// WithObjectReconciler wires the post-commit synchronous per-object materializer
// (rbac-contract-a-fix, C-01b). nil-safe.
func (u *CreateRoleUseCase) WithObjectReconciler(r ObjectReconciler) *CreateRoleUseCase {
	u.reconciler = r
	return u
}

func (u *CreateRoleUseCase) Execute(ctx context.Context, r domain.Role) (*operations.Operation, error) {
	// Anti-anonymous: anonymous custom Role с iam.*.* permissions → escalation prep.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	// #212: a custom role is EXACTLY ONE scope — account XOR project. System
	// roles are seeded via migration, never via this RPC. The DB CHECK
	// roles_scope_xor is the backstop; this gives a friendly sync error first.
	accountSet := r.AccountID != ""
	projectSet := r.ProjectID != ""
	switch {
	case accountSet && projectSet:
		return nil, shared.InvalidArg("project_id", "Illegal argument: exactly one of account_id / project_id (a custom role is account- XOR project-scoped)")
	case !accountSet && !projectSet:
		return nil, shared.InvalidArg("account_id", "Illegal argument: one of account_id / project_id required (system roles are seeded via migration, not API)")
	case accountSet:
		if err := shared.ValidateResourceID(string(r.AccountID), domain.PrefixAccount, "account"); err != nil {
			return nil, err
		}
	default: // projectSet
		if err := shared.ValidateResourceID(string(r.ProjectID), domain.PrefixProject, "project"); err != nil {
			return nil, err
		}
	}
	// Sync: enforce is_system=false (только custom).
	r.IsSystem = false
	// RBAC rules-model 2026 (A): the authored rules are the input; compile them
	// into the INTERNAL permissions projection (anchor/names arms; matchLabels NOT
	// compiled) and store BOTH. Compilation also enforces the ≤1024 compiled-cap
	// (A-12). rules[] non-empty is required (legacy permissions-only Create is no
	// longer accepted on the API — A requires rules; legacy roles stay valid on read).
	if len(r.Rules) == 0 {
		return nil, shared.InvalidArg("rules", "Illegal argument rules (must be non-empty)")
	}
	// Validate the authored rules FIRST (cardinality / wildcard / XOR / feed-gate),
	// so a malformed rule surfaces its specific error (A-05/A-10/A-13) rather than a
	// misleading compiled-cap message. Only a well-formed rule set is then compiled;
	// the compiler enforces the ≤1024 compiled-cap (A-12).
	if verr := r.Rules.Validate(r.IsSystem); verr != nil {
		return nil, shared.MapValidationErr(verr)
	}
	compiled, cerr := domain.CompileRules(r.Rules)
	if cerr != nil {
		return nil, shared.MapValidationErr(cerr)
	}
	r.Permissions = compiled
	if err := r.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}

	roleID := ids.NewID(domain.PrefixRole)
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Create role %s", r.Name),
		&iamv1.CreateRoleMetadata{RoleId: roleID},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	actor := authzguard.PrincipalUserID(ctx)
	r.ID = domain.RoleID(roleID)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doCreate(ctx, r, actor)
	})
	return &op, nil
}

func (u *CreateRoleUseCase) doCreate(ctx context.Context, r domain.Role, actor string) (*anypb.Any, error) {
	created, err := shared.DoWithWriteTx(ctx, u.repo,
		func(ctx context.Context, w Writer) (domain.Role, error) {
			inserted, ierr := w.RolesW().Insert(ctx, r)
			if ierr != nil {
				return domain.Role{}, ierr
			}
			// RBAC explicit-model 2026 P4 (КФ-3): sync role_rule_selectors with the
			// role's UNIFIED materializing rules (anchor/names/labels) in the SAME
			// writer-tx (ban #10) so the reconciler's fast-path / sweep can find
			// bindings carrying this role on a mirror-change event (forward-mat, D-4).
			// No-op when the role has no materializing rules (legacy permissions-only).
			if serr := w.RolesW().ReplaceRuleSelectors(ctx, inserted.ID, inserted.Rules.MaterializingSelectors()); serr != nil {
				return domain.Role{}, serr
			}
			// Role audit payload carries id + name + actor — NOT the full
			// permissions matrix (avoid payload blow-up; 5.2-17).
			if aerr := w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventRoleCreated,
				TenantAccountID: string(inserted.AccountID),
				Payload: map[string]any{
					"actor":         actor,
					"resource_type": "role",
					"resource_id":   string(inserted.ID),
					"account_id":    string(inserted.AccountID),
					"name":          string(inserted.Name),
				},
			}); aerr != nil {
				return domain.Role{}, aerr
			}
			// FGA role→account hierarchy parent-pointer intent co-committed in the
			// SAME writer-tx (запрет #10). Under the FLAT OpenFGA model (Contract-A)
			// this `account:<acc>#account@iam_role:<id>` pointer no longer grants
			// access by itself — the `<rel> from account` ACCESS cascade on iam_role
			// was removed. It is retained as the hierarchy/ownership lineage edge; the
			// owner's (and creator's) ACTUAL admin/v_* access on this role is
			// MATERIALIZED per-object by the reconciler (see the reconcile-event emit
			// below), not derived from this pointer.
			//
			// #212: ONLY account-scoped roles get this pointer (the iam_role type has a
			// single `account` hierarchy relation, no `project` ancestor).
			if inserted.AccountID != "" {
				if ferr := w.EmitFGARelationWrite(ctx, []service.RelationTuple{
					{User: "account:" + string(inserted.AccountID), Relation: "account", Object: "iam_role:" + string(inserted.ID)},
				}); ferr != nil {
					return domain.Role{}, ferr
				}
			}
			// rbac-contract-a-fix (forward-mat, C-01b): co-commit a reconcile event in
			// the SAME writer-tx (ban #10) so the γ reconciler re-evaluates the owner
			// `*.*` (and any other ARM_ANCHOR/ARM_NAMES) binding against this brand-new
			// role and materializes the per-object admin/v_* tuple on iam_role:<id> —
			// the access the flat model's removed `from account` cascade no longer
			// derives. The event re-uses the mirror.upsert literal (the worker keys on
			// object_type/object_id, not the event type). nil-safe by construction
			// (EmitReconcileEvent is a plain outbox INSERT). Drained worker →
			// ReconcileObject("iam.role", id) → IAMDirectSelectorBindingsMatchingObject
			// finds the owner binding (arm='anchor') → full recompute materializes it.
			if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.role", string(inserted.ID)); rerr != nil {
				return domain.Role{}, rerr
			}
			return inserted, nil
		})
	if err != nil {
		return nil, err
	}

	// rbac-contract-a-fix (forward-mat, C-01b): SYNCHRONOUSLY materialize the
	// per-object access on the just-committed role so the owner / account-admin
	// per-object admin/v_* tuple is observable when the Operation reports done —
	// closing the GET-after-create race the async event drain would otherwise lose
	// under the flat model. Best-effort/non-fatal: the role is durably created and
	// the co-committed reconcile event + periodic sweep are the at-least-once
	// backstop. nil-safe.
	u.reconcileObject(ctx, "iam.role", string(created.ID))

	return marshalRole(created)
}

// reconcileObject runs the post-commit synchronous per-object materialization
// (nil-safe, non-fatal — logs and proceeds; the reconcile event + sweep retry).
func (u *CreateRoleUseCase) reconcileObject(ctx context.Context, objectType, objectID string) {
	if u.reconciler == nil {
		return
	}
	if rerr := u.reconciler.ReconcileObject(ctx, objectType, objectID); rerr != nil && u.logger != nil {
		u.logger.Error("role create: object reconcile failed (event/sweep will retry)",
			"object_type", objectType, "object_id", objectID, "err", rerr)
	}
}
