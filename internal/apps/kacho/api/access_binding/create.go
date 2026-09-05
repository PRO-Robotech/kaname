// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// create.go — CreateAccessBindingUseCase.
//
// Strict create: a duplicate active grant (5-tuple WHERE revoked_at IS NULL)
// raises 23505 from partial UNIQUE access_bindings_active_grant_uniq, which
// `iamerr.WrapPgErr` translates to ErrAlreadyExists with verbatim text
// «these permissions are already granted to <subject_id> on <res_type>:<res_id>».
// The handler returns the failure inside `Operation.Error` as gRPC
// codes.AlreadyExists. The earlier idempotent ON CONFLICT path is gone
// (migration 0003 documents the rationale).
//
// Atomic grant emit-in-tx flow:
//   - The FGA tuple INSERT is queued via
//     `w.AccessBindingsW().EmitRelationWrite(ctx, tuples)` inside the same
//     writer-tx as the binding INSERT. Tx rollback ⇒ no orphan fga_outbox rows.
//   - Relations are resolved permission-based via
//     `authzmap.PermissionsToRelations(role.Permissions)`.
//   - The journal row becomes a direct fact by trigger, in the SAME commit —
//     there is no separate delivery step to wait for.

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	abrepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
)

// MinExpiresIn — the shortest lifetime AccessBinding.Create accepts. A binding's
// access is materialised asynchronously within a bounded window, so anything
// shorter risks being revoked before it is ever usable; such a request is refused
// by name rather than issued as a grant that cannot be delivered.
const MinExpiresIn = 5 * time.Minute

// SelectorReconciler — narrow port (γ): materialize a selector binding's
// membership right after Create commits, so the membership + per-object FGA
// tuples are observable when the Operation reports done (γ-01). Implemented by
// the reconcile.Reconciler. Optional — nil-safe: when unwired the periodic sweep
// (D12) still materializes it, just not synchronously.
//
// rbac-contract-a-fix (C-01b): the port ALSO exposes ReconcileObject — the
// freshly-created access_binding is itself an iam-native OBJECT (iam.accessBinding)
// whose per-object access (owner / account-admin admin/v_*) must be materialized
// under the flat model (the `from <scope>` ACCESS cascade on iam_access_binding is
// gone). ReconcileBinding materializes THIS binding's own grant membership;
// ReconcileObject materializes every OTHER binding's per-object access ON this new
// binding-object. Both run synchronously post-commit so a GET right after the
// Operation reports done does not race the async drain.
type SelectorReconciler interface {
	// ReconcileBindingForward is the ADDITIVE create-path fast-path (sub-phase IAM-FMB):
	// it materializes THIS freshly-created binding's per-object membership additively while
	// holding NO advisory lock at all (neither EXCLUSIVE nor SHARE, no FOR UPDATE, no
	// delete-stale); the throughput fix
	// for a mass-binding-create burst. It transparently delegates to the FULL
	// ReconcileBinding if the binding already has members (delete-stale guard).
	ReconcileBindingForward(ctx context.Context, bindingID domain.AccessBindingID) error
	// ReconcileBinding is the FULL EXCLUSIVE path (Role.Update fan-out + sweep backstop);
	// still consumed by the reconcile machinery, not by the create hot-path.
	ReconcileBinding(ctx context.Context, bindingID domain.AccessBindingID) error
	// ReconcileObjectForwardNoStale is the ADDITIVE forward fast-path for the freshly-created
	// binding-AS-OBJECT (iam.accessBinding): it materializes ONLY that new object's
	// per-object owner/admin tuples across the matching bindings while holding NO
	// advisory lock at all (neither EXCLUSIVE nor SHARE, no O(scope) recompute); the throughput fix for the owner-tuple
	// materialization lag under a parallel create burst.
	//
	// The …NoStale variant asserts what only this call site knows: the object id was minted
	// in the writer-tx that has just committed, so it never existed before and carries
	// nothing stale. That matters because the SIBLING pass above
	// (ReconcileBindingForward) may already have written a member row ON THIS VERY
	// OBJECT — an anchor/`*.*` role in scope covers iam.accessBinding, i.e. the row just
	// created — and the plain ReconcileObjectForward reads such rows as "this object
	// existed before" and falls back to the FULL EXCLUSIVE ReconcileObject, the very
	// serialization this fast-path exists to avoid (measured: account-admin verbs ~67s
	// after create). The delete-stale guard is untouched for every other caller.
	ReconcileObjectForwardNoStale(ctx context.Context, objectType, objectID string) error
	// ReconcileObject is the FULL EXCLUSIVE object-fan-out (async at-least-once backstop —
	// delete-stale / audit / sweep); still driven by the reconcile worker off the
	// co-committed reconcile-outbox event, not by the create hot-path.
	ReconcileObject(ctx context.Context, objectType, objectID string) error
}

type CreateAccessBindingUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// relations — the door to the rights decision. The grant TUPLES are NOT written
	// through it (they go via the atomic fga_outbox emit-in-tx flow, and a trigger
	// folds them into direct facts). It IS a live dependency on the READ side:
	// requireGrantAuthority
	// resolves delegated-admin grant-authority (Path 2 — FGA `admin`/
	// `system_admin` on the scope object) through this client. Do not drop it.
	relations  clients.RelationStore
	reconciler SelectorReconciler // γ — optional, nil-safe
	logger     *slog.Logger
}

func NewCreateAccessBindingUseCase(r Repo, opsRepo operations.Repo) *CreateAccessBindingUseCase {
	return &CreateAccessBindingUseCase{repo: r, opsRepo: opsRepo}
}

// WithReconciler wires the γ selector reconciler (post-commit membership
// materialization). nil-safe.
func (u *CreateAccessBindingUseCase) WithReconciler(r SelectorReconciler) *CreateAccessBindingUseCase {
	u.reconciler = r
	return u
}

// WithRelationStore wires the door to the rights decision. Grant tuples are emitted
// via fga_outbox (not through this client), but the door is required on the
// READ side by requireGrantAuthority to resolve delegated-admin grant authority
// (FGA `admin`/`system_admin` on the scope object). Logger is used for failure
// diagnostics.
func (u *CreateAccessBindingUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *CreateAccessBindingUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

func (u *CreateAccessBindingUseCase) Execute(ctx context.Context, b domain.AccessBinding) (*operations.Operation, error) {
	// AccessBinding.Create grant-authority model.
	//
	// Grant authority follows from the GRANT SCOPE, not identity equality:
	// the caller may create a binding on `resource_id` iff they
	//   * own the owning Account (bootstrap path — DB owner_user_id check), OR
	//   * hold an FGA `admin` relation on the scope object (delegated admin).
	// A self-only `subject_id == principal.ID` rule would block the core
	// peer-access use-case (an Account/Project owner granting a role to
	// ANOTHER user). A non-admin still cannot grant; anonymous is still rejected.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	// Resolve the canonical subjects[] set from the request — subjects[] is
	// canonical, the legacy single subject_type/subject_id is a one-element
	// projection; a conflicting pair is rejected sync (INVALID_ARGUMENT). The
	// binding row + the legacy projection + the active-grant UNIQUE anchor use
	// subjects[0].
	subjects, err := domain.NormalizeSubjects(b.Subjects, b.SubjectType, b.SubjectID)
	if err != nil {
		return nil, shared.MapValidationErr(err)
	}
	b.Subjects = subjects
	b.SubjectType = subjects[0].Type
	b.SubjectID = subjects[0].ID

	// Stamp granted_by from the authenticated caller (anti-spoofing — never
	// from a request-body field). This also feeds the durable audit_outbox
	// compliance event's `actor` so "who granted this" is recorded.
	b.GrantedByUserID = domain.UserID(authzguard.PrincipalUserID(ctx))
	// F9 gate 1 (IAM-1-26): scope well-formedness — first statement, BEFORE
	// domain.Validate, so a malformed scope id yields the canonical
	// "invalid access binding scope id '<x>'" (not a generic scope-mismatch).
	if err := validateScopeID(string(b.ResourceType), b.ResourceID); err != nil {
		return nil, err
	}
	if err := b.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}
	// Lifetime floor — sync, before any Operation is minted. Access materialises
	// asynchronously (bounded, seconds), so a binding that elapses sooner than
	// MinExpiresIn could be revoked before it ever becomes usable: the caller
	// would be told the grant succeeded and would never see it work. Refuse by
	// name instead of issuing something that cannot be delivered.
	if b.ExpiresAt != nil && !b.ExpiresAt.After(time.Now().UTC().Add(MinExpiresIn)) {
		return nil, shared.InvalidArg("expires_at", "expires_at must be at least "+MinExpiresIn.String()+" in the future")
	}
	// Grant-authority on the binding's scope — AUTHZ FIRST, before ANY read of an
	// object the caller may not own. This RPC is `permission = "<exempt>"` in proto
	// (the api-gateway runs no per-RPC Check for it), so this handler is the ONLY
	// gate: a structural pre-check running first would let any authenticated
	// principal probe foreign role / project ids and tell them apart by the
	// distinguishable reject (absent role vs present-but-not-assignable vs denied) —
	// a cross-tenant existence + metadata oracle. Masking a structural reject as
	// PermissionDenied for an unauthorized caller is the DESIRED least-info outcome.
	//
	// It doubles as the group-amplification guard: a GROUP subject grants the role to
	// every member, so an admin/editor-tier binding with a GROUP subject must be
	// authored by a grant-authority holder on the scope. Enforced for EVERY Create,
	// so the guard holds by construction.
	if err := u.requireGrantAuthority(ctx, string(b.ResourceType), string(b.ResourceID)); err != nil {
		return nil, err
	}
	// F9 gates 2 & 3 (IAM-1-24/25): IsRoleAssignable + RoleCoversType — SYNC, before
	// any Operation is minted (Operation.error reserved for truly-async FGA
	// tuple-emission) and AFTER the authority gate above (they read the role + the
	// scope project).
	if err := u.validateStructuralGates(ctx, b); err != nil {
		return nil, err
	}

	// GLOBAL (=cluster scope) + selector all is legal ONLY for the system
	// cluster-admin role (`*.*.*`, served by the cluster-relation short-circuit).
	// For an ordinary role a
	// GLOBAL + ARM_ANCHOR grant would demand per-object materialization cluster-wide
	// (unbounded ledger + churn on every Create) — rejected SYNC with
	// INVALID_ARGUMENT before any Operation/tuple is created. GLOBAL + names/labels
	// is legal (finite explicit set). The role is read sync here for this
	// gate (re-read in the worker for the FGA mapping — the sync read keeps the
	// rejection observable on the request path, not buried in Operation.error).
	if err := u.validateGlobalAllSelector(ctx, b); err != nil {
		return nil, err
	}

	// Strict create — generate a candidate id; on a duplicate active grant
	// the DB-level UNIQUE access_bindings_active_grant_uniq raises 23505
	// (mapped to ErrAlreadyExists in the worker). No pre-resolution via
	// FindExisting: idempotent-upsert behaviour is intentionally gone
	// (migration 0003).
	abID := ids.NewID(domain.PrefixAccessBinding)
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Create access binding (%s/%s → %s on %s/%s)",
			b.SubjectType, b.SubjectID, b.RoleID, b.ResourceType, b.ResourceID),
		// account_id NARROW-SCOPE: stamped only for account-scoped bindings
		// (ResourceType=="account" → ResourceID); project/cluster/cross-service
		// bindings leave it empty (SQL NULL → not in the account-scoped list,
		// visible per-resource + cluster-wide Internal). auditTenantAccountID is
		// the single decision point (also used for audit_outbox tenant scope).
		&iamv1.CreateAccessBindingMetadata{AccessBindingId: abID, AccountId: auditTenantAccountID(b)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	b.ID = domain.AccessBindingID(abID)

	// Operation.done = durability of the binding (doCreate commits the row + the
	// atomic fga_outbox / audit / reconcile events in one writer-tx). The binding's
	// per-object access (iam_access_binding:<id> # v_update/v_delete) materializes
	// eventually-consistent — synchronous post-commit ReconcileObject (window
	// optimization) plus the co-committed reconcile event + periodic sweep as the
	// at-least-once backstop. It does NOT gate op.done; an immediate mutate by the
	// creator may briefly race the materialization and is handled by the client's
	// bounded retry (design-review: eventual-consistency model).
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (res *anypb.Any, derr error) {
		// The operations worker masks any non-gRPC-status error (including a
		// panic) from the worker fn as `Internal "internal worker error"` and
		// does not log it — so a failing async AccessBinding.Create silently
		// drops the FGA relation tuple, leaving the granted subject with
		// `no path` at the authz gate and no diagnostic trail. Recover here
		// and log the real cause (panic stack or error) before it is masked.
		defer func() {
			if r := recover(); r != nil {
				derr = fmt.Errorf("panic in access_binding doCreate: %v", r)
				if u.logger != nil {
					u.logger.Error("access_binding create operation panicked",
						"op", op.ID, "panic", fmt.Sprint(r),
						"subject", b.SubjectType, "subject_id", b.SubjectID,
						"role", b.RoleID, "resource", string(b.ResourceType)+":"+b.ResourceID)
				}
			}
		}()
		res, derr = u.doCreate(ctx, b)
		if derr != nil && u.logger != nil {
			u.logger.Error("access_binding create operation failed",
				"op", op.ID, "err", derr,
				"subject", b.SubjectType, "subject_id", b.SubjectID,
				"role", b.RoleID, "resource", string(b.ResourceType)+":"+b.ResourceID)
		}
		return res, derr
	})
	return &op, nil
}

func (u *CreateAccessBindingUseCase) doCreate(ctx context.Context, b domain.AccessBinding) (*anypb.Any, error) {
	w, err := u.repo.Writer(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = w.Rollback(ctx)
		}
	}()
	// Read the role inside the writer-tx (the writer also satisfies the Reader
	// interface) BEFORE the binding INSERT for the permission-based FGA mapping
	// below. The structural gates (role-scope IsRoleAssignable, RoleCoversType) are
	// enforced SYNC before the Operation is minted (validateStructuralGates, F9) — a
	// mis-scoped role never reaches doCreate. A missing role is still handled here as
	// the FK-RESTRICT backstop (FAILED_PRECONDITION), defensive to a direct caller.
	role, err := w.Roles().Get(ctx, b.RoleID)
	if err != nil {
		if stderrors.Is(err, iamerr.ErrNotFound) {
			return nil, status.Errorf(codes.FailedPrecondition, "Role %s not found", b.RoleID)
		}
		return nil, shared.MapRepoErr(err)
	}

	created, err := w.AccessBindingsW().Insert(ctx, b)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}

	// Persist the multi-subject set atomically with the binding
	// INSERT. scanAB does not carry Subjects (it reads the legacy single columns),
	// so stamp the resolved set onto `created` for the per-subject tuple emission
	// below. A nil/zero Subjects would be a back-compat single-subject binding;
	// Execute always normalizes Subjects to ≥1 element before doCreate.
	created.Subjects = b.Subjects
	if err := w.AccessBindingsW().InsertSubjects(ctx, created.ID, b.Subjects); err != nil {
		return nil, shared.MapRepoErr(err)
	}

	// FGA tuple emission. The binding
	// is thin (no per-binding target). buildBindingTuples is the SINGLE source of
	// truth shared with the Role.Update reconcile fan-out. A RULES-role emits ONLY
	// the binding-lifecycle hierarchy
	// parent-pointer at Create — the per-object access tuples (ARM_ANCHOR/ARM_NAMES/
	// ARM_LABELS) are materialized post-commit by the reconciler (no binding-time
	// scope_grant emission). A legacy permissions-only role emits its role-relation
	// tier tuples on the scope anchor.

	// Emit an INDEPENDENT tuple-set
	// PER SUBJECT. buildBindingTuples derives the subject from b.SubjectType/
	// b.SubjectID, so call it once per subject with that pair set; the per-subject
	// role-relation tuples differ by FGA `User` (user:… / group:…#member /
	// service_account:…) while the scope→binding hierarchy parent-pointer is
	// subject-independent (the ledger PK + ON CONFLICT DO NOTHING dedupe it).
	// The emitted-tuple ledger keys by (binding_id, fga_user, relation, object) so
	// each subject's lineage is distinguishable for per-subject revoke/audit.
	var tuples []abrepo.RelationTuple
	perSubject := created
	for _, s := range b.Subjects {
		perSubject.SubjectType = s.Type
		perSubject.SubjectID = s.ID
		st, berr := buildBindingTuples(perSubject, role)
		if berr != nil {
			// Fail-closed on a tuple/coverage desync: a
			// covered ref that emits 0 tuples returns INTERNAL → tx rollback, never a
			// target row without a backing FGA tuple.
			return nil, berr
		}
		tuples = append(tuples, st...)
	}
	tuples = dedupeTuples(tuples)

	// Atomic emit-in-tx. The fga_outbox INSERT commits iff the binding
	// INSERT commits (запрет #10), and a trigger on that INSERT folds the row
	// into a direct fact within the same commit.
	if err := w.AccessBindingsW().EmitRelationWrite(ctx, tuples); err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Persist the EXACT emitted-set in the SAME writer-tx (co-commit
	// with the fga_outbox emit, ban #10). This is the source of truth for a
	// SYMMETRIC revoke (delete.go reads it instead of re-deriving from the
	// possibly-mutated role) and the diff base for the Role.Update reconcile
	// fan-out. "What is emitted to FGA is what is recorded as emitted."
	if err := w.AccessBindingsW().InsertEmittedTuples(ctx, created.ID, tuples); err != nil {
		return nil, shared.MapRepoErr(err)
	}

	// Emit a subject_change_outbox row + a durable audit_outbox compliance event
	// PER SUBJECT atomically with the binding creation: each
	// subject's authz-cache must be invalidated and each grant must be audited
	// independently ("who granted role R to <subject> on <resource>"). Both run in
	// the SAME writer-tx as the binding INSERT (ban #10).
	for _, s := range b.Subjects {
		if err := w.AccessBindingsW().EmitSubjectChangeEvent(ctx, abrepo.SubjectChangeEvent{
			SubjectID:   string(s.ID),
			SubjectType: string(s.Type),
			EventType:   "binding_grant",
			Op:          "binding_upsert",
		}); err != nil {
			return nil, shared.MapRepoErr(err)
		}
		if err := w.AccessBindingsW().EmitAuditEvent(ctx, abrepo.AuditEvent{
			EventType:       abrepo.AuditEventTypeGranted,
			Actor:           string(created.GrantedByUserID),
			SubjectType:     string(s.Type),
			SubjectID:       string(s.ID),
			ResourceType:    string(created.ResourceType),
			ResourceID:      created.ResourceID,
			RoleID:          string(created.RoleID),
			BindingID:       string(created.ID),
			TenantAccountID: auditTenantAccountID(created),
		}); err != nil {
			return nil, shared.MapRepoErr(err)
		}
	}
	// rbac-contract-a-fix (forward-mat, C-01b): co-commit a reconcile event for the
	// NEW access_binding OBJECT in the SAME writer-tx (ban #10) so the owner `*.*`
	// (and any other ARM_ANCHOR/ARM_NAMES) binding materializes its per-object
	// admin/v_* tuple on iam_access_binding:<id> — under the flat model (Contract-A)
	// the `from account` ACCESS cascade on iam_access_binding is gone, so without this
	// a grant-owner gets 403 on GET of the binding they just created. This event is
	// about the binding-AS-OBJECT (iam.accessBinding), distinct from the post-commit
	// ReconcileBinding(created.ID) below which materializes THIS binding's own grant
	// membership. Drained → ReconcileObject("iam.accessBinding", id).
	if err := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.accessBinding", string(created.ID)); err != nil {
		return nil, shared.MapRepoErr(err)
	}
	if err := w.Commit(ctx); err != nil {
		return nil, shared.MapRepoErr(err)
	}
	committed = true

	// RBAC explicit-model 2026 P4 (КФ-3): a binding whose ROLE carries ANY
	// materializing rule (ARM_ANCHOR(all) / ARM_NAMES / ARM_LABELS) needs a
	// post-commit reconcile to materialize the per-object membership — the reconciler
	// is the SINGLE materialization path now (binding-time scope_grant emission is
	// removed, D-4). The reconcile runs in its OWN writer-tx (it reads the
	// just-committed binding). nil-safe: the periodic sweep materializes it
	// otherwise. Non-fatal to Create — the binding is durably created; log + proceed.
	//
	// IAM-FMB throughput fix: the create-path takes the ADDITIVE forward
	// (ReconcileBindingForward, NO advisory lock at all, no delete-stale) instead of the FULL
	// EXCLUSIVE ReconcileBinding — a create is purely additive (the binding is brand-new →
	// nothing stale to delete), so a mass-binding-create burst no longer serializes on the
	// per-binding EXCLUSIVE lock / O(scope) delete-stale recompute (which lagged grant
	// materialization past the client read-your-writes retry budget). The forward
	// transparently delegates to the FULL path if the binding already has members
	// (delete-stale guard). The FULL EXCLUSIVE ReconcileBinding REMAINS for the Role.Update
	// fan-out + periodic sweep backstop (delete-stale needs EXCLUSIVE there).
	//
	// OFF THE done-PATH (ban #9). Both passes below are O(objects-in-scope ×
	// verbs-per-object): a broad role at account scope walks the whole account. Run
	// inline in this worker-fn they gated `Operation.done` on the visibility of the
	// very side-effect `done` is forbidden to describe — measured on the stand, an
	// `admin` (verbs `*`) account-scoped binding reported done after 29.06s while its
	// `view` sibling on the same scope, created 0.4s earlier, took 4.3s. They now run
	// detached (shared.GoPostCommit): the binding row is durable at Commit above, the
	// fga_outbox rows and the reconcile event are co-committed with it, and the async
	// drainer + reconciler-worker + periodic sweep remain the at-least-once backstop —
	// so detaching changes WHEN materialization is observed, never WHETHER it happens.
	needsReconcile := len(role.Rules.MaterializingSelectors()) > 0
	bindingID := created.ID
	shared.GoPostCommit(ctx, u.logger, "access_binding create materialization", func(ctx context.Context) {
		if needsReconcile && u.reconciler != nil {
			if rerr := u.reconciler.ReconcileBindingForward(ctx, bindingID); rerr != nil && u.logger != nil {
				u.logger.Error("access_binding create: rules forward reconcile failed (fga_outbox drainer + sweep will retry)",
					"binding_id", string(bindingID), "err", rerr)
			}
		}
		u.reconcileNewBindingObject(ctx, bindingID)
	})

	return marshalAB(created)
}

// reconcileNewBindingObject is the create-path's SECOND post-commit materialization
// pass (rbac-contract-a-fix, forward-mat C-01b). It materializes the per-object access
// of every binding (owner `*.*`, account-admin) whose selector matches the NEW
// access_binding OBJECT (iam.accessBinding) — SHORTENING the window in which a GET of
// the just-created binding is not yet authorized under the flat model. It does NOT
// close that window and is NOT waited on: materialization is eventually-consistent and
// Operation.done means the binding row is DURABLE, never that its tuples are visible
// (ban #9); an immediate reader converges via bounded client-retry, and the
// co-committed EmitReconcileEvent + periodic sweep are the at-least-once backstop.
// Distinct from ReconcileBindingForward (which materializes THIS binding's own grant
// membership). Best-effort/non-fatal.
//
// IAM-FMB throughput fix: it takes the ADDITIVE forward with the nothing-stale proof
// (ReconcileObjectForwardNoStale, NO advisory lock at all, single-object) instead of the FULL
// EXCLUSIVE ReconcileObject, whose per-binding advisory lock + O(scope) recompute
// serialized on the SINGLE owner/account binding every access_binding of an account
// shares. The …NoStale variant matters because the sibling ReconcileBindingForward has,
// moments earlier, written a member row ON THIS VERY OBJECT (an anchor/`*.*` role in
// scope covers iam.accessBinding — the row just created), which the plain forward's
// delete-stale guard reads as "already existed" and bounces onto the FULL path:
// measured against the Read API, the subject's own tuples landed in ~3s while the scope
// parent-pointer took ~61s and the account-admin's per-object verbs ~67s, against a 25s
// client poll budget. The id was minted in the tx that committed before this call, so
// nothing stale can exist on it. The FULL ReconcileObject REMAINS the async
// at-least-once backstop (delete-stale / audit / PENDING), driven by the co-committed
// EmitReconcileEvent.
func (u *CreateAccessBindingUseCase) reconcileNewBindingObject(ctx context.Context, bindingID domain.AccessBindingID) {
	if u.reconciler == nil {
		return
	}
	if rerr := u.reconciler.ReconcileObjectForwardNoStale(ctx, "iam.accessBinding", string(bindingID)); rerr != nil && u.logger != nil {
		u.logger.Error("access_binding create: object forward reconcile failed (event/sweep will retry)",
			"binding_id", string(bindingID), "err", rerr)
	}
}
