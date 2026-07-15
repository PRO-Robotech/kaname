// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package user

// invite.go — UserService.Invite use-case.
//
// Flow:
//  1. sync: validate AccountID + email; permission-check через
//     `canInviteUsers` (invite_authz.go — один Check(editor) через
//     cascade-traversal покрывает editor/admin/owner; viewer не может).
//  2. (sync) validate project_id + role_id consistency; peer-check project
//     принадлежит указанному account.
//  3. async (LRO worker): найти existing user-row через GetByAccountEmail —
//     если есть ACTIVE → idempotent (если project+role указаны → создать AB);
//     если есть PENDING → idempotent; если нет → InsertPending в TX
//     (+ optionally INSERT AccessBinding).
//  4. response = User; metadata = {user_id, account_id}.
//
// The Kratos admin magic-link step was removed (Kratos client deleted). Invite
// still creates a PENDING user row + optional AccessBinding; how the invitee
// activates the row (magic-link / IdP login / admin assist) is left to the
// broker layer.

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/relationhook"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// InviteUserInput — параметры use-case'а (resolved из gRPC request).
type InviteUserInput struct {
	AccountID   domain.AccountID
	Email       domain.Email
	DisplayName domain.DisplayName // optional; если "" — defaults к email
	ProjectID   domain.ProjectID   // optional; если set → role_id обязателен
	RoleID      domain.RoleID      // required IFF ProjectID set
}

// ObjectReconciler — narrow port: SYNCHRONOUSLY
// materialize the per-object access of every binding whose selector matches the
// invite-flow's freshly-created iam-native objects (the project-scoped
// AccessBinding + a brand-new invitee user), right after the invite tx commits.
// Under the flat OpenFGA model the `from <scope>` ACCESS cascade on these leaf
// types is gone, so the owner/account-admin per-object tuple is materialized
// per-object; the sync call closes the GET-after-create race the async drain would
// otherwise lose. Implemented by reconcile.Reconciler. nil-safe (the co-committed
// reconcile event + periodic sweep are the at-least-once backstop).
type ObjectReconciler interface {
	ReconcileObject(ctx context.Context, objectType, objectID string) error
	// ReconcileBinding materializes the invite-flow AccessBinding's OWN grant
	// membership through the unified reconciler — the per-object verb-bearing v_*
	// (+ back-compat tier) tuples derived from the granted role's verbs. Under
	// Design-B (flat-authz verb-bearing) enforcement resolves get→v_get,
	// update→v_update, … so the grant MUST carry v_* — a tier-only emit (the old
	// writeInviteBindingTuples path) leaves the invitee with `editor` but no
	// `v_get`/`v_update`, denied on GET/PATCH of the granted project. This is the
	// SAME materialization path
	// AccessBindingService.Create drives, so the invite-flow grant is identical to a
	// direct binding.
	ReconcileBinding(ctx context.Context, bindingID domain.AccessBindingID) error
}

// InviteUserUseCase — invite-or-bind use-case.
type InviteUserUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	authz   AuthzChecker
	// Optional FGA tuple writer. The invite-flow creates a project-scoped
	// AccessBinding directly (bypassing AccessBindingService), so without
	// this hook the project role-grant tuple and the iam_access_binding
	// hierarchy tuple are not written → the invitee's authz cascade has no
	// path. When wired, doInvite emits both tuples after the AB INSERT commits.
	relations  clients.RelationStore
	reconciler ObjectReconciler // optional, nil-safe
	logger     *slog.Logger
}

func NewInviteUserUseCase(
	r Repo,
	opsRepo operations.Repo,
	authz AuthzChecker,
) *InviteUserUseCase {
	return &InviteUserUseCase{
		repo:    r,
		opsRepo: opsRepo,
		authz:   authz,
	}
}

// WithObjectReconciler wires the post-commit synchronous per-object materializer.
// nil-safe.
func (uc *InviteUserUseCase) WithObjectReconciler(r ObjectReconciler) *InviteUserUseCase {
	uc.reconciler = r
	return uc
}

// WithRelationStore wires the invite-flow AccessBinding FGA tuple writer.
//
// It also re-points the `CanInviteUsers` permission checker at the real FGA
// client: NewInviteUserUseCase is constructed with the no-op authzStub, so
// without this the invite permission gate always denies even for an account
// admin ("Permission denied to invite users" for the account owner).
// RelationStore satisfies the narrow AuthzChecker interface (both expose
// Check), so the same client backs the permission gate and the tuple writer.
func (uc *InviteUserUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *InviteUserUseCase {
	uc.relations = relations
	uc.authz = relations
	uc.logger = logger
	return uc
}

// Execute — основной entry-point.
//
// **Sync validation** (все до Operation):
//   - AccountID required.
//   - Email format (RFC 5321 lite via domain.Email.Validate).
//   - ProjectID+RoleID consistency.
//   - Permission check (CanInviteUsers cascade). 401/PERMISSION_DENIED — НЕ
//     создаем Operation.
//
// **Async work** в LRO worker'е:
//   - GetByAccountEmail → idempotent path или INSERT PENDING.
//   - Optionally AB-Insert (idempotent через ON CONFLICT).
//   - Magic-link generation.
func (uc *InviteUserUseCase) Execute(ctx context.Context, in InviteUserInput) (*operations.Operation, error) {
	// 1. Sync validation.
	if in.AccountID == "" {
		return nil, shared.InvalidArg("account_id", "Illegal argument account_id: required")
	}
	if err := in.Email.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}
	if in.DisplayName != "" {
		if err := in.DisplayName.Validate(); err != nil {
			return nil, shared.MapValidationErr(err)
		}
	}
	if in.ProjectID != "" && in.RoleID == "" {
		return nil, shared.InvalidArg("role_id", "Illegal argument role_id: required when project_id is set")
	}
	if in.ProjectID == "" && in.RoleID != "" {
		return nil, shared.InvalidArg("project_id", "Illegal argument project_id: required when role_id is set")
	}

	// 2. Permission check через cascade Check(editor).
	principal := operations.PrincipalFromContext(ctx)
	if principal.ID == "" {
		return nil, status.Error(codes.Unauthenticated, "principal required")
	}
	allowed, err := canInviteUsers(ctx, uc.authz, principal.ID, string(in.AccountID))
	if err != nil {
		return nil, fmt.Errorf("authz check: %w", err)
	}
	if !allowed {
		return nil, status.Errorf(codes.PermissionDenied,
			"Permission denied to invite users in account %s", in.AccountID)
	}

	// 3. Peer-check project (если указан) — он должен принадлежать тому же
	// Account. Same-DB read (Project — ресурс kacho-iam, нет cross-service hop).
	if in.ProjectID != "" {
		rd, rerr := uc.repo.Reader(ctx)
		if rerr != nil {
			return nil, shared.MapRepoErr(rerr)
		}
		prj, perr := rd.Projects().Get(ctx, in.ProjectID)
		_ = rd.Rollback(ctx)
		if perr != nil {
			return nil, shared.MapRepoErr(perr)
		}
		if prj.AccountID != in.AccountID {
			return nil, status.Error(codes.FailedPrecondition,
				"project_id belongs to different account")
		}
	}

	// 4. Pre-allocate user-id (на случай INSERT в async path; при idempotent
	// возврате existing-row id игнорируется).
	candidateUserID := domain.UserID(ids.NewID(domain.PrefixUser))
	invitedBy := domain.UserID(principal.ID)

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Invite user %s to account %s", in.Email, in.AccountID),
		&iamv1.InviteUserMetadata{
			UserId:    string(candidateUserID),
			AccountId: string(in.AccountID),
		},
	)
	if err != nil {
		return nil, err
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}

	operations.Run(ctx, uc.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return uc.doInvite(ctx, op.ID, candidateUserID, invitedBy, in)
	})
	return &op, nil
}

// doInvite — async-часть. Возвращает marshalled User для Operation.response.
func (uc *InviteUserUseCase) doInvite(
	ctx context.Context, opID string, candidateID, invitedBy domain.UserID, in InviteUserInput,
) (*anypb.Any, error) {
	// 4.1 Read-side check (быстрый path для idempotent ACTIVE/PENDING).
	rd, err := uc.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	existing, exErr := rd.Users().GetByAccountEmail(ctx, in.AccountID, in.Email)
	_ = rd.Rollback(ctx)

	dn := in.DisplayName
	if dn == "" {
		dn = defaultDisplayName(in.Email)
	}

	// 4.2 INSERT (или Get-existing) + AB-INSERT в одной TX.
	type inviteTxResult struct {
		user      domain.User
		userIsNew bool
		createdAB domain.AccessBinding
		haveAB    bool
	}
	res, err := shared.DoWithWriteTx(ctx, uc.repo,
		func(ctx context.Context, w Writer) (inviteTxResult, error) {
			var out inviteTxResult
			if exErr == nil {
				// Idempotent: row already exists (ACTIVE / PENDING / BLOCKED).
				out.user = existing
			} else {
				// Insert new PENDING.
				ins, _, err := w.UsersW().InsertPending(ctx, domain.User{
					ID:           candidateID,
					AccountID:    in.AccountID,
					Email:        in.Email,
					DisplayName:  dn,
					InviteStatus: domain.InviteStatusPending,
					InvitedBy:    invitedBy,
				})
				if err != nil {
					return inviteTxResult{}, err
				}
				out.user = ins
				out.userIsNew = true
			}

			// Optional bind-to-Project (idempotent через ON CONFLICT DO UPDATE).
			//
			// The AccessBinding subject must be the SAME user-row that the
			// api-gateway resolves the invitee's JWT to (InternalIAMService.
			// LookupSubject → GetByExternalID → oldest ACTIVE row). With the
			// user-per-Account model one identity has N user-rows (one per Account):
			// `user` above is the per-Account row in `in.AccountID` (a fresh PENDING
			// row, or an existing row in that Account). If the invitee is ALREADY
			// ACTIVE in another Account (e.g. their bootstrap personal Account), the
			// gateway resolves the JWT to that older row, NOT this one — so a
			// project-grant tuple on `user.ID` would be `no path` for the
			// gateway-resolved subject. AccessBinding.subject_id is Account-agnostic
			// (it grants ANY user a role on ANY resource), so resolve the canonical
			// (gateway-visible) identity row and bind the project-scoped grant to it.
			if in.ProjectID != "" {
				subjectID := uc.resolveCanonicalSubjectID(ctx, out.user, in.Email)
				ab := domain.AccessBinding{
					ID:           domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
					SubjectType:  domain.SubjectTypeUser,
					SubjectID:    subjectID,
					RoleID:       in.RoleID,
					ResourceType: domain.ResourceType("project"),
					ResourceID:   string(in.ProjectID),
				}
				ins, abErr := w.AccessBindingsW().Insert(ctx, ab)
				if abErr != nil {
					return inviteTxResult{}, abErr
				}
				out.createdAB = ins
				out.haveAB = true
				// Co-commit a reconcile
				// event for the NEW access_binding object so the owner `*.*` binding
				// materializes admin on iam_access_binding:<id> (the flat model dropped
				// the `from <scope>` access cascade). ban #10 co-commit.
				if err := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.accessBinding", string(ins.ID)); err != nil {
					return inviteTxResult{}, err
				}
			}
			// A freshly-inserted invitee user
			// row must forward-materialize under the owner `*.*` binding (the flat model
			// dropped the iam_user `from account` access cascade). Co-commit the
			// reconcile event in the SAME writer-tx as the InsertPending (ban #10).
			if out.userIsNew {
				if err := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.user", string(out.user.ID)); err != nil {
					return inviteTxResult{}, err
				}
			}
			return out, nil
		})
	if err != nil {
		return nil, err
	}
	user := res.user
	userIsNew := res.userIsNew
	createdAB := res.createdAB
	haveAB := res.haveAB

	// Emit the iam_access_binding hierarchy tuple for the invite-flow AccessBinding
	// (so an iam_access_binding-scoped Get/Delete on it resolves). The binding's
	// GRANT membership (the project-scoped v_* + tier tuples) is NOT hand-written
	// here — it is materialized through the unified reconciler below
	// (ReconcileBinding), so the invite grant carries the verb-bearing v_* the
	// Design-B enforcement requires (parity with AccessBindingService.Create).
	// Non-fatal — the AB row is already committed.
	if haveAB && uc.relations != nil {
		uc.writeInviteBindingHierarchyTuple(ctx, createdAB)
	}
	// Emit the iam_user→account hierarchy tuple for a freshly inserted
	// invitee row. Without it a per-resource UserService.Get on the invitee
	// is FGA `no path`. Idempotent re-invite of an existing user already
	// has the tuple (skipped). Non-fatal.
	if userIsNew && uc.relations != nil {
		relationhook.WriteHierarchyTuple(ctx, uc.relations, uc.logger,
			"account", string(user.AccountID), "account",
			"iam_user", string(user.ID))
	}

	// SYNCHRONOUSLY materialize the
	// per-object access on the just-committed invite-flow objects so the owner /
	// account-admin per-object admin/v_* tuple is observable when the Operation
	// reports done — closing the GET-after-create race the async event drain (the
	// co-committed EmitReconcileEvent rows above) would otherwise lose under the flat
	// model. Best-effort/non-fatal: rows are durably committed; reconcile event +
	// sweep backstop. nil-safe.
	if haveAB {
		// Materialize the invite grant's OWN membership (per-object v_* + tier from the
		// role's verbs) through the unified reconciler — Design-B verb-bearing parity
		// with AccessBindingService.Create (the invitee gets v_get/v_update on the
		// granted project, not just `editor`). nil-safe / non-fatal (sweep
		// backstops).
		uc.reconcileBinding(ctx, createdAB.ID)
		// Also reconcile the iam_access_binding OBJECT so the owner/account-admin's
		// per-object admin tuple on the new binding materializes (flat model).
		uc.reconcileObject(ctx, "iam.accessBinding", string(createdAB.ID))
	}
	if userIsNew {
		uc.reconcileObject(ctx, "iam.user", string(user.ID))
	}

	// The Kratos magic-link
	// step that used to run here was removed; activation of the freshly
	// invited PENDING row is now the broker's responsibility.
	_ = opID

	return marshalUser(user)
}

// reconcileObject runs the post-commit synchronous per-object materialization
// (nil-safe, non-fatal — logs and proceeds; the reconcile event + sweep retry).
func (uc *InviteUserUseCase) reconcileObject(ctx context.Context, objectType, objectID string) {
	if uc.reconciler == nil {
		return
	}
	if rerr := uc.reconciler.ReconcileObject(ctx, objectType, objectID); rerr != nil && uc.logger != nil {
		uc.logger.Error("invite user: object reconcile failed (event/sweep will retry)",
			"object_type", objectType, "object_id", objectID, "err", rerr)
	}
}

// reconcileBinding runs the post-commit synchronous grant-membership materialization
// for the invite-flow AccessBinding (nil-safe, non-fatal). It drives the unified
// reconciler so the grant emits the per-object verb-bearing v_* (+ back-compat tier)
// tuples derived from the granted role's verbs — Design-B parity with
// AccessBindingService.Create. The periodic sweep + the binding's reconcile-event
// backstop a transient failure.
func (uc *InviteUserUseCase) reconcileBinding(ctx context.Context, bindingID domain.AccessBindingID) {
	if uc.reconciler == nil {
		return
	}
	if rerr := uc.reconciler.ReconcileBinding(ctx, bindingID); rerr != nil && uc.logger != nil {
		uc.logger.Error("invite user: binding grant reconcile failed (sweep will retry)",
			"binding_id", string(bindingID), "err", rerr)
	}
}

// writeInviteBindingHierarchyTuple writes the iam_access_binding hierarchy tuple
// `iam_access_binding:<ab_id>#project@project:<id>` so an iam_access_binding-scoped
// Get/Delete on the invite-flow binding resolves. The binding's GRANT membership (the
// project-scoped v_* + tier tuples) is materialized by the unified reconciler
// (reconcileBinding) — NOT hand-written tier-only here — so the invitee holds the
// verb-bearing v_* the Design-B enforcement requires. Best-effort; logged, never fatal.
func (uc *InviteUserUseCase) writeInviteBindingHierarchyTuple(ctx context.Context, ab domain.AccessBinding) {
	relationhook.WriteHierarchyTuple(ctx, uc.relations, uc.logger,
		"project", string(ab.ResourceID), "project",
		"iam_access_binding", string(ab.ID))
}

// resolveCanonicalSubjectID returns the user-row id the api-gateway resolves
// the invitee's JWT to — the subject a project-scoped AccessBinding (and its
// FGA tuple) must be granted to so the per-RPC authz Check finds a path.
//
// The gateway resolves a JWT via InternalIAMService.LookupSubject →
// userReader.GetByExternalID → `WHERE external_id=$1 AND status='ACTIVE'
// ORDER BY created_at ASC LIMIT 1` (the oldest ACTIVE row of the identity).
// With the user-per-Account model one identity has N rows (one per Account);
// the invite-flow works on the per-Account row in `in.AccountID`, which is
// NOT necessarily that oldest ACTIVE row:
//
//   - the invitee may ALREADY be ACTIVE in another Account (e.g. a bootstrap
//     personal Account) — that older row carries the external_id and is what
//     the gateway resolves; the just-created per-Account PENDING row has an
//     empty external_id and is invisible to GetByExternalID;
//   - so a project-grant on the per-Account row's id would be `no path` for
//     the gateway-resolved subject.
//
// AccessBinding.subject_id is Account-agnostic, so this resolves the canonical
// (gateway-visible) identity row by EMAIL (the invitee identifier the invite
// request carries — the per-Account row's external_id may still be empty at
// AB-creation time): the oldest ACTIVE user-row with that email. When the
// invitee has no ACTIVE row anywhere (a genuinely new invitee who has never
// signed in), it falls back to the per-Account row's own id — once that
// PENDING row is activated by first-login it becomes the identity's row.
// Best-effort: any lookup error falls back to `perAccountRow.ID`.
func (uc *InviteUserUseCase) resolveCanonicalSubjectID(
	ctx context.Context, perAccountRow domain.User, email domain.Email,
) domain.SubjectID {
	fallback := domain.SubjectID(perAccountRow.ID)
	rd, err := uc.repo.Reader(ctx)
	if err != nil {
		return fallback
	}
	defer func() { _ = rd.Rollback(ctx) }()
	actives, err := rd.Users().FindActiveByEmail(ctx, email)
	if err != nil || len(actives) == 0 {
		return fallback
	}
	// FindActiveByEmail is ordered created_at ASC — actives[0] is the oldest
	// ACTIVE row, exactly the row GetByExternalID (and thus the gateway)
	// resolves the invitee's JWT to.
	canonical := domain.SubjectID(actives[0].ID)
	if uc.logger != nil && string(canonical) != string(perAccountRow.ID) {
		uc.logger.Info("invite: project-grant bound to canonical identity row",
			"per_account_row", string(perAccountRow.ID),
			"canonical_row", string(canonical),
			"email", string(email))
	}
	return canonical
}

// defaultDisplayName — extract local-part из email (до '@'); usable как
// placeholder display_name для PENDING-row до first-login.
func defaultDisplayName(email domain.Email) domain.DisplayName {
	s := string(email)
	if i := strings.IndexByte(s, '@'); i > 0 {
		return domain.DisplayName(s[:i])
	}
	return domain.DisplayName(s)
}
