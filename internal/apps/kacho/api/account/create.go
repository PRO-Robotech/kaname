// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package account

// create.go — CreateAccountUseCase.
//
// Canonical flow: sync validate → ops.Create → spawn worker → worker
// doCreate (Insert + outbox-emit + commit) → marshal anypb response.
//
// Sync validations (до Operation):
//   1. owner_user_id required + format proxy через domain.Account.Validate.
//   2. domain.Account.Validate() — multierr (name regex / description length /
//      labels cardinality+key+val).
// Async validations (внутри worker doCreate):
//   - FK accounts_owner_fk: user не существует → SQLSTATE 23503 →
//     ErrFailedPrecondition "User <id> not found".
//   - UNIQUE accounts_name_unique: дубль имени → SQLSTATE 23505 →
//     ErrAlreadyExists "Account with name <name> already exists".
// Запрет #10: software-precheck `repo.ExistsByName` НЕ
// делаем — UNIQUE на DB-уровне атомарно ловит race.

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
	abrepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// OwnerBindingReconciler — narrow port (P6 C-01/C-01b): materialize the owner
// AccessBinding's per-object membership (scope-self verb-bearing tuples on
// account:<A> + ARM_ANCHOR forward over the account's content) after the account
// + owner-binding co-commit. Implemented by reconcile.Reconciler (the SAME single
// materialization path as AccessBinding.Create). nil-safe: when unwired the
// periodic sweep materializes it, just not synchronously.
type OwnerBindingReconciler interface {
	ReconcileBinding(ctx context.Context, bindingID domain.AccessBindingID) error
}

// ownerTuples builds the owner self-grant + SEC-L cluster parent-pointer
// owner-tuple intents for a freshly-created Account. Co-committed in the writer-tx
// (SEC-D); see doCreate.
func ownerTuples(a domain.Account) []service.RelationTuple {
	return []service.RelationTuple{
		// user:<owner>#owner@account:<id> — owner self-grant.
		{User: "user:" + string(a.OwnerUserID), Relation: "owner", Object: "account:" + string(a.ID)},
		// cluster:cluster_kacho_root#cluster@account:<id> — SEC-L cluster pointer.
		{User: "cluster:cluster_kacho_root", Relation: "cluster", Object: "account:" + string(a.ID)},
	}
}

// ownerBindingHierarchyTuples builds the binding-OBJECT hierarchy parent-pointer
// intent for the owner AccessBinding (no-access-loss, КФ-БАГ-2):
//
//	account:<A>#account@iam_access_binding:<ownerBindingID>
//
// This mirrors access_binding.hierarchyParentTuple for an account-scoped binding,
// wiring the owner-binding OBJECT into the account hierarchy. rbac-contract-a-fix:
// under the flat OpenFGA model the `viewer/editor from account` ACCESS computed
// relations on iam_access_binding were removed, so this parent-pointer is the
// hierarchy/lineage edge only — the account owner's Get/List/Delete authz on the
// owner-binding OBJECT is materialized per-object by the reconciler (the owner `*.*`
// ARM_ANCHOR over iam.accessBinding). Co-committed in the writer-tx; see doCreate.
func ownerBindingHierarchyTuples(a domain.Account, bindingID domain.AccessBindingID) []service.RelationTuple {
	return []service.RelationTuple{
		{
			User:     "account:" + string(a.ID),
			Relation: "account",
			Object:   "iam_access_binding:" + string(bindingID),
		},
	}
}

// ownerBindingLedgerTuples builds the OWNER-BINDING-LIFECYCLE emitted-tuple ledger
// rows for the owner AccessBinding (symmetric revoke). A regular
// AccessBinding.Create records its emitted tuples into access_binding_emitted_tuples
// (InsertEmittedTuples) so delete.go's SYMMETRIC revoke (SelectEmittedTuples →
// EmitRelationDelete) removes EXACTLY what was emitted. The owner-binding emitted its
// FGA tuples but recorded NONE → revoking the owner-binding orphaned them, and because
// the FGA model derives account admin from owner (`define admin: … or owner`), the
// revoked owner retained standing admin (contradicts acceptance C-03).
//
// We record the two OWNER-BINDING-lifecycle tuples:
//   - the owner self-grant  user:<owner>#owner@account:<A>
//   - the hierarchy pointer account:<A>#account@iam_access_binding:<bindingID>
//
// The SEC-L cluster pointer (cluster:cluster_kacho_root#cluster@account:<A>) is
// DELIBERATELY excluded — it is ACCOUNT-lifecycle (mirrored by Project.Create / user
// upsert; ties the account to the cluster root) and MUST survive an owner-binding
// revoke, so it is not part of the owner-binding's revoke set. The reconciler-
// materialized per-object content/scope-self tuples (source='member') are recorded
// separately by the reconciler — these are the binding-lifecycle (source='binding')
// tuples a regular Create would record.
func ownerBindingLedgerTuples(a domain.Account, bindingID domain.AccessBindingID) []abrepo.RelationTuple {
	return []abrepo.RelationTuple{
		{User: "user:" + string(a.OwnerUserID), Relation: "owner", Object: "account:" + string(a.ID)},
		{User: "account:" + string(a.ID), Relation: "account", Object: "iam_access_binding:" + string(bindingID)},
	}
}

// CreateAccountUseCase инициирует создание Account.
//
// Скоупный гэп с kacho-vpc-pattern: kacho-iam НЕ имеет folder/parent peer-check
// на request-path (Account — top-level), поэтому FolderClient-аналога нет.
type CreateAccountUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// relations/logger — kept for backwards-compatible WithRelationStore wiring
	// (composition root still passes them). The owner-tuple is no longer written
	// sync from the Create path: it is co-committed into kacho_iam.fga_outbox in
	// the writer-tx (SEC-D) and applied by the drainer. The
	// fields remain so future read-side helpers can reuse the client.
	relations clients.RelationStore
	logger    *slog.Logger
	// reconciler — P6 owner-binding materialization (C-01/C-01b). nil-safe.
	reconciler OwnerBindingReconciler
}

// NewCreateAccountUseCase создает use-case.
func NewCreateAccountUseCase(r Repo, opsRepo operations.Repo) *CreateAccountUseCase {
	return &CreateAccountUseCase{repo: r, opsRepo: opsRepo}
}

// WithReconciler wires the owner-binding materialization reconciler (P6). nil-safe.
func (u *CreateAccountUseCase) WithReconciler(r OwnerBindingReconciler) *CreateAccountUseCase {
	u.reconciler = r
	return u
}

// WithRelationStore wires the account owner-tuple writer.
func (u *CreateAccountUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *CreateAccountUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

// Execute — sync validate + create Operation + запуск worker'а. Возвращает
// созданный Operation указателем (caller'у нужен он для `OperationService.Get`).
//
// Принимает `domain.Account` напрямую — никаких
// тривиальных `CreateInput`-оберток. Поле `a.ID` на входе пустое — назначим
// внутри через `ids.NewID(ids.PrefixAccount)`.
func (u *CreateAccountUseCase) Execute(ctx context.Context, a domain.Account) (*operations.Operation, error) {
	// Anti-anonymous: anonymous create Account с произвольным owner → account hijack.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	// Sync 1: required fields.
	if a.OwnerUserID == "" {
		return nil, shared.InvalidArg("owner_user_id", "owner_user_id required")
	}
	// Anti-hijacking: principal must == owner_user_id.
	// Authenticated user может создать Account ТОЛЬКО с самим собой как owner.
	// Cluster-admin tooling должно ходить через internal listener (bypass guard).
	if err := authzguard.RequireOwnerMatchesPrincipal(ctx, string(a.OwnerUserID)); err != nil {
		return nil, err
	}
	// Sync 2: full domain validation (name regex + description length + labels).
	if err := a.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}

	// ID generation: используем literal-prefix через domain.PrefixAccount.
	// Future: переключиться на `ids.PrefixAccount` после его добавления
	// в kacho-corelib/ids.
	accID := ids.NewID(domain.PrefixAccount)

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Create account %s", a.Name),
		&iamv1.CreateAccountMetadata{AccountId: accID},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}

	// Capture the verified caller sync (anti-spoofing — never a body field) to
	// stamp the durable audit_outbox `actor`. The async worker ctx may not carry
	// the principal, so it is resolved here and passed into doCreate.
	actor := authzguard.PrincipalUserID(ctx)

	a.ID = domain.AccountID(accID)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doCreate(ctx, a, actor)
	})
	return &op, nil
}

// doCreate — async часть (внутри Operation worker). Открывает Writer-TX,
// атомарно (запрет #10 / SEC-D / ВЗ-3) co-commit'ит: account INSERT + audit +
// FGA owner-tuple intent + **owner AccessBinding row + its subjects** (RBAC
// explicit-model 2026 P6 — D-8/C-01). После commit запускает reconcile owner-
// binding'а (scope-self verb-bearing tuples на account:<A> + ARM_ANCHOR forward
// над содержимым — C-01/C-01b; единый materialization-путь). Возвращает anypb с
// финальным state Account'а.
func (u *CreateAccountUseCase) doCreate(ctx context.Context, a domain.Account, actor string) (*anypb.Any, error) {
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

	// FK accounts_owner_fk (23503): пользователь не существует. Constraint —
	// DEFERRABLE INITIALLY DEFERRED, поэтому этот INSERT НЕ падает — нарушение
	// всплывает на COMMIT (см. writeTx.Commit), где мапится в
	// FailedPrecondition "User <id> not found" через тот же constraint-aware bridge.
	inserted, ierr := w.AccountsW().Insert(ctx, a)
	if ierr != nil {
		return nil, shared.MapRepoErr(ierr)
	}
	// Durable audit_outbox compliance row in the SAME writer-tx (запрет #10).
	if aerr := w.EmitAuditEvent(ctx, service.AuditEvent{
		EventType:       auditEventAccountCreated,
		TenantAccountID: string(inserted.ID),
		Payload: map[string]any{
			"actor":         actor,
			"resource_type": "account",
			"resource_id":   string(inserted.ID),
			"name":          string(inserted.Name),
		},
	}); aerr != nil {
		return nil, shared.MapRepoErr(aerr)
	}
	// FGA owner/hierarchy owner-tuple intent co-committed in the SAME writer-tx
	// (SEC-D):
	//   user:<owner>#owner@account:<id>          — owner self-grant (D-4: NOT
	//     reconstructible by the reconciler ⇒ in-tx emit is the ONLY guarantee).
	//   cluster:cluster_kacho_root#cluster@account:<id> — SEC-L cluster pointer.
	if ferr := w.EmitFGARelationWrite(ctx, ownerTuples(inserted)); ferr != nil {
		return nil, shared.MapRepoErr(ferr)
	}

	// RBAC explicit-model 2026 P6 (D-8 / C-01 / ВЗ-3): co-commit the owner
	// AccessBinding (subject=creator, role=owner, scope=ACCOUNT:<A>,
	// deletion_protection=true) in the SAME writer-tx. The FK
	// access_bindings_role_fk references the `owner` system-role (seeded by
	// migration 0035); a missing role rolls the whole tx back (account included).
	// Per-object access tuples (scope-self + content) are materialized FORWARD by
	// the reconciler after commit (the account is empty at Create, D-8a) — the
	// single materialization path; no binding-time scope_grant emission.
	ownerBindingID := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	ownerBinding := domain.AccessBinding{
		ID:                 ownerBindingID,
		SubjectType:        domain.SubjectTypeUser,
		SubjectID:          domain.SubjectID(inserted.OwnerUserID),
		RoleID:             domain.OwnerRoleID,
		ResourceType:       "account",
		ResourceID:         string(inserted.ID),
		Scope:              domain.ScopeAccount,
		GrantedByUserID:    domain.UserID(actor),
		DeletionProtection: true,
		Subjects:           []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(inserted.OwnerUserID)}},
	}
	// Self-validating-domain: assert the internally-built
	// owner-binding is well-formed BEFORE Insert — parity with the public
	// AccessBinding.Create path (which calls b.Validate()). All fields are
	// internally constructed, so a failure here means field drift, not bad input;
	// returning the error inside the worker-tx triggers Rollback (defer above),
	// fail-closed.
	if verr := ownerBinding.Validate(); verr != nil {
		return nil, shared.MapValidationErr(verr)
	}
	createdBinding, berr := w.AccessBindingsW().Insert(ctx, ownerBinding)
	if berr != nil {
		return nil, shared.MapRepoErr(berr)
	}
	if serr := w.AccessBindingsW().InsertSubjects(ctx, createdBinding.ID, ownerBinding.Subjects); serr != nil {
		return nil, shared.MapRepoErr(serr)
	}
	// Owner-binding OBJECT hierarchy parent-pointer co-committed in the SAME
	// writer-tx (parity with a regular AccessBinding.Create, tuplesForBinding/
	// hierarchyParentTuple): account:<A>#account@iam_access_binding:<id>.
	// rbac-contract-a-fix: under the FLAT OpenFGA model (Contract-A) the
	// `viewer/editor from account` ACCESS cascade on iam_access_binding was REMOVED,
	// so this pointer is the hierarchy/lineage edge only — it no longer by itself
	// grants the scope owner a path to the binding OBJECT. The owner's Get/List/Delete
	// access on its OWN owner-binding object is MATERIALIZED per-object by the
	// reconciler: the owner `*.*` ARM_ANCHOR over iam.accessBinding (now in
	// AllMaterializableTypes, iam-direct scan of the access_bindings table within the
	// account scope) covers the owner-binding row itself, emitted by the post-commit
	// ReconcileBinding below (and the periodic sweep). The pointer is retained for
	// lineage parity (and so a future cascade re-introduction would not need a
	// migration), not for access.
	if ferr := w.EmitFGARelationWrite(ctx, ownerBindingHierarchyTuples(inserted, createdBinding.ID)); ferr != nil {
		return nil, shared.MapRepoErr(ferr)
	}
	// Record the OWNER-BINDING-lifecycle tuples in the emitted-tuple ledger in the SAME
	// writer-tx (symmetric revoke). Without this the owner-binding's revoke
	// (delete.go SelectEmittedTuples) finds no rows for the owner self-grant + hierarchy
	// pointer and orphans them → standing admin via the FGA `or owner` derivation. This
	// mirrors what a regular AccessBinding.Create records (source='binding'). The SEC-L
	// cluster pointer is account-lifecycle and intentionally excluded (survives revoke).
	if lerr := w.AccessBindingsW().InsertEmittedTuples(ctx, createdBinding.ID,
		ownerBindingLedgerTuples(inserted, createdBinding.ID)); lerr != nil {
		return nil, shared.MapRepoErr(lerr)
	}
	// Per-subject audit_outbox grant event in the SAME tx (parity with
	// AccessBinding.Create's grant audit).
	if aerr := w.AccessBindingsW().EmitAuditEvent(ctx, abrepo.AuditEvent{
		EventType:       abrepo.AuditEventTypeGranted,
		Actor:           actor,
		SubjectType:     string(domain.SubjectTypeUser),
		SubjectID:       string(inserted.OwnerUserID),
		ResourceType:    "account",
		ResourceID:      string(inserted.ID),
		RoleID:          domain.OwnerRoleID,
		BindingID:       string(createdBinding.ID),
		TenantAccountID: string(inserted.ID),
	}); aerr != nil {
		return nil, shared.MapRepoErr(aerr)
	}

	if cerr := w.Commit(ctx); cerr != nil {
		return nil, shared.MapRepoErr(cerr)
	}
	committed = true

	// Post-commit: materialize the owner-binding's per-object membership (scope-self
	// verb-bearing on account:<A> + ARM_ANCHOR over content). nil-safe; the periodic
	// sweep retries otherwise. Non-fatal to Create — the account + binding are
	// durably created.
	if u.reconciler != nil {
		if rerr := u.reconciler.ReconcileBinding(ctx, createdBinding.ID); rerr != nil && u.logger != nil {
			u.logger.Error("account create: owner-binding reconcile failed (sweep will retry)",
				"account_id", string(inserted.ID), "binding_id", string(createdBinding.ID), "err", rerr)
		}
	}

	return marshalAccount(inserted)
}
