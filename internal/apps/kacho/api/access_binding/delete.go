// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// delete.go — DeleteAccessBindingUseCase.
// 0 rows → NotFound (repo возвращает ErrNotFound).
//
// Atomic revoke notes:
//   - The FGA tuple deletion is queued via
//     `w.AccessBindingsW().EmitRelationDelete(ctx, stored)` inside the same
//     writer-tx as the binding delete. Tx rollback ⇒ no orphan fga_outbox
//     rows AND no orphan binding state.
//   - The revoked tuple set is the PERSISTED emitted-set
//     (access_binding_emitted_tuples — F3/#178), read via
//     `w.AccessBindings().SelectEmittedTuples(id)`. This makes the revoke
//     byte-symmetric to what was actually emitted at grant / last reconcile,
//     even if the binding's role permissions changed in between (re-deriving
//     from the CURRENT role would orphan the originally-granted tuples).
//
// Синхронный revoke (паритет латентности с grant):
//   - После commit writer-tx тот же persisted emitted-set удаляется из OpenFGA
//     синхронно через подключенный RelationStore (DeleteTuples). Это зеркало
//     grant-пути, который материализует FGA-tuples сразу после commit: deny
//     наблюдается как только Operation становится done, а не с задержкой async
//     fga_outbox drain. In-tx EmitRelationDelete + drainer остаются at-least-once
//     backstop; DeleteTuples идемпотентен (отсутствующий tuple ⇒ success), поэтому
//     повторное удаление дренером — no-op. Удаляется ровно тот же набор, что и
//     async-путь, так что cross-binding-поведение не меняется — только тайминг.

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	abrepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

type DeleteAccessBindingUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// relations — подключенный OpenFGA RelationStore. Используется на READ-стороне
	// (requireGrantAuthority — delegated-admin grant-authority через FGA admin) И
	// для СИНХРОННОГО revoke: после commit writer-tx тот же persisted emitted-set
	// удаляется из OpenFGA через DeleteTuples (паритет латентности с grant). Async
	// EmitRelationDelete + drainer — at-least-once backstop. nil-safe: при unwired
	// клиенте sync-удаление пропускается, остается только async drain.
	relations clients.RelationStore
	logger    *slog.Logger
}

func NewDeleteAccessBindingUseCase(r Repo, opsRepo operations.Repo) *DeleteAccessBindingUseCase {
	return &DeleteAccessBindingUseCase{repo: r, opsRepo: opsRepo}
}

// WithRelationStore подключает OpenFGA RelationStore. Он нужен на READ-стороне
// (requireGrantAuthority — delegated-admin authority через FGA admin) И как
// синхронный applier revoke: после commit writer-tx persisted emitted-set
// удаляется из OpenFGA через DeleteTuples (паритет латентности с grant). Logger —
// для диагностики сбоев sync-удаления.
func (u *DeleteAccessBindingUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *DeleteAccessBindingUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

func (u *DeleteAccessBindingUseCase) Execute(ctx context.Context, id domain.AccessBindingID) (*operations.Operation, error) {
	// Anti-anon guard.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if err := shared.ValidateResourceID(string(id), domain.PrefixAccessBinding, "access binding"); err != nil {
		return nil, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	binding, err := rd.AccessBindings().Get(ctx, id)
	_ = rd.Rollback(ctx)
	if err != nil {
		if stderrors.Is(err, iamerr.ErrNotFound) {
			// Non-existent AB → PermissionDenied (not NotFound) to prevent
			// existence-leakage. The authz-deny garbage-per-resource scope expects 403
			// for all subjects including authenticated non-owners.
			return nil, authzguard.PermissionDenied()
		}
		// Any OTHER Get failure (transient DB fault) is NOT existence-hiding —
		// map it to its real, retriable/terminal gRPC code (shared.MapRepoErr),
		// not the non-retriable PermissionDenied a client would never retry.
		return nil, shared.MapRepoErr(err)
	}
	// AUTHZ FIRST (#4/#6 — security-ordering). requireGrantAuthority MUST run before
	// any state-dependent response (the deletion_protection pre-check below),
	// otherwise an authenticated caller WITHOUT grant authority who targets a
	// protected binding would receive the friendly FAILED_PRECONDITION
	// "deletion_protection enabled" instead of PermissionDenied — leaking that the
	// binding (a) exists and (b) is protected, contradicting the uniform-403
	// existence-leak protection the not-found branch above enforces. Only a caller
	// who is actually allowed to delete the binding may observe its protection state.
	//
	// requireGrantAuthority is the exact mirror of Create's authority rule. A
	// self-only IsSelf(subjectID) form would reject legitimate admin-revokes (an
	// account/project owner could grant a role to user X but could not revoke it).
	// With grant-authority: admin can grant AND revoke; subject self-revoke trivially
	// passes the owner path when the binding is on their own account, or the FGA admin
	// path when the binding is on a resource they admin.
	if err := requireGrantAuthority(ctx, u.repo, u.relations,
		string(binding.ResourceType), binding.ResourceID); err != nil {
		return nil, err
	}
	// RBAC explicit-model 2026 P6 (D-10 / C-02): sync deletion_protection
	// pre-check for a friendly FAILED_PRECONDITION on the request path (before any
	// Operation is created) — reached ONLY by an authorized deleter (authz ran
	// above). The async worker additionally runs an atomic CAS backstop
	// (DeleteGuarded) against the TOCTOU window (C-04).
	if binding.DeletionProtection {
		return nil, status.Errorf(codes.FailedPrecondition,
			"access binding %s has deletion_protection enabled; clear it via Update before Delete", id)
	}
	// Capture the authenticated caller as the revoke actor NOW (sync path —
	// the principal is in ctx here, not necessarily in the async worker ctx).
	// Anti-spoofing: sourced from PrincipalFromContext, never a request field.
	actor := authzguard.PrincipalUserID(ctx)
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Delete access binding %s", id),
		// account_id NARROW-SCOPE (D-9): only account-scoped bindings (the loaded
		// binding's ResourceType=="account") carry account_id; project/cluster
		// bindings leave it empty (SQL NULL). auditTenantAccountID is the single
		// decision point shared with the audit_outbox tenant scope.
		&iamv1.DeleteAccessBindingMetadata{AccessBindingId: string(id), AccountId: auditTenantAccountID(binding)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doDelete(ctx, id, actor)
	})
	return &op, nil
}

func (u *DeleteAccessBindingUseCase) doDelete(ctx context.Context, id domain.AccessBindingID, actor string) (*anypb.Any, error) {
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
	// Read the binding's subject_id within the writer TX before deletion,
	// so we can emit the outbox row atomically.
	deletedBinding, err := w.AccessBindings().Get(ctx, id)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// F3/#178 — SYMMETRIC revoke from the PERSISTED emitted-set, NOT a re-derive
	// from the binding's CURRENT role. The role's permissions may have changed
	// (Role.Update) between grant and revoke; re-deriving would emit
	// EmitRelationDelete on the NEW tuple set and orphan the originally-granted
	// ones (standing privilege). access_binding_emitted_tuples records exactly
	// what was emitted at grant / last reconcile, so deleting that set is
	// byte-symmetric to what is live in OpenFGA. Read on THIS writer-tx BEFORE the
	// binding DELETE (the FK ON DELETE CASCADE drops the ledger rows on delete).
	stored, err := w.AccessBindings().SelectEmittedTuples(ctx, id)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}

	// RBAC explicit-model 2026 P6 (C-04): atomic CAS backstop against TOCTOU —
	// `DELETE … WHERE deletion_protection=false`. If a concurrent Update re-armed
	// protection between the sync pre-check and here, DeleteGuarded returns
	// FAILED_PRECONDITION and the binding stays (the row-lock serializes them).
	if err := w.AccessBindingsW().DeleteGuarded(ctx, id); err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Atomic revoke emit-in-tx. Tx rollback ⇒ neither the binding row is
	// gone NOR is the outbox row visible to drainer.
	if err := w.AccessBindingsW().EmitRelationDelete(ctx, stored); err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Emit subject_change_outbox row in the same TX as the deletion: a rollback
	// of this TX will not leave an orphan outbox row (atomicity guarantee).
	if err := w.AccessBindingsW().EmitSubjectChangeEvent(ctx, abrepo.SubjectChangeEvent{
		SubjectID:    string(deletedBinding.SubjectID),
		EventType:    "binding_revoke",
		Op:           "binding_delete",
		ResourceType: string(deletedBinding.ResourceType),
		ResourceID:   string(deletedBinding.ResourceID),
	}); err != nil {
		return nil, shared.MapRepoErr(err)
	}

	// Emit the durable audit_outbox compliance event in the SAME writer-tx
	// (запрет #10). Actor = the authenticated revoker (captured sync), falling
	// back to the original granter when the caller identity is unknown so the
	// trail is never empty. Atomic with the DELETE: a rolled-back revoke leaves
	// no audit row claiming the access was removed.
	revokeActor := actor
	if revokeActor == "" {
		revokeActor = string(deletedBinding.GrantedByUserID)
	}
	if err := w.AccessBindingsW().EmitAuditEvent(ctx, abrepo.AuditEvent{
		EventType:       abrepo.AuditEventTypeRevoked,
		Actor:           revokeActor,
		SubjectType:     string(deletedBinding.SubjectType),
		SubjectID:       string(deletedBinding.SubjectID),
		ResourceType:    string(deletedBinding.ResourceType),
		ResourceID:      deletedBinding.ResourceID,
		RoleID:          string(deletedBinding.RoleID),
		BindingID:       string(deletedBinding.ID),
		TenantAccountID: auditTenantAccountID(deletedBinding),
	}); err != nil {
		return nil, shared.MapRepoErr(err)
	}
	if err := w.Commit(ctx); err != nil {
		return nil, shared.MapRepoErr(err)
	}
	committed = true

	// Синхронное удаление tuples из OpenFGA — зеркало post-commit FGA-материализации
	// grant'а. Async EmitRelationDelete (заэнкューенный в writer-tx выше) остается
	// at-least-once backstop; применение того же revoke-набора к OpenFGA сразу после
	// commit делает deny наблюдаемым к моменту Operation done, не дожидаясь outbox
	// drain (revoke ≈ grant по латентности). Идемпотентно: DeleteTuples трактует
	// отсутствующий tuple как success, поэтому последующий async-drain тех же строк —
	// no-op. nil-safe: при unwired RelationStore остается только async-путь.
	// Best-effort/non-fatal: binding уже удален durable, ошибку логируем — backstop
	// сходит за идемпотентный повтор.
	if u.relations != nil && len(stored) > 0 {
		if derr := u.syncRemoveTuples(ctx, toClientTuples(stored)); derr != nil && u.logger != nil {
			u.logger.Warn("access_binding delete: synchronous FGA tuple-removal failed after retries; async drain will backstop",
				"binding_id", string(id), "tuple_count", len(stored), "err", derr)
		}
	}

	return anypb.New(&emptypb.Empty{})
}

// syncRemoveBaseDelay / syncRemoveMaxAttempts — параметры bounded retry синхронного
// revoke. Worker-ctx detached (без deadline запроса), поэтому общий бюджет ретраев
// (~3s при экспоненте 100ms→max 1s) не блокирует запрос — он давно вернул Operation.
const (
	syncRemoveBaseDelay   = 100 * time.Millisecond
	syncRemoveMaxAttempts = 6
)

// syncRemoveTuples синхронно удаляет revoke-набор из OpenFGA с ограниченным retry.
//
// Grant материализует FGA-tuples надежно (reconciler sync-write); revoke обязан быть
// ему симметричен по надежности. Одиночный best-effort DeleteTuples под нагрузкой мог
// транзиентно упасть — и тогда deny ждал отставший async fga_outbox drain (revoke-deny
// convergence > bounded poll на нагруженном CI). Bounded retry доводит удаление до успеха
// на транзиентном сбое OpenFGA, поэтому deny наблюдается к моменту Operation done.
//
// Идемпотентно: DeleteTuples трактует отсутствующий tuple как success, поэтому повтор —
// no-op. После исчерпания попыток возвращает последнюю ошибку (caller логирует non-fatal;
// async EmitRelationDelete остается at-least-once backstop). Прерывается на отмене ctx
// (graceful shutdown).
func (u *DeleteAccessBindingUseCase) syncRemoveTuples(ctx context.Context, tuples []clients.RelationTuple) error {
	delay := syncRemoveBaseDelay
	var err error
	for attempt := 1; attempt <= syncRemoveMaxAttempts; attempt++ {
		if err = u.relations.DeleteTuples(ctx, tuples); err == nil {
			return nil
		}
		if attempt == syncRemoveMaxAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if delay < time.Second {
			delay *= 2
		}
	}
	return err
}

// toClientTuples переводит persisted emitted-set (abrepo.RelationTuple) в
// clients.RelationTuple для синхронного DeleteTuples. Оба типа структурно
// идентичны {User, Relation, Object}; это адаптер на границе слоев.
func toClientTuples(in []abrepo.RelationTuple) []clients.RelationTuple {
	out := make([]clients.RelationTuple, len(in))
	for i, t := range in {
		out[i] = clients.RelationTuple{User: t.User, Relation: t.Relation, Object: t.Object}
	}
	return out
}
