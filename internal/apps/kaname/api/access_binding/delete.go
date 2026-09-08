// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
//     `w.AccessBindings().SelectEmittedTuples(id)`, MINUS the tuples another
//     ACTIVE binding still claims (partitionRevokeSet — revoke_set.go). Reading
//     the ledger instead of re-deriving keeps the revoke faithful to what was
//     actually emitted at grant / last reconcile even if the binding's role
//     permissions changed in between (a re-derive would orphan the originally-
//     granted tuples); subtracting the surviving claims keeps it from deleting a
//     non-refcounted relation fact that a sibling ACTIVE binding also grants.
//
// ОТЗЫВ ДЕЙСТВУЕТ С КОММИТА, и догоняющего пути для этого не нужно.
//   - Строка снятия, положенная в журнал намерений ТОЙ ЖЕ writer-tx, снимает
//     прямой факт триггером журнала — в том же коммите. Прежде здесь стоял
//     синхронный пост-коммитный вызов в чужое хранилище: он закрывал окно между
//     коммитом и дренажом, пока право продолжало действовать. Хранилища нет
//     (стадия S6, эпик #747) — нет ни окна, ни того, кого догонять.
//   - Снимается ровно тот же набор, что и прежде: emitted-set МИНУС всё, что ещё
//     держит другая ACTIVE-привязка.

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

type DeleteAccessBindingUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// relations — ДВЕРЬ РЕШЕНИЯ, и только на READ-стороне: `requireGrantAuthority`
	// спрашивает, вправе ли вызывающий снимать эту выдачу.
	//
	// Писать через неё больше нельзя и не нужно: синхронное удаление кортежей из
	// чужого хранилища снято вместе с хранилищем (стадия S6, эпик #747), а строка
	// журнала, положенная writer-tx, снимает прямой факт триггером — в том же
	// коммите. nil-safe: непровязанная дверь означает отказ отвечать, а не «доступ
	// есть».
	relations clients.RelationStore
	logger    *slog.Logger
}

func NewDeleteAccessBindingUseCase(r Repo, opsRepo operations.Repo) *DeleteAccessBindingUseCase {
	return &DeleteAccessBindingUseCase{repo: r, opsRepo: opsRepo}
}

// WithRelationStore подключает ДВЕРЬ РЕШЕНИЯ. Она нужна на READ-стороне:
// `requireGrantAuthority` спрашивает, вправе ли вызывающий снимать эту выдачу.
// Синхронного applier'а снятия за ней больше нет — см. разбор в шапке файла.
// Logger остаётся для диагностики самой проверки прав.
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
	// Take the binding's EXCLUSIVE xact advisory lock FIRST — the same
	// pg_advisory_xact_lock(hashtext(binding_id)) key the reconciler's FULL pass uses
	// (reconcile_adapter.go AcquireBindingLock). Взаимное исключение с полным проходом,
	// истечением срока и параллельным отзывом этим держится.
	//
	// ЧЕГО ЭТА БЛОКИРОВКА БОЛЬШЕ НЕ ДАЁТ — И ЭТО НАДО ЗНАТЬ, А НЕ ДОСТРАИВАТЬ.
	// Здесь стояло утверждение, что EXCLUSIVE разводит отзыв с аддитивным форвардом,
	// потому что тот держит SHARE-блокировку того же ключа. **Форвард не берёт
	// advisory-блокировку вовсе** (снята 2026-08-05, см. reconcile/forward.go «LOCK
	// CHOICE»), поэтому у EXCLUSIVE на этой стороне не осталось контрагента: два
	// утверждения об одном предмете, из которых верным было одно, и верным — не это.
	// Комментарий приведён к коду; сам разъезд отзыва с пост-коммитной записью форварда
	// в хранилище прав — открытая задача (её предмет наблюдаем как кортежи, которых не
	// держит ни одна выдача), и закрывается она упорядочиванием ПРИМЕНЕНИЯ, а не
	// возвратом блокировки: применение к хранилищу прав у обеих сторон происходит ПОСЛЕ
	// коммита, то есть заведомо вне любой xact-блокировки.
	if err := w.AdvisoryXactLock(ctx, string(id)); err != nil {
		return nil, shared.MapRepoErr(err)
	}
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
	// what THIS binding emitted at grant / last reconcile — the candidate revoke-set,
	// narrowed just below by whatever another ACTIVE binding still claims. Read on THIS
	// writer-tx BEFORE the binding DELETE (the FK ON DELETE CASCADE drops the ledger
	// rows on delete).
	stored, err := w.AccessBindings().SelectEmittedTuples(ctx, id)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// CROSS-BINDING SHARED TUPLES (access-loss fix). The ledger is keyed PER binding
	// while a relation fact is not refcounted, so replaying `stored` verbatim would
	// delete access ANOTHER ACTIVE binding of the same subject still grants — and
	// nothing would ever re-write it (the ledger is read as the mirror of the store).
	// Subtract the tuples another ACTIVE binding still claims; the rest is this
	// binding's true revoke-set (see revoke_set.go).
	revokeTuples, retained, err := partitionRevokeSet(ctx, w.AccessBindings(), id, stored)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	if len(retained) > 0 && u.logger != nil {
		u.logger.Info("access_binding delete: tuples retained — still granted by another ACTIVE binding",
			"binding_id", string(id), "retained_count", len(retained), "revoked_count", len(revokeTuples))
	}

	// RBAC explicit-model 2026 P6 (C-04): atomic CAS backstop against TOCTOU —
	// `DELETE … WHERE deletion_protection=false`. If a concurrent Update re-armed
	// protection between the sync pre-check and here, DeleteGuarded returns
	// FAILED_PRECONDITION and the binding stays (the row-lock serializes them).
	if err := w.AccessBindingsW().DeleteGuarded(ctx, id); err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Atomic revoke emit-in-tx. Tx rollback ⇒ neither the binding row is
	// gone NOR is the outbox row visible to drainer. The at-least-once async
	// backstop carries the SAME cross-binding-filtered set as the sync removal
	// below — otherwise the drainer would strip a still-claimed tuple seconds
	// after the sync path correctly kept it.
	if err := w.AccessBindingsW().EmitRelationDelete(ctx, revokeTuples); err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Симметрия созданию (kacho#2055): создание со-коммитит событие реконсайла,
	// которым материализуется пообъектный кортеж владельца, — снятие обязано
	// со-коммитить ОТЗЫВ в ту же writer-tx. Каскад `ON DELETE` его не заменяет:
	// он ключуется по идентификатору ПРИВЯЗКИ, а не снятого объекта. Воркер на
	// событие зовёт `ReconcileObject`, а тот на отсутствующем объекте получает
	// пустой желаемый набор — что и есть отзыв.
	// Снятие ВЫПУЩЕННЫХ кортежей выше — не то же самое: оно снимает набор,
	// который эмитировала САМА привязка. Событие отзывает пообъектные
	// кортежи, которые материализовали ДРУГИЕ привязки НА этом объекте.
	if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventDelete, "iam.accessBinding", string(id)); rerr != nil {
		return nil, shared.MapRepoErr(rerr)
	}
	// Emit subject_change_outbox row in the same TX as the deletion: a rollback
	// of this TX will not leave an orphan outbox row (atomicity guarantee).
	// НА КАЖДОГО субъекта привязки, а не на легаси-одиночку: см.
	// emitSubjectChangeForEverySubject.
	if err := emitSubjectChangeForEverySubject(ctx, w.AccessBindings().ListSubjects, w.AccessBindingsW().EmitSubjectChangeEvent,
		deletedBinding, "binding_revoke", "binding_delete"); err != nil {
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

	// ЗДЕСЬ СТОЯЛО СИНХРОННОЕ УДАЛЕНИЕ КОРТЕЖЕЙ ИЗ ВНЕШНЕГО ДВИЖКА — предмета нет.
	//
	// Оно существовало ради ЛАТЕНТНОСТИ: строка намерения, положенная в журнал той же
	// транзакцией, доезжала до движка дренажом, и до этого момента отозванный доступ
	// продолжал отвечать «есть». Быстрый путь закрывал окно, журнал оставался доставкой
	// «хотя бы один раз».
	//
	// Окна больше нет: прямой факт складывается из ТОЙ ЖЕ строки журнала триггером —
	// в ТОЙ ЖЕ транзакции, что и снятие выдачи. Отзыв действует С КОММИТА не «быстрее»,
	// а по построению, и догонять его вторым писателем нечего.

	return anypb.New(&emptypb.Empty{})
}
