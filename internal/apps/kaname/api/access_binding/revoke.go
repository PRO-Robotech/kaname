// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// revoke.go — RevokeAccessBindingUseCase (redesign-2026 F10 IAM-1-28).
//
// SOFT-revoke, contrast with Delete=HARD (delete.go):
//   - Delete physically removes the row (Get→NotFound).
//   - Revoke RETAINS the row, transitioning status ACTIVE→REVOKED (terminal) and
//     stamping revoked_at / revoked_by_user_id for audit-retention (Get still
//     returns the row, status=REVOKED). Either way the emitted FGA-tuple set is
//     removed in the same writer-tx, so access is denied once the Operation is
//     done — the two paths differ only in row-retention, not in access outcome.
//
// The tuple-removal is identical to Delete: it revokes the PERSISTED emitted-set
// (access_binding_emitted_tuples) MINUS whatever another ACTIVE binding still claims
// (partitionRevokeSet), not a re-derive from the binding's CURRENT role — so a
// Role.Update between grant and revoke cannot orphan tuples, and a sibling ACTIVE
// binding's access is never stripped along with this one's.
// "The SAME writer-tx" opens with the binding's EXCLUSIVE advisory lock (see doRevoke).
// Здесь стояло, что этим отзыв разведён с аддитивным форвардом, «берущим SHARE-близнеца
// того же ключа». Форвард advisory-блокировку НЕ БЕРЁТ (снята 2026-08-05, см.
// reconcile/forward.go «LOCK CHOICE»), поэтому утверждение описывало код, которого нет;
// оставшийся разъезд назван у doRevoke и открыт как отдельная задача.
// Отзыв действует С КОММИТА: строка снятия, положенная в журнал намерений ТОЙ ЖЕ
// writer-tx, снимает прямой факт триггером журнала. Прежде здесь был синхронный
// пост-коммитный вызов в чужое хранилище — он закрывал окно до дренажа; хранилища
// нет (стадия S6, эпик #747), окна нет, догоняющего пути нет.
// Because revoked rows carry revoked_at, the partial active-grant UNIQUE
// (access_bindings_active_grant_uniq WHERE revoked_at IS NULL) frees the slot, so
// an identical re-grant Create afterwards is a NEW ACTIVE row (IAM-1-29).

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

type RevokeAccessBindingUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// relations — ДВЕРЬ РЕШЕНИЯ на READ-стороне (`requireGrantAuthority`).
	//
	// Синхронного снятия кортежей через неё больше нет: чужого хранилища не
	// существует, а строка журнала снимает прямой факт в том же коммите, что и
	// отзыв (стадия S6, эпик #747).
	relations clients.RelationStore
	logger    *slog.Logger
}

func NewRevokeAccessBindingUseCase(r Repo, opsRepo operations.Repo) *RevokeAccessBindingUseCase {
	return &RevokeAccessBindingUseCase{repo: r, opsRepo: opsRepo}
}

// WithRelationStore wires the decision door (read-side grant-authority;
// synchronous revoke applier). Logger diagnoses sync-removal failures.
func (u *RevokeAccessBindingUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *RevokeAccessBindingUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

func (u *RevokeAccessBindingUseCase) Execute(ctx context.Context, id domain.AccessBindingID) (*operations.Operation, error) {
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
			// Existence-hiding: non-existent AB → PermissionDenied (mirror Delete),
			// so an authenticated non-owner cannot distinguish absent vs unauthorized.
			return nil, authzguard.PermissionDenied()
		}
		return nil, shared.MapRepoErr(err)
	}
	// AUTHZ FIRST (security-ordering): grant-authority MUST run before the
	// deletion_protection state-dependent response, otherwise a caller without
	// authority learns the binding exists AND is protected. Exact mirror of Delete.
	if err := requireGrantAuthority(ctx, u.repo, u.relations,
		string(binding.ResourceType), binding.ResourceID); err != nil {
		return nil, err
	}
	// Sync deletion_protection pre-check for a friendly FAILED_PRECONDITION on the
	// request path (before any Operation), reached ONLY by an authorized revoker.
	// The async worker additionally runs the atomic CAS backstop (RevokeGuarded
	// `… AND deletion_protection=false`) against the TOCTOU window. Mirror of Delete.
	if binding.DeletionProtection {
		return nil, status.Errorf(codes.FailedPrecondition,
			"access binding %s has deletion_protection enabled; clear it via Update before revoke", id)
	}
	// Capture the authenticated caller as the revoke actor NOW (sync path — the
	// principal is in ctx here, not necessarily in the async worker ctx).
	actor := authzguard.PrincipalUserID(ctx)
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Revoke access binding %s", id),
		// account_id NARROW-SCOPE: only account-scoped bindings carry account_id
		// (auditTenantAccountID); project/cluster bindings leave it empty (NULL).
		&iamv1.RevokeAccessBindingMetadata{AccessBindingId: string(id), AccountId: auditTenantAccountID(binding)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doRevoke(ctx, id, actor)
	})
	return &op, nil
}

func (u *RevokeAccessBindingUseCase) doRevoke(ctx context.Context, id domain.AccessBindingID, actor string) (*anypb.Any, error) {
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
	// Take the binding's EXCLUSIVE xact advisory lock as the FIRST statement of the
	// writer-tx — the SAME pg_advisory_xact_lock(hashtext(binding_id)) key the
	// reconciler's FULL pass uses (reconcile_adapter.go AcquireBindingLock). Этим
	// держится взаимное исключение отзыва с полным проходом, истечением срока и вторым
	// отзывом: ни один из них не вклинится между снимком реестра и коммитом.
	//
	// ЧТО ЭТА БЛОКИРОВКА НЕ ЗАКРЫВАЕТ (сказано прямо, чтобы следующий не достроил).
	// Прежняя редакция объясняла её тем, что аддитивный форвард берёт SHARE-близнеца
	// того же ключа. Форвард advisory-блокировку не берёт вовсе (снята 2026-08-05,
	// reconcile/forward.go «LOCK CHOICE»), поэтому контрагента у EXCLUSIVE на этой
	// стороне нет. Существенно же то, что ни одна xact-блокировка и не могла бы это
	// закрыть: применение к хранилищу прав у ОБЕИХ сторон — и у выдачи, и у отзыва —
	// происходит ПОСЛЕ коммита своей транзакции, то есть заведомо вне блокировки.
	// Значит порядок применения обязан обеспечиваться на уровне применения, а не
	// транзакции; предмет наблюдаем как кортежи, которых не держит ни одна выдача, и
	// ведётся отдельной задачей.
	if err := w.AdvisoryXactLock(ctx, string(id)); err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Read the binding within the writer-tx for the event dimensions.
	binding, err := w.AccessBindings().Get(ctx, id)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// The revoker identity for both the CAS (revoked_by_user_id — CHECK requires
	// non-empty with status=REVOKED) and the audit event. Falls back to the
	// original granter, then a system marker, so the CAS never fails on an empty
	// actor and the audit trail is never blank.
	revokeActor := actor
	if revokeActor == "" {
		revokeActor = string(binding.GrantedByUserID)
	}
	if revokeActor == "" {
		revokeActor = "system:revoke"
	}
	// Atomic CAS soft-revoke honoring deletion_protection + status='ACTIVE'
	// (RevokeGuarded). 0 rows → mapped FailedPrecondition/NotFound.
	revoked, err := w.AccessBindingsW().RevokeGuarded(ctx, id, domain.UserID(revokeActor))
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// SYMMETRIC revoke from the PERSISTED emitted-set (what THIS binding emitted at
	// grant / last reconcile) — NOT a re-derive from the CURRENT role.
	// Read AFTER the CAS so the snapshot is taken with the row already REVOKED:
	// defense-in-depth on top of the advisory lock above, so no ledger row added
	// while the binding was still ACTIVE can fall outside the delete-set.
	stored, err := w.AccessBindings().SelectEmittedTuples(ctx, id)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// CROSS-BINDING SHARED TUPLES (access-loss fix, mirror of Delete): the ledger is
	// per-binding while a relation fact is not refcounted, so subtract the tuples
	// another ACTIVE binding still claims — a soft revoke must not strip access a
	// sibling ACTIVE binding independently grants (see revoke_set.go).
	revokeTuples, retained, err := partitionRevokeSet(ctx, w.AccessBindings(), id, stored)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	if len(retained) > 0 && u.logger != nil {
		u.logger.Info("access_binding revoke: tuples retained — still granted by another ACTIVE binding",
			"binding_id", string(id), "retained_count", len(retained), "revoked_count", len(revokeTuples))
	}
	// Atomic revoke emit-in-tx (same writer-tx as the status transition). Carries the
	// SAME cross-binding-filtered set as the post-commit sync removal below.
	if err := w.AccessBindingsW().EmitRelationDelete(ctx, revokeTuples); err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Subject-change outbox (authz-cache invalidation — access removed).
	// НА КАЖДОГО субъекта привязки, а не на легаси-одиночку: см.
	// emitSubjectChangeForEverySubject.
	if err := emitSubjectChangeForEverySubject(ctx, w.AccessBindings().ListSubjects, w.AccessBindingsW().EmitSubjectChangeEvent,
		binding, "binding_revoke", "binding_delete"); err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Durable compliance audit event in the SAME writer-tx (ban #10).
	if err := w.AccessBindingsW().EmitAuditEvent(ctx, abrepo.AuditEvent{
		EventType:       abrepo.AuditEventTypeRevoked,
		Actor:           revokeActor,
		SubjectType:     string(binding.SubjectType),
		SubjectID:       string(binding.SubjectID),
		ResourceType:    string(binding.ResourceType),
		ResourceID:      binding.ResourceID,
		RoleID:          string(binding.RoleID),
		BindingID:       string(binding.ID),
		TenantAccountID: auditTenantAccountID(binding),
	}); err != nil {
		return nil, shared.MapRepoErr(err)
	}
	if err := w.Commit(ctx); err != nil {
		return nil, shared.MapRepoErr(err)
	}
	committed = true

	// Синхронного удаления кортежей из движка здесь больше нет — разбор тот же, что в
	// delete.go: прямой факт снимается триггером в той же транзакции, что и отзыв.

	pb, err := abToPb(revoked)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return anypb.New(pb)
}
