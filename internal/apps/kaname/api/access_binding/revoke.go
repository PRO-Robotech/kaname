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
// Снятие кортежей — как у Delete: строки снятия на СОХРАНЁННЫЙ реестр выдачи
// (access_binding_emitted_tuples), а не на набор, выведенный из ТЕКУЩЕЙ роли, —
// поэтому Role.Update между выдачей и отзывом кортежей не осиротит. Не снимает ли это
// доступ, который даёт другая действующая выдача того же субъекта, решает не
// use-case, а свёртка строки снятия: под замком строки факта, свежим снимком
// (миграция 20261019180000, kaname#919). Снимок соседей, прочитанный здесь до
// вставки строки, устаревал раньше, чем применялся.
// Writer-транзакция отзыва открывается EXCLUSIVE advisory-замком выдачи, а строку
// выдачи берёт `FOR UPDATE` до чтения реестра (см. doRevoke): первый разводит отзыв
// с полным проходом, истечением и вторым отзывом, второй — с аддитивным форвардом,
// который advisory не берёт и решает «выдача жива» под `FOR KEY SHARE` (kaname#923).
// Отзыв действует С КОММИТА: строка снятия, положенная в журнал намерений ТОЙ ЖЕ
// writer-tx, снимает прямой факт триггером журнала. Прежде здесь был синхронный
// пост-коммитный вызов в чужое хранилище — он закрывал окно до дренажа; хранилища
// нет (стадия S6, эпик kacho#747), окна нет, догоняющего пути нет.
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

	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

type RevokeAccessBindingUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// relations — ДВЕРЬ РЕШЕНИЯ на READ-стороне (`requireGrantAuthority`).
	//
	// Синхронного снятия кортежей через неё больше нет: чужого хранилища не
	// существует, а строка журнала снимает прямой факт в том же коммите, что и
	// отзыв (стадия S6, эпик kacho#747).
	relations clients.RelationStore
	logger    *slog.Logger
	// delegated — делегированный путь права выдавать (kaname#986, Р2); nil —
	// выключен.
	delegated *DelegatedGrantPath
}

// WithDelegatedGrantPath — делегат отзывает выдачи своего делегирования
// (kaname#986, Р2). Провязывает корень службы.
func (u *RevokeAccessBindingUseCase) WithDelegatedGrantPath(p *DelegatedGrantPath) *RevokeAccessBindingUseCase {
	u.delegated = p
	return u
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
	//
	// Право отозвать и удалить (kaname#986, Р1а, Р2): прежний вопрос двери
	// слушателя (`v_delete` на объекте выдачи) переехал сюда дословно, вместе с
	// правом выдавать на области; делегат проходит только по выдаче своего
	// действующего делегирования (`removalAuthority`).
	if err := removalAuthority(ctx, u.repo, u.relations, u.delegated, binding); err != nil {
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
	// ПОРЯДОК ЗАМКОВ транзакции отзыва — тот же, что у удаления и истечения срока
	// (reconcile.ExpireBinding):
	//
	//	1  advisory-замок выдачи   pg_advisory_xact_lock(hashtext(id)) — против полного прохода, истечения, второго отзыва
	//	2  строка access_bindings   FOR UPDATE (GetForDeactivation) — против аддитивного форварда
	//	3  строка access_bindings   CAS RevokeGuarded — уже покрыт шагом 2
	//	4  дочерние строки и журналы  чтение реестра, строки журналов намерений, смены субъекта, аудита
	//
	// Шаг 1 — та же пара ключа, что у полного прохода (AcquireBindingLock): ни один из
	// названных путей не вклинится между снимком реестра и коммитом. Аддитивный форвард
	// advisory не берёт (reconcile/forward.go «LOCK CHOICE») и решает «выдача жива»
	// чтением под `FOR KEY SHARE`, а пишет члена, реестр и строку журнала позже, в своей
	// транзакции. Применение к прямому факту у обеих сторон идёт В ТОЙ ЖЕ транзакции —
	// триггером журнала намерений, — поэтому порядок держит строчный замок шага 2: из
	// режимов строки только `FOR UPDATE` конфликтует с `FOR KEY SHARE`. Без него CAS
	// (`FOR NO KEY UPDATE`) с форвардом не пересекался, реестр читался до записи
	// форварда, и прямой факт форварда переживал отзыв (kaname#923). Строк каталога
	// (`catalog_module`, `catalog_resource`, порядок 2р→2а→4 применителей, kaname#913)
	// транзакция не берёт, поэтому ребра ожидания с ними нет.
	//
	// Замка строки мало: исход снятия решает и ВЕРСИЯ строки журнала — свёртка в
	// прямой факт снимает факт, лишь если его версия не новее версии строки снятия.
	// Строка снятия несёт момент своей вставки, а не начало транзакции
	// (fga_outbox, deleteStamp): иначе снятие, открывшее транзакцию раньше форварда и
	// получившее строку после его коммита, писало бы строку старше факта, и факт её
	// переживал. Оба порядка начала транзакций держит
	// reconcile_deactivation_order_race_integration_test.go.
	if err := w.AdvisoryXactLock(ctx, string(id)); err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Строка выдачи — под замком снятия (шаг 2), она же даёт измерения событий.
	binding, err := w.AccessBindingsW().GetForDeactivation(ctx, id)
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
	// Читается ПОСЛЕ замка строки и CAS: форвард, решивший «выдача жива», к этому
	// моменту зафиксирован, и его записи реестра входят в снимаемый набор; форвард,
	// пришедший позже, прочитает выдачу REVOKED и писать не станет.
	stored, err := w.AccessBindings().SelectEmittedTuples(ctx, id)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Строки снятия — на ВЕСЬ реестр выдачи. Общий кортеж, который держит другая
	// действующая выдача, свёртка строки не снимает: вопрос о держателях она задаёт
	// под замком строки факта, после коммита любого, кто держит эту строку
	// (kaname#919). Выдача к этому моменту уже REVOKED, поэтому свой реестр её факт
	// не держит.
	if err := w.AccessBindingsW().EmitRelationDelete(ctx, stored); err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Subject-change outbox (authz-cache invalidation — access removed).
	// НА КАЖДОГО субъекта привязки, а не на легаси-одиночку: см.
	// emitSubjectChangeForEverySubject.
	subjects, err := bindingSubjectsOf(ctx, w.AccessBindings().ListSubjects, binding)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	if err := emitSubjectChangeFor(ctx, w.AccessBindingsW().EmitSubjectChangeEvent, subjects,
		"binding_revoke", "binding_delete"); err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Durable compliance audit event in the SAME writer-tx (ban #10) — на каждого
	// субъекта, симметрично аудиту создания.
	if err := revokedAuditFor(ctx, w, subjects, revokeActor, binding); err != nil {
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
