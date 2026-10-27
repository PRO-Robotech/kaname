// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grant_delegation

// revoke.go — RevokeGrantDelegationUseCase (GD-40…GD-44, GD-51; Р4 приёмки).
//
// Отзыв делегирования в ОДНОЙ транзакции переводит делегирование в REVOKED и
// каждую его действующую выдачу — в REVOKED с причиной DELEGATION_REVOKED, со
// всеми следствиями отзыва (`accessbindingapp.WithdrawDelegatedBindings`).
// Порядок замков: строка делегирования `FOR UPDATE` первой — запись выдачи
// делегатом держит её `FOR SHARE` и, дождавшись фиксации отзыва, выдачу по
// отозванному делегированию не пишет (Т-D1); затем выдачи делегирования
// `FOR UPDATE` по возрастанию id.

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// RevokeGrantDelegationUseCase — отзыв делегирования.
type RevokeGrantDelegationUseCase struct {
	repo      Repo
	opsRepo   operations.Repo
	relations clients.RelationStore
	logger    *slog.Logger
}

// NewRevokeGrantDelegationUseCase — над хранилищем и операциями службы.
func NewRevokeGrantDelegationUseCase(r Repo, opsRepo operations.Repo) *RevokeGrantDelegationUseCase {
	return &RevokeGrantDelegationUseCase{repo: r, opsRepo: opsRepo}
}

// WithRelationStore — дверь решения: право выдавать на аккаунте делегирования.
func (u *RevokeGrantDelegationUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *RevokeGrantDelegationUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

// Execute — форма идентификатора; несуществующее делегирование и отказ в праве —
// побайтово одинаковый `PERMISSION_DENIED` (GD-43 b, GD-44); право — право
// выдавать на аккаунте делегирования (делегат своё делегирование не отзывает);
// повторный отзыв — `FAILED_PRECONDITION` синхронно, с CAS-страховкой в
// исполнителе.
func (u *RevokeGrantDelegationUseCase) Execute(ctx context.Context, id domain.GrantDelegationID) (*operations.Operation, error) {
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if err := validateDelegationID(id); err != nil {
		return nil, err
	}
	d, err := loadDelegation(ctx, u.repo, id)
	if err != nil {
		return nil, err
	}
	if err := requireAccountGrantAuthority(ctx, u.repo, u.relations, d.AccountID); err != nil {
		return nil, err
	}
	if !d.Active() {
		return nil, status.Errorf(codes.FailedPrecondition, "grant delegation %s is already revoked", id)
	}
	caller := operations.PrincipalFromContext(ctx)
	by := domain.GrantDelegationActor{Type: caller.Type, ID: caller.ID}
	actor := authzguard.PrincipalUserID(ctx)
	op, err := operations.NewFromContext(ctx, domain.PrefixOperationIAM,
		fmt.Sprintf("Revoke grant delegation %s", id),
		&iamv1.RevokeGrantDelegationMetadata{GrantDelegationId: string(id), AccountId: string(d.AccountID)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		res, derr := u.doRevoke(ctx, id, by, actor)
		if derr != nil && u.logger != nil {
			u.logger.Error("grant_delegation revoke operation failed", "op", op.ID, "err", derr,
				"grant_delegation", string(id))
		}
		return res, derr
	})
	return &op, nil
}

// revokeAttempts — сколько раз тело отзыва исполняет СВОЮ транзакцию, если база
// откатила её как сторону взаимной блокировки либо конфликта сериализации
// (находка ревью SD-986-I1). Отзыв не берёт advisory-замков выдач (CE-10) и
// делит строки выдач и прямых фактов с фоновой материализацией; цикл ожиданий
// база разрывает откатом одной стороны ЦЕЛИКОМ, и отзыв права у делегата не
// обязан проигрывать фоновой работе. Повтор безопасен по построению: тело — одна
// транзакция записи, после коммита ничего не делает, на 40P01/40001 откатилось
// целиком. Признак повтора — `iamerr.ErrAborted`, и только он. Число и отступ —
// те же, что у снятия выдачи и по тому же основанию (`deleteAttempts`,
// `access_binding/delete.go`, kaname#679).
const revokeAttempts = 3

// revokeRetryBackoff — отступ перед следующей попыткой: выжившей стороне цикла
// нужно дойти до коммита.
const revokeRetryBackoff = 50 * time.Millisecond

// doRevoke — делегирование и его выдачи одной транзакцией писателя, аудит в ней
// же (Р4, Р5); жертва взаимной блокировки исполняется заново.
func (u *RevokeGrantDelegationUseCase) doRevoke(ctx context.Context, id domain.GrantDelegationID, by domain.GrantDelegationActor, actor string) (*anypb.Any, error) {
	for attempt := 1; ; attempt++ {
		revoked, err := u.revokeOnce(ctx, id, by, actor)
		if err == nil {
			return marshalGD(revoked)
		}
		if !stderrors.Is(err, iamerr.ErrAborted) || attempt == revokeAttempts {
			return nil, shared.MapRepoErrAt(ctx, err)
		}
		if u.logger != nil {
			u.logger.WarnContext(ctx, "grant_delegation revoke: transaction lost a concurrent-change conflict, retrying",
				"grant_delegation", string(id), "attempt", attempt, "of", revokeAttempts)
		}
		timer := time.NewTimer(time.Duration(attempt) * revokeRetryBackoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, shared.MapRepoErrAt(ctx, ctx.Err())
		case <-timer.C:
		}
	}
}

// revokeOnce — ОДНА транзакция отзыва. Отказы возвращаются НЕпереведёнными в
// статус: признак повтора читает [RevokeGrantDelegationUseCase.doRevoke], перевод
// в gRPC-код — там же, один раз.
func (u *RevokeGrantDelegationUseCase) revokeOnce(ctx context.Context, id domain.GrantDelegationID, by domain.GrantDelegationActor, actor string) (domain.GrantDelegation, error) {
	w, err := u.repo.Writer(ctx)
	if err != nil {
		return domain.GrantDelegation{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = w.Rollback(ctx)
		}
	}()
	gw := w.AccessBindingsW().GrantDelegationsW()
	if _, err := gw.LockForRevoke(ctx, id); err != nil {
		return domain.GrantDelegation{}, err
	}
	at := time.Now().UTC()
	d, err := gw.MarkRevoked(ctx, id, by, at)
	if err != nil {
		return domain.GrantDelegation{}, err
	}
	count, err := accessbindingapp.WithdrawDelegatedBindings(ctx, w, d, actor, at)
	if err != nil {
		return domain.GrantDelegation{}, err
	}
	if err := w.EmitAuditEvent(ctx, outboxtypes.AuditEvent{
		EventType:       auditEventRevoked,
		TenantAccountID: string(d.AccountID),
		Payload: map[string]any{
			"actor":                 actor,
			"delegation_id":         string(d.ID),
			"account_id":            string(d.AccountID),
			"revoked_binding_count": count,
		},
	}); err != nil {
		return domain.GrantDelegation{}, err
	}
	if err := w.Commit(ctx); err != nil {
		return domain.GrantDelegation{}, err
	}
	committed = true
	return d, nil
}
