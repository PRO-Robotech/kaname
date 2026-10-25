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

// doRevoke — делегирование и его выдачи одной транзакцией писателя, аудит в ней
// же (Р4, Р5).
func (u *RevokeGrantDelegationUseCase) doRevoke(ctx context.Context, id domain.GrantDelegationID, by domain.GrantDelegationActor, actor string) (*anypb.Any, error) {
	revoked, err := shared.DoWithWriteTx(ctx, u.repo, func(ctx context.Context, w Writer) (domain.GrantDelegation, error) {
		gw := w.AccessBindingsW().GrantDelegationsW()
		if _, lerr := gw.LockForRevoke(ctx, id); lerr != nil {
			return domain.GrantDelegation{}, lerr
		}
		at := time.Now().UTC()
		d, merr := gw.MarkRevoked(ctx, id, by, at)
		if merr != nil {
			return domain.GrantDelegation{}, merr
		}
		count, werr := accessbindingapp.WithdrawDelegatedBindings(ctx, w, d, actor, at)
		if werr != nil {
			return domain.GrantDelegation{}, werr
		}
		if aerr := w.EmitAuditEvent(ctx, outboxtypes.AuditEvent{
			EventType:       auditEventRevoked,
			TenantAccountID: string(d.AccountID),
			Payload: map[string]any{
				"actor":                 actor,
				"delegation_id":         string(d.ID),
				"account_id":            string(d.AccountID),
				"revoked_binding_count": count,
			},
		}); aerr != nil {
			return domain.GrantDelegation{}, aerr
		}
		return d, nil
	})
	if err != nil {
		return nil, err
	}
	return marshalGD(revoked)
}
