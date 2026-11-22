// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5"
)

// Причина остаётся внутри исполнителя; публичная ошибка сохраняет один sentinel.
type resourceChildRefusal string

const (
	childInvalidCoordinates resourceChildRefusal = "invalid_coordinates"
	childPolicyUnavailable  resourceChildRefusal = "policy_unavailable"
	childPermissionDenied   resourceChildRefusal = "permission_denied"
	childTypeUnavailable    resourceChildRefusal = "child_type_unavailable"
	childParentUnavailable  resourceChildRefusal = "parent_type_unavailable"
	childParentMissing      resourceChildRefusal = "parent_missing"
	childFinalDenied        resourceChildRefusal = "final_permission_denied"
	childParentClosed       resourceChildRefusal = "parent_closed"
	childOccupied           resourceChildRefusal = "child_occupied"
	childCapacity           resourceChildRefusal = "capacity"
	childRate               resourceChildRefusal = "rate"
)

func (e resourceChildRefusal) Error() string { return domain.ErrUserChildRegistrationRefused.Error() }
func (e resourceChildRefusal) Unwrap() error { return domain.ErrUserChildRegistrationRefused }

func (e resourceChildRefusal) valid() bool {
	switch e {
	case childInvalidCoordinates, childPolicyUnavailable, childPermissionDenied, childTypeUnavailable,
		childParentUnavailable, childParentMissing, childFinalDenied, childParentClosed, childOccupied, childCapacity, childRate:
		return true
	default:
		return false
	}
}

// Вызывается только после возврата whole-attempt: rollback завершён, lease
// освобождена. Новая ordinary TX пишет только audit, без authority admission
// и без чтения каталога, родителя, областей или состояния регистрации.
func (r *ResourceDecisionRunner) childRefusalAfterAttempt(ctx context.Context, principal operations.Principal, cause error) error {
	var reason resourceChildRefusal
	var failed *resourceAttemptError
	if ctx.Err() != nil || !errors.As(cause, &reason) || !reason.valid() ||
		(errors.As(cause, &failed) && failed.cleanup != nil) {
		return resourceChildError(ctx, cause)
	}
	verified, ok := operations.PrincipalFromContextOK(ctx)
	_, named := authzguard.SubjectFromPrincipal(verified)
	if !ok || !named || verified.Type != "user" || verified.IsAnonymous() || verified != principal {
		return resourceChildError(ctx, cause)
	}
	if err := r.recordChildRefusal(ctx, verified, reason); err != nil {
		return errors.Join(iamerr.ErrUnavailable, cause, err)
	}
	return cause
}

func (r *ResourceDecisionRunner) recordChildRefusal(ctx context.Context, principal operations.Principal, reason resourceChildRefusal) (err error) {
	if r == nil || r.repo == nil || r.repo.master == nil || !reason.valid() {
		return iamerr.ErrUnavailable
	}
	verified, ok := operations.PrincipalFromContextOK(ctx)
	_, named := authzguard.SubjectFromPrincipal(verified)
	if !ok || !named || verified.Type != "user" || verified.IsAnonymous() || verified != principal {
		return iamerr.ErrUnavailable
	}
	auditCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := r.repo.master.BeginTx(auditCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, rollbackResourceAttempt(auditCtx, tx)) }()
	// Ни сырая координата запроса, ни сведения о parent не нужны для причины.
	// Пустой tenant остаётся NULL: отказ не запускает lookup ради аудита.
	if err = insertAuditEventTx(auditCtx, tx, service.AuditEvent{
		EventType: "iam.child_registration.refused",
		Payload: map[string]any{
			"actor": "user:" + principal.ID, "outcome": "permission_denied", "reason": string(reason),
		},
	}); err != nil {
		return err
	}
	// Неизвестный исход commit не повторяется: один отказ не удваивает audit.
	return tx.Commit(auditCtx)
}
