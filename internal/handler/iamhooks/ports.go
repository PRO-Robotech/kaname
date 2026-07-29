// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// ports.go — port-интерфейсы handler-слоя (Clean Architecture).
//
// Handler НЕ зависит от pgx / sqlc / grpc-stubs. Зависит только от этих
// abstract port'ов; реализации инжектируются из cmd/kacho-iam/main.go.
package iamhooks

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// UserLookupPort — read-side dependency для token/refresh hooks.
//
// FindByExternalID возвращает ВСЕ row для identity (Kratos sub) через все
// Account-ы, в любом состоянии. Для multi-Account membership берётся первый
// row, который вправе аутентифицироваться (default active account); явный
// выбор аккаунта через `account_id` hint — будущее расширение.
//
// ACTIVE-фильтрующего варианта здесь СОЗНАТЕЛЬНО нет. Он отвечает «дай
// пригодные строки», тогда как хук спрашивает «в каком состоянии субъект»:
// заблокированный пользователь возвращался пустым результатом, и два хука
// читали эту пустоту противоположно — один отказывал, второй принимал за
// «зеркало ещё не доехало» и выдавал урезанный набор claims. Вердикт выносит
// domain.InviteStatus.MayAuthenticate по прочитанной строке.
type UserLookupPort interface {
	FindByExternalID(ctx context.Context, externalID domain.ExternalSubject) ([]domain.User, error)
	GetByID(ctx context.Context, id domain.UserID) (domain.User, error)
}

// SessionRevocationsWriter — revocation lookups for the refresh-hook gate.
//
//   - IsRevoked          — per-jti exact revocation (single-token logout).
//   - UserRevokedBefore  — per-user revoke-all cutoff; the refresh-hook denies a
//     token whose session auth_time is at-or-before this cutoff. Backs admin
//     ForceLogout + Revoke(revoke_all_user_tokens). Returns (cutoff, found, err);
//     err is surfaced so the hook fails closed on a lookup error.
//
// Revoke stays on the port because the same adapter implements the write path.
type SessionRevocationsWriter interface {
	Revoke(ctx context.Context, rev domain.SessionRevocation, revokedBy domain.UserID) error
	IsRevoked(ctx context.Context, jti string) (bool, error)
	UserRevokedBefore(ctx context.Context, userID string) (time.Time, bool, error)
}

// AuditEmitter — append-only audit log.
type AuditEmitter interface {
	Emit(ctx context.Context, evt AuditEvent) error
}

// AuditEvent — structured event для audit_outbox.
type AuditEvent struct {
	EventType       string
	TenantAccountID string
	Payload         map[string]any
}
