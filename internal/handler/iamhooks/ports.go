// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ports.go — port-интерфейсы handler-слоя (Clean Architecture).
//
// Handler НЕ зависит от pgx / sqlc / grpc-stubs. Зависит только от этих
// abstract port'ов; реализации инжектируются из cmd/kaname/main.go.
package iamhooks

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
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

// UserRevocationLookup — the revoke-all cutoff. Read by BOTH hooks: once where a
// token is MINTED, and again where one is refreshed.
//
// Both is the point. The cutoff is written by an administrator forcing a user
// out, by a user revoking all of their own tokens, and by password recovery —
// and it used to be read only on the refresh path, so a live session kept
// obtaining brand-new tokens straight through a force-logout that had reported
// success. Worse for a personal access token: its grant has no refresh hook at
// all, so nothing minted through it was ever re-examined and the cutoff had no
// point of enforcement whatsoever. One port, one adapter, one row — the two
// hooks cannot answer the same question differently.
//
// Narrow on purpose. This asks "has this person been logged out of everything,
// and when?" and nothing else. The port it replaces also declared the write
// path and a per-token lookup, the latter stated as being there because "the
// same adapter implements the write path" — but what an adapter can do is not
// what a caller needs, and neither was called from this package.
type UserRevocationLookup interface {
	// UserRevokedBefore returns the cutoff recorded for a user and whether one
	// exists. The error is surfaced rather than folded into "no cutoff" so the
	// caller can fail closed: an unavailable store is not an answer of "no".
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
