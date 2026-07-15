// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package user — CQRS port-iface'ы для kacho_iam.users.
package user

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

type ReaderIface interface {
	Get(ctx context.Context, id domain.UserID) (domain.User, error)
	GetByExternalID(ctx context.Context, ext domain.ExternalSubject) (domain.User, error)
	GetByEmail(ctx context.Context, email domain.Email) (domain.User, error)
	List(ctx context.Context, filter ListFilter) ([]domain.User, string, error)

	// GetByAccountEmail — поиск user-row в конкретном Account по email
	// (case-insensitive). Используется для idempotent Invite.
	// Возвращает ErrNotFound если row нет.
	GetByAccountEmail(ctx context.Context, accountID domain.AccountID, email domain.Email) (domain.User, error)

	// FindPendingByEmail — все PENDING-row'ы по email через все Account'ы
	// (cross-Account). Используется в `InternalUserService.UpsertFromIdentity`
	// для активации pending-invites при first-login.
	FindPendingByEmail(ctx context.Context, email domain.Email) ([]domain.User, error)

	// FindActiveByExternalID — все ACTIVE-row'ы по identity (Kratos sub) через
	// все Account'ы. Используется в UpsertFromIdentity чтобы определить,
	// нужен ли bootstrap новый Account.
	FindActiveByExternalID(ctx context.Context, externalID domain.ExternalSubject) ([]domain.User, error)

	// FindByExternalIDInStatuses — все row'ы по identity (Kratos sub) через все
	// Account'ы, ограниченные множеством invite_status'ов, ORDER BY created_at
	// ASC. В отличие от FindActiveByExternalID (ACTIVE-only), этот reader видит
	// и BLOCKED-row'ы — recovery обязан их находить и re-enable'ить
	// (InternalUserService.OnRecoveryCompleted). Пустой externalID либо пустой
	// statuses → nil-срез. Возвращает nil-срез если
	// нет ни одной row.
	FindByExternalIDInStatuses(ctx context.Context, externalID domain.ExternalSubject, statuses []domain.InviteStatus) ([]domain.User, error)

	// FindActiveByEmail — все ACTIVE-row'ы по email (case-insensitive) через
	// все Account'ы, ORDER BY created_at ASC. Используется invite-flow'ом
	// чтобы привязать project-scoped AccessBinding к тому же (старейшему
	// ACTIVE) user-row, который api-gateway резолвит из JWT invitee
	// (GetByExternalID). Возвращает nil-срез если ACTIVE-row нет.
	FindActiveByEmail(ctx context.Context, email domain.Email) ([]domain.User, error)

	// ListAccountsForUser — все Account'ы, где у user'а есть ACTIVE-row.
	// Используется для default-deny scope в `UserService.List`.
	ListAccountsForUser(ctx context.Context, userID domain.UserID) ([]domain.AccountID, error)
}

type WriterIface interface {
	// Upsert — InternalUserService.UpsertFromIdentity (legacy path; ACTIVE-only).
	// Kept for backward compatibility with tests; production-path —
	// `InsertPending` / `ActivateInvite` / `bootstrapNewIdentity` use-case.
	// Создает row если (account_id, external_id) новый, иначе UPDATE
	// email/display_name. Caller должен заполнить AccountID + InviteStatus=ACTIVE.
	Upsert(ctx context.Context, u domain.User) (domain.User, bool /*created*/, error)

	// InsertPending — атомарный idempotent INSERT PENDING-row через
	// ON CONFLICT (account_id, lower(email)) DO NOTHING.
	// Если row с таким (account_id, email) уже существует — возвращает
	// existing-row с inserted=false; display_name НЕ перезаписывается.
	InsertPending(ctx context.Context, u domain.User) (domain.User, bool /*inserted*/, error)

	// ActivateInvite — атомарный UPDATE PENDING → ACTIVE с set external_id +
	// (optional) display_name. 0 rows → ErrNotFound (row либо несуществует,
	// либо уже не PENDING — race с параллельной активацией).
	ActivateInvite(ctx context.Context, userID domain.UserID, externalID domain.ExternalSubject, displayName domain.DisplayName) (domain.User, error)

	// InsertActive — INSERT обычной ACTIVE-row (для bootstrap-flow).
	// FK violation на account_id → SQLSTATE 23503 → ErrFailedPrecondition; на
	// DEFERRABLE FK violation проверяется на COMMIT.
	InsertActive(ctx context.Context, u domain.User) (domain.User, error)

	// ReEnable — атомарный CAS BLOCKED → ACTIVE для recovery
	// (InternalUserService.OnRecoveryCompleted). Идемпотентен:
	// уже-ACTIVE row проходит без изменения статуса (re-enable — no-op, не
	// ошибка). 0 rows RETURNING → ErrNotFound (row не существует, либо PENDING —
	// recovery работает только по ACTIVE/BLOCKED). Single-statement
	// UPDATE … WHERE invite_status IN ('ACTIVE','BLOCKED') защищен row-lock'ом
	// (запрет #10, не TOCTOU). Возвращает (re-enabled row, wasBlocked).
	ReEnable(ctx context.Context, userID domain.UserID) (domain.User, bool /*wasBlocked*/, error)

	// Delete — UserService.Delete. RESTRICT если у user'а есть Account'ы /
	// GroupMember'ы / AccessBinding'и.
	Delete(ctx context.Context, id domain.UserID) error

	// UpdateLabels — атомарный UPDATE tenant-facing меток (единственное mutable
	// поле User через публичный UpdateUser RPC). Single-statement
	// `UPDATE users SET labels = $2 WHERE id = $1 RETURNING …` защищен row-lock'ом
	// (запрет #10 — last-writer-wins, не TOCTOU). 0 rows RETURNING → ErrNotFound.
	// Identity-поля (external_id и пр.) этим путем не меняются.
	UpdateLabels(ctx context.Context, id domain.UserID, labels domain.Labels) (domain.User, error)
}

type ListFilter struct {
	PageSize  int32
	PageToken string
	Filter    string // filter-syntax: email="..." | externalId="..."

	// AccountID — фильтр по конкретному Account (default-deny scope).
	// Пустой → no per-account filter (caller обязан добавить AccountIDs).
	AccountID domain.AccountID
	// AccountIDs — множественный фильтр (список Account'ов, где principal является
	// member; используется в `UserService.List` без explicit account_id).
	AccountIDs []domain.AccountID
}
