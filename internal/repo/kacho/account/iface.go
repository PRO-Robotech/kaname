// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package account — CQRS port-iface'ы для kacho_iam.accounts.
//
// Реализация — `internal/repo/kacho/pg/account_repo.go` (pgxpool).
// Mock — `internal/repo/repomock` (для unit-тестов use-case'ов).
package account

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// ReaderIface — read-only методы.
type ReaderIface interface {
	Get(ctx context.Context, id domain.AccountID) (domain.Account, error)
	List(ctx context.Context, filter ListFilter) ([]domain.Account, string /*next_page_token*/, error)
	// ExistsByName — для idempotency-precheck в InternalIAMService.LookupSubject
	// (DB UNIQUE — backstop).
	ExistsByName(ctx context.Context, name domain.AccountName) (bool, error)

	// CountAccountsByOwner — число account'ов, которыми владеет user
	// (accounts.owner_user_id == ownerUserID). Backing для
	// bootstrap-gate «owns-zero-accounts»: любой разрешенный/активированный
	// user-row без собственного account'а получает personal default Account +
	// "default" Project. Читает существующую колонку owner_user_id (миграции
	// нет). Неизвестный user → 0, не ошибка.
	CountAccountsByOwner(ctx context.Context, ownerUserID domain.UserID) (int, error)
}

// WriterIface — mutation.
type WriterIface interface {
	Insert(ctx context.Context, a domain.Account) (domain.Account, error)
	Update(ctx context.Context, a domain.Account, updateMask []string) (domain.Account, error)
	Delete(ctx context.Context, id domain.AccountID) error
}

// ListFilter — параметры List-RPC (ListAccountsRequest).
// Set of fields and filter-string parsing through kacho-corelib/filter.
type ListFilter struct {
	PageSize  int32
	PageToken string
	Filter    string // filter-syntax: name="..."
}
