// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package account — CQRS port-iface'ы для kacho_iam.accounts.
//
// Реализация — `internal/repo/kacho/pg/account_repo.go` (pgxpool).
// Mock — `internal/repo/repomock` (для unit-тестов use-case'ов).
package account

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/visibility"
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
	PageSize int32
	// PageToken — токен, КАК ЕГО ПРИСЛАЛ КЛИЕНТ. Его разбирает use-case (форма
	// токена принадлежит контракту RPC, а не таблице), поэтому на пути к
	// репозиторию он пуст, а курсор приезжает разобранным в After.
	PageToken string
	Filter    string // filter-syntax: name="..."

	// After — курсор keyset В РАЗОБРАННОМ ВИДЕ: страница начинается со строки,
	// строго следующей за (CreatedAt, ID). nil — с начала.
	//
	// Пара с PageToken взаимоисключающая по построению: одно значение выражается
	// ровно одним способом, и путь, задающий After, PageToken не задаёт.
	After *Cursor

	// Candidates — сужение НАБОРА КАНДИДАТОВ до надмножества видимого
	// вызывающему (задача #645).
	//
	// Аккаунт — сам себе аккаунт: строка проходит, если её id назван ЛИБО в
	// AccountIDs (аккаунты, до которых вызывающий дотягивается), ЛИБО в ObjectIDs
	// (аккаунт, названный выдачей поимённо). Оба набора сравниваются с одной и
	// той же колонкой `id`, и это не совпадение, а свойство типа.
	//
	// nil ЗНАЧИТ «не сужать», и это НЕ то же, что пустой набор: пустой не
	// называет ничего и потому не пропускает ничего. Различие — это различие
	// между администратором облака и посторонним, и оно обязано быть представимо
	// отдельно от значений.
	//
	// Сужение НЕ решает вопрос о доступе: оно отбирает кандидатов, вердикт по
	// каждому выносит модель прав (`security.md` §«Авторизация живёт в МОДЕЛИ»).
	Candidates *visibility.PageScope
}

// Cursor — граница keyset-обхода `(created_at, id) ASC`.
type Cursor struct {
	CreatedAt time.Time
	ID        string
}
