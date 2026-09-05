// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package service_account — CQRS port-iface'ы для kacho_iam.service_accounts.
package service_account

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/visibility"
)

type ReaderIface interface {
	Get(ctx context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error)
	List(ctx context.Context, filter ListFilter) ([]domain.ServiceAccount, string, error)
}

type WriterIface interface {
	Insert(ctx context.Context, sa domain.ServiceAccount) (domain.ServiceAccount, error)
	Update(ctx context.Context, sa domain.ServiceAccount, updateMask []string) (domain.ServiceAccount, error)
	Delete(ctx context.Context, id domain.ServiceAccountID) error

	// SetEnabled writes `service_accounts.enabled` — whether this service
	// account may authenticate at all.
	//
	// Separate from Update on purpose. Update carries a field mask, an EMPTY mask
	// means full replacement by convention, and a proto3 bool cannot say "not
	// sent" — so had `enabled` been made a maskable field, omitting it would have
	// disabled the account. That design was declined rather than repaired; the
	// state deciding whether a machine identity still works must not be reachable
	// by forgetting something.
	//
	// The argument is the STATE, not a transition: setting the state an account
	// is already in succeeds and reports it. A retry of a disable is a disable.
	//
	// Missing row → iamerr.ErrNotFound ("ServiceAccount <id> not found").
	SetEnabled(ctx context.Context, id domain.ServiceAccountID, enabled bool) (domain.ServiceAccount, error)
}

type ListFilter struct {
	PageSize int32
	// PageToken — токен, КАК ЕГО ПРИСЛАЛ КЛИЕНТ. Его разбирает use-case (форма
	// токена принадлежит контракту RPC, а не таблице), поэтому на пути к
	// репозиторию он пуст, а курсор приезжает разобранным в After.
	PageToken string
	Filter    string
	AccountID domain.AccountID

	// After — курсор keyset В РАЗОБРАННОМ ВИДЕ: страница начинается со строки,
	// строго следующей за (CreatedAt, ID). nil — с начала.
	//
	// Пара с PageToken взаимоисключающая по построению: одно значение выражается
	// ровно одним способом, и путь, задающий After, PageToken не задаёт.
	After *Cursor

	// Candidates — сужение НАБОРА КАНДИДАТОВ до надмножества видимого
	// вызывающему (задача #645): строка проходит, если её аккаунт назван, либо
	// названа она сама.
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
