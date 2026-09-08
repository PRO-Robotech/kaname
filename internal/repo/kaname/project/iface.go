// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package project — CQRS port-iface'ы для kaname.projects.
package project

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
)

type ReaderIface interface {
	Get(ctx context.Context, id domain.ProjectID) (domain.Project, error)
	List(ctx context.Context, filter ListFilter) ([]domain.Project, string, error)
	// CountByAccount — для AccountService.Delete sync precheck.
	CountByAccount(ctx context.Context, accountID domain.AccountID) (int64, error)
}

type WriterIface interface {
	Insert(ctx context.Context, p domain.Project) (domain.Project, error)
	Update(ctx context.Context, p domain.Project, updateMask []string) (domain.Project, error)
	Delete(ctx context.Context, id domain.ProjectID) error
}

type ListFilter struct {
	PageSize int32
	// PageToken — токен, КАК ЕГО ПРИСЛАЛ КЛИЕНТ. Его разбирает use-case (форма
	// токена принадлежит контракту RPC, а не таблице), поэтому на пути к
	// репозиторию он пуст, а курсор приезжает разобранным в After.
	PageToken string
	Filter    string
	// AccountID — для List в scope'е Account (`/iam/v1/projects?accountId=...`).
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
