// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grant_delegation

// list.go — ListGrantDelegationsUseCase (GD-61).

import (
	"context"

	"github.com/PRO-Robotech/corelib/safeconv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	gdrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/grant_delegation"
)

// ListGrantDelegationsUseCase — делегирования аккаунта.
type ListGrantDelegationsUseCase struct {
	repo      Repo
	relations clients.RelationStore
}

// NewListGrantDelegationsUseCase — над хранилищем службы.
func NewListGrantDelegationsUseCase(r Repo) *ListGrantDelegationsUseCase {
	return &ListGrantDelegationsUseCase{repo: r}
}

// WithRelationStore — дверь решения: право выдавать на аккаунте.
func (u *ListGrantDelegationsUseCase) WithRelationStore(relations clients.RelationStore) *ListGrantDelegationsUseCase {
	u.relations = relations
	return u
}

// ListInput — вход перечня.
type ListInput struct {
	AccountID string
	PageSize  int64
	PageToken string
}

// Execute — форма страницы ПЕРВОЙ, в этой же функции и до права
// (`shared.ValidateRawPagination`, единственный производитель отказов формы
// страницы, §0.10в приёмки); затем аккаунт, право выдавать на нём и страница
// курсором `(created_at, id)`.
func (u *ListGrantDelegationsUseCase) Execute(ctx context.Context, in ListInput) ([]domain.GrantDelegation, string, error) {
	if err := shared.ValidateRawPagination(in.PageToken, in.PageSize); err != nil {
		return nil, "", err
	}
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, "", err
	}
	if in.AccountID == "" {
		return nil, "", shared.InvalidArg("account_id", "account_id: required")
	}
	if err := shared.ValidateResourceID(in.AccountID, domain.PrefixAccount, "account"); err != nil {
		return nil, "", err
	}
	account := domain.AccountID(in.AccountID)
	if err := requireAccountGrantAuthority(ctx, u.repo, u.relations, account); err != nil {
		return nil, "", err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	rows, next, err := rd.AccessBindings().GrantDelegations().List(ctx, account, gdrepo.PageFilter{
		PageSize:  safeconv.ClampNonNegInt32(in.PageSize),
		PageToken: in.PageToken,
	})
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	return rows, next, nil
}
