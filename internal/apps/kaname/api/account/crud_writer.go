// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package account

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Явный prepared порт заменяет только открытие транзакции конкретного UC.
// Не настроенный старый конструктор сохраняет прежний путь; настроенный nil
// никогда не возвращается к raw Writer.
type crudWriterRepo struct {
	Repo
	open func(context.Context) (Writer, error)
}

func (r crudWriterRepo) Writer(ctx context.Context) (Writer, error) { return r.open(ctx) }

func (u *CreateAccountUseCase) WithAccountCreateWriter(f kaname.AccountCreateWriterFactory) *CreateAccountUseCase {
	u.crudConfigured, u.crudFactory = true, f
	return u
}
func (u *CreateAccountUseCase) crudRepo(request kaname.AccountCreateAuthority) Repo {
	if !u.crudConfigured {
		return u.repo
	}
	return crudWriterRepo{Repo: u.repo, open: func(ctx context.Context) (Writer, error) {
		if u.crudFactory == nil {
			return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "AccountCreate authority writer unavailable")
		}
		w, err := u.crudFactory.AccountCreateWriter(ctx, request, grantpolicy.Actor(ctx))
		if err != nil {
			return nil, err
		}
		if w == nil {
			return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "AccountCreate authority writer unavailable")
		}
		return w, nil
	}}
}

func (u *DeleteAccountUseCase) WithAccountDeleteWriter(f kaname.AccountDeleteWriterFactory) *DeleteAccountUseCase {
	u.crudConfigured, u.crudFactory = true, f
	return u
}
func (u *DeleteAccountUseCase) crudRepo(id domain.AccountID) Repo {
	if !u.crudConfigured {
		return u.repo
	}
	return crudWriterRepo{Repo: u.repo, open: func(ctx context.Context) (Writer, error) {
		if u.crudFactory == nil {
			return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "AccountDelete authority writer unavailable")
		}
		w, err := u.crudFactory.AccountDeleteWriter(ctx, id, grantpolicy.Actor(ctx))
		if err != nil {
			return nil, err
		}
		if w == nil {
			return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "AccountDelete authority writer unavailable")
		}
		return w, nil
	}}
}
