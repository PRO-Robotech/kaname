// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package service_account

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

func (u *CreateServiceAccountUseCase) WithServiceAccountCreateWriter(f kaname.ServiceAccountCreateWriterFactory) *CreateServiceAccountUseCase {
	u.crudConfigured, u.crudFactory = true, f
	return u
}
func (u *CreateServiceAccountUseCase) crudRepo(target domain.ServiceAccount) Repo {
	if !u.crudConfigured {
		return u.repo
	}
	return crudWriterRepo{Repo: u.repo, open: func(ctx context.Context) (Writer, error) {
		if u.crudFactory == nil {
			return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "ServiceAccountCreate authority writer unavailable")
		}
		w, err := u.crudFactory.ServiceAccountCreateWriter(ctx, target, grantpolicy.Actor(ctx))
		if err != nil {
			return nil, err
		}
		if w == nil {
			return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "ServiceAccountCreate authority writer unavailable")
		}
		return w, nil
	}}
}

func (u *DeleteServiceAccountUseCase) WithServiceAccountDeleteWriter(f kaname.ServiceAccountDeleteWriterFactory) *DeleteServiceAccountUseCase {
	u.crudConfigured, u.crudFactory = true, f
	return u
}
func (u *DeleteServiceAccountUseCase) crudRepo(id domain.ServiceAccountID) Repo {
	if !u.crudConfigured {
		return u.repo
	}
	return crudWriterRepo{Repo: u.repo, open: func(ctx context.Context) (Writer, error) {
		if u.crudFactory == nil {
			return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "ServiceAccountDelete authority writer unavailable")
		}
		w, err := u.crudFactory.ServiceAccountDeleteWriter(ctx, id, grantpolicy.Actor(ctx))
		if err != nil {
			return nil, err
		}
		if w == nil {
			return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "ServiceAccountDelete authority writer unavailable")
		}
		return w, nil
	}}
}
