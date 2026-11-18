// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package role

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Явный prepared порт владеет целой транзакцией конкретного UC.
// Не настроенный старый конструктор сохраняет прежний путь; настроенный nil
// никогда не возвращается к raw Writer.
type crudWriterRepo struct {
	Repo
	factory any
	open func(context.Context) (Writer, error)
}

func (r crudWriterRepo) Writer(ctx context.Context) (Writer, error) { return r.open(ctx) }

func (u *DeleteRoleUseCase) WithRoleDeleteWriter(f kaname.RoleDeleteWriterFactory) *DeleteRoleUseCase {
	u.crudConfigured, u.crudFactory = true, f
	return u
}
func (u *DeleteRoleUseCase) crudRepo(id domain.RoleID) Repo {
	if !u.crudConfigured {
		return u.repo
	}
	return crudWriterRepo{Repo: u.repo, factory: u.crudFactory, open: func(ctx context.Context) (Writer, error) {
		if u.crudFactory == nil {
			return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "RoleDelete authority writer unavailable")
		}
		w, err := u.crudFactory.RoleDeleteWriter(ctx, id, grantpolicy.Actor(ctx))
		if err != nil {
			return nil, err
		}
		if w == nil {
			return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "RoleDelete authority writer unavailable")
		}
		return w, nil
	}}
}

func (r crudWriterRepo) RunPreparedWrite(ctx context.Context, action func(context.Context, kaname.Writer) error) error {
	return shared.ExecuteConfiguredPreparedWrite(ctx, r.factory, r.open, action)
}
