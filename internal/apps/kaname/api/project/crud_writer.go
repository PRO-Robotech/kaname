// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package project

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

func (u *CreateProjectUseCase) WithProjectCreateWriter(f kaname.ProjectCreateWriterFactory) *CreateProjectUseCase {
	u.crudConfigured, u.crudFactory = true, f
	return u
}
func (u *CreateProjectUseCase) crudRepo(target domain.Project) Repo {
	if !u.crudConfigured {
		return u.repo
	}
	return crudWriterRepo{Repo: u.repo, open: func(ctx context.Context) (Writer, error) {
		if u.crudFactory == nil {
			return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "ProjectCreate authority writer unavailable")
		}
		w, err := u.crudFactory.ProjectCreateWriter(ctx, target, grantpolicy.Actor(ctx))
		if err != nil {
			return nil, err
		}
		if w == nil {
			return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "ProjectCreate authority writer unavailable")
		}
		return w, nil
	}}
}

func (u *DeleteProjectUseCase) WithProjectDeleteWriter(f kaname.ProjectDeleteWriterFactory) *DeleteProjectUseCase {
	u.crudConfigured, u.crudFactory = true, f
	return u
}
func (u *DeleteProjectUseCase) crudRepo(id domain.ProjectID) Repo {
	if !u.crudConfigured {
		return u.repo
	}
	return crudWriterRepo{Repo: u.repo, open: func(ctx context.Context) (Writer, error) {
		if u.crudFactory == nil {
			return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "ProjectDelete authority writer unavailable")
		}
		w, err := u.crudFactory.ProjectDeleteWriter(ctx, id, grantpolicy.Actor(ctx))
		if err != nil {
			return nil, err
		}
		if w == nil {
			return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "ProjectDelete authority writer unavailable")
		}
		return w, nil
	}}
}
