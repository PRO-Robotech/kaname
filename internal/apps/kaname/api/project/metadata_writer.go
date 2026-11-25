// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package project

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// WithProjectMetadataWriter выбирает подготовленный порт для всех правок.
// Явный nil означает отказ, а не возврат к обычному writer.
func (u *UpdateProjectUseCase) WithProjectMetadataWriter(f kaname.ProjectMetadataWriterFactory) *UpdateProjectUseCase {
	u.metadataConfigured, u.metadataFactory = true, f
	u.metadataLabelsOnly = false
	return u
}

// WithProjectLabelAuthorityWriter защищает только намерение записать labels.
// Маска без labels сохраняет обычный путь; nil для меток означает отказ.
// Пустая persistence-маска включает labels и потому тоже требует этот порт.
func (u *UpdateProjectUseCase) WithProjectLabelAuthorityWriter(f kaname.ProjectMetadataWriterFactory) *UpdateProjectUseCase {
	u.metadataConfigured, u.metadataFactory = true, f
	u.metadataLabelsOnly = true
	return u
}

type metadataUpdateRepo struct {
	Repo
	factory any
	open    func(context.Context) (Writer, error)
}

func (r metadataUpdateRepo) Writer(ctx context.Context) (Writer, error) { return r.open(ctx) }

// Отдельный порт обязателен даже при наличии обычного metadata writer.
func (u *UpdateProjectUseCase) accessLabelsWriter() kaname.ProjectAccessLabelsWriterFactory {
	if u == nil || !u.metadataConfigured || u.metadataLabelsOnly {
		return nil
	}
	writer, _ := u.metadataFactory.(kaname.ProjectAccessLabelsWriterFactory)
	return writer
}

// Один предикат выбирает защищённый порт и обязательность его фактической дельты.
func (u *UpdateProjectUseCase) metadataRequired(mask []string) bool {
	return shared.AccessLabelsMaskRequested(mask) ||
		(u.metadataConfigured && (!u.metadataLabelsOnly || shared.MaskAllows(mask, "labels")))
}

func (u *UpdateProjectUseCase) metadataRepo(target domain.Project, mask []string) Repo {
	if !u.metadataRequired(mask) {
		return u.repo
	}
	return metadataUpdateRepo{Repo: u.repo, factory: u.metadataFactory, open: func(ctx context.Context) (Writer, error) {
		if u.metadataFactory == nil {
			return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "Metadata authority writer unavailable")
		}
		actor := grantpolicy.Actor(ctx)
		var w kaname.SemanticAuthorityWriter
		var err error
		if shared.AccessLabelsMaskRequested(mask) {
			writer := u.accessLabelsWriter()
			if writer == nil {
				return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "Protected accessLabels writer unavailable")
			}
			w, err = writer.ProjectAccessLabelsWriter(ctx, target, mask, actor)
		} else {
			w, err = u.metadataFactory.ProjectMetadataWriter(ctx, target, mask, actor)
		}
		if err != nil {
			return nil, err
		}
		if w == nil {
			return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "Metadata authority writer unavailable")
		}
		return w, nil
	}}
}

func (r metadataUpdateRepo) RunPreparedWrite(ctx context.Context, action func(context.Context, kaname.Writer) error) error {
	return shared.ExecuteConfiguredPreparedWrite(ctx, r.factory, r.open, action)
}
