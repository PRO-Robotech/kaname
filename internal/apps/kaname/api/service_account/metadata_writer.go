// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package service_account

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// WithServiceAccountMetadataWriter explicitly selects the prepared UPDATE port.
// A configured nil port fails closed; the default constructor remains staged.
func (u *UpdateServiceAccountUseCase) WithServiceAccountMetadataWriter(f kaname.ServiceAccountMetadataWriterFactory) *UpdateServiceAccountUseCase {
	u.metadataConfigured, u.metadataFactory = true, f
	u.metadataLabelsOnly = false
	return u
}

// Legacy entry защищает намерение записать labels, оставляя прочие поля на прежнем пути.
func (u *UpdateServiceAccountUseCase) WithServiceAccountLabelAuthorityWriter(f kaname.ServiceAccountMetadataWriterFactory) *UpdateServiceAccountUseCase {
	u.metadataConfigured, u.metadataFactory, u.metadataLabelsOnly = true, f, true
	return u
}

type metadataUpdateRepo struct {
	Repo
	factory any
	open    func(context.Context) (Writer, error)
}

func (r metadataUpdateRepo) Writer(ctx context.Context) (Writer, error) { return r.open(ctx) }
func (u *UpdateServiceAccountUseCase) accessLabelsWriter() kaname.ServiceAccountAccessLabelsWriterFactory {
	if u == nil || !u.metadataConfigured || u.metadataLabelsOnly {
		return nil
	}
	writer, _ := u.metadataFactory.(kaname.ServiceAccountAccessLabelsWriterFactory)
	return writer
}

func (u *UpdateServiceAccountUseCase) metadataRequired(mask []string) bool {
	return shared.AccessLabelsMaskRequested(mask) || (u.metadataConfigured && (!u.metadataLabelsOnly || shared.MaskAllows(mask, "labels")))
}

func (u *UpdateServiceAccountUseCase) metadataRepo(target domain.ServiceAccount, mask []string) Repo {
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
			w, err = writer.ServiceAccountAccessLabelsWriter(ctx, target, mask, actor)
		} else {
			w, err = u.metadataFactory.ServiceAccountMetadataWriter(ctx, target, mask, actor)
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
