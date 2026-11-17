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

// WithProjectMetadataWriter explicitly selects the prepared UPDATE port.
// A configured nil port fails closed; the default constructor remains staged.
func (u *UpdateProjectUseCase) WithProjectMetadataWriter(f kaname.ProjectMetadataWriterFactory) *UpdateProjectUseCase {
	u.metadataConfigured, u.metadataFactory = true, f
	return u
}

type metadataUpdateRepo struct {
	Repo
	open func(context.Context) (Writer, error)
}

func (r metadataUpdateRepo) Writer(ctx context.Context) (Writer, error) { return r.open(ctx) }
func (u *UpdateProjectUseCase) metadataRepo(target domain.Project, mask []string) Repo {
	if !u.metadataConfigured {
		return u.repo
	}
	return metadataUpdateRepo{Repo: u.repo, open: func(ctx context.Context) (Writer, error) {
		if u.metadataFactory == nil {
			return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "Metadata authority writer unavailable")
		}
		w, err := u.metadataFactory.ProjectMetadataWriter(ctx, target, mask, grantpolicy.Actor(ctx))
		if err != nil {
			return nil, err
		}
		if w == nil {
			return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "Metadata authority writer unavailable")
		}
		return w, nil
	}}
}
