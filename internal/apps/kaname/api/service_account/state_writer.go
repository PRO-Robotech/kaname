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

func (u *EnableServiceAccountUseCase) WithServiceAccountStateWriter(f kaname.ServiceAccountStateWriterFactory) *EnableServiceAccountUseCase {
	u.stateConfigured, u.stateFactory = true, f
	return u
}
func (u *DisableServiceAccountUseCase) WithServiceAccountStateWriter(f kaname.ServiceAccountStateWriterFactory) *DisableServiceAccountUseCase {
	u.stateConfigured, u.stateFactory = true, f
	return u
}
func (u *setEnabledServiceAccountUseCase) stateRepo(id domain.ServiceAccountID) Repo {
	if !u.stateConfigured {
		return u.repo
	}
	return metadataUpdateRepo{Repo: u.repo, open: func(ctx context.Context) (Writer, error) {
		if u.stateFactory == nil {
			return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "Service account state writer unavailable")
		}
		w, err := u.stateFactory.ServiceAccountStateWriter(ctx, id, u.enabled, grantpolicy.Actor(ctx))
		if err != nil {
			return nil, err
		}
		if w == nil {
			return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "Service account state writer unavailable")
		}
		return w, nil
	}}
}
