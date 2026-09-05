// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service_account

import (
	"context"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

type GetServiceAccountUseCase struct {
	repo Repo
	// relations — FGA relation-Check port resolving the caller's v_get grant on
	// iam_service_account:<id> (Design B). nil → fail-closed; production wires it
	// via WithRelationStore.
	relations clients.RelationStore
}

func NewGetServiceAccountUseCase(r Repo) *GetServiceAccountUseCase {
	return &GetServiceAccountUseCase{repo: r}
}

// WithRelationStore wires the FGA client authorizing the read via the
// verb-bearing `v_get` relation on iam_service_account:<id> (+ cluster-admin
// short-circuit). Without it a non-cluster-admin Get fails closed.
func (u *GetServiceAccountUseCase) WithRelationStore(relations clients.RelationStore) *GetServiceAccountUseCase {
	u.relations = relations
	return u
}

// Execute — sync read.
//
// Authz (Design B, D-6/D-9): the caller must hold `v_get` on
// iam_service_account:<id> OR be a cluster-admin. Otherwise (incl. anonymous) →
// NotFound (hide existence). Replaces the legacy owner-only gate that denied a
// delegate granted `iam.serviceAccount.get`.
func (u *GetServiceAccountUseCase) Execute(ctx context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error) {
	if err := shared.ValidateResourceID(string(id), domain.PrefixServiceAccount, "service account"); err != nil {
		return domain.ServiceAccount{}, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return domain.ServiceAccount{}, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	sa, err := rd.ServiceAccounts().Get(ctx, id)
	if err != nil {
		return domain.ServiceAccount{}, shared.MapRepoErr(err)
	}
	allowed, azErr := authzguard.AllowsVGet(ctx, u.relations, "iam_service_account", string(id))
	if azErr != nil {
		// The read gate could not be evaluated. Not a denial, and above all not
		// "does not exist" — say so, and let the client retry.
		return domain.ServiceAccount{}, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	if !allowed {
		return domain.ServiceAccount{}, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrNotFound, "ServiceAccount %s not found", id))
	}
	return sa, nil
}
