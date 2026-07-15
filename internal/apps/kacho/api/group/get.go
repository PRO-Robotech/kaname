// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package group

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

type GetGroupUseCase struct {
	repo Repo
	// relations — FGA relation-Check port resolving the caller's v_get grant on
	// iam_group:<id> (Design B). nil → fail-closed; production wires it via
	// WithRelationStore.
	relations clients.RelationStore
}

func NewGetGroupUseCase(r Repo) *GetGroupUseCase {
	return &GetGroupUseCase{repo: r}
}

// WithRelationStore wires the FGA client authorizing the read via the
// verb-bearing `v_get` relation on iam_group:<id> (+ cluster-admin short-circuit).
// Without it a non-cluster-admin Get fails closed.
func (u *GetGroupUseCase) WithRelationStore(relations clients.RelationStore) *GetGroupUseCase {
	u.relations = relations
	return u
}

// Execute — sync read.
//
// Authz (Design B, D-6/D-9): the caller must hold `v_get` on iam_group:<id> OR be
// a cluster-admin. Otherwise (incl. anonymous) → NotFound (hide existence; no
// enumeration). Replaces the legacy owner-only gate that denied a delegate
// granted `iam.group.get`.
func (u *GetGroupUseCase) Execute(ctx context.Context, id domain.GroupID) (domain.Group, error) {
	if err := shared.ValidateResourceID(string(id), domain.PrefixGroup, "group"); err != nil {
		return domain.Group{}, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return domain.Group{}, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	g, err := rd.Groups().Get(ctx, id)
	if err != nil {
		return domain.Group{}, shared.MapRepoErr(err)
	}
	if !authzguard.AllowsVGet(ctx, u.relations, "iam_group", string(id)) {
		return domain.Group{}, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrNotFound, "Group %s not found", id))
	}
	return g, nil
}
