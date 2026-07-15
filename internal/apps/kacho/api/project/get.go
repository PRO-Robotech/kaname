// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package project

// get.go — GetProjectUseCase. Sync read.

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

type GetProjectUseCase struct {
	repo Repo
	// relations — FGA relation-Check port resolving the caller's v_get grant on
	// project:<id> (Design B). nil → fail-closed; production wires it via
	// WithRelationStore.
	relations clients.RelationStore
}

func NewGetProjectUseCase(r Repo) *GetProjectUseCase {
	return &GetProjectUseCase{repo: r}
}

// WithRelationStore wires the FGA client authorizing the read via the
// verb-bearing `v_get` relation on project:<id> (+ cluster-admin short-circuit).
// Mirrors ListProjectsUseCase. Without it a non-cluster-admin Get fails closed.
func (u *GetProjectUseCase) WithRelationStore(relations clients.RelationStore) *GetProjectUseCase {
	u.relations = relations
	return u
}

// Execute — sync read.
//
// Authz (Design B, D-6/D-9): the caller must hold `v_get` on project:<id> OR be
// a cluster-admin. Otherwise (incl. anonymous) → NotFound (hide existence).
// Replaces the prior authenticated-pass-through guard, which exposed every
// project's metadata to any authenticated caller.
func (u *GetProjectUseCase) Execute(ctx context.Context, id domain.ProjectID) (domain.Project, error) {
	if err := shared.ValidateResourceID(string(id), domain.PrefixProject, "project"); err != nil {
		return domain.Project{}, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return domain.Project{}, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	p, err := rd.Projects().Get(ctx, id)
	if err != nil {
		return domain.Project{}, shared.MapRepoErr(err)
	}
	if !authzguard.AllowsVGet(ctx, u.relations, "project", string(id)) {
		return domain.Project{}, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrNotFound, "Project %s not found", id))
	}
	return p, nil
}
