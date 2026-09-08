// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// get.go — GetUserUseCase (public RPC; sync read).

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

type GetUserUseCase struct {
	repo Repo
	// relations — FGA relation-Check port resolving the caller's v_get grant on
	// iam_user:<id> (Design B). nil → fail-closed (only self passes); production
	// wires it via WithRelationStore.
	relations clients.RelationStore
}

func NewGetUserUseCase(r Repo) *GetUserUseCase {
	return &GetUserUseCase{repo: r}
}

// WithRelationStore wires the FGA client authorizing a cross-user read via the
// verb-bearing `v_get` relation on iam_user:<id> (+ cluster-admin short-circuit).
// Without it only self-read passes (fail-closed for everyone else).
func (u *GetUserUseCase) WithRelationStore(relations clients.RelationStore) *GetUserUseCase {
	u.relations = relations
	return u
}

// Execute — sync read.
//
// Authz (Design B, D-6/D-9):
//   - anonymous → NotFound (hide existence).
//   - self (principal == target user) → ALLOW (a user may always read itself;
//     additive fast-path independent of FGA materialization).
//   - otherwise: the caller must hold `v_get` on iam_user:<id> OR be a
//     cluster-admin. Else → NotFound (hide existence; never PermissionDenied).
//
// Replaces the legacy owner-only `IsSelf(account.OwnerUserID)` cross-user gate
// that denied a delegate explicitly granted `iam.user.get`.
func (u *GetUserUseCase) Execute(ctx context.Context, id domain.UserID) (domain.User, error) {
	if err := shared.ValidateResourceID(string(id), domain.PrefixUser, "user"); err != nil {
		return domain.User{}, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return domain.User{}, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	got, err := rd.Users().Get(ctx, id)
	if err != nil {
		return domain.User{}, shared.MapRepoErr(err)
	}
	if authzguard.IsAnonymous(ctx) {
		return domain.User{}, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", id))
	}
	// Self always reads itself.
	if authzguard.IsSelf(ctx, string(got.ID)) {
		return got, nil
	}
	// Cross-user: v_get on iam_user:<id> OR cluster-admin.
	allowed, azErr := authzguard.AllowsVGet(ctx, u.relations, "iam_user", string(id))
	if azErr != nil {
		// The read gate could not be evaluated. Not a denial, and above all not
		// "does not exist" — say so, and let the client retry.
		return domain.User{}, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	if allowed {
		return got, nil
	}
	return domain.User{}, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", id))
}
