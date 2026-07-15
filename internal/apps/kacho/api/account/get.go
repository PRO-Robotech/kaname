// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package account

// get.go — GetAccountUseCase. Sync read.

import (
	"context"

	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// GetAccountUseCase читает Account по id.
type GetAccountUseCase struct {
	repo Repo
	// relations — FGA relation-Check port resolving the caller's v_get grant on
	// account:<id> (Design B). nil → fail-closed (every non-cluster-admin Get is
	// hidden); production wiring always injects it via WithRelationStore.
	relations clients.RelationStore
}

// NewGetAccountUseCase создает use-case.
func NewGetAccountUseCase(r Repo) *GetAccountUseCase {
	return &GetAccountUseCase{repo: r}
}

// WithRelationStore wires the FGA client used to authorize the read via the
// verb-bearing `v_get` relation on account:<id> (+ cluster-admin short-circuit).
// Mirrors ListAccountsUseCase / GetRoleUseCase. Without it a non-cluster-admin
// Get fails closed (NotFound).
func (u *GetAccountUseCase) WithRelationStore(relations clients.RelationStore) *GetAccountUseCase {
	u.relations = relations
	return u
}

// Execute — sync read. Malformed id (нет prefix `acc` или длина ≠ 20) →
// InvalidArgument; well-formed-но-несуществующий → NotFound.
//
// Authz (Design B, D-6/D-9): the caller must hold `v_get` on account:<id>
// (owner-binding materializes it for the owner; an explicit `iam.account.get`
// grant materializes it for a delegate) OR be a cluster-admin. A non-authorized
// caller (incl. anonymous) → NotFound (hide existence; never PermissionDenied —
// no enumeration). Replaces the legacy owner-only `IsSelf(OwnerUserID)` gate that
// produced the "granted invitee → 404" bug.
func (u *GetAccountUseCase) Execute(ctx context.Context, id domain.AccountID) (domain.Account, error) {
	if err := shared.ValidateResourceID(string(id), domain.PrefixAccount, "account"); err != nil {
		return domain.Account{}, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return domain.Account{}, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	a, err := rd.Accounts().Get(ctx, id)
	if err != nil {
		return domain.Account{}, shared.MapRepoErr(err)
	}
	if !authzguard.AllowsVGet(ctx, u.relations, "account", string(id)) {
		return domain.Account{}, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrNotFound, "Account %s not found", id))
	}
	return a, nil
}
