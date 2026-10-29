// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grant_delegation

// get.go — GetGrantDelegationUseCase (GD-60).

import (
	"context"
	stderrors "errors"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"

	_ "github.com/PRO-Robotech/kaname/internal/dto/toproto" // регистрация переводов реестра
)

// GetGrantDelegationUseCase — чтение делегирования.
type GetGrantDelegationUseCase struct {
	repo      Repo
	relations clients.RelationStore
}

// NewGetGrantDelegationUseCase — над хранилищем службы.
func NewGetGrantDelegationUseCase(r Repo) *GetGrantDelegationUseCase {
	return &GetGrantDelegationUseCase{repo: r}
}

// WithRelationStore — дверь решения: право выдавать на аккаунте делегирования.
func (u *GetGrantDelegationUseCase) WithRelationStore(relations clients.RelationStore) *GetGrantDelegationUseCase {
	u.relations = relations
	return u
}

// Execute — форма идентификатора первой; несуществующее делегирование и отказ в
// праве отвечают побайтово одинаково (скрытие существования). Право — делегат
// либо право выдавать на аккаунте делегирования.
func (u *GetGrantDelegationUseCase) Execute(ctx context.Context, id domain.GrantDelegationID) (domain.GrantDelegation, error) {
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return domain.GrantDelegation{}, err
	}
	if err := validateDelegationID(id); err != nil {
		return domain.GrantDelegation{}, err
	}
	d, err := loadDelegation(ctx, u.repo, id)
	if err != nil {
		return domain.GrantDelegation{}, err
	}
	caller := operations.PrincipalFromContext(ctx)
	if d.IsDelegate(caller.Type, caller.ID) {
		return d, nil
	}
	if err := requireAccountGrantAuthority(ctx, u.repo, u.relations, d.AccountID); err != nil {
		return domain.GrantDelegation{}, err
	}
	return d, nil
}

// validateDelegationID — форма идентификатора делегирования: `INVALID_ARGUMENT`
// `invalid grant delegation id '<x>'`, без деталей (Р6).
func validateDelegationID(id domain.GrantDelegationID) error {
	return shared.ValidateResourceID(string(id), domain.PrefixGrantDelegation, "grant delegation")
}

// loadDelegation — делегирование по id; нет строки — отказ в праве (скрытие
// существования, как у выдачи).
func loadDelegation(ctx context.Context, repo Repo, id domain.GrantDelegationID) (domain.GrantDelegation, error) {
	rd, err := repo.Reader(ctx)
	if err != nil {
		return domain.GrantDelegation{}, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	d, err := rd.AccessBindings().GrantDelegations().Get(ctx, id)
	if err != nil {
		if stderrors.Is(err, iamerr.ErrNotFound) {
			return domain.GrantDelegation{}, authzguard.PermissionDenied()
		}
		return domain.GrantDelegation{}, shared.MapRepoErr(err)
	}
	return d, nil
}

// ToProto — проекция делегирования для ответа.
func ToProto(d domain.GrantDelegation) (*iamv1.GrantDelegation, error) {
	var out *iamv1.GrantDelegation
	if err := dto.Transfer(dto.FromTo(d, &out)); err != nil {
		return nil, fmt.Errorf("dto.Transfer GrantDelegation: %w", err)
	}
	return out, nil
}

func marshalGD(d domain.GrantDelegation) (*anypb.Any, error) {
	pb, err := ToProto(d)
	if err != nil {
		return nil, err
	}
	return anypb.New(pb)
}
