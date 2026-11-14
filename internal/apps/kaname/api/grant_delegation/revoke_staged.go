// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grant_delegation

import (
	"context"
	"reflect"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// WithRevokeAuthorityWriter включает staged каскад. Явно настроенный nil
// закрывает путь; отсутствие настройки сохраняет прежний legacy режим.
func (u *RevokeGrantDelegationUseCase) WithRevokeAuthorityWriter(f kaname.GrantDelegationRevokeWriterFactory) *RevokeGrantDelegationUseCase {
	u.revokeAuthorityWriter = f
	u.revokeAuthorityConfigured = true
	return u
}

func (u *RevokeGrantDelegationUseCase) stagedRevokeOnce(ctx context.Context, id domain.GrantDelegationID, by domain.GrantDelegationActor, actor string) (domain.GrantDelegation, error) {
	f := u.revokeAuthorityWriter
	if f == nil || (reflect.ValueOf(f).Kind() == reflect.Ptr && reflect.ValueOf(f).IsNil()) {
		return domain.GrantDelegation{}, authzguard.AuthzBackendUnavailable()
	}
	w, err := f.GrantDelegationRevokeWriter(ctx, id)
	if err != nil {
		return domain.GrantDelegation{}, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = w.Rollback(cleanup)
	}()
	current := w.LockedGrantDelegation()
	checker, err := w.TransactionRelationChecker(nil)
	if err != nil {
		return domain.GrantDelegation{}, err
	}
	if err = requireAccountGrantAuthorityWithOwner(ctx, checker, current.AccountID, func(ctx context.Context) (domain.UserID, error) {
		return accountOwnerFromReader(ctx, w, current.AccountID)
	}); err != nil {
		return domain.GrantDelegation{}, err
	}
	at := w.AuthorityFence().DecisionAt()
	d, err := w.AccessBindingsW().GrantDelegationsW().MarkRevoked(ctx, id, by, at)
	if err != nil {
		return domain.GrantDelegation{}, err
	}
	count, err := w.WithdrawGrantDelegation(ctx, d, actor, at)
	if err != nil {
		return domain.GrantDelegation{}, err
	}
	if err = emitDelegationRevoked(ctx, w, d, actor, count); err != nil {
		return domain.GrantDelegation{}, err
	}
	if err = w.Commit(ctx); err != nil {
		return domain.GrantDelegation{}, err
	}
	return d, nil
}
