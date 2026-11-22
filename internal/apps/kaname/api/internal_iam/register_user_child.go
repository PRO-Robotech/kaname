// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"
	"errors"
	"time"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type UserChildRegistration struct {
	tx kaname.UserChildRegistrationTransactions
}

func NewUserChildRegistration(tx kaname.UserChildRegistrationTransactions) *UserChildRegistration {
	return &UserChildRegistration{tx: tx}
}

func (uc *UserChildRegistration) Register(ctx context.Context, input kaname.UserChildRegistrationInput) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	principal, verified := operations.PrincipalFromContextOK(ctx)
	_, named := authzguard.SubjectFromPrincipal(principal)
	if !verified || !named || principal.Type != "user" || principal.IsAnonymous() ||
		input.ResourceType == "" || input.ResourceID == "" {
		return time.Time{}, authzguard.PermissionDenied()
	}
	if uc == nil || uc.tx == nil {
		return time.Time{}, authzguard.AuthzBackendUnavailable()
	}

	version, err := uc.tx.RunUserChildRegistration(ctx, input, principal)
	// Конец запроса первичен: поздний отказ хранилища не выдаётся за решение
	// о праве. Причина остаётся в цепочке для диагностики на границе сервиса.
	if canceled := ctx.Err(); err != nil && canceled != nil {
		return time.Time{}, errors.Join(canceled, err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return time.Time{}, err
	}
	if errors.Is(err, iamerr.ErrUnavailable) || errors.Is(err, iamerr.ErrAborted) || errors.Is(err, iamerr.ErrInternal) {
		return time.Time{}, err
	}
	if errors.Is(err, domain.ErrUserChildRegistrationRefused) {
		return time.Time{}, authzguard.PermissionDenied()
	}
	if err != nil {
		return time.Time{}, err
	}
	if version.IsZero() {
		return time.Time{}, authzguard.AuthzBackendUnavailable()
	}
	return version, nil
}
