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
	"github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type UserChildRegistration struct {
	tx kaname.UserChildRegistrationTransactions
}

func NewUserChildRegistration(tx kaname.UserChildRegistrationTransactions) *UserChildRegistration {
	return &UserChildRegistration{tx: tx}
}

func (uc *UserChildRegistration) Register(ctx context.Context, input kaname.UserChildRegistrationInput) (time.Time, error) {
	principal, verified := operations.PrincipalFromContextOK(ctx)
	subject, named := authzguard.SubjectFromPrincipal(principal)
	if !verified || !named || principal.Type != "user" || principal.IsAnonymous() ||
		input.ResourceType == "" || input.ResourceID == "" {
		return time.Time{}, authzguard.PermissionDenied()
	}
	if uc == nil || uc.tx == nil {
		return time.Time{}, authzguard.AuthzBackendUnavailable()
	}

	version, err := uc.tx.RunUserChildRegistration(ctx, input, principal, func(ctx context.Context, tx kaname.UserChildRegistrationTx) (time.Time, error) {
		target, err := tx.ResolveUserChildRegistration(ctx, input)
		if err != nil {
			return time.Time{}, err
		}
		if target.ChildObject == "" || target.ParentObject == "" || target.ParentAction == "" ||
			target.ChildObject == target.ParentObject {
			return time.Time{}, domain.ErrUserChildRegistrationRefused
		}
		allowed, err := tx.Check(ctx, subject, target.ParentAction, target.ParentObject)
		if err != nil {
			return time.Time{}, err
		}
		if !allowed {
			return time.Time{}, domain.ErrUserChildRegistrationRefused
		}
		version, err := tx.ApplyUserChildRegistration(ctx, target, principal)
		if err != nil {
			return time.Time{}, err
		}
		if version.IsZero() {
			return time.Time{}, authzguard.AuthzBackendUnavailable()
		}
		return version, nil
	})
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
