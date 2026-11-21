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
)

// UserChildRegistrationInput содержит только координату нового объекта.
type UserChildRegistrationInput struct {
	ResourceType string
	ResourceID   string
}

type UserChildRegistrationTx interface {
	// ResolveUserChildRegistration читает только политику типа и выводит
	// ключ родителя из ID. Состояние родителя до проверки права не читается.
	ResolveUserChildRegistration(context.Context, UserChildRegistrationInput) (domain.UserChildRegistrationTarget, error)
	// Check читает право после последнего ожидания блокировок. До конца
	// записи её ограждения сохраняют согласованность решения с изменениями прав.
	Check(ctx context.Context, subject, relation, object string) (bool, error)
	// ApplyUserChildRegistration проверяет записанное состояние и пределы
	// родителя под блокировкой. Он сохраняет только указатель parent, а
	// личность пользователя использует в аудите. Версию назначает Kaname.
	ApplyUserChildRegistration(context.Context, domain.UserChildRegistrationTarget, operations.Principal) (time.Time, error)
}

type UserChildRegistrationTransactions interface {
	// RunUserChildRegistration возвращает версию после фиксации транзакции.
	// При повторе транзакции выполняется и проверка права на родителе.
	RunUserChildRegistration(context.Context, func(context.Context, UserChildRegistrationTx) (time.Time, error)) (time.Time, error)
}

type UserChildRegistration struct {
	tx UserChildRegistrationTransactions
}

func NewUserChildRegistration(tx UserChildRegistrationTransactions) *UserChildRegistration {
	return &UserChildRegistration{tx: tx}
}

func (uc *UserChildRegistration) Register(ctx context.Context, input UserChildRegistrationInput) (time.Time, error) {
	principal, verified := operations.PrincipalFromContextOK(ctx)
	subject, named := authzguard.SubjectFromPrincipal(principal)
	if !verified || !named || principal.Type != "user" || principal.IsAnonymous() ||
		input.ResourceType == "" || input.ResourceID == "" {
		return time.Time{}, authzguard.PermissionDenied()
	}
	if uc == nil || uc.tx == nil {
		return time.Time{}, authzguard.AuthzBackendUnavailable()
	}

	version, err := uc.tx.RunUserChildRegistration(ctx, func(ctx context.Context, tx UserChildRegistrationTx) (time.Time, error) {
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
		return tx.ApplyUserChildRegistration(ctx, target, principal)
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
