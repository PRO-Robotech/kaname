// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"
	"time"

	"github.com/PRO-Robotech/corelib/operations"

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
	// RunUserChildRegistration получает неизменяемый запрос для подготовки до
	// callback. При подготовке право проверяется до раскрытия состояния
	// родителя. Callback исполняется после ожиданий под ограждениями записи
	// и повторно проверяет право. Версия возвращается после успешного коммита.
	RunUserChildRegistration(context.Context, UserChildRegistrationInput, operations.Principal,
		func(context.Context, UserChildRegistrationTx) (time.Time, error),
	) (time.Time, error)
}
