// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
)

// UserChildRegistrationInput содержит только координату нового объекта.
type UserChildRegistrationInput struct {
	ResourceType string
	ResourceID   string
}

// UserChildRegistrationTransactions принимает только исходную координату и
// подтверждённого человека. Репозиторий владеет RR/RC, обеими проверками права,
// закрытым телом и повтором всей попытки; версия возвращается после Commit.
type UserChildRegistrationTransactions interface {
	RunUserChildRegistration(context.Context, UserChildRegistrationInput, operations.Principal) (time.Time, error)
}
