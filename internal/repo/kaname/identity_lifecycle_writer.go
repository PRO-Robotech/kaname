// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// IdentityMutation ограничивает выбор писателя мутациями личности и её членства.
// Это участие в протоколе записи, а не новая политика допуска или grant.
type IdentityMutation string

const (
	IdentityUpdate            IdentityMutation = "update"
	IdentityDelete            IdentityMutation = "delete"
	IdentityBlock             IdentityMutation = "block"
	IdentityUnblock           IdentityMutation = "unblock"
	IdentityRemoveFromAccount IdentityMutation = "remove_from_account"
)

type IdentityLifecycleWriterFactory interface {
	IdentityLifecycleWriter(context.Context, IdentityMutation, domain.UserID) (Writer, error)
}
