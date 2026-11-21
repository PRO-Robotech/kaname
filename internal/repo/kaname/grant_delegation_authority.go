// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// GrantDelegationMutation описывает существующие операции: отзыв сохраняет
// строку и атомарно снимает выданные по ней bindings. Delete/expiry у модели нет.
type GrantDelegationMutation string

const (
	GrantDelegationCreate GrantDelegationMutation = "create"
	GrantDelegationUpdate GrantDelegationMutation = "update"
)

// GrantDelegationWriterFactory классифицирует OLD и предложенные NEW источники
// до прежних pair/row locks. При Update proposed содержит ID и новые role_ids;
// остальные неизменяемые anchors repository читает самостоятельно.
type GrantDelegationWriterFactory interface {
	GrantDelegationWriter(context.Context, GrantDelegationMutation, domain.GrantDelegation) (Writer, error)
}
