// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// GrantDelegationRevokeWriterFactory готовит полный каскад ДО authority fences.
// Возвращаемый writer уже держит pair/row locks и проверенные protected epochs;
// native checker использует момент решения после всех этих ожиданий.
// PRO-Robotech/kaname#1034: весь отзыв фиксируется одной транзакцией вызывающего.
type GrantDelegationRevokeWriterFactory interface {
	GrantDelegationRevokeWriter(context.Context, domain.GrantDelegationID) (GrantDelegationRevokeWriter, error)
}

// GrantDelegationRevokeWriter исполняет типизированный snapshot каскада в той же
// транзакции, что MarkRevoked, native policy и аудит делегирования. Withdrawal
// не перечитывает inventory и не завершает транзакцию самостоятельно.
type GrantDelegationRevokeWriter interface {
	Writer
	AuthorityFence() AuthorityFence
	LockedGrantDelegation() domain.GrantDelegation
	WithdrawGrantDelegation(context.Context, domain.GrantDelegation, string, time.Time) (int, error)
}
