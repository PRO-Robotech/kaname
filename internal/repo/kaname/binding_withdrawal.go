// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

type BindingWithdrawalKind uint8

const (
	BindingWithdrawalDelete BindingWithdrawalKind = iota + 1
	BindingWithdrawalRevoke
	BindingWithdrawalExpiry
)

// BindingWithdrawalRunner — kaname#1034: snapshot полного сохранённого ledger
// до fences; CAS, снятие, subject-change и audit фиксируются ОДНОЙ транзакцией.
// Callback не фиксирует writer и не читает заново inventory. Это participant,
// не доказательство D1/D2/D3 и не переключатель публичных policy gates.
type BindingWithdrawalRunner interface {
	WithdrawBinding(context.Context, domain.AccessBindingID, BindingWithdrawalKind, string, func(context.Context, Writer, clients.RelationStore, domain.AccessBinding) error, func(context.Context, Writer, domain.AccessBinding) error) (domain.AccessBinding, error)
}
